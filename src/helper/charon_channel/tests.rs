use super::*;
use crate::helper::{fd_guard, local_socket::Budget};
use std::{
    io,
    os::fd::AsRawFd,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

mod native;
use native::Fixture;

/// Reaps the original child on every path, including a failed assertion.
struct OwnedChild(Option<ManagedChild>);

impl OwnedChild {
    fn new(child: ManagedChild) -> Self {
        Self(Some(child))
    }
    fn get(&mut self) -> &mut ManagedChild {
        self.0.as_mut().unwrap()
    }
    fn wait(&mut self) -> std::process::ExitStatus {
        native::exit_status(self.get())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.stop(Duration::from_secs(2));
        }
    }
}

/// `Descriptor` deliberately implements no `Debug`, so a refusal is classified
/// by an explicit match.
fn refusal(result: io::Result<Descriptor>) -> io::ErrorKind {
    match result {
        Ok(_) => panic!("capability was admitted when it had to be refused"),
        Err(error) => error.kind(),
    }
}
// Mutations: omit the single-use/PID binding, the CLOEXEC marking, or the
// exact one-descriptor cardinality.
#[test]
fn single_descriptor_handoff_is_cloexec_usable_and_single_use() {
    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("good");
    let mut child = OwnedChild::new(child);
    assert!(
        fixture.wait_for("ready"),
        "child did not validate its stdio and FD3 contract"
    );
    let budget = fixture.budget();
    let descriptor = receiver.receive(child.get(), &budget).unwrap();
    let fd = descriptor.raw_fd();
    // SAFETY: the received descriptor is live and owned by `descriptor`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0, "received descriptor is not live");
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "received descriptor must be close-on-exec"
    );
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: descriptor is live; the output buffer and length match.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0, "received descriptor is not a usable socket");
    assert_eq!(kind, libc::SOCK_STREAM);
    drop(descriptor);
    assert!(
        fixture.wait_for("closed"),
        "child did not observe the descriptor close"
    );
    let status = child.wait();
    assert!(status.success(), "child exit: {status:?}");
    assert_eq!(
        refusal(receiver.receive(child.get(), &budget)),
        io::ErrorKind::InvalidInput,
        "a consumed receiver must not admit a second handoff"
    );
    // The real plugin closes FD3 immediately after send. The first validated
    // handoff is still admitted; only the second recv observes the peer close.
    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("closed-after");
    let mut child = OwnedChild::new(child);
    assert!(fixture.wait_for("ready"));
    let fd = receiver
        .receive(child.get(), &fixture.budget())
        .expect("closed-after first");
    drop(fd);
    assert!(
        fixture.wait_for("closed"),
        "closed-after: the delivered right was not released"
    );
    let status = child.wait();
    assert!(status.success(), "closed-after child exit: {status:?}");
}
// Mutations: accept a malformed payload, zero/multiple descriptors or a second
// queued datagram, and leak the reported rights on refusal.
//
// Truncated ancillary data cannot be produced here: the buffer covers the
// documented kernel bound, and a real `MSG_CTRUNC` poisons the guard instead of
// being a simple refusal. That fail-stop path is being proven with root.
#[test]
fn malformed_cardinality_and_extra_handoffs_are_refused_and_reported_rights_closed() {
    for mode in [
        "bad-magic",
        "bad-version",
        "bad-reserved",
        "short",
        "long",
        "zero",
        "two",
        "many",
        "max",
        "extra",
        "extra-closed",
    ] {
        let fixture = Fixture::new();
        let (child, mut receiver) = fixture.spawn(mode);
        let mut child = OwnedChild::new(child);
        assert!(
            fixture.wait_for("ready"),
            "{mode}: child did not become ready"
        );
        assert_eq!(
            refusal(receiver.receive(child.get(), &fixture.budget())),
            io::ErrorKind::InvalidData,
            "{mode}"
        );
        assert!(
            fixture.wait_for("closed"),
            "{mode}: delivered rights or the endpoint were not released"
        );
        let status = child.wait();
        assert!(status.success(), "{mode}: child exit {status:?}");
    }
}

// Mutations: admit a foreign or exited child, or replay after a failure.
#[test]
fn exited_or_foreign_child_cannot_redeem_the_capability() {
    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("exit");
    let mut child = OwnedChild::new(child);
    child.wait();
    assert_eq!(
        refusal(receiver.receive(child.get(), &fixture.budget())),
        io::ErrorKind::BrokenPipe
    );

    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("hold");
    let mut child = OwnedChild::new(child);
    assert!(fixture.wait_for("ready"));
    let mut sleeper =
        OwnedChild::new(ManagedChild::spawn(Command::new("/bin/sleep").arg("5")).unwrap());
    assert_eq!(
        refusal(receiver.receive(sleeper.get(), &fixture.budget())),
        io::ErrorKind::InvalidInput,
        "a different child must not receive the capability"
    );
    assert_eq!(
        refusal(receiver.receive(child.get(), &fixture.budget())),
        io::ErrorKind::InvalidInput,
        "any attempt consumes the admission"
    );

    // PID reuse: a different live child whose recorded PID is forced to the
    // receiver's, while its spawn authority stays its own. Only the authority
    // allocation can tell the two apart after a reap.
    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("hold");
    let _child = OwnedChild::new(child);
    assert!(fixture.wait_for("ready"));
    let mut imposter =
        OwnedChild::new(ManagedChild::spawn(Command::new("/bin/sleep").arg("5")).unwrap());
    let original = receiver.pid;
    imposter.get().retarget_pid_for_test(original);
    assert_eq!(imposter.get().id(), original);
    assert_eq!(
        refusal(receiver.receive(imposter.get(), &fixture.budget())),
        io::ErrorKind::InvalidInput,
        "a reused PID with a different spawn authority must not redeem the capability"
    );
}

// Mutations: restart the budget, ignore cancellation, or wait unbounded for the
// spawn guard.
#[test]
fn deadline_cancellation_and_guard_contention_are_bounded() {
    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("hold");
    let mut child = OwnedChild::new(child);
    assert!(fixture.wait_for("ready"));
    let short = Budget::new(Duration::from_millis(150)).unwrap();
    let started = Instant::now();
    assert_eq!(
        refusal(receiver.receive(child.get(), &short)),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() < Duration::from_secs(2));

    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("hold");
    let mut child = OwnedChild::new(child);
    assert!(fixture.wait_for("ready"));
    let cancel = Arc::new(AtomicBool::new(false));
    let budget = Budget::until(
        Instant::now() + Duration::from_secs(2),
        Some(cancel.clone()),
    )
    .unwrap();
    cancel.store(true, Ordering::Release);
    assert_eq!(
        refusal(receiver.receive(child.get(), &budget)),
        io::ErrorKind::ConnectionAborted
    );

    let fixture = Fixture::new();
    let (child, mut receiver) = fixture.spawn("good");
    let mut child = OwnedChild::new(child);
    assert!(fixture.wait_for("ready"));
    let guard = fd_guard::spawn();
    let budget = Budget::new(Duration::from_millis(150)).unwrap();
    let outcome = std::thread::scope(|scope| {
        scope
            .spawn(|| receiver.receive(child.get(), &budget))
            .join()
            .unwrap()
    });
    drop(guard);
    assert_eq!(
        refusal(outcome),
        io::ErrorKind::TimedOut,
        "a held spawn guard must not hold the receiver past its budget"
    );
}

// Mutation: drop the helper-wide spawn guard, so a fork can inherit a descriptor
// the kernel installed but nobody has marked close-on-exec yet.
#[test]
fn spawn_guard_blocks_fork_while_a_delivered_descriptor_is_still_inheritable() {
    let fixture = Fixture::new();
    // Shape of a freshly installed SCM_RIGHTS fd: live and still inheritable.
    let (pending, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let raw = pending.as_raw_fd();
    // SAFETY: this test owns the live descriptor and only clears a flag.
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_SETFD, 0) }, 0);
    let guard = fd_guard::spawn();
    let (finished, status) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut child = fixture.spawn_plain("scan");
            let status = native::exit_status(&mut child);
            let _ = finished.send(status);
        });
        // No fork may happen while the guard is held; the fixture only writes
        // its pre-scan marker after exec, so a bounded wait for completion is
        // an upper bound for blocking, not the exit proof.
        assert!(
            status.recv_timeout(Duration::from_millis(200)).is_err(),
            "an own child spawned while the descriptor was still inheritable"
        );
        // SAFETY: same live descriptor; mark it close-on-exec as reception does.
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        drop(guard);
        let status = status.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(status.success(), "scan child exit: {status:?}");
    });
    let report = fixture.audit();
    assert!(
        report.contains("started"),
        "scan child did not run: {report}"
    );
    assert!(
        !report.lines().any(|line| line.starts_with("fd=")),
        "child inherited a descriptor that was not yet close-on-exec: {report}"
    );
}
