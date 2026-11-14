//! Isolated-process cases: re-exec this binary with a marker, FD 3 in pre_exec.
use crate::helper::fd_guard;
use std::{
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{net::UnixDatagram, process::CommandExt},
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Markers that turn a re-executed test binary into an isolated importer.
const FAIL_STOP_MARKER: &str = "VPNT_CHARON_CHANNEL_FAIL_STOP_CHILD";
const CAPACITY_MARKER: &str = "VPNT_CHARON_CHANNEL_CAPACITY_CHILD";
const FAIL_STOP_TEST: &str = "helper::charon_channel::tests::native::importer::truncated_ancillary_data_fail_stops_the_importing_process";
const CAPACITY_TEST: &str = "helper::charon_channel::tests::native::importer::small_fd_limit_refuses_rights_without_fail_stop";
/// One descriptor fits (12 + 4); anything more truncates the control layout.
const REDUCED_CONTROL: usize = 16;
/// Room for well over the rights the slot-limited child is sent.
const WIDE_CONTROL: usize = 1024;
const RIGHT_COPIES: usize = 128;
/// Only the re-executed child lowers its own descriptor limit.
const CHILD_FD_LIMIT: libc::rlim_t = 64;

/// Re-executes this binary with `marker` set and FD 3 carrying one end of a
/// fresh datagram pair; the child runs only the filtered test.
fn spawn_importer(marker: &str, filter: &str) -> (std::process::Child, UnixDatagram) {
    let (child_end, parent_end) = UnixDatagram::pair().unwrap();
    for fd in [child_end.as_raw_fd(), parent_end.as_raw_fd()] {
        // SAFETY: both descriptors are live and owned by this test.
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    // SAFETY: duplicate above the fixed target so `dup2` cannot alias it.
    let source = unsafe { libc::fcntl(child_end.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    assert!(source >= 0, "duplicate child endpoint failed");
    // SAFETY: the duplicate is a new owned descriptor.
    let source = unsafe { OwnedFd::from_raw_fd(source) };

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env(marker, "1")
        .args(["--exact", filter, "--test-threads=1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child_source = source.as_raw_fd();
    // SAFETY: only dup2/fcntl run after fork, on a descriptor kept alive here.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child_source, crate::helper::charon_channel::INHERITED_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(
                crate::helper::charon_channel::INHERITED_FD,
                libc::F_SETFD,
                0,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(source);
    drop(child_end);
    (child, parent_end)
}

/// Kills and reaps the importer if an assertion fails; otherwise the orphan
/// would hold the pipes open and hang the runner.
struct Importer {
    child: std::process::Child,
}

impl Drop for Importer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_exit(child: &mut std::process::Child, what: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("{what} did not exit");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stderr_of(child: &mut std::process::Child) -> String {
    String::from_utf8_lossy(&super::read_all(child.stderr.as_mut().unwrap())).into_owned()
}
// Mutation: return Err with unreported descriptors instead of exiting. The
// importer itself must die under the guard, and the kernel must close every
// delivered right with it. The parent branch asserts; the child branch is this
// same test re-executed with the marker set.
#[test]
fn truncated_ancillary_data_fail_stops_the_importing_process() {
    if std::env::var_os(FAIL_STOP_MARKER).is_some() {
        super::write_out(b"ready\n");
        if !super::await_inherited() {
            // SAFETY: distinct code so the parent sees the readiness timeout.
            unsafe { libc::_exit(80) };
        }
        let _guard = fd_guard::spawn();
        let _ = crate::helper::charon_channel::receive::receive_once_limited(3, REDUCED_CONTROL);
        // Truncated rights must never be returned: reaching here is a failure.
        // SAFETY: distinct code so the parent can tell this apart from exit 78.
        unsafe { libc::_exit(79) };
    }

    let (child, parent_end) = spawn_importer(FAIL_STOP_MARKER, FAIL_STOP_TEST);
    let mut importer = Importer { child };
    let mut stdout = importer.child.stdout.take().unwrap();
    let ready = super::await_line(&mut stdout, "ready");
    assert!(
        ready.ends_with("ready\n"),
        "unexpected ready line: {ready:?}"
    );
    std::thread::sleep(Duration::from_millis(50));
    let mut pairs = Vec::new();
    let mut sent = Vec::new();
    for _ in 0..6 {
        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        sent.push(writer);
        pairs.push(reader);
    }
    let raw: Vec<RawFd> = sent.iter().map(|socket| socket.as_raw_fd()).collect();
    // A child that skipped its readiness wait may already be gone; the
    // assertion below still reports the wrong exit code instead of masking it.
    let _ = send_rights_once(parent_end.as_raw_fd(), &raw);
    drop((sent, parent_end));

    let status = wait_exit(&mut importer.child, "fail-stop child");
    let stdout = super::read_all(&mut stdout);
    let stderr = stderr_of(&mut importer.child);
    assert_eq!(
        status.code(),
        Some(fd_guard::FAIL_STOP_EXIT),
        "importer did not fail-stop: {status:?}\nstdout: {}\nstderr: {stderr}",
        String::from_utf8_lossy(&stdout)
    );
    let mut byte = [0u8; 1];
    for (index, mut peer) in pairs.into_iter().enumerate() {
        assert_eq!(
            peer.read(&mut byte).unwrap_or(1),
            0,
            "right {index} survived the fail-stop"
        );
    }
    drop(importer.child.stdin.take());
}

// Mutation: fail-stop the helper when `unp_externalize` cannot reserve slots.
// A missing-slot error installs nothing and must surface as an error, with
// every reference gone while the importer is still alive.
#[test]
fn small_fd_limit_refuses_rights_without_fail_stop() {
    if std::env::var_os(CAPACITY_MARKER).is_some() {
        super::write_out(b"ready\n");
        let limit = libc::rlimit {
            rlim_cur: CHILD_FD_LIMIT,
            rlim_max: CHILD_FD_LIMIT,
        };
        // SAFETY: a plain struct with a valid limit for this process only.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            super::write_out(b"outcome=limit\n");
            // SAFETY: nothing left to unwind.
            unsafe { libc::_exit(1) };
        }
        if !super::await_inherited() {
            // SAFETY: distinct code so the parent sees the readiness timeout.
            unsafe { libc::_exit(81) };
        }
        let _guard = fd_guard::spawn();
        let outcome = crate::helper::charon_channel::receive::receive_once_limited(3, WIDE_CONTROL);
        // SAFETY: fd 3 is the inherited endpoint; closing it is the drop the
        // receiver performs on every outcome.
        unsafe { libc::close(3) };
        match outcome {
            Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                super::write_out(b"outcome=emsgsize\n");
            }
            Err(error) if error.raw_os_error() == Some(libc::EMFILE) => {
                super::write_out(b"outcome=emfile\n");
            }
            Ok(()) => super::write_out(b"outcome=ok\n"),
            Err(error) => {
                let line = match error.raw_os_error() {
                    Some(errno) => format!("outcome=errno:{errno}\n"),
                    None => format!("outcome=kind:{:?}\n", error.kind()),
                };
                super::write_out(line.as_bytes());
            }
        }
        // Stay alive until the parent has observed the peer EOF, so that EOF
        // cannot be explained by this process exiting.
        let mut byte = [0u8; 1];
        loop {
            // SAFETY: blocking read of one byte from stdin.
            if unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) } <= 0 {
                break;
            }
        }
        // SAFETY: nothing left to unwind.
        unsafe { libc::_exit(0) };
    }

    let (child, parent_end) = spawn_importer(CAPACITY_MARKER, CAPACITY_TEST);
    let mut importer = Importer { child };
    let mut stdout = importer.child.stdout.take().unwrap();
    let ready = super::await_line(&mut stdout, "ready");
    assert!(
        ready.ends_with("ready\n"),
        "unexpected ready line: {ready:?}"
    );
    std::thread::sleep(Duration::from_millis(50));
    let (writer, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let copies = [writer.as_raw_fd(); RIGHT_COPIES];
    // The slot-exhaustion assertion requires this fixture's datagram to be sent;
    // report a failed send separately from the child's receive outcome.
    send_rights_once(parent_end.as_raw_fd(), &copies).unwrap_or_else(|error| {
        match error.raw_os_error() {
            Some(errno) => panic!("128-right fixture send failed: errno={errno}"),
            None => panic!("128-right fixture send failed: kind={:?}", error.kind()),
        }
    });
    drop((writer, parent_end));

    let line = super::await_outcome(&mut stdout);
    assert!(
        line.ends_with("outcome=emsgsize\n") || line.ends_with("outcome=emfile\n"),
        "unexpected capacity outcome: {line:?}"
    );
    let mut byte = [0u8; 1];
    assert_eq!(
        peer.read(&mut byte).unwrap_or(1),
        0,
        "a right survived the capacity rollback"
    );
    // Now the child may finish; it exits only after this stdin closes.
    drop(importer.child.stdin.take());
    let status = wait_exit(&mut importer.child, "capacity child");
    assert!(
        status.success(),
        "capacity child exit: {status:?}\n{}",
        stderr_of(&mut importer.child)
    );
}

/// Sends `fds` with the protocol payload over one `SOCK_DGRAM` message.
fn send_rights_once(socket: RawFd, fds: &[RawFd]) -> io::Result<()> {
    let data = [0x56u8, 0x50, 0x55, 0x46, 1, 0, 0, 0];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let rights = std::mem::size_of_val(fds);
    // SAFETY: word-sized arithmetic used by the C msg macros.
    let space = unsafe { libc::CMSG_SPACE(rights as libc::c_uint) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: msghdr is a plain C struct; all-zero bits are valid.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    // SAFETY: the control buffer is CMSG_SPACE-sized, so the first header and
    // its data fit; the kernel only reads them.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(rights as libc::c_uint) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(), libc::CMSG_DATA(cmsg), rights);
    }
    // SAFETY: initialized msghdr over live buffers.
    let sent = unsafe { libc::sendmsg(socket, &message, 0) };
    if sent != data.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
