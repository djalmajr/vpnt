use super::bound::{prepared, profile};
use super::*;
use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    sync::{atomic::Ordering, mpsc},
    thread,
    time::Duration,
};

struct Watch {
    watched: libc::c_int,
    fd: libc::c_int,
}

impl Watch {
    fn new(directory: &std::path::Path) -> Self {
        let path = CString::new(directory.as_os_str().as_bytes()).expect("lease path");
        // SAFETY: live NUL-terminated path; O_EVTONLY is the kqueue watch flag.
        let watched = unsafe { libc::open(path.as_ptr(), libc::O_EVTONLY) };
        assert!(watched >= 0, "kqueue watch open");
        // SAFETY: no memory preconditions.
        let fd = unsafe { libc::kqueue() };
        assert!(fd >= 0, "kqueue");
        let change = libc::kevent {
            ident: watched as libc::uintptr_t,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_WRITE | libc::NOTE_DELETE | libc::NOTE_RENAME,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one valid change registration, no event output.
        let registered =
            unsafe { libc::kevent(fd, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        assert_eq!(registered, 0, "kqueue register");
        // Keep `watched` open: closing the last vnode descriptor removes the knote.
        Self { watched, fd }
    }

    fn events(&self) -> usize {
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: one writable event slot, zero timeout, no changelist.
        let count = unsafe { libc::kevent(self.fd, std::ptr::null(), 0, &mut event, 1, &timeout) };
        assert!(count >= 0, "kqueue poll");
        count as usize
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: both descriptors were created here; the knote dies with the
        // watched descriptor.
        unsafe { libc::close(self.fd) };
        unsafe { libc::close(self.watched) };
    }
}

#[test]
fn open_lease_io_wait_honors_deadline_and_cancel_then_retry_reaches_vici() {
    for mode in ["deadline", "cancel"] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("lease-io", 21)).unwrap();
        let profile = profile("lease-io");
        let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        thread::scope(|scope| {
            let holder = context.clone();
            scope.spawn(move || {
                let _guard = holder.store.io_lock();
                ready_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
            });
            ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let cancel = token();
            let expires = if mode == "deadline" {
                Instant::now() + Duration::from_millis(170)
            } else {
                until()
            };
            if mode == "cancel" {
                let flag = cancel.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(50));
                    flag.store(true, Ordering::Release);
                });
            }
            let started = Instant::now();
            let result = peer.open(reservation.owner(), expires, cancel);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{mode}: {:?}",
                started.elapsed()
            );
            let expected = if mode == "deadline" {
                Error::Timeout
            } else {
                Error::Canceled
            };
            assert_eq!(result.err(), Some(expected), "{mode}");
            {
                let producer = peer.producer.lock().unwrap();
                assert_eq!(producer.lease.record.stage, record::Stage::Prepared);
                assert!(producer.lease.record.child.is_none());
            }
            assert!(peer.producer.lock().unwrap().child_exited());
            drop(release_tx);
        });
        let opened = peer.open(reservation.owner(), until(), token()).unwrap();
        let response = opened
            .command("version", Message::new(), &[])
            .unwrap()
            .response;
        assert_eq!(response.get_text("version"), Some("6.1.0"), "{mode}");
        assert_eq!(peer.retire(reservation.owner()), Ok(true));
        registry.release(&reservation).unwrap();
        assert!(context.store.records().unwrap().is_empty());
    }
}

#[test]
fn already_running_open_lease_io_wait_uses_the_caller_budget() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("lease-running", 22)).unwrap();
    let profile = profile("lease-running");
    let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
    drop(peer.open(reservation.owner(), until(), token()).unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        let holder = context.clone();
        scope.spawn(move || {
            let _guard = holder.store.io_lock();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let result = peer.open(
            reservation.owner(),
            Instant::now() + Duration::from_millis(170),
            token(),
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.err(), Some(Error::Timeout));
        drop(release_tx);
    });
    let again = peer.open(reservation.owner(), until(), token()).unwrap();
    let response = again
        .command("version", Message::new(), &[])
        .unwrap()
        .response;
    assert_eq!(response.get_text("version"), Some("6.1.0"));
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    registry.release(&reservation).unwrap();
}

#[test]
fn observe_and_take_lease_io_wait_is_bounded_before_native() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("lease-observe", 23)).unwrap();
    let profile = profile("lease-observe");
    let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
    drop(peer.open(reservation.owner(), until(), token()).unwrap());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        let holder = context.clone();
        scope.spawn(move || {
            let _guard = holder.store.io_lock();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let observed = context.observe_interface(
            reservation.owner(),
            Instant::now() + Duration::from_millis(170),
            token(),
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "observe: {:?}",
            started.elapsed()
        );
        assert_eq!(observed.err(), Some(Error::Timeout));
        let started = Instant::now();
        let taken = context.take_interface(
            reservation.owner(),
            Instant::now() + Duration::from_millis(170),
            token(),
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "take: {:?}",
            started.elapsed()
        );
        assert_eq!(taken.err(), Some(Error::Timeout));
        assert!(
            peer.producer.lock().unwrap().cached_fd().is_some(),
            "descriptor consumed before the bounded validate"
        );
        drop(release_tx);
    });
    peer.retire(reservation.owner()).unwrap();
    registry.release(&reservation).unwrap();
}

#[test]
fn stage_cannot_start_after_expiry_with_io_held() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("lease-stage", 24)).unwrap();
    let profile = profile("lease-stage");
    let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
    let lease = peer.producer.lock().unwrap().lease.directory.path.clone();
    let watch = Watch::new(&lease);
    let expires = Instant::now() + Duration::from_millis(120);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (result_tx, result_rx) = mpsc::channel();
    peer.producer
        .lock()
        .unwrap()
        .pause_before_stage(ready_tx, release_rx);
    thread::scope(|scope| {
        let producer = &mut peer;
        scope.spawn(move || {
            let result = producer
                .open(reservation.owner(), expires, token())
                .map(|_| ());
            result_tx.send(result).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let _io = context.store.io_lock();
        thread::sleep(Duration::from_millis(150));
        let started = Instant::now();
        release_tx.send(()).unwrap();
        let result = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("stage wait exceeded 1s");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.err(), Some(Error::Timeout));
        assert_eq!(watch.events(), 0, "stage wrote after known expiry");
    });
}
