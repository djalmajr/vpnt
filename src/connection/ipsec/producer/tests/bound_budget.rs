use super::bound::{egress, prepared, profile};
use super::*;
use std::{ffi::CString, os::unix::ffi::OsStrExt, sync::mpsc, thread, time::Duration};

fn store_entries(context: &Arc<NativeContext<'_>>) -> usize {
    fs::read_dir(&context.store.root.path)
        .expect("store root")
        .count()
}

/// Executed filesystem discriminator: kqueue `NOTE_WRITE` on the store root,
/// so a directory create/remove is observed even if a later check unwinds it.
struct Watch {
    watched: libc::c_int,
    fd: libc::c_int,
}

impl Watch {
    fn new(directory: &std::path::Path) -> Self {
        let path = CString::new(directory.as_os_str().as_bytes()).expect("store path");
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
        // Keep `watched` open: closing the last vnode descriptor removes the
        // EVFILT_VNODE knote.
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
fn watch_observes_a_directory_entry_change() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let watch = Watch::new(&context.store.root.path);
    assert_eq!(watch.events(), 0, "quiet before the probe");
    fs::create_dir(context.store.root.path.join("probe")).unwrap();
    assert!(watch.events() > 0, "kqueue missed a directory create");
    fs::remove_dir(context.store.root.path.join("probe")).unwrap();
}

#[test]
fn admission_wait_honors_deadline_and_cancel_without_writing() {
    for mode in ["deadline", "cancel"] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("admission-budget", 11)).unwrap();
        let profile = profile("admission-budget");
        let holder = context.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        thread::scope(|scope| {
            scope.spawn(move || {
                let _guard = holder.admission.lock().unwrap();
                ready_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
            });
            ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let cancel = token();
            let expires = if mode == "deadline" {
                Instant::now() + Duration::from_millis(180)
            } else {
                until()
            };
            if mode == "cancel" {
                let flag = cancel.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(50));
                    flag.store(true, std::sync::atomic::Ordering::Release);
                });
            }
            let started = Instant::now();
            let result = context.prepare_bound(
                &registry,
                &reservation,
                &profile,
                egress(&profile),
                (expires, cancel),
            );
            let elapsed = started.elapsed();
            let expected = if mode == "deadline" {
                Error::Timeout
            } else {
                Error::Canceled
            };
            assert!(elapsed < Duration::from_secs(1), "{mode}: {elapsed:?}");
            assert_eq!(result.err(), Some(expected), "{mode}");
            assert_eq!(store_entries(&context), 0, "{mode}");
            drop(release_tx);
        });
    }
}

#[test]
fn store_io_wait_honors_budget_without_writing() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("io-budget", 12)).unwrap();
    let profile = profile("io-budget");
    let holder = context.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        scope.spawn(move || {
            let _guard = holder.store.io_lock();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let result = context.prepare_bound(
            &registry,
            &reservation,
            &profile,
            egress(&profile),
            (Instant::now() + Duration::from_millis(180), token()),
        );
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(result.err(), Some(Error::Timeout));
        assert_eq!(store_entries(&context), 0);
        drop(release_tx);
    });
}

#[test]
fn active_map_wait_honors_budget_without_writing() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("active-budget", 13)).unwrap();
    let profile = profile("active-budget");
    let holder = context.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        scope.spawn(move || {
            let _guard = holder.active.lock().unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let result = context.prepare_bound(
            &registry,
            &reservation,
            &profile,
            egress(&profile),
            (Instant::now() + Duration::from_millis(180), token()),
        );
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(result.err(), Some(Error::Timeout));
        assert_eq!(store_entries(&context), 0);
        drop(release_tx);
    });
}

#[test]
fn producer_open_wait_honors_budget_without_latching() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("producer-budget", 14)).unwrap();
    let profile = profile("producer-budget");
    let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
    let holder = peer.producer.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::scope(|scope| {
        scope.spawn(move || {
            let _guard = holder.lock().unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let result = peer.open(
            reservation.owner(),
            Instant::now() + Duration::from_millis(180),
            token(),
        );
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(result.err(), Some(Error::Timeout));
        drop(release_tx);
    });
}

#[test]
fn pre_attempt_binding_error_does_not_latch_and_fresh_retry_reaches_vici() {
    for error in [Error::Canceled, Error::Timeout] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("preflight-budget", 15)).unwrap();
        let profile = profile("preflight-budget");
        let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
        peer.producer.lock().unwrap().fail_next_binding(error);
        assert_eq!(
            peer.open(reservation.owner(), until(), token()).err(),
            Some(error)
        );
        let records = context.store.records().unwrap();
        assert_eq!(records[0].stage, record::Stage::Prepared);
        assert!(records[0].child.is_none());
        let opened = peer
            .open(reservation.owner(), until(), token())
            .unwrap_or_else(|error| panic!("fresh retry did not spawn: {error:?}"));
        let response = opened
            .command("version", Message::new(), &[])
            .unwrap()
            .response;
        assert_eq!(response.get_text("version"), Some("6.1.0"));
        assert_eq!(peer.retire(reservation.owner()), Ok(true));
        registry.release(&reservation).unwrap();
        assert!(context.store.records().unwrap().is_empty());
    }
}

#[test]
fn cancel_before_first_write_creates_no_directory_or_file() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("first-write", 16)).unwrap();
    let profile = profile("first-write");
    let cancel = token();
    context.store.cancel_before_create(cancel.clone());
    let watch = Watch::new(&context.store.root.path);
    let started = Instant::now();
    let result = context.prepare_bound(
        &registry,
        &reservation,
        &profile,
        egress(&profile),
        (until(), cancel),
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(result.err(), Some(Error::Canceled));
    assert_eq!(store_entries(&context), 0);
    assert_eq!(watch.events(), 0, "durable write despite cancel");
}
