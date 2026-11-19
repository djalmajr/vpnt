use super::*;
use std::{os::unix::net::UnixListener, sync::atomic::Ordering};

// Same 20 s open budget as the base test: a VICI lookup delayed past it is a
// real regression, and the CI failure was Unavailable, not a deadline miss.
fn open_until() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

// Mutation: allow the persistent phase to reenter a spent attempt.
#[test]
fn persistent_phase_transitions_never_reenter_a_spent_attempt() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("normal", 1)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    assert_eq!(
        peer.producer
            .lock()
            .unwrap()
            .lease
            .stage(record::Stage::Running, Some((&context.identity).into())),
        Err(Error::Changed)
    );
    // One admission attempt only: production stops on the first open error.
    // The guard bounds the fixture; it never permits a second open. On failure
    // report the recorded phase and what the fixture left on disk so the next
    // CI occurrence can name the step without changing production.
    let expires = open_until();
    let started = Instant::now();
    let client = peer
        .open(reservation.owner(), expires, token())
        .unwrap_or_else(|error| {
            let records = context.store.records().unwrap_or_default();
            let mut producer = peer.producer.lock().unwrap();
            let mut files = fs::read_dir(&producer.lease.directory.path)
                .map(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            files.sort();
            // child_exited() unwraps its own poll; keep the original failure
            // message even when that secondary observation itself panics.
            let child_probe = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| producer.child_exited()),
            )
            .map(|exited| exited.to_string())
            .unwrap_or_else(|payload| {
                let text = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|text| (*text).to_string()))
                    .unwrap_or_else(|| "unknown panic".to_string());
                format!("child probe panicked: {text}")
            });
            panic!(
                "open failed after {:?} ({} left on guard): {error:?}; recorded stage={:?} child={:?}; fixture files={files:?}; child_probe={child_probe} cached_fd={:?}",
                started.elapsed(),
                expires.saturating_duration_since(Instant::now()).as_secs(),
                records.first().map(|record| record.stage),
                records.first().and_then(|record| record.child.clone()),
                producer.cached_fd()
            );
        });
    client.command("version", Message::new(), &[]).unwrap();
    assert_eq!(
        peer.producer
            .lock()
            .unwrap()
            .lease
            .stage(record::Stage::Starting, None),
        Err(Error::Changed)
    );
    peer.retire(reservation.owner()).unwrap();
    assert_eq!(
        peer.producer
            .lock()
            .unwrap()
            .lease
            .stage(record::Stage::Starting, None),
        Err(Error::Changed)
    );
    registry.release(&reservation).unwrap();
}

// Mutation: let charon's unconditional unlink replace a preexisting socket.
#[test]
fn an_existing_runtime_socket_is_preserved_and_cannot_trigger_spawn() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("normal", 1)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    let path = peer.producer.lock().unwrap().lease.directory.path.join("v");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    let stamp = socket::stamp(&path, context.runtime.owner()).unwrap();
    assert_eq!(
        peer.open(reservation.owner(), until(), token()).err(),
        Some(Error::Changed)
    );
    let records = context.store.records().unwrap();
    assert_eq!(records[0].stage, record::Stage::Prepared);
    assert!(records[0].child.is_none());
    assert_eq!(
        socket::stamp(&path, context.runtime.owner()).unwrap(),
        stamp
    );
    peer.retire(reservation.owner()).unwrap();
    registry.release(&reservation).unwrap();
    drop(listener);
}

// Mutations: ignore the caller's deadline/cancellation or stop its child to
// make an observation finish. Neither outcome grants permission to restart.
#[test]
fn socket_wait_honors_cancellation_and_deadline_and_retains_the_original_producer() {
    for canceled in [false, true] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let mut registry = Registry::new(context.observer(Kernel::default()));
        let reservation = registry.reserve(owner("silence", 1)).unwrap();
        let configuration = config(&registry, &reservation);
        let mut peer = context
            .prepare(&registry, &reservation, &configuration)
            .unwrap();
        let pidfile = peer
            .producer
            .lock()
            .unwrap()
            .lease
            .directory
            .path
            .join("pid");
        // Fixture phase prerequisite: run the spawn/handoff once so the
        // cancellation below lands in the VICI socket wait, never in
        // reception. This deadline is a fixture barrier, not a product result;
        // it is generous so child startup cannot masquerade as a handoff
        // failure under parallel load.
        let warm = peer
            .open(
                reservation.owner(),
                Instant::now() + Duration::from_secs(20),
                token(),
            )
            .err();
        assert_eq!(
            warm,
            Some(Error::Timeout),
            "fixture prerequisite: the handoff must complete and VICI stay silent"
        );
        assert!(
            peer.producer.lock().unwrap().cached_fd().is_some(),
            "fixture prerequisite: the handoff must be cached before the socket wait"
        );
        let cancel = token();
        let signal = cancel.clone();
        let canceler = std::thread::spawn(move || {
            let expires = Instant::now() + Duration::from_secs(20);
            while !pidfile.exists() {
                assert!(
                    Instant::now() < expires,
                    "fixture did not reach its socket wait"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let signaled = Instant::now();
            signal.store(true, Ordering::Release);
            signaled
        });
        // The PID file is only a fixture barrier, never process/signal authority.
        // Start timing cancellation after the child has actually initialized.
        let result = peer.open(reservation.owner(), until(), cancel).err();
        let signaled = canceler.join().unwrap();
        assert_eq!(result, Some(Error::Canceled));
        assert!(signaled.elapsed() < Duration::from_millis(800));
        let original = context.store.records().unwrap()[0].child.clone();
        assert!(original.is_some());
        if !canceled {
            let started = Instant::now();
            let expires = started + Duration::from_millis(150);
            assert_eq!(
                peer.open(reservation.owner(), expires, token()).err(),
                Some(Error::Timeout)
            );
            assert!(started.elapsed() < Duration::from_millis(800));
        }
        assert_eq!(context.store.records().unwrap()[0].child, original);
        assert!(!peer.producer.lock().unwrap().child_exited());
        assert!(registry.has_reservations());
        peer.retire(reservation.owner()).unwrap();
        registry.release(&reservation).unwrap();
    }
}
