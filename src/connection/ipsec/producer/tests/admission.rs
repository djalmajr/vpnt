use super::*;
use std::{os::unix::net::UnixListener, sync::atomic::Ordering};

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
    peer.open(reservation.owner(), until(), token())
        .unwrap()
        .command("version", Message::new(), &[])
        .unwrap();
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
                Instant::now() + Duration::from_secs(2),
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
            let expires = Instant::now() + Duration::from_secs(5);
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
