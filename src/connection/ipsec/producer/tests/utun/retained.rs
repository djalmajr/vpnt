use super::*;
use std::{
    io::{self, Read},
    os::unix::net::UnixListener,
};

// Mutation: allow a take before any attempt, or after retire, so a producer
// that never held a capability still hands one out.
#[test]
fn take_interface_requires_the_same_attempted_and_unretired_owner() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    assert_eq!(
        context
            .take_interface(reservation.owner(), until(), token())
            .err(),
        Some(Error::Changed)
    );
    assert_eq!(
        context
            .take_interface(&owner("other", 1), until(), token())
            .err(),
        Some(Error::Unavailable)
    );
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert_eq!(
        context
            .take_interface(reservation.owner(), until(), token())
            .err(),
        Some(Error::Changed)
    );
    assert_eq!(state(&context).stage, record::Stage::Stopped);
    registry.release(&reservation).unwrap();
}

// Mutation: accept the received descriptor without the SDK same-socket check,
// or keep it cached after a refusal so a second take retries it.
#[test]
fn ordinary_received_descriptor_is_refused_once_dropped_and_closed() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    assert_eq!(
        context
            .take_interface(reservation.owner(), until(), token())
            .err(),
        Some(Error::Unavailable)
    );
    // The refusal consumed the cached descriptor: no retry, no second handoff.
    assert_eq!(
        context
            .take_interface(reservation.owner(), until(), token())
            .err(),
        Some(Error::Changed)
    );
    // EOF from the fixture's own peer proves the descriptor was really closed.
    let audit = fixture.directory.join("retain.audit");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut content = String::new();
    while Instant::now() < deadline {
        content = std::fs::read_to_string(&audit).unwrap_or_default();
        if content == "closed\n" {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        content, "closed\n",
        "the received descriptor was not closed"
    );
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    registry.release(&reservation).unwrap();
}

// Mutation: block on the producer mutex instead of honoring the take budget.
#[test]
fn take_interface_is_bounded_while_the_producer_mutex_is_held() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    let producer = peer.producer.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    thread::scope(|scope| {
        let holder = scope.spawn(move || {
            let _guard = producer.lock().unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        assert_eq!(
            context
                .take_interface(
                    reservation.owner(),
                    started + Duration::from_millis(200),
                    token()
                )
                .err(),
            Some(Error::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
    });
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    registry.release(&reservation).unwrap();
}

// Mutation: keep the cached descriptor after retire, so the last helper
// reference outlives the original child.
#[test]
fn retire_drops_an_untaken_descriptor_after_reaping_the_child() {
    let fixture = Fixture::new();
    let context = fixture.context();
    // The child connects this listener and sends that same stream over FD3.
    let listener = UnixListener::bind(fixture.directory.join("retain-peer.sock")).unwrap();
    let (mut registry, reservation, mut peer) = prepared(&context, "retire-eof", 1);
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    // Still open before the stop: the child keeps its own copy until it exits.
    stream.set_nonblocking(true).unwrap();
    let mut byte = [0u8; 1];
    assert!(
        matches!(stream.read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "the fixture peer closed before the retirement"
    );
    stream.set_nonblocking(false).unwrap();
    assert!(!peer.producer.lock().unwrap().child_exited());
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    // Child reaped and cached descriptor dropped: only the EOF can prove it.
    stream.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut eof = false;
    while Instant::now() < deadline {
        match stream.read(&mut byte) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(_) => break,
        }
    }
    assert!(eof, "the received descriptor was kept open after retire");
    registry.release(&reservation).unwrap();
}

// Mutation: reinstate the "retryable budget error" carve-out, so a canceled
// handoff is not latched and a fresh open can reach VICI without a capability.
#[test]
fn canceled_handoff_is_latched_and_a_fresh_open_cannot_reach_vici() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "handoff-silence", 1);
    let ready = fixture.directory.join("handoff.ready");
    let cancel = token();
    let signal = cancel.clone();
    let canceler = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "fixture never reached the handoff"
            );
            thread::sleep(Duration::from_millis(1));
        }
        signal.store(true, Ordering::Release);
    });
    // Cancellation lands while the receiver is waiting for the handoff.
    assert_eq!(
        peer.open(reservation.owner(), until(), cancel).err(),
        Some(Error::Canceled)
    );
    canceler.join().unwrap();
    let original = state(&context).child.clone();
    assert!(original.is_some());
    // A fresh call must be the latched cancellation, not a new socket wait.
    let started = Instant::now();
    assert_eq!(
        peer.open(
            reservation.owner(),
            started + Duration::from_millis(150),
            token()
        )
        .err(),
        Some(Error::Canceled)
    );
    assert!(started.elapsed() < Duration::from_millis(800));
    assert_eq!(state(&context).child, original);
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    registry.release(&reservation).unwrap();
}

// Mutation: block on the active-map mutex instead of retrying inside the
// deadline/cancel loop, so a held map outlives the caller's budget.
#[test]
fn take_interface_is_bounded_while_the_active_map_is_held() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    let holder_context = context.clone();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    thread::scope(|scope| {
        let holder = scope.spawn(move || {
            let _guard = holder_context.active.lock().unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        assert_eq!(
            context
                .take_interface(
                    reservation.owner(),
                    started + Duration::from_millis(200),
                    token()
                )
                .err(),
            Some(Error::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        let cancel = token();
        let signal = cancel.clone();
        let started = Instant::now();
        let timer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.store(true, Ordering::Release);
        });
        assert_eq!(
            context
                .take_interface(
                    reservation.owner(),
                    started + Duration::from_secs(5),
                    cancel
                )
                .err(),
            Some(Error::Canceled)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        timer.join().unwrap();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
    });
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    registry.release(&reservation).unwrap();
}
