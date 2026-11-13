use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

fn state(context: &NativeContext<'_>) -> record::Record {
    context.store.records().unwrap()[0].clone()
}

fn prepared<'a>(
    context: &Arc<NativeContext<'a>>,
    id: &str,
    generation: u64,
) -> (
    Registry<NativeObserver<'a, Kernel>>,
    Reservation,
    NativePeer<'a>,
) {
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner(id, generation)).unwrap();
    let configuration = config(&registry, &reservation);
    let peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    (registry, reservation, peer)
}

// Mutation: admit an unattempted producer, so the prepared attempt is probed
// and reports `Unavailable` instead of being rejected as changed.
#[test]
fn prepared_unattempted_observation_is_rejected_without_spawn() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let before = state(&context);
    assert_eq!(
        context.observe_interface(reservation.owner(), until(), token()),
        Err(Error::Changed)
    );
    assert_eq!(state(&context), before);
    assert!(peer.producer.lock().unwrap().child_exited());
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    registry.release(&reservation).unwrap();
    assert!(context.active.lock().unwrap().is_empty());
}

// Mutation: match the wrong owner in the public lookup, so the producer's own
// owner guard turns the rejection into `Changed` instead of `Unavailable`.
#[test]
fn unknown_and_wrong_owner_are_rejected_without_spawn() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let before = state(&context);
    for wrong in [owner("other", 1), owner("normal", 99)] {
        assert_eq!(
            context.observe_interface(&wrong, until(), token()),
            Err(Error::Unavailable)
        );
    }
    assert_eq!(state(&context), before);
    assert!(peer.producer.lock().unwrap().child_exited());
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    registry.release(&reservation).unwrap();
}

// Mutation: map the native scanner's not-found result to `Changed`, so the
// public path no longer reports the absence of a utun as `Unavailable`.
#[test]
fn public_observation_reaches_the_native_scanner_without_a_utun() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    let before = state(&context);
    assert_eq!(
        context.observe_interface(reservation.owner(), until(), token()),
        Err(Error::Unavailable)
    );
    assert_eq!(state(&context), before);
    assert!(!peer.producer.lock().unwrap().child_exited());
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    registry.release(&reservation).unwrap();
}

// Mutation: drop the retired guard, so a stopped attempt is probed and
// reports `Unavailable` instead of the durable `Changed` rejection.
#[test]
fn retired_and_released_attempts_are_rejected_without_respawn() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (mut registry, reservation, mut peer) = prepared(&context, "normal", 1);
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    let stopped = state(&context);
    assert_eq!(stopped.stage, record::Stage::Stopped);
    assert_eq!(
        context.observe_interface(reservation.owner(), until(), token()),
        Err(Error::Changed)
    );
    assert_eq!(state(&context), stopped);
    assert!(peer.producer.lock().unwrap().child_exited());
    registry.release(&reservation).unwrap();
    assert!(context.active.lock().unwrap().is_empty());
    assert_eq!(
        context.observe_interface(reservation.owner(), until(), token()),
        Err(Error::Unavailable)
    );
}

// Mutation: replace the bounded `try_lock` with a blocking lock, so the public
// call waits for the holder instead of honoring its own deadline/cancel.
#[test]
fn public_observation_is_bounded_while_the_producer_mutex_is_held() {
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
            context.observe_interface(
                reservation.owner(),
                Instant::now() + Duration::from_millis(200),
                token()
            ),
            Err(Error::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
    });

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
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let timer = thread::spawn(move || {
            started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            signal.store(true, Ordering::Release);
        });
        started_tx.send(()).unwrap();
        let started = Instant::now();
        assert_eq!(
            context.observe_interface(
                reservation.owner(),
                Instant::now() + Duration::from_secs(5),
                cancel
            ),
            Err(Error::Canceled)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        timer.join().unwrap();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
    });

    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    registry.release(&reservation).unwrap();
}

mod retained;
