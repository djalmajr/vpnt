//! Lifecycle/domain/map/serial regressions for the resource ledger. The C
//! producer and VICI are real; absence is explicitly synthetic.
use super::super::bound::{egress, profile};
use super::super::{Fixture, owner, token, until};
use super::*;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[test]
fn admission_map_wait_is_bounded_and_retry_reaches_vici() {
    for mode in ["deadline", "cancel"] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
        let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
        let reservation = registry.reserve(owner("map-wait", 50)).unwrap();
        let profile = profile("map-wait");
        let (_, mut admission) = prepared(&ledger, &registry, &reservation, &profile);
        let holder = ledger.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        thread::scope(|scope| {
            scope.spawn(move || {
                let _guard = holder.entries_lock();
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
            let result = admission.open(reservation.owner(), expires, cancel);
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
            drop(release_tx);
        });
        assert!(
            admission
                .raw_peer_for_test()
                .lock()
                .unwrap()
                .producer
                .lock()
                .unwrap()
                .child_exited(),
            "{mode}: child spawned before the map wait"
        );
        let opened = admission
            .open(reservation.owner(), until(), token())
            .unwrap();
        let response = opened
            .command("version", Message::new(), &[])
            .unwrap()
            .response;
        assert_eq!(response.get_text("version"), Some("6.1.0"), "{mode}");
        let _ = admission.retire(reservation.owner());
    }
}

#[test]
fn serial_exhaustion_keeps_claim_and_stays_exhausted() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let first = registry.reserve(owner("serial-a", 51)).unwrap();
    let first_profile = profile("serial-a");
    let (_, _admission) = prepared(&ledger, &registry, &first, &first_profile);
    ledger.set_next_for_test(u64::MAX);
    let second = registry.reserve(owner("serial-b", 52)).unwrap();
    let second_profile = profile("serial-b");
    for _ in 0..2 {
        assert_eq!(
            ledger
                .prepare(
                    &registry,
                    &second,
                    &second_profile,
                    egress(&second_profile),
                    (until(), token())
                )
                .map(|_| ()),
            Err(Error::Exhausted)
        );
    }
    assert_eq!(
        ledger.pending_owners().unwrap(),
        vec![first.owner().clone()]
    );
    assert!(ledger.has_resources());
}

#[test]
fn context_claim_is_singleton_and_clone_shares_claims() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    assert_eq!(NativeLedger::new(context.clone()).err(), Some(Error::Busy));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("singleton", 53)).unwrap();
    let profile = profile("singleton");
    let (_, _admission) = prepared(&ledger, &registry, &reservation, &profile);
    let mut clone = ledger.clone();
    assert_eq!(
        clone.pending_owners().unwrap(),
        vec![reservation.owner().clone()]
    );
    assert_eq!(NativeLedger::new(context.clone()).err(), Some(Error::Busy));
    drop(ledger);
    assert_eq!(NativeLedger::new(context.clone()).err(), Some(Error::Busy));
    drop(clone);
    drop(_admission);
    assert_eq!(NativeLedger::new(context.clone()).err(), Some(Error::Busy));
}

#[test]
fn observed_stop_syncs_before_release_and_completed_removes() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger = NativeLedger::scripted(
        context.clone(),
        Scripted::new(vec![Ok(true), Ok(true), Ok(true)]),
    );
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("observed", 54)).unwrap();
    let profile = profile("observed");
    let (_, mut admission) = prepared(&ledger, &registry, &reservation, &profile);
    let opened = admission
        .open(reservation.owner(), until(), token())
        .unwrap();
    let response = opened
        .command("version", Message::new(), &[])
        .unwrap()
        .response;
    assert_eq!(response.get_text("version"), Some("6.1.0"));
    let peer = admission.raw_peer_for_test();
    peer.lock().unwrap().retire(reservation.owner()).unwrap();
    admission.begin_cleanup().unwrap();
    assert_eq!(ledger.pending_owners().err(), Some(Error::Changed));
    assert!(ledger.pending_owners().unwrap().is_empty());
    registry.release(&reservation).unwrap();
    assert!(!ledger.has_resources());
    assert_eq!(admission.retire(reservation.owner()), Ok(true));
}

struct Slow {
    first: AtomicBool,
    started: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Slow {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        (
            Arc::new(Self {
                first: AtomicBool::new(true),
                started: Mutex::new(started_tx),
                release: Mutex::new(release_rx),
            }),
            started_rx,
            release_tx,
        )
    }
}

impl Absence for Slow {
    fn complete(&self) -> Result<bool, Error> {
        if self.first.swap(false, Ordering::AcqRel) {
            self.started.lock().unwrap().send(()).unwrap();
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2));
        }
        Ok(false)
    }
}

#[test]
fn concurrent_begin_cleanup_during_absence_invalidates_version() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let (slow, started, release) = Slow::new();
    let mut ledger = NativeLedger::scripted(context.clone(), slow);
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let first = registry.reserve(owner("life-a", 55)).unwrap();
    let first_profile = profile("life-a");
    let (_, admission_a) = prepared(&ledger, &registry, &first, &first_profile);
    let second = registry.reserve(owner("life-b", 56)).unwrap();
    let second_profile = profile("life-b");
    let (_, admission_b) = prepared(&ledger, &registry, &second, &second_profile);
    let peer = admission_a.raw_peer_for_test();
    peer.lock().unwrap().retire(first.owner()).unwrap();
    admission_a.begin_cleanup().unwrap();
    thread::scope(|scope| {
        let ledger = &mut ledger;
        let query = scope.spawn(move || ledger.pending_owners());
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        admission_b.begin_cleanup().unwrap();
        release.send(()).unwrap();
        assert_eq!(query.join().unwrap().err(), Some(Error::Changed));
    });
}
