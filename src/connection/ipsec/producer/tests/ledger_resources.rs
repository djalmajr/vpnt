//! Phase2 pin/admission tests. Real C/VICI where possible; the opaque
//! ConfiguredUtun/RetainedInterface origin is NOT fabricated and remains static.
use super::super::{Fixture, owner, token, until};
use super::*;
use crate::connection::ipsec::{Candidate, Control, Error, NativeLedger, Registry};
use crate::connection::macos::routing::ResourceFence;
use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

fn candidate() -> Candidate {
    Candidate {
        ike_id: 1,
        child_id: 2,
        reqid: 0,
        local: "192.0.2.2".parse().unwrap(),
        remote: "198.51.100.3".parse().unwrap(),
        local_port: 500,
        remote_port: 500,
        udp_encap: false,
        spi_in: 1,
        spi_out: 2,
        local_ts: vec![],
        remote_ts: vec![],
        vips: vec!["10.20.0.9".parse().unwrap()],
        active: false,
    }
}

#[test]
fn real_control_cleanup_marks_draining_and_releases_durable_claim() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![Ok(true)]));
    let registry = Arc::new(Mutex::new(Registry::new(
        context.userspace_observer(ledger.clone()),
    )));
    let reservation = registry
        .lock()
        .unwrap()
        .reserve(owner("control", 70))
        .unwrap();
    let profile = profile("control");
    let (config, mut admission) = {
        let registry = registry.lock().unwrap();
        ledger
            .prepare(
                &registry,
                &reservation,
                &profile,
                egress(&profile),
                (until(), token()),
            )
            .unwrap()
    };
    let opened = admission
        .open(reservation.owner(), until(), token())
        .unwrap();
    let response = opened
        .command("version", Message::new(), &[])
        .unwrap()
        .response;
    assert_eq!(response.get_text("version"), Some("6.1.0"));
    let raw = admission.raw_peer_for_test();
    let mut control = Control::new(registry.clone(), reservation, config, admission).unwrap();
    assert_eq!(control.cleanup(until()), Ok(true));
    assert_eq!(control.phase(), crate::connection::ipsec::Phase::Released);
    assert!(raw.lock().unwrap().producer.lock().unwrap().child_exited());
    assert!(context.store.records().unwrap().is_empty());
    assert!(!ledger.has_resources());
}

#[test]
fn draining_admission_refuses_new_pin_work_without_manual_begin_cleanup() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("refuse", 71)).unwrap();
    let profile = profile("refuse");
    let (_, admission) = prepared(&ledger, &registry, &reservation, &profile);
    admission.begin_cleanup().unwrap();
    assert_eq!(
        admission.capture_interface(until(), token()).err(),
        Some(Error::Changed)
    );
    assert_eq!(
        admission
            .configure(&candidate(), until(), token())
            .map(|_| ())
            .err(),
        Some(Error::Changed)
    );
    assert_eq!(
        admission.begin_routes(until(), token()).err(),
        Some(Error::Changed)
    );
}

#[test]
fn pin_work_requires_opened_captured_and_configured_states() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("states", 72)).unwrap();
    let profile = profile("states");
    let (_, admission) = prepared(&ledger, &registry, &reservation, &profile);
    assert_eq!(
        admission.capture_interface(until(), token()).err(),
        Some(Error::Changed),
        "capture requires the same peer opened"
    );
    assert_eq!(
        admission.begin_routes(until(), token()).err(),
        Some(Error::Changed)
    );
}

#[test]
fn actual_claims_observe_injected_passive_route_fence() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut ledger =
        NativeLedger::scripted(context.clone(), Scripted::new(vec![Ok(true), Ok(true)]));
    let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
    let reservation = registry.reserve(owner("fence", 73)).unwrap();
    let profile = profile("fence");
    let (_, admission) = prepared(&ledger, &registry, &reservation, &profile);
    let (fence, work) = ResourceFence::begin(reservation.owner()).unwrap();
    admission.inject_route_fence_for_test(fence);
    let raw = admission.raw_peer_for_test();
    raw.lock().unwrap().retire(reservation.owner()).unwrap();
    admission.begin_cleanup().unwrap();
    // First query may conservatively report the observed-stop version change.
    let _ = ledger.pending_owners();
    assert_eq!(
        ledger.pending_owners().unwrap(),
        vec![reservation.owner().clone()]
    );
    assert_eq!(registry.release(&reservation), Err(Error::Busy));
    drop(work);
    assert!(ledger.pending_owners().unwrap().is_empty());
    registry.release(&reservation).unwrap();
    assert!(!ledger.has_resources());
}

#[test]
fn grant_map_waits_honor_the_caller_budget_before_the_phase_gate() {
    for mode in ["deadline", "cancel"] {
        let fixture = Fixture::new();
        let context = fixture.context();
        let ledger = NativeLedger::scripted(context.clone(), Scripted::new(vec![]));
        let mut registry = Registry::new(context.userspace_observer(ledger.clone()));
        let reservation = registry.reserve(owner("grant", 74)).unwrap();
        let profile = profile("grant");
        let (_, admission) = prepared(&ledger, &registry, &reservation, &profile);
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
                    flag.store(true, std::sync::atomic::Ordering::Release);
                });
            }
            let expected = if mode == "deadline" {
                Error::Timeout
            } else {
                Error::Canceled
            };
            let started = Instant::now();
            assert_eq!(
                admission.native_peer(expires, cancel.clone()).err(),
                Some(expected)
            );
            assert!(started.elapsed() < Duration::from_secs(1), "{mode}");
            let started = Instant::now();
            assert_eq!(
                admission.begin_routes(expires, cancel).err(),
                Some(expected)
            );
            assert!(started.elapsed() < Duration::from_secs(1), "{mode}");
            drop(release_tx);
        });
    }
}
