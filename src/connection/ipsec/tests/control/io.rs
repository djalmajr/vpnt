use super::*;

// Mutation: lose cancellation/deadline between lifecycle and VICI transport.
#[test]
fn cancellation_during_initiate_keeps_the_live_producer_reserved_and_does_not_replay() {
    use std::sync::atomic::Ordering;
    let (mut control, harness, observation, registry) = setup("hold-initiate", false);
    let cancel = token();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| control.start(creds(), until(), cancel.clone()));
        harness.wait_for("initiate");
        cancel.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), Err(Error::Canceled));
    });
    assert!(!harness.process.lock().unwrap().exited());
    assert!(registry.lock().unwrap().has_reservations());
    assert_eq!(
        control.start(creds(), until(), token()),
        Err(Error::Changed)
    );
    assert_eq!(harness.audit().len(), 6);
    assert_eq!(control.cleanup(until()), Ok(false));
    settle(&mut control, &harness, &observation, &registry);
}

// Mutation: validation failure skips retirement of the originally owned peer.
#[test]
fn registry_failure_still_requests_producer_retirement_and_retains_the_claim() {
    use std::sync::atomic::Ordering;
    let (mut control, harness, _, registry) = setup("normal", false);
    control.start(creds(), until(), token()).unwrap();
    let other = registry.clone();
    assert!(
        std::thread::spawn(move || {
            let _lock = other.lock().unwrap();
            panic!("fixture poison");
        })
        .join()
        .is_err()
    );
    harness.retire.store(true, Ordering::Release);
    assert_eq!(control.cleanup(until()), Err(Error::Unavailable));
    harness.wait_exit();
    assert!(match registry.lock() {
        Err(e) => e.into_inner().has_reservations(),
        Ok(_) => false,
    });
}

// Mutation: replace the caller's VICI deadline with a fresh timeout.
#[test]
fn deadline_during_initiate_returns_while_the_producer_is_alive_and_cleanup_has_its_own_budget() {
    let (mut control, harness, observation, registry) = setup("hold-initiate", false);
    let started = Instant::now();
    assert_eq!(
        control.start(creds(), started + Duration::from_millis(150), token()),
        Err(Error::Timeout)
    );
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "lifecycle deadline was extended"
    );
    assert!(!harness.process.lock().unwrap().exited());
    assert_eq!(harness.audit().len(), 6);
    assert_eq!(control.cleanup(until()), Ok(false));
    assert!(harness.audit().iter().any(|s| s == "terminate"));
    settle(&mut control, &harness, &observation, &registry);
}
