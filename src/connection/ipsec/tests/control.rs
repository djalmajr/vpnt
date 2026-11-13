use super::*;
use std::{sync::atomic::AtomicBool, time::Instant};
struct NoPeer;
impl Peer for NoPeer {
    fn open(
        &mut self,
        _: &Owner,
        _: Instant,
        _: Arc<AtomicBool>,
    ) -> Result<crate::helper::vici::Client, Error> {
        Err(Error::Unavailable)
    }
    fn retire(&mut self, _: &Owner) -> Result<bool, Error> {
        Ok(false)
    }
}

// Mutations: omit the config binding, its registry authority, or its serial.
#[test]
fn constructor_returns_the_reservation_when_config_belongs_to_another_or_retired_admission() {
    for foreign in [false, true] {
        let observation = Observation::default();
        observation.0.lock().unwrap().stopped = true;
        let mut registry = Registry::new(observation.clone());
        let old = registry.reserve(owner("Case", 1)).unwrap();
        let config = config(&registry, &old, &profile()).unwrap();
        registry.release(&old).unwrap();
        let mut registry = if foreign {
            Registry::new(observation)
        } else {
            registry
        };
        let reservation = registry.reserve(owner("Case", 1)).unwrap();
        let registry = Arc::new(Mutex::new(registry));
        let (error, returned) = match Control::new(registry.clone(), reservation, config, NoPeer) {
            Err(result) => result,
            Ok(_) => panic!("configuration crossed an admission boundary"),
        };
        assert_eq!(error, Error::Changed);
        registry.lock().unwrap().validate(&returned).unwrap();
        registry.lock().unwrap().release(&returned).unwrap();
        assert!(!registry.lock().unwrap().has_reservations());
    }
}

use super::control_peer::{Harness, TestPeer};
type RegistryHandle = Arc<Mutex<Registry<Observation>>>;
type Controller = Control<Observation, TestPeer>;
fn until() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn token() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
fn setup(mode: &str, collide: bool) -> (Controller, Harness, Observation, RegistryHandle) {
    let observation = Observation::default();
    let mut registry = Registry::new(observation.clone());
    let reservation = registry.reserve(owner("Case", 7)).unwrap();
    let mut p = profile();
    if mode == "ipv6" {
        p.networks = vec!["2001:db8:20::/64".into()];
    }
    if mode == "mismatch-family" {
        p.networks.clear();
    }
    let config = config(&registry, &reservation, &p).unwrap();
    let registry = Arc::new(Mutex::new(registry));
    let (peer, harness) = TestPeer::new(mode, registry.clone(), observation.clone(), collide);
    let control = Control::new(registry.clone(), reservation, config, peer).unwrap();
    (control, harness, observation, registry)
}
fn settle(
    control: &mut Controller,
    harness: &Harness,
    observation: &Observation,
    registry: &RegistryHandle,
) {
    harness.stop();
    {
        let mut k = observation.0.lock().unwrap();
        k.stopped = true;
        k.occupied.clear();
    }
    assert_eq!(control.cleanup(until()), Ok(true));
    assert!(!registry.lock().unwrap().has_reservations());
    assert_eq!(control.phase(), Phase::Released);
}

// Mutations: omit version admission, replay an attempt, skip dirty/cleanup
// retention, or release based on only VICI success/producer exit/kernel absence.
#[test]
fn lifecycle_retains_uncertainty_and_requires_both_producer_and_kernel_absence_without_replay() {
    let (mut control, harness, observation, registry) = setup("terminate:1", false);
    control.start(creds(), until(), token()).unwrap();
    assert_eq!(control.phase(), Phase::Initiated);
    let initial = vec![
        "version",
        "stats",
        "load-conn",
        "load-shared",
        "load-shared",
        "initiate",
    ];
    assert_eq!(harness.audit(), initial);
    assert_eq!(
        control.start(creds(), until(), token()),
        Err(Error::Changed)
    );
    observation.0.lock().unwrap().stopped = true;
    assert_eq!(control.cleanup(until()), Ok(false));
    assert_eq!(control.phase(), Phase::Dirty);
    assert!(!harness.process.lock().unwrap().exited());
    assert!(registry.lock().unwrap().has_reservations());
    let cleanup = harness.audit();
    assert_eq!(
        &cleanup[6..],
        &["terminate", "unload-conn", "unload-shared", "unload-shared"]
    );
    assert_eq!(control.cleanup(until()), Ok(false));
    assert_eq!(
        harness.audit(),
        cleanup,
        "cleanup replayed an uncertain command"
    );
    harness.stop();
    observation.0.lock().unwrap().stopped = false;
    assert_eq!(control.cleanup(until()), Ok(false));
    {
        let mut k = observation.0.lock().unwrap();
        k.stopped = true;
        k.occupied.insert(16383);
    }
    assert_eq!(control.cleanup(until()), Ok(false));
    assert!(registry.lock().unwrap().has_reservations());
    settle(&mut control, &harness, &observation, &registry);
    assert_eq!(control.cleanup(Instant::now()), Ok(true));
    assert_eq!(harness.audit(), cleanup);
}

// Mutations: accept a failed response, replay start, or mark
// load uncertainty only after a positive reply and omit its targeted cleanup.
#[test]
fn every_failed_start_prefix_is_redacted_consumed_and_targeted_for_cleanup() {
    for (mode, length, error) in [
        ("incompatible", 1, Error::Incompatible),
        ("incompatible-daemon", 1, Error::Incompatible),
        ("load-conn:1", 3, Error::Rejected),
        ("load-shared:1", 4, Error::Rejected),
        ("load-shared:2", 5, Error::Rejected),
        ("initiate:1", 6, Error::Rejected),
    ] {
        let (mut control, harness, observation, registry) = setup(mode, false);
        let result = control.start(creds(), until(), token());
        assert_eq!(result, Err(error), "prefix failure ignored: {mode}");
        assert_eq!(control.phase(), Phase::Dirty);
        assert_eq!(harness.audit().len(), length);
        assert!(!format!("{result:?}").contains("fictional-secret"));
        assert_eq!(
            control.start(creds(), until(), token()),
            Err(Error::Changed)
        );
        assert_eq!(
            harness.audit().len(),
            length,
            "failed start replayed: {mode}"
        );
        assert_eq!(control.cleanup(until()), Ok(false));
        let audit = harness.audit();
        assert_eq!(
            audit.iter().filter(|s| *s == "unload-conn").count(),
            usize::from(!mode.starts_with("incompatible")),
            "lost load uncertainty: {mode}"
        );
        assert_eq!(
            audit.iter().filter(|s| *s == "terminate").count(),
            usize::from(!mode.starts_with("incompatible"))
        );
        settle(&mut control, &harness, &observation, &registry);
    }
}

// Mutations: skip fresh namespace admission or ignore canceled/expired input.
#[test]
fn namespace_conflict_and_preflight_cancellation_cannot_reach_initiate() {
    let (mut control, harness, observation, registry) = setup("normal", true);
    assert_eq!(control.start(creds(), until(), token()), Err(Error::Busy));
    assert_eq!(
        harness.audit(),
        vec![
            "version",
            "stats",
            "load-conn",
            "load-shared",
            "load-shared"
        ]
    );
    assert_eq!(control.cleanup(Instant::now()), Ok(false));
    settle(&mut control, &harness, &observation, &registry);
    for canceled in [false, true] {
        let (mut control, harness, observation, registry) = setup("normal", false);
        let result = control.start(
            creds(),
            if canceled { until() } else { Instant::now() },
            Arc::new(AtomicBool::new(canceled)),
        );
        assert_eq!(
            result,
            Err(if canceled {
                Error::Canceled
            } else {
                Error::Timeout
            })
        );
        assert!(harness.audit().is_empty());
        settle(&mut control, &harness, &observation, &registry);
    }
}

mod backend;
mod io;
mod selected;
mod snapshots;
