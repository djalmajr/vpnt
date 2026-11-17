use super::*;
use crate::preferences::ProbeInterval;
use std::{cell::RefCell, rc::Rc, time::Duration};

struct Data {
    saved: Option<Preferences>,
    status: StartupStatus,
    applied: Vec<bool>,
    writes: Vec<Preferences>,
    outcome: Option<Result<StartupStatus, StartupFailure>>,
    fail_save: bool,
    reads: usize,
}
#[derive(Clone)]
struct Fake(Rc<RefCell<Data>>);
impl Fake {
    fn new(saved: Option<Preferences>, status: StartupStatus) -> Self {
        Self(Rc::new(RefCell::new(Data {
            saved,
            status,
            applied: vec![],
            writes: vec![],
            outcome: None,
            fail_save: false,
            reads: 0,
        })))
    }
}
impl Backend for Fake {
    fn load(&mut self) -> Result<Option<Preferences>, Error> {
        Ok(self.0.borrow().saved)
    }
    fn save(&mut self, value: Preferences) -> Result<(), Error> {
        let mut data = self.0.borrow_mut();
        if data.fail_save {
            return Err(Error::Storage);
        }
        data.writes.push(value);
        data.saved = Some(value);
        Ok(())
    }
    fn startup_status(&mut self) -> StartupStatus {
        let mut data = self.0.borrow_mut();
        data.reads += 1;
        data.status
    }
    fn set_startup(&mut self, enabled: bool) -> Result<StartupStatus, StartupFailure> {
        let mut data = self.0.borrow_mut();
        data.applied.push(enabled);
        let result = data.outcome.take().unwrap_or(Ok(if enabled {
            StartupStatus::Enabled
        } else {
            StartupStatus::Disabled
        }));
        if let Ok(status) = result {
            data.status = status;
        }
        result
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn changed(startup: bool) -> Preferences {
    Preferences {
        interval: ProbeInterval::SIXTY,
        notify: false,
        reconnect: true,
        startup,
    }
}

#[test]
fn restoring_cached_startup_never_registers_and_uses_actual_system_state() {
    let fake = Fake::new(Some(changed(true)), StartupStatus::Disabled);
    let host = Coordinator::restore(fake.clone()).unwrap();
    assert_eq!(host.current(), changed(false));
    let data = fake.0.borrow();
    assert!(data.applied.is_empty());
    assert!(data.writes.is_empty());
}
#[test]
fn other_preference_changes_do_not_undo_an_external_login_item_change() {
    let fake = Fake::new(None, StartupStatus::Disabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    fake.0.borrow_mut().status = StartupStatus::Enabled;
    assert_eq!(host.apply(changed(false), until()).unwrap(), changed(true));
    assert!(fake.0.borrow().applied.is_empty());
    assert_eq!(fake.0.borrow().writes, [changed(true)]);
}
#[test]
fn approval_required_is_not_reported_enabled_or_committed_as_success() {
    let fake = Fake::new(None, StartupStatus::Disabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    fake.0.borrow_mut().outcome = Some(Ok(StartupStatus::RequiresApproval));
    let failure = host.apply(changed(true), until()).unwrap_err();
    assert_eq!(failure.error, Error::StartupRequiresApproval);
    assert_eq!(failure.observed, Preferences::default());
    assert_eq!(host.current(), Preferences::default());
    assert_eq!(fake.0.borrow().applied, [true]);
    assert!(fake.0.borrow().writes.is_empty());
}
#[test]
fn an_expired_request_performs_no_backend_effect_or_observation() {
    let fake = Fake::new(None, StartupStatus::Disabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    let reads = fake.0.borrow().reads;
    let failure = host
        .apply(changed(true), Instant::now() - Duration::from_millis(1))
        .unwrap_err();
    assert_eq!(failure.error, Error::Expired);
    assert_eq!(fake.0.borrow().reads, reads);
    assert!(fake.0.borrow().writes.is_empty());
    assert!(fake.0.borrow().applied.is_empty());
}
#[test]
fn a_failed_system_call_preserves_the_observed_effect_and_other_choices() {
    let fake = Fake::new(None, StartupStatus::Disabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    fake.0.borrow_mut().outcome = Some(Err(StartupFailure {
        observed: Some(StartupStatus::Enabled),
    }));
    let failure = host.apply(changed(true), until()).unwrap_err();
    assert_eq!(failure.error, Error::StartupFailed);
    assert_eq!(
        failure.observed,
        Preferences {
            startup: true,
            ..Preferences::default()
        }
    );
    assert!(fake.0.borrow().writes.is_empty());
}
#[test]
fn failed_persistence_does_not_hide_a_completed_login_item_effect() {
    let fake = Fake::new(None, StartupStatus::Disabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    fake.0.borrow_mut().fail_save = true;
    let failure = host.apply(changed(true), until()).unwrap_err();
    assert_eq!(failure.error, Error::Storage);
    assert!(failure.observed.startup);
    assert_eq!(failure.observed.interval, ProbeInterval::TEN);
    assert!(!failure.observed.reconnect);
    assert_eq!(host.current(), failure.observed);
}
#[test]
fn valid_choices_are_persisted_and_restore_without_reapplying_startup() {
    let fake = Fake::new(None, StartupStatus::Disabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    assert_eq!(host.apply(changed(true), until()).unwrap(), changed(true));
    let restored = Coordinator::restore(fake.clone()).unwrap();
    assert_eq!(restored.current(), changed(true));
    assert_eq!(fake.0.borrow().applied, [true]);
    assert_eq!(fake.0.borrow().writes, [changed(true)]);
}

#[test]
fn unavailable_status_does_not_invent_that_a_previously_enabled_item_was_disabled() {
    let fake = Fake::new(Some(changed(true)), StartupStatus::Enabled);
    let mut host = Coordinator::restore(fake.clone()).unwrap();
    fake.0.borrow_mut().status = StartupStatus::Unavailable;
    assert_eq!(host.apply(changed(true), until()).unwrap(), changed(true));
    assert!(fake.0.borrow().applied.is_empty());
}
