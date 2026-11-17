use super::*;
use crate::preferences::host::{Backend, Coordinator, Error, StartupFailure, StartupStatus};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct Observed {
    saved: Option<Preferences>,
    enabled: bool,
    actions: Vec<bool>,
    fail_after_effect: bool,
}
#[derive(Clone, Default)]
struct BackendFixture(Rc<RefCell<Observed>>);
impl Backend for BackendFixture {
    fn load(&mut self) -> Result<Option<Preferences>, Error> {
        Ok(self.0.borrow().saved)
    }
    fn save(&mut self, value: Preferences) -> Result<(), Error> {
        self.0.borrow_mut().saved = Some(value);
        Ok(())
    }
    fn startup_status(&mut self) -> StartupStatus {
        if self.0.borrow().enabled {
            StartupStatus::Enabled
        } else {
            StartupStatus::Disabled
        }
    }
    fn set_startup(&mut self, value: bool) -> Result<StartupStatus, StartupFailure> {
        let mut observed = self.0.borrow_mut();
        observed.actions.push(value);
        observed.enabled = value;
        let status = if value {
            StartupStatus::Enabled
        } else {
            StartupStatus::Disabled
        };
        if observed.fail_after_effect {
            Err(StartupFailure {
                observed: Some(status),
            })
        } else {
            Ok(status)
        }
    }
}
fn attached(backend: BackendFixture) -> Broker<NoSecrets> {
    broker().with_preferences_host(Box::new(Coordinator::restore(backend).unwrap()))
}
#[test]
fn a_failed_real_store_never_reports_a_volatile_choice_as_persisted() {
    let mut broker = broker().with_preferences_host(Box::new(
        crate::preferences::host::Unavailable::new(Error::Storage),
    ));
    assert_eq!(
        broker
            .dispatch(
                Command::SetPreferences {
                    preferences: Preferences::default()
                },
                deadline()
            )
            .err(),
        Some("preferences_unavailable")
    );
    assert!(!broker.snapshot().preferences.notify);
    assert!(!broker.snapshot().preferences.reconnect);
}
#[test]
fn broker_dispatch_applies_the_injected_host_and_restores_without_registration() {
    let backend = BackendFixture::default();
    let mut broker = attached(backend.clone());
    let chosen = Preferences {
        interval: ProbeInterval::SIXTY,
        notify: false,
        reconnect: true,
        startup: true,
    };
    assert_eq!(submit(&mut broker, chosen).preferences, chosen);
    assert_eq!(backend.0.borrow().actions, [true]);
    assert_eq!(backend.0.borrow().saved, Some(chosen));
    drop(broker);
    assert_eq!(attached(backend.clone()).snapshot().preferences, chosen);
    assert_eq!(backend.0.borrow().actions, [true]);
}
#[test]
fn broker_reports_observed_startup_after_failure_and_does_not_commit_other_values() {
    let backend = BackendFixture::default();
    backend.0.borrow_mut().fail_after_effect = true;
    let mut broker = attached(backend.clone());
    assert_eq!(
        broker
            .dispatch(
                Command::SetPreferences {
                    preferences: Preferences {
                        interval: ProbeInterval::SIXTY,
                        notify: false,
                        reconnect: true,
                        startup: true,
                    }
                },
                deadline()
            )
            .err(),
        Some("startup_unavailable")
    );
    assert_eq!(
        broker.snapshot().preferences,
        Preferences {
            startup: true,
            ..Preferences::default()
        }
    );
    assert!(backend.0.borrow().saved.is_none());
}
