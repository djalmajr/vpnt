use super::*;
use std::{cell::Cell, rc::Rc};

/// Private stand-in for the native service. Every call is counted so the tests
/// can prove "at most once" and the idempotent paths.
struct Fake {
    status: Cell<isize>,
    register_to: Cell<isize>,
    unregister_to: Cell<isize>,
    register_fails: Cell<bool>,
    unregister_fails: Cell<bool>,
    registers: Cell<u32>,
    unregisters: Cell<u32>,
}

impl Fake {
    fn new(status: isize) -> Rc<Self> {
        Rc::new(Self {
            status: Cell::new(status),
            register_to: Cell::new(status),
            unregister_to: Cell::new(status),
            register_fails: Cell::new(false),
            unregister_fails: Cell::new(false),
            registers: Cell::new(0),
            unregisters: Cell::new(0),
        })
    }
    fn register_to(self: &Rc<Self>, status: isize) -> Rc<Self> {
        self.register_to.set(status);
        self.clone()
    }
    fn unregister_to(self: &Rc<Self>, status: isize) -> Rc<Self> {
        self.unregister_to.set(status);
        self.clone()
    }
    fn register_fails(self: &Rc<Self>) -> Rc<Self> {
        self.register_fails.set(true);
        self.clone()
    }
    fn unregister_fails(self: &Rc<Self>) -> Rc<Self> {
        self.unregister_fails.set(true);
        self.clone()
    }
}

impl Service for Rc<Fake> {
    fn status(&self) -> isize {
        self.status.get()
    }
    fn register(&self) -> Result<(), ()> {
        self.registers.set(self.registers.get() + 1);
        // A failed registration can still move the service (for example to
        // `RequiresApproval`); the tests choose that post-error state.
        self.status.set(self.register_to.get());
        if self.register_fails.get() {
            return Err(());
        }
        Ok(())
    }
    fn unregister(&self) -> Result<(), ()> {
        self.unregisters.set(self.unregisters.get() + 1);
        self.status.set(self.unregister_to.get());
        if self.unregister_fails.get() {
            return Err(());
        }
        Ok(())
    }
}

fn adapter(fake: &Rc<Fake>) -> Adapter {
    Adapter::fixture(Box::new(fake.clone()))
}

// Mutation captured: dropping a status from the mapping, or folding two SDK
// states into one, misreports what the system holds.
#[test]
fn every_sdk_status_is_reported() {
    for (raw, expected) in [
        (0, Status::NotRegistered),
        (1, Status::Enabled),
        (2, Status::RequiresApproval),
        (3, Status::NotFound),
    ] {
        assert_eq!(adapter(&Fake::new(raw)).status(), Ok(expected), "{raw}");
    }
}

// Mutation captured: defaulting an unrecognised status to a real one hides
// binding/SDK drift and invents a user-visible state.
#[test]
fn unknown_raw_status_is_rejected() {
    for raw in [4, 5, 99, -1, isize::MIN, isize::MAX] {
        assert_eq!(
            adapter(&Fake::new(raw)).status(),
            Err(Error::Unavailable),
            "{raw}"
        );
    }
}

// Mutation captured: ignoring the settled state calls register on an item that
// is already enabled and breaks the "user choice does nothing else" contract.
#[test]
fn enabling_an_enabled_item_is_idempotent() {
    let fake = Fake::new(1);
    assert_eq!(adapter(&fake).set_enabled(true), Ok(Status::Enabled));
    assert_eq!(fake.registers.get(), 0, "no native operation when settled");
    assert_eq!(fake.unregisters.get(), 0);
}

// Mutation captured: reporting `RequiresApproval` as `Enabled` (or registering
// again) would show the toggle on while the user still has to approve it.
#[test]
fn pending_approval_is_preserved_and_never_becomes_enabled() {
    let fake = Fake::new(2);
    assert_eq!(
        adapter(&fake).set_enabled(true),
        Ok(Status::RequiresApproval)
    );
    assert_eq!(fake.registers.get(), 0);
    assert_eq!(fake.status.get(), 2);
}

// Mutation captured: unregistering an item that is already off asks the system
// for a change the user did not make (and can fail with JobNotFound).
#[test]
fn disabling_is_idempotent_when_unregistered_or_missing() {
    for raw in [0, 3] {
        let fake = Fake::new(raw);
        assert!(adapter(&fake).set_enabled(false).is_ok(), "{raw}");
        assert_eq!(fake.unregisters.get(), 0, "{raw}");
        assert_eq!(fake.status.get(), raw, "{raw}");
    }
}

// Mutation captured: registering twice, or returning a guessed state instead of
// the one the system reports afterwards.
#[test]
fn enabling_registers_once_and_returns_the_observed_status() {
    let fake = Fake::new(0).register_to(2);
    assert_eq!(
        adapter(&fake).set_enabled(true),
        Ok(Status::RequiresApproval)
    );
    assert_eq!(fake.registers.get(), 1, "exactly one register");
    assert_eq!(fake.unregisters.get(), 0);
}

// Mutation captured: treating `NotFound` as a settled state would silently do
// nothing for a bundle whose service state the system cannot resolve.
#[test]
fn enabling_a_missing_item_attempts_registration_once() {
    let fake = Fake::new(3).register_to(3);
    assert_eq!(adapter(&fake).set_enabled(true), Ok(Status::NotFound));
    assert_eq!(fake.registers.get(), 1);
}

// Mutation captured: calling unregister more than once, or reporting the state
// the caller asked for instead of the state the system now holds.
#[test]
fn disabling_unregisters_once_and_returns_the_observed_status() {
    for raw in [1, 2] {
        let fake = Fake::new(raw).unregister_to(0);
        assert_eq!(adapter(&fake).set_enabled(false), Ok(Status::NotRegistered));
        assert_eq!(fake.unregisters.get(), 1, "{raw}");
        assert_eq!(fake.registers.get(), 0, "{raw}");
    }
}

// Mutation captured: swallowing the native error and reporting the status as a
// success, which would leave the toggle enabled while nothing is registered.
#[test]
fn register_failure_is_an_error_with_the_observed_status() {
    let fake = Fake::new(0).register_to(2).register_fails();
    assert_eq!(
        adapter(&fake).set_enabled(true),
        Err(Error::Failed {
            observed: Some(Status::RequiresApproval)
        })
    );
    assert_eq!(fake.registers.get(), 1);
}

// Mutation captured: turning a failed unregister into `NotRegistered` success.
#[test]
fn unregister_failure_never_reports_success() {
    let fake = Fake::new(1).unregister_to(1).unregister_fails();
    assert_eq!(
        adapter(&fake).set_enabled(false),
        Err(Error::Failed {
            observed: Some(Status::Enabled)
        })
    );
    assert_eq!(fake.unregisters.get(), 1);
}

// Mutation captured: inventing an observation (or panicking) when the service
// reports a state this build cannot read after a failure.
#[test]
fn failure_with_unreadable_status_carries_no_observation() {
    let fake = Fake::new(0).register_to(99).register_fails();
    assert_eq!(
        adapter(&fake).set_enabled(true),
        Err(Error::Failed { observed: None })
    );
}

// Mutation captured: admitting any bundle (or skipping the availability gate)
// would let a dev binary drive the login item of a different application. This
// reads bundle metadata only; no ServiceManagement call is made.
#[test]
fn unbundled_test_binary_is_not_admitted() {
    let identifier = NSBundle::mainBundle().bundleIdentifier();
    assert!(
        !identifier.is_some_and(|value| value.to_string() == BUNDLE_ID),
        "the test binary must not run as the app bundle"
    );
    assert_eq!(Adapter::current_bundle().err(), Some(Error::Unavailable));
}
