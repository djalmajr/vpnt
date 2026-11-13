//! Login-item control for the running app, backed by ServiceManagement.
//!
//! Only `SMAppService.mainAppService` is used: no daemon, agent or LoginItems
//! helper API, no plist and no path or identifier from the caller. Nothing here
//! registers, unregisters or opens System Settings on its own; the host calls
//! `set_enabled` from an explicit user action.
//!
//! The SDK marks these APIs `API_AVAILABLE(macos(13.0))` and imposes no main
//! thread (the bindings take no `MainThreadMarker`). The adapter keeps a retained
//! Objective-C object, so it is neither `Send` nor `Sync`: use it from one thread.
//! Apps that use `SMAppService` must be code signed; an unsigned development
//! build fails the native operation, which surfaces as `Error::Failed`, never as
//! success.

// The desktop actor that consumes this adapter belongs to the next slice; until
// then a production build has no caller for these items.
#![allow(dead_code)]

use objc2::{available, rc::Retained};
use objc2_foundation::NSBundle;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

/// The only bundle this adapter admits as the main application.
const BUNDLE_ID: &str = "dev.vpnt.app";

/// Login-item state reported by the SDK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Status {
    /// Never registered, or unregistered after being registered.
    NotRegistered,
    /// Registered and eligible to launch at login.
    Enabled,
    /// Registered, but the user must allow it in System Settings.
    RequiresApproval,
    /// The service could not be found for this bundle.
    NotFound,
}

/// Typed failures. No `NSError`, path or system text crosses this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    /// The binding cannot be used here: not the admitted bundle, macOS older
    /// than 13, or a status value this build does not understand.
    Unavailable,
    /// A native operation failed. `observed` is the status read after the
    /// failure when it could still be read, so the caller can keep the truth.
    Failed { observed: Option<Status> },
}

/// The raw service surface. The native implementation maps to `SMAppService`;
/// tests inject a private fake through `cfg(test)`.
trait Service {
    fn status(&self) -> isize;
    fn register(&self) -> Result<(), ()>;
    fn unregister(&self) -> Result<(), ()>;
}

pub(super) struct Adapter {
    service: Box<dyn Service>,
}

impl Adapter {
    /// Admits only the running `dev.vpnt.app` bundle. Constructors never change
    /// login-item state; there is deliberately no `Default`.
    pub(super) fn current_bundle() -> Result<Self, Error> {
        if !available!(macos = 13.0) {
            return Err(Error::Unavailable);
        }
        let identifier = NSBundle::mainBundle().bundleIdentifier();
        if !identifier.is_some_and(|value| value.to_string() == BUNDLE_ID) {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            service: Box::new(Native::new()),
        })
    }

    pub(super) fn status(&self) -> Result<Status, Error> {
        map_status(self.service.status())
    }

    /// Applies the explicit user choice, at most once, then reports the state
    /// the system actually holds. A pending approval is never reported as
    /// enabled, and a failed operation is never reported as success.
    pub(super) fn set_enabled(&self, enabled: bool) -> Result<Status, Error> {
        let settled = matches!(
            (enabled, self.status()?),
            (true, Status::Enabled | Status::RequiresApproval)
                | (false, Status::NotRegistered | Status::NotFound)
        );
        if !settled {
            let outcome = if enabled {
                self.service.register()
            } else {
                self.service.unregister()
            };
            if outcome.is_err() {
                return Err(Error::Failed {
                    observed: self.status().ok(),
                });
            }
        }
        self.status()
    }

    #[cfg(test)]
    fn fixture(service: Box<dyn Service>) -> Self {
        Self { service }
    }
}

/// Rejects values the SDK does not define instead of guessing a state.
fn map_status(raw: isize) -> Result<Status, Error> {
    let raw = SMAppServiceStatus(raw);
    if raw == SMAppServiceStatus::NotRegistered {
        Ok(Status::NotRegistered)
    } else if raw == SMAppServiceStatus::Enabled {
        Ok(Status::Enabled)
    } else if raw == SMAppServiceStatus::RequiresApproval {
        Ok(Status::RequiresApproval)
    } else if raw == SMAppServiceStatus::NotFound {
        Ok(Status::NotFound)
    } else {
        Err(Error::Unavailable)
    }
}

struct Native(Retained<SMAppService>);

impl Native {
    fn new() -> Self {
        // SAFETY: `mainAppService` has no preconditions beyond availability,
        // which the factory checked before constructing this value.
        Self(unsafe { SMAppService::mainAppService() })
    }
}

impl Service for Native {
    fn status(&self) -> isize {
        // SAFETY: retained class instance; reading the status mutates nothing.
        unsafe { self.0.status() }.0
    }
    fn register(&self) -> Result<(), ()> {
        // SAFETY: retained class instance; the SDK reports failure through the
        // returned error, which never leaves this adapter.
        unsafe { self.0.registerAndReturnError() }.map_err(|_| ())
    }
    fn unregister(&self) -> Result<(), ()> {
        // SAFETY: retained class instance, same contract as `register`.
        unsafe { self.0.unregisterAndReturnError() }.map_err(|_| ())
    }
}

#[cfg(test)]
#[path = "login_item/tests.rs"]
mod tests;
