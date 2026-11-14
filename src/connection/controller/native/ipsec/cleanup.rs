//! Cleanup protocol for the native IPsec attempt. Namespace/Control cleanup is
//! attempted first, then the original peer stop is made positive, the Driver
//! pin is dropped, and owned routes are released before the final namespace
//! callback. Uncertain or failed steps keep every resource for a later retry.
use super::*;
use crate::connection::ipsec::Peer;

impl NativeIpsecAttempt<'_> {
    pub(super) fn cleanup_driver(&mut self) -> bool {
        self.credentials = None;
        let fresh = || Instant::now() + Duration::from_secs(2);
        // Cleanup is a fresh non-canceled path; the connection cancel is
        // already set by the worker before this loop and must not deny it.
        let cleanup_cancel = AtomicBool::new(false);
        if let Some(control) = self.control.as_mut() {
            // First attempt must not be preceded by Admission::begin_cleanup;
            // this is the VICI cleanup/open window.
            let _ = control.cleanup(fresh());
        }
        let mut stopped = true;
        if let Some(admission) = self.admission.as_mut() {
            if admission.begin_cleanup().is_err() {
                return false;
            }
            match admission.retire(&self.owner) {
                Ok(true) => {
                    // Drop only the Driver-owned Arc after positive stop; the
                    // ledger remains responsible for its own strong pin until
                    // its release/fresh-absence path.
                    self.configured = None;
                }
                Ok(false) | Err(_) => return false,
            }
        }
        stopped = stopped && self.configured.is_none();
        if !stopped {
            return false;
        }
        if let Some(token) = self.token.as_ref() {
            let mut routes = match lock_until(&self.routes, fresh(), &cleanup_cancel) {
                Ok(routes) => routes,
                Err(_) => return false,
            };
            match routes.backend_mut().begin_cleanup(token) {
                Ok(true) => {}
                Ok(false) | Err(_) => return false,
            }
        }
        if let Some(lease) = self.lease.as_mut() {
            let mut routes = match lock_until(&self.routes, fresh(), &cleanup_cancel) {
                Ok(routes) => routes,
                Err(_) => return false,
            };
            match lease.release(&mut routes) {
                Ok(true) => {}
                Ok(false) | Err(_) => return false,
            }
        }
        {
            let mut routes = match lock_until(&self.routes, fresh(), &cleanup_cancel) {
                Ok(routes) => routes,
                Err(_) => return false,
            };
            let _ = routes.retry_cleanup();
            if routes.has_owner(&self.owner) {
                return false;
            }
            if routes.backend_mut().reap_retired().is_err() {
                return false;
            }
        }
        let mut finished = false;
        if let Some(token) = self.token.as_ref() {
            let mut routes = match lock_until(&self.routes, fresh(), &cleanup_cancel) {
                Ok(routes) => routes,
                Err(_) => return false,
            };
            if routes.backend_mut().finish_cleanup(token).is_err() {
                return false;
            }
            finished = true;
        }
        if finished {
            self.token = None;
        }
        if let Some(control) = self.control.as_mut() {
            // Only after route/pin obligations are clear may the registry's
            // durable completed callback release the namespace.
            match control.cleanup(fresh()) {
                Ok(true) => {}
                _ => return false,
            }
        }
        if self.control.is_none()
            && let Some(reservation) = self.reservation.take()
        {
            let mut registry = match lock_until(self.domain.registry(), fresh(), &cleanup_cancel) {
                Ok(registry) => registry,
                Err(_) => {
                    self.reservation = Some(reservation);
                    return false;
                }
            };
            if registry.release(&reservation).is_err() {
                self.reservation = Some(reservation);
                return false;
            }
        }
        if let Some(profile) = self.profile_use.as_ref()
            && profile.complete().is_err()
        {
            return false;
        }
        self.profile_use = None;
        true
    }
}
