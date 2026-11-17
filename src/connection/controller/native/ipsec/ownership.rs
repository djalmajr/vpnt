//! Small ownership carriers for the Driver. They are the actual code used by
//! start/cleanup, not parallel test helpers.
use super::*;
use crate::connection::{
    ipsec::{Error as IpsecError, Reservation},
    routes::{Backend, Coordinator, Error, Lease, Owner},
};

/// Keep the non-Clone Reservation alive across a successful prepare result.
/// Only Control construction may consume it later; this helper never takes it.
pub(super) fn keep_for_control<T>(
    reservation: &mut Option<Reservation>,
    prepared: Result<T, IpsecError>,
) -> Result<T, Failure> {
    reservation.as_ref().ok_or_else(Failure::unavailable)?;
    match prepared {
        Ok(value) => Ok(value),
        Err(_) => Err(Failure::unavailable()),
    }
}

/// Lease ownership and release state. Release consumes the opaque Lease once;
/// an invariant release error is latched so later calls cannot report success
/// merely because the coordinator no longer knows the owner.
pub(in crate::connection::controller::native) struct OwnedLease {
    lease: Option<Lease>,
    owner: Owner,
    failed: bool,
}

impl OwnedLease {
    pub(super) fn new(lease: Lease, owner: Owner) -> Self {
        Self {
            lease: Some(lease),
            owner,
            failed: false,
        }
    }

    pub(super) fn validate<B: Backend>(&self, routes: &mut Coordinator<B>) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Busy);
        }
        let lease = self.lease.as_ref().ok_or(Error::Invalid)?;
        routes.validate(lease)
    }

    /// true only when the owner claim is actually gone from this coordinator.
    /// A pending cleanup or an invariant release error keeps false/Err.
    pub(super) fn release<B: Backend>(
        &mut self,
        routes: &mut Coordinator<B>,
    ) -> Result<bool, Error> {
        if self.failed {
            return Err(Error::Busy);
        }
        if let Some(lease) = self.lease.take()
            && let Err(error) = routes.release(lease)
        {
            self.failed = true;
            return Err(error);
        }
        let _ = routes.retry_cleanup();
        Ok(!routes.has_owner(&self.owner))
    }
}

#[cfg(test)]
#[path = "ownership/tests.rs"]
mod tests;
