//! Passive completion fence for one linear route-work chain.
//!
//! `ResourceFence` is the passive, cloneable observation handle. `RouteWork`
//! is the single linear handle that must travel with the actual cleanup owner
//! and may complete the fence only after stop and fresh absence. Neither type
//! grants namespace, route or cleanup authority.
use crate::{
    connection::routes::{Error, Owner},
    model::valid_profile_id,
};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

const PENDING: u8 = 0;
const BOUND: u8 = 1;
const COMPLETED: u8 = 2;

pub struct ResourceFence {
    state: Arc<AtomicU8>,
    owner: Owner,
}

impl Clone for ResourceFence {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            owner: self.owner.clone(),
        }
    }
}

impl ResourceFence {
    /// Mint one passive fence plus its linear work handle. Only the ledger
    /// integration is expected to call this in production; the private phase
    /// intentionally leaves it unconsumed (no public constructor just to hide
    /// the expected warning).
    pub(crate) fn begin(owner: &Owner) -> Result<(Self, RouteWork), Error> {
        if owner.uid == 0 || owner.generation == 0 || !valid_profile_id(&owner.profile) {
            return Err(Error::Invalid);
        }
        let state = Arc::new(AtomicU8::new(PENDING));
        Ok((
            Self {
                state: state.clone(),
                owner: owner.clone(),
            },
            RouteWork {
                state,
                owner: owner.clone(),
            },
        ))
    }

    pub fn is_complete(&self) -> bool {
        self.state.load(Ordering::Acquire) == COMPLETED
    }

    pub fn owner(&self) -> &Owner {
        &self.owner
    }
}

/// Linear work handle. Non-clone: dropping an unbound Pending handle proves no
/// route work was accepted; a Bound handle can only complete through the
/// actual stopped/absent cleanup path.
pub struct RouteWork {
    state: Arc<AtomicU8>,
    owner: Owner,
}

impl RouteWork {
    pub(in crate::connection::macos::routing) fn owner(&self) -> &Owner {
        &self.owner
    }

    pub(in crate::connection::macos::routing) fn bind(
        &mut self,
        owner: &Owner,
    ) -> Result<(), Error> {
        if &self.owner != owner {
            return Err(Error::Invalid);
        }
        match self
            .state
            .compare_exchange(PENDING, BOUND, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(BOUND) => Err(Error::Busy),
            Err(_) => Err(Error::Invalid),
        }
    }

    pub(in crate::connection::macos::routing) fn complete(&mut self) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(BOUND, COMPLETED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(COMPLETED) => Ok(()),
            Err(_) => Err(Error::Invalid),
        }
    }
}

impl Drop for RouteWork {
    fn drop(&mut self) {
        if self.state.load(Ordering::Acquire) == PENDING {
            self.state.store(COMPLETED, Ordering::Release);
        }
    }
}

#[cfg(test)]
#[path = "resource_fence/tests.rs"]
mod tests;
