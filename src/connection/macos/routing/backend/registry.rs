use super::{Error, Key, Route};
use crate::{
    connection::routes::{Backend, NextHop, Owner, Presence},
    model::valid_profile_id,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_BACKEND: AtomicU64 = AtomicU64::new(1);

pub(super) trait Table {
    fn exact(&mut self, key: Key) -> Result<Option<Route>, Error>;
}
pub(super) struct Attempt {
    pub confirmation: Result<(), Error>,
}
pub(super) trait Scope {
    fn index(&self) -> u16;
    fn owns(&self, index: u16) -> bool {
        self.index() == index
    }
    fn active(&self) -> Result<(), Error>;
    fn add(&mut self, route: Route) -> Result<Attempt, Error>;
    fn detach_if_stopped(&mut self) -> Result<bool, Error>;
    /// Includes implicit alias/local routes outside the explicit plan.
    fn cleanup_complete(&mut self) -> Result<bool, Error>;
}
/// Opaque machine/backend-bound generation. Not accepted from IPC.
pub struct InterfaceToken {
    backend: u64,
    scope: u64,
    index: u16,
}
/// Evidence is a retained interface and confirmed ADD, not a kernel route ID.
/// These receipts never authorize a per-key delete or an attribute-based CAS.
pub struct NativeReceipt {
    backend: u64,
    scope: u64,
    primary: u16,
    route: Route,
    confirmation: Result<(), Error>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Active,
    Draining,
    Detached,
}
struct Entry<S> {
    scope: S,
    serial: u64,
    owner: Owner,
    plan: Vec<Route>,
    phase: Phase,
}
pub(super) struct Registry<S, K> {
    id: u64,
    next: u64,
    entries: BTreeMap<u16, Entry<S>>,
    table: K,
}
impl<S: Scope, K: Table> Registry<S, K> {
    pub fn new(table: K) -> Result<Self, Error> {
        let mut id = NEXT_BACKEND.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).ok_or(Error::Limit)?;
            match NEXT_BACKEND.compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(now) => id = now,
            }
        }
        Ok(Self {
            id,
            next: 0,
            entries: BTreeMap::new(),
            table,
        })
    }
    pub fn register(
        &mut self,
        scope: S,
        owner: Owner,
        plan: Vec<Route>,
    ) -> Result<InterfaceToken, Error> {
        let index = scope.index();
        if index == 0
            || !scope.owns(index)
            || owner.uid == 0
            || owner.generation == 0
            || !valid_profile_id(&owner.profile)
            || plan.is_empty()
            || plan.len() > 128
        {
            return Err(Error::Invalid);
        }
        if self.entries.len() >= 64 {
            return Err(Error::Limit);
        }
        if self.entries.contains_key(&index)
            || self
                .entries
                .values()
                .any(|entry| entry.owner.uid == owner.uid && entry.owner.profile == owner.profile)
        {
            return Err(Error::Busy);
        }
        let mut keys = BTreeSet::new();
        for route in &plan {
            route.validate()?;
            if !scope.owns(route.interface)
                || route.key.scope != 0
                || matches!(route.next_hop, NextHop::Gateway(_))
                || !keys.insert(route.key)
            {
                return Err(Error::Invalid);
            }
            if self
                .entries
                .values()
                .any(|old| old.scope.owns(route.interface) || scope.owns(old.scope.index()))
            {
                return Err(Error::Busy);
            }
        }
        scope.active()?;
        self.next = self.next.checked_add(1).ok_or(Error::Limit)?;
        let serial = self.next;
        self.entries.insert(
            index,
            Entry {
                scope,
                serial,
                owner,
                plan,
                phase: Phase::Active,
            },
        );
        Ok(InterfaceToken {
            backend: self.id,
            scope: serial,
            index,
        })
    }
    fn entry(&mut self, token: &InterfaceToken) -> Result<&mut Entry<S>, Error> {
        if token.backend != self.id {
            return Err(Error::Invalid);
        }
        self.entries
            .get_mut(&token.index)
            .filter(|entry| entry.serial == token.scope)
            .ok_or(Error::Invalid)
    }
    pub fn begin_cleanup(&mut self, token: &InterfaceToken) -> Result<bool, Error> {
        let entry = self.entry(token)?;
        if entry.phase == Phase::Detached {
            return Ok(true);
        }
        entry.phase = Phase::Draining;
        if !entry.scope.detach_if_stopped()? {
            return Ok(false);
        }
        entry.phase = Phase::Detached;
        Ok(true)
    }
    pub fn finish_cleanup(&mut self, token: &InterfaceToken) -> Result<(), Error> {
        let entry = self.entry(token)?;
        if entry.phase != Phase::Detached {
            return Err(Error::Busy);
        }
        let plan = entry.plan.clone();
        for route in plan {
            // Same numeric index after close is still uncertain, including
            // possible reuse; do not declare it foreign based on attributes.
            if let Some(now) = self.observed(route.key)?
                && self.entry(token)?.scope.owns(now.interface)
            {
                return Err(Error::Busy);
            }
        }
        if !self
            .entry(token)?
            .scope
            .cleanup_complete()
            .map_err(|_| Error::Unavailable)?
        {
            return Err(Error::Busy);
        }
        self.entries.remove(&token.index);
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    fn observed(&mut self, key: Key) -> Result<Option<Route>, Error> {
        // Coordinator treats Error::Changed as disposable. Read failures must
        // instead retain receipts even if the platform adapter used that code.
        self.table.exact(key).map_err(|_| Error::Unavailable)
    }
}
impl<S: Scope, K: Table> Backend for Registry<S, K> {
    type Receipt = NativeReceipt;
    fn authorize(&mut self, owner: &Owner, route: Route) -> Result<(), Error> {
        let entry = self
            .entries
            .values()
            .find(|entry| entry.scope.owns(route.interface))
            .ok_or(Error::Invalid)?;
        if entry.owner != *owner || !entry.plan.contains(&route) {
            return Err(Error::Invalid);
        }
        if entry.phase != Phase::Active {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
        self.observed(key)
    }
    fn create(&mut self, route: Route) -> Result<Self::Receipt, Error> {
        let (&primary, entry) = self
            .entries
            .iter_mut()
            .find(|(_, entry)| entry.scope.owns(route.interface))
            .ok_or(Error::Invalid)?;
        if entry.phase != Phase::Active {
            return Err(Error::Busy);
        }
        if !entry.plan.contains(&route) {
            return Err(Error::Invalid);
        }
        entry.scope.active()?;
        let mut attempt = entry.scope.add(route)?;
        let scope = entry.serial;
        // Once dispatch was attempted, postflight errors belong in a receipt.
        // Returning Err here would let the coordinator forget a possible ADD.
        if attempt.confirmation.is_ok() {
            attempt.confirmation =
                entry
                    .scope
                    .active()
                    .and_then(|()| match self.observed(route.key) {
                        Ok(Some(actual)) if actual == route => Ok(()),
                        Ok(_) => Err(Error::Changed),
                        Err(error) => Err(error),
                    });
        }
        Ok(NativeReceipt {
            backend: self.id,
            scope,
            primary,
            route,
            confirmation: attempt.confirmation,
        })
    }
    fn receipt_state(&mut self, receipt: &Self::Receipt) -> Result<Presence, Error> {
        if receipt.backend != self.id {
            return Err(Error::Invalid);
        }
        let Some(now) = self.observed(receipt.route.key)? else {
            return Ok(Presence::Absent);
        };
        if now.interface != receipt.route.interface {
            let still_ours = self
                .entries
                .get(&receipt.primary)
                .filter(|entry| entry.serial == receipt.scope)
                .is_some_and(|entry| entry.scope.owns(now.interface));
            return if still_ours {
                Err(Error::Busy)
            } else {
                Ok(Presence::Replaced)
            };
        }
        // Even a different route on the same ifnet cannot be deleted safely.
        if now != receipt.route {
            return Err(Error::Busy);
        }
        let entry = self
            .entries
            .get(&receipt.primary)
            .filter(|entry| entry.serial == receipt.scope)
            .ok_or(Error::Unavailable)?;
        if entry.phase != Phase::Active || receipt.confirmation.is_err() {
            return Err(Error::Busy);
        }
        entry.scope.active().map_err(|_| Error::Unavailable)?;
        // Owned here means a usable, retained target following a confirmed ADD.
        // It is deliberately insufficient to remove an individual route.
        Ok(Presence::Owned)
    }
    fn remove(&mut self, receipt: &Self::Receipt) -> Result<(), Error> {
        match self.receipt_state(receipt)? {
            Presence::Absent | Presence::Replaced => Ok(()),
            Presence::Owned => Err(Error::Busy),
        }
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
