use super::{Error, Key, Route};
use crate::model::valid_profile_id;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_MANAGER: AtomicU64 = AtomicU64::new(1);
mod acquire;
mod cleanup;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    Owned,
    Absent,
    Replaced,
}
fn manager_id() -> Result<u64, Error> {
    let mut id = NEXT_MANAGER.load(Ordering::Relaxed);
    loop {
        let next = id.checked_add(1).ok_or(Error::Limit)?;
        match NEXT_MANAGER.compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(id),
            Err(current) => id = current,
        }
    }
}

/// The native implementation must retain evidence from its own create attempt
/// and refuse removal on uncertainty/change. A matching destination alone is
/// not ownership. create may return an unconfirmed receipt: receipt_state must
/// then refuse promotion until it has sufficient evidence.
pub trait Backend {
    type Receipt;
    fn existing(&mut self, key: Key) -> Result<Option<Route>, Error>;
    fn create(&mut self, route: Route) -> Result<Self::Receipt, Error>;
    fn receipt_state(&mut self, receipt: &Self::Receipt) -> Result<Presence, Error>;
    fn remove(&mut self, receipt: &Self::Receipt) -> Result<(), Error>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Owner {
    pub uid: u32,
    pub profile: String,
    pub generation: u64,
}
impl Owner {
    fn valid(&self) -> bool {
        self.uid != 0 && self.generation != 0 && valid_profile_id(&self.profile)
    }
}
/// Opaque, single-owner handle. There is no deserialize/clone path from IPC.
#[derive(Debug)]
pub struct Lease {
    manager: u64,
    token: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Cleanup {
    pub removed: usize,
    pub borrowed: usize,
    pub absent: usize,
    pub changed: usize,
    pub pending: usize,
}
impl Cleanup {
    fn merge(&mut self, other: Self) {
        self.removed += other.removed;
        self.borrowed += other.borrowed;
        self.absent += other.absent;
        self.changed += other.changed;
        self.pending += other.pending;
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquireError {
    pub reason: Error,
    pub cleanup: Cleanup,
}
impl From<Error> for AcquireError {
    fn from(reason: Error) -> Self {
        Self {
            reason,
            cleanup: Cleanup::default(),
        }
    }
}
struct Entry<R> {
    route: Route,
    receipt: Option<R>,
    users: BTreeSet<u64>,
}
struct Claim {
    owner: Owner,
    keys: Vec<Key>,
    releasing: bool,
    failed: bool,
}
pub struct Coordinator<B: Backend> {
    backend: B,
    manager: u64,
    next: u64,
    entries: BTreeMap<Key, Entry<B::Receipt>>,
    claims: BTreeMap<u64, Claim>,
}
impl<B: Backend> Coordinator<B> {
    pub fn new(backend: B) -> Result<Self, Error> {
        let manager = manager_id()?;
        Ok(Self {
            backend,
            manager,
            next: 0,
            entries: BTreeMap::new(),
            claims: BTreeMap::new(),
        })
    }
    pub fn validate(&mut self, lease: &Lease) -> Result<(), Error> {
        if lease.manager != self.manager {
            return Err(Error::Invalid);
        }
        let claim = self.claims.get(&lease.token).ok_or(Error::Invalid)?;
        if claim.releasing || claim.failed {
            return Err(Error::Changed);
        }
        let keys = &claim.keys;
        for key in keys {
            let entry = self.entries.get(key).ok_or(Error::Changed)?;
            let current = match &entry.receipt {
                Some(receipt) => self.backend.receipt_state(receipt)? == Presence::Owned,
                None => self.backend.existing(*key)? == Some(entry.route),
            };
            if !current {
                return Err(Error::Changed);
            }
        }
        Ok(())
    }
    pub(super) fn admit(&mut self, route: Route) -> Result<(), Error> {
        if let Some(entry) = self.entries.get(&route.key) {
            if entry.route != route || entry.users.is_empty() {
                return Err(Error::Conflict);
            }
            if let Some(receipt) = &entry.receipt
                && self.backend.receipt_state(receipt)? != Presence::Owned
            {
                return Err(Error::Changed);
            }
        }
        match self.backend.existing(route.key)? {
            Some(old) if old != route => Err(Error::Conflict),
            None if self.entries.contains_key(&route.key) => Err(Error::Changed),
            _ => Ok(()),
        }
    }
    pub(super) fn attach(&mut self, token: u64, route: Route) -> Result<(), Error> {
        // State may have changed since preflight; never replace on create.
        self.admit(route)?;
        if !self.entries.contains_key(&route.key) {
            let receipt = if self.backend.existing(route.key)?.is_some() {
                None
            } else {
                Some(self.backend.create(route)?)
            };
            self.entries.insert(
                route.key,
                Entry {
                    route,
                    receipt,
                    users: BTreeSet::new(),
                },
            );
        }
        self.entries
            .get_mut(&route.key)
            .ok_or(Error::Unavailable)?
            .users
            .insert(token);
        self.claims
            .get_mut(&token)
            .ok_or(Error::Unavailable)?
            .keys
            .push(route.key);
        Ok(())
    }
}
