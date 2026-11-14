//! Owner-bound native producer admission for the helper. Kernel
//! and VIP/route observers must supply complete absence before finalization.
use super::{Error, Observer, Peer};
pub use crate::connection::macos::utun_observer::{InterfaceObservation, RetainedInterface};
use crate::{
    connection::{
        macos::process::{Identity, Process},
        routes::Owner,
    },
    helper::{controller_lock::ControllerLock, runtime::Runtime, vici::Client},
};
use bound::budget::{self, Budget};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak, atomic::AtomicBool},
    time::Instant,
};
mod bound;
mod child;
mod config;
mod files;
mod ledger;
mod record;
mod socket;
mod state;
mod userspace;
pub use ledger::{Admission, NativeLedger};
pub use userspace::{ResourceClaims, UserspaceObserver};

type SharedProducer<'a> = Arc<Mutex<child::Producer<'a>>>;
type WeakProducer<'a> = Weak<Mutex<child::Producer<'a>>>;

pub struct NativeContext<'a> {
    controller: &'a ControllerLock,
    runtime: Runtime,
    identity: Identity,
    store: Arc<state::Store>,
    active: Mutex<BTreeMap<String, WeakProducer<'a>>>,
    admission: Mutex<()>,
    ledger_claimed: AtomicBool,
}
impl<'a> NativeContext<'a> {
    pub fn new(controller: &'a ControllerLock) -> Result<Arc<Self>, Error> {
        // SAFETY: UID queries have no memory preconditions. Deny before any state write or spawn.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(Error::PermissionDenied);
        }
        Self::using(
            controller,
            Runtime::installed().map_err(|_| Error::Unavailable)?,
        )
    }
    fn using(controller: &'a ControllerLock, runtime: Runtime) -> Result<Arc<Self>, Error> {
        controller.validate().map_err(|_| Error::Changed)?;
        runtime.verify().map_err(|_| Error::Changed)?;
        let me = Process::read(std::process::id()).map_err(|_| Error::Unavailable)?;
        if !me.running || me.uid != runtime.owner() || me.real_uid != runtime.owner() {
            return Err(Error::Changed);
        }
        let store = state::Store::open(controller.directory(), runtime.owner())?;
        Ok(Arc::new(Self {
            controller,
            runtime,
            identity: me.identity,
            store,
            active: Mutex::new(BTreeMap::new()),
            admission: Mutex::new(()),
            ledger_claimed: AtomicBool::new(false),
        }))
    }
    fn validate(&self) -> Result<(), Error> {
        self.controller.validate().map_err(|_| Error::Changed)?;
        let me = Process::read(std::process::id()).map_err(|_| Error::Unavailable)?;
        if me.identity != self.identity
            || !me.running
            || me.uid != self.runtime.owner()
            || me.real_uid != self.runtime.owner()
        {
            return Err(Error::Changed);
        }
        self.runtime.verify().map_err(|_| Error::Changed)?;
        self.store.root.validate()
    }
    pub fn observer<K: KernelClaims>(self: &Arc<Self>, kernel: K) -> NativeObserver<'a, K> {
        NativeObserver {
            context: self.clone(),
            kernel,
        }
    }
    /// Explicit userspace admission observer bound to this verified
    /// kernel-libipsec context. `resources` must describe the complete fresh
    /// pending IPsec resource domain; a test/empty adapter is not a production
    /// substitute for the missing real ledger.
    pub fn userspace_observer<R: ResourceClaims>(
        self: &Arc<Self>,
        resources: R,
    ) -> UserspaceObserver<'a, R> {
        UserspaceObserver::new(self.clone(), resources)
    }
    /// Observe the utun control socket of the active producer for `owner`.
    ///
    /// Read-only and bounded: it never spawns or reopens a producer, exposes no
    /// PID/FD, and confers no route, cleanup or ownership authority.
    pub fn observe_interface(
        &self,
        owner: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<InterfaceObservation, Error> {
        self.validate()?;
        let observation = self.observe_active(owner, expires, &cancel)?;
        self.validate()?;
        Ok(observation)
    }
    fn observe_active(
        &self,
        owner: &Owner,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<InterfaceObservation, Error> {
        child::interface::observe_active(self, owner, expires, cancel)
    }
    /// Take the typed retained interface of the active attempt for `owner`.
    ///
    /// Bounded `try_lock` lookup, exactly once, only for the same
    /// attempted/non-retired/non-released producer. The returned value pins the
    /// received socket and carries the observation stamps; it confers no route
    /// or cleanup authority by itself.
    pub fn take_interface(
        &self,
        owner: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<RetainedInterface, Error> {
        self.validate()?;
        let retained = child::interface::take_active(self, owner, expires, &cancel)?;
        self.validate()?;
        Ok(retained)
    }
    fn lookup(&self, owner: &Owner) -> Result<Option<SharedProducer<'a>>, Error> {
        let live: Vec<_> = self
            .active
            .lock()
            .map_err(|_| Error::Unavailable)?
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut found = None;
        for p in live {
            if p.lock()
                .map_err(|_| Error::Unavailable)?
                .lease
                .record
                .owner()
                == *owner
            {
                if found.is_some() {
                    return Err(Error::Changed);
                }
                found = Some(p);
            }
        }
        Ok(found)
    }
    fn unrepresented(&self) -> Result<BTreeSet<u32>, Error> {
        self.validate()?;
        let mut result = BTreeSet::new();
        for record in self.store.records()? {
            let live = self
                .active
                .lock()
                .map_err(|_| Error::Unavailable)?
                .get(&record.session)
                .and_then(Weak::upgrade);
            let represented = if let Some(p) = live {
                let p = p.lock().map_err(|_| Error::Unavailable)?;
                p.lease.validate()?;
                p.lease.record.same_admission(&record) && !p.released
            } else {
                false
            };
            if !represented {
                result.insert(u32::from(record.reqid));
            }
        }
        Ok(result)
    }
    fn stopped(&self, owner: &Owner) -> Result<bool, Error> {
        self.validate()?;
        if let Some(p) = self.lookup(owner)? {
            return Ok(p.lock().map_err(|_| Error::Unavailable)?.stopped());
        }
        Ok(!self.store.records()?.iter().any(|r| r.owner() == *owner))
    }
    fn completed(&self, owner: &Owner, reqid: u16) -> Result<(), Error> {
        self.validate()?;
        let Some(p) = self.lookup(owner)? else {
            return if self.store.records()?.iter().any(|r| r.owner() == *owner) {
                Err(Error::Busy)
            } else {
                Ok(())
            };
        };
        let mut p = p.lock().map_err(|_| Error::Unavailable)?;
        if p.lease.record.reqid != reqid || !p.stopped() {
            return Err(Error::Busy);
        }
        p.lease.complete()?;
        p.released = true;
        self.active
            .lock()
            .map_err(|_| Error::Unavailable)?
            .remove(&p.lease.record.session);
        Ok(())
    }
}

/// Must include complete SAD/SPD observations and pending VIP/route leases.
/// A partial/cached reply must fail rather than report an empty set.
pub trait KernelClaims {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error>;
}
pub struct NativeObserver<'a, K: KernelClaims> {
    context: Arc<NativeContext<'a>>,
    kernel: K,
}
impl<K: KernelClaims> Observer for NativeObserver<'_, K> {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        let mut ids = self.kernel.occupied()?;
        ids.extend(self.context.unrepresented()?);
        Ok(ids)
    }
    fn producer_stopped(&mut self, owner: &Owner) -> Result<bool, Error> {
        self.context.stopped(owner)
    }
    fn completed(&mut self, owner: &Owner, reqid: u16) -> Result<(), Error> {
        self.context.completed(owner, reqid)
    }
}
pub struct NativePeer<'a> {
    producer: SharedProducer<'a>,
}
impl Peer for NativePeer<'_> {
    fn open(
        &mut self,
        owner: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Client, Error> {
        let budget = Budget::new(expires, cancel.clone());
        let mut producer = budget::lock(Some(&budget), &self.producer)?;
        producer.open(owner, expires, cancel)
    }
    fn retire(&mut self, owner: &Owner) -> Result<bool, Error> {
        let mut p = self.producer.lock().map_err(|_| Error::Unavailable)?;
        if p.lease.record.owner() != *owner {
            return Err(Error::Changed);
        }
        p.retire()
    }
}
#[cfg(test)]
mod tests;
