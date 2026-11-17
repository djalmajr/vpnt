//! Real resource ledger; lock order: Registry -> ledger map -> NativeContext.
use super::bound::budget;
use super::*;
use crate::{
    connection::{
        ipsec::{Config, Peer, Registry, Reservation},
        macos::ipsec_egress::IpsecEgress,
    },
    model::{Profile, VpnKind},
};
#[cfg(test)]
pub(in crate::connection::ipsec::producer) use resource::Absence;
use resource::{Entry, EntryState};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};
mod admission;
mod claims;
mod pins;
mod resource;

pub use admission::Admission;

pub(super) struct Inner<'a> {
    pub(super) context: Arc<NativeContext<'a>>,
    pub(super) entries: Mutex<BTreeMap<u64, Arc<Entry<'a>>>>,
    pub(super) version: AtomicU64,
    next: AtomicU64,
    #[cfg(test)]
    pub(super) version_race: AtomicBool,
    #[cfg(test)]
    absence: Mutex<Option<Arc<dyn resource::Absence>>>,
}

/// Cloneable ledger over the same private state and the same verified
/// `NativeContext`. Constructing it makes no writes and stores no empty source.
#[derive(Clone)]
pub struct NativeLedger<'a> {
    inner: Arc<Inner<'a>>,
}

impl<'a> NativeLedger<'a> {
    pub fn new(context: Arc<NativeContext<'a>>) -> Result<Self, Error> {
        if context
            .ledger_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                context,
                entries: Mutex::new(BTreeMap::new()),
                version: AtomicU64::new(0),
                next: AtomicU64::new(1),
                #[cfg(test)]
                version_race: AtomicBool::new(false),
                #[cfg(test)]
                absence: Mutex::new(None),
            }),
        })
    }

    /// Test-only deterministic absence; production `prepare` always captures
    /// the real early-cleanup before-image.
    #[cfg(test)]
    pub(super) fn scripted(
        context: Arc<NativeContext<'a>>,
        absence: Arc<dyn resource::Absence>,
    ) -> Self {
        let ledger = Self::new(context).expect("fresh test context");
        *ledger.inner.absence.lock().expect("absence hook") = Some(absence);
        ledger
    }

    #[cfg(test)]
    pub(super) fn arm_version_race(&self) {
        self.inner.version_race.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn set_next_for_test(&self, value: u64) {
        self.inner.next.store(value, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn entries_lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, Arc<Entry<'a>>>> {
        self.inner.entries.lock().expect("entries")
    }

    /// `u64::MAX` is the exhausted sentinel and is never assigned.
    fn reserve_serial(&self) -> Result<u64, Error> {
        let mut current = self.inner.next.load(Ordering::Acquire);
        loop {
            if current == u64::MAX {
                return Err(Error::Exhausted);
            }
            match self.inner.next.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(current),
                Err(value) => current = value,
            }
        }
    }

    fn absence(&self) -> Result<Arc<dyn resource::Absence>, Error> {
        #[cfg(test)]
        if let Some(absence) = self
            .inner
            .absence
            .lock()
            .map_err(|_| Error::Unavailable)?
            .clone()
        {
            return Ok(absence);
        }
        resource::capture()
    }

    /// Prepare one durable attempt under the caller's namespace guard. The
    /// same budget covers the ledger map wait and every checkpoint before the
    /// exact `NativeContext::prepare_bound`; the strong entry is inserted
    /// before returning, with no fallible post-commit step.
    pub fn prepare<N: Observer>(
        &self,
        registry: &Registry<N>,
        reservation: &Reservation,
        profile: &Profile,
        egress: Arc<IpsecEgress>,
        budget: (Instant, Arc<AtomicBool>),
    ) -> Result<(Config, Admission<'a>), Error> {
        let (expires, cancel) = budget;
        if profile.kind != VpnKind::Ipsec || profile.validate().is_err() {
            return Err(Error::Invalid);
        }
        registry.validate(reservation)?;
        let owner = reservation.owner().clone();
        let mut entries = budget::lock_until(expires, &cancel, &self.inner.entries)?;
        budget::check_until(expires, &cancel)?;
        if entries.len() >= 64 {
            return Err(Error::Exhausted);
        }
        if entries
            .values()
            .any(|entry| entry.owner.uid == owner.uid && entry.owner.profile == owner.profile)
        {
            return Err(Error::Busy);
        }
        let serial = self.reserve_serial()?;
        // Passive before-image is captured before any child can spawn.
        let absence = self.absence()?;
        budget::check_until(expires, &cancel)?;
        let (config, peer) = self.inner.context.prepare_bound(
            registry,
            reservation,
            profile,
            egress,
            (expires, cancel.clone()),
        )?;
        let peer = Arc::new(Mutex::new(peer));
        let entry = Arc::new(Entry {
            owner,
            serial,
            peer: peer.clone(),
            absence,
            state: EntryState::new(),
            config: config.clone(),
            pin: Mutex::new(pins::PinState::new()),
            route_fence: Mutex::new(None),
            opened: AtomicBool::new(false),
            configured: AtomicBool::new(false),
            authority: Arc::new(()),
        });
        entries.insert(serial, entry.clone());
        self.inner.version.fetch_add(1, Ordering::Release);
        Ok((config, admission::Admission::new(self.inner.clone(), entry)))
    }

    /// Stop only Draining original peers. A busy peer keeps its entry; Live
    pub fn reap(&self) -> Result<(), Error> {
        let snapshot: Vec<Arc<Entry<'a>>> = {
            let entries = self.inner.entries.lock().map_err(|_| Error::Unavailable)?;
            entries
                .values()
                .filter(|entry| entry.state.draining() && !entry.state.stopped())
                .cloned()
                .collect()
        };
        for entry in snapshot {
            let mut pin = match entry.pin.try_lock() {
                Ok(pin) => pin,
                Err(std::sync::TryLockError::WouldBlock) => continue,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(Error::Unavailable);
                }
            };
            match entry.peer.try_lock() {
                Ok(mut peer) => {
                    let result = peer.retire(&entry.owner);
                    drop(peer);
                    match result {
                        Ok(true) => {
                            let release = pin.release();
                            if release.changed {
                                self.inner.version.fetch_add(1, Ordering::Release);
                            }
                            if entry.state.mark_stopped() {
                                self.inner.version.fetch_add(1, Ordering::Release);
                            }
                        }
                        Ok(false) => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
            }
        }
        Ok(())
    }

    /// Conservative: map entries, durable records, or an unreadable store make
    /// this true. Unknown records are never erased.
    pub fn has_resources(&self) -> bool {
        let entries = match self.inner.entries.lock() {
            Ok(entries) => !entries.is_empty(),
            Err(poisoned) => !poisoned.into_inner().is_empty(),
        };
        if entries {
            return true;
        }
        match self.inner.context.store.records() {
            Ok(records) => !records.is_empty(),
            Err(_) => true,
        }
    }
}
