//! `ResourceClaims` over the real ledger: every Live entry is pending; a
//! Draining entry stays pending until its original peer is confirmed stopped
//! and a fresh passive absence read succeeds. No empty answer is cached.
use super::NativeLedger;
use super::resource::Entry;
use crate::connection::{ipsec::Error, ipsec::ResourceClaims, routes::Owner};
use std::sync::{Arc, atomic::Ordering};

impl ResourceClaims for NativeLedger<'_> {
    fn pending_owners(&mut self) -> Result<Vec<Owner>, Error> {
        let version = self.inner.version.load(Ordering::Acquire);
        let snapshot: Vec<Arc<Entry<'_>>> = {
            let entries = self.inner.entries.lock().map_err(|_| Error::Unavailable)?;
            entries.values().cloned().collect()
        };
        let mut owners: Vec<Owner> = Vec::new();
        for entry in snapshot {
            if owners.iter().any(|owner| owner == &entry.owner) {
                return Err(Error::Changed);
            }
            if entry.state.completed() {
                continue;
            }
            if entry.state.live() {
                owners.push(entry.owner.clone());
                continue;
            }
            // Draining: only omit after the original stop AND a fresh passive
            // absence proof. Busy/poison or a false proof keeps it pending.
            let observed = if entry.state.stopped() {
                false
            } else {
                match entry.peer.try_lock() {
                    Ok(peer) => peer
                        .producer
                        .lock()
                        .map_err(|_| Error::Unavailable)?
                        .stopped(),
                    Err(std::sync::TryLockError::WouldBlock) => false,
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return Err(Error::Unavailable);
                    }
                }
            };
            // Guards are dropped before the state/version update.
            if observed && entry.state.mark_stopped() {
                self.inner.version.fetch_add(1, Ordering::Release);
            }
            if entry.state.stopped() {
                match entry.pin.try_lock() {
                    Ok(mut pin) => {
                        if pin.release().changed {
                            self.inner.version.fetch_add(1, Ordering::Release);
                        }
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {}
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        return Err(Error::Unavailable);
                    }
                }
            }
            if !entry.state.stopped() {
                owners.push(entry.owner.clone());
                continue;
            }
            let fences_complete = match entry.route_fence.try_lock() {
                Ok(fence) => fence.as_ref().is_none_or(|fence| fence.is_complete()),
                Err(std::sync::TryLockError::WouldBlock) => false,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(Error::Unavailable);
                }
            };
            if !fences_complete {
                owners.push(entry.owner.clone());
                continue;
            }
            let absent = match entry.pin.try_lock() {
                Ok(pin) => matches!(pin.claim_absence(entry.absence.as_ref())?, Some(true)),
                Err(std::sync::TryLockError::WouldBlock) => false,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(Error::Unavailable);
                }
            };
            if !absent {
                owners.push(entry.owner.clone());
            }
        }
        #[cfg(test)]
        if self.inner.version_race.swap(false, Ordering::AcqRel) {
            self.inner.version.fetch_add(1, Ordering::Release);
        }
        if self.inner.version.load(Ordering::Acquire) != version {
            return Err(Error::Changed);
        }
        Ok(owners)
    }

    /// Durable completion already happened in `UserspaceObserver::completed`.
    /// Remove only the exact stopped+Draining entry; any invariant failure
    /// leaves it conservatively busy. Infallible and I/O free.
    fn completed(&mut self, owner: &Owner) {
        let mut entries = match self.inner.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        let serial = entries
            .iter()
            .find(|(_, entry)| {
                entry.owner == *owner && entry.state.draining() && entry.state.stopped()
            })
            .map(|(serial, _)| *serial);
        let Some(serial) = serial else {
            return;
        };
        if let Some(entry) = entries.remove(&serial) {
            entry.state.complete();
        }
        self.inner.version.fetch_add(1, Ordering::Release);
    }
}
