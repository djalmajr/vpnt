//! Opaque admission and its private handle. The map owns the strong resource;
//! the handle only shares the actual admission and marks Draining on last Drop.
use super::super::{NativePeer, Peer, bound::budget};
use super::{Inner, resource::Entry};
use crate::connection::{
    ipsec::{Candidate, Error},
    macos::routing::{ResourceFence, RouteWork},
    macos::vip::ConfiguredUtun,
    routes::Owner,
};
use crate::helper::vici::Client;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

#[derive(Clone)]
pub struct Admission<'a> {
    handle: Arc<AdmissionHandle<'a>>,
}

pub(super) struct AdmissionHandle<'a> {
    ledger: Arc<Inner<'a>>,
    entry: Arc<Entry<'a>>,
    authority: Arc<()>,
}

impl<'a> Admission<'a> {
    /// Private constructor from an actual inserted entry; no raw factory.
    pub(super) fn new(ledger: Arc<Inner<'a>>, entry: Arc<Entry<'a>>) -> Self {
        let authority = entry.authority.clone();
        Self {
            handle: Arc::new(AdmissionHandle {
                ledger,
                entry,
                authority,
            }),
        }
    }

    pub fn owner(&self) -> &Owner {
        &self.handle.entry.owner
    }

    pub fn begin_cleanup(&self) -> Result<(), Error> {
        if self.handle.entry.state.mark_draining() {
            self.handle.ledger.version.fetch_add(1, Ordering::Release);
        }
        Ok(())
    }

    fn require_current_bounded(&self, expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
        let entries = budget::lock_until(expires, cancel, &self.handle.ledger.entries)?;
        budget::check_until(expires, cancel)?;
        self.check_current(&entries)
    }

    fn check_current(
        &self,
        entries: &std::collections::BTreeMap<u64, Arc<Entry<'a>>>,
    ) -> Result<(), Error> {
        let entry = entries
            .get(&self.handle.entry.serial)
            .ok_or(Error::Changed)?;
        if !Arc::ptr_eq(entry, &self.handle.entry)
            || !Arc::ptr_eq(&entry.authority, &self.handle.authority)
        {
            return Err(Error::Changed);
        }
        Ok(())
    }

    /// Grant the original peer after configuration within the caller budget.
    pub fn native_peer(
        &self,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Arc<Mutex<NativePeer<'a>>>, Error> {
        self.require_current_bounded(expires, &cancel)?;
        if !self.handle.entry.state.live() || !self.handle.entry.configured.load(Ordering::Acquire)
        {
            return Err(Error::Changed);
        }
        Ok(self.handle.entry.peer.clone())
    }

    /// Take the exact typed retained interface once, after the same peer was
    /// opened and before the future Control.start/credentials.
    pub fn capture_interface(
        &self,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<(), Error> {
        self.require_current_bounded(expires, &cancel)?;
        let entry = &self.handle.entry;
        if !entry.state.live() || !entry.opened.load(Ordering::Acquire) {
            return Err(Error::Changed);
        }
        let gate = cancel.clone();
        let mut pin = budget::lock_until(expires, &gate, &entry.pin)?;
        budget::check_until(expires, &cancel)?;
        if !entry.state.live() || !pin.empty() {
            return Err(Error::Changed);
        }
        let retained = self
            .handle
            .ledger
            .context
            .take_interface(&entry.owner, expires, cancel)?;
        *pin = super::pins::PinState::Captured(retained);
        self.handle.ledger.version.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Configure the typed retained pin exactly once. The map is not held
    /// across VIP SDK work; the pin lock covers the whole intention.
    pub fn configure(
        &self,
        candidate: &Candidate,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Arc<ConfiguredUtun<'a>>, Error> {
        self.require_current_bounded(expires, &cancel)?;
        let entry = &self.handle.entry;
        if !entry.state.live() || !entry.opened.load(Ordering::Acquire) {
            return Err(Error::Changed);
        }
        entry.config.select(std::slice::from_ref(candidate))?;
        entry.config.route_networks(candidate)?;
        let gate = cancel.clone();
        let mut pin = budget::lock_until(expires, &gate, &entry.pin)?;
        budget::check_until(expires, &cancel)?;
        if !entry.state.live() {
            return Err(Error::Changed);
        }
        let retained = pin.take_retained().ok_or(Error::Changed)?;
        let controller = self.handle.ledger.context.controller;
        match ConfiguredUtun::configure_until(retained, candidate, controller, expires, &cancel) {
            Ok(configured) => {
                let retired = configured.retirement().ok();
                let strong = Arc::new(configured);
                pin.store_configured(strong.clone(), retired);
                entry.configured.store(true, Ordering::Release);
                self.handle.ledger.version.fetch_add(1, Ordering::Release);
                Ok(strong)
            }
            Err(failure) => {
                let error = failure.error();
                let retired = failure.retirement().ok();
                pin.store_failed(failure, retired);
                self.handle.ledger.version.fetch_add(1, Ordering::Release);
                Err(error)
            }
        }
    }

    /// Mint the single linear route work for this configured admission.
    pub fn begin_routes(
        &self,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<RouteWork, Error> {
        self.require_current_bounded(expires, &cancel)?;
        if !self.handle.entry.state.live() || !self.handle.entry.configured.load(Ordering::Acquire)
        {
            return Err(Error::Changed);
        }
        let route_gate = cancel.clone();
        let mut route = budget::lock_until(expires, &route_gate, &self.handle.entry.route_fence)?;
        budget::check_until(expires, &cancel)?;
        if !self.handle.entry.state.live() || !self.handle.entry.configured.load(Ordering::Acquire)
        {
            return Err(Error::Changed);
        }
        if route.is_some() {
            return Err(Error::Busy);
        }
        let (fence, work) =
            ResourceFence::begin(&self.handle.entry.owner).map_err(|_| Error::Invalid)?;
        *route = Some(fence);
        self.handle.ledger.version.fetch_add(1, Ordering::Release);
        Ok(work)
    }

    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn raw_peer_for_test(
        &self,
    ) -> Arc<Mutex<NativePeer<'a>>> {
        self.handle.entry.peer.clone()
    }

    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn inject_route_fence_for_test(
        &self,
        fence: ResourceFence,
    ) {
        assert_eq!(fence.owner(), self.owner());
        let mut slot = self.handle.entry.route_fence.lock().unwrap();
        assert!(slot.is_none());
        *slot = Some(fence);
    }
}

impl Drop for AdmissionHandle<'_> {
    fn drop(&mut self) {
        if self.entry.state.mark_draining() {
            self.ledger.version.fetch_add(1, Ordering::Release);
        }
    }
}

impl<'a> Peer for Admission<'a> {
    fn open(
        &mut self,
        owner: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<Client, Error> {
        if *owner != self.handle.entry.owner {
            return Err(Error::Changed);
        }
        self.require_current_bounded(expires, &cancel)?;
        if !self.handle.entry.state.live() {
            return Err(Error::Changed);
        }
        let gate = cancel.clone();
        let mut peer = budget::lock_until(expires, &gate, &self.handle.entry.peer)?;
        if !self.handle.entry.state.live() {
            return Err(Error::Changed);
        }
        let client = peer.open(owner, expires, cancel)?;
        self.handle.entry.opened.store(true, Ordering::Release);
        Ok(client)
    }

    fn retire(&mut self, owner: &Owner) -> Result<bool, Error> {
        if *owner != self.handle.entry.owner {
            return Err(Error::Changed);
        }
        if self.handle.entry.state.completed() {
            return Ok(self.handle.entry.state.stopped());
        }
        if self.handle.entry.state.mark_draining() {
            self.handle.ledger.version.fetch_add(1, Ordering::Release);
        }
        let result = {
            let mut pin = self
                .handle
                .entry
                .pin
                .lock()
                .map_err(|_| Error::Unavailable)?;
            let mut peer = self
                .handle
                .entry
                .peer
                .lock()
                .map_err(|_| Error::Unavailable)?;
            let result = peer.retire(owner);
            if matches!(result, Ok(true)) {
                let release = pin.release();
                if release.changed {
                    self.handle.ledger.version.fetch_add(1, Ordering::Release);
                }
            }
            result
        };
        if matches!(result, Ok(true)) && self.handle.entry.state.mark_stopped() {
            self.handle.ledger.version.fetch_add(1, Ordering::Release);
        }
        result
    }
}
