//! Active owned retirement for retained-UTUN scopes. Unlike the passive PPP
//! queue, this keeps a pin and the original peer until stop is confirmed; only
//! then is the pin released and fresh absence allowed to finish cleanup.
use super::super::resource_fence::RouteWork;
use super::*;
use crate::connection::macos::{
    Interfaces,
    sink::RetiredSink,
    vip::{ConfiguredUtun, Family},
};
use std::net::IpAddr;

/// Retained observation metadata plus the configured pin while stop is
/// unconfirmed. `release` drops the pin after a confirmed stop but keeps the
/// metadata needed for the fresh-absence check.
pub(super) trait Pin: Clone {
    fn name(&self) -> &str;
    fn index(&self) -> u16;
    fn absent(&self) -> Result<bool, Error>;
    fn release(&mut self);
}

/// The one original producer attempt for this owner. Never a PID lookup.
pub(super) trait Retire: Clone {
    fn retire_peer(&self, owner: &Owner) -> Result<bool, Error>;
}

/// Optional owned sink metadata; absence is the same fresh-table check.
pub(super) trait Sink: Clone {
    fn gone(&self) -> Result<bool, Error>;
}

/// Pinned configured UTUN metadata. The `Arc` pin is dropped by `release`
/// only after the original producer stop is confirmed; the name/index/VIP
/// metadata remains for the fresh-absence check.
#[derive(Clone)]
pub(super) struct UtunPin<'a> {
    link: Option<Arc<ConfiguredUtun<'a>>>,
    name: String,
    index: u16,
    vips: Vec<IpAddr>,
}

impl<'a> UtunPin<'a> {
    pub(super) fn new(link: &Arc<ConfiguredUtun<'a>>, index: u16) -> Self {
        Self {
            link: Some(link.clone()),
            name: link.name().to_owned(),
            index,
            vips: [Family::V4, Family::V6]
                .into_iter()
                .filter_map(|family| link.vip(family))
                .collect(),
        }
    }
    pub(super) fn link(&self) -> Option<&Arc<ConfiguredUtun<'a>>> {
        self.link.as_ref()
    }
}

impl Pin for UtunPin<'_> {
    fn name(&self) -> &str {
        &self.name
    }
    fn index(&self) -> u16 {
        self.index
    }
    fn absent(&self) -> Result<bool, Error> {
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let table = Snapshot::read()?;
        Ok(super::utun_absence::observed(
            self.name(),
            self.index(),
            &self.vips,
            &interfaces,
            &table,
        ))
    }
    fn release(&mut self) {
        self.link = None;
    }
}

struct Entry<P: Pin, E: Retire, S: Sink> {
    owner: Owner,
    pin: P,
    /// Cleared only after the original stop is confirmed.
    peer: Option<E>,
    sink: Option<S>,
    /// Retained until stop, pin release and fresh absence all succeed.
    work: Option<RouteWork>,
}

pub(super) struct Lifecycle<P: Pin, E: Retire, S: Sink> {
    entries: Mutex<Vec<Entry<P, E, S>>>,
}

impl<P: Pin, E: Retire, S: Sink> Lifecycle<P, E, S> {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(Vec::new()),
        })
    }
    /// Reject a duplicate owner/index and a busy queue before creating any
    /// guard, so a repeated registration cannot later stop an active producer.
    pub(super) fn open_guard(
        self: &Arc<Self>,
        conflict: bool,
        owner: Owner,
        pin: P,
        peer: E,
    ) -> Result<Guard<P, E, S>, Error> {
        if conflict {
            return Err(Error::Busy);
        }
        self.admit()?;
        Ok(self.guard(owner, pin, peer))
    }
    fn guard(self: &Arc<Self>, owner: Owner, pin: P, peer: E) -> Guard<P, E, S> {
        Guard {
            queue: self.clone(),
            entry: Some(Entry {
                owner,
                pin,
                peer: Some(peer),
                sink: None,
                work: None,
            }),
            stopped: false,
        }
    }
    pub(super) fn has_entries(&self) -> Result<bool, Error> {
        Ok(!self
            .entries
            .lock()
            .map_err(|_| Error::Unavailable)?
            .is_empty())
    }
    pub(super) fn admit(&self) -> Result<(), Error> {
        if self.has_entries()? {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// Neither the pin nor the peer is dropped here: a Drop must not perform
    /// I/O and must not release the last pin before a confirmed stop.
    fn enqueue(&self, entry: Entry<P, E, S>) {
        self.entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(entry);
    }
    /// Retry only this entry's original peer, then release the pin and check
    /// fresh absence. Errors and pending absence keep the whole entry.
    pub(super) fn reap(&self) -> Result<(), Error> {
        let mut queue = self.entries.lock().map_err(|_| Error::Unavailable)?;
        let mut kept = Vec::new();
        let mut first_error = None;
        for mut entry in queue.drain(..) {
            match entry.retire_and_absent() {
                Ok(true) => {}
                Ok(false) => kept.push(entry),
                Err(error) => {
                    first_error.get_or_insert(error);
                    kept.push(entry);
                }
            }
        }
        *queue = kept;
        first_error.map_or(Ok(()), Err)
    }
}

impl<P: Pin, E: Retire, S: Sink> Entry<P, E, S> {
    fn retire_and_absent(&mut self) -> Result<bool, Error> {
        if let Some(peer) = self.peer.as_ref() {
            if !peer.retire_peer(&self.owner)? {
                return Ok(false);
            }
            self.pin.release();
            self.peer = None;
        }
        if !self.pin.absent()? {
            return Ok(false);
        }
        if let Some(sink) = &self.sink
            && !sink.gone()?
        {
            return Ok(false);
        }
        if let Some(work) = self.work.as_mut() {
            work.complete()?;
        }
        Ok(true)
    }
}

pub(super) struct Guard<P: Pin, E: Retire, S: Sink> {
    queue: Arc<Lifecycle<P, E, S>>,
    entry: Option<Entry<P, E, S>>,
    stopped: bool,
}

impl<P: Pin, E: Retire, S: Sink> Guard<P, E, S> {
    /// Bind the linear work handle exactly once before any allocation. A
    /// failure leaves a fresh Pending work to Drop-complete (no allocation).
    pub(super) fn attach_work(&mut self, mut work: RouteWork) -> Result<(), Error> {
        let Some(entry) = self.entry.as_mut() else {
            return Err(Error::Changed);
        };
        if entry.work.is_some() {
            return Err(Error::Busy);
        }
        if work.owner() != &entry.owner {
            return Err(Error::Invalid);
        }
        work.bind(&entry.owner)?;
        entry.work = Some(work);
        Ok(())
    }
    /// Record sink metadata even when creation failed partway.
    pub(super) fn set_sink(&mut self, sink: Option<S>) {
        if let Some(entry) = self.entry.as_mut() {
            entry.sink = sink;
        }
    }
    /// Idempotently stop the original peer. A failed stop keeps the pin and
    /// returns Busy; only a confirmed stop releases the guard pin.
    pub(super) fn detach(&mut self) -> Result<bool, Error> {
        let Some(entry) = self.entry.as_mut() else {
            return Ok(true);
        };
        if self.stopped {
            return Ok(true);
        }
        let Some(peer) = entry.peer.as_ref() else {
            self.stopped = true;
            return Ok(true);
        };
        if !peer.retire_peer(&entry.owner).map_err(|_| Error::Busy)? {
            return Err(Error::Busy);
        }
        entry.pin.release();
        entry.peer = None;
        self.stopped = true;
        Ok(true)
    }
    /// Fresh absence after the confirmed stop. Never a route delete.
    pub(super) fn complete(&mut self) -> Result<bool, Error> {
        if !self.stopped {
            return Ok(false);
        }
        let Some(entry) = self.entry.as_mut() else {
            return Ok(true);
        };
        if !entry.pin.absent()? {
            return Ok(false);
        }
        if let Some(sink) = &entry.sink
            && !sink.gone()?
        {
            return Ok(false);
        }
        if let Some(work) = entry.work.as_mut() {
            work.complete()?;
        }
        self.entry = None;
        Ok(true)
    }
}

impl<P: Pin, E: Retire, S: Sink> Drop for Guard<P, E, S> {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.queue.enqueue(entry);
        }
    }
}

impl Sink for RetiredSink {
    fn gone(&self) -> Result<bool, Error> {
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let table = Snapshot::read()?;
        Ok(RetiredSink::gone(self, &interfaces, &table))
    }
}

#[cfg(test)]
#[path = "utun_retirement/tests.rs"]
mod tests;
