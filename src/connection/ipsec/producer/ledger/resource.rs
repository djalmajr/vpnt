//! Ledger-owned resource entry and the passive absence source.
//!
//! `Absence` is deliberately private to the producer. Production uses the
//! early-cleanup before-image; only a `#[cfg(test)]` script can substitute a
//! deterministic source, and it labels that evidence synthetic.
use super::super::{Error, NativePeer};
use super::pins::PinState;
use crate::connection::{
    ipsec::Config,
    macos::{ipsec_early_cleanup, routing::ResourceFence},
    routes::Owner,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

pub(in crate::connection::ipsec::producer) trait Absence:
    Send + Sync
{
    fn complete(&self) -> Result<bool, Error>;
}

struct BeforeAbsence(ipsec_early_cleanup::Before);

impl Absence for BeforeAbsence {
    fn complete(&self) -> Result<bool, Error> {
        self.0.complete().map_err(|_| Error::Unavailable)
    }
}

pub(in crate::connection::ipsec::producer) fn capture() -> Result<Arc<dyn Absence>, Error> {
    let before = ipsec_early_cleanup::capture().map_err(|_| Error::Unavailable)?;
    Ok(Arc::new(BeforeAbsence(before)))
}

const LIVE: u8 = 0;
const DRAINING: u8 = 1;
const COMPLETED: u8 = 2;

pub(in crate::connection::ipsec::producer) struct EntryState {
    phase: AtomicU8,
    stopped: AtomicBool,
}

impl EntryState {
    pub(in crate::connection::ipsec::producer) fn new() -> Self {
        Self {
            phase: AtomicU8::new(LIVE),
            stopped: AtomicBool::new(false),
        }
    }

    pub(in crate::connection::ipsec::producer) fn live(&self) -> bool {
        self.phase.load(Ordering::Acquire) == LIVE
    }

    pub(in crate::connection::ipsec::producer) fn draining(&self) -> bool {
        self.phase.load(Ordering::Acquire) == DRAINING
    }

    pub(in crate::connection::ipsec::producer) fn completed(&self) -> bool {
        self.phase.load(Ordering::Acquire) == COMPLETED
    }

    pub(in crate::connection::ipsec::producer) fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub(in crate::connection::ipsec::producer) fn mark_draining(&self) -> bool {
        self.phase
            .compare_exchange(LIVE, DRAINING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(in crate::connection::ipsec::producer) fn mark_stopped(&self) -> bool {
        !self.stopped.swap(true, Ordering::AcqRel)
    }

    pub(in crate::connection::ipsec::producer) fn complete(&self) {
        self.phase.store(COMPLETED, Ordering::Release);
    }
}

pub(in crate::connection::ipsec::producer) struct Entry<'a> {
    pub owner: Owner,
    pub serial: u64,
    pub peer: Arc<Mutex<NativePeer<'a>>>,
    pub absence: Arc<dyn Absence>,
    pub state: EntryState,
    /// Actual admitted metadata; clone, never credentials.
    pub config: Config,
    /// Typed retained/configured pin and its release state.
    pub pin: Mutex<PinState<'a>>,
    /// At most one passive route fence minted by this admission.
    pub route_fence: Mutex<Option<ResourceFence>>,
    pub opened: AtomicBool,
    pub configured: AtomicBool,
    /// Private authority token shared only with the originating admission.
    pub authority: Arc<()>,
}
