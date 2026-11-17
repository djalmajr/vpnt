//! Typed retained-UTUN pin lifecycle owned by one ledger entry.
//!
//! Configured and failed variants share the private hold policy: payload until
//! explicit stop, metadata retained across release. No route/namespace
//! authority is granted here.
use super::resource::Absence;
use crate::helper::runtime::cleanup::{self as diagnostic, Reason};

use crate::connection::{
    ipsec::Error,
    macos::{
        utun_observer::RetainedInterface,
        vip::{ConfiguredUtun, RetiredUtun, VipFailure},
    },
};
use hold::{Hold, Release};
use std::sync::Arc;

mod hold;

pub(in crate::connection::ipsec::producer) enum PinState<'a> {
    Empty,
    Captured(RetainedInterface),
    /// Passive domain retained after the captured FD is closed. A failed
    /// capture keeps None and continues to require the original fallback.
    RetiredCaptured(Option<RetiredUtun>),
    Configured(Hold<ConfiguredUtun<'a>, RetiredUtun>),
    Failed(Hold<VipFailure, RetiredUtun>),
}

impl<'a> PinState<'a> {
    pub(in crate::connection::ipsec::producer) fn new() -> Self {
        Self::Empty
    }

    pub(in crate::connection::ipsec::producer) fn empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    pub(in crate::connection::ipsec::producer) fn take_retained(
        &mut self,
    ) -> Option<RetainedInterface> {
        match std::mem::replace(self, Self::Empty) {
            Self::Captured(retained) => Some(retained),
            other => {
                *self = other;
                None
            }
        }
    }

    pub(in crate::connection::ipsec::producer) fn store_configured(
        &mut self,
        strong: Arc<ConfiguredUtun<'a>>,
        retired: Option<RetiredUtun>,
    ) {
        *self = Self::Configured(Hold::new(strong, retired));
    }

    pub(in crate::connection::ipsec::producer) fn store_failed(
        &mut self,
        failure: VipFailure,
        retired: Option<RetiredUtun>,
    ) {
        *self = Self::Failed(Hold::new(Arc::new(failure), retired));
    }

    /// Drop the ledger-owned payload only after a confirmed stop. The captured
    /// metadata is retained for the subsequent fresh known-domain absence.
    pub(in crate::connection::ipsec::producer) fn release(&mut self) -> Release {
        self.release_with(RetainedInterface::retirement)
    }

    fn release_with(
        &mut self,
        capture: impl FnOnce(&RetainedInterface) -> Result<RetiredUtun, Error>,
    ) -> Release {
        match self {
            Self::Empty | Self::RetiredCaptured(_) => Release::default(),
            Self::Captured(retained) => {
                let retired = capture(retained).ok();
                *self = Self::RetiredCaptured(retired);
                Release {
                    changed: true,
                    external: false,
                }
            }
            Self::Configured(hold) => hold.release(),
            Self::Failed(hold) => hold.release(),
        }
    }

    /// `None` = still owned/external; otherwise fresh known/fallback answer.
    pub(in crate::connection::ipsec::producer) fn claim_absence(
        &self,
        fallback: &dyn Absence,
    ) -> Result<Option<bool>, Error> {
        let result = self.claim_absence_with(fallback, RetiredUtun::gone);
        if !matches!(result, Ok(Some(true))) {
            diagnostic::mark(match self {
                Self::Captured(_) => Reason::PinStillOwned,
                Self::RetiredCaptured(Some(_)) => Reason::AbsenceKnownUtun,
                Self::Configured(hold) => hold.absence_reason(),
                Self::Failed(hold) => hold.absence_reason(),
                _ => Reason::AbsenceFallback,
            });
        }
        result
    }

    fn claim_absence_with(
        &self,
        fallback: &dyn Absence,
        known: impl FnOnce(&RetiredUtun) -> Result<bool, Error>,
    ) -> Result<Option<bool>, Error> {
        match self {
            Self::Empty => Ok(Some(fallback.complete()?)),
            Self::Captured(_) => Ok(None),
            Self::RetiredCaptured(Some(retired)) => Ok(Some(known(retired)?)),
            Self::RetiredCaptured(None) => Ok(Some(fallback.complete()?)),
            Self::Configured(hold) => hold.claim_absence(known, fallback),
            Self::Failed(hold) => hold.claim_absence(known, fallback),
        }
    }
}

#[cfg(test)]
mod tests;
