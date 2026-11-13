//! Typed retained-UTUN pin lifecycle owned by one ledger entry.
//!
//! Configured and failed variants share the private hold policy: payload until
//! explicit stop, metadata retained across release. No route/namespace
//! authority is granted here.
use super::resource::Absence;
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
        match self {
            Self::Empty => Release::default(),
            Self::Captured(_) => {
                *self = Self::Empty;
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
        match self {
            Self::Empty => Ok(Some(fallback.complete()?)),
            Self::Captured(_) => Ok(None),
            Self::Configured(hold) => hold.claim_absence(RetiredUtun::gone, fallback),
            Self::Failed(hold) => hold.claim_absence(RetiredUtun::gone, fallback),
        }
    }
}
