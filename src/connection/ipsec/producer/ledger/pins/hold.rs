//! Shared private hold policy for a typed pin and its retirement metadata.
//!
//! The payload is retained until an explicit release after a confirmed stop.
//! The metadata survives release so known-domain absence can still be used;
//! only missing metadata falls back to the caller's before-image.
use super::super::resource::Absence;
use crate::connection::ipsec::Error;
use std::sync::{Arc, Weak};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::connection::ipsec::producer) struct Release {
    pub changed: bool,
    pub external: bool,
}

pub(in crate::connection::ipsec::producer) struct Hold<T, M> {
    strong: Option<Arc<T>>,
    weak: Weak<T>,
    metadata: Option<M>,
    released: bool,
}

impl<T, M> Hold<T, M> {
    pub(in crate::connection::ipsec::producer) fn new(
        payload: Arc<T>,
        metadata: Option<M>,
    ) -> Self {
        let weak = Arc::downgrade(&payload);
        Self {
            strong: Some(payload),
            weak,
            metadata,
            released: false,
        }
    }

    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn metadata(&self) -> Option<&M> {
        self.metadata.as_ref()
    }

    pub(in crate::connection::ipsec::producer) fn release(&mut self) -> Release {
        let changed = !self.released;
        if changed {
            self.released = true;
            let _ = self.strong.take();
        }
        Release {
            changed,
            external: self.weak.strong_count() > 0,
        }
    }

    /// `None` = still owned/external; otherwise a fresh known/fallback answer.
    pub(in crate::connection::ipsec::producer) fn claim_absence<K>(
        &self,
        known: K,
        fallback: &dyn Absence,
    ) -> Result<Option<bool>, Error>
    where
        K: FnOnce(&M) -> Result<bool, Error>,
    {
        if !self.released || self.strong.is_some() || self.weak.strong_count() > 0 {
            return Ok(None);
        }
        match self.metadata.as_ref() {
            Some(metadata) => Ok(Some(known(metadata)?)),
            None => Ok(Some(fallback.complete()?)),
        }
    }
}

#[cfg(test)]
#[path = "hold/tests.rs"]
mod tests;
