//! Bounded binding between the durable producer and the captured typed egress.
use super::*;
use crate::{
    connection::{
        ipsec::{Config, Registry, Reservation},
        macos::{ipsec_egress::IpsecEgress, utun_observer},
    },
    model::Profile,
};
use std::{net::IpAddr, num::NonZeroU16, sync::atomic::Ordering, time::Duration};

pub(in crate::connection::ipsec::producer) mod budget;

pub(super) struct Binding {
    profile: Profile,
    egress: Arc<IpsecEgress>,
    index: NonZeroU16,
    /// Test-only injected pre-attempt failure; never set in production.
    #[cfg(test)]
    fail_once: std::cell::Cell<Option<Error>>,
}

impl Binding {
    pub(super) fn new(
        profile: Profile,
        egress: Arc<IpsecEgress>,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<Self, Error> {
        let index = NonZeroU16::new(egress.interface_index()).ok_or(Error::Invalid)?;
        let binding = Self {
            profile,
            egress,
            index,
            #[cfg(test)]
            fail_once: std::cell::Cell::new(None),
        };
        binding.validate(expires, cancel)?;
        Ok(binding)
    }

    pub(super) fn index(&self) -> NonZeroU16 {
        self.index
    }

    pub(super) fn local(&self) -> IpAddr {
        self.egress.local()
    }

    pub(super) fn remote(&self) -> IpAddr {
        self.egress.remote()
    }

    /// Bounded, DNS-free revalidation. `false` is a changed binding; route
    /// timeout/cancel map to the IPsec errors and never become a fallback.
    pub(super) fn validate(&self, expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(error) = self.fail_once.take() {
            return Err(error);
        }
        let remaining = remaining(expires, cancel)?;
        let current = self
            .egress
            .is_current(&self.profile, cancel, remaining)
            .map_err(map_routes)?;
        if !current || self.egress.interface_index() != self.index.get() {
            return Err(Error::Changed);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn invalidate_for_test(&mut self) {
        self.profile.id = "stale-binding".into();
    }

    /// Inject one pre-attempt validation error without changing the binding.
    #[cfg(test)]
    pub(super) fn fail_next_validation(&self, error: Error) {
        self.fail_once.set(Some(error));
    }
}

fn remaining(expires: Instant, cancel: &AtomicBool) -> Result<Duration, Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    let remaining = expires
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::Timeout)?;
    Ok(remaining.min(Duration::from_secs(5)))
}

fn map_routes(error: crate::connection::routes::Error) -> Error {
    use crate::connection::routes::Error as RouteError;
    match error {
        RouteError::Canceled => Error::Canceled,
        RouteError::TimedOut => Error::Timeout,
        RouteError::Changed => Error::Changed,
        RouteError::Invalid => Error::Invalid,
        _ => Error::Unavailable,
    }
}

impl<'a> NativeContext<'a> {
    /// Protected production entry: validates the typed egress and constructs
    /// the Config itself. The old arbitrary-Config entry is test-only.
    pub fn prepare_bound<N: Observer>(
        self: &Arc<Self>,
        registry: &Registry<N>,
        reservation: &Reservation,
        profile: &Profile,
        egress: Arc<IpsecEgress>,
        budget: (Instant, Arc<AtomicBool>),
    ) -> Result<(Config, NativePeer<'a>), Error> {
        let (expires, cancel) = budget;
        let budget = budget::Budget::new(expires, cancel.clone());
        let _lock = budget.lock(&self.admission)?;
        if profile.id != reservation.owner().profile {
            return Err(Error::Changed);
        }
        let binding = bound::Binding::new(profile.clone(), egress, expires, &cancel)?;
        let configuration = Config::new(
            registry,
            reservation,
            profile,
            binding.local(),
            binding.remote(),
        )?;
        budget.check()?;
        let peer = self.prepare_shared(
            registry,
            reservation,
            &configuration,
            Some(binding.index()),
            Some(binding),
            Some(&budget),
        )?;
        Ok((configuration, peer))
    }

    #[cfg(test)]
    pub fn prepare<N: Observer>(
        self: &Arc<Self>,
        registry: &Registry<N>,
        reservation: &Reservation,
        configuration: &Config,
    ) -> Result<NativePeer<'a>, Error> {
        let _lock = self.admission.lock().map_err(|_| Error::Unavailable)?;
        self.prepare_shared(registry, reservation, configuration, None, None, None)
    }

    fn prepare_shared<N: Observer>(
        self: &Arc<Self>,
        registry: &Registry<N>,
        reservation: &Reservation,
        configuration: &Config,
        transport: Option<std::num::NonZeroU16>,
        binding: Option<bound::Binding>,
        budget: Option<&budget::Budget>,
    ) -> Result<NativePeer<'a>, Error> {
        registry.validate(reservation)?;
        if !configuration.matches(reservation) {
            return Err(Error::Changed);
        }
        self.validate()?;
        budget::check(budget)?;
        let hash = self
            .runtime
            .file_hashes()
            .get("bin/charon")
            .ok_or(Error::Changed)?
            .clone();
        // Take the active-map lock before the durable commit. A budget failure
        // here leaves no claim behind; after `Store::prepare` the peer is
        // returned even if the map insert is the last step.
        let mut active = budget::lock(budget, &self.active)?;
        let lease = self.store.prepare(
            reservation,
            configuration,
            (&self.identity).into(),
            hash,
            transport,
            budget,
        )?;
        let session = lease.record.session.clone();
        let producer = Arc::new(Mutex::new(child::Producer::new(
            self.clone(),
            lease,
            binding,
        )));
        active.insert(session, Arc::downgrade(&producer));
        Ok(NativePeer { producer })
    }
}

pub(super) fn map_budget(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::TimedOut => Error::Timeout,
        std::io::ErrorKind::ConnectionAborted => Error::Canceled,
        _ => Error::Unavailable,
    }
}

pub(super) fn map_handoff(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::TimedOut => Error::Timeout,
        std::io::ErrorKind::ConnectionAborted => Error::Canceled,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => Error::Changed,
        _ => Error::Unavailable,
    }
}

pub(super) fn map_check(error: utun_observer::Error) -> Error {
    match error {
        utun_observer::Error::Canceled => Error::Canceled,
        utun_observer::Error::Timeout => Error::Timeout,
        _ => Error::Unavailable,
    }
}

pub(super) fn map_observe(error: utun_observer::Error) -> Error {
    match error {
        utun_observer::Error::NotFound => Error::Unavailable,
        utun_observer::Error::Ambiguous | utun_observer::Error::Changed => Error::Changed,
        utun_observer::Error::Canceled => Error::Canceled,
        utun_observer::Error::Timeout => Error::Timeout,
        utun_observer::Error::Unavailable => Error::Unavailable,
        utun_observer::Error::Exhausted => Error::Exhausted,
        utun_observer::Error::Permission => Error::PermissionDenied,
        utun_observer::Error::Invalid => Error::Invalid,
    }
}
