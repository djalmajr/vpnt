//! Start half of the native IPsec attempt: reserve, prepare, capture the
//! original typed interface and start Control without consuming credentials
//! before the guarded operation.
use super::*;
use crate::connection::ipsec::Peer;
use crate::connection::macos::ipsec_egress::IpsecEgress;

impl NativeIpsecAttempt<'_> {
    pub(super) fn start_driver(
        &mut self,
        canceled: &AtomicBool,
        expires: Instant,
    ) -> Result<(), Failure> {
        if self.profile.kind != VpnKind::Ipsec {
            return Err(missing_program());
        }
        check(expires, canceled)?;
        self.expires = Some(expires);
        let profile_use = self
            .profiles
            .begin(&self.profile, self.owner.generation)
            .map_err(profile_failure)?;
        self.profile_use = Some(profile_use);
        let egress = IpsecEgress::select(&self.profile, canceled, bounded(expires, canceled)?)
            .map_err(|_| unavailable())?;
        let domain = self.domain.clone();
        let ledger = domain.ledger().clone();
        let mut registry = lock_until(domain.registry(), expires, canceled)?;
        let reservation = registry
            .reserve(self.owner.clone())
            .map_err(|_| unavailable())?;
        self.reservation = Some(reservation);
        let prepared = ledger.prepare(
            &registry,
            self.reservation.as_ref().ok_or_else(unavailable)?,
            &self.profile,
            Arc::new(egress),
            (expires, self.canceled.clone()),
        );
        let (config, admission) = keep_for_control(&mut self.reservation, prepared)?;
        drop(registry);
        self.admission = Some(admission.clone());
        let mut admission = admission;
        // The original Admission peer must be opened before capture/start.
        let client = admission
            .open(&self.owner, expires, self.canceled.clone())
            .map_err(|_| unavailable())?;
        drop(client);
        admission
            .capture_interface(expires, self.canceled.clone())
            .map_err(|_| unavailable())?;
        let reservation = self.reservation.take().ok_or_else(unavailable)?;
        let control = match Control::new(
            domain.registry().clone(),
            reservation,
            config,
            admission.clone(),
        ) {
            Ok(control) => control,
            Err((_error, reservation)) => {
                self.reservation = Some(reservation);
                return Err(unavailable());
            }
        };
        self.control = Some(control);
        let credentials = self.credentials.take().ok_or_else(unavailable)?;
        self.control
            .as_mut()
            .ok_or_else(unavailable)?
            .start(credentials, expires, self.canceled.clone())
            .map_err(|_| unavailable())
    }
}
