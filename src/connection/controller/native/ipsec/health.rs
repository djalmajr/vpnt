//! Ready, maintenance health and traffic probe for the native IPsec attempt.
//! The connection deadline governs only start/ready; maintenance uses a fresh
//! short budget and the existing probe keeps its own timeout.
use super::*;
use crate::connection::macos::probe::{self, Outcome};

impl NativeIpsecAttempt<'_> {
    /// IKE selection and the owned utun are `Tunnel`; route registration and
    /// the lease are `Routes`.
    pub(super) fn ready_driver(&mut self) -> Result<bool, Failure> {
        let unavailable = || Failure::at(Step::Tunnel);
        let routing = || Failure::at(Step::Routes);
        let expires = self.expires.ok_or_else(unavailable)?;
        check(expires, &self.canceled, Step::Tunnel)?;
        self.profile_use
            .as_ref()
            .ok_or_else(unavailable)?
            .validate()
            .map_err(|_| unavailable())?;
        if self.configured.is_none() {
            let selected = {
                let control = self.control.as_mut().ok_or_else(unavailable)?;
                match control.selected(expires, self.canceled.clone()) {
                    Ok(selected) => Some(selected),
                    Err(crate::connection::ipsec::Error::Busy) => None,
                    Err(_) => return Err(unavailable()),
                }
            };
            let Some((candidate, networks)) = selected else {
                return Ok(false);
            };
            check(expires, &self.canceled, Step::Tunnel)?;
            let admission = self.admission.as_mut().ok_or_else(unavailable)?;
            let link = admission
                .configure(&candidate, expires, self.canceled.clone())
                .map_err(|_| unavailable())?;
            self.selected_vips = candidate.vips.clone();
            self.selected_networks = networks.clone();
            self.configured = Some(link.clone());
            let peer = admission
                .native_peer(expires, self.canceled.clone())
                .map_err(|_| unavailable())?;
            let work = admission
                .begin_routes(expires, self.canceled.clone())
                .map_err(|_| routing())?;
            let owner = self.owner.clone();
            let context = self.domain.context().clone();
            let canceled = self.canceled.clone();
            let (token, plan) = {
                let mut routes =
                    lock_until(&self.routes, expires, &canceled).map_err(|()| routing())?;
                routes
                    .backend_mut()
                    .register_utun(
                        &link,
                        (context, peer),
                        owner.clone(),
                        &networks,
                        &canceled,
                        work,
                    )
                    .map_err(|_| routing())?
            };
            self.token = Some(token);
            let lease = {
                let mut routes =
                    lock_until(&self.routes, expires, &canceled).map_err(|()| routing())?;
                routes
                    .acquire_guarded(owner.clone(), &plan, || {
                        if canceled.load(Ordering::Acquire) {
                            Err(crate::connection::routes::Error::Canceled)
                        } else if Instant::now() >= expires {
                            Err(crate::connection::routes::Error::TimedOut)
                        } else {
                            Ok(())
                        }
                    })
                    .map_err(|_| routing())?
            };
            self.lease = Some(OwnedLease::new(lease, owner));
            check(expires, &self.canceled, Step::Routes)?;
            return Ok(true);
        }
        self.revalidate(expires, Step::Tunnel)
    }

    pub(super) fn healthy_driver(&mut self) -> Result<(), Failure> {
        // Maintenance is outside the 60 s connection deadline. Use a fresh
        // short budget and the same real cancellation flag.
        let expires = Instant::now() + Duration::from_secs(2);
        check(expires, &self.canceled, Step::Health)?;
        if !self.revalidate(expires, Step::Health)? {
            return Err(Failure::at(Step::Health));
        }
        Ok(())
    }

    /// `step`: `Health` for maintenance; `Tunnel` if a ready poll repeats.
    fn revalidate(&mut self, expires: Instant, step: Step) -> Result<bool, Failure> {
        let unavailable = || Failure::at(step);
        self.profile_use
            .as_ref()
            .ok_or_else(unavailable)?
            .validate()
            .map_err(|_| unavailable())?;
        let configured = self.configured.as_ref().ok_or_else(unavailable)?;
        configured.validate().map_err(|_| unavailable())?;
        self.admission
            .as_ref()
            .ok_or_else(unavailable)?
            .native_peer(expires, self.canceled.clone())
            .map_err(|_| unavailable())?;
        let selected = {
            let control = self.control.as_mut().ok_or_else(unavailable)?;
            control.selected(expires, self.canceled.clone())
        };
        let (candidate, networks): (Candidate, Vec<String>) = match selected {
            Ok(selected) => selected,
            Err(crate::connection::ipsec::Error::Busy) => return Ok(false),
            Err(_) => return Err(unavailable()),
        };
        if !same_selection(
            &candidate,
            &networks,
            &self.selected_vips,
            &self.selected_networks,
        ) {
            return Err(unavailable());
        }
        let lease = self.lease.as_ref().ok_or_else(unavailable)?;
        let mut routes =
            lock_until(&self.routes, expires, &self.canceled).map_err(|()| unavailable())?;
        lease.validate(&mut routes).map_err(|_| unavailable())?;
        Ok(true)
    }

    /// A periodic probe failure is `Health`; the worker marks the initial
    /// probe, which verifies the new tunnel, as `Verify`.
    pub(super) fn probe_driver(
        &mut self,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> Result<bool, Failure> {
        let unavailable = || Failure::at(Step::Health);
        if canceled.load(Ordering::Acquire) {
            return Ok(false);
        }
        if !std::ptr::eq(canceled, self.canceled.as_ref()) {
            return Err(unavailable());
        }
        let link = self.configured.as_ref().ok_or_else(unavailable)?;
        let context = self.domain.context().as_ref();
        match probe::probe_utun(
            link,
            (context, &self.owner),
            &self.profile,
            &self.canceled,
            timeout,
        ) {
            Outcome::Responsive(_) => Ok(true),
            Outcome::Unresponsive | Outcome::Canceled => Ok(false),
            Outcome::InvalidLink | Outcome::InvalidTarget => Err(unavailable()),
        }
    }
}
