//! Ready, maintenance health and traffic probe for the native IPsec attempt.
//! The connection deadline governs only start/ready; maintenance uses a fresh
//! short budget and the existing probe keeps its own timeout.
use super::*;
use crate::connection::macos::{
    probe::{self, Outcome},
    routing::{TransportDefault, TunnelPlan},
};
use std::net::IpAddr;

/// The plan and the transport decision are `Routes`, as they were inside
/// `register_utun`; configuring the owned utun is `Tunnel`.
fn prepare_owned_utun<T>(
    networks: &[String],
    families: (bool, bool),
    transport_default: impl FnOnce()
        -> Result<Option<TransportDefault>, crate::connection::routes::Error>,
    configure: impl FnOnce() -> Result<T, crate::connection::routes::Error>,
) -> Result<(TunnelPlan, T), Failure> {
    let mut configuring = false;
    TunnelPlan::prepare(networks, families, transport_default, |plan| {
        configuring = true;
        Ok((plan, configure()?))
    })
    .map_err(|_| {
        if configuring {
            Failure::at(Step::Tunnel)
        } else {
            Failure::at(Step::Routes)
        }
    })
}

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
            let egress = self.egress.as_deref().ok_or_else(unavailable)?;
            let families = (
                candidate.vips.iter().any(IpAddr::is_ipv4),
                candidate.vips.iter().any(IpAddr::is_ipv6),
            );
            let (route_plan, link) = prepare_owned_utun(
                &networks,
                families,
                || egress.transport_default(),
                || {
                    admission
                        .configure(&candidate, expires, self.canceled.clone())
                        .map_err(|_| crate::connection::routes::Error::Unavailable)
                },
            )?;
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
                        route_plan,
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
                    .map_err(route_acquire_failure)?
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

#[cfg(test)]
mod tests {
    //! `ready_driver` needs a root-built `NativeDomain`, so these drive the
    //! step split it delegates to, with the real `TunnelPlan::prepare`.
    use super::*;
    use crate::connection::routes::{Address, Error, NextHop};
    use std::cell::Cell;

    fn transport_default() -> TransportDefault {
        TransportDefault::from_egress(
            7,
            NextHop::Gateway(Address::unscoped("192.0.2.1".parse().unwrap())),
        )
        .unwrap()
    }

    /// Calls `prepare_owned_utun`, counting how often each callback ran.
    fn prepare(
        networks: &[&str],
        families: (bool, bool),
        decision: Result<Option<TransportDefault>, Error>,
        configured: Result<u16, Error>,
    ) -> (Result<u16, Failure>, usize, usize) {
        let networks: Vec<String> = networks.iter().map(|text| (*text).to_owned()).collect();
        let (decided, configures) = (Cell::new(0), Cell::new(0));
        let result = prepare_owned_utun(
            &networks,
            families,
            || {
                decided.set(decided.get() + 1);
                decision
            },
            || {
                configures.set(configures.get() + 1);
                configured
            },
        )
        .map(|(_, link)| link);
        (result, decided.get(), configures.get())
    }

    /// Before the owned utun is configured, a refused plan or a failed
    /// transport decision is `Routes`, and nothing is configured.
    #[test]
    fn plan_and_transport_failures_before_configuring_are_routes() {
        for (case, networks, families, decision, decided) in [
            (
                "unparsable network",
                &["10.20.0.0/33"][..],
                (true, false),
                Ok(None),
                0,
            ),
            (
                "no address family",
                &["10.20.0.0/24"][..],
                (false, false),
                Ok(None),
                0,
            ),
            (
                "unsupported family",
                &["2001:db8::/32"][..],
                (true, false),
                Ok(None),
                0,
            ),
            (
                "transport decision",
                &[][..],
                (true, false),
                Err(Error::Changed),
                1,
            ),
        ] {
            let (result, decisions, configures) = prepare(networks, families, decision, Ok(9));
            let failure = result.expect_err(case);
            assert_eq!(failure.step, Step::Routes, "{case}");
            assert_eq!(failure.state, ConnectionState::Dropped, "{case}");
            assert_eq!(failure.error, ErrorCode::BackendFailure, "{case}");
            assert_eq!((decisions, configures), (decided, 0), "{case}");
        }
    }

    /// Once the plan and the transport decision passed, a failed utun
    /// configuration is `Tunnel`; the same inputs that configure succeed.
    #[test]
    fn utun_configuration_failure_is_tunnel() {
        for (case, networks, decision, decided) in [
            ("split tunnel", &["10.20.0.0/24"][..], Ok(None), 0),
            ("full tunnel", &[][..], Ok(Some(transport_default())), 1),
        ] {
            let (result, decisions, configures) =
                prepare(networks, (true, false), decision, Err(Error::Unavailable));
            let failure = result.expect_err(case);
            assert_eq!(failure.step, Step::Tunnel, "{case}");
            assert_eq!(failure.state, ConnectionState::Dropped, "{case}");
            assert_eq!(failure.error, ErrorCode::BackendFailure, "{case}");
            assert_eq!((decisions, configures), (decided, 1), "{case}");

            // Control: the configured link comes back through the same path.
            let (result, decisions, configures) = prepare(networks, (true, false), decision, Ok(9));
            assert_eq!(result.ok(), Some(9), "{case}");
            assert_eq!((decisions, configures), (decided, 1), "{case}");
        }
    }
}
