use super::profiles::{ProfileUse, Profiles};
use super::*;
mod cleanup;
mod factory;
mod ipsec;
mod ovpn;
#[cfg(target_os = "macos")]
pub(crate) mod ovpn_base;
use crate::{
    connection::{
        macos::{
            Interfaces,
            egress::{Egress, acquire_ssl_routes},
            ppp::{OwnedPpp, OwnershipError},
            ppp_early_cleanup, probe,
            routing::{InterfaceToken, NativeBackend, Snapshot, TransportDefault},
            store::DnsLease,
        },
        routes::{Coordinator, Lease, Owner},
        ssl::{SslDriver, SslFailure, StartError},
    },
    helper::{
        controller_lock::ControllerLock,
        protocol::{Message, Request},
        runtime::{Runtime, RuntimeError},
    },
    model::VpnKind,
    storage::StoreError,
};
use factory::NativeFactory;
use ipsec::NativeDomain;
use std::sync::{
    Mutex,
    atomic::Ordering,
    mpsc::{Receiver, SyncSender},
};

type Routes<'a> = Arc<Mutex<Coordinator<NativeBackend<'a>>>>;

#[cfg(test)]
type DnsPublication = (Vec<std::net::Ipv4Addr>, Vec<String>);

#[cfg(test)]
thread_local! {
    static READY_NETWORKS: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
    static READY_DNS: std::cell::RefCell<Option<Vec<DnsPublication>>> = const { std::cell::RefCell::new(None) };
    // A plan `register_ppp` returns, with a token for a fixture scope on the
    // plan's first link route, instead of calling the root-only writer.
    static READY_PLAN: std::cell::RefCell<Option<Vec<crate::connection::routes::Route>>> = const { std::cell::RefCell::new(None) };
}

// Forward the exact call to the real backend while observing its input in a
// fixture. The native attachment itself remains subject to the real root gate.
#[cfg(test)]
struct ObservedBackend<'b, 'a>(&'b mut NativeBackend<'a>);
#[cfg(test)]
impl ObservedBackend<'_, '_> {
    fn register_ppp(
        &mut self,
        link: &Arc<OwnedPpp>,
        owner: Owner,
        networks: &[String],
        canceled: &Arc<AtomicBool>,
        egress: Option<&Egress>,
    ) -> Result<
        (InterfaceToken, Vec<crate::connection::routes::Route>),
        crate::connection::routes::Error,
    > {
        READY_NETWORKS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                *observed = networks.to_vec();
            }
        });
        if let Some(plan) = READY_PLAN.with(|slot| slot.borrow_mut().take()) {
            let link_route = plan
                .iter()
                .find(|route| TransportDefault::try_from(**route).is_err())
                .copied()
                .ok_or(crate::connection::routes::Error::Invalid)?;
            return Ok((self.0.fixture_scope(owner, link_route), plan));
        }
        self.0.register_ppp(link, owner, networks, canceled, egress)
    }
}

// Test-only seam: with an injected egress error, an unprivileged fixture
// passes the installed runtime checks and `Egress::select` returns that error,
// so the real consumer in `start` maps it. Builds without `cfg(test)` always
// run both real calls.
#[cfg(test)]
thread_local! {
    static EGRESS_FAILURE: std::cell::Cell<Option<crate::connection::routes::Error>> = const { std::cell::Cell::new(None) };
}

fn installed_runtime() -> Result<(), RuntimeError> {
    #[cfg(test)]
    if EGRESS_FAILURE.with(std::cell::Cell::get).is_some() {
        return Ok(());
    }
    Runtime::installed()
        .and_then(|_| Runtime::verify_pinentry())
        .and_then(|_| Runtime::verify_ppp_supervisor())
}

fn select_egress(
    profile: &Profile,
    canceled: &AtomicBool,
    timeout: Duration,
) -> Result<Egress, crate::connection::routes::Error> {
    #[cfg(test)]
    if let Some(error) = EGRESS_FAILURE.with(std::cell::Cell::get) {
        return Err(error);
    }
    Egress::select(profile, canceled, timeout)
}
/// Prepared root-side consumer. Not an installer or an elevation entrypoint.
/// The prepared helper binds uid to its inherited caller and keeps this
/// controller/lock alive through EOF and every outstanding cleanup. Installed
/// execution through the application broker remains unverified.
pub fn run_ssl(
    controller: &ControllerLock,
    uid: u32,
    requests: Receiver<Request>,
    output: SyncSender<Message>,
) -> Result<(), ErrorCode> {
    // SAFETY: queries have no memory preconditions; no process starts on denial.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(ErrorCode::PermissionDenied);
    }
    controller
        .validate()
        .map_err(|_| ErrorCode::UntrustedConfiguration)?;
    let store = Arc::new(Profiles::for_user(uid).map_err(|_| ErrorCode::UntrustedConfiguration)?);
    let profiles = store
        .load()
        .map_err(|_| ErrorCode::UntrustedConfiguration)?;
    let backend = NativeBackend::new(controller).map_err(|_| ErrorCode::Unavailable)?;
    let routes = Arc::new(Mutex::new(
        Coordinator::new(backend).map_err(|_| ErrorCode::Unavailable)?,
    ));
    // A missing IPsec domain is a real unsupported capability; SSL still runs.
    let domain = NativeDomain::new(controller).ok();
    engine::run(
        NativeFactory::new(routes, store, domain, uid),
        uid,
        profiles,
        requests,
        output,
        Timing::default(),
    )
}
struct NativeAttempt<'a> {
    owner: Owner,
    profile: Profile,
    profiles: Arc<Profiles>,
    credentials: Option<Credentials>,
    routes: Routes<'a>,
    canceled: Arc<AtomicBool>,
    before: Option<Interfaces>,
    before_routes: Option<Snapshot>,
    client: Option<SslDriver>,
    egress: Option<Box<Egress>>,
    link: Option<Arc<OwnedPpp>>,
    token: Option<InterfaceToken>,
    requires_transport_default: bool,
    lease: Option<Lease>,
    dns: Option<DnsLease>,
    spawn_attempted: bool,
    stopped: bool,
    uncertain_cleanup: bool,
    fence_root: std::path::PathBuf,
    fence_owner: u32,
    /// A journal of this generation is on disk: set by (i) or (ii), cleared
    /// at `start` and by (iii). The factory reads it for the exit watchdog.
    journaled: Arc<AtomicBool>,
    // Last: recovery must not classify this attempt as dead while its other
    // fields are still being dropped during unwind.
    profile_use: Option<ProfileUse>,
}
impl NativeAttempt<'_> {
    /// `step`: `Tunnel` while the tunnel comes up, `Health` once connected.
    fn client_health(&mut self, step: Step) -> Result<(), Failure> {
        let at = || Failure::at(step);
        self.profile_use
            .as_ref()
            .ok_or_else(at)?
            .validate()
            .map_err(|_| at())?;
        let update = self
            .client
            .as_mut()
            .ok_or_else(at)?
            .poll()
            .map_err(|_| at())?;
        if update.start_error.is_some() {
            // A setup error retained after spawn keeps the step it was born in.
            let born = self.client.as_ref().and_then(SslDriver::start_step);
            return Err(Failure::at(born.unwrap_or(step)));
        }
        if let Some(failure) = update.failure {
            return Err(Failure {
                state: match failure {
                    SslFailure::CredentialsRejected => ConnectionState::CredentialsRejected,
                    SslFailure::GatewayTimeout => ConnectionState::GatewayTimeout,
                },
                error: ErrorCode::BackendFailure,
                step,
            });
        }
        if update.exited {
            return Err(at());
        }
        Ok(())
    }
    /// `step`: `Egress` while the plan is acquired (the outgoing network moved
    /// since start), `Health` once connected.
    fn validate_transport_egress(&self, step: Step) -> Result<(), Failure> {
        let at = || Failure::at(step);
        validate_ssl_egress(step, self.requires_transport_default, || {
            self.egress
                .as_ref()
                .ok_or_else(at)?
                .is_current(&self.profile)
                .map_err(|_| at())
        })
    }

    fn discover(&mut self) -> Result<bool, Failure> {
        if self.link.is_some() {
            return Ok(true);
        }
        let at = || Failure::at(Step::Tunnel);
        let client = self.client.as_mut().ok_or_else(at)?;
        let before = self.before.as_ref().ok_or_else(at)?;
        match OwnedPpp::discover(client, before) {
            Ok(link) => {
                self.link = Some(Arc::new(link));
                Ok(true)
            }
            Err(OwnershipError::NotReady) => Ok(false),
            Err(_) => Err(at()),
        }
    }
    /// (i) The first `Ok(true)` journals the established connection, with
    /// everything acquired, DNS included. A lock held elsewhere is "not yet":
    /// the next poll tries again within the connect deadline. A failed write,
    /// or a record that cannot be built, fails the connection at the routes
    /// step, whose lease the journal records, and then takes the ordinary
    /// cleanup.
    fn established(&mut self) -> Result<bool, Failure> {
        if !self.journaled.load(Ordering::Acquire) {
            match self.journal(Reason::Journal) {
                Ok(()) => {}
                Err(AbandonError::Busy) => return Ok(false),
                Err(_) => return Err(Failure::at(Step::Routes)),
            }
        }
        Ok(true)
    }
}

fn ssl_networks(
    profile: &[String],
    observation: &crate::connection::ssl_output::Observation,
) -> Option<Vec<String>> {
    use crate::connection::routes::Network;
    use std::net::{IpAddr, Ipv4Addr};

    if !profile.is_empty() {
        return Some(profile.to_vec());
    }
    if observation.split_invalid || observation.split_count != Some(observation.split.len()) {
        return None;
    }
    if observation.split.is_empty()
        || observation
            .split
            .iter()
            .any(|(ip, prefix)| ip.is_unspecified() && *prefix == 0)
    {
        return Some(Vec::new());
    }
    let forbidden: [Network; 3] = ["127.0.0.0/8", "224.0.0.0/4", "169.254.0.0/16"]
        .map(|value| value.parse().expect("fixed network"));
    let mut networks = Vec::with_capacity(observation.split.len());
    for &(ip, prefix) in &observation.split {
        let network = Network::new(IpAddr::V4(ip), prefix).ok()?;
        if ip == Ipv4Addr::UNSPECIFIED
            || forbidden.iter().any(|blocked| {
                blocked.contains(network.address()) || network.contains(blocked.address())
            })
        {
            return None;
        }
        networks.push(format!("{ip}/{prefix}"));
    }
    Some(networks)
}

/// Every failure here, including the `DnsLease` that `publish` opens, is born
/// at the `Dns` step.
fn apply_dns(
    configured: &[String],
    observation: &crate::connection::ssl_output::Observation,
    publish: impl FnOnce(&[std::net::Ipv4Addr], &[String]) -> Result<(), ()>,
) -> Result<bool, Failure> {
    if observation.dns_invalid
        || observation.dns_count
            != Some((observation.dns_servers.len(), observation.dns_domains.len()))
    {
        return Err(Failure::at(Step::Dns));
    }
    let domains = if configured.is_empty() {
        &observation.dns_domains
    } else {
        configured
    };
    if domains.is_empty() || observation.dns_servers.is_empty() {
        return Ok(false);
    }
    publish(&observation.dns_servers, domains).map_err(|()| Failure::at(Step::Dns))?;
    Ok(true)
}
/// `step`: the step the guarded operation belongs to.
fn check(expires: Instant, canceled: &AtomicBool, step: Step) -> Result<(), Failure> {
    if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
        return Err(Failure::at(step));
    }
    Ok(())
}

fn bounded(expires: Instant, canceled: &AtomicBool, step: Step) -> Result<Duration, Failure> {
    check(expires, canceled, step)?;
    let remaining = expires
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(3));
    if remaining.is_zero() {
        return Err(Failure::at(step));
    }
    Ok(remaining)
}

impl Attempt for NativeAttempt<'_> {
    fn abandon(&mut self, reason: Reason) -> Result<(), AbandonError> {
        self.abandon_ssl(reason)
    }
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        if self.profile.kind != VpnKind::Ssl {
            return Err(Failure {
                state: ConnectionState::MissingProgram,
                error: ErrorCode::MissingProgram,
                step: Step::Profile,
            });
        }
        self.journaled.store(false, Ordering::Release);
        check(expires, canceled, Step::Profile)?;
        self.profile_use = Some(
            self.profiles
                .begin(&self.profile, self.owner.generation)
                .map_err(|error| Failure {
                    state: ConnectionState::Dropped,
                    error: match error {
                        StoreError::Busy => ErrorCode::ProfileBusy,
                        StoreError::NotFound => ErrorCode::ProfileNotFound,
                        _ => ErrorCode::UntrustedConfiguration,
                    },
                    step: Step::Profile,
                })?,
        );
        // Preflight failures have no spawned child. After attempting spawn,
        // uncertainty must survive even if setup returns an error.
        check(expires, canceled, Step::Runtime)?;
        installed_runtime().map_err(|error| Failure {
            state: if error == RuntimeError::Missing {
                ConnectionState::MissingProgram
            } else {
                ConnectionState::Dropped
            },
            error: if error == RuntimeError::Missing {
                ErrorCode::MissingProgram
            } else {
                ErrorCode::UntrustedConfiguration
            },
            step: Step::Runtime,
        })?;
        check(expires, canceled, Step::Egress)?;
        let egress = select_egress(
            &self.profile,
            canceled,
            bounded(expires, canceled, Step::Egress)?,
        )
        .map_err(|_| Failure::at(Step::Egress))?;
        // The interface and route baselines belong to the client start: the
        // owned link and routes are later identified against them.
        let spawn = || Failure::at(Step::Spawn);
        check(expires, canceled, Step::Spawn)?;
        self.before = Some(Interfaces::read().map_err(|_| spawn())?);
        self.before_routes = Some(Snapshot::read().map_err(|_| spawn())?);
        check(expires, canceled, Step::Spawn)?;
        let credentials = self.credentials.take().ok_or_else(spawn)?;
        self.client = Some(
            SslDriver::start(&self.profile, credentials, &egress, &self.canceled).map_err(
                |error| Failure {
                    state: if error == StartError::MissingProgram {
                        ConnectionState::MissingProgram
                    } else {
                        ConnectionState::Dropped
                    },
                    error: ErrorCode::BackendFailure,
                    step: Step::Spawn,
                },
            )?,
        );
        self.egress = Some(Box::new(egress));
        self.spawn_attempted = true;
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.client_health(Step::Tunnel)?;
        if !self.discover()? {
            return Ok(false);
        }
        let link = self.link.as_ref().unwrap();
        let at = || Failure::at(Step::Routes);
        let mut routes = self.routes.lock().map_err(|_| at())?;
        if self.token.is_none() {
            let client = self.client.as_ref().ok_or_else(at)?;
            let networks = ssl_networks(&self.profile.networks, &client.split_observation())
                .ok_or_else(|| {
                    client.note_invalid_split();
                    at()
                })?;
            macro_rules! setup_routes {
                () => {{
                    #[cfg(test)]
                    let mut backend = ObservedBackend(routes.backend_mut());
                    #[cfg(not(test))]
                    let backend = routes.backend_mut();
                    let (token, plan) = backend
                        .register_ppp(
                            link,
                            self.owner.clone(),
                            &networks,
                            &self.canceled,
                            self.egress.as_deref(),
                        )
                        .map_err(|_| at())?;
                    self.token = Some(token); // retain before any fallible validation or ADD
                    // This is a dependency of the plan even if acquire borrows it.
                    self.requires_transport_default = plan_requires_transport_default(&plan);
                    self.validate_transport_egress(Step::Egress)?;
                    self.lease = Some(
                        acquire_ssl_routes(
                            &mut routes,
                            self.owner.clone(),
                            &plan,
                            self.egress.as_deref(),
                            Snapshot::read,
                        )
                        .map_err(route_acquire_failure)?,
                    );
                }};
            }
            #[cfg(test)]
            if !READY_DNS.with(|slot| slot.borrow().is_some()) {
                setup_routes!();
            }
            #[cfg(not(test))]
            setup_routes!();
            let observation = client.split_observation();
            apply_dns(
                &self.profile.dns_domains,
                &observation,
                |servers, domains| {
                    #[cfg(test)]
                    if READY_DNS.with(|slot| {
                        if let Some(calls) = slot.borrow_mut().as_mut() {
                            calls.push((servers.to_vec(), domains.to_vec()));
                            true
                        } else {
                            false
                        }
                    }) {
                        return Ok(());
                    }
                    let proof = client.supervised_ppp().ok_or(())?;
                    self.dns =
                        Some(DnsLease::new(proof.child().service().clone()).map_err(|_| ())?);
                    self.dns
                        .as_ref()
                        .ok_or(())?
                        .publish(servers, domains)
                        .map_err(|_| ())
                },
            )?;
            if !self.profile.dns_domains.is_empty() && observation.dns_servers.is_empty() {
                client.note_no_dns_servers();
            } else if self.profile.dns_domains.is_empty() && observation.dns_domains.is_empty() {
                client.note_no_dns_domain();
            }
        }
        // The DNS seam skipped `register_ppp`, so it has no lease to validate;
        // it still reaches the journal (i) below.
        #[cfg(test)]
        let unleased = READY_DNS.with(|slot| slot.borrow().is_some());
        #[cfg(not(test))]
        let unleased = false;
        let valid = if unleased {
            Ok(())
        } else {
            routes
                .validate(self.lease.as_ref().ok_or_else(at)?)
                .map_err(|_| at())
        };
        // The journal takes the coordinator again with try_lock.
        drop(routes);
        valid?;
        self.established()
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.client_health(Step::Health)?;
        let at = || Failure::at(Step::Health);
        let link = self.link.as_ref().ok_or_else(at)?;
        if !link.is_current().unwrap_or(false) {
            return Err(at());
        }
        self.validate_transport_egress(Step::Health)?;
        self.routes
            .lock()
            .map_err(|_| at())?
            .validate(self.lease.as_ref().ok_or_else(at)?)
            .map_err(|_| at())
    }
    /// A periodic probe failure is `Health`; the worker marks the initial
    /// probe, which verifies the new tunnel, as `Verify`.
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        let at = || Failure::at(Step::Health);
        let link = self.link.as_ref().ok_or_else(at)?;
        match probe::probe(link, &self.profile, canceled, timeout) {
            probe::Outcome::Responsive(_) => Ok(true),
            probe::Outcome::Unresponsive | probe::Outcome::Canceled => Ok(false),
            _ => Err(at()),
        }
    }
    fn cleanup(&mut self) -> bool {
        use crate::helper::runtime::cleanup as diagnostic;
        diagnostic::begin();
        let complete = self.settle();
        diagnostic::finish(
            std::path::Path::new(crate::helper::paths::STATE),
            &self.owner,
            complete,
        );
        complete
    }
}

fn plan_requires_transport_default(plan: &[crate::connection::routes::Route]) -> bool {
    plan.iter()
        .any(|route| TransportDefault::try_from(*route).is_ok())
}

fn validate_ssl_egress(
    step: Step,
    requires_transport_default: bool,
    is_current: impl FnOnce() -> Result<bool, Failure>,
) -> Result<(), Failure> {
    if requires_transport_default && !is_current()? {
        return Err(Failure::at(step));
    }
    Ok(())
}

/// SSL and IPsec both acquire the plan at the routes step.
fn route_acquire_failure(error: crate::connection::routes::AcquireError) -> Failure {
    if error.reason == crate::connection::routes::Error::Conflict {
        // SAFETY: the format string is fixed and has no conversion specifiers.
        unsafe {
            libc::syslog(
                libc::LOG_WARNING,
                c"vpnt: route plan conflicts with an existing route".as_ptr(),
            )
        };
    }
    Failure::at(Step::Routes)
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use crate::connection::ssl_output::Observation;

    #[test]
    fn connected_split_stays_healthy_after_physical_ipv6_renewal() {
        use std::net::IpAddr;
        let before: [IpAddr; 2] = ["192.0.2.2".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let after: [IpAddr; 2] = ["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()];
        assert_eq!(before[0], after[0]);
        assert_ne!(before[1], after[1]);
        use crate::connection::routes::{Address, Key, NextHop, Route, ppp_networks};
        let split = ppp_networks(&["10.0.0.0/8".into()], 3, true, true, None).unwrap();
        let mut full = ppp_networks(&[], 3, true, true, None).unwrap();
        let ipv6_renewal = || Ok(before == after);
        let health = Step::Health;
        let split_default = plan_requires_transport_default(&split);
        assert!(validate_ssl_egress(health, split_default, ipv6_renewal).is_ok());
        let full_default = plan_requires_transport_default(&full);
        assert!(validate_ssl_egress(health, full_default, ipv6_renewal).is_ok());

        let router = Address::unscoped("192.0.2.1".parse().unwrap());
        full.insert(
            0,
            Route {
                key: Key {
                    network: "0.0.0.0/0".parse().unwrap(),
                    scope: 7,
                },
                interface: 7,
                next_hop: NextHop::Gateway(router),
            },
        );
        let depends_on_default = plan_requires_transport_default(&full);
        assert!(depends_on_default);
        let failure = validate_ssl_egress(health, depends_on_default, ipv6_renewal).unwrap_err();
        assert_eq!(failure.step, Step::Health);
        assert!(validate_ssl_egress(health, depends_on_default, || Ok(true)).is_ok());
    }

    #[test]
    fn dns_requires_both_a_domain_and_a_server() {
        let mut value = Observation {
            dns_servers: vec!["172.16.0.4".parse().unwrap()],
            dns_domains: vec!["corp.example".into()],
            dns_count: Some((1, 1)),
            ..Observation::default()
        };
        let mut calls = Vec::new();
        assert!(
            apply_dns(&[], &value, |servers, domains| {
                calls.push((servers.to_vec(), domains.to_vec()));
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(calls.len(), 1);
        value.dns_domains.clear();
        value.dns_count = Some((1, 0));
        assert!(
            !apply_dns(&[], &value, |_, _| {
                calls.push((vec![], vec![]));
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(calls.len(), 1);
        value.dns_count = Some((1, 1));
        assert!(apply_dns(&[], &value, |_, _| Ok(())).is_err());
    }

    // `ready` publishes through `DnsLease`; the closure stands for its
    // `new`/`publish` result, which the real closure maps to `Err(())`.
    #[test]
    fn dns_failures_are_noted_at_the_dns_step() {
        let mut value = Observation {
            dns_servers: vec!["172.16.0.4".parse().unwrap()],
            dns_domains: vec!["corp.example.com".into()],
            dns_count: Some((1, 1)),
            ..Observation::default()
        };
        let failure = apply_dns(&[], &value, |_, _| Err(())).unwrap_err();
        assert_eq!(failure.step, Step::Dns);
        assert_eq!(failure.state, ConnectionState::Dropped);
        assert_eq!(failure.error, ErrorCode::BackendFailure);
        value.dns_count = Some((2, 1));
        let failure = apply_dns(&[], &value, |_, _| panic!("incoherent batch")).unwrap_err();
        assert_eq!(failure.step, Step::Dns);
        value.dns_count = Some((1, 1));
        value.dns_invalid = true;
        let failure = apply_dns(&[], &value, |_, _| panic!("invalid batch")).unwrap_err();
        assert_eq!(failure.step, Step::Dns);
    }

    #[test]
    fn configured_domains_override_gateway_and_require_servers() {
        let mut value = Observation {
            dns_servers: vec!["172.16.0.4".parse().unwrap()],
            dns_domains: vec!["gateway.example".into()],
            dns_count: Some((1, 1)),
            ..Observation::default()
        };
        let configured = vec!["corp.example.com".to_owned()];
        assert!(
            apply_dns(&configured, &value, |servers, domains| {
                assert_eq!(servers, value.dns_servers);
                assert_eq!(domains, configured);
                Ok(())
            })
            .unwrap()
        );
        assert!(
            apply_dns(&[], &value, |_, domains| {
                assert_eq!(domains, ["gateway.example"]);
                Ok(())
            })
            .unwrap()
        );
        value.dns_servers.clear();
        value.dns_count = Some((0, 1));
        assert!(
            !apply_dns(&configured, &value, |_, _| panic!(
                "must not publish without servers"
            ))
            .unwrap()
        );
    }

    fn observation(routes: &[(&str, u8)], count: Option<usize>) -> Observation {
        Observation {
            split: routes
                .iter()
                .map(|(ip, prefix)| (ip.parse().unwrap(), *prefix))
                .collect(),
            split_count: count,
            ..Observation::default()
        }
    }

    #[test]
    fn selection_honors_profile_and_complete_gateway_routes() {
        let split = observation(
            &[("10.0.0.0", 8), ("172.16.0.0", 16), ("192.168.1.0", 24)],
            Some(3),
        );
        let chosen = ssl_networks(&[], &split).unwrap();
        assert_eq!(chosen, ["10.0.0.0/8", "172.16.0.0/16", "192.168.1.0/24"]);
        let plan = crate::connection::routes::ppp_networks(&chosen, 9, true, false, None).unwrap();
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|route| route.interface == 9
            && route.next_hop == crate::connection::routes::NextHop::Interface));
        assert_eq!(
            ssl_networks(
                &["10.1.0.0/16".into()],
                &Observation {
                    split_invalid: true,
                    ..Observation::default()
                }
            )
            .unwrap(),
            ["10.1.0.0/16"]
        );
        assert!(
            ssl_networks(&[], &observation(&[], Some(0)))
                .unwrap()
                .is_empty()
        );
        assert!(
            ssl_networks(&[], &observation(&[("0.0.0.0", 0)], Some(1)))
                .unwrap()
                .is_empty()
        );
        assert!(ssl_networks(&[], &observation(&[("10.0.0.0", 8)], None)).is_none());
        assert!(ssl_networks(&[], &observation(&[("10.0.0.0", 8)], Some(2))).is_none());
        for (ip, prefix) in [
            ("127.0.0.0", 8),
            ("224.0.0.0", 4),
            ("169.254.0.0", 16),
            ("0.0.0.0", 8),
        ] {
            assert!(ssl_networks(&[], &observation(&[(ip, prefix)], Some(1))).is_none());
        }
    }

    #[test]
    fn selection_refuses_mismatched_count() {
        let mismatch = observation(&[("10.0.0.0", 8)], Some(2));
        assert!(ssl_networks(&[], &mismatch).is_none());
        let control = observation(&[("10.0.0.0", 8)], Some(1));
        assert_eq!(ssl_networks(&[], &control).unwrap(), ["10.0.0.0/8"]);
    }
}
