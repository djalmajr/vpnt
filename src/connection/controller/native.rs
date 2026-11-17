use super::profiles::{ProfileUse, Profiles};
use super::*;
mod cleanup;
mod factory;
mod ipsec;
use crate::{
    connection::{
        macos::{
            Interfaces,
            egress::Egress,
            ppp::{OwnedPpp, OwnershipError},
            ppp_early_cleanup, probe,
            routing::{InterfaceToken, NativeBackend, Snapshot},
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
thread_local! {
    static READY_NETWORKS: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
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
    ) -> Result<
        (InterfaceToken, Vec<crate::connection::routes::Route>),
        crate::connection::routes::Error,
    > {
        READY_NETWORKS.with(|slot| {
            if let Some(observed) = slot.borrow_mut().as_mut() {
                *observed = networks.to_vec();
            }
        });
        self.0.register_ppp(link, owner, networks, canceled)
    }
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
    profile_use: Option<ProfileUse>,
    credentials: Option<Credentials>,
    routes: Routes<'a>,
    canceled: Arc<AtomicBool>,
    before: Option<Interfaces>,
    before_routes: Option<Snapshot>,
    client: Option<SslDriver>,
    link: Option<Arc<OwnedPpp>>,
    token: Option<InterfaceToken>,
    lease: Option<Lease>,
    dns: Option<DnsLease>,
    spawn_attempted: bool,
    stopped: bool,
    uncertain_cleanup: bool,
    fence_root: std::path::PathBuf,
    fence_owner: u32,
}
impl NativeAttempt<'_> {
    fn client_health(&mut self) -> Result<(), Failure> {
        self.profile_use
            .as_ref()
            .ok_or_else(Failure::unavailable)?
            .validate()
            .map_err(|_| Failure::unavailable())?;
        let update = self
            .client
            .as_mut()
            .ok_or_else(Failure::unavailable)?
            .poll()
            .map_err(|_| Failure::unavailable())?;
        if update.start_error.is_some() {
            return Err(Failure::unavailable());
        }
        if let Some(failure) = update.failure {
            return Err(Failure {
                state: match failure {
                    SslFailure::CredentialsRejected => ConnectionState::CredentialsRejected,
                    SslFailure::GatewayTimeout => ConnectionState::GatewayTimeout,
                },
                error: ErrorCode::BackendFailure,
            });
        }
        if update.exited {
            return Err(Failure::unavailable());
        }
        Ok(())
    }
    fn discover(&mut self) -> Result<bool, Failure> {
        if self.link.is_some() {
            return Ok(true);
        }
        let client = self.client.as_mut().ok_or_else(Failure::unavailable)?;
        let before = self.before.as_ref().ok_or_else(Failure::unavailable)?;
        match OwnedPpp::discover(client, before) {
            Ok(link) => {
                self.link = Some(Arc::new(link));
                Ok(true)
            }
            Err(OwnershipError::NotReady) => Ok(false),
            Err(_) => Err(Failure::unavailable()),
        }
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

fn apply_dns(
    configured: &[String],
    observation: &crate::connection::ssl_output::Observation,
    publish: impl FnOnce(&[std::net::Ipv4Addr], &[String]) -> Result<(), ()>,
) -> Result<bool, ()> {
    if observation.dns_invalid
        || observation.dns_count
            != Some((observation.dns_servers.len(), observation.dns_domains.len()))
    {
        return Err(());
    }
    let domains = if configured.is_empty() {
        &observation.dns_domains
    } else {
        configured
    };
    if domains.is_empty() || observation.dns_servers.is_empty() {
        return Ok(false);
    }
    publish(&observation.dns_servers, domains)?;
    Ok(true)
}
fn check(expires: Instant, canceled: &AtomicBool) -> Result<(), Failure> {
    if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
        return Err(Failure::unavailable());
    }
    Ok(())
}

fn bounded(expires: Instant, canceled: &AtomicBool) -> Result<Duration, Failure> {
    check(expires, canceled)?;
    let remaining = expires
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(3));
    if remaining.is_zero() {
        return Err(Failure::unavailable());
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
            });
        }
        check(expires, canceled)?;
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
                })?,
        );
        // Preflight failures have no spawned child. After attempting spawn,
        // uncertainty must survive even if setup returns an error.
        check(expires, canceled)?;
        Runtime::installed()
            .and_then(|_| Runtime::verify_pinentry())
            .and_then(|_| Runtime::verify_ppp_supervisor())
            .map_err(|error| Failure {
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
            })?;
        check(expires, canceled)?;
        let egress = Egress::select(&self.profile, canceled, bounded(expires, canceled)?)
            .map_err(|_| Failure::unavailable())?;
        check(expires, canceled)?;
        self.before = Some(Interfaces::read().map_err(|_| Failure::unavailable())?);
        self.before_routes = Some(Snapshot::read().map_err(|_| Failure::unavailable())?);
        check(expires, canceled)?;
        let credentials = self.credentials.take().ok_or_else(Failure::unavailable)?;
        self.client = Some(
            SslDriver::start(&self.profile, credentials, &egress, &self.canceled).map_err(
                |error| Failure {
                    state: if error == StartError::MissingProgram {
                        ConnectionState::MissingProgram
                    } else {
                        ConnectionState::Dropped
                    },
                    error: ErrorCode::BackendFailure,
                },
            )?,
        );
        self.spawn_attempted = true;
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.client_health()?;
        if !self.discover()? {
            return Ok(false);
        }
        let link = self.link.as_ref().unwrap();
        let mut routes = self.routes.lock().map_err(|_| Failure::unavailable())?;
        if self.token.is_none() {
            let client = self.client.as_ref().ok_or_else(Failure::unavailable)?;
            let networks = ssl_networks(&self.profile.networks, &client.split_observation())
                .ok_or_else(|| {
                    client.note_invalid_split();
                    Failure::unavailable()
                })?;
            #[cfg(test)]
            let mut backend = ObservedBackend(routes.backend_mut());
            #[cfg(not(test))]
            let backend = routes.backend_mut();
            let (token, plan) = backend
                .register_ppp(link, self.owner.clone(), &networks, &self.canceled)
                .map_err(|_| Failure::unavailable())?;
            self.token = Some(token); // retain before any fallible ADD/lease
            self.lease = Some(
                routes
                    .acquire(self.owner.clone(), &plan)
                    .map_err(|_| Failure::unavailable())?,
            );
            let observation = client.split_observation();
            apply_dns(
                &self.profile.dns_domains,
                &observation,
                |servers, domains| {
                    let proof = client.supervised_ppp().ok_or(())?;
                    self.dns =
                        Some(DnsLease::new(proof.child().service().clone()).map_err(|_| ())?);
                    self.dns
                        .as_ref()
                        .ok_or(())?
                        .publish(servers, domains)
                        .map_err(|_| ())
                },
            )
            .map_err(|_| Failure::unavailable())?;
            if !self.profile.dns_domains.is_empty() && observation.dns_servers.is_empty() {
                client.note_no_dns_servers();
            } else if self.profile.dns_domains.is_empty() && observation.dns_domains.is_empty() {
                client.note_no_dns_domain();
            }
        }
        routes
            .validate(self.lease.as_ref().ok_or_else(Failure::unavailable)?)
            .map_err(|_| Failure::unavailable())?;
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.client_health()?;
        let link = self.link.as_ref().ok_or_else(Failure::unavailable)?;
        if !link.is_current().unwrap_or(false) {
            return Err(Failure::unavailable());
        }
        self.routes
            .lock()
            .map_err(|_| Failure::unavailable())?
            .validate(self.lease.as_ref().ok_or_else(Failure::unavailable)?)
            .map_err(|_| Failure::unavailable())
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        let link = self.link.as_ref().ok_or_else(Failure::unavailable)?;
        match probe::probe(link, &self.profile, canceled, timeout) {
            probe::Outcome::Responsive(_) => Ok(true),
            probe::Outcome::Unresponsive | probe::Outcome::Canceled => Ok(false),
            _ => Err(Failure::unavailable()),
        }
    }
    fn cleanup(&mut self) -> bool {
        use crate::helper::runtime::cleanup::{self as diagnostic, Reason};
        diagnostic::begin();
        let complete = (|| {
            if !self.cleanup_network() {
                return false;
            }
            if let Some(profile) = &self.profile_use
                && profile.complete().is_err()
            {
                return diagnostic::refuse(Reason::ProfileCompletion);
            }
            self.profile_use = None;
            true
        })();
        diagnostic::finish(
            std::path::Path::new(crate::helper::paths::STATE),
            &self.owner,
            complete,
        );
        complete
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use crate::connection::ssl_output::Observation;

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
