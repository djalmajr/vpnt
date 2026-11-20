//! OpenVPN session and network lifecycle for the native controller.
use super::remote_signer::SignContext;
use super::*;
use crate::{
    connection::{
        fence::{self, Fence, Interface, ProcessIdentity},
        macos::{process::Process, routing::ResourceFence, vip::ovpn_link::OvpnUtun},
        ovpn::{
            management::Reason as OvpnReason,
            network::NetworkConfig,
            profile::inspect,
            session::{
                ConfigSource, Launch, Progress, RestartPolicy, Session, SignError, Signatures,
                Signer,
            },
            signing::Padding,
        },
        routes::{AbandonedRoute, Error as RouteError},
    },
    helper::{paths, ppp_supervisor::ServiceId, runtime::Program},
    model::OvpnTls,
};
use std::{
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const RESTART_WITHDRAWAL_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_WAIT: Duration = Duration::from_secs(10);
const RECONFIGURE_BUDGET: Duration = Duration::from_secs(10);
const INITIAL_EPOCH: u64 = 0;

pub(super) trait OvpnSigners: Send + Sync {
    fn signer(&self, profile: &str, generation: u64, context: Arc<SignContext>) -> Box<dyn Signer>;
}

// Session takes an owned implementation of Signer, while the factory does
// not know the provider's concrete type.
struct BoxedSigner(Box<dyn Signer>);
impl Signer for BoxedSigner {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        self.0.certificate()
    }

    fn sign(&mut self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, SignError> {
        self.0.sign(padding, data)
    }
}

trait Tunnel {
    fn next(&mut self) -> Option<Progress>;
    fn approval_pending(&self) -> bool;
    fn exited(&self) -> Option<Option<OvpnReason>>;
    fn restart_hold_expired(&self) -> bool;
    fn release_restart_hold(&mut self, epoch: u64);
    fn has_session(&self) -> bool;
    fn stop(&mut self) -> io::Result<()>;
    fn reap(&mut self);
    fn force_stop(&mut self);
    fn confirm_absent(&self) -> bool;
}

trait Network {
    fn canceled(&self) -> bool;
    fn interfaces(&mut self) -> std::io::Result<Interfaces>;
    fn address(
        &mut self,
        link: &OvpnUtun,
        config: &NetworkConfig,
        expires: Instant,
    ) -> Result<(), Failure>;
    fn mtu(&mut self, link: &OvpnUtun, mtu: u16, expires: Instant) -> Result<(), Failure>;
    fn routes(
        &mut self,
        link: &OvpnUtun,
        config: &NetworkConfig,
        expires: Instant,
    ) -> Result<(), Failure>;
    fn publish_dns(
        &mut self,
        service: &ServiceId,
        servers: &[Ipv4Addr],
        domains: &[String],
    ) -> Result<(), Failure>;
    fn close_dns(&mut self) -> Result<(), Failure>;
    fn withdraw_routes(&mut self) -> Result<bool, Failure>;
    fn journal_cleanup(&mut self) -> Result<(), Failure> {
        Ok(())
    }
    fn journal_withdrawn(&mut self) -> Result<(), Failure> {
        Ok(())
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn pause(&mut self, expires: Instant) {
        thread::sleep(
            expires
                .saturating_duration_since(self.now())
                .min(Duration::from_millis(25)),
        );
    }
    fn finish(&mut self) -> Result<(), Failure>;
    fn validate_routes(&mut self) -> Result<(), Failure>;
    fn probe(
        &mut self,
        link: &OvpnUtun,
        address: Ipv4Addr,
        profile: &Profile,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> Result<bool, Failure>;
}

struct Cycle<T, N> {
    session: T,
    network: N,
    signing: Arc<SignContext>,
    before: Interfaces,
    dns_service: Option<ServiceId>,
    last_up: Option<(OvpnUtun, NetworkConfig)>,
    network_active: bool,
    phase: Option<ConnectionState>,
    restart_epoch: u64,
    stopped: bool,
    initial_deadline: Option<Instant>,
}

impl<T: Tunnel, N: Network> Cycle<T, N> {
    fn new(session: T, network: N, signing: Arc<SignContext>) -> Self {
        Self {
            session,
            network,
            signing,
            before: Interfaces::default(),
            dns_service: None,
            last_up: None,
            network_active: false,
            phase: None,
            restart_epoch: INITIAL_EPOCH,
            stopped: false,
            initial_deadline: None,
        }
    }

    fn phase(&self) -> Option<ConnectionState> {
        if self.session.approval_pending() {
            Some(ConnectionState::AwaitingApproval)
        } else {
            self.phase
        }
    }

    fn prove(&mut self, device: Option<&str>) -> Result<OvpnUtun, Failure> {
        let failure = || Failure::at(Step::Tunnel);
        let device = device.ok_or_else(failure)?;
        let current = self.network.interfaces().map_err(|_| failure())?;
        OvpnUtun::prove(device, &self.before, &current).ok_or_else(failure)
    }

    fn apply_network(&mut self, profile: &Profile, config: NetworkConfig) -> Result<(), Failure> {
        let link = self.prove(config.device.as_deref())?;
        if let Some((configured, previous)) = &self.last_up {
            if configured == &link && previous == &config {
                return Ok(());
            }
            // A replacement must first withdraw the previous configuration.
            return Err(Failure::at(Step::Tunnel));
        }
        let expires = self
            .initial_deadline
            .unwrap_or_else(|| Instant::now() + RECONFIGURE_BUDGET);
        self.network.address(&link, &config, expires)?;
        self.network
            .mtu(&link, config.mtu.unwrap_or(1500), expires)?;
        self.network.routes(&link, &config, expires)?;
        let domains = if profile.dns_domains.is_empty() {
            &config.dns_domains
        } else {
            &profile.dns_domains
        };
        if !config.dns_servers.is_empty() && !domains.is_empty() {
            if self.dns_service.is_none() {
                self.dns_service = Some(ServiceId::random().map_err(|_| Failure::at(Step::Dns))?);
            }
            self.network.publish_dns(
                self.dns_service.as_ref().unwrap(),
                &config.dns_servers,
                domains,
            )?;
        }
        self.last_up = Some((link, config));
        self.network_active = true;
        self.initial_deadline = None;
        Ok(())
    }

    fn can_continue(&self) -> Result<bool, Failure> {
        if self.network.canceled() {
            return Ok(false);
        }
        match self.session.exited() {
            Some(Some(OvpnReason::AuthFailure)) => Err(rejected()),
            Some(_) => Err(Failure::at(Step::Tunnel)),
            None if self.session.restart_hold_expired() => Err(Failure::at(Step::Tunnel)),
            None => Ok(true),
        }
    }

    fn withdraw_config(&mut self) -> Result<bool, Failure> {
        self.network_active = false;
        let expires = self.network.now() + RESTART_WITHDRAWAL_TIMEOUT;
        let journaled = self.network.journal_cleanup();
        self.network.close_dns()?;

        let at = || Failure::at(Step::Routes);
        loop {
            if !self.can_continue()? {
                return Ok(false);
            }
            if self.network.now() >= expires {
                return Err(at());
            }
            let link_gone = if let Some((link, _)) = &self.last_up {
                match self.network.interfaces() {
                    Ok(interfaces) => link.absent(&interfaces),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(_) => return Err(at()),
                }
            } else {
                true
            };
            if link_gone && self.network.withdraw_routes()? {
                if self.network.now() >= expires {
                    return Err(at());
                }
                // Finish withdrawing the old network even if the write
                // failed. Keep HOLD closed and stop through normal cleanup.
                journaled?;
                self.network.journal_withdrawn()?;
                if self.network.now() >= expires {
                    return Err(at());
                }
                self.last_up = None;
                return Ok(true);
            }
            self.network.pause(expires);
        }
    }

    fn poll(&mut self, profile: &Profile) -> Result<(), Failure> {
        let exit = self.session.exited();
        while let Some(event) = self.session.next() {
            match event {
                Progress::Refused(SignError::Canceled) => return Err(rejected()),
                Progress::Refused(_) => return Err(Failure::at(Step::Tunnel)),
                Progress::BadNetwork(_) => return Err(Failure::at(Step::Routes)),
                Progress::State(state) | Progress::Restarting { state, .. }
                    if state.reason == Some(OvpnReason::AuthFailure) =>
                {
                    return Err(rejected());
                }
                _ if exit.is_some() => {}
                Progress::AwaitingApproval => self.phase = Some(ConnectionState::AwaitingApproval),
                Progress::Restarting { epoch, .. } => {
                    self.phase = Some(ConnectionState::Reconnecting);
                    self.restart_epoch = epoch;
                    if !self.withdraw_config()? || !self.can_continue()? {
                        return Ok(());
                    }
                    self.signing.set_epoch(epoch);
                    self.session.release_restart_hold(epoch);
                }
                Progress::Up(config) => {
                    if !self.can_continue()? {
                        self.network_active = false;
                        return Ok(());
                    }
                    self.apply_network(profile, config)?;
                    self.phase = None;
                }
                // DOWN can precede the close of the utun and the Restarting
                // event. Keep its proof until that event observes absence.
                Progress::Down => self.network_active = false,
                Progress::State(_) => {}
            }
        }
        match self.session.exited().or(exit) {
            Some(Some(OvpnReason::AuthFailure)) => Err(rejected()),
            Some(_) if !self.stopped => Err(Failure::at(Step::Tunnel)),
            _ if self.session.restart_hold_expired() => Err(Failure::at(Step::Tunnel)),
            _ => Ok(()),
        }
    }

    fn ready(&mut self, profile: &Profile) -> Result<bool, Failure> {
        self.poll(profile)?;
        self.validate_network()?;
        Ok(self.network_active)
    }

    fn validate_network(&mut self) -> Result<(), Failure> {
        if self.network_active
            && let Some((link, _)) = &self.last_up
        {
            let current = self
                .network
                .interfaces()
                .map_err(|_| Failure::at(Step::Health))?;
            if !link.matches(&current) {
                return Err(Failure::at(Step::Health));
            }
            self.network.validate_routes()?;
        }
        Ok(())
    }

    fn probe(
        &mut self,
        profile: &Profile,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> Result<bool, Failure> {
        self.poll(profile)?;
        if !self.network_active {
            return Ok(false);
        }
        let Some((link, config)) = &self.last_up else {
            return Ok(false);
        };
        let epoch = self.restart_epoch;
        let response = self
            .network
            .probe(link, config.address, profile, canceled, timeout)?;
        self.poll(profile)?;
        Ok(response && self.network_active && self.restart_epoch == epoch)
    }

    fn cleanup(&mut self) -> bool {
        self.signing.cancel();
        self.network_active = false;
        let _ = self.network.journal_cleanup();
        let dns_closed = self.network.close_dns().is_ok();
        if !self.stopped {
            self.stopped = true;
            if self.session.has_session() {
                self.stop_session();
            }
        }
        if !self.session.confirm_absent() {
            return false;
        }
        let network_closed = self.network.finish().is_ok();
        dns_closed && network_closed
    }

    fn stop_session(&mut self) {
        if let Err(error) = self.session.stop() {
            eprintln!("ovpn_stop_failed: {:?}", error.kind());
            self.session.force_stop();
            return;
        }
        let expires = self.network.now() + STOP_WAIT;
        loop {
            if self.session.exited().is_some() {
                self.session.reap();
                return;
            }
            if self.network.now() >= expires {
                self.session.force_stop();
                return;
            }
            self.network.pause(expires);
        }
    }
}

fn rejected() -> Failure {
    Failure {
        state: ConnectionState::CredentialsRejected,
        error: ErrorCode::InvalidSecret,
        step: Step::Tunnel,
    }
}

#[derive(Default)]
struct RealTunnel {
    session: Option<Session>,
    pid: Option<u32>,
    // Retained until absence is confirmed. Never used to signal a process.
    identity: Option<Process>,
    reaped: bool,
}

impl Tunnel for RealTunnel {
    fn next(&mut self) -> Option<Progress> {
        self.session.as_ref()?.progress().try_recv().ok()
    }

    fn approval_pending(&self) -> bool {
        self.session.as_ref().is_some_and(Session::approval_pending)
    }

    fn exited(&self) -> Option<Option<OvpnReason>> {
        self.session.as_ref()?.exited()
    }

    fn restart_hold_expired(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(Session::restart_hold_expired)
    }

    fn release_restart_hold(&mut self, epoch: u64) {
        if let Some(session) = &self.session {
            session.release_restart_hold(epoch);
        }
    }

    fn has_session(&self) -> bool {
        self.session.is_some()
    }

    fn stop(&mut self) -> io::Result<()> {
        self.session.as_ref().map_or(Ok(()), Session::stop)
    }

    fn reap(&mut self) {
        if let Some(session) = self.session.take() {
            match session.wait() {
                Ok(_) => self.reaped = true,
                Err(error) => eprintln!("ovpn_wait_failed: {:?}", error.kind()),
            }
        }
    }

    fn force_stop(&mut self) {
        drop(self.session.take());
    }

    fn confirm_absent(&self) -> bool {
        if self.reaped {
            return true;
        }
        let Some(pid) = self.pid else {
            return true;
        };
        match Process::read(pid) {
            Err(error) => {
                error.kind() == io::ErrorKind::NotFound
                    // proc_pidpath can return NotFound while the PID still exists.
                    // SAFETY: pid came from the owned Child, and signal zero only checks existence.
                    && unsafe { libc::kill(pid as i32, 0) } != 0
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            }
            Ok(current) => self.identity.as_ref().is_some_and(|expected| {
                if current.identity == expected.identity
                    && current.executable != expected.executable
                {
                    eprintln!("ovpn_process_executable_changed");
                }
                current.identity != expected.identity
            }),
        }
    }
}

struct NativeNetwork<'a> {
    owner: Owner,
    routes: Routes<'a>,
    canceled: Arc<AtomicBool>,
    address: Option<(OvpnUtun, Ipv4Addr, u8)>,
    token: Option<InterfaceToken>,
    lease: Option<Lease>,
    fence: Option<ResourceFence>,
    dns: Option<DnsLease>,
    journal: Journal,
}

struct Journal {
    root: PathBuf,
    owner: u32,
    record: Option<Fence>,
}

impl Journal {
    fn new((root, owner): (PathBuf, u32)) -> Self {
        Self {
            root,
            owner,
            record: None,
        }
    }

    fn begin(&mut self, owner: &Owner, directory: &Path, process: &Process) -> io::Result<()> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        let written_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?;
        let record = Fence {
            version: 1,
            uid: owner.uid,
            profile: owner.profile.clone(),
            generation: owner.generation,
            kind: fence::Kind::Ovpn,
            reason: crate::helper::runtime::cleanup::Reason::Journal.id().into(),
            incomplete: true,
            written_unix_ms: u64::try_from(written_unix_ms.as_millis()).map_err(|_| invalid())?,
            service_id: None,
            dns_key: None,
            session_dir: Some(directory.to_str().ok_or_else(invalid)?.into()),
            processes: vec![ProcessIdentity {
                pid: process.identity.pid,
                start_sec: i64::try_from(process.identity.start.0).map_err(|_| invalid())?,
                start_usec: i32::try_from(process.identity.start.1).map_err(|_| invalid())?,
                program: process.executable.to_str().ok_or_else(invalid)?.into(),
            }],
            interface: None,
            sink: None,
            retired: Vec::new(),
            routes: Vec::new(),
        };
        fence::write(&self.root, self.owner, &record)?;
        self.record = Some(record);
        Ok(())
    }

    fn update(&mut self, change: impl FnOnce(&mut Fence)) -> io::Result<()> {
        if let Some(record) = &mut self.record {
            let mut next = record.clone();
            change(&mut next);
            fence::write(&self.root, self.owner, &next)?;
            *record = next;
        }
        Ok(())
    }

    fn remove(&mut self) -> Result<(), fence::Error> {
        if let Some(record) = &self.record {
            fence::remove(
                &self.root,
                self.owner,
                record.uid,
                &record.profile,
                record.generation,
            )?;
            self.record = None;
        }
        Ok(())
    }
}

fn route_result(error: RouteError) -> Failure {
    route_acquire_failure(error.into())
}

fn route_guard(expires: Instant, canceled: &AtomicBool) -> Result<(), RouteError> {
    if canceled.load(Ordering::Acquire) {
        return Err(RouteError::Canceled);
    }
    if Instant::now() >= expires {
        return Err(RouteError::TimedOut);
    }
    Ok(())
}

impl NativeNetwork<'_> {
    fn journal_spawn(&mut self, directory: &Path, identity: &Process) -> Result<(), Failure> {
        self.journal
            .begin(&self.owner, directory, identity)
            .map_err(|_| Failure::at(Step::Spawn))
    }
}

impl Network for NativeNetwork<'_> {
    fn canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    fn interfaces(&mut self) -> std::io::Result<Interfaces> {
        Interfaces::read()
    }

    fn address(
        &mut self,
        link: &OvpnUtun,
        config: &NetworkConfig,
        expires: Instant,
    ) -> Result<(), Failure> {
        let error = || Failure::at(Step::Routes);
        check(expires, &self.canceled, Step::Routes)?;
        if let Some((previous, address, prefix)) = &self.address {
            if previous == link {
                if *address != config.address || *prefix != config.prefix {
                    return Err(error());
                }
                if link.address_current(*address) {
                    return Ok(());
                }
            } else if !previous.index_absent().map_err(|_| error())? {
                return Err(error());
            }
        }
        let name = config.device.as_ref().ok_or_else(error)?;
        self.journal
            .update(|record| {
                record.incomplete = true;
                record.interface = Some(Interface {
                    name: name.clone(),
                    index: link.index(),
                });
            })
            .map_err(|_| error())?;
        self.address = Some((link.clone(), config.address, config.prefix));
        link.assign_address(config.address, config.prefix, expires, &self.canceled)
            .map_err(|_| error())
    }

    fn mtu(&mut self, link: &OvpnUtun, mtu: u16, expires: Instant) -> Result<(), Failure> {
        check(expires, &self.canceled, Step::Routes)?;
        link.set_mtu(mtu).map_err(|_| Failure::at(Step::Routes))
    }

    fn routes(
        &mut self,
        link: &OvpnUtun,
        config: &NetworkConfig,
        expires: Instant,
    ) -> Result<(), Failure> {
        if config.routes.is_empty() {
            // An empty push means no routes. TunnelPlan uses empty for full tunnel.
            return Ok(());
        }
        let mut routes = self.routes.lock().map_err(|_| Failure::at(Step::Routes))?;
        let guard = || route_guard(expires, &self.canceled);
        guard().map_err(route_result)?;
        let (fence, work) = ResourceFence::begin(&self.owner).map_err(route_result)?;
        let networks: Vec<_> = config
            .routes
            .iter()
            .map(|route| format!("{}/{}", route.network, route.prefix))
            .collect();
        let (token, plan) = routes
            .backend_mut()
            .register_ovpn_utun(
                link,
                config.address,
                self.owner.clone(),
                &networks,
                &self.canceled,
                work,
            )
            .map_err(route_result)?;
        self.token = Some(token);
        self.fence = Some(fence);
        // The registered backend plan bounds even a partially applied acquire.
        self.journal
            .update(|record| {
                record.routes = plan
                    .iter()
                    .map(|&route| AbandonedRoute {
                        route,
                        created: false,
                    })
                    .collect();
            })
            .map_err(|_| Failure::at(Step::Routes))?;
        let result = routes.acquire_guarded(self.owner.clone(), &plan, guard);
        // Keep the live lease before any subsequent I/O can fail.
        let result = result.map(|lease| self.lease = Some(lease));
        let written = self
            .journal
            .update(|record| record.routes = routes.inventory(&self.owner));
        result.map_err(route_acquire_failure)?;
        written.map_err(|_| Failure::at(Step::Routes))?;
        Ok(())
    }

    fn publish_dns(
        &mut self,
        service: &ServiceId,
        servers: &[Ipv4Addr],
        domains: &[String],
    ) -> Result<(), Failure> {
        let at = || Failure::at(Step::Dns);
        if self.canceled.load(Ordering::Acquire) {
            return Err(at());
        }
        let lease = self
            .dns
            .insert(DnsLease::new(service.clone()).map_err(|_| at())?);
        self.journal
            .update(|record| {
                record.service_id = Some(service.as_str().into());
                record.dns_key = Some(lease.key());
            })
            .map_err(|_| at())?;
        lease.publish(servers, domains).map_err(|_| at())
    }

    fn close_dns(&mut self) -> Result<(), Failure> {
        if let Some(lease) = &mut self.dns {
            if !lease
                .close_and_observe()
                .map_err(|_| Failure::at(Step::Dns))?
            {
                return Err(Failure::at(Step::Dns));
            }
            self.dns = None;
        }
        Ok(())
    }

    fn withdraw_routes(&mut self) -> Result<bool, Failure> {
        if let Some((link, _, _)) = &self.address
            && Snapshot::read()
                .map_err(route_result)?
                .records
                .iter()
                .any(|record| u32::from(record.interface) == link.index())
        {
            return Ok(false);
        }
        if let Some(token) = &self.token {
            let mut routes = match self.routes.try_lock() {
                Ok(routes) => routes,
                Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(Failure::at(Step::Routes)),
            };
            if !routes
                .backend_mut()
                .begin_cleanup(token)
                .map_err(route_result)?
            {
                return Ok(false);
            }
            if let Some(lease) = self.lease.take() {
                routes.release(lease).map_err(route_result)?;
            }
            if routes.has_owner(&self.owner) {
                NativeBackend::retry_observed_cleanup(&mut routes);
                if routes.has_owner(&self.owner) {
                    return Ok(false);
                }
            }
            match routes.backend_mut().finish_cleanup(token) {
                Ok(()) => {}
                Err(RouteError::Busy) => return Ok(false),
                Err(error) => return Err(route_result(error)),
            }
            self.token = None;
            if !self.fence.take().is_some_and(|fence| fence.is_complete()) {
                return Err(Failure::at(Step::Routes));
            }
        }
        self.address = None;
        Ok(true)
    }

    fn finish(&mut self) -> Result<(), Failure> {
        let at = || Failure::at(Step::Routes);
        if let Some((link, _, _)) = &self.address
            && link.matches(&Interfaces::read().map_err(|_| at())?)
        {
            return Err(at());
        }
        if !self.withdraw_routes()? {
            return Err(at());
        }
        Ok(())
    }

    fn journal_cleanup(&mut self) -> Result<(), Failure> {
        self.journal
            .update(|record| record.incomplete = false)
            .inspect_err(|error| eprintln!("ovpn_cleanup_journal_failed: {:?}", error.kind()))
            .map_err(|_| Failure::at(Step::Routes))
    }

    fn journal_withdrawn(&mut self) -> Result<(), Failure> {
        self.journal
            .update(|record| {
                record.incomplete = true;
                record.interface = None;
                record.routes.clear();
                record.service_id = None;
                record.dns_key = None;
            })
            .inspect_err(|error| eprintln!("ovpn_withdrawn_journal_failed: {:?}", error.kind()))
            .map_err(|_| Failure::at(Step::Routes))
    }

    fn validate_routes(&mut self) -> Result<(), Failure> {
        if let Some(lease) = &self.lease {
            let at = || Failure::at(Step::Health);
            self.routes
                .lock()
                .map_err(|_| at())?
                .validate(lease)
                .map_err(|_| at())?;
        }
        Ok(())
    }

    fn probe(
        &mut self,
        link: &OvpnUtun,
        address: Ipv4Addr,
        profile: &Profile,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> Result<bool, Failure> {
        link.probe(address, profile, canceled, timeout)
            .map_err(|_| Failure::at(Step::Health))
    }
}

pub(super) struct NativeOvpnAttempt<'a> {
    profile: Profile,
    profiles: Arc<Profiles>,
    signer: Option<Box<dyn Signer>>,
    cycle: Cycle<RealTunnel, NativeNetwork<'a>>,
    profile_use: Option<ProfileUse>,
}

impl<'a> NativeOvpnAttempt<'a> {
    pub(super) fn new(
        profile: Profile,
        profiles: Arc<Profiles>,
        signers: &dyn OvpnSigners,
        owner: Owner,
        routes: Routes<'a>,
        canceled: Arc<AtomicBool>,
        storage: (PathBuf, u32),
    ) -> Self {
        let signing = Arc::new(SignContext::new(INITIAL_EPOCH, canceled.clone()));
        let signer = signers.signer(&owner.profile, owner.generation, signing.clone());
        Self {
            profile,
            profiles,
            signer: Some(signer),
            cycle: Cycle::new(
                RealTunnel::default(),
                NativeNetwork {
                    owner,
                    routes,
                    canceled,
                    address: None,
                    token: None,
                    lease: None,
                    fence: None,
                    dns: None,
                    journal: Journal::new(storage),
                },
                signing,
            ),
            profile_use: None,
        }
    }

    fn read_config(&self) -> Result<(ConfigSource, Signatures), Failure> {
        let invalid = || Failure {
            state: ConnectionState::Dropped,
            error: ErrorCode::UntrustedConfiguration,
            step: Step::Profile,
        };
        if self.profile.kind != VpnKind::Ovpn || self.profile.validate().is_err() {
            return Err(invalid());
        }
        let settings = self.profile.ovpn.as_ref().ok_or_else(invalid)?;
        let usage = self.profile_use.as_ref().ok_or_else(invalid)?;
        let bytes = self
            .profiles
            .read_ovpn_config(&self.profile.id, usage)
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let inspected = inspect(&bytes).map_err(|_| invalid())?;
        let signatures = match settings.tls {
            OvpnTls::Any => Signatures::Any,
            OvpnTls::Pkcs1Only => Signatures::Pkcs1Only,
        };
        // validate() already checks certificate_id. The injected signer
        // resolves that certificate for this profile/generation.
        // Reopening the utun without persist-tun requires root. The inspector
        // rejects user, group and chroot before preparing this launch copy.
        Ok((
            ConfigSource::private(without_persist_tun(&inspected.normalized).as_bytes()),
            signatures,
        ))
    }

    fn validate_profile_use(&self) -> Result<(), Failure> {
        let at = || Failure::at(Step::Profile);
        self.profile_use
            .as_ref()
            .ok_or_else(at)?
            .validate()
            .map_err(|_| at())
    }
}

/// The inspector has already validated and normalized the file. Preserve
/// inline blocks byte for byte and remove only the top-level directive.
fn without_persist_tun(normalized: &str) -> String {
    let mut inline = false;
    normalized
        .split_inclusive('\n')
        .filter(|line| {
            let line = line.trim_start_matches([' ', '\t']);
            if inline {
                if line.starts_with("</") {
                    inline = false;
                }
                return true;
            }
            if line.starts_with('<') {
                inline = true;
                return true;
            }
            let word = line.split_ascii_whitespace().next().unwrap_or_default();
            word.strip_prefix("--").unwrap_or(word) != "persist-tun"
        })
        .collect()
}

impl NativeOvpnAttempt<'_> {
    fn start_using(
        &mut self,
        canceled: &AtomicBool,
        expires: Instant,
        launch: impl FnOnce(&mut Self, ConfigSource, Signatures) -> Result<(), Failure>,
    ) -> Result<(), Failure> {
        check(expires, canceled, Step::Profile)?;
        self.profile
            .validate()
            .map_err(|_| Failure::at(Step::Profile))?;
        if self.profile.kind != VpnKind::Ovpn || self.profile_use.is_some() || self.cycle.stopped {
            return Err(Failure::at(Step::Profile));
        }
        self.profile_use = Some(
            self.profiles
                .begin(&self.profile, self.cycle.network.owner.generation)
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
        let (config, signatures) = self.read_config()?;
        launch(self, config, signatures)
    }

    fn start_session(
        &mut self,
        canceled: &AtomicBool,
        expires: Instant,
        config: ConfigSource,
        signatures: Signatures,
    ) -> Result<(), Failure> {
        check(expires, canceled, Step::Runtime)?;
        let runtime = Runtime::installed().map_err(|error| Failure {
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
        let openvpn = runtime.program(Program::Openvpn);
        let base = paths::ovpn_sessions_directory();
        super::ovpn_base::ensure_base(&base, 0).map_err(|_| Failure::at(Step::Runtime))?;

        let at = || Failure::at(Step::Spawn);
        check(expires, canceled, Step::Spawn)?;
        self.cycle.before = self.cycle.network.interfaces().map_err(|_| at())?;
        check(expires, canceled, Step::Spawn)?;
        let signer = self.signer.take().ok_or_else(at)?;
        let launch = Launch {
            openvpn: openvpn.clone(),
            config,
            dev: None,
            signatures,
            extra: vec![],
            env: vec![],
        };
        self.cycle.session.session = Some(
            Session::start_with(
                launch,
                BoxedSigner(signer),
                &base,
                RestartPolicy::CallerOrStop,
            )
            .map_err(|_| at())?,
        );
        let session = self.cycle.session.session.as_ref().unwrap();
        let pid = session.pid().ok_or_else(at)?;
        self.cycle.session.pid = Some(pid);
        let identity = self
            .cycle
            .session
            .identity
            .insert(Process::read(pid).map_err(|_| at())?);
        if session.pid() != Some(pid)
            || !identity.running
            || identity.parent != std::process::id()
            || identity.uid != 0
            || identity.real_uid != 0
            || identity.executable != openvpn
        {
            return Err(at());
        }
        self.cycle
            .network
            .journal_spawn(session.directory(), identity)?;
        self.cycle.initial_deadline = Some(expires);
        Ok(())
    }
}

impl Attempt for NativeOvpnAttempt<'_> {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        self.start_using(canceled, expires, |attempt, config, signatures| {
            attempt.start_session(canceled, expires, config, signatures)
        })
        .inspect_err(|_| self.cycle.signing.cancel())
    }

    fn ready(&mut self) -> Result<bool, Failure> {
        self.validate_profile_use()
            .and_then(|()| self.cycle.ready(&self.profile))
            .inspect_err(|_| self.cycle.signing.cancel())
    }

    fn phase(&self) -> Option<ConnectionState> {
        self.cycle.phase()
    }

    fn restart_epoch(&self) -> u64 {
        self.cycle.restart_epoch
    }

    fn healthy(&mut self) -> Result<(), Failure> {
        self.validate_profile_use()
            .and_then(|()| self.cycle.poll(&self.profile))
            .and_then(|()| self.cycle.validate_network())
            .inspect_err(|_| self.cycle.signing.cancel())
    }

    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        self.validate_profile_use()
            .and_then(|()| self.cycle.probe(&self.profile, canceled, timeout))
            .inspect_err(|_| self.cycle.signing.cancel())
    }

    fn cleanup(&mut self) -> bool {
        if !self.cycle.cleanup() {
            return false;
        }
        if self.cycle.network.journal.remove().is_err() {
            return false;
        }
        self.cycle.session.identity = None;
        self.cycle.session.pid = None;
        if let Some(reservation) = &self.profile_use {
            if reservation.complete().is_err() {
                return false;
            }
            self.profile_use = None;
        }
        true
    }
}

impl Drop for NativeOvpnAttempt<'_> {
    fn drop(&mut self) {
        self.cycle.signing.cancel();
    }
}

#[cfg(test)]
mod tests;
