//! The worker thread owns the OpenVPN child for its entire lifetime. This is
//! required because Linux PDEATHSIG follows the thread that spawned it.
use super::super::{Attempt, Failure};
use crate::{
    connection::ovpn::{
        management::{Phase, Reason},
        network::NetworkConfig,
        pkcs11::TokenKey,
        session::{ConfigSource, Launch, Progress, Session, SignError, Signatures},
    },
    helper::protocol::{ErrorCode, Step},
    model::{OvpnSettings, OvpnTls, Profile, VpnKind},
    netd::{
        client::{Client, ClientError, SOCKET_PATH},
        protocol::{Config, Dns, ErrorCode as NetCode, Route, TunName},
    },
    session::ConnectionState,
    storage::ProfileStore,
};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    net::{TcpStream, ToSocketAddrs},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
enum NetFailure {
    Backend,
    RouteConflict,
    Dns,
    Transport,
    Other,
}
trait Network {
    fn open_tun(&mut self) -> Result<String, NetFailure>;
    fn configure(&mut self, config: &Config) -> Result<(), NetFailure>;
    fn close_tun(&mut self, name: &str) -> Result<(), NetFailure>;
}
trait Tunnel {
    fn next(&mut self) -> Option<Progress>;
    fn exited(&self) -> Option<Option<Reason>>;
    fn stop(&mut self);
    fn wait(&mut self, timeout: Duration) -> bool;
    fn release_restart_hold(&self, epoch: u64);
    fn approval_pending(&self) -> Option<bool> {
        None
    }
}
pub(super) struct RealNetwork(Client);
fn net_error(e: ClientError) -> NetFailure {
    match e {
        ClientError::Io(_) | ClientError::Protocol => NetFailure::Transport,
        ClientError::Refused(NetCode::Backend) => NetFailure::Backend,
        ClientError::Refused(NetCode::RouteConflict) => NetFailure::RouteConflict,
        ClientError::Refused(NetCode::InvalidDns) => NetFailure::Dns,
        ClientError::Refused(_) => NetFailure::Other,
    }
}
impl Network for RealNetwork {
    fn open_tun(&mut self) -> Result<String, NetFailure> {
        self.0.open_tun().map(|v| v.to_string()).map_err(net_error)
    }
    fn configure(&mut self, config: &Config) -> Result<(), NetFailure> {
        self.0.configure(config).map_err(net_error)
    }
    fn close_tun(&mut self, name: &str) -> Result<(), NetFailure> {
        let name = TunName::parse(name).map_err(|_| NetFailure::Other)?;
        self.0.close_tun(&name).map_err(net_error)
    }
}
pub(super) struct RealTunnel {
    session: Option<Session>,
    waiting: Option<mpsc::Receiver<bool>>,
    wait_failed: bool,
}
impl Tunnel for RealTunnel {
    fn next(&mut self) -> Option<Progress> {
        self.session.as_ref()?.progress().try_recv().ok()
    }
    fn exited(&self) -> Option<Option<Reason>> {
        self.session.as_ref()?.exited()
    }
    fn approval_pending(&self) -> Option<bool> {
        self.session.as_ref().map(Session::approval_pending)
    }
    fn release_restart_hold(&self, epoch: u64) {
        if let Some(session) = &self.session {
            session.release_restart_hold(epoch);
        }
    }
    fn stop(&mut self) {
        if let Some(s) = &self.session
            && s.stop().is_err()
        {
            eprintln!("openvpn stop request failed");
        }
    }
    fn wait(&mut self, timeout: Duration) -> bool {
        if self.wait_failed {
            return false;
        }
        if let Some(session) = self.session.take() {
            let (send, recv) = mpsc::sync_channel(1);
            if thread::Builder::new()
                .name("vpnt-ovpn-wait".into())
                .spawn(move || {
                    let _ = send.send(session.wait().is_ok());
                })
                .is_err()
            {
                self.wait_failed = true;
                return false;
            }
            self.waiting = Some(recv);
        }
        match self.waiting.as_ref().map(|recv| recv.recv_timeout(timeout)) {
            Some(Ok(true)) => {
                self.waiting = None;
                true
            }
            Some(Err(mpsc::RecvTimeoutError::Timeout)) => false,
            Some(_) => {
                self.wait_failed = true;
                false
            }
            None => true,
        }
    }
}
fn read_profile(path: &Path, uid: u32) -> Result<ConfigSource, Failure> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Failure::at(Step::Profile))?;
    let metadata = file.metadata().map_err(|_| Failure::at(Step::Profile))?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(Failure::at(Step::Profile));
    }
    const LIMIT: u64 = 256 * 1024;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::at(Step::Profile))?;
    if bytes.len() as u64 > LIMIT {
        return Err(Failure::at(Step::Profile));
    }
    let inspected = crate::connection::ovpn::profile::inspect(&bytes)
        .map_err(|_| Failure::at(Step::Profile))?;
    ConfigSource::sealed(inspected.normalized.as_bytes()).map_err(|_| Failure::at(Step::Profile))
}

trait Starter<N, T> {
    type Key;
    fn connect(&mut self) -> Result<N, Failure>;
    fn token(
        &mut self,
        settings: &OvpnSettings,
        id: &[u8],
        canceled: &AtomicBool,
        expires: Instant,
    ) -> Result<Self::Key, Failure>;
    fn session(
        &mut self,
        config: ConfigSource,
        settings: &OvpnSettings,
        name: String,
        key: Self::Key,
    ) -> Result<T, Failure>;
}
pub(super) struct RealStart;
impl Starter<RealNetwork, RealTunnel> for RealStart {
    type Key = TokenKey;
    fn connect(&mut self) -> Result<RealNetwork, Failure> {
        Client::connect(Path::new(SOCKET_PATH))
            .map(RealNetwork)
            .map_err(|_| {
                state_failure(
                    ConnectionState::HelperMissing,
                    ErrorCode::Unavailable,
                    Step::Runtime,
                )
            })
    }
    fn token(
        &mut self,
        settings: &OvpnSettings,
        id: &[u8],
        canceled: &AtomicBool,
        expires: Instant,
    ) -> Result<TokenKey, Failure> {
        TokenKey::open_until(Path::new(&settings.module), id, canceled, expires)
            .map_err(|_| Failure::at(Step::Profile))?
            .ok_or_else(|| {
                state_failure(
                    ConnectionState::GatewayTimeout,
                    ErrorCode::BackendFailure,
                    Step::Tunnel,
                )
            })
    }
    fn session(
        &mut self,
        config: ConfigSource,
        settings: &OvpnSettings,
        name: String,
        key: TokenKey,
    ) -> Result<RealTunnel, Failure> {
        let program = Path::new("/usr/bin/openvpn");
        if !program.is_file() {
            return Err(state_failure(
                ConnectionState::MissingProgram,
                ErrorCode::MissingProgram,
                Step::Spawn,
            ));
        }
        let session = Session::start(
            Launch {
                openvpn: program.into(),
                config,
                signatures: match settings.tls {
                    OvpnTls::Any => Signatures::Any,
                    OvpnTls::Pkcs1Only => Signatures::Pkcs1Only,
                },
                dev: Some(name),
                extra: vec![],
                env: vec![],
            },
            key,
        )
        .map_err(|_| Failure::at(Step::Spawn))?;
        Ok(RealTunnel {
            session: Some(session),
            waiting: None,
            wait_failed: false,
        })
    }
}

static PROBES: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
struct ProbeSlot(String);
impl ProbeSlot {
    fn acquire(id: &str) -> Option<Self> {
        let mut slots = PROBES.lock().unwrap_or_else(|e| e.into_inner());
        slots.insert(id.to_owned()).then(|| Self(id.to_owned()))
    }
}
impl Drop for ProbeSlot {
    fn drop(&mut self) {
        PROBES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

fn rejected(step: Step) -> Failure {
    Failure {
        state: ConnectionState::CredentialsRejected,
        error: ErrorCode::InvalidSecret,
        step,
    }
}
fn state_failure(state: ConnectionState, error: ErrorCode, step: Step) -> Failure {
    Failure { state, error, step }
}

const RECONNECT_GRACE: Duration = Duration::from_secs(120);

pub(super) struct OvpnAttempt<N, T, S = RealStart> {
    profile: Profile,
    uid: u32,
    network: Option<N>,
    tunnel: Option<T>,
    name: Option<String>,
    last_config: Option<Config>,
    config_withdrawn: bool,
    phase: Option<ConnectionState>,
    reconnect_started: Option<Instant>,
    restart_epoch: u64,
    down: bool,
    stopped: bool,
    probe_job: Arc<dyn Fn(String, u16, Instant) -> bool + Send + Sync>,
    probe_inflight: Option<(mpsc::Receiver<bool>, thread::JoinHandle<()>)>,
    probe_busy: bool,
    starter: S,
    config_path: Option<PathBuf>,
}
fn probe_connection(host: String, port: u16, deadline: Instant) -> bool {
    let addresses = match (host.as_str(), port).to_socket_addrs() {
        Ok(addresses) => addresses,
        Err(_) => return false,
    };
    for address in addresses {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if !remaining.is_zero() && TcpStream::connect_timeout(&address, remaining).is_ok() {
            return true;
        }
    }
    false
}
impl<N, T, S> OvpnAttempt<N, T, S> {
    fn with_start(profile: Profile, uid: u32, config_path: Option<PathBuf>, starter: S) -> Self {
        Self {
            profile,
            uid,
            network: None,
            tunnel: None,
            name: None,
            last_config: None,
            config_withdrawn: false,
            phase: None,
            reconnect_started: None,
            restart_epoch: 0,
            down: false,
            stopped: false,
            probe_job: Arc::new(probe_connection),
            probe_inflight: None,
            probe_busy: false,
            starter,
            config_path,
        }
    }
}
impl OvpnAttempt<RealNetwork, RealTunnel> {
    pub(super) fn new(profile: Profile, uid: u32) -> Self {
        Self::with_start(profile, uid, None, RealStart)
    }
}
#[allow(private_bounds)]
impl<N: Network, T: Tunnel, S: Starter<N, T>> OvpnAttempt<N, T, S> {
    fn open(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        if self.profile.kind != VpnKind::Ovpn || self.profile.validate().is_err() {
            return Err(Failure::at(Step::Profile));
        }
        let settings = self
            .profile
            .ovpn
            .as_ref()
            .ok_or_else(|| Failure::at(Step::Profile))?;
        let path = match &self.config_path {
            Some(path) => path.clone(),
            None => ProfileStore::for_current_user()
                .and_then(|s| s.ovpn_dir())
                .map_err(|_| Failure::at(Step::Profile))?
                .join(format!("{}.ovpn", self.profile.id)),
        };
        let config = read_profile(&path, self.uid)?;
        self.network = Some(self.starter.connect()?);
        let name = self
            .network
            .as_mut()
            .unwrap()
            .open_tun()
            .map_err(|_| Failure::at(Step::Tunnel))?;
        self.name = Some(name.clone());
        let bytes = settings
            .certificate_id
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap_or(""), 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Failure::at(Step::Profile))?;
        let key = self.starter.token(settings, &bytes, canceled, expires)?;
        if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
            return Err(Failure::at(Step::Tunnel));
        }
        self.tunnel = Some(self.starter.session(config, settings, name, key)?);
        Ok(())
    }
    fn configure(&mut self, net: NetworkConfig) -> Result<(), Failure> {
        let name = TunName::parse(
            self.name
                .as_deref()
                .ok_or_else(|| Failure::at(Step::Routes))?,
        )
        .map_err(|_| Failure::at(Step::Routes))?;
        let domains = if self.profile.dns_domains.is_empty() {
            net.dns_domains
        } else {
            self.profile.dns_domains.clone()
        };
        let config = Config {
            name,
            address: net.address,
            prefix: net.prefix,
            mtu: net.mtu.unwrap_or(1500),
            routes: net
                .routes
                .into_iter()
                .map(|r| Route {
                    network: r.network,
                    prefix: r.prefix,
                })
                .collect(),
            dns: Dns {
                servers: net.dns_servers,
                domains,
            },
        };
        Self::apply_config(&mut self.network, &config)?;
        self.last_config = Some(config);
        self.config_withdrawn = false;
        Ok(())
    }
    fn apply_config(network: &mut Option<N>, config: &Config) -> Result<(), Failure> {
        network
            .as_mut()
            .ok_or_else(|| Failure::at(Step::Routes))?
            .configure(config)
            .map_err(|e| {
                Failure::at(if matches!(e, NetFailure::Dns) {
                    Step::Dns
                } else {
                    Step::Routes
                })
            })
    }
    fn withdraw_config(&mut self) -> Result<(), Failure> {
        let Some(config) = &self.last_config else {
            return Ok(());
        };
        // A persisted TUN may still route the token's traffic into the stalled VPN.
        let withdrawn = Config {
            name: config.name.clone(),
            address: config.address,
            prefix: config.prefix,
            mtu: config.mtu,
            routes: Vec::new(),
            dns: Dns {
                servers: Vec::new(),
                domains: Vec::new(),
            },
        };
        Self::apply_config(&mut self.network, &withdrawn).map_err(|_| Failure::at(Step::Routes))?;
        self.config_withdrawn = true;
        Ok(())
    }
    fn process(&mut self, ready: bool) -> Result<bool, Failure> {
        while let Some(event) = self.tunnel.as_mut().and_then(Tunnel::next) {
            match event {
                Progress::AwaitingApproval if ready || self.reconnect_started.is_some() => {
                    self.phase = Some(ConnectionState::AwaitingApproval);
                }
                Progress::AwaitingApproval => {}
                Progress::Up(net) => {
                    self.phase = None;
                    if ready || self.down || self.config_withdrawn {
                        self.configure(net)?;
                        self.down = false;
                        if ready {
                            return Ok(true);
                        }
                    }
                }
                Progress::Down => self.down = true,
                Progress::BadNetwork(_) => return Err(Failure::at(Step::Routes)),
                Progress::Refused(SignError::Canceled) => return Err(rejected(Step::Tunnel)),
                Progress::Refused(_) => return Err(Failure::at(Step::Tunnel)),
                Progress::State(s) if s.reason == Some(Reason::AuthFailure) => {
                    return Err(rejected(Step::Tunnel));
                }
                Progress::Restarting { state, epoch } => {
                    if state.reason == Some(Reason::AuthFailure) {
                        return Err(rejected(Step::Tunnel));
                    }
                    if self.reconnect_started.is_none() {
                        self.reconnect_started = Some(Instant::now());
                        self.restart_epoch = self.restart_epoch.wrapping_add(1);
                    }
                    // An intervening UP can have reapplied the network without
                    // a CONNECTED state closing the recovery window.
                    if !self.config_withdrawn {
                        self.withdraw_config()?;
                    }
                    if let Some(tunnel) = &self.tunnel {
                        tunnel.release_restart_hold(epoch);
                    }
                }
                Progress::State(s) if s.phase == Phase::Connected => {
                    if self.config_withdrawn
                        && let Some(config) = &self.last_config
                    {
                        Self::apply_config(&mut self.network, config)?;
                        self.config_withdrawn = false;
                    }
                    self.reconnect_started = None;
                    self.phase = None;
                }
                Progress::State(_) => {}
            }
        }
        if let Some(reason) = self.tunnel.as_ref().and_then(Tunnel::exited) {
            if reason == Some(Reason::AuthFailure) {
                return Err(rejected(if ready { Step::Tunnel } else { Step::Health }));
            }
            return Err(Failure::at(if ready { Step::Tunnel } else { Step::Health }));
        }
        Ok(false)
    }
    #[cfg(test)]
    fn fixture(profile: Profile, network: N, tunnel: T, starter: S) -> Self {
        let mut result = Self::with_start(profile, 0, None, starter);
        result.network = Some(network);
        result.tunnel = Some(tunnel);
        result.name = Some("vpnt0".into());
        result
    }
}
impl<N: Network, T: Tunnel, S: Starter<N, T>> Attempt for OvpnAttempt<N, T, S> {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
            return Err(Failure::at(Step::Tunnel));
        }
        self.open(canceled, expires)
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.process(true)
    }
    fn phase(&self) -> Option<ConnectionState> {
        let Some(started) = self.reconnect_started else {
            return self.phase;
        };
        if started.elapsed() >= RECONNECT_GRACE {
            return None;
        }
        let approval = self
            .tunnel
            .as_ref()
            .and_then(Tunnel::approval_pending)
            .unwrap_or(self.phase == Some(ConnectionState::AwaitingApproval));
        Some(if approval {
            ConnectionState::AwaitingApproval
        } else {
            ConnectionState::Reconnecting
        })
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.process(false).map(|_| ())
    }
    fn restart_epoch(&self) -> u64 {
        self.restart_epoch
    }
    fn probe_busy(&self) -> bool {
        self.probe_busy
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        self.probe_busy = true;
        if self.config_withdrawn || canceled.load(Ordering::Acquire) || timeout.is_zero() {
            return Ok(false);
        }
        if let Some((_, worker)) = self.probe_inflight.as_ref() {
            if !worker.is_finished() {
                return Ok(false);
            }
            let (_, worker) = self.probe_inflight.take().unwrap();
            let _ = worker.join();
        }
        let Some(slot) = ProbeSlot::acquire(&self.profile.id) else {
            return Ok(false);
        };
        let deadline = Instant::now() + timeout;
        let job = self.probe_job.clone();
        let host = self.profile.probe_host.clone();
        let port = self.profile.probe_port;
        let (send, recv) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("vpnt-ovpn-probe".into())
            .spawn(move || {
                let _slot = slot;
                let _ = send.send(job(host, port, deadline));
            })
            .map_err(|_| Failure::at(Step::Verify))?;
        self.probe_busy = false;
        self.probe_inflight = Some((recv, worker));
        let (recv, _) = self.probe_inflight.as_ref().unwrap();
        loop {
            if canceled.load(Ordering::Acquire) {
                return Ok(false);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(false);
            };
            if remaining.is_zero() {
                return Ok(false);
            }
            match recv.recv_timeout(remaining.min(Duration::from_millis(50))) {
                Ok(result) => {
                    return Ok(result
                        && !canceled.load(Ordering::Acquire)
                        && Instant::now() < deadline);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(false),
            }
        }
    }
    fn cleanup(&mut self) -> bool {
        if let Some(tunnel) = self.tunnel.as_mut() {
            if !self.stopped {
                tunnel.stop();
                self.stopped = true;
            }
            if !tunnel.wait(Duration::from_secs(10)) {
                return false;
            }
        }
        self.tunnel = None;
        if let (Some(network), Some(name)) = (self.network.as_mut(), self.name.as_ref()) {
            match network.close_tun(name) {
                Ok(()) => {}
                // A lost transport closes the client; netd cleans disconnected
                // sessions and retries any deletion it cannot finish immediately.
                Err(NetFailure::Transport) => {}
                Err(_) => return false,
            }
        }
        self.network = None;
        self.name = None;
        true
    }
}
#[cfg(test)]
#[path = "ovpn_tests.rs"]
mod tests;
