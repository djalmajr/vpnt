//! The worker thread owns the OpenVPN child for its entire lifetime. This is
//! required because Linux PDEATHSIG follows the thread that spawned it.
use super::super::{Attempt, Failure};
use crate::{
    connection::ovpn::{
        management::Reason,
        network::NetworkConfig,
        pkcs11::TokenKey,
        session::{Launch, Progress, Session, SignError, Signatures},
    },
    helper::protocol::{ErrorCode, Step},
    model::{OvpnTls, Profile, VpnKind},
    netd::{
        client::{Client, ClientError, SOCKET_PATH},
        protocol::{Config, Dns, ErrorCode as NetCode, Route, TunName},
    },
    session::ConnectionState,
    storage::ProfileStore,
};
use std::{
    fs,
    net::{TcpStream, ToSocketAddrs},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{
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
fn profile_file_ok(path: &Path, uid: u32) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| {
        m.file_type().is_file() && m.uid() == uid && m.mode() & 0o7777 == 0o600 && m.nlink() == 1
    })
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

pub(super) struct OvpnAttempt<N, T> {
    profile: Profile,
    uid: u32,
    network: Option<N>,
    tunnel: Option<T>,
    name: Option<String>,
    phase: Option<ConnectionState>,
    down: bool,
    stopped: bool,
    start_real: fn(&mut Self) -> Result<(), Failure>,
}
impl OvpnAttempt<RealNetwork, RealTunnel> {
    pub(super) fn new(profile: Profile, uid: u32) -> Self {
        Self {
            profile,
            uid,
            network: None,
            tunnel: None,
            name: None,
            phase: None,
            down: false,
            stopped: false,
            start_real: Self::open,
        }
    }
    fn open(&mut self) -> Result<(), Failure> {
        if self.profile.kind != VpnKind::Ovpn || self.profile.validate().is_err() {
            return Err(Failure::at(Step::Profile));
        }
        let settings = self
            .profile
            .ovpn
            .as_ref()
            .ok_or_else(|| Failure::at(Step::Profile))?;
        let path = ProfileStore::for_current_user()
            .and_then(|s| s.ovpn_dir())
            .map_err(|_| Failure::at(Step::Profile))?
            .join(format!("{}.ovpn", self.profile.id));
        if !profile_file_ok(&path, self.uid) {
            return Err(Failure::at(Step::Profile));
        }
        let client = Client::connect(Path::new(SOCKET_PATH)).map_err(|_| {
            state_failure(
                ConnectionState::HelperMissing,
                ErrorCode::Unavailable,
                Step::Runtime,
            )
        })?;
        self.network = Some(RealNetwork(client));
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
        let token = TokenKey::open(Path::new(&settings.module), &bytes)
            .map_err(|_| Failure::at(Step::Profile))?;
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
                config: path,
                signatures: match settings.tls {
                    OvpnTls::Any => Signatures::Any,
                    OvpnTls::Pkcs1Only => Signatures::Pkcs1Only,
                },
                dev: Some(name),
                extra: vec![],
                env: vec![],
            },
            token,
        )
        .map_err(|_| Failure::at(Step::Spawn))?;
        self.tunnel = Some(RealTunnel {
            session: Some(session),
            waiting: None,
            wait_failed: false,
        });
        Ok(())
    }
}
#[allow(private_bounds)] // The injectable interfaces stay private to this module.
impl<N: Network, T: Tunnel> OvpnAttempt<N, T> {
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
        self.network
            .as_mut()
            .ok_or_else(|| Failure::at(Step::Routes))?
            .configure(&config)
            .map_err(|e| {
                Failure::at(if matches!(e, NetFailure::Dns) {
                    Step::Dns
                } else {
                    Step::Routes
                })
            })
    }
    fn process(&mut self, ready: bool) -> Result<bool, Failure> {
        while let Some(event) = self.tunnel.as_mut().and_then(Tunnel::next) {
            match event {
                Progress::AwaitingApproval => self.phase = Some(ConnectionState::AwaitingApproval),
                Progress::Up(net) => {
                    self.phase = None;
                    if ready || self.down {
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
    fn fixture(profile: Profile, network: N, tunnel: T) -> Self {
        Self {
            profile,
            uid: 0,
            network: Some(network),
            tunnel: Some(tunnel),
            name: Some("vpnt0".into()),
            phase: None,
            down: false,
            stopped: false,
            start_real: |_| Ok(()),
        }
    }
}
impl<N: Network, T: Tunnel> Attempt for OvpnAttempt<N, T> {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        if canceled.load(Ordering::Acquire) || Instant::now() >= expires {
            return Err(Failure::at(Step::Tunnel));
        }
        (self.start_real)(self)
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.process(true)
    }
    fn phase(&self) -> Option<ConnectionState> {
        self.phase
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        self.process(false).map(|_| ())
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        let deadline = Instant::now() + timeout;
        let addresses =
            match (self.profile.probe_host.as_str(), self.profile.probe_port).to_socket_addrs() {
                Ok(a) => a,
                Err(_) => return Ok(false),
            };
        for address in addresses {
            if canceled.load(Ordering::Acquire) {
                return Ok(false);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if !remaining.is_zero() && TcpStream::connect_timeout(&address, remaining).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
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
