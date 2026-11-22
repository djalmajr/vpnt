//! A Linux IPsec or Fortinet attempt owns exactly one authenticated daemon session.
use super::super::{Attempt, Failure};
use crate::{
    helper::protocol::{ErrorCode, Step},
    model::{Profile, VpnKind},
    secrets::Credentials,
    session::ConnectionState,
    tunnel_policy::certificate_pin,
    tunneld::{
        SOCKET_PATH,
        client::Client,
        protocol::{
            CidrV4, CleanupState, Credentials as WireCredentials, Endpoint, ErrorCode as WireError,
            FortinetRequest, FrameError, Generation, IpsecRequest, Prepare, ProbeBinding, State,
        },
    },
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::BTreeSet,
    io,
    net::{SocketAddr, SocketAddrV4, ToSocketAddrs},
    num::NonZeroU32,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const STATUS_INTERVAL: Duration = Duration::from_millis(500);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PROBE_DESTINATIONS: usize = 64;

type Probe = fn(&Profile, &ProbeBinding, &AtomicBool, Instant, ProbeSlot) -> Result<bool, Failure>;

enum Session {
    Inactive,
    Active(Client),
    Observing,
}

pub(super) struct TunnelAttempt {
    profile: Profile,
    credentials: Option<Credentials>,
    socket_path: PathBuf,
    probe: Probe,
    probe_busy: bool,
    session: Session,
    connect_deadline: Instant,
    next_status: Instant,
    generation: Option<Generation>,
    probe_binding: Option<ProbeBinding>,
}

impl TunnelAttempt {
    pub(super) fn new(profile: Profile, credentials: Credentials) -> Self {
        Self::with_socket(profile, credentials, SOCKET_PATH.into(), probe_tcp)
    }

    fn with_socket(
        profile: Profile,
        credentials: Credentials,
        socket_path: PathBuf,
        probe: Probe,
    ) -> Self {
        let now = Instant::now();
        Self {
            profile,
            credentials: Some(credentials),
            socket_path,
            probe,
            probe_busy: false,
            session: Session::Inactive,
            connect_deadline: now,
            next_status: now,
            generation: None,
            probe_binding: None,
        }
    }

    fn status(&mut self, deadline: Instant, step: Step) -> Result<State, Failure> {
        let Session::Active(client) = &mut self.session else {
            return Err(Failure::at(step));
        };
        self.next_status = Instant::now() + STATUS_INTERVAL;
        match client.status_with_binding(deadline) {
            Ok((State::NetworkReady, Some(binding)))
                if Some(binding.generation()) == self.generation.as_ref()
                    && self
                        .probe_binding
                        .as_ref()
                        .is_none_or(|previous| previous == &binding) =>
            {
                self.probe_binding = Some(binding);
                Ok(State::NetworkReady)
            }
            Ok((State::NetworkReady, _)) => {
                self.observe_cleanup();
                Err(Failure::at(step))
            }
            Ok((state, _)) => {
                match state {
                    State::Stopped => self.cleaned(),
                    State::Stopping | State::CleanupPending => self.observe_cleanup(),
                    _ => self.probe_binding = None,
                }
                Ok(state)
            }
            Err(error) => {
                self.observe_cleanup();
                Err(wire_failure(error, step))
            }
        }
    }

    fn observe_cleanup(&mut self) {
        self.session = Session::Observing;
        self.probe_binding = None;
    }

    fn cleaned(&mut self) {
        self.session = Session::Inactive;
        self.generation = None;
        self.probe_binding = None;
    }
}

fn profile_failure() -> Failure {
    Failure {
        state: ConnectionState::Dropped,
        error: ErrorCode::UntrustedConfiguration,
        step: Step::Profile,
    }
}

fn wire_failure(error: FrameError, step: Step) -> Failure {
    let (state, error, step) = match error {
        FrameError::Protocol(WireError::PermissionDenied)
        | FrameError::Io(io::ErrorKind::PermissionDenied) => (
            ConnectionState::Dropped,
            ErrorCode::PermissionDenied,
            Step::Profile,
        ),
        FrameError::Protocol(WireError::MissingProgram) => (
            ConnectionState::MissingProgram,
            ErrorCode::MissingProgram,
            step,
        ),
        FrameError::Io(io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused)
            if step == Step::Runtime =>
        {
            (
                ConnectionState::MissingProgram,
                ErrorCode::MissingProgram,
                step,
            )
        }
        FrameError::Protocol(WireError::Busy) => {
            (ConnectionState::Dropped, ErrorCode::ProfileBusy, step)
        }
        FrameError::Protocol(WireError::Timeout) | FrameError::Io(io::ErrorKind::TimedOut) => (
            ConnectionState::GatewayTimeout,
            ErrorCode::BackendFailure,
            step,
        ),
        _ => (ConnectionState::Dropped, ErrorCode::BackendFailure, step),
    };
    Failure { state, error, step }
}

fn prepare(profile: &Profile) -> Result<Prepare, Failure> {
    profile.validate().map_err(|_| profile_failure())?;
    let endpoint =
        Endpoint::new(profile.gateway.clone(), profile.port).map_err(|_| profile_failure())?;
    match profile.kind {
        VpnKind::Ipsec if profile.certificate.is_empty() => {
            let networks = profile
                .networks
                .iter()
                .map(|cidr| {
                    let (address, prefix) = cidr.split_once('/').ok_or_else(profile_failure)?;
                    CidrV4::new(
                        address.parse().map_err(|_| profile_failure())?,
                        prefix.parse().map_err(|_| profile_failure())?,
                    )
                    .map_err(|_| profile_failure())
                })
                .collect::<Result<Vec<_>, _>>()?;
            IpsecRequest::new(endpoint, profile.username.clone(), networks)
                .map(Prepare::Ipsec)
                .map_err(|_| profile_failure())
        }
        VpnKind::Ssl => {
            let pin = certificate_pin(&profile.certificate).map_err(|_| profile_failure())?;
            FortinetRequest::new(endpoint, profile.username.clone(), pin)
                .map(Prepare::Fortinet)
                .map_err(|_| profile_failure())
        }
        _ => Err(profile_failure()),
    }
}

impl Attempt for TunnelAttempt {
    fn start(&mut self, canceled: &AtomicBool, expires: Instant) -> Result<(), Failure> {
        let credentials = self.credentials.take().ok_or_else(profile_failure)?;
        if canceled.load(Ordering::Acquire) {
            return Ok(());
        }
        let offer = prepare(&self.profile)?;
        let wire_credentials = match &offer {
            Prepare::Ipsec(_) => {
                WireCredentials::ipsec(credentials.password.expose(), credentials.psk.expose())
            }
            Prepare::Fortinet(_) => WireCredentials::fortinet(credentials.password.expose()),
        }
        .map_err(|_| Failure {
            state: ConnectionState::CredentialsRejected,
            error: ErrorCode::InvalidSecret,
            step: Step::Profile,
        })?;
        drop(credentials);
        let mut client = Client::connect_v2(&self.socket_path, expires)
            .map_err(|error| wire_failure(error, Step::Runtime))?;
        self.generation = client
            .prepare(offer, expires)
            .map_err(|error| wire_failure(error, Step::Tunnel))?;
        self.session = Session::Observing;
        if canceled.load(Ordering::Acquire) {
            return Ok(());
        }
        client
            .send_credentials(wire_credentials, expires)
            .map_err(|error| wire_failure(error, Step::Tunnel))?;
        self.session = Session::Active(client);
        self.connect_deadline = expires;
        self.next_status = Instant::now();
        Ok(())
    }

    fn ready(&mut self) -> Result<bool, Failure> {
        if Instant::now() < self.next_status {
            return Ok(false);
        }
        match self.status(self.connect_deadline, Step::Tunnel)? {
            State::NetworkReady => Ok(true),
            State::Prepared | State::Starting => Ok(false),
            State::Stopping | State::Stopped | State::CleanupPending => {
                Err(Failure::at(Step::Tunnel))
            }
        }
    }

    fn healthy(&mut self) -> Result<(), Failure> {
        if Instant::now() < self.next_status {
            return Ok(());
        }
        match self.status(Instant::now() + CONTROL_TIMEOUT, Step::Health)? {
            State::NetworkReady => Ok(()),
            _ => Err(Failure::at(Step::Health)),
        }
    }

    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        let deadline = Instant::now() + timeout;
        if timeout.is_zero() || canceled.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.probe_busy = true;
        let Some(slot) = ProbeSlot::acquire(&self.profile.id) else {
            return Ok(false);
        };
        self.probe_busy = false;
        let binding = self
            .probe_binding
            .as_ref()
            .ok_or_else(|| Failure::at(Step::Verify))?
            .clone();
        if !(self.probe)(&self.profile, &binding, canceled, deadline, slot)?
            || canceled.load(Ordering::Acquire)
            || Instant::now() >= deadline
        {
            return Ok(false);
        }

        // Force an authenticated refresh even inside the periodic status interval.
        // Resolution, TCP and the refresh share the caller's absolute budget.
        let refresh_by = deadline.min(Instant::now() + CONTROL_TIMEOUT);
        if self.status(refresh_by, Step::Verify)? != State::NetworkReady
            || self.probe_binding.as_ref() != Some(&binding)
        {
            return Err(Failure::at(Step::Verify));
        }
        Ok(!canceled.load(Ordering::Acquire) && Instant::now() < deadline)
    }

    fn probe_busy(&self) -> bool {
        self.probe_busy
    }

    fn cleanup(&mut self) -> bool {
        self.probe_binding = None;
        let session = std::mem::replace(&mut self.session, Session::Observing);
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let stopped = match session {
            Session::Inactive => true,
            Session::Active(mut client) => matches!(client.stop(deadline), Ok(State::Stopped)),
            Session::Observing => self.generation.as_ref().is_some_and(|generation| {
                Client::connect_v2(&self.socket_path, deadline)
                    .and_then(|client| client.cleanup_status(generation, deadline))
                    .is_ok_and(|state| state == CleanupState::Stopped)
            }),
        };
        if stopped {
            self.cleaned();
        }
        stopped
    }
}

// Resolution can outlive the probe deadline in libc. Keep its slot until the
// resolver returns, including across attempts for the same profile.
static PROBES: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

struct ProbeSlot(String);

impl ProbeSlot {
    fn acquire(id: &str) -> Option<Self> {
        let mut slots = PROBES.lock().unwrap_or_else(|error| error.into_inner());
        slots.insert(id.to_owned()).then(|| Self(id.to_owned()))
    }
}

impl Drop for ProbeSlot {
    fn drop(&mut self) {
        PROBES
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.0);
    }
}

fn allowed_probe_address(binding: &ProbeBinding, address: SocketAddr) -> Option<SocketAddrV4> {
    match address {
        SocketAddr::V4(address) if binding.allows(*address.ip()) => Some(address),
        _ => None,
    }
}

fn connect_bound(
    ifindex: NonZeroU32,
    address: SocketAddrV4,
    deadline: Instant,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device_by_index_v4(Some(ifindex))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    socket.connect_timeout(&SocketAddr::V4(address).into(), remaining)?;
    Ok(socket)
}

fn probe_tcp(
    profile: &Profile,
    binding: &ProbeBinding,
    canceled: &AtomicBool,
    deadline: Instant,
    slot: ProbeSlot,
) -> Result<bool, Failure> {
    if Instant::now() >= deadline || canceled.load(Ordering::Acquire) {
        return Ok(false);
    }
    let binding = binding.clone();
    let (host, port) = (profile.probe_host.clone(), profile.probe_port);
    let (send, receive) = mpsc::sync_channel(1);
    let interrupted = Arc::new(AtomicBool::new(false));
    let job_interrupted = interrupted.clone();
    thread::Builder::new()
        .name("vpnt-tunneld-probe".into())
        .spawn(move || {
            let _slot = slot;
            let reachable = (host.as_str(), port)
                .to_socket_addrs()
                .is_ok_and(|addresses| {
                    addresses.take(MAX_PROBE_DESTINATIONS).any(|address| {
                        Instant::now() < deadline
                            && !job_interrupted.load(Ordering::Acquire)
                            && allowed_probe_address(&binding, address).is_some_and(|address| {
                                connect_bound(binding.ifindex(), address, deadline).is_ok()
                            })
                    })
                });
            let _ = send.send(reachable);
        })
        .map_err(|_| Failure::at(Step::Verify))?;
    let result = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || canceled.load(Ordering::Acquire) {
            break Ok(false);
        }
        match receive.recv_timeout(remaining.min(Duration::from_millis(50))) {
            Ok(reachable) => {
                break Ok(reachable
                    && !canceled.load(Ordering::Acquire)
                    && Instant::now() < deadline);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break Err(Failure::at(Step::Verify)),
        }
    };
    interrupted.store(true, Ordering::Release);
    result
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;
