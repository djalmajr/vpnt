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
            CidrV4, Credentials as WireCredentials, Endpoint, ErrorCode as WireError,
            FortinetRequest, FrameError, IpsecRequest, Prepare, State,
        },
    },
};
use std::{
    collections::BTreeSet,
    io,
    net::{TcpStream, ToSocketAddrs},
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

type Probe = fn(&Profile, &AtomicBool, Duration, ProbeSlot) -> Result<bool, Failure>;

enum Session {
    Inactive,
    Active(Client),
    Stopping(Client),
    Unconfirmed,
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
    admission_pending: bool,
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
            admission_pending: true,
        }
    }

    fn status(&mut self, deadline: Instant, step: Step) -> Result<State, Failure> {
        let Session::Active(client) = &mut self.session else {
            return Err(Failure::at(step));
        };
        self.next_status = Instant::now() + STATUS_INTERVAL;
        match client.status(deadline) {
            Ok(state) => {
                match state {
                    State::Starting | State::NetworkReady => self.admission_pending = false,
                    State::Stopped => self.session = Session::Inactive,
                    State::Stopping | State::CleanupPending => {
                        self.admission_pending = false;
                        let Session::Active(client) =
                            std::mem::replace(&mut self.session, Session::Unconfirmed)
                        else {
                            unreachable!("status requires an active session");
                        };
                        self.session = Session::Stopping(client);
                    }
                    State::Prepared => {}
                }
                Ok(state)
            }
            Err(error) => {
                self.session = if confirms_absence(error, self.admission_pending) {
                    Session::Inactive
                } else {
                    Session::Unconfirmed
                };
                Err(wire_failure(error, step))
            }
        }
    }
}

fn confirms_absence(error: FrameError, admission_pending: bool) -> bool {
    // These protocol refusals can reject admission. After observed activation
    // or a stop in progress, only Stopped confirms that the generation is gone.
    admission_pending
        && matches!(
            error,
            FrameError::Protocol(WireError::MissingProgram | WireError::PermissionDenied)
        )
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
        let mut client = Client::connect(&self.socket_path, expires)
            .map_err(|error| wire_failure(error, Step::Runtime))?;
        client
            .prepare(offer, expires)
            .map_err(|error| wire_failure(error, Step::Tunnel))?;
        if canceled.load(Ordering::Acquire) {
            return Ok(());
        }
        self.session = Session::Unconfirmed;
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
        self.probe_busy = true;
        let Some(slot) = ProbeSlot::acquire(&self.profile.id) else {
            return Ok(false);
        };
        self.probe_busy = false;
        (self.probe)(&self.profile, canceled, timeout, slot)
    }

    fn probe_busy(&self) -> bool {
        self.probe_busy
    }

    fn cleanup(&mut self) -> bool {
        let session = std::mem::replace(&mut self.session, Session::Unconfirmed);
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        let (client, result) = match session {
            Session::Inactive => {
                self.session = Session::Inactive;
                return true;
            }
            Session::Unconfirmed => return false,
            Session::Active(mut client) => {
                let result = client.stop(deadline);
                (client, result)
            }
            Session::Stopping(mut client) => {
                let result = client.status(deadline);
                (client, result)
            }
        };
        match result {
            Ok(State::Stopped) => self.session = Session::Inactive,
            Ok(_) => {
                self.admission_pending = false;
                self.session = Session::Stopping(client);
            }
            Err(error) if confirms_absence(error, self.admission_pending) => {
                self.session = Session::Inactive;
            }
            Err(_) => {}
        }
        matches!(self.session, Session::Inactive)
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

fn probe_tcp(
    profile: &Profile,
    canceled: &AtomicBool,
    timeout: Duration,
    slot: ProbeSlot,
) -> Result<bool, Failure> {
    if timeout.is_zero() || canceled.load(Ordering::Acquire) {
        return Ok(false);
    }
    let deadline = Instant::now() + timeout;
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
                .is_ok_and(|mut addresses| {
                    addresses.any(|address| {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        !remaining.is_zero()
                            && !job_interrupted.load(Ordering::Acquire)
                            && TcpStream::connect_timeout(&address, remaining).is_ok()
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
