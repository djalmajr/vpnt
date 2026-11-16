//! Runs openvpn as a management client and answers its certificate and
//! signature requests from a Signer. The management socket lives in a private
//! directory: over loopback TCP any local process could connect first and use
//! the driver as a signing oracle for the user's certificate.
//!
//! openvpn never configures the network itself (`--ifconfig-noexec`,
//! `--route-noexec`): the address, routes and DNS it receives are applied by
//! the vpnt helper, so a `Connected` state alone does not mean traffic flows.
use super::{
    management::{self, Event, Reason, State},
    private_dir::PrivateDir,
    signing::Padding,
};
use std::{
    ffi::OsString,
    fs,
    io::{self, BufReader, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `wait` lets the management thread read openvpn's last lines.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub trait Signer: Send + 'static {
    /// DER certificate whose key answers `sign`.
    fn certificate(&mut self) -> Result<Vec<u8>, SignError>;
    fn sign(&mut self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, SignError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignError {
    /// The user declined, or did not approve in time.
    Canceled,
    /// openvpn asked for a padding or input the driver does not sign.
    Unsupported,
    /// The token needs a PIN, which this driver does not collect yet.
    PinRequired,
    Unavailable,
}

pub struct Launch {
    pub openvpn: PathBuf,
    pub config: PathBuf,
    /// Also advertise RSA-PSS, which TLS 1.3 requires. openvpn does not limit
    /// TLS to what is advertised: a server that picks PSS fails the handshake
    /// when this is off.
    pub pss: bool,
    pub extra: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Progress {
    AwaitingApproval,
    State(State),
    Refused(SignError),
}

#[derive(Debug)]
pub struct Outcome {
    /// Last reason openvpn gave for leaving or restarting the session.
    pub reason: Option<Reason>,
    pub status: ExitStatus,
}

pub struct Session {
    openvpn: Openvpn,
    control: Arc<Mutex<UnixStream>>,
    reason: Arc<Mutex<Option<Reason>>>,
    worker: JoinHandle<()>,
    /// Disconnects when the management thread ends.
    finished: mpsc::Receiver<()>,
    progress: mpsc::Receiver<Progress>,
    _directory: PrivateDir,
}

impl Session {
    pub fn start(launch: Launch, signer: impl Signer) -> io::Result<Self> {
        let directory = PrivateDir::create(Path::new("/tmp"))?;
        let socket = directory.path.join("management");
        let listener = UnixListener::bind(&socket)?;
        let mut openvpn = Openvpn(
            Command::new(&launch.openvpn)
                .arg("--config")
                .arg(&launch.config)
                .arg("--management")
                .arg(&socket)
                .arg("unix")
                .args(["--management-client", "--management-hold"])
                .args(["--management-external-key", "pkcs1"])
                .args(launch.pss.then_some("pss"))
                .args(["--management-external-cert", "vpnt"])
                .args(["--route-noexec", "--ifconfig-noexec"])
                .args(&launch.extra)
                .envs(launch.env.iter().map(|(key, value)| (key, value)))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let stream = accept(&listener, &mut openvpn.0)?;
        drop(listener);
        let _ = fs::remove_file(&socket);
        let control = Arc::new(Mutex::new(stream.try_clone()?));
        let reason = Arc::default();
        let (sender, progress) = mpsc::channel();
        let (writer, last_reason) = (Arc::clone(&control), Arc::clone(&reason));
        let (done, finished) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("vpnt-ovpn-management".into())
            .spawn(move || {
                let _done = done;
                drive(stream, &writer, signer, &sender, &last_reason);
            })?;
        Ok(Self {
            openvpn,
            control,
            reason,
            worker,
            finished,
            progress,
            _directory: directory,
        })
    }

    pub fn progress(&self) -> &mpsc::Receiver<Progress> {
        &self.progress
    }

    /// Asks openvpn to leave, notifying the server.
    pub fn stop(&self) -> io::Result<()> {
        send(&self.control, management::TERMINATE)
    }

    /// Returns once openvpn has exited and its last lines were read, so a
    /// refusal reported just before the exit is not lost. A signature still
    /// waiting for the user does not hold this up: that thread is cut off and
    /// finishes on its own, while its C_Sign stays pending in the module until
    /// the token gives up (cryptoki exposes no C_SessionCancel).
    pub fn wait(mut self) -> io::Result<Outcome> {
        let status = self.openvpn.0.wait()?;
        match self.finished.recv_timeout(DRAIN_TIMEOUT) {
            Err(RecvTimeoutError::Timeout) => {
                let _ = lock(&self.control).shutdown(Shutdown::Both);
            }
            _ => {
                let _ = self.worker.join();
            }
        }
        let reason = *lock(&self.reason);
        Ok(Outcome { reason, status })
    }
}

/// Kills and reaps openvpn unless it already exited, on every early return.
struct Openvpn(Child);

impl Drop for Openvpn {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn accept(listener: &UnixListener, child: &mut Child) -> io::Result<UnixStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "openvpn exited before connecting ({status})"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "openvpn did not connect",
                    ));
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
}

fn drive(
    stream: UnixStream,
    control: &Mutex<UnixStream>,
    mut signer: impl Signer,
    progress: &mpsc::Sender<Progress>,
    reason: &Mutex<Option<Reason>>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    // A failed write means openvpn is gone; its last lines are still worth
    // reading, so writes never end the loop, only the end of the stream does.
    let _ = send(control, management::VERSION).and_then(|()| send(control, management::STATE_ON));
    while let Ok(true) = management::read_line(&mut reader, &mut line) {
        let reply = match management::parse(&line) {
            Event::Hold => Some(management::HOLD_RELEASE.to_owned()),
            Event::NeedCertificate => Some(match signer.certificate() {
                Ok(der) => management::certificate(&der),
                Err(error) => refuse(progress, error),
            }),
            Event::Sign { data, algorithm } => Some(match request(algorithm.as_deref(), &data) {
                Ok(padding) => {
                    let _ = progress.send(Progress::AwaitingApproval);
                    match signer.sign(padding, &data) {
                        Ok(signature) => management::signature(&signature),
                        Err(error) => refuse(progress, error),
                    }
                }
                Err(error) => refuse(progress, error),
            }),
            Event::UnreadableSign => Some(refuse(progress, SignError::Unsupported)),
            Event::State(state) => {
                if state.reason.is_some() {
                    *lock(reason) = state.reason;
                }
                let _ = progress.send(Progress::State(state));
                None
            }
            Event::Fatal => {
                *lock(reason) = Some(Reason::Fatal);
                None
            }
            Event::Ignored | Event::Malformed => None,
        };
        if let Some(reply) = reply {
            let _ = send(control, &reply);
        }
    }
}

/// Validated before the user is asked to approve anything.
fn request(algorithm: Option<&str>, data: &[u8]) -> Result<Padding, SignError> {
    let padding = Padding::from_request(algorithm).map_err(|_| SignError::Unsupported)?;
    if !padding.accepts(data) {
        return Err(SignError::Unsupported);
    }
    Ok(padding)
}

/// Without a signature the handshake cannot finish, so leave instead of
/// letting openvpn retry against a token that already said no.
fn refuse(progress: &mpsc::Sender<Progress>, error: SignError) -> String {
    let _ = progress.send(Progress::Refused(error));
    management::TERMINATE.to_owned()
}

fn send(control: &Mutex<UnixStream>, text: &str) -> io::Result<()> {
    lock(control).write_all(text.as_bytes())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
