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
    network::{self, NetworkConfig, NetworkError},
    private_dir::PrivateDir,
    signing::Padding,
};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::{self, BufReader, Read, Write},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        mpsc::{self, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Version = Option<(u64, u64)>;
static VERSIONS: OnceLock<Mutex<HashMap<PathBuf, Version>>> = OnceLock::new();
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

fn parse_version(output: &[u8]) -> Version {
    let line = std::str::from_utf8(output).ok()?.lines().next()?;
    let mut words = line.split_whitespace();
    if words.next()? != "OpenVPN" {
        return None;
    }
    let mut numbers = words.next()?.split('.');
    let major = numbers.next()?.parse().ok()?;
    let minor = numbers.next()?.parse().ok()?;
    Some((major, minor))
}

fn version_for(path: &Path) -> io::Result<Version> {
    let mut cache = lock(VERSIONS.get_or_init(|| Mutex::new(HashMap::new())));
    if let Some(version) = cache.get(path) {
        return Ok(*version);
    }
    let mut child = Openvpn(
        Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut output = child
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("version output unavailable"))?;
    use std::os::fd::AsRawFd;
    let fd = output.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + VERSION_TIMEOUT;
    let mut captured = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        for _ in 0..4 {
            match output.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let remaining = 4096usize.saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..n.min(remaining)]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err(io::Error::other("openvpn version check failed"));
            }
            while captured.len() < 4096 {
                match output.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let remaining = 4096 - captured.len();
                        captured.extend_from_slice(&buffer[..n.min(remaining)]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            let version = parse_version(&captured);
            if version.is_none() {
                eprintln!("warning: could not read OpenVPN version");
            }
            cache.insert(path.to_owned(), version);
            return Ok(version);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "openvpn version check timed out",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn add_extra_options(command: &mut Command, extra: &[OsString], version: Version) {
    command.args(extra);
    if version.is_some_and(|version| version >= (2, 7)) {
        command.args(["--dns-updown", "disable"]);
    }
}

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

#[derive(Debug)]
pub enum ConfigSource {
    Path(PathBuf),
    #[cfg(target_os = "linux")]
    Sealed(std::os::fd::OwnedFd),
}
impl From<PathBuf> for ConfigSource {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}
impl From<&str> for ConfigSource {
    fn from(path: &str) -> Self {
        Self::Path(path.into())
    }
}
impl ConfigSource {
    /// Immutable bytes retained until the child inherits its config descriptor.
    #[cfg(target_os = "linux")]
    pub fn sealed(text: &[u8]) -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let fd = unsafe {
            libc::memfd_create(
                c"vpnt-ovpn".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        file.write_all(text)?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::Sealed(OwnedFd::from(file)))
    }
}

pub struct Launch<C = PathBuf> {
    pub openvpn: PathBuf,
    pub config: C,
    pub dev: Option<String>,
    pub signatures: Signatures,
    pub extra: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
}

/// Signature schemes the token may be asked for in the TLS handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signatures {
    /// PKCS#1 v1.5 or RSA-PSS, so TLS 1.3 can be negotiated.
    Any,
    /// PKCS#1 v1.5 only, which caps TLS at 1.2: for tokens whose PSS
    /// signatures servers do not accept (seen with the SerproID cloud token).
    Pkcs1Only,
}

/// openvpn does not limit TLS to the paddings it advertises: a server that
/// offers PSS gets picked and the handshake fails before any signature is
/// requested. OpenSSL itself is therefore told to offer only PKCS#1 v1.5.
/// This replaces the system OpenSSL configuration (and its policy) for
/// openvpn alone; `SignatureAlgorithms` also limits the server's own
/// signature, which suits the RSA servers this is meant for.
const PKCS1_ONLY: &str = "openssl_conf = vpnt\n[vpnt]\nssl_conf = vpnt_ssl\n\
    [vpnt_ssl]\nsystem_default = vpnt_tls\n[vpnt_tls]\nMaxProtocol = TLSv1.2\n\
    SignatureAlgorithms = RSA+SHA256:RSA+SHA384:RSA+SHA512\n\
    ClientSignatureAlgorithms = RSA+SHA256:RSA+SHA384:RSA+SHA512\n";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Progress {
    Up(NetworkConfig),
    Down,
    BadNetwork(NetworkError),
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
    #[cfg(target_os = "linux")]
    exit_observed: Mutex<Option<Instant>>,
}

impl Session {
    /// On Linux the child receives SIGTERM when the thread calling this method
    /// dies; that thread must outlive the session.
    pub fn start<C: Into<ConfigSource>>(
        launch: Launch<C>,
        signer: impl Signer,
    ) -> io::Result<Self> {
        let config = launch.config.into();
        let version = version_for(&launch.openvpn)?;
        let directory = PrivateDir::create(Path::new("/tmp"))?;
        let socket = directory.path.join("management");
        let listener = UnixListener::bind(&socket)?;
        let mut command = Command::new(&launch.openvpn);
        command.arg("--config");
        match &config {
            ConfigSource::Path(path) => {
                command.arg(path);
            }
            #[cfg(target_os = "linux")]
            ConfigSource::Sealed(_) => {
                command.arg("/dev/fd/3");
            }
        }
        if let Some(dev) = &launch.dev {
            command.args(["--dev", dev, "--dev-type", "tun", "--disable-dco"]);
        }
        command
            .arg("--management")
            .arg(&socket)
            .arg("unix")
            .args([
                "--management-client",
                "--management-hold",
                "--management-up-down",
            ])
            .args(["--management-external-cert", "vpnt"])
            .args(["--route-noexec", "--ifconfig-noexec"])
            .envs(launch.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        add_extra_options(&mut command, &launch.extra, version);
        command.args(["--remote-cert-tls", "server"]);
        match launch.signatures {
            Signatures::Any => {
                command.args(["--management-external-key", "pkcs1", "pss"]);
            }
            Signatures::Pkcs1Only => {
                let config = directory.path.join("openssl.cnf");
                fs::write(&config, PKCS1_ONLY)?;
                // After the profile and the extras, so a profile asking for
                // TLS 1.3 cannot bring back the PSS handshake.
                command
                    .args(["--management-external-key", "pkcs1"])
                    .args(["--tls-version-max", "1.2"])
                    .env("OPENSSL_CONF", config);
            }
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::process::CommandExt;
            let config_fd = match &config {
                ConfigSource::Path(_) => None,
                ConfigSource::Sealed(fd) => {
                    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
                    let required = libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL;
                    if seals < 0 || seals & required != required {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    Some(fd.as_raw_fd())
                }
            };
            let parent = unsafe { libc::getpid() };
            // With pre_exec, spawn waits for fork/exec via its CLOEXEC pipe,
            // keeping this calling thread alive through prctl. getppid checks
            // process death between fork and prctl.
            unsafe {
                command.pre_exec(move || {
                    if let Some(fd) = config_fd
                        && (libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0)
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        return Err(io::Error::other("parent exited"));
                    }
                    Ok(())
                });
            }
        }
        let mut openvpn = Openvpn(command.spawn()?);
        let stream = accept(&listener, &mut openvpn.0)?;
        drop(listener);
        let _ = fs::remove_file(&socket);
        let control_stream = stream.try_clone()?;
        // macOS refuses SO_SNDTIMEO with EINVAL once openvpn has already
        // closed its end; writes to such a peer fail at once, so the session
        // goes on and reports the exit. Any other error still aborts.
        if let Err(error) = control_stream.set_write_timeout(Some(Duration::from_secs(2)))
            && error.raw_os_error() != Some(libc::EINVAL)
        {
            return Err(error);
        }
        let control = Arc::new(Mutex::new(control_stream));
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
            #[cfg(target_os = "linux")]
            exit_observed: Mutex::new(None),
        })
    }

    /// Observe exit without reaping; `wait` still owns the final status.
    #[cfg(target_os = "linux")]
    pub fn exited(&self) -> Option<Option<Reason>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.openvpn.0.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 && unsafe { info.si_pid() } != 0 {
            let first = *lock(&self.exit_observed).get_or_insert_with(Instant::now);
            let remaining = (first + DRAIN_TIMEOUT).saturating_duration_since(Instant::now());
            let _ = self.finished.recv_timeout(remaining);
            Some(*lock(&self.reason))
        } else {
            None
        }
    }

    pub fn progress(&self) -> &mpsc::Receiver<Progress> {
        &self.progress
    }

    /// Asks openvpn to leave, notifying the server.
    pub fn stop(&self) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut control = match self.control.try_lock() {
                Ok(control) => control,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(io::ErrorKind::TimedOut.into());
                    };
                    if remaining.is_zero() {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    thread::sleep(remaining.min(Duration::from_millis(10)));
                    continue;
                }
            };
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(io::ErrorKind::TimedOut.into());
            };
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            control.set_write_timeout(Some(remaining))?;
            return control.write_all(management::TERMINATE.as_bytes());
        }
    }

    /// Returns once openvpn has exited and its last lines were read, so a
    /// refusal reported just before the exit is not lost. A signature still
    /// waiting for the user does not hold this up: that thread is cut off and
    /// finishes on its own, while its C_Sign stays pending in the module until
    /// the token gives up (cryptoki exposes no C_SessionCancel).
    pub fn wait(mut self) -> io::Result<Outcome> {
        let status = self.openvpn.0.wait()?;
        // The drain budget counts from the first time the exit was seen, so an
        // exit already observed (and waited for) by `exited` is not waited
        // for again here.
        #[cfg(target_os = "linux")]
        let drain = {
            let first = *lock(&self.exit_observed).get_or_insert_with(Instant::now);
            (first + DRAIN_TIMEOUT).saturating_duration_since(Instant::now())
        };
        #[cfg(not(target_os = "linux"))]
        let drain = DRAIN_TIMEOUT;
        match self.finished.recv_timeout(drain) {
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
    let mut block: Option<Option<Vec<(String, String)>>> = None;
    while let Ok(true) = management::read_line(&mut reader, &mut line) {
        let event = management::parse(&line);
        if let Event::Env { key, value } = event {
            if let Some(Some(pairs)) = &mut block {
                if pairs.len() == 1024 {
                    let _ = progress.send(Progress::BadNetwork(NetworkError::TooLarge));
                    let _ = send(control, management::TERMINATE);
                    block = Some(None);
                } else {
                    pairs.push((key, value));
                }
            }
            continue;
        }
        // Inside an UP block only well-formed lines may close it; anything
        // malformed (a broken UPDOWN record or any unparsable line) rejects it.
        if matches!(event, Event::MalformedEnv | Event::Malformed) {
            if matches!(block, Some(Some(_))) {
                let _ = progress.send(Progress::BadNetwork(NetworkError::Malformed));
                let _ = send(control, management::TERMINATE);
                block = Some(None);
            }
            continue;
        }
        if let Some(Some(pairs)) = block.take() {
            // openvpn ends every UP block with >UPDOWN:ENV,END. Any other line
            // before it means the block is incomplete or forged: never publish
            // the pairs read so far. The line itself is then handled normally.
            if event == Event::EnvEnd {
                match network::from_env(&pairs) {
                    Ok(config) => {
                        let _ = progress.send(Progress::Up(config));
                    }
                    Err(error) => {
                        let _ = progress.send(Progress::BadNetwork(error));
                        let _ = send(control, management::TERMINATE);
                    }
                }
            } else {
                let _ = progress.send(Progress::BadNetwork(NetworkError::Malformed));
                let _ = send(control, management::TERMINATE);
            }
        }
        let reply = match event {
            Event::Up => {
                block = Some(Some(Vec::new()));
                None
            }
            Event::Down => {
                let _ = progress.send(Progress::Down);
                block = Some(None);
                None
            }
            Event::EnvEnd => None,
            Event::Env { .. } | Event::MalformedEnv | Event::Malformed => unreachable!(),
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
            Event::Ignored => None,
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
