//! Admission of one tunnel session up to the authenticated backend instance.
//!
//! The order is fixed. Under the shared network lock the launcher refuses when
//! the network backend reports an OVPN link or any lease exists, and otherwise
//! registers the lease of this generation. Outside the lock it creates the
//! private generation directory, publishes the handshake record and control
//! socket, starts the instance unit and authenticates the instance through the
//! system manager. Every failure, a stop and a closed client run the same
//! teardown: stop the unit, remove the directory, then withdraw the lease
//! under the lock. A lease is withdrawn only after the unit stop is proven, so
//! an unproven stop keeps the network reserved and reports `CleanupPending`.
//!
//! Tunnel configuration inside the instance (VICI, routes, DNS) is not part of
//! this slice: the received credentials are dropped, zeroed, without being used.
use super::{
    attest::SystemdAttestor,
    handshake::{AuthenticatedChannel, Backend, UnitAttestor, Writer},
    protocol::{ErrorCode, State},
};
use crate::{
    netd::{iproute::Backend as NetworkBackend, server::ovpn_present},
    netlease::{NetworkGuard, NetworkLock},
};
use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Runtime directory shared with the network writers.
pub(super) const RUNTIME_DIRECTORY: &str = "/run/vpnt";
/// Per-generation private directories live in `<runtime>/tunneld/<generation>`.
/// The unit templates bind that directory read-only into the instance.
pub(super) const INSTANCE_DIRECTORY: &str = "tunneld";
/// Control socket basename inside the generation directory. The handshake
/// record is published next to it under the generation as its basename.
pub(super) const CONTROL_SOCKET: &str = "control.sock";
/// The instance units run as root with group 0.
pub(super) const INSTANCE_GID: libc::gid_t = 0;

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const LOCK_DEADLINE: Duration = Duration::from_secs(4);
const START_DEADLINE: Duration = Duration::from_secs(5);
const STOP_DEADLINE: Duration = Duration::from_secs(30);

/// Admit a session and return its running handle.
pub(super) trait Launch: Send + Sync {
    fn launch<'a>(&'a self, backend: Backend) -> Result<Box<dyn Running + 'a>, ErrorCode>;
}

/// One admitted session. Dropping it stops it.
pub(super) trait Running {
    fn state(&self) -> State;
    /// Stop and clean up. A `CleanupPending` result may be retried.
    fn stop(&mut self) -> State;
}

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub lock: Duration,
    pub start: Duration,
    pub stop: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            lock: LOCK_DEADLINE,
            start: START_DEADLINE,
            stop: STOP_DEADLINE,
        }
    }
}

type AcquireLock = Box<dyn Fn(Instant) -> io::Result<NetworkGuard> + Send + Sync>;

pub(super) struct Launcher<N, A> {
    runtime: PathBuf,
    systemctl: PathBuf,
    network: N,
    attestor: A,
    lock: AcquireLock,
    limits: Limits,
}

impl<N: NetworkBackend> Launcher<N, SystemdAttestor> {
    pub(super) fn system(network: N) -> Self {
        Self {
            runtime: PathBuf::from(RUNTIME_DIRECTORY),
            systemctl: PathBuf::from(SYSTEMCTL),
            network,
            attestor: SystemdAttestor,
            lock: Box::new(NetworkLock::acquire),
            limits: Limits::default(),
        }
    }
}

/// What this attempt has already done, so teardown reverses exactly that.
struct Attempt {
    backend: Backend,
    generation: String,
    unit: String,
    registered: bool,
    directory: bool,
    started: bool,
}

impl Attempt {
    fn new(backend: Backend, generation: String) -> Self {
        let kind = match backend {
            Backend::Ipsec => "ipsec",
            Backend::Fortinet => "fortinet",
        };
        let unit = format!("vpnt-tunneld-{kind}@{generation}.service");
        Self {
            backend,
            generation,
            unit,
            registered: false,
            directory: false,
            started: false,
        }
    }
}

struct Failure {
    code: ErrorCode,
    cause: String,
}

impl Failure {
    fn new(code: ErrorCode, cause: impl std::fmt::Display) -> Self {
        Self {
            code,
            cause: cause.to_string(),
        }
    }

    fn io(step: &str, error: &io::Error) -> Self {
        let code = if error.kind() == io::ErrorKind::TimedOut {
            ErrorCode::Timeout
        } else {
            ErrorCode::Backend
        };
        Self::new(code, format_args!("{step}: {error}"))
    }
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launcher<N, A> {
    fn bring_up(&self, attempt: &mut Attempt) -> Result<AuthenticatedChannel, Failure> {
        {
            // The checks and the registration share this one acquisition, so
            // a competing admission cannot slip between them.
            let guard = (self.lock)(Instant::now() + self.limits.lock).map_err(|error| {
                if error.kind() == io::ErrorKind::TimedOut {
                    Failure::new(ErrorCode::Busy, "network write lock is contended")
                } else {
                    Failure::io("network write lock", &error)
                }
            })?;
            if ovpn_present(&self.network).map_err(|e| Failure::io("network inventory", &e))? {
                return Err(Failure::new(ErrorCode::Busy, "an OVPN tunnel is present"));
            }
            if guard
                .tunnels_present()
                .map_err(|e| Failure::io("lease registry", &e))?
            {
                return Err(Failure::new(ErrorCode::Busy, "a tunnel lease is present"));
            }
            // A sync error after creation leaves the marker, so mark first.
            attempt.registered = true;
            guard
                .register(&attempt.generation)
                .map_err(|e| Failure::io("lease registration", &e))?;
        }

        attempt.directory = true;
        let directory = self
            .create_directory(&attempt.generation)
            .map_err(|e| Failure::io("generation directory", &e))?;
        let writer = Writer::publish(
            &directory,
            OsStr::new(CONTROL_SOCKET),
            &attempt.generation,
            attempt.backend,
            INSTANCE_GID,
        )
        .map_err(|e| Failure::io("handshake publication", &e))?;

        // An attempt that failed to run may still have queued the job.
        attempt.started = true;
        run_systemctl(
            &self.systemctl,
            &["start", "--no-block", "--", &attempt.unit],
            self.limits.start,
        )
        .map_err(|e| Failure::io("systemctl start", &e))?;
        writer
            .authenticate(&self.attestor)
            .map_err(|e| Failure::io("instance authentication", &e))
    }

    fn create_directory(&self, generation: &str) -> io::Result<PathBuf> {
        let parent = self.runtime.join(INSTANCE_DIRECTORY);
        match DirBuilder::new().mode(0o700).create(&parent) {
            Ok(()) => fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        require_private(&parent)?;
        let directory = parent.join(generation);
        // Exclusive: a generation is never reused.
        DirBuilder::new().mode(0o700).create(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        require_private(&directory)?;
        Ok(directory)
    }

    /// Reverse what the attempt did. True when every step is proven.
    fn teardown(&self, attempt: &Attempt) -> bool {
        if attempt.started {
            let stop = ["stop", "--", &attempt.unit];
            if let Err(error) = run_systemctl(&self.systemctl, &stop, self.limits.stop) {
                // The instance may still run: keep its directory and lease.
                eprintln!("vpnt-tunneld: unit stop is unproven: {error}");
                return false;
            }
        }
        let mut proven = true;
        if attempt.directory {
            let path = self
                .runtime
                .join(INSTANCE_DIRECTORY)
                .join(&attempt.generation);
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    eprintln!("vpnt-tunneld: generation directory removal failed: {error}");
                    proven = false;
                }
            }
        }
        if attempt.registered {
            let withdrawn = (self.lock)(Instant::now() + self.limits.lock)
                .and_then(|guard| guard.withdraw(&attempt.generation));
            if let Err(error) = withdrawn {
                eprintln!("vpnt-tunneld: lease withdrawal failed: {error}");
                proven = false;
            }
        }
        proven
    }
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launch for Launcher<N, A> {
    fn launch<'a>(&'a self, backend: Backend) -> Result<Box<dyn Running + 'a>, ErrorCode> {
        let generation = generation().map_err(|error| {
            eprintln!("vpnt-tunneld: could not draw a generation: {error}");
            ErrorCode::Backend
        })?;
        let mut attempt = Attempt::new(backend, generation);
        match self.bring_up(&mut attempt) {
            Ok(channel) => Ok(Box::new(Session {
                launcher: self,
                attempt,
                channel: Some(channel),
                state: State::Starting,
            })),
            Err(failure) => {
                eprintln!("vpnt-tunneld: admission failed: {}", failure.cause);
                Err(if self.teardown(&attempt) {
                    failure.code
                } else {
                    ErrorCode::CleanupPending
                })
            }
        }
    }
}

struct Session<'a, N: NetworkBackend, A: UnitAttestor + Send + Sync> {
    launcher: &'a Launcher<N, A>,
    attempt: Attempt,
    channel: Option<AuthenticatedChannel>,
    state: State,
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Running for Session<'_, N, A> {
    fn state(&self) -> State {
        self.state
    }

    fn stop(&mut self) -> State {
        if self.state == State::Stopped {
            return self.state;
        }
        self.state = State::Stopping;
        drop(self.channel.take());
        self.state = if self.launcher.teardown(&self.attempt) {
            State::Stopped
        } else {
            State::CleanupPending
        };
        self.state
    }
}

impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Drop for Session<'_, N, A> {
    fn drop(&mut self) {
        Running::stop(self);
    }
}

fn require_private(path: &Path) -> io::Result<()> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = File::metadata(&directory)?;
    // SAFETY: geteuid has no preconditions.
    let owner = unsafe { libc::geteuid() };
    if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

/// 32 lowercase hex characters from the kernel, new for every session.
fn generation() -> io::Result<String> {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: the remaining slice is writable for the supplied length.
        let count = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        match usize::try_from(count) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => filled += count,
            Err(_) => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
    let mut generation = String::with_capacity(32);
    for byte in bytes {
        write!(generation, "{byte:02x}").expect("writing to a String");
    }
    Ok(generation)
}

struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Run the fixed systemctl with a clean environment and an absolute deadline.
fn run_systemctl(path: &Path, args: &[&str], timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut child = Reaper(
        Command::new(path)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    loop {
        if let Some(status) = child.0.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("systemctl exited with {status}")))
            };
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
impl<N: NetworkBackend, A: UnitAttestor + Send + Sync> Launcher<N, A> {
    fn for_test(
        runtime: PathBuf,
        systemctl: PathBuf,
        network: N,
        attestor: A,
        lock: AcquireLock,
        limits: Limits,
    ) -> Self {
        Self {
            runtime,
            systemctl,
            network,
            attestor,
            lock,
            limits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        netd::{
            iproute::Existing,
            protocol::{Config, TunName},
        },
        tunneld::handshake::{UnitIdentity, connect_instance},
    };
    use std::{
        os::fd::BorrowedFd,
        process::Command,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::JoinHandle,
    };

    const NAMESPACE: &str = "VPNT_ADMISSION_NAMESPACE";
    const INVOCATION: &str = "fedcba9876543210fedcba9876543210";

    /// The handshake accepts only a root peer and a root-owned directory, so
    /// each case re-runs itself as root of a private user and mount namespace.
    /// Returns true inside that namespace, where the case body must run.
    fn namespaced(name: &str) -> bool {
        if std::env::var_os(NAMESPACE).is_some() {
            return true;
        }
        let unshare = || {
            let mut command = Command::new("/usr/bin/unshare");
            command.args(["--user", "--map-root-user", "--mount", "--"]);
            command
        };
        let probe = unshare()
            .arg("/bin/true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !probe.as_ref().is_ok_and(|status| status.success()) {
            // CI sets VPNT_REQUIRE_USERNS=1 where the namespaces are enabled.
            assert!(
                std::env::var_os("VPNT_REQUIRE_USERNS").is_none(),
                "unprivileged user and mount namespaces are required here: {probe:?}"
            );
            eprintln!("skipped: unprivileged user namespaces are unavailable here: {probe:?}");
            return false;
        }
        let output = unshare()
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &format!("tunneld::backend::tests::{name}")])
            .arg("--nocapture")
            .env_clear()
            .env(NAMESPACE, "1")
            .env("TMPDIR", std::env::temp_dir())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{name} failed:\n{stdout}\n{stderr}"
        );
        assert!(stdout.contains("1 passed"), "{name} did not run:\n{stdout}");
        false
    }

    #[derive(Default)]
    struct FakeNetwork {
        ovpn: Arc<AtomicBool>,
        inventories: Arc<AtomicUsize>,
    }

    impl NetworkBackend for FakeNetwork {
        fn create_tun(&self, _: &TunName, _: u32) -> io::Result<()> {
            Err(io::Error::other("inventory fixture"))
        }
        fn configure(&self, _: &Config) -> io::Result<()> {
            Err(io::Error::other("inventory fixture"))
        }
        fn delete_tun(&self, _: &TunName) -> io::Result<()> {
            Err(io::Error::other("inventory fixture"))
        }
        fn existing(&self) -> io::Result<Vec<Existing>> {
            self.inventories.fetch_add(1, Ordering::SeqCst);
            Ok(if self.ovpn.load(Ordering::SeqCst) {
                vec![Existing {
                    name: TunName::parse("vpnt0").unwrap(),
                    owned: true,
                    ifindex: std::num::NonZeroU32::new(7).unwrap(),
                    is_tun: true,
                }]
            } else {
                Vec::new()
            })
        }
    }

    /// Attests the unit that the fake systemctl was asked to start.
    struct FakeAttestor {
        log: PathBuf,
        fail: bool,
    }

    impl UnitAttestor for FakeAttestor {
        fn attest(&self, _: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
            if self.fail {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(UnitIdentity {
                name: started_unit(&self.log).ok_or(io::ErrorKind::NotFound)?,
                invocation: INVOCATION.to_owned(),
                // The fake instance is a thread of this process.
                // SAFETY: getpid has no preconditions.
                main_pid: unsafe { libc::getpid() },
            })
        }
    }

    fn started_unit(log: &Path) -> Option<String> {
        fs::read_to_string(log)
            .ok()?
            .lines()
            .filter_map(|line| line.strip_prefix("start --no-block -- "))
            .next_back()
            .map(str::to_owned)
    }

    fn generation_of(unit: &str) -> String {
        let (_, rest) = unit.split_once('@').unwrap();
        rest.strip_suffix(".service").unwrap().to_owned()
    }

    struct Harness {
        root: PathBuf,
        runtime: PathBuf,
        log: PathBuf,
        stop: Arc<AtomicBool>,
        instance: Option<JoinHandle<Option<AuthenticatedChannel>>>,
    }

    impl Harness {
        fn new() -> Self {
            // Unix socket paths are short: keep the fixture root brief.
            let root = std::env::temp_dir().join(format!("va-{}", &generation().unwrap()[..8]));
            DirBuilder::new().mode(0o700).create(&root).unwrap();
            let runtime = root.join("run");
            DirBuilder::new().mode(0o700).create(&runtime).unwrap();
            let log = root.join("systemctl.log");
            let script = format!(
                "#!/bin/sh\necho \"$*\" >> '{log}'\n\
                 [ \"$1\" = start ] && [ -e '{root}/fail-start' ] && exit 1\n\
                 [ \"$1\" = stop ] && [ -e '{root}/fail-stop' ] && exit 1\n\
                 exit 0\n",
                log = log.display(),
                root = root.display(),
            );
            let systemctl = root.join("systemctl");
            fs::write(&systemctl, script).unwrap();
            fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                root,
                runtime,
                log,
                stop: Arc::default(),
                instance: None,
            }
        }

        fn flag(&self, name: &str, on: bool) {
            let path = self.root.join(name);
            if on {
                fs::write(path, b"").unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
        }

        fn lock(&self) -> AcquireLock {
            let runtime = self.runtime.clone();
            Box::new(move |deadline| NetworkLock::acquire_test(&runtime, deadline))
        }

        fn launcher(&self, fail_attest: bool) -> Launcher<FakeNetwork, FakeAttestor> {
            self.launcher_with(
                FakeNetwork::default(),
                fail_attest,
                self.lock(),
                Limits::default(),
            )
        }

        fn launcher_with(
            &self,
            network: FakeNetwork,
            fail: bool,
            lock: AcquireLock,
            limits: Limits,
        ) -> Launcher<FakeNetwork, FakeAttestor> {
            Launcher::for_test(
                self.runtime.clone(),
                self.root.join("systemctl"),
                network,
                FakeAttestor {
                    log: self.log.clone(),
                    fail,
                },
                lock,
                limits,
            )
        }

        /// A fake instance that runs the real handshake once its unit is started.
        fn instance(&mut self, backend: Backend) {
            let (log, runtime, stop) = (self.log.clone(), self.runtime.clone(), self.stop.clone());
            self.instance = Some(thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(20);
                let unit = loop {
                    if stop.load(Ordering::SeqCst) || Instant::now() > deadline {
                        return None;
                    }
                    if let Some(unit) = started_unit(&log) {
                        break unit;
                    }
                    thread::sleep(Duration::from_millis(5));
                };
                let generation = generation_of(&unit);
                let directory = runtime.join(INSTANCE_DIRECTORY).join(&generation);
                connect_instance(
                    &directory.join(CONTROL_SOCKET),
                    &directory.join(&generation),
                    &generation,
                    backend,
                    INVOCATION,
                    INSTANCE_GID,
                )
                .ok()
            }));
        }

        fn log(&self) -> Vec<String> {
            fs::read_to_string(&self.log)
                .map(|log| log.lines().map(str::to_owned).collect())
                .unwrap_or_default()
        }

        fn leases(&self) -> Vec<String> {
            let mut leases: Vec<String> = fs::read_dir(self.runtime.join("tunnel-leases"))
                .map(|entries| {
                    entries
                        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                        .collect()
                })
                .unwrap_or_default();
            leases.sort();
            leases
        }

        fn directory(&self, generation: &str) -> PathBuf {
            self.runtime.join(INSTANCE_DIRECTORY).join(generation)
        }

        /// Nothing was started, created or registered.
        fn assert_no_effect(&self, leases: &[&str]) {
            assert!(self.log().is_empty(), "systemctl ran: {:?}", self.log());
            assert!(!self.runtime.join(INSTANCE_DIRECTORY).exists());
            assert_eq!(self.leases(), leases);
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            drop(self.instance.take().map(|instance| instance.join()));
            let removed = fs::remove_dir_all(&self.root);
            if !thread::panicking() {
                removed.expect("remove only this test's fixture");
            }
        }
    }

    fn admitted<'a>(result: Result<Box<dyn Running + 'a>, ErrorCode>) -> Box<dyn Running + 'a> {
        match result {
            Ok(session) => session,
            Err(code) => panic!("admission refused: {code:?}"),
        }
    }

    fn refused(result: Result<Box<dyn Running + '_>, ErrorCode>) -> ErrorCode {
        match result {
            Err(code) => code,
            Ok(session) => panic!("admitted in state {:?}", session.state()),
        }
    }

    fn admit_and_stop(name: &str, backend: Backend, kind: &str) {
        if !namespaced(name) {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(backend);
        let launcher = harness.launcher(false);
        let mut running = admitted(launcher.launch(backend));
        assert_eq!(running.state(), State::Starting);

        let unit = started_unit(&harness.log).unwrap();
        let generation = generation_of(&unit);
        assert_eq!(unit, format!("vpnt-tunneld-{kind}@{generation}.service"));
        assert_eq!(generation.len(), 32);
        assert_eq!(harness.log(), [format!("start --no-block -- {unit}")]);
        assert_eq!(harness.leases(), [generation.as_str()]);
        let directory = harness.directory(&generation);
        assert!(directory.join(&generation).is_file(), "handshake record");
        assert!(
            !directory.join(CONTROL_SOCKET).exists(),
            "listener consumed"
        );

        assert_eq!(running.stop(), State::Stopped);
        assert_eq!(running.state(), State::Stopped);
        assert_eq!(
            harness.log(),
            [
                format!("start --no-block -- {unit}"),
                format!("stop -- {unit}")
            ]
        );
        assert!(!directory.exists());
        assert!(harness.leases().is_empty());
        // A repeated stop does not repeat the mutation.
        assert_eq!(running.stop(), State::Stopped);
        assert_eq!(harness.log().len(), 2);
    }

    #[test]
    fn admits_an_ipsec_instance_and_stops_it() {
        admit_and_stop(
            "admits_an_ipsec_instance_and_stops_it",
            Backend::Ipsec,
            "ipsec",
        );
    }

    #[test]
    fn admits_a_fortinet_instance_under_its_own_unit() {
        admit_and_stop(
            "admits_a_fortinet_instance_under_its_own_unit",
            Backend::Fortinet,
            "fortinet",
        );
    }

    #[test]
    fn dropping_a_running_session_stops_it() {
        if !namespaced("dropping_a_running_session_stops_it") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        let running = admitted(launcher.launch(Backend::Ipsec));
        let unit = started_unit(&harness.log).unwrap();
        drop(running);
        assert_eq!(harness.log().last().unwrap(), &format!("stop -- {unit}"));
        assert!(harness.leases().is_empty());
        assert!(!harness.directory(&generation_of(&unit)).exists());
    }

    #[test]
    fn ovpn_present_refuses_without_effect() {
        if !namespaced("ovpn_present_refuses_without_effect") {
            return;
        }
        let harness = Harness::new();
        let network = FakeNetwork::default();
        network.ovpn.store(true, Ordering::SeqCst);
        let inventories = network.inventories.clone();
        let launcher = harness.launcher_with(network, false, harness.lock(), Limits::default());
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
        assert_eq!(inventories.load(Ordering::SeqCst), 1);
        harness.assert_no_effect(&[]);
    }

    #[test]
    fn a_present_lease_refuses_without_effect() {
        if !namespaced("a_present_lease_refuses_without_effect") {
            return;
        }
        let harness = Harness::new();
        NetworkLock::acquire_test(&harness.runtime, Instant::now() + Duration::from_secs(2))
            .unwrap()
            .register("other-tunnel")
            .unwrap();
        let launcher = harness.launcher(false);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
        harness.assert_no_effect(&["other-tunnel"]);
    }

    #[test]
    fn a_contended_lock_refuses_without_effect() {
        if !namespaced("a_contended_lock_refuses_without_effect") {
            return;
        }
        let harness = Harness::new();
        let held =
            NetworkLock::acquire_test(&harness.runtime, Instant::now() + Duration::from_secs(2))
                .unwrap();
        let limits = Limits {
            lock: Duration::from_millis(100),
            ..Limits::default()
        };
        let network = FakeNetwork::default();
        let inventories = network.inventories.clone();
        let launcher = harness.launcher_with(network, false, harness.lock(), limits);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
        // The inventory is read only under the lock.
        assert_eq!(inventories.load(Ordering::SeqCst), 0);
        harness.assert_no_effect(&[]);
        drop(held);
    }

    #[test]
    fn checks_and_registration_share_one_lock_acquisition() {
        if !namespaced("checks_and_registration_share_one_lock_acquisition") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let armed = Arc::new(AtomicBool::new(true));
        let lock: AcquireLock = {
            let (runtime, acquisitions, armed) =
                (harness.runtime.clone(), acquisitions.clone(), armed.clone());
            Box::new(move |deadline| {
                // A second acquisition by the same admission opens a window
                // between its checks and its registration: a competing
                // admission fits in it, passes its own checks and registers.
                if acquisitions.fetch_add(1, Ordering::SeqCst) >= 1 && armed.load(Ordering::SeqCst)
                {
                    let guard = NetworkLock::acquire_test(&runtime, deadline)?;
                    if !guard.tunnels_present()? {
                        guard.register("competitor")?;
                    }
                }
                NetworkLock::acquire_test(&runtime, deadline)
            })
        };
        let launcher =
            harness.launcher_with(FakeNetwork::default(), false, lock, Limits::default());
        let mut running = admitted(launcher.launch(Backend::Ipsec));
        let generation = generation_of(&started_unit(&harness.log).unwrap());
        assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
        assert_eq!(harness.leases(), [generation.as_str()]);
        armed.store(false, Ordering::SeqCst);
        assert_eq!(running.stop(), State::Stopped);
    }

    #[test]
    fn systemctl_start_failure_cleans_up() {
        if !namespaced("systemctl_start_failure_cleans_up") {
            return;
        }
        let mut harness = Harness::new();
        harness.flag("fail-start", true);
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Backend);
        let unit = started_unit(&harness.log).unwrap();
        assert_eq!(
            harness.log(),
            [
                format!("start --no-block -- {unit}"),
                format!("stop -- {unit}")
            ]
        );
        assert!(!harness.directory(&generation_of(&unit)).exists());
        assert!(harness.leases().is_empty());
    }

    #[test]
    fn attestation_failure_cleans_up() {
        if !namespaced("attestation_failure_cleans_up") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(true);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Backend);
        let unit = started_unit(&harness.log).unwrap();
        assert_eq!(harness.log().last().unwrap(), &format!("stop -- {unit}"));
        assert!(!harness.directory(&generation_of(&unit)).exists());
        assert!(harness.leases().is_empty());
    }

    #[test]
    fn unproven_unit_stop_keeps_the_lease_and_a_retry_converges() {
        if !namespaced("unproven_unit_stop_keeps_the_lease_and_a_retry_converges") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        let mut running = admitted(launcher.launch(Backend::Ipsec));
        let unit = started_unit(&harness.log).unwrap();
        let generation = generation_of(&unit);

        harness.flag("fail-stop", true);
        assert_eq!(running.stop(), State::CleanupPending);
        // The instance may still run, so its directory and lease stay.
        assert!(harness.directory(&generation).exists());
        assert_eq!(harness.leases(), [generation.as_str()]);
        assert_eq!(running.state(), State::CleanupPending);

        harness.flag("fail-stop", false);
        assert_eq!(running.stop(), State::Stopped);
        assert!(!harness.directory(&generation).exists());
        assert!(harness.leases().is_empty());
    }

    #[test]
    fn failed_admission_with_unproven_stop_reports_cleanup_pending_and_blocks_the_next() {
        if !namespaced(
            "failed_admission_with_unproven_stop_reports_cleanup_pending_and_blocks_the_next",
        ) {
            return;
        }
        let harness = Harness::new();
        harness.flag("fail-start", true);
        harness.flag("fail-stop", true);
        let launcher = harness.launcher(false);
        assert_eq!(
            refused(launcher.launch(Backend::Ipsec)),
            ErrorCode::CleanupPending
        );
        let generation = generation_of(&started_unit(&harness.log).unwrap());
        assert_eq!(harness.leases(), [generation.as_str()]);
        assert_eq!(refused(launcher.launch(Backend::Ipsec)), ErrorCode::Busy);
    }

    #[test]
    fn failed_directory_removal_reports_cleanup_pending_and_a_retry_converges() {
        if !namespaced("failed_directory_removal_reports_cleanup_pending_and_a_retry_converges") {
            return;
        }
        let mut harness = Harness::new();
        harness.instance(Backend::Ipsec);
        let launcher = harness.launcher(false);
        let mut running = admitted(launcher.launch(Backend::Ipsec));
        let generation = generation_of(&started_unit(&harness.log).unwrap());
        let directory = harness.directory(&generation);

        // A mount point cannot be removed (EBUSY): a real removal failure.
        let (source, target) = (harness.root.join("pin-source"), directory.join("pin"));
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        let cpath = |path: &Path| std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: both paths are NUL-terminated and the other arguments are null.
        let mounted = unsafe {
            libc::mount(
                cpath(&source).as_ptr(),
                cpath(&target).as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if mounted != 0 {
            let error = io::Error::last_os_error();
            assert!(
                std::env::var_os("VPNT_REQUIRE_USERNS").is_none(),
                "bind mounts are required here: {error}"
            );
            eprintln!("skipped: bind mounts are unavailable here: {error}");
            assert_eq!(running.stop(), State::Stopped);
            return;
        }

        assert_eq!(running.stop(), State::CleanupPending);
        assert!(directory.exists());
        // The unit stop was proven, so the network reservation is released.
        assert!(harness.leases().is_empty());

        // SAFETY: target is a NUL-terminated mount point created above.
        assert_eq!(unsafe { libc::umount2(cpath(&target).as_ptr(), 0) }, 0);
        assert_eq!(running.stop(), State::Stopped);
        assert!(!directory.exists());
    }

    #[test]
    fn generations_are_32_lowercase_hex_and_new_each_time() {
        let first = generation().unwrap();
        let second = generation().unwrap();
        assert_eq!(first.len(), 32);
        assert!(
            first
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        );
        assert_ne!(first, second);
    }

    #[test]
    fn systemctl_runs_with_a_clean_environment_and_a_deadline() {
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let removed = fs::remove_dir_all(&self.0);
                if !thread::panicking() {
                    removed.expect("remove only this test's fixture");
                }
            }
        }
        let root = std::env::temp_dir().join(format!("vs-{}", &generation().unwrap()[..8]));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let root = Root(root);
        let script = |name: &str, body: &str| {
            let path = root.0.join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        };
        let env = script("env", "[ -z \"$HOME$USER$LANG$TMPDIR\" ]");
        let slow = script("slow", "exec /bin/sleep 5");
        let failing = script("fail", "exit 3");
        // A fork in a sibling test can hold a script's write descriptor for an
        // instant, which makes its exec fail with ETXTBSY. Only the fixture retries.
        let run = |path: &Path, timeout: Duration| loop {
            match run_systemctl(path, &[], timeout) {
                Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                    thread::sleep(Duration::from_millis(10));
                }
                result => break result,
            }
        };
        run(&env, Duration::from_secs(5)).unwrap();
        // Control: the script does detect an inherited environment.
        if std::env::var_os("HOME").is_some() {
            let inherited = loop {
                match Command::new(&env).status() {
                    Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {}
                    status => break status.unwrap(),
                }
            };
            assert!(!inherited.success());
        }
        assert!(run(&failing, Duration::from_secs(5)).is_err());
        let started = Instant::now();
        let error = run(&slow, Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
