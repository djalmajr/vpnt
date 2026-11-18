struct NoStart;
impl<N, T> super::Starter<N, T> for NoStart {
    type Key = ();
    fn connect(&mut self) -> Result<N, super::Failure> {
        Err(super::Failure::at(super::Step::Runtime))
    }
    fn token(&mut self, _: &crate::model::OvpnSettings, _: &[u8]) -> Result<(), super::Failure> {
        Ok(())
    }
    fn session(
        &mut self,
        _: super::ConfigSource,
        _: &crate::model::OvpnSettings,
        _: String,
        _: (),
    ) -> Result<T, super::Failure> {
        Err(super::Failure::at(super::Step::Spawn))
    }
}
fn valid_profile() -> &'static str {
    "client\nremote vpn.example.test 1194\n<ca>\nfixture\n</ca>\n"
}
use super::*;
use std::{
    collections::VecDeque,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Observed {
    configs: Vec<Config>,
    opened: std::collections::BTreeSet<String>,
    events: Vec<&'static str>,
    open_error: Option<NetFailure>,
    closes: usize,
    stops: usize,
    close_error: Option<NetFailure>,
    configure_error: Option<NetFailure>,
}
struct FakeNetwork(Arc<Mutex<Observed>>);
impl Network for FakeNetwork {
    fn open_tun(&mut self) -> Result<String, NetFailure> {
        let mut s = self.0.lock().unwrap();
        s.events.push("open");
        if let Some(error) = s.open_error.take() {
            return Err(error);
        }
        assert!(s.opened.insert("vpnt0".into()));
        Ok("vpnt0".into())
    }
    fn configure(&mut self, c: &Config) -> Result<(), NetFailure> {
        let mut s = self.0.lock().unwrap();
        s.configs.push(c.clone());
        s.configure_error.take().map_or(Ok(()), Err)
    }
    fn close_tun(&mut self, _: &str) -> Result<(), NetFailure> {
        let mut s = self.0.lock().unwrap();
        s.closes += 1;
        s.events.push("close");
        if let Some(error) = s.close_error.take() {
            return Err(error);
        }
        s.opened.remove("vpnt0");
        Ok(())
    }
}
struct FakeTunnel {
    state: Arc<Mutex<Observed>>,
    events: VecDeque<Progress>,
    exit: Option<Option<Reason>>,
}
impl Tunnel for FakeTunnel {
    fn next(&mut self) -> Option<Progress> {
        self.events.pop_front()
    }
    fn exited(&self) -> Option<Option<Reason>> {
        self.exit
    }
    fn stop(&mut self) {
        self.state.lock().unwrap().stops += 1;
    }
    fn wait(&mut self, _: Duration) -> bool {
        true
    }
}
fn profile() -> Profile {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let id = format!("fixture-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    serde_json::from_value(serde_json::json!({"id":id, "name":"fixture", "kind":"ovpn", "gateway":"vpn.example.test", "username":"", "networks":[], "port":443, "certificate":"", "probeHost":"127.0.0.1", "probePort":1234, "probeMethod":"tcp", "ovpn":{"certificateId":"01", "module":"/fixture.so"}})).unwrap()
}
fn network() -> NetworkConfig {
    NetworkConfig {
        address: "10.1.2.3".parse().unwrap(),
        prefix: 24,
        mtu: None,
        routes: vec![],
        dns_servers: vec![],
        dns_domains: vec!["pushed.test".into()],
        server: None,
    }
}
fn attempt(
    p: Profile,
    events: Vec<Progress>,
    exit: Option<Option<Reason>>,
) -> (
    OvpnAttempt<FakeNetwork, FakeTunnel, NoStart>,
    Arc<Mutex<Observed>>,
) {
    let state = Arc::new(Mutex::new(Observed::default()));
    state.lock().unwrap().opened.insert("vpnt0".into());
    let a = OvpnAttempt::fixture(
        p,
        FakeNetwork(state.clone()),
        FakeTunnel {
            state: state.clone(),
            events: events.into(),
            exit,
        },
        NoStart,
    );
    (a, state)
}
#[test]
fn approval_domains_reconfigure_and_cleanup_retry() {
    let mut p = profile();
    p.dns_domains = vec!["profile.test".into()];
    let (mut a, state) = attempt(p, vec![Progress::AwaitingApproval], None);
    assert!(!a.ready().unwrap());
    assert_eq!(a.phase(), Some(ConnectionState::AwaitingApproval));
    a.tunnel
        .as_mut()
        .unwrap()
        .events
        .push_back(Progress::Up(network()));
    assert!(a.ready().unwrap());
    assert_eq!(a.phase(), None);
    {
        let s = state.lock().unwrap();
        assert_eq!(s.configs.len(), 1);
        assert_eq!(s.configs[0].dns.domains, ["profile.test"]);
        assert_eq!(s.configs[0].mtu, 1500);
    }
    let tunnel = a.tunnel.as_mut().unwrap();
    tunnel.events.push_back(Progress::Down);
    tunnel.events.push_back(Progress::Up(network()));
    a.healthy().unwrap();
    assert_eq!(state.lock().unwrap().configs.len(), 2);
    state.lock().unwrap().close_error = Some(NetFailure::Backend);
    assert!(!a.cleanup());
    assert!(a.cleanup());
    let s = state.lock().unwrap();
    assert_eq!(s.closes, 2);
    assert_eq!(s.stops, 1);
}
#[test]
fn pushed_domains_and_transport_loss() {
    let (mut a, state) = attempt(profile(), vec![Progress::Up(network())], None);
    assert!(a.ready().unwrap());
    assert_eq!(
        state.lock().unwrap().configs[0].dns.domains,
        ["pushed.test"]
    );
    state.lock().unwrap().close_error = Some(NetFailure::Transport);
    assert!(a.cleanup());
    assert_eq!(state.lock().unwrap().closes, 1);
}
#[test]
fn refusal_and_early_exit_are_classified() {
    let (mut a, _) = attempt(
        profile(),
        vec![Progress::Refused(SignError::Canceled)],
        None,
    );
    assert_eq!(
        a.ready().unwrap_err().state,
        ConnectionState::CredentialsRejected
    );
    let (mut a, _) = attempt(profile(), vec![], Some(None));
    assert_eq!(a.ready().unwrap_err().step, Step::Tunnel);
    let (mut a, _) = attempt(profile(), vec![], Some(Some(Reason::AuthFailure)));
    assert_eq!(
        a.ready().unwrap_err().state,
        ConnectionState::CredentialsRejected
    );
}
#[test]
fn route_conflict_is_reported_at_routes() {
    let (mut a, state) = attempt(profile(), vec![Progress::Up(network())], None);
    state.lock().unwrap().configure_error = Some(NetFailure::RouteConflict);
    assert_eq!(a.ready().unwrap_err().step, Step::Routes);
    assert!(a.cleanup());
}
#[test]
fn profile_mode_and_probe() {
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let directory = std::env::temp_dir().join(format!("vpnt-ovpn-mode-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let _guard = Fixture(directory.clone());
    let path = directory.join("profile.ovpn");
    fs::write(&path, valid_profile()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_profile(&path, unsafe { libc::geteuid() }).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(read_profile(&path, unsafe { libc::geteuid() }).is_ok());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut p = profile();
    p.probe_port = listener.local_addr().unwrap().port();
    let (mut a, _) = attempt(p, vec![], None);
    assert!(
        a.probe(&AtomicBool::new(false), Duration::from_secs(1))
            .unwrap()
    );
}

#[test]
fn real_session_exit_waits_for_auth_failure_on_fifty_attempts() {
    use crate::connection::ovpn::{session::Signer, signing::Padding};
    use base64::{Engine, engine::general_purpose::STANDARD};
    struct DelayedSigner;
    impl Signer for DelayedSigner {
        fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
            Ok(vec![1])
        }
        fn sign(&mut self, _: Padding, _: &[u8]) -> Result<Vec<u8>, SignError> {
            thread::sleep(Duration::from_millis(40));
            Ok(vec![1])
        }
    }
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let dir = std::env::temp_dir().join(format!("vpnt-ovpn-auth-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let _fixture = Fixture(dir.clone());
    let program = dir.join("fake-openvpn");
    let lines = format!(
        ">PK_SIGN:{},RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest\n>STATE:2,EXITING,auth-failure,,,,,\n",
        STANDARD.encode([5u8; 32])
    );
    let script = format!(
        "#!/usr/bin/python3\nimport socket,sys\nif '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\ns=socket.socket(socket.AF_UNIX)\ns.connect(sys.argv[sys.argv.index('--management')+1])\ns.sendall({lines:?}.encode())\n"
    );
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    for round in 0..50 {
        let launch = Launch {
            openvpn: program.clone(),
            config: ConfigSource::from("/dev/null"),
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        };
        let session = Session::start(launch, DelayedSigner).unwrap();
        let state = Arc::new(Mutex::new(Observed::default()));
        let mut attempt = OvpnAttempt::fixture(
            profile(),
            FakeNetwork(state),
            RealTunnel {
                session: Some(session),
                waiting: None,
                wait_failed: false,
            },
            NoStart,
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        let failure = loop {
            match attempt.ready() {
                Err(e) => break Some(e),
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                _ => break None,
            }
        };
        let cleaned = attempt.cleanup();
        assert!(cleaned, "cleanup failed in round {round}");
        assert_eq!(
            failure.expect("no exit").state,
            ConnectionState::CredentialsRejected,
            "round {round}"
        );
    }
}

#[test]
fn probe_deadline_cancellation_and_single_inflight_job() {
    use std::sync::{Condvar, atomic::AtomicUsize};
    struct Guard {
        gate: Arc<(Mutex<bool>, Condvar)>,
        worker: Option<thread::JoinHandle<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let (lock, cv) = &*self.gate;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
    for cancel_while_waiting in [false, true] {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (mut attempt, _) = attempt(profile(), vec![], None);
        let inner_gate = gate.clone();
        let inner_calls = calls.clone();
        attempt.probe_job = Arc::new(move |_, _, _| {
            inner_calls.fetch_add(1, Ordering::SeqCst);
            let _ = started_tx.send(());
            let (lock, cv) = &*inner_gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
            let _ = finished_tx.send(());
            true
        });
        let canceled = Arc::new(AtomicBool::new(false));
        let worker_canceled = canceled.clone();
        let (answer_tx, answer_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let deadline = if cancel_while_waiting {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(100)
            };
            let first = attempt.probe(&worker_canceled, deadline).unwrap();
            worker_canceled.store(false, Ordering::Release);
            let second = attempt
                .probe(&worker_canceled, Duration::from_millis(100))
                .unwrap();
            let _ = answer_tx.send((first, second));
        });
        let mut guard = Guard {
            gate: gate.clone(),
            worker: Some(worker),
        };
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        if cancel_while_waiting {
            canceled.store(true, Ordering::Release);
        }
        let answer = answer_rx.recv_timeout(Duration::from_millis(600));
        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        guard.worker.take().unwrap().join().unwrap();
        finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            answer.expect("probe failed to respect deadline or cancellation"),
            (false, false)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "only one job may be in flight"
        );
    }
}

#[test]
fn probe_slot_survives_three_retired_generations() {
    use std::sync::{Condvar, atomic::AtomicUsize};
    struct Guard {
        gate: Arc<(Mutex<bool>, Condvar)>,
        workers: Vec<thread::JoinHandle<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let (lock, cv) = &*self.gate;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
            for worker in self.workers.drain(..) {
                worker.join().unwrap();
            }
        }
    }
    let p = profile();
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let mut guard = Guard {
        gate: gate.clone(),
        workers: vec![],
    };
    for _ in 0..3 {
        let (mut a, _) = attempt(p.clone(), vec![], None);
        let gate = gate.clone();
        let calls = calls.clone();
        a.probe_job = Arc::new(move |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            let (lock, cv) = &*gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
            true
        });
        assert!(
            !a.probe(&AtomicBool::new(false), Duration::from_millis(50))
                .unwrap()
        );
        assert!(a.cleanup());
        if let Some((_, worker)) = a.probe_inflight.take() {
            guard.workers.push(worker);
        }
        drop(a);
    }
    let observed = calls.load(Ordering::SeqCst);
    drop(guard);
    assert_eq!(
        observed, 1,
        "retired attempts must not release a live probe slot"
    );
    let (mut next, _) = attempt(p, vec![], None);
    next.probe_job = Arc::new(|_, _, _| true);
    assert!(
        next.probe(&AtomicBool::new(false), Duration::from_secs(1))
            .unwrap()
    );
    if let Some((_, worker)) = next.probe_inflight.take() {
        worker.join().unwrap();
    }
}

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vpnt-start-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn profile(&self, text: &[u8]) -> std::path::PathBuf {
        let path = self.0.join("profile.ovpn");
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone, Copy)]
enum FailStart {
    Connect,
    Open,
    Token,
    Session,
}
struct FakeStart {
    state: Arc<Mutex<Observed>>,
    fail: FailStart,
}
impl Starter<FakeNetwork, FakeTunnel> for FakeStart {
    type Key = ();
    fn connect(&mut self) -> Result<FakeNetwork, Failure> {
        let mut s = self.state.lock().unwrap();
        s.events.push("connect");
        if matches!(self.fail, FailStart::Connect) {
            return Err(state_failure(
                ConnectionState::HelperMissing,
                ErrorCode::Unavailable,
                Step::Runtime,
            ));
        }
        if matches!(self.fail, FailStart::Open) {
            s.open_error = Some(NetFailure::Backend);
        }
        Ok(FakeNetwork(self.state.clone()))
    }
    fn token(&mut self, _: &OvpnSettings, _: &[u8]) -> Result<(), Failure> {
        self.state.lock().unwrap().events.push("token");
        if matches!(self.fail, FailStart::Token) {
            return Err(Failure::at(Step::Profile));
        }
        Ok(())
    }
    fn session(
        &mut self,
        _: ConfigSource,
        _: &OvpnSettings,
        _: String,
        _: (),
    ) -> Result<FakeTunnel, Failure> {
        self.state.lock().unwrap().events.push("session");
        Err(Failure::at(Step::Spawn))
    }
}
#[test]
fn partial_start_failure_releases_every_acquired_tun() {
    let scratch = Scratch::new();
    let path = scratch.profile(valid_profile().as_bytes());
    for fail in [
        FailStart::Connect,
        FailStart::Open,
        FailStart::Token,
        FailStart::Session,
    ] {
        let state = Arc::new(Mutex::new(Observed::default()));
        let mut a = OvpnAttempt::with_start(
            profile(),
            unsafe { libc::geteuid() },
            Some(path.clone()),
            FakeStart {
                state: state.clone(),
                fail,
            },
        );
        let failure = a
            .start(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap_err();
        let (step, expected) = match fail {
            FailStart::Connect => {
                assert_eq!(failure.state, ConnectionState::HelperMissing);
                (Step::Runtime, vec!["connect"])
            }
            FailStart::Open => (Step::Tunnel, vec!["connect", "open"]),
            FailStart::Token => (Step::Profile, vec!["connect", "open", "token", "close"]),
            FailStart::Session => (
                Step::Spawn,
                vec!["connect", "open", "token", "session", "close"],
            ),
        };
        assert_eq!(failure.step, step);
        assert!(a.cleanup());
        assert!(a.cleanup());
        let state = state.lock().unwrap();
        assert!(state.opened.is_empty());
        assert_eq!(state.stops, 0);
        assert_eq!(state.events, expected);
    }
}
#[test]
fn start_revalidates_the_profile_before_any_external_effect() {
    let scratch = Scratch::new();
    for text in [
        b"script-security 2\nup /bad\n".to_vec(),
        vec![b'x'; 256 * 1024 + 1],
        b"remote vpn.example.test\0\n".to_vec(),
    ] {
        let path = scratch.profile(&text);
        let state = Arc::new(Mutex::new(Observed::default()));
        let mut a = OvpnAttempt::with_start(
            profile(),
            unsafe { libc::geteuid() },
            Some(path),
            FakeStart {
                state: state.clone(),
                fail: FailStart::Connect,
            },
        );
        assert_eq!(
            a.start(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap_err()
            .step,
            Step::Profile
        );
        assert!(a.cleanup());
        assert!(state.lock().unwrap().events.is_empty());
    }
    let path = scratch.profile(valid_profile().as_bytes());
    assert!(read_profile(&path, unsafe { libc::geteuid() } + 1).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_profile(&path, unsafe { libc::geteuid() }).is_err());
    let link = scratch.0.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read_profile(&link, unsafe { libc::geteuid() }).is_err());
    assert!(read_profile(&scratch.0, unsafe { libc::geteuid() }).is_err());
    let fifo = scratch.0.join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(read_profile(&fifo, unsafe { libc::geteuid() }).is_err());
}
#[test]
fn sealed_profile_survives_rename_and_link_after_session_start() {
    use crate::connection::ovpn::session::Signer;
    use crate::connection::ovpn::signing::Padding;
    struct NoSigner;
    impl Signer for NoSigner {
        fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
            Err(SignError::Unavailable)
        }
        fn sign(&mut self, _: Padding, _: &[u8]) -> Result<Vec<u8>, SignError> {
            Err(SignError::Unavailable)
        }
    }
    let scratch = Scratch::new();
    let original = valid_profile().replace('\n', "\r\n");
    let path = scratch.profile(original.as_bytes());
    let config = read_profile(&path, unsafe { libc::geteuid() }).unwrap();
    let program = scratch.0.join("openvpn");
    let release = scratch.0.join("release");
    let observed = scratch.0.join("observed");
    let script = format!(
        "#!/usr/bin/python3\nimport socket,sys,time,pathlib\nif '--version' in sys.argv: print('OpenVPN 2.6.19');sys.exit(0)\ns=socket.socket(socket.AF_UNIX);s.connect(sys.argv[sys.argv.index('--management')+1])\nend=time.monotonic()+5\nwhile not pathlib.Path({release:?}).exists() and time.monotonic()<end: time.sleep(.005)\nc=sys.argv[sys.argv.index('--config')+1]\npathlib.Path({observed:?}).write_text(c+'\\n'+pathlib.Path(c).read_text())\n"
    );
    fs::write(&program, script).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let session = Session::start(
        Launch {
            openvpn: program,
            config,
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        },
        NoSigner,
    )
    .unwrap();
    fs::rename(&path, scratch.0.join("original")).unwrap();
    let alternate = scratch.0.join("alternate");
    fs::write(&alternate, b"replacement").unwrap();
    std::os::unix::fs::symlink(&alternate, &path).unwrap();
    fs::write(release, b"go").unwrap();
    session.wait().unwrap();
    assert_eq!(
        fs::read_to_string(observed).unwrap(),
        format!("/dev/fd/3\n{}", valid_profile())
    );
}

#[test]
fn dead_session_is_not_healthy_while_the_signer_is_blocked() {
    use crate::connection::ovpn::{session::Signer, signing::Padding};
    struct Blocking {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Signer for Blocking {
        fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
            Ok(vec![1])
        }
        fn sign(&mut self, _: Padding, _: &[u8]) -> Result<Vec<u8>, SignError> {
            let _ = self.entered.send(());
            let _ = self.release.recv_timeout(Duration::from_secs(5));
            Ok(vec![1])
        }
    }
    let scratch = Scratch::new();
    let program = scratch.0.join("openvpn");
    fs::write(&program,"#!/usr/bin/python3\nimport socket,sys\nif '--version' in sys.argv: print('OpenVPN 2.6.19');sys.exit(0)\ns=socket.socket(socket.AF_UNIX);s.connect(sys.argv[sys.argv.index('--management')+1])\ns.sendall(b'>PK_SIGN:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=,RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest\\n')\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let session = Session::start(
        Launch {
            openvpn: program,
            config: ConfigSource::from("/dev/null"),
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        },
        Blocking {
            entered,
            release: gate,
        },
    )
    .unwrap();
    let state = Arc::new(Mutex::new(Observed::default()));
    let mut a = OvpnAttempt::fixture(
        profile(),
        FakeNetwork(state),
        RealTunnel {
            session: Some(session),
            waiting: None,
            wait_failed: false,
        },
        NoStart,
    );
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    let began = Instant::now();
    let mut result = Ok(false);
    while began.elapsed() < Duration::from_millis(1500) {
        result = a.ready();
        if result.is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let elapsed = began.elapsed();
    let health_began = Instant::now();
    let health = a.healthy();
    let health_elapsed = health_began.elapsed();
    let _ = release.send(());
    assert!(a.cleanup());
    assert_eq!(result.unwrap_err().step, Step::Tunnel);
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    assert_eq!(health.unwrap_err().step, Step::Health);
    assert!(
        health_elapsed < Duration::from_millis(100),
        "{health_elapsed:?}"
    );
}

#[test]
fn sealed_profile_rejects_writes_and_resizing() {
    let scratch = Scratch::new();
    let path = scratch.profile(valid_profile().as_bytes());
    let config = read_profile(&path, unsafe { libc::geteuid() }).unwrap();
    let ConfigSource::Sealed(fd) = &config else {
        panic!("profile is not sealed");
    };
    use std::io::Write;
    let mut attempt_write = std::fs::File::from(fd.try_clone().unwrap());
    assert!(attempt_write.write_all(b"change").is_err());
    assert!(attempt_write.set_len(1).is_err());
    assert!(attempt_write.set_len(1024 * 1024).is_err());
}
