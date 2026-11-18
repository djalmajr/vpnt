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
    closes: usize,
    stops: usize,
    close_error: Option<NetFailure>,
    configure_error: Option<NetFailure>,
}
struct FakeNetwork(Arc<Mutex<Observed>>);
impl Network for FakeNetwork {
    fn open_tun(&mut self) -> Result<String, NetFailure> {
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
        s.close_error.take().map_or(Ok(()), Err)
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
    serde_json::from_value(serde_json::json!({"id":"fixture", "name":"fixture", "kind":"ovpn", "gateway":"vpn.example.test", "username":"", "networks":[], "port":443, "certificate":"", "probeHost":"127.0.0.1", "probePort":1234, "probeMethod":"tcp", "ovpn":{"certificateId":"01", "module":"/fixture.so"}})).unwrap()
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
) -> (OvpnAttempt<FakeNetwork, FakeTunnel>, Arc<Mutex<Observed>>) {
    let state = Arc::new(Mutex::new(Observed::default()));
    let a = OvpnAttempt::fixture(
        p,
        FakeNetwork(state.clone()),
        FakeTunnel {
            state: state.clone(),
            events: events.into(),
            exit,
        },
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
    fs::write(&path, b"fixture").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!profile_file_ok(&path, unsafe { libc::geteuid() }));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(profile_file_ok(&path, unsafe { libc::geteuid() }));
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
            config: "/dev/null".into(),
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
