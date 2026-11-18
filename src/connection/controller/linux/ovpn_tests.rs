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
