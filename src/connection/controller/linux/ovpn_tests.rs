struct NoStart;
impl<N, T> super::Starter<N, T> for NoStart {
    type Key = ();
    fn connect(&mut self) -> Result<N, super::Failure> {
        Err(super::Failure::at(super::Step::Runtime))
    }
    fn token(
        &mut self,
        _: &crate::model::OvpnSettings,
        _: &[u8],
        _: &AtomicBool,
        _: Instant,
    ) -> Result<(), super::Failure> {
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
use crate::connection::controller::{ProbeClock, Timing, worker};
use crate::connection::ovpn::management::State;
use crate::netd::protocol::Configure;
use std::{
    collections::VecDeque,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex, atomic::AtomicUsize},
};

#[derive(Default)]
struct Observed {
    configs: Vec<Config>,
    applied: Option<Config>,
    opened: std::collections::BTreeSet<String>,
    events: Vec<&'static str>,
    open_error: Option<NetFailure>,
    closes: usize,
    stops: usize,
    close_error: Option<NetFailure>,
    configure_error: Option<NetFailure>,
    before_configure: Option<Box<dyn FnOnce() + Send>>,
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
        let before = self.0.lock().unwrap().before_configure.take();
        if let Some(before) = before {
            before();
        }
        let mut s = self.0.lock().unwrap();
        s.configs.push(c.clone());
        if let Some(error) = s.configure_error.take() {
            return Err(error);
        }
        s.applied = Some(c.clone());
        Ok(())
    }
    fn close_tun(&mut self, _: &str) -> Result<(), NetFailure> {
        let mut s = self.0.lock().unwrap();
        s.closes += 1;
        s.events.push("close");
        if let Some(error) = s.close_error.take() {
            return Err(error);
        }
        s.opened.remove("vpnt0");
        s.applied = None;
        Ok(())
    }
}
struct FakeTunnel {
    state: Arc<Mutex<Observed>>,
    events: VecDeque<Progress>,
    exit: Option<Option<Reason>>,
    approval_pending: Option<bool>,
}
impl Tunnel for FakeTunnel {
    fn next(&mut self) -> Option<Progress> {
        self.events.pop_front()
    }
    fn exited(&self) -> Option<Option<Reason>> {
        self.exit
    }
    fn approval_pending(&self) -> Option<bool> {
        self.approval_pending
    }
    fn release_restart_hold(&self, _: u64) {}
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
            approval_pending: None,
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
fn connected_clears_approval_without_an_up_event() {
    let (mut a, observed) = attempt(profile(), vec![Progress::Up(network())], None);
    assert!(a.ready().unwrap());
    a.restart_epoch = u64::MAX;
    let tunnel = a.tunnel.as_mut().unwrap();
    tunnel.events.push_back(state_event(Phase::Reconnecting));
    tunnel.events.push_back(Progress::AwaitingApproval);
    a.healthy().unwrap();
    assert_eq!(a.phase(), Some(ConnectionState::AwaitingApproval));
    assert_eq!(a.restart_epoch(), 0);

    a.tunnel
        .as_mut()
        .unwrap()
        .events
        .push_back(Progress::State(State {
            phase: Phase::Connected,
            reason: None,
            tunnel_ipv4: Some(network().address),
        }));
    a.healthy().unwrap();
    assert_eq!(a.phase(), None);
    assert_eq!(a.restart_epoch(), 0);
    let observed = observed.lock().unwrap();
    assert_eq!(observed.configs.len(), 3);
    assert_eq!(observed.closes, 0);
}

fn pushed_network() -> NetworkConfig {
    NetworkConfig {
        mtu: Some(1420),
        routes: vec![crate::connection::ovpn::network::Route {
            network: "192.0.2.0".parse().unwrap(),
            prefix: 24,
        }],
        dns_servers: vec!["192.0.2.53".parse().unwrap()],
        ..network()
    }
}

type FixtureAttempt = OvpnAttempt<FakeNetwork, FakeTunnel, NoStart>;

fn configured_attempt() -> (FixtureAttempt, Arc<Mutex<Observed>>) {
    let (mut a, observed) = attempt(profile(), vec![Progress::Up(pushed_network())], None);
    assert!(a.ready().unwrap());
    (a, observed)
}

fn state_event(phase: Phase) -> Progress {
    let state = State {
        tunnel_ipv4: (phase == Phase::Connected).then_some(network().address),
        phase,
        reason: None,
    };
    if phase == Phase::Reconnecting {
        Progress::Restarting { state, epoch: 1 }
    } else {
        Progress::State(state)
    }
}

fn process_health(
    a: &mut FixtureAttempt,
    events: impl IntoIterator<Item = Progress>,
) -> Result<(), Failure> {
    a.tunnel.as_mut().unwrap().events.extend(events);
    a.healthy()
}

fn wire(config: &Config) -> Vec<u8> {
    serde_json::to_vec(&Configure::from(config)).unwrap()
}

#[test]
fn reconnect_withdraws_only_routes_and_dns() {
    let (mut a, observed) = configured_attempt();
    process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
    let s = observed.lock().unwrap();
    let [original, withdrawn] = s.configs.as_slice() else {
        panic!(
            "expected one withdrawal, saw {} configure calls",
            s.configs.len()
        );
    };
    assert!(!original.routes.is_empty());
    assert!(!original.dns.servers.is_empty());
    assert!(!original.dns.domains.is_empty());
    assert_eq!(withdrawn.name, original.name);
    assert_eq!(withdrawn.address, original.address);
    assert_eq!(withdrawn.prefix, original.prefix);
    assert_eq!(withdrawn.mtu, original.mtu);
    assert!(withdrawn.routes.is_empty());
    assert!(withdrawn.dns.servers.is_empty());
    assert!(withdrawn.dns.domains.is_empty());
    Configure::from(withdrawn).validate().unwrap();
    assert_eq!(wire(s.applied.as_ref().unwrap()), wire(withdrawn));
    assert!(s.opened.contains("vpnt0"));
    assert_eq!(s.closes, 0);
}

#[test]
fn connected_restores_the_original_config_without_up() {
    let (mut a, observed) = configured_attempt();
    process_health(&mut a, [state_event(Phase::Connected)]).unwrap();
    assert_eq!(observed.lock().unwrap().configs.len(), 1);
    process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
    process_health(&mut a, [state_event(Phase::Connected)]).unwrap();
    assert_eq!(a.phase(), None);
    process_health(&mut a, [state_event(Phase::Connected)]).unwrap();
    let s = observed.lock().unwrap();
    let [original, _, restored] = s.configs.as_slice() else {
        panic!(
            "expected a restored configuration, saw {} configure calls",
            s.configs.len()
        );
    };
    assert_eq!(wire(restored), wire(original));
    assert_eq!(wire(s.applied.as_ref().unwrap()), wire(original));
}

#[test]
fn new_up_replaces_withdrawn_config_before_connected() {
    let changed = NetworkConfig {
        address: "198.51.100.2".parse().unwrap(),
        prefix: 30,
        mtu: Some(1450),
        routes: vec![crate::connection::ovpn::network::Route {
            network: "203.0.113.0".parse().unwrap(),
            prefix: 24,
        }],
        dns_servers: vec!["203.0.113.53".parse().unwrap()],
        dns_domains: vec!["new.test".into()],
        ..pushed_network()
    };
    for emits_down in [true, false] {
        let (mut a, observed) = configured_attempt();
        process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
        if emits_down {
            process_health(&mut a, [Progress::Down]).unwrap();
        }
        process_health(&mut a, [Progress::Up(changed.clone())]).unwrap();
        assert_eq!(a.phase(), Some(ConnectionState::Reconnecting));
        let replacement = wire(observed.lock().unwrap().applied.as_ref().unwrap());
        process_health(&mut a, [state_event(Phase::Connected)]).unwrap();
        {
            let s = observed.lock().unwrap();
            let [original, _, applied] = s.configs.as_slice() else {
                panic!(
                    "expected only the new config after withdrawal, saw {} configure calls",
                    s.configs.len()
                );
            };
            assert_eq!(applied.name, original.name);
            assert_eq!(applied.address, changed.address);
            assert_eq!(applied.prefix, changed.prefix);
            assert_eq!(applied.mtu, changed.mtu.unwrap());
            assert_eq!(applied.routes.len(), 1);
            assert_eq!(applied.routes[0].network, changed.routes[0].network);
            assert_eq!(applied.routes[0].prefix, changed.routes[0].prefix);
            assert_eq!(applied.dns.servers, changed.dns_servers);
            assert_eq!(applied.dns.domains, changed.dns_domains);
            assert_eq!(wire(applied), replacement);
        }
        process_health(
            &mut a,
            [
                state_event(Phase::Reconnecting),
                state_event(Phase::Connected),
            ],
        )
        .unwrap();
        let s = observed.lock().unwrap();
        assert_eq!(s.configs.len(), 5);
        assert_eq!(wire(s.applied.as_ref().unwrap()), replacement);
    }
}

#[test]
fn repeated_reconnecting_withdraws_only_once() {
    let (mut a, observed) = configured_attempt();
    let epoch = a.restart_epoch();
    process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
    let started = a.reconnect_started;
    process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
    assert_eq!(a.reconnect_started, started);
    assert_eq!(a.restart_epoch(), epoch + 1);
    assert_eq!(observed.lock().unwrap().configs.len(), 2);
}

#[test]
fn failed_withdrawal_reports_routes_and_cleans_the_session() {
    let (mut a, observed) = configured_attempt();
    observed.lock().unwrap().configure_error = Some(NetFailure::Dns);
    let failure = process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap_err();
    assert_eq!(failure.step, Step::Routes);
    {
        let s = observed.lock().unwrap();
        assert_eq!(s.configs.len(), 2);
        assert_eq!(wire(s.applied.as_ref().unwrap()), wire(&s.configs[0]));
    }
    assert!(a.cleanup());
    assert_clean(&observed);
}

#[test]
fn failed_reapplication_keeps_the_routes_and_dns_error_mapping() {
    for (error, step) in [
        (NetFailure::RouteConflict, Step::Routes),
        (NetFailure::Dns, Step::Dns),
    ] {
        let (mut a, observed) = configured_attempt();
        process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
        observed.lock().unwrap().configure_error = Some(error);
        let failure = process_health(&mut a, [state_event(Phase::Connected)]).unwrap_err();
        assert_eq!(failure.step, step);
        assert_eq!(a.phase(), Some(ConnectionState::Reconnecting));
        {
            let s = observed.lock().unwrap();
            assert_eq!(s.configs.len(), 3);
            assert_eq!(wire(&s.configs[2]), wire(&s.configs[0]));
            assert_eq!(wire(s.applied.as_ref().unwrap()), wire(&s.configs[1]));
        }
        assert!(a.cleanup());
        assert_clean(&observed);
    }
}

#[test]
fn reconnect_expiry_and_unpaired_down_do_not_restore_routes() {
    let (mut a, observed) = configured_attempt();
    process_health(&mut a, [state_event(Phase::Reconnecting), Progress::Down]).unwrap();
    a.reconnect_started = Some(Instant::now() - RECONNECT_GRACE);
    a.healthy().unwrap();
    assert_eq!(a.phase(), None);
    {
        let s = observed.lock().unwrap();
        assert_eq!(s.configs.len(), 2);
        assert!(s.applied.as_ref().unwrap().routes.is_empty());
    }
    process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
    assert_eq!(observed.lock().unwrap().configs.len(), 2);
    process_health(&mut a, [Progress::Up(pushed_network())]).unwrap();
    process_health(&mut a, [state_event(Phase::Connected)]).unwrap();
    let s = observed.lock().unwrap();
    assert_eq!(s.configs.len(), 3);
    assert_eq!(wire(s.applied.as_ref().unwrap()), wire(&s.configs[0]));
}

fn assert_clean(observed: &Mutex<Observed>) {
    let s = observed.lock().unwrap();
    assert_eq!(s.stops, 1);
    assert_eq!(s.closes, 1);
    assert!(s.opened.is_empty());
    assert!(s.applied.is_none());
}

#[test]
fn interrupted_reconnect_cleans_the_withdrawn_network() {
    for child_exited in [false, true] {
        let (mut a, observed) = configured_attempt();
        process_health(&mut a, [state_event(Phase::Reconnecting)]).unwrap();
        assert!(
            observed
                .lock()
                .unwrap()
                .applied
                .as_ref()
                .unwrap()
                .routes
                .is_empty()
        );
        if child_exited {
            a.tunnel.as_mut().unwrap().exit = Some(None);
            assert_eq!(a.healthy().unwrap_err().step, Step::Health);
        }
        assert!(a.cleanup());
        assert_clean(&observed);
        assert_eq!(observed.lock().unwrap().configs.len(), 2);

        let (mut next, next_observed) = attempt(
            profile(),
            vec![
                state_event(Phase::Reconnecting),
                state_event(Phase::Connected),
            ],
            None,
        );
        next.healthy().unwrap();
        assert!(next_observed.lock().unwrap().configs.is_empty());
    }
}

enum RecoveryEvent {
    Progress(Progress),
    ApprovalPending(bool),
    CompleteRestart(mpsc::Sender<()>),
    Expire,
    ProbeSucceeds,
    SetProbeBusy(bool),
    BlockProbe {
        armed: mpsc::Sender<()>,
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    },
    ObserveNextHealth(mpsc::Sender<Option<worker::Progress>>),
}

struct RecoveryAttempt {
    attempt: OvpnAttempt<FakeNetwork, FakeTunnel, NoStart>,
    events: mpsc::Receiver<RecoveryEvent>,
    probes_pass: bool,
    real_probe: bool,
    busy: bool,
    last_probe_busy: bool,
    probes: Arc<AtomicUsize>,
    status: Arc<Mutex<Option<worker::Progress>>>,
    blocked_probe: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    observe_next_health: Option<mpsc::Sender<Option<worker::Progress>>>,
}

impl Attempt for RecoveryAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        self.attempt.ready()
    }
    fn phase(&self) -> Option<ConnectionState> {
        self.attempt.phase()
    }
    fn restart_epoch(&self) -> u64 {
        self.attempt.restart_epoch()
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        if let Some(observe) = self.observe_next_health.take() {
            let _ = observe.send(*self.status.lock().unwrap());
        }
        while let Ok(event) = self.events.try_recv() {
            match event {
                RecoveryEvent::Progress(progress) => {
                    self.attempt
                        .tunnel
                        .as_mut()
                        .unwrap()
                        .events
                        .push_back(progress);
                }
                RecoveryEvent::CompleteRestart(processed) => {
                    for phase in [Phase::Reconnecting, Phase::Connected] {
                        self.attempt
                            .tunnel
                            .as_mut()
                            .unwrap()
                            .events
                            .push_back(state_event(phase));
                    }
                    self.attempt.healthy()?;
                    processed.send(()).unwrap();
                }
                RecoveryEvent::ApprovalPending(pending) => {
                    self.attempt.tunnel.as_mut().unwrap().approval_pending = Some(pending);
                }
                RecoveryEvent::Expire => {
                    self.attempt.reconnect_started =
                        Some(Instant::now() - Duration::from_secs(120));
                }
                RecoveryEvent::ProbeSucceeds => self.probes_pass = true,
                RecoveryEvent::SetProbeBusy(busy) => self.busy = busy,
                RecoveryEvent::BlockProbe {
                    armed,
                    entered,
                    release,
                } => {
                    self.blocked_probe = Some((entered, release));
                    let _ = armed.send(());
                }
                RecoveryEvent::ObserveNextHealth(observe) => {
                    self.observe_next_health = Some(observe);
                }
            }
        }
        self.attempt.healthy()
    }
    fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
        self.probes.fetch_add(1, Ordering::Relaxed);
        if self.real_probe {
            let result = self.attempt.probe(canceled, timeout);
            self.last_probe_busy = self.attempt.probe_busy();
            return result;
        }
        if let Some((entered, release)) = self.blocked_probe.take() {
            let _ = entered.send(());
            let _ = release.recv_timeout(Duration::from_secs(3));
        }
        self.last_probe_busy = self.busy;
        if self.last_probe_busy {
            return Ok(false);
        }
        Ok(std::mem::take(&mut self.probes_pass))
    }
    fn probe_busy(&self) -> bool {
        self.last_probe_busy
    }
    fn cleanup(&mut self) -> bool {
        self.attempt.cleanup()
    }
}

struct RecoveryWorker {
    canceled: Arc<AtomicBool>,
    probe: Arc<AtomicBool>,
    status: Arc<Mutex<Option<worker::Progress>>>,
    probes: Arc<AtomicUsize>,
    events: mpsc::Sender<RecoveryEvent>,
    interval: ProbeClock,
    worker: Option<thread::JoinHandle<worker::Finished>>,
}

impl RecoveryWorker {
    fn start() -> Self {
        let (attempt, _) = attempt(profile(), vec![Progress::Up(network())], None);
        Self::with_attempt(attempt, false)
    }

    fn with_attempt(attempt: FixtureAttempt, real_probe: bool) -> Self {
        let (send, events) = mpsc::channel();
        let probes = Arc::new(AtomicUsize::new(0));
        let canceled = Arc::new(AtomicBool::new(false));
        let probe = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(None));
        let attempt = RecoveryAttempt {
            attempt,
            events,
            probes_pass: true,
            real_probe,
            busy: false,
            last_probe_busy: false,
            probes: probes.clone(),
            status: status.clone(),
            blocked_probe: None,
            observe_next_health: None,
        };
        let signals = worker::Signals {
            canceled: canceled.clone(),
            probe: probe.clone(),
            state: status.clone(),
            exit: Arc::new(worker::ExitRequested::new(Duration::from_secs(1))),
        };
        let timing = Timing {
            health: Duration::ZERO,
            poll: Duration::from_millis(1),
            ..Timing::default()
        };
        let interval = ProbeClock::new(Duration::from_secs(60));
        let worker_interval = interval.clone();
        let worker = thread::spawn(move || worker::run(attempt, signals, timing, worker_interval));
        let fixture = Self {
            canceled,
            probe,
            status,
            probes,
            events: send,
            interval,
            worker: Some(worker),
        };
        fixture.expect(ConnectionState::Connected, 0);
        fixture
    }

    fn phase(&self, phase: Phase) {
        self.events
            .send(RecoveryEvent::Progress(state_event(phase)))
            .unwrap();
    }

    fn probe(&self) {
        self.probe.store(true, Ordering::Release);
        self.wait(|| (!self.probe.load(Ordering::Acquire)).then_some(()));
    }

    fn arm_busy_probe(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (armed, ready) = mpsc::channel();
        let (entered, blocked) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        self.events.send(RecoveryEvent::SetProbeBusy(true)).unwrap();
        self.events
            .send(RecoveryEvent::BlockProbe {
                armed,
                entered,
                release: gate,
            })
            .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        (blocked, release)
    }

    fn after_probe(&self, release: mpsc::Sender<()>) -> Option<worker::Progress> {
        let (report, observed) = mpsc::channel();
        self.events
            .send(RecoveryEvent::ObserveNextHealth(report))
            .unwrap();
        release.send(()).unwrap();
        observed.recv_timeout(Duration::from_secs(2)).unwrap()
    }

    fn expect(&self, state: ConnectionState, failures: u32) {
        self.wait(|| {
            let status = *self.status.lock().unwrap();
            status.filter(|p| p.state == state && p.failures == failures)
        });
    }

    fn wait<T>(&self, predicate: impl Fn() -> Option<T>) -> T {
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(result) = predicate() {
                return result;
            }
            assert!(
                Instant::now() < until,
                "last worker status: {:?}",
                self.status.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for RecoveryWorker {
    fn drop(&mut self) {
        self.canceled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn soft_restart_suppresses_failed_probes_until_connected_again() {
    let worker = RecoveryWorker::start();
    worker.phase(Phase::Reconnecting);
    worker.expect(ConnectionState::Reconnecting, 0);
    worker
        .events
        .send(RecoveryEvent::ApprovalPending(true))
        .unwrap();
    worker.expect(ConnectionState::AwaitingApproval, 0);
    worker
        .events
        .send(RecoveryEvent::Progress(Progress::AwaitingApproval))
        .unwrap();
    for _ in 0..3 {
        worker.probe();
        worker.expect(ConnectionState::AwaitingApproval, 0);
    }
    worker
        .events
        .send(RecoveryEvent::ApprovalPending(false))
        .unwrap();
    worker.expect(ConnectionState::Reconnecting, 0);
    worker.events.send(RecoveryEvent::ProbeSucceeds).unwrap();
    worker.phase(Phase::Connected);
    worker.expect(ConnectionState::Connected, 0);
    assert_eq!(worker.probes.load(Ordering::Relaxed), 2);
    for failures in 1..=3 {
        worker.probe();
        worker.expect(ConnectionState::Unresponsive, failures);
    }
}

#[test]
fn soft_restart_discards_a_failed_probe_already_in_flight() {
    let worker = RecoveryWorker::start();
    let (armed, ready) = mpsc::channel();
    let (entered, blocked) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::BlockProbe {
            armed,
            entered,
            release: gate,
        })
        .unwrap();
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.probe();
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();

    worker.phase(Phase::Reconnecting);
    let (report, observed) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::ObserveNextHealth(report))
        .unwrap();
    release.send(()).unwrap();
    let status = observed
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    assert_eq!(
        (status.state, status.failures),
        (ConnectionState::Reconnecting, 0)
    );
}

#[test]
fn completed_restarts_discard_an_in_flight_probe_and_reset_the_failure_streak() {
    let worker = RecoveryWorker::start();
    for failures in 1..=2 {
        worker.probe();
        worker.expect(ConnectionState::Unresponsive, failures);
    }

    let (armed, ready) = mpsc::channel();
    let (entered, blocked) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::BlockProbe {
            armed,
            entered,
            release: gate,
        })
        .unwrap();
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.probe();
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();

    for _ in 0..2 {
        worker.phase(Phase::Reconnecting);
        worker.phase(Phase::Connected);
    }
    // The old probe is still in flight when the restart events are applied.
    // Its completion is stale and the forced retry cannot start yet.
    let (armed, ready) = mpsc::channel();
    let (entered, blocked) = mpsc::channel();
    let (resume, gate) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::SetProbeBusy(true))
        .unwrap();
    worker
        .events
        .send(RecoveryEvent::BlockProbe {
            armed,
            entered,
            release: gate,
        })
        .unwrap();
    let (report, observed) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::ObserveNextHealth(report))
        .unwrap();
    release.send(()).unwrap();
    let status = observed
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    // The failed pre-restart probe never publishes. The automatic retry is
    // the first failure of the restored tunnel, even with a 60 s cadence.
    assert_eq!(
        (status.state, status.failures),
        (ConnectionState::Unresponsive, 2)
    );
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    blocked.recv_timeout(Duration::from_secs(2)).unwrap();
    worker
        .events
        .send(RecoveryEvent::SetProbeBusy(false))
        .unwrap();
    assert_eq!(worker.after_probe(resume), Some(status));
    worker.expect(ConnectionState::Unresponsive, 1);
    assert_eq!(worker.probes.load(Ordering::Relaxed), 6);
}

#[test]
fn probe_deferral_keeps_manual_request_and_failure_streak() {
    let worker = RecoveryWorker::start();
    worker.probe();
    worker.expect(ConnectionState::Unresponsive, 1);

    let (entered, release) = worker.arm_busy_probe();
    worker.probe();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let before = worker.status.lock().unwrap().take();
    assert_eq!(before.unwrap().failures, 1);
    worker
        .events
        .send(RecoveryEvent::SetProbeBusy(false))
        .unwrap();
    assert_eq!(worker.after_probe(release), None);

    // The next real probe publishes the second failure with no new request.
    worker.expect(ConnectionState::Unresponsive, 2);
    assert_eq!(worker.probes.load(Ordering::Relaxed), 4);
}

#[test]
fn probe_deferral_counts_a_failure_after_one_cadence() {
    let worker = RecoveryWorker::start();
    let (entered, release) = worker.arm_busy_probe();
    worker.probe();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    // Keep the slot busy at every poll while the clock is shortened.
    let before = *worker.status.lock().unwrap();
    assert_eq!(worker.after_probe(release), before);
    worker.interval.set(Duration::from_millis(10));
    worker.expect(ConnectionState::Unresponsive, 1);
}

#[test]
fn probe_deferral_allows_cancellation_while_the_slot_is_busy() {
    let mut worker = RecoveryWorker::start();
    let (entered, release) = worker.arm_busy_probe();
    worker.probe();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let before = *worker.status.lock().unwrap();
    assert_eq!(worker.after_probe(release), before);
    worker.canceled.store(true, Ordering::Release);
    let finished = worker.worker.take().unwrap().join().unwrap();
    assert_eq!(finished.state, ConnectionState::Off);
    assert_eq!(finished.error, None);
}

#[test]
fn soft_restart_deadline_is_not_extended_by_repeated_reconnects() {
    let worker = RecoveryWorker::start();
    worker.phase(Phase::Reconnecting);
    worker.expect(ConnectionState::Reconnecting, 0);
    worker.events.send(RecoveryEvent::Expire).unwrap();
    worker.phase(Phase::Reconnecting);
    worker.probe();
    worker.expect(ConnectionState::Unresponsive, 1);
}

#[test]
fn soft_restart_approval_can_be_disconnected_or_refused() {
    for refuse in [false, true] {
        let worker = RecoveryWorker::start();
        worker.phase(Phase::Reconnecting);
        worker
            .events
            .send(RecoveryEvent::Progress(Progress::AwaitingApproval))
            .unwrap();
        worker.expect(ConnectionState::AwaitingApproval, 0);
        if refuse {
            worker
                .events
                .send(RecoveryEvent::Progress(Progress::Refused(
                    SignError::Canceled,
                )))
                .unwrap();
            worker.expect(ConnectionState::CredentialsRejected, 0);
        } else {
            worker.canceled.store(true, Ordering::Release);
            worker.expect(ConnectionState::Disconnecting, 0);
        }
        drop(worker);
    }
}

#[test]
fn duplicate_down_keeps_the_tun_until_the_next_network() {
    let initial = network();
    let (mut a, observed) = attempt(profile(), vec![Progress::Up(initial.clone())], None);
    assert!(a.ready().unwrap());
    a.tunnel
        .as_mut()
        .unwrap()
        .events
        .extend([Progress::Down, Progress::Down]);
    a.healthy().unwrap();
    {
        let s = observed.lock().unwrap();
        assert_eq!(s.configs.len(), 1);
        assert_eq!(s.configs[0].address, initial.address);
        assert!(s.opened.contains("vpnt0"));
        assert_eq!(s.closes, 0);
        assert_eq!(s.stops, 0);
    }

    let mut changed = initial;
    changed.address = "10.2.3.4".parse().unwrap();
    changed.dns_servers = vec!["10.2.3.1".parse().unwrap()];
    changed.dns_domains = vec!["new.test".into()];
    changed.routes = vec![crate::connection::ovpn::network::Route {
        network: "10.2.4.0".parse().unwrap(),
        prefix: 24,
    }];
    a.tunnel
        .as_mut()
        .unwrap()
        .events
        .extend([Progress::Up(changed.clone()), Progress::Up(changed.clone())]);
    a.healthy().unwrap();
    let s = observed.lock().unwrap();
    let [old, new] = s.configs.as_slice() else {
        panic!("expected an initial configuration and one replacement");
    };
    assert_eq!(old.name, new.name);
    assert_eq!(new.name.as_str(), "vpnt0");
    assert_eq!(new.address, changed.address);
    assert_eq!(new.dns.servers, changed.dns_servers);
    assert_eq!(new.dns.domains, changed.dns_domains);
    assert_eq!(new.routes.len(), 1);
    assert_eq!(new.routes[0].network, changed.routes[0].network);
    assert_eq!(new.routes[0].prefix, changed.routes[0].prefix);
    assert_eq!(s.closes, 0);
    assert_eq!(s.stops, 0);
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
    for (canceled, timeout) in [(true, Duration::from_secs(1)), (false, Duration::ZERO)] {
        assert!(!a.probe(&AtomicBool::new(canceled), timeout).unwrap());
        assert!(a.probe_busy());
    }
    assert!(
        a.probe(&AtomicBool::new(false), Duration::from_secs(1))
            .unwrap()
    );
    assert!(!a.probe_busy());
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
            let first_busy = attempt.probe_busy();
            worker_canceled.store(false, Ordering::Release);
            let second = attempt
                .probe(&worker_canceled, Duration::from_millis(100))
                .unwrap();
            let _ = answer_tx.send((first, first_busy, second, attempt.probe_busy()));
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
            (false, false, false, true)
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
    for generation in 0..3 {
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
        assert_eq!(a.probe_busy(), generation != 0);
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
        Self::in_directory(&std::env::temp_dir())
    }

    fn in_directory(directory: &Path) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = directory.join(format!(
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
    fn token(
        &mut self,
        _: &OvpnSettings,
        _: &[u8],
        _: &AtomicBool,
        _: Instant,
    ) -> Result<(), Failure> {
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
fn replacement_waits_for_a_pending_signature_before_opening_the_token() {
    // Use a harmless file with a trusted ancestry so native admission runs.
    // The file cannot load as a PKCS#11 provider, even after the gate opens.
    let program = std::env::current_exe().unwrap();
    let scratch = Scratch::in_directory(program.parent().unwrap());
    let module = scratch.0.join("fixture.so");
    fs::write(&module, b"not a library").unwrap();
    let canonical = module.canonicalize().unwrap();
    let mut settings = profile().ovpn.unwrap();
    settings.module = module.to_str().unwrap().to_owned();
    let gate = TokenKey::module_gate(&canonical);
    thread::scope(|scope| {
        // The signing entry point requires this same production guard for the
        // entire provider call and any login retry.
        let signing = TokenKey::signing_guard(&gate);

        let expires = Instant::now() + Duration::from_millis(40);
        let failure = RealStart
            .token(&settings, &[1], &AtomicBool::new(false), expires)
            .err()
            .unwrap();
        assert_eq!(failure.step, Step::Tunnel);
        assert_eq!(failure.state, ConnectionState::GatewayTimeout);
        assert!(Instant::now() >= expires);

        let expires = Instant::now() + Duration::from_secs(2);
        let failure = RealStart
            .token(&settings, &[1], &AtomicBool::new(true), expires)
            .err()
            .unwrap();
        assert_eq!(failure.step, Step::Tunnel);
        assert!(Instant::now() < expires);
        let (started, starting) = mpsc::channel();
        let (opened, opening) = mpsc::channel();
        let settings = &settings;
        let replacement = scope.spawn(move || {
            started.send(()).unwrap();
            let failure = RealStart
                .token(
                    settings,
                    &[1],
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_secs(3),
                )
                .err()
                .expect("the fixture is not a loadable module");
            opened.send(failure).unwrap();
        });
        starting.recv_timeout(Duration::from_secs(2)).unwrap();
        let while_signing = opening.recv_timeout(Duration::from_millis(100));
        drop(signing);
        assert!(matches!(
            while_signing,
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        let failure = opening.recv_timeout(Duration::from_secs(2)).unwrap();
        replacement.join().unwrap();
        assert_eq!(failure.step, Step::Profile);
    });
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
    // Provider profiles carry the control-channel timers; the child must get them.
    let profile = format!("{}tls-timeout 2\ntran-window 3600\n", valid_profile());
    let original = profile.replace('\n', "\r\n");
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
        format!("/dev/fd/3\n{profile}")
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
    // The signer is still blocked: cleanup must not spend a second drain
    // budget on the exit that ready already waited for.
    let cleanup_began = Instant::now();
    assert!(a.cleanup());
    let cleanup_elapsed = cleanup_began.elapsed();
    let _ = release.send(());
    assert!(
        cleanup_elapsed < Duration::from_millis(500),
        "{cleanup_elapsed:?}"
    );
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

#[test]
fn complete_restart_between_probes_resets_failure_streak() {
    // A periodic health check drains Reconnecting and Connected together while
    // no probe is running. The next probe starts a new streak.
    let worker = RecoveryWorker::start();
    for failures in 1..=2 {
        worker.probe();
        worker.expect(ConnectionState::Unresponsive, failures);
    }
    let (armed, ready) = mpsc::channel();
    let (entered, blocked) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::BlockProbe {
            armed,
            entered,
            release: gate,
        })
        .unwrap();
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let (processed, done) = mpsc::channel();
    worker
        .events
        .send(RecoveryEvent::CompleteRestart(processed))
        .unwrap();
    done.recv_timeout(Duration::from_secs(2)).unwrap();

    // No manual request: the restart itself must schedule the next probe.
    blocked
        .recv_timeout(Duration::from_secs(2))
        .expect("restart should schedule a probe without a manual request");
    let _ = worker.status.lock().unwrap().take();
    let status = worker
        .after_probe(release)
        .expect("fresh failed probe must publish");
    assert_eq!(
        (status.state, status.failures),
        (ConnectionState::Unresponsive, 1)
    );
}

#[test]
fn restart_hold_withdrawn_network_cannot_publish_loopback_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut profile = profile();
    profile.probe_port = listener.local_addr().unwrap().port();
    let mut stream_count = 0;
    let mut accept_probe = || {
        listener.set_nonblocking(true).unwrap();
        while listener.accept().is_ok() {
            stream_count += 1;
        }
        stream_count
    };
    let (attempt, observed) = attempt(profile, vec![Progress::Up(pushed_network())], None);
    let worker = RecoveryWorker::with_attempt(attempt, true);
    assert_eq!(accept_probe(), 1);
    worker.phase(Phase::Reconnecting);
    worker.expect(ConnectionState::Reconnecting, 0);
    assert!(
        observed
            .lock()
            .unwrap()
            .applied
            .as_ref()
            .unwrap()
            .routes
            .is_empty()
    );

    // Shorten only the fixture's failure cadence and expire the real grace window.
    worker.interval.set(Duration::from_millis(40));
    worker.events.send(RecoveryEvent::Expire).unwrap();
    let published = worker.wait(|| {
        let status = *worker.status.lock().unwrap();
        status.filter(|value| value.state != ConnectionState::Reconnecting)
    });
    assert_eq!(
        published.state,
        ConnectionState::Unresponsive,
        "loopback succeeded before route restoration"
    );
    assert_eq!(
        accept_probe(),
        1,
        "a probe opened a socket with the network withdrawn"
    );
    assert_eq!(observed.lock().unwrap().configs.len(), 2);

    worker.phase(Phase::Connected);
    worker.expect(ConnectionState::Connected, 0);
    assert!(accept_probe() > 1);
    let observed = observed.lock().unwrap();
    assert_eq!(observed.configs.len(), 3);
    assert_eq!(
        wire(observed.applied.as_ref().unwrap()),
        wire(&observed.configs[0])
    );
}

fn restart_hold_signature_after_network(configured: bool, fails: bool) {
    restart_signature_after_network(configured, fails, false);
}

fn restart_signature_after_network(configured: bool, fails: bool, hold_first: bool) {
    use crate::connection::ovpn::{session::Signer, signing::Padding};

    struct RecordingSigner {
        observed: Arc<Mutex<Observed>>,
        entered: mpsc::Sender<Option<(usize, usize)>>,
    }
    impl Signer for RecordingSigner {
        fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
            Ok(vec![1])
        }
        fn sign(&mut self, _: Padding, _: &[u8]) -> Result<Vec<u8>, SignError> {
            let observed = self.observed.lock().unwrap();
            let _ = self.entered.send(
                observed
                    .applied
                    .as_ref()
                    .map(|c| (c.routes.len(), c.dns.servers.len())),
            );
            Ok(vec![1])
        }
    }

    let scratch = Scratch::new();
    let program = scratch.0.join("openvpn");
    fs::write(
        &program,
        format!(
            "#!/usr/bin/python3\nHOLD_FIRST = {}\n{}",
            if hold_first {{ "True" }} else {{ "False" }},
            r#"import pathlib, socket, sys
if "--version" in sys.argv:
    print("OpenVPN 2.6.19")
    sys.exit(0)
with socket.socket(socket.AF_UNIX) as sock:
    sock.settimeout(4)
    sock.connect(sys.argv[sys.argv.index("--management") + 1])
    with sock.makefile("rb") as wire:
        assert wire.readline() == b"version 3\n"
        assert wire.readline() == b"state on\n"
        sock.sendall(b">HOLD:startup\n")
        assert wire.readline() == b"hold release\n"
        if HOLD_FIRST:
            # Out of order: the restart HOLD precedes the restart state, and the
            # signature request follows the state without another HOLD.
            sock.sendall(b">HOLD:restart-before-state\n")
            assert wire.readline() == b"hold release\n"
            sock.sendall(b">STATE:1,RECONNECTING,ping-restart,,,,,\n")
            sock.sendall(b">PK_SIGN:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=,RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest\n")
            command = b"hold release\n"
        else:
            sock.sendall(b">STATE:1,RECONNECTING,ping-restart,,,,,\n>HOLD:restart\n")
            command = wire.readline()
            if command == b"hold release\n":
                sock.sendall(b">PK_SIGN:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=,RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest\n")
        if command == b"hold release\n":
            command = wire.readline()
        if command == b"pk-sig\n":
            assert wire.readline() == b"AQ==\n"
            assert wire.readline() == b"END\n"
            pathlib.Path(__file__).with_name("signed").touch()
            command = wire.readline()
        assert command == b"signal SIGTERM\n"
        pathlib.Path(__file__).with_name("terminated").touch()
"#
        ),
    )
    .unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let observed = Arc::new(Mutex::new(Observed::default()));
    let mut attempt = OvpnAttempt::fixture(
        profile(),
        FakeNetwork(observed.clone()),
        RealTunnel {
            session: None,
            waiting: None,
            wait_failed: false,
        },
        NoStart,
    );
    if configured {
        attempt.configure(pushed_network()).unwrap();
    }
    if fails {
        observed.lock().unwrap().configure_error = Some(NetFailure::Dns);
    }
    let (entered, signing) = mpsc::channel();
    let signing = Arc::new(Mutex::new(signing));
    if configured {
        let signing = signing.clone();
        observed.lock().unwrap().before_configure = Some(Box::new(move || {
            let during_withdrawal = signing
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(150));
            assert_eq!(
                during_withdrawal,
                Err(mpsc::RecvTimeoutError::Timeout),
                "signer entered before configure completed"
            );
        }));
    }
    let session = Session::start(
        Launch {
            openvpn: program,
            config: PathBuf::from("/dev/null"),
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        },
        RecordingSigner {
            observed: observed.clone(),
            entered,
        },
    )
    .unwrap();
    attempt.tunnel.as_mut().unwrap().session = Some(session);
    // The controller is deliberately parked while management receives the HOLD.
    // The signature itself samples the routes and DNS seen by the token.
    let early_signature = signing
        .lock()
        .unwrap()
        .recv_timeout(Duration::from_millis(200));
    assert_eq!(
        early_signature,
        Err(mpsc::RecvTimeoutError::Timeout),
        "signer entered before the controller withdrew the routes"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = loop {
        let result = attempt.healthy();
        if attempt.reconnect_started.is_some() || result.is_err() {
            break result;
        }
        assert!(Instant::now() < deadline, "restart was not processed");
        thread::sleep(Duration::from_millis(5));
    };
    if fails {
        assert_eq!(result.unwrap_err().step, Step::Routes);
    } else {
        result.unwrap();
        assert_eq!(
            signing
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            configured.then_some((0, 0))
        );
        // Wait until the peer has read the whole signature before terminating.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !scratch.0.join("signed").exists() {
            assert!(
                Instant::now() < deadline,
                "peer did not receive the signature"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    assert!(attempt.cleanup());
    assert!(
        scratch.0.join("terminated").is_file(),
        "management transcript failed"
    );
    assert_eq!(
        observed.lock().unwrap().configs.len(),
        if configured { 2 } else { 0 }
    );
    if fails {
        assert_eq!(
            signing.lock().unwrap().try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        );
    }
}

#[test]
fn restart_hold_configures_withdrawal_before_the_signer_enters() {
    restart_hold_signature_after_network(true, false);
}

#[test]
fn restart_hold_before_first_up_signals_without_configuring() {
    restart_hold_signature_after_network(false, false);
}

#[test]
fn restart_hold_failed_withdrawal_stops_without_releasing() {
    restart_hold_signature_after_network(true, true);
}

#[test]
fn restart_signature_after_an_early_hold_waits_for_the_withdrawal() {
    restart_signature_after_network(true, false, true);
}

#[test]
fn restart_signature_after_an_early_hold_stops_when_the_withdrawal_fails() {
    restart_signature_after_network(true, true, true);
}
