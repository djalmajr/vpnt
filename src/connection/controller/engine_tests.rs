use super::*;
use crate::{
    connection::routes::{
        Backend, Coordinator, Error, Key, Lease, Owner, Presence, Route, ppp_networks,
    },
    helper::{
        process::ManagedChild,
        protocol::{parse_request, read_message, write_message},
    },
    preferences::ProbeInterval,
    secrets::Secret,
};
use std::{
    io::BufReader,
    process::Command as ProcessCommand,
    sync::{Mutex, mpsc},
    thread::JoinHandle,
    time::Instant,
};

#[cfg(target_os = "macos")]
mod recovery {
    use super::*;

    struct RecoveryEngine(Arc<crate::connection::macos::fence_recovery::tests::RecoveryFixture>);
    struct RecoveryAttempt;
    impl Attempt for RecoveryAttempt {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            Ok(())
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            Ok(true)
        }
        fn healthy(&mut self) -> Result<(), Failure> {
            Ok(())
        }
        fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
            Ok(true)
        }
        fn cleanup(&mut self) -> bool {
            true
        }
    }
    impl Factory for RecoveryEngine {
        type Attempt = RecoveryAttempt;
        fn create(
            &self,
            _: Profile,
            _: u32,
            _: u64,
            _: Credentials,
            _: Arc<AtomicBool>,
        ) -> Self::Attempt {
            RecoveryAttempt
        }
        fn idle(&self) -> bool {
            true
        }
        fn cleanup_blocked(&self, profile: &Profile) -> bool {
            self.0.blocked(profile)
        }
        fn verify_cleanup(&self, profile: &Profile) -> bool {
            self.0.verify(profile)
        }
    }
    struct EngineGuard(Option<JoinHandle<Result<(), ErrorCode>>>);
    impl Drop for EngineGuard {
        fn drop(&mut self) {
            if let Some(worker) = self.0.take() {
                let _ = worker.join();
            }
        }
    }
    struct FixtureSecrets;
    impl crate::secrets::SecretStore for FixtureSecrets {
        fn contains(&self, _: &str, _: VpnKind) -> Result<bool, crate::secrets::SecretError> {
            Ok(true)
        }
        fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, crate::secrets::SecretError> {
            Ok(Credentials {
                password: "fictional".into(),
                psk: "".into(),
            })
        }
        fn save(
            &self,
            _: &str,
            _: VpnKind,
            _: &Credentials,
        ) -> Result<(), crate::secrets::SecretError> {
            Ok(())
        }
        fn remove(&self, _: &str, _: VpnKind) -> Result<(), crate::secrets::SecretError> {
            Ok(())
        }
    }

    #[test]
    fn broker_and_engine_negotiate_cleanup_and_legacy_snapshots_stay_off() {
        use crate::{bridge::Command as UiCommand, broker::Broker, helper::client::Client};
        let recovery =
            Arc::new(crate::connection::macos::fence_recovery::tests::RecoveryFixture::new());
        let (input, requests) = mpsc::sync_channel(32);
        let (output, replies) = mpsc::sync_channel(64);
        let state = recovery.clone();
        let guard = EngineGuard(Some(thread::spawn(move || {
            run(
                RecoveryEngine(state),
                unsafe { libc::geteuid() },
                vec![profile("one")],
                requests,
                output,
                Timing::default(),
            )
        })));
        let client = Client::fixture_channels(input, replies);
        let mut broker = Broker::fixture(client, FixtureSecrets);
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = broker.snapshot();
            if snapshot
                .vpns
                .iter()
                .any(|v| v.profile.id == "one" && v.state == ConnectionState::CleanupUnconfirmed)
            {
                break;
            }
            assert!(
                Instant::now() < until,
                "new broker never received negotiated cleanup state"
            );
            thread::sleep(Duration::from_millis(2));
        }
        recovery.remove_observed_route();
        broker
            .dispatch(
                UiCommand::Probe { id: "one".into() },
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        loop {
            let snapshot = broker.snapshot();
            if snapshot
                .vpns
                .iter()
                .any(|v| v.profile.id == "one" && v.state == ConnectionState::Off)
            {
                break;
            }
            assert!(
                Instant::now() < until,
                "VerifyCleanup did not release the profile"
            );
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(recovery.verifies(), 1);
        assert!(!recovery.fence_exists());
        drop(broker);
        drop(guard);

        let recovery =
            Arc::new(crate::connection::macos::fence_recovery::tests::RecoveryFixture::new());
        let (input, requests) = mpsc::sync_channel(32);
        let (output, replies) = mpsc::sync_channel(64);
        let state = recovery.clone();
        let guard = EngineGuard(Some(thread::spawn(move || {
            run(
                RecoveryEngine(state),
                unsafe { libc::geteuid() },
                vec![profile("one")],
                requests,
                output,
                Timing::default(),
            )
        })));
        for id in [
            crate::helper::protocol::WAIT_CAPABILITY_SNAPSHOT_ID,
            "legacy-query",
        ] {
            input
                .send(Request {
                    id: id.into(),
                    command: Command::Snapshot {},
                })
                .unwrap();
            let message = replies.recv_timeout(Duration::from_secs(5)).unwrap();
            let Message::Snapshot { connections, .. } = message else {
                panic!("legacy snapshot expected")
            };
            assert!(
                connections
                    .iter()
                    .all(|status| status.state == ConnectionState::Off)
            );
        }
        assert_eq!(recovery.verifies(), 0);
        assert!(recovery.fence_exists());
        drop(input);
        drop(replies);
        drop(guard);
    }
}

#[derive(Default)]
struct Control {
    started: bool,
    ready: bool,
    responsive: bool,
    hold_probe: bool,
    probed: bool,
    probes: usize,
    invalidate_after_probe: bool,
    invalid: bool,
    cleanup_allowed: bool,
    cleanup_calls: usize,
    abandon_result: Option<Result<(), AbandonError>>,
    stopped: bool,
    finished: bool,
    index: u16,
}
#[derive(Default)]
struct Kernel {
    attempts: BTreeMap<(String, u64), Control>,
    routes: BTreeMap<Key, (Route, u64)>,
    serial: u64,
    retired_pending: bool,
    retirement_observed: bool,
    test_shutdown: bool,
}
type Shared = Arc<Mutex<Kernel>>;
struct Table(Shared);
impl Backend for Table {
    type Receipt = (Route, u64);
    fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
        Ok(self.0.lock().unwrap().routes.get(&key).map(|entry| entry.0))
    }
    fn create(&mut self, route: Route) -> Result<Self::Receipt, Error> {
        let mut kernel = self.0.lock().unwrap();
        if kernel.routes.contains_key(&route.key) {
            return Err(Error::Conflict);
        }
        kernel.serial += 1;
        let receipt = (route, kernel.serial);
        kernel.routes.insert(route.key, receipt);
        Ok(receipt)
    }
    fn receipt_state(&mut self, receipt: &Self::Receipt) -> Result<Presence, Error> {
        Ok(match self.0.lock().unwrap().routes.get(&receipt.0.key) {
            None => Presence::Absent,
            Some(actual) if actual == receipt => Presence::Owned,
            _ => Presence::Replaced,
        })
    }
    fn remove(&mut self, receipt: &Self::Receipt) -> Result<(), Error> {
        let mut kernel = self.0.lock().unwrap();
        if kernel
            .attempts
            .values()
            .any(|control| control.index == receipt.0.interface && !control.cleanup_allowed)
        {
            return Err(Error::Busy);
        }
        if kernel.routes.get(&receipt.0.key) == Some(receipt) {
            kernel.routes.remove(&receipt.0.key);
        }
        Ok(())
    }
}
struct Fixture {
    uid: u32,
    kernel: Shared,
    routes: Arc<Mutex<Coordinator<Table>>>,
}
impl Factory for Fixture {
    type Attempt = FixtureAttempt;
    fn create(
        &self,
        profile: Profile,
        uid: u32,
        generation: u64,
        credentials: Credentials,
        canceled: Arc<AtomicBool>,
    ) -> Self::Attempt {
        assert_eq!(uid, self.uid);
        assert!(generation > 0);
        let mut kernel = self.kernel.lock().unwrap();
        let index = 3 + kernel.attempts.len() as u16;
        let cleanup_allowed = kernel.test_shutdown;
        assert!(
            kernel
                .attempts
                .insert(
                    (profile.id.clone(), generation),
                    Control {
                        index,
                        cleanup_allowed,
                        ..Control::default()
                    }
                )
                .is_none()
        );
        drop(kernel);
        FixtureAttempt {
            kernel: self.kernel.clone(),
            routes: self.routes.clone(),
            owner: Owner {
                uid,
                profile: profile.id.clone(),
                generation,
            },
            profile,
            credentials: Some(credentials),
            canceled,
            child: None,
            lease: None,
        }
    }
    fn idle(&self) -> bool {
        let mut routes = self.routes.lock().unwrap();
        routes.retry_cleanup();
        let mut kernel = self.kernel.lock().unwrap();
        kernel.retirement_observed = true;
        !routes.has_resources() && !kernel.retired_pending
    }
}
struct FixtureAttempt {
    kernel: Shared,
    routes: Arc<Mutex<Coordinator<Table>>>,
    owner: Owner,
    profile: Profile,
    credentials: Option<Credentials>,
    canceled: Arc<AtomicBool>,
    child: Option<ManagedChild>,
    lease: Option<Lease>,
}
impl Drop for FixtureAttempt {
    fn drop(&mut self) {
        // Test unwind still cleans its own process/leases. This deliberately
        // does not set the explicit cleanup evidence used by the assertions.
        drop(self.child.take());
        if let Some(lease) = self.lease.take() {
            let _ = self.routes.lock().unwrap().release(lease);
        }
    }
}
impl FixtureAttempt {
    fn key(&self) -> (String, u64) {
        (self.owner.profile.clone(), self.owner.generation)
    }
}
impl Attempt for FixtureAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        let credentials = self.credentials.take().unwrap();
        assert_eq!(credentials.password.expose(), "fixture-password");
        self.child =
            Some(ManagedChild::spawn(ProcessCommand::new("/bin/sleep").arg("60")).unwrap());
        self.kernel
            .lock()
            .unwrap()
            .attempts
            .get_mut(&self.key())
            .unwrap()
            .started = true;
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        let (ready, index) = {
            let kernel = self.kernel.lock().unwrap();
            let c = &kernel.attempts[&self.key()];
            (c.ready, c.index)
        };
        if !ready {
            return Ok(false);
        }
        if self.lease.is_none() {
            let plan = ppp_networks(&self.profile.networks, index, true, false, None).unwrap();
            self.lease = Some(
                self.routes
                    .lock()
                    .unwrap()
                    .acquire(self.owner.clone(), &plan)
                    .map_err(|_| Failure::unavailable())?,
            );
        }
        Ok(true)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        if self.kernel.lock().unwrap().attempts[&self.key()].invalid {
            return Err(Failure::unavailable());
        }
        self.routes
            .lock()
            .unwrap()
            .validate(self.lease.as_ref().ok_or_else(Failure::unavailable)?)
            .map_err(|_| Failure::unavailable())
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        loop {
            let (held, responsive) = {
                let mut kernel = self.kernel.lock().unwrap();
                let c = kernel.attempts.get_mut(&self.key()).unwrap();
                c.probed = true;
                c.probes += 1;
                if c.invalidate_after_probe {
                    c.invalid = true;
                }
                (c.hold_probe, c.responsive)
            };
            // Deliberately return a late success even after cancellation. The
            // actual controller must reject it; the fake must not hide it.
            if !held {
                return Ok(responsive);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn cleanup(&mut self) -> bool {
        assert!(self.canceled.load(Ordering::Acquire));
        if let Some(mut child) = self.child.take() {
            child.stop(Duration::from_millis(10)).unwrap();
            assert!(child.poll().unwrap().is_some());
        }
        if let Some(lease) = self.lease.take() {
            self.routes.lock().unwrap().release(lease).unwrap();
        }
        let mut routes = self.routes.lock().unwrap();
        routes.retry_cleanup();
        let resources = routes.has_owner(&self.owner);
        drop(routes);
        let mut kernel = self.kernel.lock().unwrap();
        let c = kernel.attempts.get_mut(&self.key()).unwrap();
        c.cleanup_calls += 1;
        c.stopped = true;
        c.finished = c.cleanup_allowed && !resources;
        c.finished
    }
    fn abandon(&mut self, _: Reason) -> Result<(), AbandonError> {
        let result = self.kernel.lock().unwrap().attempts[&self.key()]
            .abandon_result
            .unwrap_or(Err(AbandonError::Unsupported));
        // This fixture has no durable inventory writer. A configured success is
        // valid only when it holds no child or route lease.
        if result.is_ok() && (self.child.is_some() || self.lease.is_some()) {
            return Err(AbandonError::Unsupported);
        }
        result
    }
}

#[test]
fn fixture_abandon_is_configurable_but_retains_live_leases() {
    let kernel = Arc::new(Mutex::new(Kernel::default()));
    let routes = Arc::new(Mutex::new(Coordinator::new(Table(kernel.clone())).unwrap()));
    let fixture = Fixture {
        uid: 501,
        kernel: kernel.clone(),
        routes,
    };
    let mut attempt = fixture.create(
        profile("abandon"),
        501,
        1,
        Credentials {
            password: Secret::from("fixture-password"),
            psk: Secret::from(""),
        },
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(
        attempt.abandon(Reason::ObservationFailed),
        Err(AbandonError::Unsupported)
    );
    kernel
        .lock()
        .unwrap()
        .attempts
        .get_mut(&attempt.key())
        .unwrap()
        .abandon_result = Some(Err(AbandonError::Persist));
    assert_eq!(
        attempt.abandon(Reason::ObservationFailed),
        Err(AbandonError::Persist)
    );
    kernel
        .lock()
        .unwrap()
        .attempts
        .get_mut(&attempt.key())
        .unwrap()
        .abandon_result = Some(Ok(()));
    assert_eq!(attempt.abandon(Reason::ObservationFailed), Ok(()));
    kernel
        .lock()
        .unwrap()
        .attempts
        .get_mut(&attempt.key())
        .unwrap()
        .ready = true;
    assert!(matches!(attempt.ready(), Ok(true)));
    assert_eq!(
        attempt.abandon(Reason::ObservationFailed),
        Err(AbandonError::Unsupported)
    );
    assert!(attempt.routes.lock().unwrap().has_owner(&attempt.owner));
}

struct Harness {
    input: Option<SyncSender<Request>>,
    output: Receiver<Message>,
    kernel: Shared,
    worker: Option<JoinHandle<Result<(), ErrorCode>>>,
    seen: Vec<Message>,
    next_request: usize,
}

#[test]
fn cleanup_verification_rejects_only_the_live_profile() {
    let mut harness = Harness::new(vec![profile("one"), profile("two")], 64);
    harness
        .input
        .as_ref()
        .unwrap()
        .send(Request {
            id: crate::helper::protocol::CLEANUP_PROBE_SNAPSHOT_ID.into(),
            command: Command::Snapshot {},
        })
        .unwrap();
    harness.wait(|h| h.seen.iter().any(|message| matches!(message, Message::Snapshot { id, .. } if id == crate::helper::protocol::CLEANUP_ACK_SNAPSHOT_ID)));
    harness.connect("one", 1);
    harness.started("one", 1);
    let busy = harness.command(Command::VerifyCleanup {
        profile: "one".into(),
    });
    harness.wait(|h| h.seen.iter().any(|message| matches!(message, Message::Failed { id, error: ErrorCode::ProfileBusy } if *id == busy)));
    let idle = harness.command(Command::VerifyCleanup {
        profile: "two".into(),
    });
    harness.wait(|h| {
        h.seen
            .iter()
            .any(|message| matches!(message, Message::Snapshot { id, .. } if *id == idle))
    });
}
impl Harness {
    fn new(profiles: Vec<Profile>, capacity: usize) -> Self {
        let kernel = Arc::new(Mutex::new(Kernel::default()));
        let routes = Arc::new(Mutex::new(Coordinator::new(Table(kernel.clone())).unwrap()));
        let fixture = Fixture {
            uid: 501,
            kernel: kernel.clone(),
            routes,
        };
        let (input, requests) = mpsc::sync_channel(64);
        let (output, receiver) = mpsc::sync_channel(capacity);
        let timing = Timing {
            connect: Duration::from_secs(5),
            probe: Duration::from_secs(1),
            interval: Duration::from_secs(60),
            health: Duration::from_millis(2),
            poll: Duration::from_millis(2),
        };
        let worker = thread::spawn(move || run(fixture, 501, profiles, requests, output, timing));
        Self {
            input: Some(input),
            output: receiver,
            kernel,
            worker: Some(worker),
            seen: vec![],
            next_request: 0,
        }
    }
    fn command(&mut self, command: Command) -> String {
        self.next_request += 1;
        let id = format!("req-{}", self.next_request);
        let request = Request {
            id: id.clone(),
            command,
        };
        // Use the real parser before handing the message to the engine.
        let bytes = serde_json::to_vec(&request).unwrap();
        self.input
            .as_ref()
            .unwrap()
            .send(parse_request(&bytes).unwrap())
            .unwrap();
        id
    }
    fn connect(&mut self, id: &str, generation: u64) {
        self.command(Command::Connect {
            id: id.into(),
            generation,
            interval: ProbeInterval::TEN,
            credentials: Credentials {
                password: Secret::from("fixture-password"),
                psk: Secret::from(""),
            },
        });
    }
    fn control(&self, id: &str, generation: u64, change: impl FnOnce(&mut Control)) {
        change(
            self.kernel
                .lock()
                .unwrap()
                .attempts
                .get_mut(&(id.into(), generation))
                .unwrap(),
        );
    }
    fn wait(&mut self, predicate: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain();
            if predicate(self) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "controller condition timed out; received {} messages",
                self.seen.len()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn drain(&mut self) {
        for message in self.output.try_iter() {
            let mut wire = vec![];
            write_message(&mut wire, &message).unwrap();
            assert!(!String::from_utf8_lossy(&wire).contains("fixture-password"));
            self.seen.push(
                read_message(&mut BufReader::new(wire.as_slice()))
                    .unwrap()
                    .unwrap(),
            );
        }
    }
    fn state(&self, id: &str, generation: u64, state: ConnectionState) -> bool {
        self.seen.iter().any(|message| matches!(message, Message::Changed { profile_id, generation: g, state: s, .. } if profile_id==id && *g==generation && *s==state))
    }
    fn barrier(&self, mut predicate: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !predicate(self) {
            assert!(
                Instant::now() < deadline,
                "controller barrier timed out; received {} messages",
                self.seen.len()
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn started(&mut self, id: &str, generation: u64) {
        self.wait(|h| {
            h.kernel
                .lock()
                .unwrap()
                .attempts
                .get(&(id.into(), generation))
                .is_some_and(|c| c.started)
        });
    }
    fn snapshot_states(&mut self) -> Vec<TunnelStatus> {
        let request = self.command(Command::Snapshot {});
        self.wait(|h| {
            h.seen
                .iter()
                .any(|m| matches!(m, Message::Snapshot { id,.. } if *id==request))
        });
        let message = self
            .seen
            .iter()
            .find(|m| matches!(m,Message::Snapshot { id,.. } if *id==request))
            .unwrap();
        if let Message::Snapshot { connections, .. } = message {
            connections
                .iter()
                .map(|s| TunnelStatus {
                    id: s.id.clone(),
                    generation: s.generation,
                    state: s.state,
                    failures: s.failures,
                    cleaning: s.cleaning,
                })
                .collect()
        } else {
            unreachable!()
        }
    }
    fn finish(&mut self) {
        self.input = None;
        self.wait(|h| h.worker.as_ref().unwrap().is_finished());
        assert!(self.worker.take().unwrap().join().unwrap().is_ok());
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.input = None;
        self.kernel.lock().unwrap().retired_pending = false;
        self.kernel.lock().unwrap().test_shutdown = true;
        for control in self.kernel.lock().unwrap().attempts.values_mut() {
            control.cleanup_allowed = true;
            control.hold_probe = false;
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn profile(id: &str) -> Profile {
    Profile {
        dns_domains: Vec::new(),
        id: id.into(),
        name: id.into(),
        kind: VpnKind::Ssl,
        gateway: "vpn.example.com".into(),
        username: "fixture".into(),
        networks: vec![
            if id == "two" {
                "10.30.0.0/16"
            } else {
                "10.20.0.0/16"
            }
            .into(),
        ],
        port: 443,
        certificate: String::new(),
        probe_host: "10.20.0.8".into(),
        probe_port: 8443,
        probe_method: "tcp".into(),
    }
}

#[test]
fn controller_connects_only_after_leases_and_probe_then_detects_and_recovers_no_traffic() {
    let mut h = Harness::new(vec![profile("one")], 64);
    h.connect("one", 1);
    h.started("one", 1);
    h.control("one", 1, |c| {
        c.ready = true;
        c.hold_probe = true;
    });
    h.wait(|h| h.state("one", 1, ConnectionState::Verifying));
    assert!(!h.state("one", 1, ConnectionState::Connected));
    h.control("one", 1, |c| c.hold_probe = false);
    h.wait(|h| h.state("one", 1, ConnectionState::Unresponsive));
    h.control("one", 1, |c| c.responsive = true);
    h.command(Command::Probe {
        id: "one".into(),
        generation: 1,
    });
    h.wait(|h| h.state("one", 1, ConnectionState::Connected));
    h.command(Command::Disconnect {
        id: "one".into(),
        generation: 2,
    });
    h.wait(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].stopped);
    assert!(!h.state("one", 2, ConnectionState::Off));
    h.control("one", 1, |c| c.cleanup_allowed = true);
    h.wait(|h| h.state("one", 2, ConnectionState::Off));
    assert!(h.kernel.lock().unwrap().routes.is_empty());
    h.finish();
}
#[test]
fn reconnect_waits_for_cleanup_and_rejects_a_late_successful_probe() {
    let mut h = Harness::new(vec![profile("one")], 64);
    h.connect("one", 1);
    h.started("one", 1);
    h.control("one", 1, |c| {
        c.ready = true;
        c.responsive = true;
        c.hold_probe = true;
    });
    h.wait(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].probed);
    h.connect("one", 2);
    h.wait(|h| h.state("one", 2, ConnectionState::Reconnecting));
    h.control("one", 1, |c| c.hold_probe = false);
    h.wait(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].stopped);
    assert!(
        !h.kernel
            .lock()
            .unwrap()
            .attempts
            .contains_key(&("one".into(), 2))
    );
    assert!(!h.state("one", 1, ConnectionState::Connected));
    // Two request/response barriers ensure the dispatcher has consumed any
    // old cleanup status before observing the current generation again.
    h.snapshot_states();
    let states = h.snapshot_states();
    assert!(
        states.iter().any(|s| s.id == "one"
            && s.generation == 2
            && s.state == ConnectionState::Reconnecting)
    );
    h.control("one", 1, |c| c.cleanup_allowed = true);
    h.started("one", 2);
    h.control("one", 2, |c| {
        c.ready = true;
        c.responsive = true;
        c.cleanup_allowed = true;
    });
    h.wait(|h| h.state("one", 2, ConnectionState::Connected));
    h.finish();
}
#[test]
fn cancel_before_discovery_does_not_forget_cleanup_or_launch_a_queued_replacement() {
    let mut h = Harness::new(vec![profile("one")], 64);
    h.connect("one", 1);
    h.started("one", 1);
    h.connect("one", 2);
    h.command(Command::Disconnect {
        id: "one".into(),
        generation: 3,
    });
    h.wait(|h| h.state("one", 3, ConnectionState::Disconnecting));
    h.control("one", 1, |c| {
        c.ready = true;
        c.responsive = true;
    });
    h.wait(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].stopped);
    assert_eq!(h.kernel.lock().unwrap().attempts.len(), 1);
    assert!(!h.state("one", 3, ConnectionState::Off));
    h.control("one", 1, |c| c.cleanup_allowed = true);
    h.wait(|h| h.state("one", 3, ConnectionState::Off));
    h.finish();
}
#[test]
fn post_probe_link_or_lease_failure_prevents_connected() {
    let mut h = Harness::new(vec![profile("one")], 64);
    h.connect("one", 1);
    h.started("one", 1);
    h.control("one", 1, |c| {
        c.ready = true;
        c.responsive = true;
        c.invalidate_after_probe = true;
        c.cleanup_allowed = true;
    });
    h.wait(|h| h.state("one", 1, ConnectionState::Dropped));
    assert!(!h.state("one", 1, ConnectionState::Connected));
    h.finish();
}
#[test]
fn profiles_run_concurrently_and_eof_waits_for_workers_leases_and_retirement() {
    let mut h = Harness::new(vec![profile("one"), profile("two")], 64);
    h.connect("one", 1);
    h.connect("two", 1);
    h.started("one", 1);
    h.started("two", 1);
    h.control("one", 1, |c| {
        c.ready = true;
        c.hold_probe = true;
    });
    h.control("two", 1, |c| {
        c.ready = true;
        c.responsive = true;
    });
    h.wait(|h| h.state("two", 1, ConnectionState::Connected));
    let snapshot = h.command(Command::Snapshot {});
    h.wait(|h| {
        h.seen
            .iter()
            .any(|m| matches!(m,Message::Snapshot { id,.. } if *id==snapshot))
    });
    h.kernel.lock().unwrap().retired_pending = true;
    h.input = None;
    h.control("one", 1, |c| {
        c.hold_probe = false;
        c.cleanup_allowed = true;
    });
    h.control("two", 1, |c| c.cleanup_allowed = true);
    h.wait(|h| {
        h.kernel
            .lock()
            .unwrap()
            .attempts
            .values()
            .all(|c| c.finished)
    });
    // Wait for a controller observation (or an incorrect return), rather
    // than racing its next instruction with an instantaneous check.
    h.wait(|h| {
        h.kernel.lock().unwrap().retirement_observed || h.worker.as_ref().unwrap().is_finished()
    });
    assert!(!h.worker.as_ref().unwrap().is_finished());
    h.kernel.lock().unwrap().retired_pending = false;
    h.finish();
}
#[test]
fn stale_operations_and_invalid_secrets_cannot_cancel_or_replace_current_worker() {
    let mut h = Harness::new(vec![profile("one")], 64);
    h.connect("one", 5);
    h.started("one", 5);
    h.control("one", 5, |c| {
        c.ready = true;
        c.responsive = true;
        c.cleanup_allowed = true;
    });
    h.wait(|h| h.state("one", 5, ConnectionState::Connected));
    let stale = h.command(Command::Disconnect {
        id: "one".into(),
        generation: 4,
    });
    let oldprobe = h.command(Command::Probe {
        id: "one".into(),
        generation: 4,
    });
    let bad = h.command(Command::Connect {
        id: "one".into(),
        generation: 6,
        interval: ProbeInterval::TEN,
        credentials: Credentials {
            password: Secret::from("x".repeat(257)),
            psk: Secret::from(""),
        },
    });
    h.wait(|h| {
        [&stale, &oldprobe].iter().all(|id| {
            h.seen.iter().any(
                |m| matches!(m,Message::Failed { id:r,error:ErrorCode::InvalidRequest } if r==*id),
            )
        }) && h
            .seen
            .iter()
            .any(|m| matches!(m,Message::Failed { id,error:ErrorCode::InvalidSecret } if *id==bad))
    });
    assert!(!h.kernel.lock().unwrap().attempts[&("one".into(), 5)].stopped);
    assert_eq!(h.kernel.lock().unwrap().attempts.len(), 1);
    h.finish();
}
#[test]
fn unread_output_does_not_block_cancel_and_bounded_overflow_shuts_down_safely() {
    let mut h = Harness::new(vec![profile("one")], 1);
    h.connect("one", 1);
    h.started("one", 1);
    h.control("one", 1, |c| c.cleanup_allowed = true);
    // Do not read the output while filling its bounded queue. Snapshot flood
    // must initiate shutdown, rather than block the dispatcher before cancel.
    for n in 0..300 {
        if h.input
            .as_ref()
            .unwrap()
            .send(Request {
                id: format!("flood-{n}"),
                command: Command::Snapshot {},
            })
            .is_err()
        {
            break;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !h.worker.as_ref().unwrap().is_finished() {
        assert!(
            Instant::now() < deadline,
            "output backpressure must not hold a worker alive"
        );
        thread::sleep(Duration::from_millis(2));
    }
    assert!(h.kernel.lock().unwrap().attempts[&("one".into(), 1)].stopped);
    assert!(h.worker.take().unwrap().join().unwrap().is_ok());
}

#[test]
fn coalesced_changes_keep_the_third_failure_and_a_responsive_probe_resets_it() {
    // Capacity one: the engine cannot hand every intermediate status to the
    // reader, so only the coalesced progress in the slot can carry failure 3.
    let mut h = Harness::new(vec![profile("one")], 1);
    h.connect("one", 1);
    h.started("one", 1);
    h.control("one", 1, |c| c.ready = true);
    // The first traffic probe is immediately due and fails; wait for the
    // engine to publish that settled status before driving manual probes.
    h.wait(|h| h.state("one", 1, ConnectionState::Unresponsive));
    h.barrier(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].probes >= 1);
    // Two more command probes while the bounded output is not drained.
    for target in [2, 3] {
        h.command(Command::Probe {
            id: "one".into(),
            generation: 1,
        });
        h.barrier(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].probes >= target);
    }
    // Snapshots are engine round-trips; repeat until the coalesced third
    // failure is visible instead of assuming the progress was applied in the
    // same loop iteration that answered the first snapshot.
    let deadline = Instant::now() + Duration::from_secs(3);
    let states = loop {
        let states = h.snapshot_states();
        if states.iter().any(|s| {
            s.id == "one"
                && s.generation == 1
                && s.state == ConnectionState::Unresponsive
                && s.failures == 3
        }) {
            break states;
        }
        assert!(
            Instant::now() < deadline,
            "coalesced third failure never reached the snapshot"
        );
        thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(
        states
            .iter()
            .find(|s| s.id == "one")
            .map(|s| (s.generation, s.failures)),
        Some((1, 3)),
        "the snapshot must echo the coalesced counter for the current generation"
    );
    assert!(h.seen.iter().any(|m| matches!(
        m,
        Message::Changed {
            profile_id,
            generation: 1,
            state: ConnectionState::Unresponsive,
            failures: 3,
            cleaning: false,
        } if profile_id == "one"
    )));
    h.control("one", 1, |c| c.responsive = true);
    h.command(Command::Probe {
        id: "one".into(),
        generation: 1,
    });
    h.wait(|h| h.kernel.lock().unwrap().attempts[&("one".into(), 1)].probes >= 4);
    h.wait(|h| {
        h.seen.iter().any(|m| {
            matches!(
                m,
                Message::Changed {
                    profile_id,
                    generation: 1,
                    state: ConnectionState::Connected,
                    failures: 0,
                    cleaning: false,
                } if profile_id == "one"
            )
        })
    });
    let states = h.snapshot_states();
    assert!(
        states
            .iter()
            .any(|s| s.id == "one" && s.failures == 0 && s.state == ConnectionState::Connected)
    );
    h.control("one", 1, |c| c.cleanup_allowed = true);
    h.finish();
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_helper_channel_drives_controller_and_retains_cleanup_after_socket_eof() {
    use std::{net::Shutdown, os::unix::net::UnixStream};
    let (client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let kernel = Arc::new(Mutex::new(Kernel::default()));
    let routes = Arc::new(Mutex::new(Coordinator::new(Table(kernel.clone())).unwrap()));
    let uid = unsafe { libc::geteuid() };
    let fixture = Fixture {
        uid,
        kernel: kernel.clone(),
        routes,
    };
    let worker = thread::spawn(move || {
        crate::helper::server::runtime_fixture(server, |actual, requests, output| {
            assert_eq!(actual, uid);
            run(
                fixture,
                actual,
                vec![profile("one")],
                requests,
                output,
                Timing {
                    connect: Duration::from_secs(5),
                    probe: Duration::from_secs(1),
                    interval: Duration::from_secs(60),
                    health: Duration::from_millis(2),
                    poll: Duration::from_millis(2),
                },
            )
        })
    });
    let (_, output) = mpsc::sync_channel(1);
    let mut h = Harness {
        input: None,
        output,
        kernel,
        worker: Some(worker),
        seen: vec![],
        next_request: 0,
    };
    // Declared after the guard: on assertion failure the socket closes before
    // Harness releases its simulated cleanup barriers and joins the controller.
    let mut client = BufReader::new(client);
    crate::helper::protocol::write_request(
        client.get_mut(),
        &Request {
            id: "socket-connect".into(),
            command: Command::Connect {
                id: "one".into(),
                generation: 1,
                interval: ProbeInterval::TEN,
                credentials: Credentials {
                    password: "fixture-password".into(),
                    psk: "".into(),
                },
            },
        },
    )
    .unwrap();
    h.started("one", 1);
    h.control("one", 1, |c| {
        c.ready = true;
        c.responsive = true;
    });
    loop {
        let message = read_message(&mut client).unwrap().unwrap();
        if matches!(
            message,
            Message::Changed {
                state: ConnectionState::Connected,
                ..
            }
        ) {
            break;
        }
    }
    h.kernel.lock().unwrap().retired_pending = true;
    client.get_mut().shutdown(Shutdown::Write).unwrap();
    h.control("one", 1, |c| c.cleanup_allowed = true);
    h.wait(|h| {
        h.kernel
            .lock()
            .unwrap()
            .attempts
            .values()
            .all(|c| c.finished)
    });
    h.wait(|h| {
        h.kernel.lock().unwrap().retirement_observed || h.worker.as_ref().unwrap().is_finished()
    });
    assert!(
        !h.worker.as_ref().unwrap().is_finished(),
        "socket EOF cannot release pending retirement"
    );
    h.kernel.lock().unwrap().retired_pending = false;
    h.finish();
    assert!(read_message(&mut client).unwrap().is_none());
}

#[path = "engine/capabilities_tests.rs"]
mod capabilities_tests;

#[cfg(target_os = "macos")]
#[test]
fn idle_helper_process_fixture() {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    let Some(root) = std::env::var_os("VPNT_IDLE_HELPER_FIXTURE") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let uid = unsafe { libc::geteuid() };
    let _signals = crate::helper::ppp_supervisor::signals::Guard::install().unwrap();
    let _lock = crate::helper::controller_lock::ControllerLock::fixture(&root, uid).unwrap();
    // The parent gives this process exclusive ownership of the fixture channel on fd 0.
    let server = UnixStream::from(unsafe { OwnedFd::from_raw_fd(0) });
    let kernel = Arc::new(Mutex::new(Kernel::default()));
    let routes = Arc::new(Mutex::new(Coordinator::new(Table(kernel.clone())).unwrap()));
    let fixture = Fixture {
        uid,
        kernel,
        routes,
    };
    let result = crate::helper::server::runtime_fixture(server, |actual, requests, output| {
        run(
            fixture,
            actual,
            vec![],
            requests,
            output,
            Timing {
                connect: Duration::from_secs(5),
                probe: Duration::from_secs(1),
                interval: Duration::from_secs(60),
                health: Duration::from_millis(2),
                poll: Duration::from_millis(2),
            },
        )
    });
    assert!(result.is_ok(), "idle server fixture failed: {result:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn idle_helper_releases_lock_after_eof_and_sigterm() {
    use std::{
        net::Shutdown,
        os::{
            fd::OwnedFd,
            unix::{
                fs::{OpenOptionsExt, PermissionsExt},
                net::UnixStream,
            },
        },
        process::{Child, Stdio},
    };
    fn identity(pid: u32) -> Option<Vec<u8>> {
        let output = ProcessCommand::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart=,comm="])
            .output()
            .ok()?;
        (output.status.success() && !output.stdout.is_empty()).then_some(output.stdout)
    }
    struct FixtureProcess {
        child: Child,
        client: UnixStream,
        identity: Vec<u8>,
        root: std::path::PathBuf,
    }
    impl FixtureProcess {
        fn terminate(&self) {
            if identity(self.child.id()).as_ref() == Some(&self.identity) {
                // Only the child spawned by this fixture, after checking start time and command.
                unsafe {
                    libc::kill(self.child.id() as i32, libc::SIGTERM);
                }
            }
        }
        fn exited(&mut self, budget: Duration) -> bool {
            let deadline = Instant::now() + budget;
            loop {
                if self.child.try_wait().unwrap().is_some() {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            let _ = self.client.shutdown(Shutdown::Write);
            if !self.exited(Duration::from_millis(200)) {
                self.terminate();
            }
            if self.exited(Duration::from_secs(3)) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
    }
    for signal in [false, true] {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!("idle-helper-{}-{signal}", std::process::id()));
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(".controller.lock"))
            .unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "connection::controller::engine::tests::idle_helper_process_fixture",
                "--nocapture",
            ])
            .env("VPNT_IDLE_HELPER_FIXTURE", &root)
            .stdin(Stdio::from(OwnedFd::from(server)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        let recorded = identity(child.id()).expect("ps must capture this fixture child identity");
        let mut fixture = FixtureProcess {
            child,
            client,
            identity: recorded,
            root,
        };
        crate::helper::protocol::write_request(
            &mut fixture.client,
            &Request {
                id: "idle-test".into(),
                command: Command::Snapshot {},
            },
        )
        .unwrap();
        let mut reader = BufReader::new(fixture.client.try_clone().unwrap());
        assert!(matches!(
            read_message(&mut reader),
            Ok(Some(Message::Snapshot { .. }))
        ));
        let uid = unsafe { libc::geteuid() };
        assert!(matches!(
            crate::helper::controller_lock::ControllerLock::fixture(&fixture.root, uid),
            Err(crate::helper::controller_lock::LockError::Busy)
        ));
        let start = Instant::now();
        if signal {
            fixture.terminate();
        } else {
            fixture.client.shutdown(Shutdown::Write).unwrap();
        }
        assert!(
            fixture.exited(Duration::from_secs(2)),
            "idle fixture must exit on {} within 2s",
            if signal { "SIGTERM" } else { "EOF" }
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            crate::helper::controller_lock::ControllerLock::fixture(&fixture.root, uid).is_ok()
        );
    }
}

/// A cleanup call that stays in flight until the test opens it, so the worker
/// can neither finish nor reach its own budget check.
#[derive(Default)]
struct InFlight {
    open: Mutex<bool>,
    wake: std::sync::Condvar,
    entered: AtomicBool,
    active: AtomicBool,
}
impl InFlight {
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.wake.notify_all();
    }
    fn entered(&self) {
        let until = Instant::now() + Duration::from_secs(3);
        while !self.entered.load(Ordering::Acquire) {
            assert!(Instant::now() < until, "cleanup never started");
            thread::sleep(Duration::from_millis(2));
        }
    }
}
struct InFlightFactory(Arc<InFlight>);
struct InFlightAttempt(Arc<InFlight>);
impl Attempt for InFlightAttempt {
    fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
        Ok(())
    }
    fn ready(&mut self) -> Result<bool, Failure> {
        Ok(false)
    }
    fn healthy(&mut self) -> Result<(), Failure> {
        Ok(())
    }
    fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
        Ok(false)
    }
    fn cleanup(&mut self) -> bool {
        self.0.entered.store(true, Ordering::Release);
        // Bounded so a broken watchdog fails the test instead of hanging it.
        let until = Instant::now() + Duration::from_secs(10);
        let mut open = self.0.open.lock().unwrap();
        while !*open && Instant::now() < until {
            open = self
                .0
                .wake
                .wait_timeout(open, Duration::from_millis(50))
                .unwrap()
                .0;
        }
        self.0.active.store(false, Ordering::Release);
        true
    }
}
impl Factory for InFlightFactory {
    type Attempt = InFlightAttempt;
    fn create(
        &self,
        _: Profile,
        _: u32,
        _: u64,
        _: Credentials,
        _: Arc<AtomicBool>,
    ) -> InFlightAttempt {
        self.0.active.store(true, Ordering::Release);
        InFlightAttempt(self.0.clone())
    }
    fn idle(&self) -> bool {
        !self.0.active.load(Ordering::Acquire)
    }
    fn unjournaled(&self) -> bool {
        true
    }
}
/// Runs the engine with an injected deadline whose action records when it
/// fired, then puts one generation in cleanup and waits for the call to start.
struct InFlightEngine {
    hold: Arc<InFlight>,
    input: mpsc::SyncSender<Request>,
    fires: mpsc::Receiver<(Instant, bool)>,
    engine: JoinHandle<Result<(), ErrorCode>>,
}
fn in_flight_engine(budget: Duration, margin: Duration) -> InFlightEngine {
    let hold = Arc::new(InFlight::default());
    let (fired, fires) = mpsc::channel();
    let deadline = Deadline::new(
        Arc::new(ExitRequested::new(budget)),
        margin,
        move |unjournaled| {
            let _ = fired.send((Instant::now(), unjournaled));
        },
    );
    let (input, requests) = mpsc::sync_channel(8);
    let (output, replies) = mpsc::sync_channel(64);
    let factory = InFlightFactory(hold.clone());
    let engine = thread::spawn(move || {
        // Replies are drained so a full pipe never closes the engine early.
        let drain = thread::spawn(move || while replies.recv().is_ok() {});
        let result = run_with_exit(
            factory,
            unsafe { libc::geteuid() }.max(1),
            vec![profile("one")],
            requests,
            output,
            Timing {
                connect: Duration::from_secs(5),
                probe: Duration::from_secs(1),
                interval: Duration::from_secs(60),
                health: Duration::from_millis(2),
                poll: Duration::from_millis(2),
            },
            deadline,
        );
        let _ = drain.join();
        result
    });
    input
        .send(Request {
            id: "connect".into(),
            command: Command::Connect {
                id: "one".into(),
                generation: 1,
                interval: ProbeInterval::TEN,
                credentials: Credentials {
                    password: Secret::from("fixture-password"),
                    psk: Secret::from(""),
                },
            },
        })
        .unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while !hold.active.load(Ordering::Acquire) {
        assert!(Instant::now() < until, "attempt never created");
        thread::sleep(Duration::from_millis(2));
    }
    input
        .send(Request {
            id: "disconnect".into(),
            command: Command::Disconnect {
                id: "one".into(),
                generation: 2,
            },
        })
        .unwrap();
    hold.entered();
    InFlightEngine {
        hold,
        input,
        fires,
        engine,
    }
}

#[test]
fn exit_watchdog_fires_at_its_deadline_only_after_an_exit_request() {
    let (budget, margin) = (Duration::from_millis(150), Duration::from_millis(150));
    let InFlightEngine {
        hold,
        input,
        fires,
        engine,
    } = in_flight_engine(budget, margin);
    struct Open(Arc<InFlight>);
    impl Drop for Open {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let _open = Open(hold.clone());
    // No exit request: a cleanup in flight past budget + margin never fires.
    assert!(
        fires
            .recv_timeout(budget + margin + Duration::from_millis(300))
            .is_err(),
        "the watchdog fired without an exit request"
    );
    assert!(!engine.is_finished());
    // EOF is the exit request; the cleanup call is still in flight.
    let requested = Instant::now();
    drop(input);
    let (fired, unjournaled) = fires
        .recv_timeout(Duration::from_secs(3))
        .expect("the watchdog never fired with the cleanup in flight");
    let elapsed = fired.duration_since(requested);
    eprintln!("deadline_elapsed={elapsed:?}");
    assert!(elapsed >= budget + margin, "fired early: {elapsed:?}");
    assert!(
        elapsed < budget + margin + Duration::from_millis(500),
        "fired late: {elapsed:?}"
    );
    assert!(unjournaled, "the action receives Factory::unjournaled");
    assert!(!engine.is_finished(), "the engine had not returned");
    hold.release();
    assert_eq!(engine.join().unwrap(), Ok(()));
    assert!(fires.try_recv().is_err(), "the watchdog fires at most once");
}

#[test]
fn exit_watchdog_stops_when_the_engine_returns_first() {
    let (budget, margin) = (Duration::from_millis(100), Duration::from_millis(900));
    let InFlightEngine {
        hold,
        input,
        fires,
        engine,
    } = in_flight_engine(budget, margin);
    let requested = Instant::now();
    drop(input);
    thread::sleep(Duration::from_millis(20));
    hold.release();
    assert_eq!(engine.join().unwrap(), Ok(()));
    // The scope joined the watchdog long before its deadline.
    assert!(requested.elapsed() < budget + margin);
    assert!(
        fires
            .recv_timeout(budget + margin + Duration::from_millis(300))
            .is_err(),
        "the watchdog fired after the engine returned"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn stuck_helper_process_fixture() {
    use std::os::{
        fd::{FromRawFd, OwnedFd},
        unix::net::UnixStream,
    };
    let Some(root) = std::env::var_os("VPNT_STUCK_HELPER_FIXTURE") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    struct StuckFactory {
        root: std::path::PathBuf,
        active: Arc<AtomicBool>,
        persist_fails: bool,
    }
    struct StuckAttempt {
        root: std::path::PathBuf,
        active: Arc<AtomicBool>,
        persist_fails: bool,
    }
    impl Attempt for StuckAttempt {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            std::fs::write(self.root.join("started"), b"1").unwrap();
            Ok(())
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            Ok(false)
        }
        fn healthy(&mut self) -> Result<(), Failure> {
            Ok(())
        }
        fn probe(&mut self, _: &AtomicBool, _: Duration) -> Result<bool, Failure> {
            Ok(false)
        }
        fn cleanup(&mut self) -> bool {
            crate::helper::runtime::cleanup::begin();
            if !self.persist_fails {
                crate::helper::runtime::cleanup::mark(Reason::RouteOwner);
            }
            std::fs::write(self.root.join("cleaning"), b"1").unwrap();
            if self.root.join("allow-cleanup").exists() {
                self.active.store(false, Ordering::Release);
                true
            } else {
                false
            }
        }
        fn abandon(&mut self, reason: Reason) -> Result<(), AbandonError> {
            std::fs::write(self.root.join("abandoned"), format!("{reason:?}")).unwrap();
            if self.persist_fails {
                return Err(AbandonError::Persist);
            }
            self.active.store(false, Ordering::Release);
            Ok(())
        }
    }
    impl Factory for StuckFactory {
        type Attempt = StuckAttempt;
        fn create(
            &self,
            _: Profile,
            _: u32,
            _: u64,
            _: Credentials,
            _: Arc<AtomicBool>,
        ) -> Self::Attempt {
            self.active.store(true, Ordering::Release);
            StuckAttempt {
                root: self.root.clone(),
                active: self.active.clone(),
                persist_fails: self.persist_fails,
            }
        }
        fn idle(&self) -> bool {
            !self.active.load(Ordering::Acquire)
        }
    }
    let uid = unsafe { libc::geteuid() };
    let _signals = crate::helper::ppp_supervisor::signals::Guard::install().unwrap();
    let _lock = crate::helper::controller_lock::ControllerLock::fixture(&root, uid).unwrap();
    let server = UnixStream::from(unsafe { OwnedFd::from_raw_fd(0) });
    let fixture = StuckFactory {
        root: root.clone(),
        active: Arc::new(AtomicBool::new(false)),
        persist_fails: std::env::var_os("VPNT_STUCK_PERSIST").is_some(),
    };
    let exit = Arc::new(ExitRequested::new(Duration::from_millis(300)));
    // The real `_exit(DEADLINE_EXIT)`, with its line in the fixture's log.
    let deadline = match std::env::var("VPNT_STUCK_DEADLINE_MS") {
        Ok(margin) => {
            let (root, margin) = (root.clone(), margin.parse().unwrap());
            Deadline::new(exit, Duration::from_millis(margin), move |unjournaled| {
                crate::helper::runtime::cleanup::deadline_at(&root, uid, unjournaled).unwrap();
                crate::helper::fd_guard::deadline_exit()
            })
        }
        Err(_) => Deadline::process(exit),
    };
    let result = crate::helper::server::runtime_fixture(server, |actual, requests, output| {
        run_with_exit(
            fixture,
            actual,
            vec![profile("one")],
            requests,
            output,
            Timing {
                connect: Duration::from_secs(5),
                probe: Duration::from_secs(1),
                interval: Duration::from_secs(60),
                health: Duration::from_millis(2),
                poll: Duration::from_millis(2),
            },
            deadline,
        )
    });
    assert!(result.is_ok(), "stuck helper fixture failed: {result:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn stuck_helper_exit_budget_preserves_lock_on_write_failure() {
    use std::{
        net::Shutdown,
        os::{
            fd::OwnedFd,
            unix::{
                fs::{OpenOptionsExt, PermissionsExt},
                net::UnixStream,
            },
        },
        process::{Child, Stdio},
    };
    fn identity(pid: u32) -> Option<Vec<u8>> {
        let output = ProcessCommand::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart=,comm="])
            .output()
            .ok()?;
        (output.status.success() && !output.stdout.is_empty()).then_some(output.stdout)
    }
    struct ProcessFixture {
        child: Child,
        identity: Vec<u8>,
        client: UnixStream,
        root: std::path::PathBuf,
    }
    impl ProcessFixture {
        fn signal(&self) {
            if identity(self.child.id()).as_ref() == Some(&self.identity) {
                unsafe {
                    libc::kill(self.child.id() as i32, libc::SIGTERM);
                }
            } else {
                panic!("fixture child identity changed before SIGTERM");
            }
        }
        fn exited(&mut self, timeout: Duration) -> bool {
            let until = Instant::now() + timeout;
            loop {
                if self.child.try_wait().unwrap().is_some() {
                    return true;
                }
                if Instant::now() >= until {
                    return false;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        /// Markers are written by create-and-truncate, then write; an empty
        /// read is not the marker yet. Returns the content it saw.
        fn wait_marker(&self, name: &str, timeout: Duration) -> String {
            let until = Instant::now() + timeout;
            loop {
                if let Ok(text) = std::fs::read_to_string(self.root.join(name))
                    && !text.is_empty()
                {
                    return text;
                }
                assert!(Instant::now() < until, "fixture marker {name} timed out");
                thread::sleep(Duration::from_millis(5));
            }
        }
        fn lock_busy(&self) -> bool {
            let uid = unsafe { libc::geteuid() };
            matches!(
                crate::helper::controller_lock::ControllerLock::fixture(&self.root, uid),
                Err(crate::helper::controller_lock::LockError::Busy)
            )
        }
    }
    impl Drop for ProcessFixture {
        fn drop(&mut self) {
            let _ = std::fs::write(self.root.join("allow-cleanup"), b"1");
            let _ = self.client.shutdown(Shutdown::Write);
            if !self.exited(Duration::from_secs(3))
                && identity(self.child.id()).as_ref() == Some(&self.identity)
            {
                unsafe {
                    libc::kill(self.child.id() as i32, libc::SIGTERM);
                }
            }
            if self.exited(Duration::from_secs(3)) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }
    }
    for (signal, persist_fails, stuck) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "stuck-helper-{}-{signal}-{persist_fails}-{stuck}",
                std::process::id()
            ));
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(".controller.lock"))
            .unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let mut command = ProcessCommand::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "connection::controller::engine::tests::stuck_helper_process_fixture",
                "--nocapture",
            ])
            .env("VPNT_STUCK_HELPER_FIXTURE", &root)
            .stdin(Stdio::from(OwnedFd::from(server)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if persist_fails {
            command.env("VPNT_STUCK_PERSIST", "1");
        }
        if stuck {
            command.env("VPNT_STUCK_DEADLINE_MS", "400");
        }
        let child = command.spawn().unwrap();
        let recorded = identity(child.id()).expect("ps must capture the fixture child identity");
        let mut f = ProcessFixture {
            child,
            identity: recorded,
            client,
            root,
        };
        crate::helper::protocol::write_request(
            &mut f.client,
            &Request {
                id: "connect".into(),
                command: Command::Connect {
                    id: "one".into(),
                    generation: 1,
                    interval: ProbeInterval::TEN,
                    credentials: Credentials {
                        password: Secret::from("fixture-password"),
                        psk: Secret::from(""),
                    },
                },
            },
        )
        .unwrap();
        f.wait_marker("started", Duration::from_secs(3));
        crate::helper::protocol::write_request(
            &mut f.client,
            &Request {
                id: "disconnect".into(),
                command: Command::Disconnect {
                    id: "one".into(),
                    generation: 2,
                },
            },
        )
        .unwrap();
        f.wait_marker("cleaning", Duration::from_secs(3));
        assert!(f.lock_busy());
        thread::sleep(Duration::from_millis(450));
        assert!(
            !f.root.join("abandoned").exists(),
            "cleanup without an exit request must not abandon"
        );
        let start = Instant::now();
        if signal {
            f.signal();
        } else {
            f.client.shutdown(Shutdown::Write).unwrap();
        }
        let abandoned = f.wait_marker("abandoned", Duration::from_secs(3));
        assert_eq!(
            abandoned,
            if persist_fails {
                "UncertainCleanup"
            } else {
                "RouteOwner"
            }
        );
        assert!(
            start.elapsed() >= Duration::from_millis(300),
            "abandoned before budget"
        );
        if persist_fails {
            assert!(
                !f.exited(Duration::from_millis(150)),
                "write failure released the helper"
            );
            assert!(f.lock_busy(), "write failure released the lock");
        }
        if stuck {
            // The cleanup never finishes: only the watchdog ends the helper,
            // at request + 300 ms budget + 400 ms margin.
            let until = Instant::now() + Duration::from_secs(3);
            let status = loop {
                if let Some(status) = f.child.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    Instant::now() < until,
                    "the watchdog never ended the helper"
                );
                thread::sleep(Duration::from_millis(5));
            };
            let elapsed = start.elapsed();
            eprintln!("stuck_exit={:?} elapsed={elapsed:?}", status.code());
            assert_eq!(status.code(), Some(crate::helper::fd_guard::DEADLINE_EXIT));
            assert!(elapsed >= Duration::from_millis(700), "{elapsed:?}");
            let log = std::fs::read_to_string(crate::helper::paths::cleanup_log(&f.root)).unwrap();
            assert!(log.ends_with(" exit=deadline unjournaled=no\n"), "{log}");
        } else if persist_fails {
            std::fs::write(f.root.join("allow-cleanup"), b"1").unwrap();
        }
        assert!(
            f.exited(Duration::from_secs(3)),
            "helper did not exit after {}",
            if signal { "SIGTERM" } else { "EOF" }
        );
        assert!(start.elapsed() < Duration::from_secs(5));
        let uid = unsafe { libc::geteuid() };
        assert!(crate::helper::controller_lock::ControllerLock::fixture(&f.root, uid).is_ok());
    }
}
