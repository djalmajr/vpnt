use super::*;
use crate::{
    connection::routes::{
        Backend, Coordinator, Error, Key, Lease, Owner, Presence, Route, ppp_networks,
    },
    helper::{
        process::ManagedChild,
        protocol::{parse_request, read_message, write_message},
    },
    secrets::Secret,
};
use std::{
    io::BufReader,
    process::Command as ProcessCommand,
    sync::{Mutex, mpsc},
    thread::JoinHandle,
    time::Instant,
};

#[derive(Default)]
struct Control {
    started: bool,
    ready: bool,
    responsive: bool,
    hold_probe: bool,
    probed: bool,
    invalidate_after_probe: bool,
    invalid: bool,
    cleanup_allowed: bool,
    cleanup_calls: usize,
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
    fn start(&mut self, _: &AtomicBool) -> Result<(), Failure> {
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
}

struct Harness {
    input: Option<SyncSender<Request>>,
    output: Receiver<Message>,
    kernel: Shared,
    worker: Option<JoinHandle<Result<(), ErrorCode>>>,
    seen: Vec<Message>,
    next_request: usize,
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
        self.seen.iter().any(|message| matches!(message, Message::Changed { profile_id, generation: g, state: s } if profile_id==id && *g==generation && *s==state))
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
