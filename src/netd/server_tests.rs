use super::*;
use crate::netd::iproute::Existing;
use crate::netd::protocol::{Config, decode_response};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

type Pause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

#[derive(Default)]
pub(in crate::netd) struct Fake {
    pub(in crate::netd) events: Mutex<Vec<String>>,
    names: Mutex<HashSet<TunName>>,
    foreign: Mutex<HashSet<TunName>>,
    unmarked: Mutex<HashMap<TunName, (NonZeroU32, bool)>>,
    partial_create: Mutex<Option<NonZeroU32>>,
    fail_delete: AtomicBool,
    fail_all_deletes: AtomicBool,
    fail_delete_for: Mutex<Option<TunName>>,
    failed_delete_times: Mutex<Vec<Instant>>,
    inventory_calls: AtomicUsize,
    fail_inventory_call: AtomicUsize,
    slow_inventory_calls: AtomicUsize,
    conflict: AtomicBool,
    fail_create: AtomicBool,
    fail_configure: AtomicBool,
    pause_create: Mutex<Option<Pause>>,
    pause_inventory: Mutex<Option<Pause>>,
    pause_delete: Mutex<Option<Pause>>,
}
impl Backend for Arc<Fake> {
    fn create_tun(&self, name: &TunName, owner: u32) -> io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(format!("create {name} {owner}"));
        if self.fail_create.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("private input"));
        }
        if let Some(ifindex) = self.partial_create.lock().unwrap().take() {
            self.unmarked
                .lock()
                .unwrap()
                .insert(name.clone(), (ifindex, true));
            return Err(io::Error::other(PartialCreate {
                ifindex,
                alias: io::Error::other("alias failed"),
                rollback: io::Error::other("rollback failed"),
            }));
        }
        let pause = self.pause_create.lock().unwrap().take();
        if let Some((started, resume)) = pause {
            started.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        assert!(self.names.lock().unwrap().insert(name.clone()));
        Ok(())
    }
    fn configure(&self, config: &Config) -> io::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(format!("configure {}", config.name));
        if self.conflict.swap(false, Ordering::SeqCst) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if self.fail_configure.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("private input"));
        }
        Ok(())
    }
    fn delete_tun(&self, name: &TunName) -> io::Result<()> {
        self.events.lock().unwrap().push(format!("delete {name}"));
        if self.fail_all_deletes.load(Ordering::SeqCst) {
            self.failed_delete_times
                .lock()
                .unwrap()
                .push(Instant::now());
            return Err(io::Error::other("delete failed"));
        }
        if self.fail_delete.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("delete failed"));
        }
        if self.fail_delete_for.lock().unwrap().as_ref() == Some(name) {
            return Err(io::Error::other("delete failed"));
        }
        let pause = self.pause_delete.lock().unwrap().take();
        if let Some((started, resume)) = pause {
            let _ = started.send(());
            resume
                .recv_timeout(Duration::from_secs(2))
                .map_err(io::Error::other)?;
        }
        self.names.lock().unwrap().remove(name);
        self.foreign.lock().unwrap().remove(name);
        self.unmarked.lock().unwrap().remove(name);
        Ok(())
    }
    fn existing(&self) -> io::Result<Vec<Existing>> {
        let call = self.inventory_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_inventory_call.load(Ordering::SeqCst) {
            return Err(io::Error::other("inventory failed"));
        }
        let pause = self.pause_inventory.lock().unwrap().take();
        if let Some((started, resume)) = pause {
            started.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        if call <= self.slow_inventory_calls.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(3));
        }
        let owned = self.names.lock().unwrap().clone();
        let foreign = self.foreign.lock().unwrap().clone();
        Ok(owned
            .into_iter()
            .map(|name| Existing {
                name,
                owned: true,
                ifindex: NonZeroU32::MIN,
                is_tun: true,
            })
            .chain(foreign.into_iter().map(|name| Existing {
                name,
                owned: false,
                ifindex: NonZeroU32::MIN,
                is_tun: false,
            }))
            .chain(
                self.unmarked
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(name, (ifindex, is_tun))| Existing {
                        name: name.clone(),
                        owned: false,
                        ifindex: *ifindex,
                        is_tun: *is_tun,
                    }),
            )
            .collect())
    }
}

pub(in crate::netd) struct Fixture {
    pub(in crate::netd) path: PathBuf,
    listener: UnixListener,
    pub(in crate::netd) server: Arc<Server<Arc<Fake>>>,
    pub(in crate::netd) fake: Arc<Fake>,
}
impl Fixture {
    pub(in crate::netd) fn new(timeout: Duration) -> Self {
        Self::with_timeouts(timeout, IDLE_TIMEOUT, FRAME_TIMEOUT)
    }
    fn with_timeouts(hello: Duration, idle: Duration, frame: Duration) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "vpnt-netd-session-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let path = directory.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let fake = Arc::new(Fake::default());
        let mut server = Server::new(Arc::clone(&fake), hello);
        server.network_directory = Some(directory);
        server.idle_timeout = idle;
        server.frame_timeout = frame;
        let server = Arc::new(server);
        Self {
            path,
            listener,
            fake,
            server,
        }
    }
    fn network_lock(&self) -> NetworkGuard {
        self.server
            .network_lock(self.server.lock_deadline())
            .unwrap()
    }
    pub(in crate::netd) fn accept(&self, uid: u32) -> Option<thread::JoinHandle<()>> {
        self.server
            .dispatch(self.listener.accept().unwrap().0, move |_| Ok(uid))
    }
    fn connection(&self, uid: u32) -> (BufReader<UnixStream>, Option<thread::JoinHandle<()>>) {
        let stream = UnixStream::connect(&self.path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        (BufReader::new(stream), self.accept(uid))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.path.parent().unwrap());
    }
}
type Wire = BufReader<UnixStream>;
const HELLO: &str = "{\"op\":\"hello\",\"version\":1}\n";
const OPEN: &str = "{\"op\":\"open_tun\"}\n";
fn exchange(wire: &mut Wire, request: &str) -> Response {
    wire.get_mut().write_all(request.as_bytes()).unwrap();
    response(wire)
}
fn response(wire: &mut Wire) -> Response {
    decode_response(&read_line(wire).unwrap()).unwrap()
}
fn assert_waiting(wire: &mut Wire) {
    let stream = wire.get_ref();
    let previous = stream.read_timeout().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let result = read_line(wire);
    wire.get_ref().set_read_timeout(previous).unwrap();
    assert!(
        matches!(&result, Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
        "{result:?}"
    );
}
fn hello(wire: &mut Wire) {
    assert!(matches!(exchange(wire, HELLO), Response::Version(1)));
}
fn open(wire: &mut Wire, expected: &str) {
    let Response::Opened(name) = exchange(wire, OPEN) else {
        panic!("expected opened")
    };
    assert_eq!(name.as_str(), expected);
}
pub(in crate::netd) fn configure(name: &str) -> String {
    format!(
        "{{\"op\":\"configure\",\"ifname\":\"{name}\",\"address\":\"10.1.2.3\",\"prefix\":24,\"routes\":[],\"dns\":{{\"servers\":[],\"domains\":[]}}}}\n"
    )
}
#[test]
fn hello_is_mandatory_and_version_checked() {
    let f = Fixture::new(HELLO_TIMEOUT);
    for (request, code) in [
        (OPEN, ErrorCode::BadRequest),
        (
            "{\"op\":\"hello\",\"version\":2}\n",
            ErrorCode::UnsupportedVersion,
        ),
    ] {
        let (mut wire, thread) = f.connection(1000);
        assert!(matches!(exchange(&mut wire, request), Response::Error(actual) if actual == code));
        assert!(read_line(&mut wire).unwrap().is_empty());
        thread.unwrap().join().unwrap();
    }
}
#[test]
fn admission_rejects_root() {
    assert_eq!(admit(0), Err(ErrorCode::NotOwned));
    assert_eq!(admit(1000), Ok(()));
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, thread) = f.connection(0);
    assert!(matches!(
        decode_response(&read_line(&mut wire).unwrap()).unwrap(),
        Response::Error(ErrorCode::NotOwned)
    ));
    assert!(read_line(&mut wire).unwrap().is_empty());
    thread.unwrap().join().unwrap();
}
#[test]
fn reservations_ownership_limit_and_disconnect() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut a, a_thread) = f.connection(1000);
    let (mut b, b_thread) = f.connection(1001);
    hello(&mut a);
    hello(&mut b);
    open(&mut a, "vpnt0");
    open(&mut b, "vpnt1");
    open(&mut a, "vpnt2");
    assert!(matches!(
        exchange(&mut a, OPEN),
        Response::Error(ErrorCode::Limit)
    ));
    assert!(matches!(
        exchange(&mut b, &configure("vpnt0")),
        Response::Error(ErrorCode::NotOwned)
    ));
    assert!(matches!(
        exchange(&mut b, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Error(ErrorCode::NotOwned)
    ));
    assert_eq!(
        *f.fake.events.lock().unwrap(),
        [
            "create vpnt0 1000",
            "create vpnt1 1001",
            "create vpnt2 1000"
        ]
    );
    drop(a);
    a_thread.unwrap().join().unwrap();
    assert_eq!(
        &f.fake.events.lock().unwrap()[3..],
        ["delete vpnt0", "delete vpnt2"]
    );
    open(&mut b, "vpnt0");
    drop(b);
    b_thread.unwrap().join().unwrap();
    assert!(f.fake.names.lock().unwrap().is_empty());
}
#[test]
fn startup_cleans_existing_and_allocator_skips_existing() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let owned = TunName::parse("vpnt7").unwrap();
    let foreign = TunName::parse("vpnt0").unwrap();
    f.fake.names.lock().unwrap().insert(owned.clone());
    f.fake.foreign.lock().unwrap().insert(foreign.clone());
    f.server.startup().unwrap();
    assert_eq!(*f.fake.events.lock().unwrap(), ["delete vpnt7"]);
    assert!(!f.fake.names.lock().unwrap().contains(&owned));
    assert!(f.fake.foreign.lock().unwrap().contains(&foreign));
    let (mut wire, thread) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt1");
    drop(wire);
    thread.unwrap().join().unwrap();
}
#[test]
fn backend_failures_are_generic_and_create_releases_name() {
    let f = Fixture::new(HELLO_TIMEOUT);
    f.fake.fail_create.store(true, Ordering::SeqCst);
    let (mut wire, thread) = f.connection(1000);
    hello(&mut wire);
    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    assert_eq!(
        read_line(&mut wire).unwrap(),
        b"{\"ok\":false,\"error\":\"backend\"}\n"
    );
    open(&mut wire, "vpnt0");
    f.fake.fail_configure.store(true, Ordering::SeqCst);
    assert!(matches!(
        exchange(&mut wire, &configure("vpnt0")),
        Response::Error(ErrorCode::Backend)
    ));
    assert!(matches!(
        exchange(&mut wire, &configure("vpnt0")),
        Response::Ok
    ));
    drop(wire);
    thread.unwrap().join().unwrap();
    assert!(f.fake.names.lock().unwrap().is_empty());
}
#[test]
fn malformed_frames_reply_then_disconnect() {
    let f = Fixture::new(HELLO_TIMEOUT);
    for line in [
        format!("{}\n", " ".repeat(crate::netd::protocol::MAX_LINE)).into_bytes(),
        b"\xff\n".to_vec(),
        b"{}\n".to_vec(),
    ] {
        let (mut wire, thread) = f.connection(1000);
        hello(&mut wire);
        wire.get_mut().write_all(&line).unwrap();
        assert!(matches!(
            decode_response(&read_line(&mut wire).unwrap()).unwrap(),
            Response::Error(ErrorCode::BadRequest)
        ));
        // Unread overflow bytes can cause Linux to reset after sending the reply.
        match read_line(&mut wire) {
            Ok(line) => assert!(line.is_empty()),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::ConnectionReset),
        }
        thread.unwrap().join().unwrap();
    }
}
#[test]
fn ninth_connection_closes_and_hello_deadline_expires() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let connections: Vec<_> = (0..8)
        .map(|index| {
            let (mut wire, worker) = f.connection(1000 + index);
            hello(&mut wire);
            (wire, worker.unwrap())
        })
        .collect();
    let (mut ninth, worker) = f.connection(1008);
    assert!(worker.is_none());
    assert!(read_line(&mut ninth).unwrap().is_empty());
    for (wire, worker) in connections {
        drop(wire);
        worker.join().unwrap();
    }
    let f = Fixture::new(Duration::from_millis(40));
    let (mut idle, worker) = f.connection(1000);
    assert!(read_line(&mut idle).unwrap().is_empty());
    worker.unwrap().join().unwrap();
}
#[test]
fn development_arguments_are_exact() {
    let parse = |args: &[&str], activation| {
        mode(
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            activation,
        )
    };
    assert_eq!(
        parse(
            &["--socket", "/run/dev.sock", "--socket-owner", "1000"],
            false
        ),
        Some(Mode::Development {
            path: "/run/dev.sock".into(),
            owner: 1000
        })
    );
    assert_eq!(parse(&[], true), Some(Mode::Activated));
    for args in [
        &[][..],
        &["--help"],
        &["--socket", "/run/dev.sock"],
        &["--socket", "", "--socket-owner", "0"],
        &["--socket", "/run/dev.sock", "--socket-owner", "-1"],
        &["--socket", "/run/dev.sock", "--socket-owner", "4294967295"],
    ] {
        assert_eq!(parse(args, false), None);
    }
}

#[test]
fn concurrent_open_waits_for_create_before_allocating_another_name() {
    use std::sync::mpsc::channel;
    let f = Fixture::new(HELLO_TIMEOUT);
    let (started, pending) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_create.lock().unwrap() = Some((started, proceed));
    let (mut a, a_thread) = f.connection(1000);
    let (mut b, b_thread) = f.connection(1001);
    hello(&mut a);
    hello(&mut b);
    a.get_mut().write_all(OPEN.as_bytes()).unwrap();
    pending.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(f.fake.names.lock().unwrap().is_empty());
    assert!(
        f.server
            .reserved
            .lock()
            .unwrap()
            .contains(&TunName::parse("vpnt0").unwrap())
    );
    b.get_mut().write_all(OPEN.as_bytes()).unwrap();
    assert_waiting(&mut b);
    let events = f.fake.events.lock().unwrap().clone();
    resume.send(()).unwrap();
    assert!(matches!(response(&mut a), Response::Opened(name) if name.as_str() == "vpnt0"));
    assert!(matches!(response(&mut b), Response::Opened(name) if name.as_str() == "vpnt1"));
    assert_eq!(events, ["create vpnt0 1000"]);
    drop((a, b));
    a_thread.unwrap().join().unwrap();
    b_thread.unwrap().join().unwrap();
    assert!(f.fake.names.lock().unwrap().is_empty());
}

#[test]
fn per_uid_quota_leaves_slots_for_other_uids() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut a, a_worker) = f.connection(1000);
    let (mut b, b_worker) = f.connection(1000);
    hello(&mut a);
    hello(&mut b);
    let (mut third, worker) = f.connection(1000);
    assert!(worker.is_none());
    assert!(read_line(&mut third).unwrap().is_empty());
    let (mut c, c_worker) = f.connection(1001);
    hello(&mut c);
    drop((a, b, c));
    for worker in [a_worker, b_worker, c_worker] {
        worker.unwrap().join().unwrap();
    }
    let (mut returned, worker) = f.connection(1000);
    hello(&mut returned);
    drop(returned);
    worker.unwrap().join().unwrap();
}

#[test]
fn idle_timeout_applies_only_without_tuns_and_rearms_on_last_close() {
    let idle = Duration::from_millis(150);
    let f = Fixture::with_timeouts(HELLO_TIMEOUT, idle, FRAME_TIMEOUT);
    let (mut waiting, worker) = f.connection(1000);
    hello(&mut waiting);
    let start = Instant::now();
    assert!(read_line(&mut waiting).unwrap().is_empty());
    assert!(start.elapsed() >= idle / 2);
    worker.unwrap().join().unwrap();

    let (mut live, worker) = f.connection(1000);
    hello(&mut live);
    open(&mut live, "vpnt0");
    thread::sleep(idle * 2);
    assert!(matches!(
        exchange(&mut live, &configure("vpnt0")),
        Response::Ok
    ));
    assert!(matches!(
        exchange(&mut live, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Ok
    ));
    let start = Instant::now();
    assert!(read_line(&mut live).unwrap().is_empty());
    assert!(start.elapsed() >= idle / 2);
    worker.unwrap().join().unwrap();
}

#[test]
fn partial_frames_expire_during_hello_and_when_tun_is_open() {
    let frame = Duration::from_millis(60);
    let f = Fixture::with_timeouts(Duration::from_secs(4), Duration::from_secs(4), frame);
    for with_tun in [false, true] {
        let (mut wire, worker) = f.connection(1000);
        if with_tun {
            hello(&mut wire);
            open(&mut wire, "vpnt0");
        }
        wire.get_mut().write_all(b"{").unwrap();
        let start = Instant::now();
        assert!(read_line(&mut wire).unwrap().is_empty());
        assert!(start.elapsed() >= frame / 2);
        worker.unwrap().join().unwrap();
        assert!(f.fake.names.lock().unwrap().is_empty());
    }
}

#[test]
fn route_conflict_is_distinct_and_preserves_session_ownership() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    f.fake.conflict.store(true, Ordering::SeqCst);
    wire.get_mut()
        .write_all(configure("vpnt0").as_bytes())
        .unwrap();
    assert_eq!(
        read_line(&mut wire).unwrap(),
        b"{\"ok\":false,\"error\":\"route_conflict\"}\n"
    );
    assert!(matches!(
        exchange(&mut wire, &configure("vpnt0")),
        Response::Ok
    ));
    drop(wire);
    worker.unwrap().join().unwrap();
}

#[test]
fn disconnect_failure_retries_on_accept_and_releases_name() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    let name = TunName::parse("vpnt0").unwrap();
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(f.server.pending.lock().unwrap().contains_key(&name));
    assert!(f.server.reserved.lock().unwrap().contains(&name));

    let (mut next, worker) = f.connection(1001);
    hello(&mut next);
    let deadline = Instant::now() + Duration::from_secs(2);
    while f.server.reserved.lock().unwrap().contains(&name) {
        assert!(Instant::now() < deadline, "accept did not finish cleanup");
        thread::yield_now();
    }
    assert!(f.fake.existing().unwrap().is_empty());
    assert_eq!(
        *f.fake.events.lock().unwrap(),
        ["create vpnt0 1000", "delete vpnt0", "delete vpnt0"]
    );
    open(&mut next, "vpnt0");
    drop(next);
    worker.unwrap().join().unwrap();
}

#[test]
fn open_retries_pending_and_never_deletes_missing_or_unmarked_interface() {
    for foreign in [false, true] {
        let f = Fixture::new(HELLO_TIMEOUT);
        let (mut wire, worker) = f.connection(1000);
        hello(&mut wire);
        open(&mut wire, "vpnt0");
        let (mut next, next_worker) = f.connection(1001);
        hello(&mut next);
        let name = TunName::parse("vpnt0").unwrap();
        f.fake.fail_delete.store(true, Ordering::SeqCst);
        drop(wire);
        worker.unwrap().join().unwrap();
        f.fake.names.lock().unwrap().remove(&name);
        if foreign {
            f.fake.foreign.lock().unwrap().insert(name.clone());
        }
        open(&mut next, if foreign { "vpnt1" } else { "vpnt0" });
        assert_eq!(
            f.fake
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event.as_str() == "delete vpnt0")
                .count(),
            1
        );
        assert_eq!(
            f.server.pending.lock().unwrap().contains_key(&name),
            foreign
        );
        assert_eq!(f.fake.foreign.lock().unwrap().contains(&name), foreign);
        drop(next);
        next_worker.unwrap().join().unwrap();
    }
}

#[test]
fn open_expires_without_creating_while_background_retry_holds_lock() {
    use std::sync::mpsc::channel;
    let mut f = Fixture::new(HELLO_TIMEOUT);
    Arc::get_mut(&mut f.server).unwrap().open_lock_timeout = Duration::from_millis(100);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    drop(wire);
    worker.unwrap().join().unwrap();
    let (started, arrived) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_delete.lock().unwrap() = Some((started, proceed));

    let (mut next, next_worker) = f.connection(1001);
    hello(&mut next);
    arrived.recv_timeout(Duration::from_secs(1)).unwrap();
    let denied = exchange(&mut next, OPEN);
    let events = f.fake.events.lock().unwrap().clone();
    resume.send(()).unwrap();
    let lock = f.network_lock();
    assert!(!ovpn_present(&f.fake).unwrap());
    drop(lock);
    assert!(
        matches!(denied, Response::Error(ErrorCode::Backend)),
        "{denied:?}"
    );
    assert_eq!(
        events,
        ["create vpnt0 1000", "delete vpnt0", "delete vpnt0"]
    );
    open(&mut next, "vpnt0");
    drop(next);
    next_worker.unwrap().join().unwrap();
    assert!(f.fake.existing().unwrap().is_empty());
}

fn failed_alias_and_rollback(f: &Fixture, ifindex: NonZeroU32) -> TunName {
    *f.fake.partial_create.lock().unwrap() = Some(ifindex);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    assert!(matches!(
        exchange(&mut wire, OPEN),
        Response::Error(ErrorCode::Backend)
    ));
    drop(wire);
    worker.unwrap().join().unwrap();
    let name = TunName::parse("vpnt0").unwrap();
    assert!(f.server.reserved.lock().unwrap().contains(&name));
    assert!(
        matches!(f.server.pending.lock().unwrap().get(&name), Some(CleanupProof::Created { ifindex: actual }) if *actual == ifindex)
    );
    name
}

#[test]
fn partially_created_tun_retries_on_next_accept_and_releases_name() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let name = failed_alias_and_rollback(&f, NonZeroU32::new(42).unwrap());
    assert!(!f.fake.existing().unwrap()[0].owned);

    let (mut next, worker) = f.connection(1001);
    hello(&mut next);
    let deadline = Instant::now() + Duration::from_secs(2);
    while f.server.reserved.lock().unwrap().contains(&name) {
        assert!(
            Instant::now() < deadline,
            "accept did not clean up the partial create"
        );
        thread::yield_now();
    }
    assert!(f.fake.existing().unwrap().is_empty());
    assert_eq!(
        *f.fake.events.lock().unwrap(),
        ["create vpnt0 1000", "delete vpnt0"]
    );
    open(&mut next, "vpnt0");
    drop(next);
    worker.unwrap().join().unwrap();
}

#[test]
fn partial_create_does_not_delete_a_replacement_link() {
    let original = NonZeroU32::new(42).unwrap();
    for replacement in [(NonZeroU32::new(43).unwrap(), true), (original, false)] {
        let f = Fixture::new(HELLO_TIMEOUT);
        let name = failed_alias_and_rollback(&f, original);
        f.fake
            .unmarked
            .lock()
            .unwrap()
            .insert(name.clone(), replacement);

        let (mut next, worker) = f.connection(1001);
        hello(&mut next);
        open(&mut next, "vpnt1");
        assert_eq!(
            *f.fake.events.lock().unwrap(),
            ["create vpnt0 1000", "create vpnt1 1001"]
        );
        assert!(f.server.reserved.lock().unwrap().contains(&name));
        assert!(f.server.pending.lock().unwrap().contains_key(&name));
        assert_eq!(f.fake.unmarked.lock().unwrap()[&name], replacement);
        drop(next);
        worker.unwrap().join().unwrap();
    }
}

#[test]
fn close_failure_retains_ownership_until_retry_succeeds() {
    struct End {
        stream: UnixStream,
        worker: Option<thread::JoinHandle<()>>,
    }
    impl Drop for End {
        fn drop(&mut self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    let _end = End {
        stream: wire.get_ref().try_clone().unwrap(),
        worker,
    };
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    let name = TunName::parse("vpnt0").unwrap();
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    assert!(matches!(
        exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Error(ErrorCode::Backend)
    ));
    assert!(!f.server.pending.lock().unwrap().contains_key(&name));
    assert!(f.server.reserved.lock().unwrap().contains(&name));
    assert!(matches!(
        exchange(&mut wire, &configure("vpnt0")),
        Response::Ok
    ));
    assert!(matches!(
        exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Ok
    ));
    assert!(f.fake.names.lock().unwrap().is_empty());
    assert!(!f.server.reserved.lock().unwrap().contains(&name));
}

#[test]
fn close_retry_refuses_to_delete_unmarked_replacement() {
    struct End {
        stream: UnixStream,
        worker: Option<thread::JoinHandle<()>>,
    }
    impl Drop for End {
        fn drop(&mut self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    let _end = End {
        stream: wire.get_ref().try_clone().unwrap(),
        worker,
    };
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    let name = TunName::parse("vpnt0").unwrap();
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    assert!(matches!(
        exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Error(ErrorCode::Backend)
    ));
    assert!(f.fake.names.lock().unwrap().remove(&name));
    assert!(f.fake.foreign.lock().unwrap().insert(name.clone()));
    assert!(matches!(
        exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Ok
    ));
    assert!(f.fake.foreign.lock().unwrap().contains(&name));
    assert!(!f.server.reserved.lock().unwrap().contains(&name));
    assert_eq!(
        f.fake
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| *event == "delete vpnt0")
            .count(),
        1
    );
}

#[test]
fn disconnect_after_failed_close_keeps_an_unmarked_replacement() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    let name = TunName::parse("vpnt0").unwrap();
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    assert!(matches!(
        exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Error(ErrorCode::Backend)
    ));
    f.fake.fail_delete.store(false, Ordering::SeqCst);
    assert!(f.fake.names.lock().unwrap().remove(&name));
    assert!(f.fake.foreign.lock().unwrap().insert(name.clone()));
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(f.fake.foreign.lock().unwrap().contains(&name));
    assert!(!f.server.reserved.lock().unwrap().contains(&name));
    assert_eq!(
        f.fake
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| *event == "delete vpnt0")
            .count(),
        1
    );
}

#[test]
fn disconnect_after_failed_close_deletes_our_marked_tun() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    let name = TunName::parse("vpnt0").unwrap();
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    assert!(matches!(
        exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n"),
        Response::Error(ErrorCode::Backend)
    ));
    f.fake.fail_delete.store(false, Ordering::SeqCst);
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(!f.fake.names.lock().unwrap().contains(&name));
    assert!(!f.server.reserved.lock().unwrap().contains(&name));
}

#[test]
fn close_retry_releases_a_missing_interface() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    let name = TunName::parse("vpnt0").unwrap();
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    let close = "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n";
    assert!(matches!(
        exchange(&mut wire, close),
        Response::Error(ErrorCode::Backend)
    ));
    assert!(f.fake.names.lock().unwrap().remove(&name));
    assert!(matches!(exchange(&mut wire, close), Response::Ok));
    assert!(!f.server.reserved.lock().unwrap().contains(&name));
    assert_eq!(
        f.fake
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| *event == "delete vpnt0")
            .count(),
        1
    );
    drop(wire);
    worker.unwrap().join().unwrap();
}

#[test]
fn open_refuses_a_registered_tunnel_before_create() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let registry = f.path.parent().unwrap().join("tunnel-leases");
    DirBuilder::new().mode(0o700).create(&registry).unwrap();
    fs::write(registry.join("test-tunnel"), []).unwrap();
    fs::set_permissions(
        registry.join("test-tunnel"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    let response = exchange(&mut wire, OPEN);
    let events = f.fake.events.lock().unwrap().clone();
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(
        matches!(response, Response::Error(ErrorCode::RouteConflict)),
        "{response:?}"
    );
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn open_refuses_an_insecure_registry_before_create() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let registry = f.path.parent().unwrap().join("tunnel-leases");
    DirBuilder::new().mode(0o700).create(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o755)).unwrap();
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    let response = exchange(&mut wire, OPEN);
    let events = f.fake.events.lock().unwrap().clone();
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(
        matches!(response, Response::Error(ErrorCode::Backend)),
        "{response:?}"
    );
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn registration_during_open_wait_blocks_creation() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let lock = f.network_lock();
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    assert_waiting(&mut wire);
    lock.register("test-tunnel").unwrap();
    drop(lock);
    assert!(matches!(
        response(&mut wire),
        Response::Error(ErrorCode::RouteConflict)
    ));
    assert!(f.fake.events.lock().unwrap().is_empty());
    drop(wire);
    worker.unwrap().join().unwrap();
}

#[test]
fn creation_during_tunnel_admission_wait_blocks_registration() {
    use std::sync::mpsc::channel;
    let f = Fixture::new(HELLO_TIMEOUT);
    let (started, creating) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_create.lock().unwrap() = Some((started, proceed));
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    creating.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(!ovpn_present(&f.fake).unwrap());

    thread::scope(|scope| {
        let (waiting, contender_started) = channel();
        let (result, admitted) = channel();
        let f = &f;
        scope.spawn(move || {
            waiting.send(()).unwrap();
            let lock = f.network_lock();
            let conflict = ovpn_present(&f.fake).unwrap();
            if !conflict {
                lock.register("test-tunnel").unwrap();
            }
            result.send(conflict).unwrap();
        });
        contender_started
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let during_create = admitted.recv_timeout(Duration::from_millis(50));
        resume.send(()).unwrap();
        assert!(matches!(
            during_create,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(admitted.recv_timeout(Duration::from_secs(1)).unwrap());
    });
    assert!(matches!(response(&mut wire), Response::Opened(name) if name.as_str() == "vpnt0"));
    assert!(!f.network_lock().tunnels_present().unwrap());
    drop(wire);
    worker.unwrap().join().unwrap();
}

#[test]
fn ovpn_receipt_survives_failed_close_and_clears_on_successful_close() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    assert!(ovpn_receipt(&f));
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    let close = "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n";
    assert!(matches!(
        exchange(&mut wire, close),
        Response::Error(ErrorCode::Backend)
    ));
    assert!(ovpn_receipt(&f));
    assert!(matches!(exchange(&mut wire, close), Response::Ok));
    assert!(!ovpn_receipt(&f));
    drop(wire);
    worker.unwrap().join().unwrap();
}

#[test]
fn ovpn_receipt_survives_server_restart_until_startup_cleanup() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let name = TunName::parse("vpnt0").unwrap();
    {
        let _lock = f.network_lock();
        f.fake.create_tun(&name, 1000).unwrap();
    }
    let mut restarted = Server::new(Arc::clone(&f.fake), HELLO_TIMEOUT);
    restarted.network_directory = f.server.network_directory.clone();
    assert!(restarted.reserved.lock().unwrap().is_empty());
    assert!(ovpn_receipt(&f));
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    restarted.startup().unwrap();
    assert!(restarted.pending.lock().unwrap().contains_key(&name));
    assert!(ovpn_receipt(&f));
    let lock = f.network_lock();
    restarted.retry_inline(&lock, restarted.lock_deadline());
    assert!(!ovpn_present(&f.fake).unwrap());
}

fn ovpn_receipt(f: &Fixture) -> bool {
    let _lock = f.network_lock();
    ovpn_present(&f.fake).unwrap()
}

#[test]
fn lock_deadline_leaves_open_configure_close_and_eof_without_backend_writes() {
    let mut f = Fixture::new(HELLO_TIMEOUT);
    let server = Arc::get_mut(&mut f.server).unwrap();
    server.lock_timeout = Duration::from_millis(80);
    server.open_lock_timeout = server.lock_timeout;
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    let lock = f.network_lock();
    assert!(matches!(
        exchange(&mut wire, OPEN),
        Response::Error(ErrorCode::Backend)
    ));
    assert!(f.fake.events.lock().unwrap().is_empty());
    drop(lock);
    open(&mut wire, "vpnt0");

    let lock = f.network_lock();
    let config = exchange(&mut wire, &configure("vpnt0"));
    let close = exchange(&mut wire, "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n");
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(matches!(config, Response::Error(ErrorCode::Backend)));
    assert!(matches!(close, Response::Error(ErrorCode::Backend)));
    assert_eq!(*f.fake.events.lock().unwrap(), ["create vpnt0 1000"]);
    let name = TunName::parse("vpnt0").unwrap();
    assert!(f.server.pending.lock().unwrap().contains_key(&name));
    assert!(ovpn_present(&f.fake).unwrap());
    f.fake.fail_all_deletes.store(true, Ordering::SeqCst);
    drop(lock);

    wait_for_cleanup(|| f.fake.failed_delete_times.lock().unwrap().len() >= 2);
    {
        let attempts = f.fake.failed_delete_times.lock().unwrap();
        assert!(attempts[1] - attempts[0] >= Duration::from_millis(500));
    }
    assert!(f.server.pending.lock().unwrap().contains_key(&name));
    assert!(ovpn_receipt(&f));
    f.fake.fail_all_deletes.store(false, Ordering::SeqCst);
    wait_for_cleanup(|| !f.server.retry_running.load(Ordering::Relaxed));
    assert!(f.server.pending.lock().unwrap().is_empty());
    assert!(!ovpn_receipt(&f));
}

fn wait_for_cleanup(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "background cleanup did not progress"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn enqueue_marked(f: &Fixture, name: &str) -> TunName {
    let name = TunName::parse(name).unwrap();
    let _lock = f.network_lock();
    f.fake.create_tun(&name, 1000).unwrap();
    f.server.reserved.lock().unwrap().insert(name.clone());
    f.server.defer(&name, CleanupProof::Marked);
    name
}

#[test]
fn open_acquires_network_lock_between_background_items() {
    use std::sync::mpsc::channel;

    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1001);
    hello(&mut wire);
    enqueue_marked(&f, "vpnt0");
    enqueue_marked(&f, "vpnt1");
    let (in_inventory, inventory) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_inventory.lock().unwrap() = Some((in_inventory, proceed));
    f.fake.slow_inventory_calls.store(2, Ordering::SeqCst);

    f.server.retry_pending();
    inventory.recv_timeout(Duration::from_secs(2)).unwrap();
    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    assert_waiting(&mut wire);
    wire.get_ref()
        .set_read_timeout(Some(Duration::from_secs(9)))
        .unwrap();
    resume.send(()).unwrap();
    let opened = response(&mut wire);
    wait_for_cleanup(|| !f.server.retry_running.load(Ordering::Relaxed));
    let events = f.fake.events.lock().unwrap().clone();
    drop(wire);
    worker.unwrap().join().unwrap();

    assert!(
        matches!(opened, Response::Opened(ref name) if name.as_str() == "vpnt0"),
        "{opened:?}"
    );
    assert_eq!(
        events,
        [
            "create vpnt0 1000",
            "create vpnt1 1000",
            "delete vpnt0",
            "create vpnt0 1001",
            "delete vpnt1",
        ]
    );
    assert!(f.fake.names.lock().unwrap().is_empty());
    assert!(f.server.reserved.lock().unwrap().is_empty());
}

#[test]
fn background_cleanup_skips_entry_removed_by_inline_retry() {
    use std::sync::mpsc::channel;

    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1001);
    hello(&mut wire);
    enqueue_marked(&f, "vpnt0");
    enqueue_marked(&f, "vpnt1");
    let (in_inventory, inventory) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_inventory.lock().unwrap() = Some((in_inventory, proceed));

    f.server.retry_pending();
    inventory.recv_timeout(Duration::from_secs(2)).unwrap();
    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    assert_waiting(&mut wire);
    resume.send(()).unwrap();
    let opened = response(&mut wire);
    wait_for_cleanup(|| !f.server.retry_running.load(Ordering::Relaxed));
    let events = f.fake.events.lock().unwrap().clone();
    drop(wire);
    worker.unwrap().join().unwrap();

    assert!(matches!(opened, Response::Opened(name) if name.as_str() == "vpnt0"));
    assert_eq!(
        events,
        [
            "create vpnt0 1000",
            "create vpnt1 1000",
            "delete vpnt0",
            "delete vpnt1",
            "create vpnt0 1001",
        ]
    );
    assert_eq!(
        f.fake.inventory_calls.load(Ordering::SeqCst),
        3,
        "worker inventories only its first item; inline retry and create each inventory once"
    );
    assert!(f.fake.names.lock().unwrap().is_empty());
    assert!(f.server.reserved.lock().unwrap().is_empty());
}

#[test]
fn background_cleanup_deletes_after_a_three_second_inventory() {
    use std::sync::mpsc::channel;

    let f = Fixture::new(HELLO_TIMEOUT);
    let first = enqueue_marked(&f, "vpnt0");
    let second = enqueue_marked(&f, "vpnt1");
    let (in_inventory, inventory) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_inventory.lock().unwrap() = Some((in_inventory, proceed));

    f.server.retry_pending();
    inventory.recv_timeout(Duration::from_secs(2)).unwrap();
    thread::sleep(Duration::from_secs(3));
    resume.send(()).unwrap();
    wait_for_cleanup(|| !f.server.retry_running.load(Ordering::Relaxed));

    assert_eq!(
        f.fake.inventory_calls.load(Ordering::SeqCst),
        2,
        "each item must be inventoried exactly once"
    );
    assert_eq!(
        *f.fake.events.lock().unwrap(),
        [
            "create vpnt0 1000",
            "create vpnt1 1000",
            "delete vpnt0",
            "delete vpnt1"
        ]
    );
    for name in [first, second] {
        assert!(!f.fake.names.lock().unwrap().contains(&name));
        assert!(!f.server.reserved.lock().unwrap().contains(&name));
    }
}

#[test]
fn background_cleanup_resumes_with_first_pending_name_without_attempt() {
    let f = Fixture::new(HELLO_TIMEOUT);
    let first = enqueue_marked(&f, "vpnt0");
    let second = enqueue_marked(&f, "vpnt1");
    *f.fake.fail_delete_for.lock().unwrap() = Some(first.clone());
    f.fake.fail_inventory_call.store(2, Ordering::SeqCst);

    f.server.retry_pending();
    wait_for_cleanup(|| !f.server.pending.lock().unwrap().contains_key(&second));
    let events = f.fake.events.lock().unwrap().clone();
    let names = f.fake.names.lock().unwrap().clone();
    let reserved = f.server.reserved.lock().unwrap().clone();
    *f.fake.fail_delete_for.lock().unwrap() = None;
    wait_for_cleanup(|| !f.server.retry_running.load(Ordering::Relaxed));

    assert!(
        events.starts_with(&[
            "create vpnt0 1000".into(),
            "create vpnt1 1000".into(),
            "delete vpnt0".into(),
            "delete vpnt1".into(),
        ]),
        "the next pass must try vpnt1 before retrying vpnt0: {events:?}"
    );
    assert!(names.contains(&first) && reserved.contains(&first));
    assert!(!names.contains(&second) && !reserved.contains(&second));
}

#[test]
fn open_with_v1_client_finishes_inventory_after_lock_acquisition_deadline() {
    use crate::netd::client::Client;
    use std::sync::mpsc::channel;

    let f = Fixture::new(HELLO_TIMEOUT);
    let lock = f.network_lock();
    let (before_open, opening) = channel();
    let (in_inventory, inventory) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_inventory.lock().unwrap() = Some((in_inventory, proceed));

    thread::scope(|scope| {
        let client = scope.spawn(|| {
            let mut client = Client::connect(&f.path).unwrap();
            before_open.send(Instant::now()).unwrap();
            client.open_tun()
        });
        let worker = f.accept(1000).unwrap();
        let start = opening.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(3250).saturating_sub(start.elapsed()));
        drop(lock);
        inventory.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(5400).saturating_sub(start.elapsed()));
        resume.send(()).unwrap();
        let opened = client.join().unwrap();
        worker.join().unwrap();
        assert_eq!(opened.unwrap().as_str(), "vpnt0");
    });
}

#[test]
fn inline_retry_stops_before_deleting_after_its_own_budget() {
    use std::sync::mpsc::channel;

    let f = Fixture::new(HELLO_TIMEOUT);
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    let pending = [
        TunName::parse("vpnt0").unwrap(),
        TunName::parse("vpnt1").unwrap(),
    ];
    {
        let _lock = f.network_lock();
        for name in &pending {
            f.fake.create_tun(name, 1001).unwrap();
            f.server.reserved.lock().unwrap().insert(name.clone());
            f.server.defer(name, CleanupProof::Marked);
        }
    }
    let (in_inventory, inventory) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_inventory.lock().unwrap() = Some((in_inventory, proceed));
    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    wire.get_ref()
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    inventory.recv_timeout(Duration::from_secs(2)).unwrap();
    thread::sleep(Duration::from_millis(2100));
    resume.send(()).unwrap();
    let opened = response(&mut wire);
    let events = f.fake.events.lock().unwrap().clone();
    let retained = f.server.pending.lock().unwrap().clone();
    let names = f.fake.names.lock().unwrap().clone();
    drop(wire);
    worker.unwrap().join().unwrap();
    wait_for_cleanup(|| !f.server.retry_running.load(Ordering::Relaxed));

    assert!(matches!(opened, Response::Opened(name) if name.as_str() == "vpnt2"));
    assert_eq!(
        events,
        [
            "create vpnt0 1001",
            "create vpnt1 1001",
            "create vpnt2 1000"
        ]
    );
    assert!(pending.iter().all(|name| {
        matches!(retained.get(name), Some(CleanupProof::Marked)) && names.contains(name)
    }));
    assert!(f.server.pending.lock().unwrap().is_empty());
    assert!(f.fake.names.lock().unwrap().is_empty());
    assert!(f.server.reserved.lock().unwrap().is_empty());
}

#[test]
fn cleanup_retry_delays_increase_and_then_stay_at_five_seconds() {
    let delays: Vec<_> = retry_delays().take(7).collect();
    assert_eq!(
        delays,
        [250, 500, 1000, 2000, 5000, 5000, 5000].map(Duration::from_millis)
    );
}
