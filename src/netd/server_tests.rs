use super::*;
use crate::netd::iproute::Existing;
use crate::netd::protocol::{Config, decode_response};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type Pause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);

#[derive(Default)]
pub(in crate::netd) struct Fake {
    pub(in crate::netd) events: Mutex<Vec<String>>,
    names: Mutex<HashSet<TunName>>,
    foreign: Mutex<HashSet<TunName>>,
    fail_delete: AtomicBool,
    conflict: AtomicBool,
    fail_create: AtomicBool,
    fail_configure: AtomicBool,
    pause_create: Mutex<Option<Pause>>,
    pause_delete: Mutex<Option<Pause>>,
    retry_wait: Mutex<Option<Duration>>,
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
        if self.fail_delete.swap(false, Ordering::SeqCst) {
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
        Ok(())
    }
    fn existing(&self) -> io::Result<Vec<Existing>> {
        let owned = self.names.lock().unwrap().clone();
        let foreign = self.foreign.lock().unwrap().clone();
        Ok(owned
            .into_iter()
            .map(|name| Existing { name, owned: true })
            .chain(
                foreign
                    .into_iter()
                    .map(|name| Existing { name, owned: false }),
            )
            .collect())
    }
    fn retry_wait(&self) -> Duration {
        self.retry_wait
            .lock()
            .unwrap()
            .unwrap_or(Duration::from_secs(5))
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
    decode_response(&read_line(wire).unwrap()).unwrap()
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
fn pending_create_reserves_name_before_kernel_inventory_changes() {
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
    open(&mut b, "vpnt1");
    resume.send(()).unwrap();
    assert!(
        matches!(decode_response(&read_line(&mut a).unwrap()).unwrap(), Response::Opened(name) if name.as_str() == "vpnt0")
    );
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
    assert!(f.server.pending.lock().unwrap().contains(&name));
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
        let name = TunName::parse("vpnt0").unwrap();
        f.fake.fail_delete.store(true, Ordering::SeqCst);
        let close = "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n";
        assert!(matches!(
            exchange(&mut wire, close),
            Response::Error(ErrorCode::Backend)
        ));
        assert!(matches!(
            exchange(&mut wire, close),
            Response::Error(ErrorCode::NotOwned)
        ));
        f.fake.names.lock().unwrap().remove(&name);
        if foreign {
            f.fake.foreign.lock().unwrap().insert(name.clone());
        }
        open(&mut wire, if foreign { "vpnt1" } else { "vpnt0" });
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
        assert_eq!(f.server.pending.lock().unwrap().contains(&name), foreign);
        assert_eq!(f.fake.foreign.lock().unwrap().contains(&name), foreign);
        drop(wire);
        worker.unwrap().join().unwrap();
    }
}

#[test]
fn slow_pending_delete_does_not_hold_open_past_retry_budget() {
    use std::sync::mpsc::channel;
    let f = Fixture::new(HELLO_TIMEOUT);
    *f.fake.retry_wait.lock().unwrap() = Some(Duration::from_millis(40));
    let (mut wire, worker) = f.connection(1000);
    hello(&mut wire);
    open(&mut wire, "vpnt0");
    f.fake.fail_delete.store(true, Ordering::SeqCst);
    let close = "{\"op\":\"close_tun\",\"ifname\":\"vpnt0\"}\n";
    assert!(matches!(
        exchange(&mut wire, close),
        Response::Error(ErrorCode::Backend)
    ));
    let (started, arrived) = channel();
    let (resume, proceed) = channel();
    *f.fake.pause_delete.lock().unwrap() = Some((started, proceed));

    wire.get_mut().write_all(OPEN.as_bytes()).unwrap();
    arrived.recv_timeout(Duration::from_secs(1)).unwrap();
    wire.get_ref()
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let response = read_line(&mut wire);
    // Release the parked worker before asserting the result, including on a timeout.
    resume.send(()).unwrap();
    assert!(
        matches!(decode_response(&response.unwrap()).unwrap(), Response::Opened(name) if name.as_str() == "vpnt1")
    );
    open(&mut wire, "vpnt0");
    drop(wire);
    worker.unwrap().join().unwrap();
    assert!(f.fake.existing().unwrap().is_empty());
}
