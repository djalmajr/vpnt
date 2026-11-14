use super::*;
mod preferences;
struct Harness {
    broker: Broker<Secrets>,
    old: Peer,
    _next: Peer,
    calls: Arc<AtomicUsize>,
    removes: Arc<AtomicUsize>,
    root: std::path::PathBuf,
}
impl Harness {
    fn new(next_mode: &str, source: &str) -> Self {
        let mut old = Peer::new("flow");
        let mut next = Peer::new(next_mode);
        let removes = Arc::new(AtomicUsize::new(0));
        let mut broker = Broker::new(Some(old.take()), Secrets(removes.clone()));
        wait(|| broker.snapshot().helper == "installed");
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let mut client = Some(next.take());
        broker.retry = Some(retry::Retry::fixture(move || {
            attempts.fetch_add(1, Ordering::Relaxed);
            client.take().ok_or(Error::Unavailable)
        }));
        let root = old.root().to_owned();
        let script = root.join("operation.py");
        fs::write(&script, source).unwrap();
        let directory = root.clone();
        broker.component.connect = Box::new(move |kind, id, locale, expires| {
            let mut command = Process::new("/usr/bin/python3");
            command
                .arg(&script)
                .arg(&directory)
                .arg(env!("CARGO_PKG_VERSION"));
            Operation::fixture(kind, command, id, locale, expires)
        });
        Self {
            broker,
            old,
            _next: next,
            calls,
            removes,
            root,
        }
    }
    fn begin(&mut self, command: Command, seconds: u64) -> u64 {
        self.broker
            .begin_component(
                command,
                Locale::EnUs,
                Instant::now() + Duration::from_secs(seconds),
            )
            .unwrap()
    }
    fn result(&mut self) -> (u64, Result<Snapshot, &'static str>) {
        let mut result = None;
        wait(|| {
            self.broker.poll();
            result = self.broker.take_component_result();
            result.is_some()
        });
        result.unwrap()
    }
    fn release(&self) {
        fs::write(self.root.join("release"), b"").unwrap();
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.release();
        self.broker.component.close();
    }
}
const HELD: &str = "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nassert (p/'peer.cleaned').exists()\n(p/'started').touch()\ndeadline=time.monotonic()+5\nwhile not (p/'release').exists() and time.monotonic()<deadline:time.sleep(0.005)\nassert (p/'release').exists()\n(p/'finished').touch()\n";

#[test]
fn removal_preserves_secrets_and_never_restarts_a_runtime_for_the_unregistered_user() {
    let source = r#"import json,pathlib,socket,sys,time
p=pathlib.Path(sys.argv[1]);assert (p/'peer.cleaned').exists()
s=socket.socket(fileno=0);s.sendall((json.dumps(dict(type='ready',format=1,version=sys.argv[2]))+'\n').encode())
r=json.loads(s.makefile('rb').read());assert set(r)=={'id'}
s.sendall((json.dumps(dict(type='removed',id=r['id'],component_present=True))+'\n').encode());s.shutdown(socket.SHUT_WR);s.close()
(p/'receipt').touch()
deadline=time.monotonic()+5
while not (p/'release').exists() and time.monotonic()<deadline:time.sleep(0.005)
assert (p/'release').exists()
(p/'finished').touch()
"#;
    let mut h = Harness::new("flow", source);
    let token = h.begin(Command::RemoveHelper {}, 3);
    wait(|| {
        h.broker.poll();
        h.root.join("receipt").exists()
    });
    assert!(h.old.cleaned());
    assert!(h.broker.take_component_result().is_none());
    assert_eq!(h.calls.load(Ordering::Relaxed), 0);
    h.release();
    let (got, result) = h.result();
    assert_eq!(got, token);
    assert_eq!(result.unwrap().helper, "missing");
    for _ in 0..30 {
        h.broker.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(h.calls.load(Ordering::Relaxed), 0);
    assert_eq!(h.removes.load(Ordering::Relaxed), 0);
    assert!(
        h.broker
            .connections
            .values()
            .all(|c| c.view.state == State::HelperMissing)
    );
}

#[test]
fn timeout_retains_exclusion_while_the_child_lives_and_never_replays_or_sends_late_success() {
    let mut h = Harness::new("flow", HELD);
    let token = h.begin(Command::InstallHelper {}, 1);
    wait(|| {
        h.broker.poll();
        h.root.join("started").exists()
    });
    let (got, result) = h.result();
    assert_eq!(got, token);
    assert_eq!(result.unwrap_err(), "component_expired");
    assert!(h.broker.component_busy());
    assert_eq!(
        serde_json::to_value(h.broker.snapshot()).unwrap()["componentOperation"],
        "settling"
    );
    assert_eq!(h.calls.load(Ordering::Relaxed), 0);
    assert!(!h.root.join("finished").exists());
    assert_eq!(
        h.broker.begin_component(
            Command::RemoveHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(1)
        ),
        Err("component_busy")
    );
    let profile = h
        .broker
        .connections
        .values()
        .next()
        .unwrap()
        .view
        .profile
        .clone();
    assert_eq!(
        h.broker.begin_admin(
            Command::SaveProfile { profile },
            Locale::EnUs,
            Instant::now() + Duration::from_secs(1)
        ),
        Err("component_busy")
    );
    assert!(matches!(
        h.broker.dispatch(
            Command::Probe { id: "one".into() },
            Instant::now() + Duration::from_secs(1)
        ),
        Err("component_busy")
    ));
    assert!(
        h.broker
            .dispatch(
                Command::GetSnapshot {},
                Instant::now() + Duration::from_secs(1)
            )
            .is_ok()
    );
    h.release();
    wait(|| {
        h.broker.poll();
        !h.broker.component_busy()
    });
    wait(|| h.broker.snapshot().helper == "installed");
    assert!(h.broker.take_component_result().is_none());
    assert_eq!(h.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn an_incompatible_new_session_cannot_turn_installer_exit_into_installation_success() {
    let mut h = Harness::new("version", HELD);
    h.begin(Command::InstallHelper {}, 1);
    h.release();
    let (_, result) = h.result();
    assert_eq!(result.unwrap_err(), "component_expired");
    assert_ne!(h.broker.snapshot().helper, "installed");
    assert!(h.root.join("finished").exists());
}

#[test]
fn artifact_admission_failure_does_not_disconnect_the_existing_runtime() {
    let mut old = Peer::new("flow");
    let mut broker = Broker::new(Some(old.take()), Secrets(Arc::new(AtomicUsize::new(0))));
    wait(|| broker.snapshot().helper == "installed");
    broker.component.connect = Box::new(|kind, id, locale, expires| {
        Operation::fixture(
            kind,
            Process::new("relative-untrusted-program"),
            id,
            locale,
            expires,
        )
    });
    broker
        .begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let mut result = None;
    wait(|| {
        broker.poll();
        result = broker.take_component_result();
        result.is_some()
    });
    assert_eq!(result.unwrap().1.unwrap_err(), "component_incompatible");
    assert_eq!(broker.snapshot().helper, "installed");
    assert!(!old.retiring());
}

#[test]
fn quitting_during_a_component_operation_never_restarts_runtime_or_admits_another_change() {
    let mut h = Harness::new("flow", HELD);
    h.begin(Command::InstallHelper {}, 3);
    wait(|| {
        h.broker.poll();
        h.root.join("started").exists()
    });
    h.broker
        .dispatch(Command::Quit {}, Instant::now() + Duration::from_secs(1))
        .unwrap();
    let (_, result) = h.result();
    assert_eq!(result.unwrap_err(), "component_canceled");
    h.release();
    wait(|| {
        h.broker.poll();
        !h.broker.component_busy()
    });
    assert!(
        h.broker.retry.is_none(),
        "quit must keep the runtime launcher disabled"
    );
    for _ in 0..20 {
        h.broker.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        h.calls.load(Ordering::Relaxed),
        0,
        "quit cannot revive the runtime"
    );
    assert_eq!(
        h.broker.begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(1)
        ),
        Err("backend_unavailable")
    );
}
