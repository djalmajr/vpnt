use super::*;
use crate::connection::controller::{Attempt, Failure};
use crate::helper::protocol::Step;
use crate::{
    helper::protocol::Command as RequestCommand,
    preferences::ProbeInterval,
    secrets::{Credentials, Secret},
    storage::ProfileStore,
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache")
            .join(format!("vpnt-linux-controller-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn profile(id: &str) -> Profile {
    serde_json::from_value(serde_json::json!({"id": id, "name": id, "kind":"ssl", "gateway":"vpn.example.test", "username":"fixture", "networks":[], "port":443, "certificate":"", "probeHost":"10.20.0.15", "probePort":8443, "probeMethod":"tcp"})).unwrap()
}
#[test]
fn linux_controller_child() {
    if std::env::var_os("VPNT_CONTROLLER_TEST_CHILD").is_none() {
        return;
    }
    let uid = unsafe { libc::geteuid() };
    assert_ne!(uid, 0);
    let store = ProfileStore::for_current_user().unwrap();
    store.save(profile("first")).unwrap();
    let mut second = profile("second");
    second.kind = VpnKind::Ipsec;
    store.save(second.clone()).unwrap();
    let mut third = profile("third");
    third.kind = VpnKind::Ovpn;
    third.username.clear();
    third.ovpn = Some(crate::model::OvpnSettings {
        certificate_id: "01".into(),
        module: "/fixture.so".into(),
        tls: crate::model::OvpnTls::Pkcs1Only,
    });
    store.save(third.clone()).unwrap();
    let factory = LinuxFactory {
        profiles: Arc::new(Profiles::for_current_user().unwrap()),
    };
    assert!(factory.supports(VpnKind::Ovpn));
    assert!(!factory.supports(VpnKind::Ssl));
    assert!(!factory.supports(VpnKind::Ipsec));
    let config = store.ovpn_dir().unwrap().join("third.ovpn");
    fs::write(&config, b"fixture").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
    let mut insecure = factory.create(
        third.clone(),
        uid,
        1,
        Credentials {
            password: Secret::from(""),
            psk: Secret::from(""),
        },
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(
        insecure
            .start(
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap_err()
            .step,
        Step::Profile
    );
    assert!(insecure.cleanup());
    let mut attempt = factory.create(
        profile("first"),
        uid,
        1,
        Credentials {
            password: Secret::from("fixture"),
            psk: Secret::from(""),
        },
        Arc::new(AtomicBool::new(false)),
    );
    let error = attempt
        .start(
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
    assert_eq!(error.step, Step::Profile);
    assert!(attempt.cleanup());
    let (requests, input) = mpsc::channel();
    let (output, messages) = mpsc::sync_channel(16);
    let (done, result) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let _ = done.send(run_linux(uid, input, output));
    });
    requests
        .send(Request {
            id: "snapshot".into(),
            command: RequestCommand::Snapshot {},
        })
        .unwrap();
    match messages.recv_timeout(Duration::from_secs(3)).unwrap() {
        Message::Snapshot { id, profiles, .. } => {
            assert_eq!(id, "snapshot");
            assert_eq!(profiles, [profile("first"), second, third]);
        }
        other => panic!("unexpected snapshot response: {other:?}"),
    }
    requests
        .send(Request {
            id: "connect".into(),
            command: RequestCommand::Connect {
                id: "first".into(),
                generation: 1,
                interval: ProbeInterval::TEN,
                credentials: Credentials {
                    password: Secret::from("fixture"),
                    psk: Secret::from(""),
                },
            },
        })
        .unwrap();
    assert!(
        matches!(messages.recv_timeout(Duration::from_secs(3)).unwrap(), Message::Failed { id, error: ErrorCode::MissingProgram } if id == "connect")
    );
    requests
        .send(Request {
            id: "connect-ipsec".into(),
            command: RequestCommand::Connect {
                id: "second".into(),
                generation: 1,
                interval: ProbeInterval::TEN,
                credentials: Credentials {
                    password: Secret::from("fixture"),
                    psk: Secret::from("fixture"),
                },
            },
        })
        .unwrap();
    assert!(
        matches!(messages.recv_timeout(Duration::from_secs(3)).unwrap(), Message::Failed { id, error: ErrorCode::MissingProgram } if id == "connect-ipsec")
    );
    requests
        .send(Request {
            id: "connect-ovpn".into(),
            command: RequestCommand::Connect {
                id: "third".into(),
                generation: 1,
                interval: ProbeInterval::TEN,
                credentials: Credentials {
                    password: Secret::from(""),
                    psk: Secret::from(""),
                },
            },
        })
        .unwrap();
    assert!(
        matches!(messages.recv_timeout(Duration::from_secs(3)).unwrap(), Message::Accepted { id } if id == "connect-ovpn")
    );
    loop {
        match messages.recv_timeout(Duration::from_secs(3)).unwrap() {
            Message::Changed {
                profile_id,
                state: crate::session::ConnectionState::Dropped,
                ..
            } if profile_id == "third" => break,
            Message::Failed { id, error } if id == "connect-ovpn" => {
                panic!("OVPN rejected before create: {error:?}")
            }
            _ => {}
        }
    }
    drop(requests);
    assert_eq!(result.recv_timeout(Duration::from_secs(3)).unwrap(), Ok(()));
    worker.join().unwrap();
    let (requests, input) = mpsc::channel();
    let (output, _) = mpsc::sync_channel(1);
    drop(requests);
    assert_eq!(
        run_linux(uid.wrapping_add(1), input, output),
        Err(ErrorCode::PermissionDenied)
    );
    let (requests, input) = mpsc::channel();
    let (output, _) = mpsc::sync_channel(1);
    drop(requests);
    assert_eq!(
        run_linux(0, input, output),
        Err(ErrorCode::PermissionDenied)
    );
}
#[test]
fn linux_controller_loads_profiles_refuses_connection_and_stops() {
    let f = Fixture::new();
    let mut process = Process(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "connection::controller::linux::tests::linux_controller_child",
                "--nocapture",
            ])
            .env("VPNT_CONTROLLER_TEST_CHILD", "1")
            .env("XDG_DATA_HOME", &f.0)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "controller child failed: {status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "controller child failed to exit within 15s"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn worker_publishes_changed_phase_and_default_phase_stays_silent() {
    use crate::connection::controller::{ConnectionState, ProbeClock, worker};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    struct AttemptWithPhase {
        calls: Arc<AtomicUsize>,
        publish: bool,
    }
    impl Attempt for AttemptWithPhase {
        fn start(&mut self, _: &AtomicBool, _: Instant) -> Result<(), Failure> {
            Ok(())
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        }
        fn phase(&self) -> Option<ConnectionState> {
            self.publish.then_some(ConnectionState::AwaitingApproval)
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
    struct WorkerGuard {
        cancel: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<worker::Finished>>,
    }
    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            self.cancel.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    for publish in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(None));
        let signals = worker::Signals {
            canceled: cancel.clone(),
            probe: Arc::new(AtomicBool::new(false)),
            state: state.clone(),
            exit: Arc::new(worker::ExitRequested::new(Duration::from_secs(1))),
        };
        let timing = Timing {
            connect: Duration::from_secs(3),
            probe: Duration::from_secs(1),
            interval: Duration::from_secs(1),
            health: Duration::from_secs(1),
            poll: Duration::from_millis(5),
        };
        let attempt = AttemptWithPhase {
            calls: calls.clone(),
            publish,
        };
        let _guard = WorkerGuard {
            cancel: cancel.clone(),
            thread: Some(thread::spawn(move || {
                worker::run(
                    attempt,
                    signals,
                    timing,
                    ProbeClock::new(Duration::from_secs(1)),
                )
            })),
        };
        let until = Instant::now() + Duration::from_secs(2);
        while calls.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < until, "ready was not called");
            thread::sleep(Duration::from_millis(5));
        }
        if publish {
            while state.lock().unwrap().is_none() {
                assert!(Instant::now() < until, "phase was not published");
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                state.lock().unwrap().as_ref().unwrap().state,
                ConnectionState::AwaitingApproval
            );
        } else {
            assert!(
                state.lock().unwrap().is_none(),
                "None must not publish a phase"
            );
        }
    }
}
