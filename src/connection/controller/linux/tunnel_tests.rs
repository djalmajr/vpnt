use super::*;
use crate::{model::VpnKind, secrets::Secret};

fn profile(kind: VpnKind) -> Profile {
    let (networks, port, certificate) = if kind == VpnKind::Ssl {
        (vec![], 443, "AB".repeat(32))
    } else {
        (vec!["10.20.0.0/24".into()], 500, String::new())
    };
    Profile {
        id: "fixture-tunnel".into(),
        name: "Fixture tunnel".into(),
        kind,
        gateway: "vpn.example.test".into(),
        username: "fixture-user".into(),
        networks,
        dns_domains: vec![],
        port,
        certificate,
        probe_host: "10.20.0.15".into(),
        probe_port: 8443,
        probe_method: "tcp".into(),
        ovpn: None,
    }
}

#[test]
fn prepares_distinct_backend_requests_from_profiles() {
    let Prepare::Ipsec(ipsec) = prepare(&profile(VpnKind::Ipsec)).unwrap() else {
        panic!("expected IPsec offer");
    };
    assert_eq!(ipsec.endpoint().host(), "vpn.example.test");
    assert_eq!(ipsec.endpoint().port(), 500);
    assert_eq!(ipsec.username(), "fixture-user");
    assert_eq!(ipsec.networks()[0].network().octets(), [10, 20, 0, 0]);
    assert_eq!(ipsec.networks()[0].prefix(), 24);

    let Prepare::Fortinet(ssl) = prepare(&profile(VpnKind::Ssl)).unwrap() else {
        panic!("expected Fortinet offer");
    };
    assert_eq!(ssl.endpoint().host(), "vpn.example.test");
    assert_eq!(ssl.endpoint().port(), 443);
    assert_eq!(ssl.username(), "fixture-user");
    assert_eq!(ssl.certificate_sha256(), &[0xab; 32]);
}

#[test]
fn fortinet_without_pin_fails_before_socket_connect() {
    let mut ssl = profile(VpnKind::Ssl);
    ssl.certificate.clear();
    let mut attempt = TunnelAttempt::with_socket(
        ssl,
        Credentials {
            password: Secret::from("fixture-password"),
            psk: Secret::from(""),
        },
        PathBuf::from("/nonexistent-fixture/socket"),
        |_, _, _, _| panic!("probe ran"),
    );
    let err = attempt
        .start(
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
    assert_eq!(err.step, Step::Profile);
    assert!(attempt.cleanup());
}

use crate::{
    connection::controller::{ProbeClock, Timing, worker},
    tunneld::protocol::{Command, ServerDecoder, VERSION},
};
use std::{
    fs,
    io::Write,
    os::unix::{
        fs::DirBuilderExt,
        net::{UnixListener, UnixStream},
    },
    process,
    sync::{Arc, atomic::AtomicUsize},
};

const TEST_PASSWORD: &str = "wire-only-fixture-password";
const TEST_PSK: &str = "wire-only-fixture-psk";

struct SocketFixture {
    dir: PathBuf,
    listener: UnixListener,
}

impl SocketFixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("vpnt-tunnel-{}-{name}", process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let listener = match UnixListener::bind(dir.join("s")) {
            Ok(listener) => listener,
            Err(error) => {
                fs::remove_dir(&dir).unwrap();
                panic!("bind fixture: {error}");
            }
        };
        let fixture = Self { dir, listener };
        fixture.listener.set_nonblocking(true).unwrap();
        fixture
    }

    fn accept(&self) -> UnixStream {
        let until = wire_deadline();
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept fixture: {error}"),
            }
        }
    }

    fn attempt(&self, kind: VpnKind, probe: Probe) -> TunnelAttempt {
        TunnelAttempt::with_socket(
            profile(kind),
            Credentials {
                password: Secret::from(TEST_PASSWORD),
                psk: Secret::from(if kind == VpnKind::Ipsec { TEST_PSK } else { "" }),
            },
            self.dir.join("s"),
            probe,
        )
    }
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        fs::remove_file(self.dir.join("s")).unwrap();
        fs::remove_dir(&self.dir).unwrap();
    }
}

fn wire_deadline() -> Instant {
    Instant::now() + Duration::from_secs(4)
}

/// Exercise an unchanged Client with a root peer confined to a user namespace.
fn wire_fixture(name: &str) -> bool {
    let is_root = unsafe { libc::geteuid() } == 0;
    if std::env::var_os("VPNT_TEST_TUNNEL_WIRE_CHILD").is_some() {
        assert!(is_root);
        return true;
    }
    let unshare = "/usr/bin/unshare";
    let args = ["--user", "--map-root-user", "--"];
    if !is_root {
        match process::Command::new(unshare)
            .args(args)
            .arg("/usr/bin/true")
            .output()
        {
            Ok(result) if result.status.success() => {}
            result => {
                eprintln!("tunneld socket fixture requires a Linux user namespace: {result:?}");
                assert!(std::env::var_os("VPNT_TEST_TUNNEL_USERNS").is_none());
                return false;
            }
        }
    }
    struct FixtureRoot(PathBuf);
    impl Drop for FixtureRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "vw-{}-{}",
        process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let root = FixtureRoot(root);
    let (_, module) = module_path!().split_once("::").unwrap();
    let mut process = process::Command::new("/usr/bin/timeout");
    process.arg("15s");
    if !is_root {
        process.arg(unshare).args(args);
    }
    let result = process
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &format!("{module}::{name}"), "--nocapture"])
        .env("VPNT_TEST_TUNNEL_WIRE_CHILD", "1")
        .env("TMPDIR", &root.0)
        .output()
        .unwrap();
    assert!(
        !result
            .stdout
            .windows(TEST_PASSWORD.len())
            .any(|bytes| bytes == TEST_PASSWORD.as_bytes())
    );
    assert!(
        !result
            .stderr
            .windows(TEST_PASSWORD.len())
            .any(|bytes| bytes == TEST_PASSWORD.as_bytes())
    );
    assert!(
        !result
            .stdout
            .windows(TEST_PSK.len())
            .any(|bytes| bytes == TEST_PSK.as_bytes())
    );
    assert!(
        !result
            .stderr
            .windows(TEST_PSK.len())
            .any(|bytes| bytes == TEST_PSK.as_bytes())
    );
    assert!(
        result.status.success(),
        "wire test child: {}",
        String::from_utf8_lossy(&[result.stdout, result.stderr].concat())
    );
    false
}

fn no_probe(_: &Profile, _: &AtomicBool, _: Duration, _: ProbeSlot) -> Result<bool, Failure> {
    panic!("probe ran before readiness");
}

fn admitted(fixture: &SocketFixture, kind: VpnKind) -> ServerDecoder {
    let mut decoder = ServerDecoder::new(fixture.accept());
    decoder.hello(wire_deadline()).unwrap();
    let offer = decoder.prepare(wire_deadline()).unwrap();
    match (kind, offer) {
        (VpnKind::Ipsec, Prepare::Ipsec(offer)) => {
            assert_eq!(offer.endpoint().host(), "vpn.example.test");
            assert_eq!(offer.endpoint().port(), 500);
            assert_eq!(offer.username(), "fixture-user");
            assert_eq!(
                offer.networks(),
                &[CidrV4::new("10.20.0.0".parse().unwrap(), 24).unwrap()]
            );
        }
        (VpnKind::Ssl, Prepare::Fortinet(offer)) => {
            assert_eq!(offer.endpoint().host(), "vpn.example.test");
            assert_eq!(offer.endpoint().port(), 443);
            assert_eq!(offer.username(), "fixture-user");
            assert_eq!(offer.certificate_sha256(), &[0xab; 32]);
        }
        _ => panic!("tunneld received the wrong backend"),
    }
    decoder.prepared(wire_deadline()).unwrap();
    let secret = decoder.credentials(wire_deadline()).unwrap();
    assert!(secret.password() == TEST_PASSWORD);
    assert!(secret.psk() == (kind == VpnKind::Ipsec).then_some(TEST_PSK));
    decoder
}

fn reply(decoder: &mut ServerDecoder, command: Command, state: State) {
    assert_eq!(decoder.command(wire_deadline()).unwrap(), command);
    decoder.reply_status(state, wire_deadline()).unwrap();
}

fn exercising_worker(fixture: &SocketFixture, kind: VpnKind, responsive: bool) {
    fn success(
        profile: &Profile,
        _: &AtomicBool,
        _: Duration,
        _: ProbeSlot,
    ) -> Result<bool, Failure> {
        assert_eq!(profile.probe_host, "10.20.0.15");
        assert_eq!(profile.probe_port, 8443);
        Ok(true)
    }
    let attempt = fixture.attempt(
        kind,
        if responsive {
            success
        } else {
            |_, _, _, _| Ok(false)
        },
    );
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(fixture, kind);
            reply(&mut decoder, Command::Status, State::Starting);
            let started = Instant::now();
            assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
            assert!(started.elapsed() >= Duration::from_millis(450));
            decoder
                .reply_status(State::NetworkReady, wire_deadline())
                .unwrap();
            loop {
                if decoder.command(wire_deadline()).unwrap() == Command::Stop {
                    decoder
                        .reply_status(State::Stopped, wire_deadline())
                        .unwrap();
                    break;
                }
                decoder
                    .reply_status(State::NetworkReady, wire_deadline())
                    .unwrap();
            }
        });
        let canceled = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(None));
        let signals = worker::Signals {
            canceled: canceled.clone(),
            probe: Arc::new(AtomicBool::new(false)),
            state: state.clone(),
            exit: Arc::new(worker::ExitRequested::new(Duration::from_secs(2))),
        };
        let timing = Timing {
            connect: Duration::from_secs(3),
            ..Timing::default()
        };
        let waiter = scope
            .spawn(move || worker::run(attempt, signals, timing, ProbeClock::new(timing.interval)));
        let until = wire_deadline();
        let observed = loop {
            let current = state
                .lock()
                .unwrap()
                .as_ref()
                .map(|progress| progress.state);
            if matches!(
                current,
                Some(
                    ConnectionState::Connected
                        | ConnectionState::Unresponsive
                        | ConnectionState::Dropped
                )
            ) || Instant::now() >= until
            {
                break current;
            }
            thread::sleep(Duration::from_millis(10));
        };
        canceled.store(true, Ordering::Release);
        // The server has its own deadline, including on the mutant's error path.
        // Join it before asserting the worker result so fixture failures are surfaced.
        let server_result = server.join();
        assert_eq!(
            waiter.join().unwrap().state,
            if server_result.is_ok() {
                ConnectionState::Off
            } else {
                ConnectionState::Dropped
            }
        );
        server_result.unwrap();
        let expected = if responsive {
            ConnectionState::Connected
        } else {
            ConnectionState::Unresponsive
        };
        assert_eq!(observed, Some(expected));
    });
}

#[test]
fn connected_requires_the_profile_probe_after_network_ready() {
    if wire_fixture("connected_requires_the_profile_probe_after_network_ready") {
        exercising_worker(&SocketFixture::new("ipsec"), VpnKind::Ipsec, true);
        exercising_worker(&SocketFixture::new("ssl-up"), VpnKind::Ssl, true);
        exercising_worker(&SocketFixture::new("ssl-down"), VpnKind::Ssl, false);
    }
}

#[test]
fn stop_waits_for_confirmed_cleanup() {
    if !wire_fixture("stop_waits_for_confirmed_cleanup") {
        return;
    }
    let fixture = SocketFixture::new("cleanup");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            reply(&mut decoder, Command::Stop, State::CleanupPending);
            reply(&mut decoder, Command::Status, State::Stopping);
            reply(&mut decoder, Command::Status, State::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
        attempt
            .start(&AtomicBool::new(false), wire_deadline())
            .unwrap();
        assert!(attempt.ready().unwrap());
        assert!(!attempt.cleanup());
        assert!(!attempt.cleanup());
        assert!(attempt.cleanup());
        assert!(attempt.cleanup());
        server.join().unwrap();
    });
}

#[test]
fn daemon_refusals_keep_their_typed_failure() {
    if !wire_fixture("daemon_refusals_keep_their_typed_failure") {
        return;
    }
    for (name, code, state, error, step) in [
        (
            "busy",
            WireError::Busy,
            ConnectionState::Dropped,
            ErrorCode::ProfileBusy,
            Step::Runtime,
        ),
        (
            "permission",
            WireError::PermissionDenied,
            ConnectionState::Dropped,
            ErrorCode::PermissionDenied,
            Step::Profile,
        ),
        (
            "missing",
            WireError::MissingProgram,
            ConnectionState::MissingProgram,
            ErrorCode::MissingProgram,
            Step::Tunnel,
        ),
        (
            "timeout",
            WireError::Timeout,
            ConnectionState::GatewayTimeout,
            ErrorCode::BackendFailure,
            Step::Tunnel,
        ),
        (
            "backend",
            WireError::Backend,
            ConnectionState::Dropped,
            ErrorCode::BackendFailure,
            Step::Tunnel,
        ),
    ] {
        let fixture = SocketFixture::new(name);
        thread::scope(|scope| {
            let server = scope.spawn(|| match code {
                WireError::Busy => {
                    let mut stream = fixture.accept();
                    let mut request = String::new();
                    use std::io::BufRead;
                    std::io::BufReader::new(&mut stream)
                        .read_line(&mut request)
                        .unwrap();
                    assert!(matches!(
                        crate::tunneld::protocol::decode_request(request.as_bytes()),
                        Ok(crate::tunneld::protocol::Request::Hello { version: VERSION })
                    ));
                    serde_json::to_writer(
                        &mut stream,
                        &crate::tunneld::protocol::Response::Error { code },
                    )
                    .unwrap();
                    stream.write_all(b"\n").unwrap();
                }
                WireError::PermissionDenied => {
                    let mut decoder = ServerDecoder::new(fixture.accept());
                    decoder.hello(wire_deadline()).unwrap();
                    decoder.prepare(wire_deadline()).unwrap();
                    decoder.reject(code, wire_deadline()).unwrap();
                }
                _ => {
                    let mut decoder = admitted(&fixture, VpnKind::Ssl);
                    assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
                    decoder.reject(code, wire_deadline()).unwrap();
                }
            });
            let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
            let result = attempt
                .start(&AtomicBool::new(false), wire_deadline())
                .and_then(|()| attempt.ready());
            let failure = result.unwrap_err();
            assert_eq!(
                (failure.state, failure.error, failure.step),
                (state, error, step)
            );
            assert_eq!(
                attempt.cleanup(),
                !matches!(code, WireError::Timeout | WireError::Backend)
            );
            server.join().unwrap();
        });
    }
}

#[test]
fn absolute_connect_deadline_expires_between_status_polls() {
    if !wire_fixture("absolute_connect_deadline_expires_between_status_polls") {
        return;
    }
    let fixture = SocketFixture::new("deadline");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::Starting);
            reply(&mut decoder, Command::Stop, State::Stopped);
        });
        let signals = worker::Signals {
            canceled: Arc::new(AtomicBool::new(false)),
            probe: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(None)),
            exit: Arc::new(worker::ExitRequested::new(Duration::from_secs(2))),
        };
        let timing = Timing {
            connect: Duration::from_millis(350),
            ..Timing::default()
        };
        let finished = worker::run(
            fixture.attempt(VpnKind::Ssl, no_probe),
            signals,
            timing,
            ProbeClock::new(timing.interval),
        );
        assert_eq!(finished.state, ConnectionState::GatewayTimeout);
        assert_eq!(finished.error, Some(ErrorCode::BackendFailure));
        assert_eq!(finished.step, Some(Step::Tunnel));
        server.join().unwrap();
    });
}

#[test]
fn credentials_follow_prepared_once_on_the_wire() {
    if !wire_fixture("credentials_follow_prepared_once_on_the_wire") {
        return;
    }
    let fixture = SocketFixture::new("order");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ipsec);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            reply(&mut decoder, Command::Stop, State::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ipsec, no_probe);
        attempt
            .start(&AtomicBool::new(false), wire_deadline())
            .expect("ordered start");
        assert!(attempt.ready().unwrap());
        assert!(attempt.cleanup());
        server.join().unwrap();
    });
}

#[test]
fn terminal_refusal_after_cleanup_pending_does_not_confirm_stop() {
    if !wire_fixture("terminal_refusal_after_cleanup_pending_does_not_confirm_stop") {
        return;
    }
    let fixture = SocketFixture::new("uncertain");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Stop, State::CleanupPending);
            assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
            decoder
                .reject(WireError::PermissionDenied, wire_deadline())
                .unwrap();
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
        attempt
            .start(&AtomicBool::new(false), wire_deadline())
            .unwrap();
        assert!(!attempt.cleanup());
        assert!(
            !attempt.cleanup(),
            "a refusal after cleanup became pending cannot prove Stopped"
        );
        assert!(!attempt.cleanup());
        server.join().unwrap();
    });
}
