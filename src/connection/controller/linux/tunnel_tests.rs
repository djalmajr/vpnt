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
        |_, _, _, _, _| panic!("probe ran"),
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
    tunneld::protocol::{CLEANUP_VERSION, Command, InitialRequest, ServerDecoder},
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

fn no_probe(
    _: &Profile,
    _: &ProbeBinding,
    _: &AtomicBool,
    _: Instant,
    _: ProbeSlot,
) -> Result<bool, Failure> {
    panic!("probe ran before readiness");
}

fn admitted(fixture: &SocketFixture, kind: VpnKind) -> ServerDecoder {
    admit_stream(fixture.accept(), kind)
}

fn admit_stream(stream: UnixStream, kind: VpnKind) -> ServerDecoder {
    let mut decoder = ServerDecoder::new(stream);
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
    decoder
        .acknowledge(Some(fixture_generation()), wire_deadline())
        .unwrap();
    let secret = decoder.credentials(wire_deadline()).unwrap();
    assert!(secret.password() == TEST_PASSWORD);
    assert!(secret.psk() == (kind == VpnKind::Ipsec).then_some(TEST_PSK));
    decoder
}

fn fixture_generation() -> Generation {
    Generation::parse("0123456789abcdef0123456789abcdef".into()).unwrap()
}

fn query_decoder(fixture: &SocketFixture) -> ServerDecoder {
    let mut decoder = ServerDecoder::new(fixture.accept());
    decoder.hello(wire_deadline()).unwrap();
    let InitialRequest::CleanupStatus(generation) =
        decoder.initial_request(wire_deadline()).unwrap()
    else {
        panic!("expected cleanup query");
    };
    assert_eq!(generation, fixture_generation());
    decoder
}

fn query(fixture: &SocketFixture, state: CleanupState) {
    query_decoder(fixture)
        .reply_cleanup(state, wire_deadline())
        .unwrap();
}

fn fixture_binding(generation: Generation, ifindex: u32) -> ProbeBinding {
    ProbeBinding::new(
        generation,
        ifindex,
        "10.99.0.2".parse().unwrap(),
        vec![CidrV4::new("10.20.0.0".parse().unwrap(), 24).unwrap()],
    )
    .unwrap()
}

fn reply_state(decoder: &mut ServerDecoder, state: State) {
    if state == State::NetworkReady {
        decoder
            .reply_ready(fixture_binding(fixture_generation(), 7), wire_deadline())
            .unwrap();
    } else {
        decoder.reply_status(state, wire_deadline()).unwrap();
    }
}

fn reply(decoder: &mut ServerDecoder, command: Command, state: State) {
    assert_eq!(decoder.command(wire_deadline()).unwrap(), command);
    reply_state(decoder, state);
}

fn expect_confirmation(decoder: &mut ServerDecoder) {
    assert!(matches!(
        decoder.command(wire_deadline()).unwrap(),
        Command::Confirm(_)
    ));
}

fn exercising_worker(fixture: &SocketFixture, kind: VpnKind, responsive: bool) {
    fn success(
        profile: &Profile,
        _: &ProbeBinding,
        _: &AtomicBool,
        _: Instant,
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
            |_, _, _, _, _| Ok(false)
        },
    );
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(fixture, kind);
            reply(&mut decoder, Command::Status, State::Starting);
            let started = Instant::now();
            assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
            assert!(started.elapsed() >= Duration::from_millis(450));
            reply_state(&mut decoder, State::NetworkReady);
            loop {
                if decoder.command(wire_deadline()).unwrap() == Command::Stop {
                    break;
                }
                reply_state(&mut decoder, State::NetworkReady);
            }
            if kind == VpnKind::Ipsec {
                reply_state(&mut decoder, State::Stopping);
                drop(decoder);
                query(fixture, CleanupState::Pending);
                query(fixture, CleanupState::Stopped);
            } else {
                reply_state(&mut decoder, State::Stopped);
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
            drop(decoder);
            query(&fixture, CleanupState::Pending);
            query(&fixture, CleanupState::Stopped);
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
fn stopping_queries_the_receipt_before_returning_from_cleanup() {
    if !wire_fixture("stopping_queries_the_receipt_before_returning_from_cleanup") {
        return;
    }
    let fixture = SocketFixture::new("stopping");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Stop, State::Stopping);
            drop(decoder);
            query(&fixture, CleanupState::Pending);
            query(&fixture, CleanupState::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
        attempt
            .start(&AtomicBool::new(false), wire_deadline())
            .unwrap();

        assert!(!attempt.cleanup(), "Stopping alone is not a receipt");
        assert!(attempt.cleanup(), "the first cleanup must consume Pending");
        assert!(attempt.cleanup(), "confirmed cleanup stays complete");
        server.join().unwrap();
    });
}

#[test]
fn contended_probe_slot_does_not_leave_the_attempt_busy() {
    let mut profile = profile(VpnKind::Ssl);
    profile.id = "contended-tunnel-probe".into();
    let _held = ProbeSlot::acquire(&profile.id).unwrap();
    let mut attempt = TunnelAttempt::with_socket(
        profile,
        Credentials {
            password: Secret::from(TEST_PASSWORD),
            psk: Secret::from(""),
        },
        PathBuf::new(),
        no_probe,
    );
    assert!(
        !attempt
            .probe(&AtomicBool::new(false), CONTROL_TIMEOUT)
            .unwrap()
    );
    assert!(!attempt.probe_busy());
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
                        Ok(crate::tunneld::protocol::Request::Hello {
                            version: CLEANUP_VERSION
                        })
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
                    query(&fixture, CleanupState::Stopped);
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
            assert!(attempt.cleanup());
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
            drop(decoder);
            query_decoder(&fixture)
                .reject(WireError::PermissionDenied, wire_deadline())
                .unwrap();
            query(&fixture, CleanupState::Unknown);
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

#[test]
fn old_daemon_rejects_before_preparation_or_credentials() {
    if !wire_fixture("old_daemon_rejects_before_preparation_or_credentials") {
        return;
    }
    let fixture = SocketFixture::new("old");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            use std::io::{BufRead, BufReader, Read};
            let mut socket = BufReader::new(fixture.accept());
            socket
                .get_ref()
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = String::new();
            socket.read_line(&mut hello).unwrap();
            assert_eq!(hello, "{\"op\":\"hello\",\"version\":2}\n");
            socket
                .get_mut()
                .write_all(b"{\"op\":\"error\",\"code\":\"unsupported_version\"}\n")
                .unwrap();
            assert_eq!(socket.read(&mut [0]).unwrap(), 0);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
        assert!(
            attempt
                .start(&AtomicBool::new(false), wire_deadline())
                .is_err()
        );
        assert!(attempt.cleanup());
        server.join().unwrap();
    });
}

#[test]
fn lost_control_replies_leave_generation_available_for_fresh_queries() {
    if !wire_fixture("lost_control_replies_leave_generation_available_for_fresh_queries") {
        return;
    }
    for stopping in [true, false] {
        let fixture = SocketFixture::new(if stopping { "lost-stop" } else { "lost-status" });
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut decoder = admitted(&fixture, VpnKind::Ssl);
                let command = if stopping {
                    Command::Stop
                } else {
                    Command::Status
                };
                assert_eq!(decoder.command(wire_deadline()).unwrap(), command);
                thread::sleep(if stopping {
                    CONTROL_TIMEOUT + Duration::from_millis(150)
                } else {
                    Duration::from_millis(500)
                });
                drop(decoder);
                query(&fixture, CleanupState::Pending);
                query(&fixture, CleanupState::Stopped);
            });
            let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
            attempt
                .start(&AtomicBool::new(false), wire_deadline())
                .unwrap();
            if stopping {
                assert!(!attempt.cleanup());
            } else {
                attempt.connect_deadline = Instant::now() + Duration::from_millis(150);
                assert!(attempt.ready().is_err());
            }
            assert!(!attempt.cleanup());
            assert!(attempt.cleanup());
            server.join().unwrap();
        });
    }
}

#[test]
fn probe_filters_ipv6_own_address_link_local_and_unaccepted_routes() {
    let binding = ProbeBinding::new(
        fixture_generation(),
        7,
        "10.20.0.2".parse().unwrap(),
        vec![CidrV4::new("10.20.0.0".parse().unwrap(), 24).unwrap()],
    )
    .unwrap();
    let accepted = "10.20.0.15:8443".parse().unwrap();
    assert_eq!(
        allowed_probe_address(&binding, accepted),
        Some("10.20.0.15:8443".parse().unwrap())
    );
    for rejected in [
        "10.20.1.15:8443",
        "10.20.0.2:8443",
        "169.254.2.1:8443",
        "127.0.0.1:8443",
        "[::ffff:10.20.0.15]:8443",
        "[2001:db8::1]:8443",
    ] {
        assert!(allowed_probe_address(&binding, rejected.parse().unwrap()).is_none());
    }
}

#[test]
fn native_loopback_probe_socket_binds_and_bind_failure_has_no_fallback() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let SocketAddr::V4(address) = listener.local_addr().unwrap() else {
        panic!("expected IPv4 listener");
    };
    // SAFETY: this is a static, NUL-terminated interface name.
    let index = NonZeroU32::new(unsafe { libc::if_nametoindex(c"lo".as_ptr()) }).unwrap();
    let cap = || Instant::now() + Duration::from_secs(1);

    let invalid = NonZeroU32::new(u32::MAX).unwrap();
    assert!(connect_bound(invalid, address, cap()).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );

    let socket = connect_bound(index, address, cap()).unwrap();
    assert_eq!(socket.device_index_v4().unwrap(), Some(index));
    let (peer, _) = listener.accept().unwrap();
    drop((peer, socket));
    assert_eq!(
        connect_bound(index, address, Instant::now())
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

fn simulated_tcp_success(
    _: &Profile,
    binding: &ProbeBinding,
    _: &AtomicBool,
    _: Instant,
    _: ProbeSlot,
) -> Result<bool, Failure> {
    assert_eq!(binding.ifindex().get(), 7);
    Ok(true)
}

#[test]
fn initial_and_recovery_probes_recheck_before_accepting_tcp_success() {
    if !wire_fixture("initial_and_recovery_probes_recheck_before_accepting_tcp_success") {
        return;
    }
    let fixture = SocketFixture::new("recheck");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            for _ in 0..2 {
                expect_confirmation(&mut decoder);
                reply_state(&mut decoder, State::NetworkReady);
            }
            reply(&mut decoder, Command::Stop, State::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, simulated_tcp_success);
        let canceled = AtomicBool::new(false);
        attempt.start(&canceled, wire_deadline()).unwrap();
        assert!(attempt.ready().unwrap());
        for _ in 0..2 {
            assert!(attempt.probe(&canceled, Duration::from_secs(1)).unwrap());
        }
        assert!(attempt.cleanup());
        server.join().unwrap();
    });
}

#[test]
fn changed_generation_link_pending_or_lost_channel_invalidates_probe() {
    if !wire_fixture("changed_generation_link_pending_or_lost_channel_invalidates_probe") {
        return;
    }
    for scenario in ["generation", "link", "pending", "eof"] {
        let fixture = SocketFixture::new(scenario);
        thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut decoder = admitted(&fixture, VpnKind::Ssl);
                reply(&mut decoder, Command::Status, State::NetworkReady);
                expect_confirmation(&mut decoder);
                match scenario {
                    "generation" => {
                        let other =
                            Generation::parse("fedcba9876543210fedcba9876543210".into()).unwrap();
                        decoder
                            .reply_ready(fixture_binding(other, 7), wire_deadline())
                            .unwrap();
                    }
                    "link" => decoder
                        .reply_ready(fixture_binding(fixture_generation(), 8), wire_deadline())
                        .unwrap(),
                    "pending" => decoder
                        .reply_status(State::CleanupPending, wire_deadline())
                        .unwrap(),
                    "eof" => {}
                    _ => unreachable!(),
                }
                drop(decoder);
                query(&fixture, CleanupState::Stopped);
            });
            let mut attempt = fixture.attempt(VpnKind::Ssl, simulated_tcp_success);
            let canceled = AtomicBool::new(false);
            attempt.start(&canceled, wire_deadline()).unwrap();
            assert!(attempt.ready().unwrap());
            assert!(
                attempt.probe(&canceled, Duration::from_secs(1)).is_err(),
                "{scenario}"
            );
            assert!(attempt.cleanup(), "{scenario}");
            server.join().unwrap();
        });
    }
}

#[test]
fn successful_tcp_does_not_extend_the_probe_budget_for_status() {
    if !wire_fixture("successful_tcp_does_not_extend_the_probe_budget_for_status") {
        return;
    }
    let fixture = SocketFixture::new("refresh-budget");
    thread::scope(|scope| {
        let (release, wait) = mpsc::channel();
        let (replied, late_reply) = mpsc::channel();
        let fixture = &fixture;
        let peer = scope.spawn(move || {
            let mut decoder = admitted(fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            expect_confirmation(&mut decoder);
            wait.recv_timeout(Duration::from_secs(2)).unwrap();
            reply_state(&mut decoder, State::NetworkReady);
            replied.send(()).unwrap();
            expect_confirmation(&mut decoder);
            reply_state(&mut decoder, State::NetworkReady);
            reply(&mut decoder, Command::Stop, State::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, simulated_tcp_success);
        let canceled = AtomicBool::new(false);
        attempt.start(&canceled, wire_deadline()).unwrap();
        assert!(attempt.ready().unwrap());
        let started = Instant::now();
        let result = attempt.probe(&canceled, Duration::from_millis(120));
        let elapsed = started.elapsed();
        release.send(()).unwrap();
        assert!(matches!(result, Ok(false)), "{result:?}");
        assert!(elapsed >= Duration::from_millis(40), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(240), "{elapsed:?}");
        late_reply.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(attempt.healthy().is_ok());
        assert!(attempt.probe(&canceled, Duration::from_secs(1)).unwrap());
        assert!(attempt.cleanup());
        peer.join().unwrap();
    });
}

#[test]
fn exhausted_tcp_reservation_sends_no_confirmation() {
    if !wire_fixture("exhausted_tcp_reservation_sends_no_confirmation") {
        return;
    }
    let fixture = SocketFixture::new("no-confirmation-budget");
    thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            reply(&mut decoder, Command::Stop, State::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, |_, _, _, cutoff, _| {
            thread::sleep(cutoff.saturating_duration_since(Instant::now()));
            Ok(true)
        });
        let canceled = AtomicBool::new(false);
        attempt.start(&canceled, wire_deadline()).unwrap();
        assert!(attempt.ready().unwrap());
        let started = Instant::now();
        assert!(
            !attempt
                .probe(&canceled, Duration::from_millis(120))
                .unwrap()
        );
        assert!(started.elapsed() < Duration::from_millis(240));
        assert!(attempt.cleanup());
        peer.join().unwrap();
    });
}

#[test]
fn worker_recovers_after_unconfirmed_samples_on_the_same_session() {
    use std::io::Write;

    if !wire_fixture("worker_recovers_after_unconfirmed_samples_on_the_same_session") {
        return;
    }
    static SAMPLES: AtomicUsize = AtomicUsize::new(0);
    let fixture = SocketFixture::new("worker-reconfirm");
    thread::scope(|scope| {
        let (release, wait) = mpsc::channel();
        let (replied, late_reply) = mpsc::channel();
        let fixture = &fixture;
        let peer = scope.spawn(move || {
            let mut stream = fixture.accept();
            let mut decoder = admit_stream(stream.try_clone().unwrap(), VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            expect_confirmation(&mut decoder);

            // Retain a partial line across the sample deadline.
            let response = serde_json::to_vec(&crate::tunneld::protocol::Response::NetworkReady {
                binding: fixture_binding(fixture_generation(), 7),
            })
            .unwrap();
            let middle = response.len() / 2;
            stream.write_all(&response[..middle]).unwrap();
            wait.recv_timeout(wire_deadline().saturating_duration_since(Instant::now()))
                .unwrap();
            stream.write_all(&response[middle..]).unwrap();
            stream.write_all(b"\n").unwrap();
            replied.send(()).unwrap();

            expect_confirmation(&mut decoder);
            reply_state(&mut decoder, State::NetworkReady);
            expect_confirmation(&mut decoder);
            decoder
                .reply_ready(fixture_binding(fixture_generation(), 8), wire_deadline())
                .unwrap();
            drop((stream, decoder));
            query(fixture, CleanupState::Stopped);
        });
        let attempt = fixture.attempt(VpnKind::Ssl, |_, _, _, cutoff, _| {
            match SAMPLES.fetch_add(1, Ordering::Relaxed) {
                0 => thread::sleep(cutoff.saturating_duration_since(Instant::now())),
                1 => thread::sleep(
                    cutoff
                        .saturating_duration_since(Instant::now())
                        .saturating_sub(Duration::from_millis(35)),
                ),
                _ => {}
            }
            Ok(true)
        });
        let state = Arc::new(Mutex::new(None));
        let requested = Arc::new(AtomicBool::new(false));
        let exit = Arc::new(worker::ExitRequested::new(Duration::ZERO));
        let worker_signals = worker::Signals {
            canceled: Arc::new(AtomicBool::new(false)),
            probe: requested.clone(),
            state: state.clone(),
            exit: exit.clone(),
        };
        let timing = Timing {
            probe: Duration::from_millis(320),
            health: Duration::from_secs(30),
            interval: Duration::from_secs(30),
            ..Timing::default()
        };
        let waiter = scope.spawn(move || {
            worker::run(
                attempt,
                worker_signals,
                timing,
                ProbeClock::new(timing.interval),
            )
        });
        let observe = |expected, failures| {
            let until = wire_deadline();
            loop {
                let progress = *state.lock().unwrap();
                if progress.is_some_and(|p| p.state == expected && p.failures == failures) {
                    return;
                }
                if Instant::now() >= until {
                    exit.request();
                    panic!("expected {expected:?}/{failures}, observed {progress:?}");
                }
                thread::sleep(Duration::from_millis(5));
            }
        };
        observe(ConnectionState::Unresponsive, 1);
        let started = Instant::now();
        requested.store(true, Ordering::Release);
        observe(ConnectionState::Unresponsive, 2);
        assert!(started.elapsed() < timing.probe + timing.poll * 2 + Duration::from_millis(80));
        release.send(()).unwrap();
        late_reply.recv_timeout(Duration::from_secs(2)).unwrap();

        requested.store(true, Ordering::Release);
        observe(ConnectionState::Connected, 0);
        requested.store(true, Ordering::Release);
        let finished = waiter.join().unwrap();
        assert_eq!(finished.state, ConnectionState::Dropped);
        assert_eq!(finished.step, Some(Step::Verify));
        peer.join().unwrap();
        assert_eq!(SAMPLES.load(Ordering::Relaxed), 4);
    });
}

#[test]
fn cancellation_during_tcp_discards_success_without_status_refresh() {
    if !wire_fixture("cancellation_during_tcp_discards_success_without_status_refresh") {
        return;
    }
    let fixture = SocketFixture::new("cancel-probe");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            reply(&mut decoder, Command::Stop, State::Stopped);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, |_, _, cancel, _, _| {
            cancel.store(true, Ordering::Release);
            Ok(true)
        });
        let canceled = AtomicBool::new(false);
        attempt.start(&canceled, wire_deadline()).unwrap();
        assert!(attempt.ready().unwrap());
        assert!(!attempt.probe(&canceled, Duration::from_secs(1)).unwrap());
        assert!(attempt.cleanup());
        server.join().unwrap();
    });
}

#[test]
fn unknown_cleanup_proof_enters_an_explicit_fence_without_polling_again() {
    if !wire_fixture("unknown_cleanup_proof_enters_an_explicit_fence_without_polling_again") {
        return;
    }
    let fixture = SocketFixture::new("expired-proof");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Stop, State::Stopping);
            drop(decoder);
            query(&fixture, CleanupState::Unknown);
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
        attempt
            .start(&AtomicBool::new(false), wire_deadline())
            .unwrap();
        assert!(!attempt.cleanup());
        assert_eq!(attempt.phase(), Some(ConnectionState::CleanupUnconfirmed));
        assert!(!attempt.cleanup());
        server.join().unwrap();
        assert_eq!(
            fixture.listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    });
}

#[test]
fn expired_observation_budget_keeps_unavailable_cleanup_fenced() {
    if !wire_fixture("expired_observation_budget_keeps_unavailable_cleanup_fenced") {
        return;
    }
    let fixture = SocketFixture::new("unavailable-proof");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Stop, State::Stopping);
            drop(decoder);
            drop(fixture.accept()); // the independent query gets a transport failure
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, no_probe);
        attempt
            .start(&AtomicBool::new(false), wire_deadline())
            .unwrap();
        assert!(!attempt.cleanup());
        assert_eq!(attempt.phase(), None);
        attempt.cleanup_until = Some(Instant::now());
        assert!(!attempt.cleanup());
        assert_eq!(attempt.phase(), Some(ConnectionState::CleanupUnconfirmed));
        server.join().unwrap();
        assert_eq!(
            fixture.listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    });
}

#[test]
fn unconfirmed_cleanup_reports_a_typed_error_while_the_worker_holds_admission() {
    if !wire_fixture("unconfirmed_cleanup_reports_a_typed_error_while_the_worker_holds_admission") {
        return;
    }
    // Permit only fixture shutdown to join a production controller whose
    // real attempt intentionally keeps the admission fence.
    struct Exitable(TunnelAttempt);
    impl Attempt for Exitable {
        fn start(&mut self, canceled: &AtomicBool, deadline: Instant) -> Result<(), Failure> {
            self.0.start(canceled, deadline)
        }
        fn ready(&mut self) -> Result<bool, Failure> {
            self.0.ready()
        }
        fn healthy(&mut self) -> Result<(), Failure> {
            self.0.healthy()
        }
        fn probe(&mut self, canceled: &AtomicBool, timeout: Duration) -> Result<bool, Failure> {
            self.0.probe(canceled, timeout)
        }
        fn phase(&self) -> Option<ConnectionState> {
            self.0.phase()
        }
        fn cleanup(&mut self) -> bool {
            self.0.cleanup()
        }
        fn abandon(
            &mut self,
            _: crate::helper::runtime::cleanup::Reason,
        ) -> Result<(), super::super::super::AbandonError> {
            Ok(())
        }
    }

    struct ExitOnDrop(Arc<worker::ExitRequested>);
    impl Drop for ExitOnDrop {
        fn drop(&mut self) {
            self.0.request();
        }
    }

    let fixture = SocketFixture::new("typed-proof");
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let mut decoder = admitted(&fixture, VpnKind::Ssl);
            assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
            decoder.reject(WireError::Backend, wire_deadline()).unwrap();
            query(&fixture, CleanupState::Unknown);
        });
        let exit = Arc::new(worker::ExitRequested::new(Duration::ZERO));
        let _exit = ExitOnDrop(exit.clone());
        let progress = Arc::new(Mutex::new(None));
        let signals = worker::Signals {
            canceled: Arc::new(AtomicBool::new(false)),
            probe: Arc::new(AtomicBool::new(false)),
            state: progress.clone(),
            exit: exit.clone(),
        };
        let attempt = Exitable(fixture.attempt(VpnKind::Ssl, no_probe));
        let timing = Timing::default();
        let worker = scope
            .spawn(move || worker::run(attempt, signals, timing, ProbeClock::new(timing.interval)));
        let deadline = wire_deadline();
        let notice = loop {
            if let Some(notice) = *progress.lock().unwrap()
                && notice.state == ConnectionState::CleanupUnconfirmed
            {
                break notice;
            }
            assert!(
                Instant::now() < deadline,
                "worker did not publish the cleanup failure"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert!(!notice.cleaning);
        assert_eq!(
            notice.failure,
            Some(crate::helper::protocol::FailureNote {
                code: ErrorCode::BackendFailure,
                step: Step::Tunnel,
            })
        );
        assert!(!worker.is_finished());
        server.join().unwrap();
        exit.request();
        worker.join().unwrap();
    });
}
