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
                    decoder
                        .reply_status(State::Stopped, wire_deadline())
                        .unwrap();
                    break;
                }
                reply_state(&mut decoder, State::NetworkReady);
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
            reply(&mut decoder, Command::Status, State::NetworkReady);
            reply(&mut decoder, Command::Status, State::NetworkReady);
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
                assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
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
        let fixture = &fixture;
        let peer = scope.spawn(move || {
            let mut decoder = admitted(fixture, VpnKind::Ssl);
            reply(&mut decoder, Command::Status, State::NetworkReady);
            assert_eq!(decoder.command(wire_deadline()).unwrap(), Command::Status);
            wait.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        let mut attempt = fixture.attempt(VpnKind::Ssl, simulated_tcp_success);
        let canceled = AtomicBool::new(false);
        attempt.start(&canceled, wire_deadline()).unwrap();
        assert!(attempt.ready().unwrap());
        let started = Instant::now();
        let result = attempt.probe(&canceled, Duration::from_millis(120));
        let elapsed = started.elapsed();
        release.send(()).unwrap();
        assert!(result.is_err());
        assert!(elapsed >= Duration::from_millis(100));
        assert!(elapsed < Duration::from_millis(750), "{elapsed:?}");
        peer.join().unwrap();
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
