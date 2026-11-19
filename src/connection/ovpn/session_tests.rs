//! Contract tests for the management conversation: the driver talks to a
//! scripted openvpn over a socket pair, with a fake token.
use super::*;
use crate::connection::ovpn::signing::Hash;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{io::BufRead, os::unix::fs::PermissionsExt};

#[derive(Clone, Default)]
struct FakeToken {
    refusal: Option<SignError>,
    no_certificate: bool,
    /// How long `sign` takes, like a user approving on a phone.
    delay: Duration,
    /// When set, `sign` waits for the test to open the gate.
    gate: Option<Arc<Mutex<mpsc::Receiver<()>>>>,
    requests: Arc<Mutex<Vec<(Padding, usize)>>>,
}

impl Signer for FakeToken {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        if self.no_certificate {
            return Err(SignError::Unavailable);
        }
        Ok(vec![1, 2, 3])
    }

    fn sign(&mut self, padding: Padding, data: &[u8]) -> Result<Vec<u8>, SignError> {
        if let Some(gate) = &self.gate {
            let _ = gate.lock().unwrap().recv_timeout(Duration::from_secs(5));
        }
        thread::sleep(self.delay);
        self.requests.lock().unwrap().push((padding, data.len()));
        self.refusal.map_or(Ok(vec![9; 4]), Err)
    }
}

struct Openvpn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    worker: JoinHandle<()>,
    reason: Arc<Mutex<Option<Reason>>>,
    progress: mpsc::Receiver<Progress>,
}

impl Openvpn {
    fn connect(token: FakeToken) -> Self {
        let (driver, openvpn) = UnixStream::pair().unwrap();
        openvpn
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let control = Arc::new(Mutex::new(driver.try_clone().unwrap()));
        let reason = Arc::new(Mutex::new(None));
        let (sender, progress) = mpsc::channel();
        let last_reason = Arc::clone(&reason);
        let worker = thread::spawn(move || drive(driver, &control, token, &sender, &last_reason));
        let mut session = Self {
            writer: openvpn.try_clone().unwrap(),
            reader: BufReader::new(openvpn),
            worker,
            reason,
            progress,
        };
        assert_eq!(session.hear(), "version 3\n");
        assert_eq!(session.hear(), "state on\n");
        session
    }

    fn say(&mut self, line: &str) {
        self.writer.write_all(line.as_bytes()).unwrap();
    }

    fn hear(&mut self) -> String {
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        line
    }

    fn hear_block(&mut self) -> String {
        let mut lines = Vec::new();
        while lines.last().is_none_or(|line| line != "END\n") {
            lines.push(self.hear());
        }
        lines.concat()
    }

    fn hang_up(self) -> (Option<Reason>, Vec<Progress>) {
        self.writer.shutdown(Shutdown::Both).unwrap();
        self.worker.join().unwrap();
        let reason = *self.reason.lock().unwrap();
        (reason, self.progress.try_iter().collect())
    }
}

fn pss_request(digest_len: usize) -> String {
    format!(
        ">PK_SIGN:{},RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest\n",
        STANDARD.encode(vec![5; digest_len])
    )
}

#[test]
fn hold_is_released_after_the_greeting() {
    // Mutation captured: never answering HOLD leaves openvpn parked forever.
    let mut openvpn = Openvpn::connect(FakeToken::default());
    openvpn.say(">HOLD:Waiting for hold release:0\n");
    assert_eq!(openvpn.hear(), "hold release\n");
}

#[test]
fn certificate_request_is_answered_with_the_token_certificate() {
    let mut openvpn = Openvpn::connect(FakeToken::default());
    openvpn.say(">NEED-CERTIFICATE:vpnt\n");
    assert_eq!(
        openvpn.hear_block(),
        "certificate\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\nEND\n"
    );
}

#[test]
fn a_missing_certificate_stops_openvpn_and_says_why() {
    let token = FakeToken {
        no_certificate: true,
        ..FakeToken::default()
    };
    let mut openvpn = Openvpn::connect(token);
    openvpn.say(">NEED-CERTIFICATE:vpnt\n");
    assert_eq!(openvpn.hear(), "signal SIGTERM\n");
    let (_, progress) = openvpn.hang_up();
    assert_eq!(progress, [Progress::Refused(SignError::Unavailable)]);
}

#[test]
fn pss_request_reaches_the_token_with_its_hash() {
    let token = FakeToken::default();
    let mut openvpn = Openvpn::connect(token.clone());
    openvpn.say(&pss_request(32));
    assert_eq!(openvpn.hear_block(), "pk-sig\nCQkJCQ==\nEND\n");
    assert_eq!(
        *token.requests.lock().unwrap(),
        [(Padding::Pss(Hash::Sha256), 32)]
    );
}

#[test]
fn the_wait_for_approval_is_announced_before_the_token_is_asked() {
    // Mutation captured: announcing after `sign` leaves the user staring at
    // "connecting" while the phone waits for an approval.
    let (open, gate) = mpsc::channel();
    let token = FakeToken {
        gate: Some(Arc::new(Mutex::new(gate))),
        ..FakeToken::default()
    };
    let mut openvpn = Openvpn::connect(token);
    openvpn.say(&pss_request(32));
    let announced = openvpn.progress.recv_timeout(Duration::from_secs(2));
    open.send(()).unwrap();
    assert_eq!(announced, Ok(Progress::AwaitingApproval));
    assert_eq!(openvpn.hear_block(), "pk-sig\nCQkJCQ==\nEND\n");
}

#[test]
fn unsupported_unreadable_or_oversized_requests_leave_without_asking_the_user() {
    // Mutation captured: skipping validation would prompt the user and sign
    // data openvpn cannot have produced; ignoring an unreadable request would
    // leave openvpn waiting for an answer.
    for request in [
        ">PK_SIGN:AAEC,RSA_NO_PADDING\n".to_owned(),
        ">PK_SIGN:%%%,RSA_PKCS1_PADDING\n".to_owned(),
        pss_request(48),
    ] {
        let token = FakeToken::default();
        let mut openvpn = Openvpn::connect(token.clone());
        openvpn.say(&request);
        assert_eq!(openvpn.hear(), "signal SIGTERM\n", "{request}");
        assert!(token.requests.lock().unwrap().is_empty());
        let (_, progress) = openvpn.hang_up();
        assert_eq!(progress, [Progress::Refused(SignError::Unsupported)]);
    }
}

#[test]
fn a_declined_approval_stops_openvpn_and_says_why() {
    let token = FakeToken {
        refusal: Some(SignError::Canceled),
        ..FakeToken::default()
    };
    let mut openvpn = Openvpn::connect(token);
    openvpn.say(&pss_request(32));
    assert_eq!(openvpn.hear(), "signal SIGTERM\n");
    let (_, progress) = openvpn.hang_up();
    assert_eq!(
        progress,
        [
            Progress::AwaitingApproval,
            Progress::Refused(SignError::Canceled)
        ]
    );
}

#[test]
fn the_exit_reason_survives_until_openvpn_hangs_up() {
    // Mutation captured: not keeping the reason reports a refused profile as
    // an ordinary disconnect.
    let mut openvpn = Openvpn::connect(FakeToken::default());
    openvpn.say(">STATE:1,GET_CONFIG,,,,,,\n");
    openvpn.say(">STATE:2,EXITING,auth-failure,,,,,\n");
    let (reason, progress) = openvpn.hang_up();
    assert_eq!(reason, Some(Reason::AuthFailure));
    assert_eq!(progress.len(), 2);
}

#[test]
fn a_fatal_error_is_the_exit_reason() {
    let mut openvpn = Openvpn::connect(FakeToken::default());
    openvpn.say(">FATAL:cannot allocate TUN/TAP dev dynamically\n");
    let (reason, _) = openvpn.hang_up();
    assert_eq!(reason, Some(Reason::Fatal));
}

#[test]
fn an_overlong_line_ends_the_conversation() {
    // Mutation captured: an unbounded read would wait for a newline forever.
    let mut openvpn = Openvpn::connect(FakeToken::default());
    openvpn.say(&"x".repeat(management::MAX_LINE + 1));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !openvpn.worker.is_finished() {
        assert!(Instant::now() < deadline, "driver kept reading");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn the_socket_directory_is_private_and_removed() {
    // Mutation captured: a group- or world-readable directory lets another
    // local user reach the socket and request signatures.
    let directory = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let mode = fs::metadata(&directory.path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    let path = directory.path.clone();
    drop(directory);
    assert!(!path.exists());
}

fn launch(openvpn: &Path) -> Launch {
    Launch {
        openvpn: openvpn.to_path_buf(),
        config: PathBuf::from("/dev/null"),
        dev: None,
        signatures: Signatures::Any,
        extra: Vec::new(),
        env: Vec::new(),
    }
}

/// A stand-in openvpn: connects to the management socket it is given, sends
/// `lines`, lingers `linger` seconds and exits. python3 is on both CI runners
/// and required here: a missing interpreter fails these tests, not skips them.
fn scripted_openvpn(directory: &Path, lines: &str, linger: f32) -> PathBuf {
    let python = std::process::Command::new("python3").arg("-V").output();
    assert!(
        python.is_ok_and(|output| output.status.success()),
        "python3 is required for the scripted openvpn tests"
    );
    let path = directory.join("openvpn");
    let script = format!(
        "#!/usr/bin/env python3\nimport socket, sys, time\n\
         if '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\n\
         path = sys.argv[sys.argv.index('--management') + 1]\n\
         s = socket.socket(socket.AF_UNIX)\ns.connect(path)\n\
         s.sendall({lines:?}.encode())\ntime.sleep({linger})\n"
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Starts a session on a script written moments ago. Another test thread that
/// forks while the script was open for writing can make exec fail with
/// "Text file busy" until that child execs; that error is retried.
fn start_scripted(openvpn: &Path, token: FakeToken) -> Session {
    for _ in 0..50 {
        match Session::start(launch(openvpn), token.clone()) {
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                thread::sleep(Duration::from_millis(20));
            }
            result => return result.unwrap(),
        }
    }
    panic!("scripted openvpn stayed busy");
}

#[test]
fn an_openvpn_that_exits_early_fails_the_start_promptly() {
    let started = Instant::now();
    let error = Session::start(launch(Path::new("/usr/bin/false")), FakeToken::default())
        .err()
        .expect("start must fail");
    assert!(
        error.to_string().contains("version check failed"),
        "{error}"
    );
    assert!(started.elapsed() < CONNECT_TIMEOUT);
}

#[test]
fn a_refusal_reported_just_before_exit_reaches_the_outcome() {
    // Mutation captured: reading the reason as soon as openvpn is reaped,
    // before its last lines are parsed, reports a refused profile as an
    // ordinary disconnect. openvpn here exits while the token is still busy.
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let lines = format!("{}>STATE:2,EXITING,auth-failure,,,,,\n", pss_request(32));
    let openvpn = scripted_openvpn(&scratch.path, &lines, 0.0);
    let token = FakeToken {
        delay: Duration::from_millis(300),
        ..FakeToken::default()
    };
    let session = start_scripted(&openvpn, token);
    assert_eq!(session.wait().unwrap().reason, Some(Reason::AuthFailure));
}

#[test]
fn a_signature_pending_approval_does_not_hold_up_wait() {
    // Mutation captured: joining the management thread unconditionally keeps
    // a disconnect waiting until the token gives up on the approval.
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let openvpn = scripted_openvpn(&scratch.path, &pss_request(32), 0.2);
    let token = FakeToken {
        delay: Duration::from_secs(4),
        ..FakeToken::default()
    };
    let session = start_scripted(&openvpn, token);
    let started = Instant::now();
    session.wait().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn up_down_and_block_boundaries() {
    let mut vpn = Openvpn::connect(FakeToken::default());
    vpn.say(">UPDOWN:UP\n>UPDOWN:ENV,ifconfig_local=10.81.0.2\n>UPDOWN:ENV,ifconfig_netmask=255.255.255.0\n>UPDOWN:ENV,END\n>UPDOWN:DOWN\n>UPDOWN:ENV,ignored=value\n>UPDOWN:ENV,END\n");
    let (_, progress) = vpn.hang_up();
    assert!(
        matches!(&progress[..], [Progress::Up(c), Progress::Down] if c.prefix == 24 && c.address == std::net::Ipv4Addr::new(10,81,0,2))
    );
}

#[test]
fn invalid_network_stops_and_reports() {
    let mut vpn = Openvpn::connect(FakeToken::default());
    vpn.say(">UPDOWN:UP\n>UPDOWN:ENV,ifconfig_netmask=255.255.255.0\n>UPDOWN:ENV,END\n");
    assert_eq!(vpn.hear(), management::TERMINATE);
    let (_, progress) = vpn.hang_up();
    assert_eq!(
        progress,
        [Progress::BadNetwork(NetworkError::MissingAddress)]
    );
}

#[test]
fn oversized_network_stops_and_reports() {
    let mut vpn = Openvpn::connect(FakeToken::default());
    vpn.say(">UPDOWN:UP\n");
    for _ in 0..1025 {
        vpn.say(">UPDOWN:ENV,k=v\n");
    }
    assert_eq!(vpn.hear(), management::TERMINATE);
    let (_, progress) = vpn.hang_up();
    assert_eq!(progress, [Progress::BadNetwork(NetworkError::TooLarge)]);
}

#[test]
fn launch_passes_device_and_management_up_down() {
    let directory = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = directory.path.join("openvpn");
    fs::write(&executable, "#!/usr/bin/env python3\nimport socket,sys,time\na=sys.argv\nif '--version' in a: print('OpenVPN 2.6.19'); sys.exit(0)\ni=a.index('--dev')\nassert a[i:i+5] == ['--dev','vpnt0','--dev-type','tun','--disable-dco']\nassert '--management-up-down' in a\nc=a.index('--config')\nr=a.index('--remote-cert-tls')\nassert r > c+1 and a[r+1] == 'server'\ns=socket.socket(socket.AF_UNIX)\ns.connect(a[a.index('--management')+1])\ntime.sleep(.2)\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let mut settings = launch(&executable);
    settings.dev = Some("vpnt0".into());
    let session = Session::start(settings, FakeToken::default()).unwrap();
    session.wait().unwrap();
}

#[test]
fn up_block_without_end_is_rejected_and_the_line_still_handled() {
    // Every line other than ENV records and END inside an open UP block
    // rejects it, even well-formed ones; the line is then processed as usual.
    for (line, reply) in [
        (">HOLD:waiting\n", Some(management::HOLD_RELEASE)),
        (">STATE:1,CONNECTED,SUCCESS,10.81.0.2,,,,\n", None),
        (
            ">PK_SIGN:%%%,RSA_PKCS1_PADDING\n",
            Some(management::TERMINATE),
        ),
        (">UPDOWN:UP\n", None),
        (">UPDOWN:DOWN\n", None),
    ] {
        let mut vpn = Openvpn::connect(FakeToken::default());
        vpn.say(">UPDOWN:UP\n>UPDOWN:ENV,ifconfig_local=10.81.0.2\n>UPDOWN:ENV,ifconfig_netmask=255.255.255.0\n");
        vpn.say(line);
        assert_eq!(vpn.hear(), management::TERMINATE, "{line}");
        if let Some(reply) = reply {
            assert_eq!(vpn.hear(), reply, "{line}");
        }
        let (_, progress) = vpn.hang_up();
        assert!(
            !progress.iter().any(|p| matches!(p, Progress::Up(_))),
            "{line}: {progress:?}"
        );
        assert!(
            progress.contains(&Progress::BadNetwork(NetworkError::Malformed)),
            "{line}: {progress:?}"
        );
    }
}

#[test]
fn openvpn_version_parsing() {
    assert_eq!(
        parse_version(b"OpenVPN 2.7.8 [git:example]\n"),
        Some((2, 7))
    );
    assert_eq!(parse_version(b"OpenVPN 2.6.19 x86_64\n"), Some((2, 6)));
    assert_eq!(parse_version(b"OpenVPN 3.0.0\n"), Some((3, 0)));
    assert_eq!(parse_version(b"garbage\n"), None);
    assert_eq!(parse_version(b"OpenVPN bad\n"), None);
    assert_eq!(parse_version(b"\xff"), None);
}

#[test]
fn dns_updown_follows_extra_options_only_for_supported_versions() {
    for (version, expected) in [
        (
            Some((2, 7)),
            vec!["--dns-updown", "other", "--dns-updown", "disable"],
        ),
        (
            Some((3, 0)),
            vec!["--dns-updown", "other", "--dns-updown", "disable"],
        ),
        (Some((2, 6)), vec!["--dns-updown", "other"]),
        (None, vec!["--dns-updown", "other"]),
    ] {
        let mut command = Command::new("openvpn");
        add_extra_options(
            &mut command,
            &["--dns-updown".into(), "other".into()],
            version,
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            expected
                .iter()
                .map(std::ffi::OsStr::new)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn version_detection_caches_and_times_out() {
    let dir = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = dir.path.join("version");
    let marker = dir.path.join("calls");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf x >> '{}'\nprintf 'OpenVPN 2.7.8 test\\n'\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(version_for(&executable).unwrap(), Some((2, 7)));
    assert_eq!(version_for(&executable).unwrap(), Some((2, 7)));
    assert_eq!(fs::read(&marker).unwrap(), b"x");
    let slow = dir.path.join("slow");
    fs::write(&slow, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    fs::set_permissions(&slow, fs::Permissions::from_mode(0o755)).unwrap();
    let start = Instant::now();
    assert_eq!(
        version_for(&slow).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() < Duration::from_secs(7));
}

#[test]
fn malformed_up_environment_rejects_block_and_terminates() {
    for invalid in [
        ">UPDOWN:ENV,broken\n",
        ">UPDOWN:ENV,=value\n",
        ">UPDOWN:ENV,key=\u{fffd}\n",
        ">UPDOWN:ENV\n",
        ">UPDOWN:UNKNOWN\n",
        ">STATE:not-a-number\n",
    ] {
        let mut vpn = Openvpn::connect(FakeToken::default());
        vpn.say(">UPDOWN:UP\n>UPDOWN:ENV,ifconfig_local=10.81.0.2\n>UPDOWN:ENV,ifconfig_netmask=255.255.255.0\n");
        if invalid.contains('\u{fffd}') {
            vpn.writer.write_all(b">UPDOWN:ENV,key=\xff\n").unwrap();
        } else {
            vpn.say(invalid);
        }
        vpn.say(">UPDOWN:ENV,END\n");
        assert_eq!(vpn.hear(), management::TERMINATE);
        let (_, progress) = vpn.hang_up();
        assert_eq!(progress, [Progress::BadNetwork(NetworkError::Malformed)]);
    }
}

#[test]
fn malformed_environment_outside_up_and_in_down_is_ignored() {
    let mut vpn = Openvpn::connect(FakeToken::default());
    vpn.say(
        ">UPDOWN:ENV,broken\n>UPDOWN:DOWN\n>UPDOWN:ENV,=invalid\n>UPDOWN:ENV,END\n>HOLD:waiting\n",
    );
    assert_eq!(vpn.hear(), management::HOLD_RELEASE);
    let (_, progress) = vpn.hang_up();
    assert_eq!(progress, [Progress::Down]);
}

#[test]
fn stop_times_out_when_management_does_not_read() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scratch.path.join("openvpn");
    fs::write(&executable, "#!/usr/bin/python3\nimport socket,sys,time\nif '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\ns=socket.socket(socket.AF_UNIX)\ns.connect(sys.argv[sys.argv.index('--management')+1])\nb=b''\nwhile b.count(b'\\n') < 2: b+=s.recv(1024)\ns.sendall(b'>STATE:1,CONNECTING,,,,,,,\\n')\ntime.sleep(20)\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let session = start_scripted(&executable, FakeToken::default());
    assert!(matches!(
        session
            .progress()
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        Progress::State(_)
    ));
    assert_eq!(
        session.control.lock().unwrap().write_timeout().unwrap(),
        Some(Duration::from_secs(2))
    );
    let mut fill = session.control.lock().unwrap().try_clone().unwrap();
    fill.set_nonblocking(true).unwrap();
    loop {
        match fill.write(&[0u8; 8192]) {
            Ok(0) => panic!("management socket closed while filling"),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("filling management socket: {e}"),
        }
    }
    fill.set_nonblocking(false).unwrap();
    let control = Arc::clone(&session.control);
    let held = control.lock().unwrap();
    let (send, recv) = mpsc::channel();
    let worker = thread::spawn(move || {
        let start = Instant::now();
        let result = session.stop();
        let _ = send.send((result, start.elapsed()));
    });
    thread::sleep(Duration::from_millis(1300));
    drop(held);
    let outcome = recv.recv_timeout(Duration::from_millis(1600));
    let _ = fill.shutdown(Shutdown::Both);
    worker.join().unwrap();
    let (result, elapsed) = outcome.expect("stop blocked for more than 3 seconds");
    assert!(result.is_err(), "full socket should time out");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

#[test]
fn stop_times_out_waiting_for_control_lock() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scripted_openvpn(&scratch.path, "", 20.0);
    let session = start_scripted(&executable, FakeToken::default());
    let control = Arc::clone(&session.control);
    let held = control.lock().unwrap();
    let (send, recv) = mpsc::channel();
    let worker = thread::spawn(move || {
        let started = Instant::now();
        let result = session.stop();
        let _ = send.send((result, started.elapsed()));
    });
    let observed = recv.recv_timeout(Duration::from_secs(3));
    drop(held);
    worker.join().unwrap();
    let (result, elapsed) = observed.expect("stop waited over 3 seconds for control lock");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn observed_exit_has_a_total_management_drain_budget() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scripted_openvpn(&scratch.path, &pss_request(32), 0.0);
    let (release, gate) = mpsc::channel();
    let session = start_scripted(
        &executable,
        FakeToken {
            gate: Some(Arc::new(Mutex::new(gate))),
            ..FakeToken::default()
        },
    );
    assert_eq!(
        session
            .progress()
            .recv_timeout(Duration::from_secs(2))
            .unwrap(),
        Progress::AwaitingApproval
    );
    let start = Instant::now();
    let mut observed = None;
    while start.elapsed() < Duration::from_millis(1500) {
        observed = session.exited();
        if observed.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let elapsed = start.elapsed();
    let again_at = Instant::now();
    let again = session.exited();
    let again_elapsed = again_at.elapsed();
    let _ = release.send(());
    session.wait().unwrap();
    assert!(
        observed.is_some(),
        "dead child remained running after {elapsed:?}"
    );
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    assert!(again.is_some());
    assert!(
        again_elapsed < Duration::from_millis(100),
        "drain budget restarted: {again_elapsed:?}"
    );
}
