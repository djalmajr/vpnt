//! Contract tests for the management conversation: the driver talks to a
//! scripted openvpn over a socket pair, with a fake token.
use super::*;
use crate::connection::ovpn::signing::Hash;
use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::MetadataExt;
use std::{io::BufRead, os::unix::fs::PermissionsExt};
#[cfg(not(target_os = "linux"))]
use std::{os::unix::ffi::OsStrExt, os::unix::fs::DirBuilderExt};

#[derive(Clone, Default)]
struct FakeToken {
    refusal: Option<SignError>,
    no_certificate: bool,
    /// How long `sign` takes, like a user approving on a phone.
    delay: Duration,
    /// When set, `sign` waits for the test to open the gate.
    gate: Option<Arc<Mutex<mpsc::Receiver<()>>>>,
    signing: Option<mpsc::Sender<()>>,
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
        if let Some(signing) = &self.signing {
            let _ = signing.send(());
        }
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
fn hold_is_released_after_down() {
    let mut vpn = Openvpn::connect(FakeToken::default());
    vpn.say(">UPDOWN:DOWN\n>UPDOWN:ENV,END\n>HOLD:Waiting for hold release:0\n");
    assert_eq!(vpn.hear(), management::HOLD_RELEASE);
    let (_, progress) = vpn.hang_up();
    assert_eq!(progress, [Progress::Down]);
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

fn session_base() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::temp_dir()
    }
}

fn test_policy() -> RestartPolicy {
    #[cfg(target_os = "linux")]
    {
        RestartPolicy::Caller
    }
    #[cfg(not(target_os = "linux"))]
    {
        RestartPolicy::Immediate
    }
}

fn launch(openvpn: &Path) -> Launch<ConfigSource> {
    #[cfg(target_os = "linux")]
    let config = ConfigSource::Path(PathBuf::from("/dev/null"));
    #[cfg(not(target_os = "linux"))]
    let config = ConfigSource::private(b"");
    Launch {
        openvpn: openvpn.to_path_buf(),
        config,
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
    start_scripted_with_policy(openvpn, token, test_policy())
}

fn start_scripted_with_policy(openvpn: &Path, token: FakeToken, policy: RestartPolicy) -> Session {
    for _ in 0..50 {
        match Session::start_with(launch(openvpn), token.clone(), &session_base(), policy) {
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
fn session_approval_pending_tracks_a_blocked_signature_until_success_or_refusal() {
    for refusal in [None, Some(SignError::Canceled)] {
        let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
        let lines = format!("{}>UPDOWN:DOWN\n>UPDOWN:ENV,END\n", pss_request(32));
        let openvpn = scripted_openvpn(&scratch.path, &lines, 1.0);
        let (entered, signing) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let token = FakeToken {
            refusal,
            signing: Some(entered),
            gate: Some(Arc::new(Mutex::new(gate))),
            ..FakeToken::default()
        };
        let session = start_scripted(&openvpn, token);
        let timeout = Duration::from_secs(3);
        let started = signing.recv_timeout(timeout);
        let pending_during = session.approval_pending();
        drop(release);
        let mut expected = vec![Progress::AwaitingApproval];
        if let Some(refusal) = refusal {
            expected.push(Progress::Refused(refusal));
        }
        expected.push(Progress::Down);
        let progress: Vec<_> = expected
            .iter()
            .map(|_| session.progress().recv_timeout(timeout))
            .collect();
        let pending_after = session.approval_pending();
        let outcome = session.wait().unwrap();

        assert_eq!(started, Ok(()), "{refusal:?}");
        assert!(pending_during, "approval missing during sign: {refusal:?}");
        assert_eq!(progress, expected.into_iter().map(Ok).collect::<Vec<_>>());
        assert!(!pending_after, "approval remained after sign: {refusal:?}");
        assert!(outcome.status.success());
    }
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

struct RestartPeer {
    session: Session,
    wire: BufReader<UnixStream>,
    _scratch: PrivateDir,
    signing: mpsc::Receiver<()>,
}

impl RestartPeer {
    const RECONNECTING: &'static str = ">STATE:2,RECONNECTING,ping-restart,,,,,\n";
    const HOLD: &'static str = ">HOLD:Waiting for hold release:0\n";
    #[cfg(target_os = "linux")]
    const CONNECTED: &'static str = ">STATE:3,CONNECTED,SUCCESS,192.0.2.2\n";

    #[cfg(target_os = "linux")]
    fn start() -> Self {
        Self::start_with(FakeToken::default(), test_policy())
    }

    fn start_with(mut token: FakeToken, policy: RestartPolicy) -> Self {
        let (entered, signing) = mpsc::channel();
        token.signing = Some(entered);
        let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
        let relay = scratch.path.join("relay");
        let listener = UnixListener::bind(&relay).unwrap();
        listener.set_nonblocking(true).unwrap();
        let executable = scratch.path.join("openvpn");
        fs::write(
            &executable,
            r#"#!/usr/bin/env python3
import select, socket, sys
if "--version" in sys.argv:
    print("OpenVPN 2.6.19")
    sys.exit(0)
with socket.socket(socket.AF_UNIX) as management, socket.socket(socket.AF_UNIX) as test:
    management.connect(sys.argv[sys.argv.index("--management") + 1])
    test.connect(sys.argv[0].rsplit("/", 1)[0] + "/relay")
    peers = {management: test, test: management}
    while True:
        ready, _, _ = select.select(list(peers), [], [], 15)
        assert ready, "relay idle"
        for source in ready:
            data = source.recv(4096)
            if not data:
                sys.exit(0)
            peers[source].sendall(data)
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let session = start_scripted_with_policy(&executable, token, policy);
        let until = Instant::now() + Duration::from_secs(2);
        let wire = loop {
            match listener.accept() {
                // BSD accept inherits O_NONBLOCK from the listener; Linux does not.
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    break BufReader::new(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until, "relay did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        let mut peer = Self {
            session,
            wire,
            _scratch: scratch,
            signing,
        };
        let timeout = Duration::from_secs(2);
        assert_eq!(peer.reply(timeout).unwrap(), management::VERSION);
        assert_eq!(peer.reply(timeout).unwrap(), management::STATE_ON);
        peer.say(Self::HOLD);
        assert_eq!(peer.reply(timeout).unwrap(), management::HOLD_RELEASE);
        peer
    }

    fn say(&mut self, lines: &str) {
        self.wire.get_mut().write_all(lines.as_bytes()).unwrap();
    }

    fn reply(&mut self, timeout: Duration) -> io::Result<String> {
        self.wire.get_ref().set_read_timeout(Some(timeout))?;
        let mut line = String::new();
        self.wire.read_line(&mut line)?;
        Ok(line)
    }

    fn reconnect(&mut self) -> u64 {
        self.say(Self::RECONNECTING);
        let event = self
            .session
            .progress()
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let Progress::Restarting { state, epoch } = event else {
            panic!("expected restarting, got {event:?}");
        };
        assert_eq!(state.phase, management::Phase::Reconnecting);
        epoch
    }

    fn expect_held(&mut self) {
        let reply = self.reply(Duration::from_millis(150));
        assert!(
            matches!(&reply, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "restart hold released before acknowledgement: {reply:?}"
        );
    }

    fn reply_block(&mut self, timeout: Duration) -> io::Result<String> {
        // macOS refuses SO_RCVTIMEO on an already-shutdown peer; the read
        // below still reports EOF.
        if let Err(error) = self.wire.get_ref().set_read_timeout(Some(timeout))
            && error.raw_os_error() != Some(libc::EINVAL)
        {
            return Err(error);
        }
        let mut text = String::new();
        loop {
            let mut line = String::new();
            if self.wire.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "signature reply ended before END",
                ));
            }
            text.push_str(&line);
            if line == "END\n" {
                return Ok(text);
            }
        }
    }

    fn finish(self) -> Outcome {
        self.wire.get_ref().shutdown(Shutdown::Both).unwrap();
        self.session.wait().unwrap()
    }
}

#[cfg(target_os = "linux")]
#[test]
fn restart_hold_rejects_the_acknowledgement_of_an_older_epoch() {
    let mut peer = RestartPeer::start();
    let timeout = Duration::from_secs(2);
    let first_epoch = peer.reconnect();
    peer.say(RestartPeer::HOLD);
    peer.session.release_restart_hold(first_epoch);
    assert_eq!(peer.reply(timeout).unwrap(), management::HOLD_RELEASE);
    peer.say(RestartPeer::CONNECTED);
    assert!(matches!(
        peer.session.progress().recv_timeout(timeout),
        Ok(Progress::State(s)) if s.phase == management::Phase::Connected
    ));

    let second_epoch = peer.reconnect();
    // An out-of-order CONNECTED must not acknowledge the new restart.
    peer.say(RestartPeer::CONNECTED);
    peer.say(RestartPeer::HOLD);
    assert!(matches!(
        peer.session.progress().recv_timeout(timeout),
        Ok(Progress::State(s)) if s.phase == management::Phase::Connected
    ));
    peer.expect_held();
    assert_ne!(first_epoch, second_epoch);
    peer.session.release_restart_hold(first_epoch);
    peer.say(RestartPeer::HOLD);
    peer.expect_held();
    peer.session.release_restart_hold(second_epoch);
    // Both HOLD records share the second restart's acknowledgement.
    assert_eq!(peer.reply(timeout).unwrap(), management::HOLD_RELEASE);
    assert_eq!(peer.reply(timeout).unwrap(), management::HOLD_RELEASE);
    assert!(peer.finish().status.success());
}

#[test]
fn restart_hold_stop_wakes_the_management_thread() {
    // The reviewer's stop probe, now portable: with Caller the hold must be
    // released by stop() on macOS too, before EXITING can be read.
    let mut peer = RestartPeer::start_with(FakeToken::default(), RestartPolicy::Caller);
    peer.reconnect();
    peer.say(RestartPeer::HOLD);
    peer.expect_held();
    peer.session.stop().unwrap();
    assert_eq!(
        peer.reply(Duration::from_secs(1)).unwrap(),
        management::TERMINATE
    );
    peer.say(">STATE:5,EXITING,auth-failure,,,,,\n");
    // Prove the reader advanced past HOLD before Session::wait can wake it.
    let event = peer.session.progress().recv_timeout(Duration::from_secs(1));
    assert!(matches!(event, Ok(Progress::State(s)) if s.reason == Some(Reason::AuthFailure)));
    assert_eq!(peer.finish().reason, Some(Reason::AuthFailure));
}

#[cfg(target_os = "linux")]
#[test]
fn restart_hold_timeout_releases_the_hold() {
    let mut peer = RestartPeer::start();
    let start = Instant::now();
    peer.reconnect();
    peer.say(RestartPeer::HOLD);
    assert_eq!(
        peer.reply(Duration::from_secs(12)).unwrap(),
        management::HOLD_RELEASE
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(10),
        "hold timed out early: {elapsed:?}"
    );
    peer.say(RestartPeer::HOLD);
    assert_eq!(
        peer.reply(Duration::from_secs(1)).unwrap(),
        management::HOLD_RELEASE
    );
    assert!(peer.finish().status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn restart_hold_acknowledgement_is_unique_to_the_session() {
    let mut old = RestartPeer::start();
    let old_epoch = old.reconnect();
    let mut current = RestartPeer::start();
    let current_epoch = current.reconnect();
    current.say(RestartPeer::HOLD);
    current.session.release_restart_hold(old_epoch);
    current.expect_held();
    current.session.release_restart_hold(current_epoch);
    assert_eq!(
        current.reply(Duration::from_secs(2)).unwrap(),
        management::HOLD_RELEASE
    );
    assert!(current.finish().status.success());
    assert!(old.finish().status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn invalid_signature_is_refused_while_a_restart_waits() {
    // Validation comes before the wait for the withdrawal: an invalid request
    // is refused at once even while the restart is unacknowledged.
    let mut peer = RestartPeer::start();
    peer.reconnect();
    peer.say(">PK_SIGN:AAEC,unknown-algorithm\n");
    let result = peer.reply(Duration::from_secs(2));
    assert_eq!(
        result.ok().as_deref(),
        Some(management::TERMINATE),
        "the invalid request must be refused while the restart is unacknowledged"
    );
    assert!(matches!(
        peer.session.progress().recv_timeout(Duration::from_secs(1)),
        Ok(Progress::Refused(SignError::Unsupported))
    ));
    assert!(peer.finish().status.success());
}

#[test]
fn restart_policy_immediate_answers_hold_without_an_acknowledgement() {
    // Mutation captured: holding the macOS restart for the caller costs ten
    // seconds on every reconnect while VPT-19 does not exist yet.
    let mut peer = RestartPeer::start_with(FakeToken::default(), RestartPolicy::Immediate);
    let started = Instant::now();
    let epoch = peer.reconnect();
    assert!(epoch > 0);
    peer.say(RestartPeer::HOLD);
    assert_eq!(
        peer.reply(Duration::from_secs(2)).unwrap(),
        management::HOLD_RELEASE
    );
    assert!(started.elapsed() < Duration::from_secs(2), "{started:?}");
    peer.say(RestartPeer::HOLD);
    assert_eq!(
        peer.reply(Duration::from_secs(1)).unwrap(),
        management::HOLD_RELEASE
    );
    assert!(peer.finish().status.success());
}

#[test]
fn restart_policy_caller_waits_for_the_acknowledgement_and_times_out() {
    let mut peer = RestartPeer::start_with(FakeToken::default(), RestartPolicy::Caller);
    let started = Instant::now();
    let epoch = peer.reconnect();
    peer.say(RestartPeer::HOLD);
    peer.expect_held();
    peer.session.release_restart_hold(epoch);
    assert_eq!(
        peer.reply(Duration::from_secs(2)).unwrap(),
        management::HOLD_RELEASE
    );

    let second = peer.reconnect();
    peer.say(RestartPeer::HOLD);
    assert_eq!(
        peer.reply(Duration::from_secs(12)).unwrap(),
        management::HOLD_RELEASE
    );
    assert!(
        started.elapsed() >= Duration::from_secs(10),
        "hold timed out early: {:?}",
        started.elapsed()
    );
    peer.session.release_restart_hold(second);
    assert!(peer.finish().status.success());
}

#[test]
fn signature_waits_for_withdrawal_after_request_validation() {
    // Validation, then withdrawal, then the signer: each boundary has its own
    // assertion so a mutant that moves any of them is caught.
    let (release, gate) = mpsc::channel();
    let token = FakeToken {
        gate: Some(Arc::new(Mutex::new(gate))),
        ..FakeToken::default()
    };
    let mut peer = RestartPeer::start_with(token, RestartPolicy::Caller);
    let epoch = peer.reconnect();

    peer.say(">PK_SIGN:AAEC,unknown-algorithm\n");
    assert_eq!(
        peer.reply(Duration::from_secs(2)).unwrap(),
        management::TERMINATE
    );
    assert_eq!(
        peer.session.progress().recv_timeout(Duration::from_secs(2)),
        Ok(Progress::Refused(SignError::Unsupported))
    );

    peer.say(&pss_request(32));
    assert!(
        peer.signing
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "the signer was called before the withdrawal"
    );
    assert!(
        peer.reply(Duration::from_millis(200)).is_err(),
        "a signature was sent before the withdrawal"
    );
    assert!(
        peer.session.progress().try_recv().is_err(),
        "approval was announced before the withdrawal"
    );

    peer.session.release_restart_hold(epoch);
    assert_eq!(peer.signing.recv_timeout(Duration::from_secs(2)), Ok(()));
    let _ = release.send(());
    assert_eq!(
        peer.reply_block(Duration::from_secs(2)).unwrap(),
        "pk-sig\nCQkJCQ==\nEND\n"
    );
    assert_eq!(
        peer.session.progress().recv_timeout(Duration::from_secs(2)),
        Ok(Progress::AwaitingApproval)
    );
    assert!(peer.finish().status.success());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn private_config_is_verified_and_refuses_planted_files() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let bytes = b"client\n";
    let path = write_private_config(&scratch.path, bytes).unwrap();
    assert_eq!(path, scratch.path.join("config"));
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(fs::read(&path).unwrap(), bytes.as_slice());
    assert!(verify_private_config(&path, bytes).is_ok());

    // O_EXCL: a file or symlink planted under the config name is never reused.
    assert_eq!(
        write_private_config(&scratch.path, bytes)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    fs::remove_file(&path).unwrap();
    let outside = scratch.path.join("outside");
    fs::write(&outside, bytes).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(verify_private_config(&path, bytes).is_err());
    assert!(write_private_config(&scratch.path, bytes).is_err());
    fs::remove_file(&path).unwrap();

    let path = write_private_config(&scratch.path, bytes).unwrap();
    fs::write(&path, b"changed\n").unwrap();
    assert_eq!(
        verify_private_config(&path, bytes).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(verify_private_config(&path, bytes).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, scratch.path.join("alias")).unwrap();
    assert!(verify_private_config(&path, bytes).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn session_start_passes_the_private_config_to_openvpn() {
    // Mutation captured: passing a path or a different file to --config loses
    // the identity guarantee; the stand-in reads exactly what openvpn is given.
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let bytes = b"dev null\n";
    let marker = scratch.path.join("config-evidence");
    let executable = scratch.path.join("openvpn");
    fs::write(
        &executable,
        format!(
            "#!/usr/bin/env python3\nimport os, socket, sys, time\n\
             if '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\n\
             a=sys.argv\np=a[a.index('--config')+1]\n\
             assert oct(os.stat(p).st_mode & 0o777) == '0o600'\n\
             assert open(p,'rb').read() == bytes({:?})\n\
             open({:?},'w').write(p)\n\
             s=socket.socket(socket.AF_UNIX)\ns.connect(a[a.index('--management')+1])\n\
             time.sleep(.2)\n",
            bytes.to_vec(),
            marker.display().to_string()
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let mut settings = launch(&executable);
    settings.config = ConfigSource::private(bytes);
    let session = Session::start_with(
        settings,
        FakeToken::default(),
        &session_base(),
        RestartPolicy::Immediate,
    )
    .unwrap();
    session.wait().unwrap();
    let used = fs::read_to_string(&marker).unwrap();
    assert!(
        Path::new(&used).starts_with(session_base().canonicalize().unwrap()),
        "{used}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn an_unsafe_or_overlong_session_base_is_refused_before_spawn() {
    let writable = PrivateDir::create(&std::env::temp_dir()).unwrap();
    fs::set_permissions(&writable.path, fs::Permissions::from_mode(0o775)).unwrap();
    let settings = launch(Path::new("/nonexistent-openvpn"));
    let error = Session::start_with(
        settings,
        FakeToken::default(),
        &writable.path,
        RestartPolicy::Immediate,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
    assert!(error.to_string().contains("unsafe session base"), "{error}");
    assert_eq!(fs::read_dir(&writable.path).unwrap().count(), 0);

    let base = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let mut long = base.path.clone();
    for _ in 0..4 {
        long.push("segment0123456789abcdef");
        fs::create_dir(&long).unwrap();
    }
    assert!(crate::connection::ovpn::private_dir::check_socket_limit(&long).is_err());
    let settings = launch(Path::new("/nonexistent-openvpn"));
    let error = Session::start_with(
        settings,
        FakeToken::default(),
        &long,
        RestartPolicy::Immediate,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("socket path"), "{error}");
}

#[cfg(not(target_os = "linux"))]
struct TestDir(PathBuf);

#[cfg(not(target_os = "linux"))]
impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(not(target_os = "linux"))]
const SHORT_NAMES: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[cfg(not(target_os = "linux"))]
fn short_name_offset() -> usize {
    std::process::id() as usize % SHORT_NAMES.len()
}

/// One-character names keep the worst-case socket path under 104 bytes.
/// The pid chooses the first candidate; `create` decides the winner, so two
/// test binaries sharing TMPDIR never claim the same entry.
#[cfg(not(target_os = "linux"))]
fn reserve_short_dir(parent: &Path, prefix: &str) -> (TestDir, char) {
    for step in 0..SHORT_NAMES.len() {
        let name = SHORT_NAMES[(short_name_offset() + step) % SHORT_NAMES.len()] as char;
        let path = parent.join(format!("{prefix}{name}"));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return (TestDir(path), name),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("reserving {}: {error}", path.display()),
        }
    }
    panic!("no free short fixture name under {}", parent.display());
}

#[cfg(not(target_os = "linux"))]
fn reserve_short_symlink(parent: &Path, target: &Path, avoid: char) -> TestDir {
    for step in 0..SHORT_NAMES.len() {
        let name = SHORT_NAMES[(short_name_offset() + step) % SHORT_NAMES.len()] as char;
        if name == avoid {
            continue;
        }
        let path = parent.join(name.to_string());
        match std::os::unix::fs::symlink(target, &path) {
            Ok(()) => return TestDir(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("reserving {}: {error}", path.display()),
        }
    }
    panic!("no free short symlink name under {}", parent.display());
}

#[cfg(not(target_os = "linux"))]
impl Drop for TestDir {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.0) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            let _ = fs::remove_file(&self.0);
        } else {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn recording_openvpn(directory: &Path, marker: &Path) -> PathBuf {
    let executable = directory.join("openvpn");
    fs::write(
        &executable,
        format!(
            "#!/usr/bin/env python3\nimport socket, sys, time\n\
             if '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\n\
             a=sys.argv\nopen({:?},'w').write(a[a.index('--config')+1])\n\
             s=socket.socket(socket.AF_UNIX)\ns.connect(a[a.index('--management')+1])\n\
             time.sleep(.2)\n",
            marker.display().to_string()
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    executable
}

#[cfg(not(target_os = "linux"))]
#[test]
fn path_launch_consumes_the_private_copy() {
    let scratch = PrivateDir::create(&session_base()).unwrap();
    let marker = scratch.path.join("config-evidence");
    let executable = recording_openvpn(&scratch.path, &marker);
    let original = scratch.path.join("input.ovpn");
    let bytes = b"remote 127.0.0.1 1194\n<ca>\nfixture\n</ca>\n";
    fs::write(&original, bytes).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
    let mut settings = launch(&executable);
    settings.config = ConfigSource::Path(original.clone());
    let session = Session::start_with(
        settings,
        FakeToken::default(),
        &session_base(),
        RestartPolicy::Immediate,
    )
    .unwrap();
    let used = PathBuf::from(fs::read_to_string(&marker).unwrap());
    assert_ne!(used, original, "child used the original profile path");
    assert!(
        used.starts_with(session_base().canonicalize().unwrap()),
        "{used:?}"
    );
    assert_eq!(fs::read(&used).unwrap(), bytes.as_slice());
    session.wait().unwrap();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn validated_canonical_base_is_the_one_used_for_the_session() {
    let scratch = PrivateDir::create(&session_base()).unwrap();
    let (real, real_name) = reserve_short_dir(&session_base(), "");
    let alias = reserve_short_symlink(&session_base(), real.path(), real_name);
    let marker = scratch.path.join("config-evidence");
    let executable = recording_openvpn(&scratch.path, &marker);
    let session = Session::start_with(
        launch(&executable),
        FakeToken::default(),
        alias.path(),
        RestartPolicy::Immediate,
    )
    .unwrap();
    session.wait().unwrap();
    let used = PathBuf::from(fs::read_to_string(&marker).unwrap());
    assert!(
        used.starts_with(real.path().canonicalize().unwrap()),
        "alias escaped the validated chain: {used:?}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn production_base_fits_the_socket_and_spaces_reach_argv() {
    let production = crate::helper::paths::ovpn_sessions_directory();
    assert!(production.to_string_lossy().contains(' '));
    assert!(crate::connection::ovpn::private_dir::check_socket_limit(&production).is_ok());

    let scratch = PrivateDir::create(&session_base()).unwrap();
    // HOME is short enough for a unique name that still contains a space.
    let home = PathBuf::from(
        std::env::var_os("HOME").expect("HOME is required for the short spaced fixture"),
    );
    let (spaced, _) = reserve_short_dir(&home, "vp ");
    assert!(spaced.path().to_string_lossy().contains(' '));
    assert!(crate::connection::ovpn::private_dir::check_socket_limit(spaced.path()).is_ok());
    let marker = scratch.path.join("config-evidence");
    let executable = recording_openvpn(&scratch.path, &marker);
    let session = Session::start_with(
        launch(&executable),
        FakeToken::default(),
        spaced.path(),
        RestartPolicy::Immediate,
    )
    .unwrap();
    session.wait().unwrap();
    let used = PathBuf::from(fs::read_to_string(&marker).unwrap());
    assert!(
        used.starts_with(spaced.path().canonicalize().unwrap()),
        "{used:?}"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn socket_limit_reserves_two_digits_for_the_attempt() {
    let base = Path::new("/").join("a".repeat(59));
    assert_eq!(base.as_os_str().as_bytes().len(), 60);
    assert!(
        crate::connection::ovpn::private_dir::check_socket_limit(&base).is_err(),
        "a two-digit attempt must push the worst-case socket over the limit"
    );
}

#[test]
fn reply_block_ends_at_eof() {
    let mut peer = RestartPeer::start_with(FakeToken::default(), RestartPolicy::Immediate);
    peer.wire.get_mut().shutdown(Shutdown::Both).unwrap();
    let error = peer.reply_block(Duration::from_secs(2)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{error}");
}

#[test]
fn pid_identity_is_available_only_before_the_reap() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scripted_openvpn(&scratch.path, "", 2.0);
    let mut session = start_scripted(&executable, FakeToken::default());
    assert_eq!(session.pid(), Some(session.openvpn.child.id()));
    // `wait` consumes the session; this is the same reap path it calls.
    let status = session.reap().unwrap();
    assert!(status.success());
    assert_eq!(session.pid(), None);
    let _ = session.stop();
}

#[test]
fn wait_clears_the_pid_identity_it_owned() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scripted_openvpn(&scratch.path, "", 0.0);
    let session = start_scripted(&executable, FakeToken::default());
    let identity = Arc::clone(&session.pid);
    assert!(session.pid().is_some());
    let outcome = session.wait().unwrap();
    assert!(outcome.status.success());
    assert_eq!(identity.load(Ordering::Acquire), 0);
}

#[test]
fn drop_reaps_and_invalidates_the_shared_identity() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scripted_openvpn(&scratch.path, "", 0.0);
    let session = start_scripted(&executable, FakeToken::default());
    let identity = Arc::clone(&session.pid);
    let pid = session.pid().unwrap();
    drop(session);
    let result = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
    assert_eq!(result, -1, "drop did not reap the child");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert_eq!(
        identity.load(Ordering::Acquire),
        0,
        "drop reaped PID {pid} but retained the identity"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_exited_observes_the_exit_without_reaping_it() {
    let scratch = PrivateDir::create(&std::env::temp_dir()).unwrap();
    let executable = scripted_openvpn(&scratch.path, "", 0.5);
    let session = start_scripted(&executable, FakeToken::default());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut observed = None;
    while observed.is_none() && Instant::now() < deadline {
        observed = session.exited();
        if observed.is_none() {
            thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(
        observed.is_some(),
        "the child exited without being observed"
    );
    assert!(session.pid().is_some(), "exited must not reap the child");
    let outcome = session.wait().unwrap();
    assert!(outcome.status.success(), "wait lost the child status");
}
