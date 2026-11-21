//! Integration with a real openvpn: a point-to-point TLS server and a client
//! driven by the OVPN session, both on loopback with `--dev null`, so no
//! privilege or network change is needed. A key-file signer stands in for the
//! token.
//!
//! Runs when VPNT_TEST_OPENVPN names an openvpn binary (2.6 or later); without
//! it every test returns early and proves nothing. VPNT_TEST_OPENSSL can name
//! the OpenSSL binary the fixture uses (see `fixture.rs`).
#![cfg(unix)]

#[path = "ovpn_session/fixture.rs"]
mod fixture;

use fixture::{Fixture, free_udp_ports};
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::DirBuilderExt;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fs, io,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
#[cfg(not(target_os = "linux"))]
use vpnt::connection::ovpn::profile;
use vpnt::connection::ovpn::{
    management::Phase,
    session::{
        ConfigSource, Launch, Progress, RestartPolicy, Session, SignError, Signatures, Signer,
    },
    signing::{Hash, Padding},
};

/// Sessions share /tmp, which the cleanup test counts.
static SERIAL: Mutex<()> = Mutex::new(());

fn session_base() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(target_os = "linux"))]
    {
        // One character: the canonical macOS temp path plus the worst-case
        // private directory still fits the 104-byte socket path.
        let base = std::env::temp_dir().join("s");
        fs::DirBuilder::new().mode(0o700).create(&base).ok();
        base
    }
}

/// Only the shared-base test gets its own Linux base, so a mutant that ignores
/// the caller's base cannot hide behind the /tmp default. Other Linux
/// integration tests keep using /tmp.
struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        #[cfg(target_os = "linux")]
        let path = {
            let salt = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos());
            let path = PathBuf::from("/tmp").join(format!("vb{}-{salt:x}", std::process::id()));
            fs::create_dir(&path).unwrap();
            path
        };
        #[cfg(not(target_os = "linux"))]
        let path = session_base();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(target_os = "linux")]
impl Drop for TestBase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn restart_policy() -> RestartPolicy {
    #[cfg(target_os = "linux")]
    {
        RestartPolicy::Caller
    }
    #[cfg(not(target_os = "linux"))]
    {
        RestartPolicy::Immediate
    }
}

fn config_source(path: &Path) -> ConfigSource {
    #[cfg(target_os = "linux")]
    {
        ConfigSource::Path(path.to_path_buf())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let inspected = profile::inspect(&fs::read(path).unwrap()).unwrap();
        ConfigSource::private(inspected.normalized.as_bytes())
    }
}

/// Connects, then stops; returns the paddings the token was asked for.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = session_base().join(format!("vpnt-int-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NoSign;

impl Signer for NoSign {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        Ok(vec![1])
    }

    fn sign(&mut self, _padding: Padding, _data: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(vec![2])
    }
}

/// The session must create its directory in the base the test passes, not in
/// a platform default that the cleanup oracle does not inspect.
#[test]
fn session_uses_the_shared_base_for_its_private_directory() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let scratch = Scratch::new();
    let marker = scratch.path().join("config-evidence");
    let executable = scratch.path().join("openvpn");
    fs::write(
        &executable,
        format!(
            "#!/usr/bin/env python3\nimport socket, sys, time\n\
             if '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\n\
             a=sys.argv\n\
             open({:?},'w').write('management=%s\\nconfig=%s\\n' % (a[a.index('--management')+1], a[a.index('--config')+1]))\n\
             s=socket.socket(socket.AF_UNIX)\ns.connect(a[a.index('--management')+1])\n\
             time.sleep(.2)\n",
            marker.display().to_string()
        ),
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let launch = || {
        #[cfg(target_os = "linux")]
        let config = ConfigSource::Path(PathBuf::from("/dev/null"));
        #[cfg(not(target_os = "linux"))]
        let config = ConfigSource::private(b"");
        Launch {
            openvpn: executable.clone(),
            config,
            dev: None,
            signatures: Signatures::Any,
            extra: Vec::new(),
            env: Vec::new(),
        }
    };
    let base = TestBase::new();
    let expected = base.path().canonicalize().unwrap();
    // The script was written moments ago: another test thread that forks while
    // it was open for writing makes exec fail with "Text file busy" until that
    // child execs, as `start_scripted` in session_tests.rs also retries.
    let mut started = None;
    for _ in 0..50 {
        match Session::start_with(launch(), NoSign, base.path(), restart_policy()) {
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => {
                started = Some(result.unwrap());
                break;
            }
        }
    }
    let session = started.expect("scripted openvpn stayed busy");
    session.wait().unwrap();
    let evidence = fs::read_to_string(&marker).unwrap();
    let mut management = "";
    let mut config = "";
    for line in evidence.lines() {
        if let Some(path) = line.strip_prefix("management=") {
            management = path;
        } else if let Some(path) = line.strip_prefix("config=") {
            config = path;
        }
    }
    // Both platforms put the management socket directly in the caller's base.
    // Linux keeps the contract of passing /dev/null as the config; only macOS
    // gets the private copy checked here.
    let directory = Path::new(management)
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("{management} has no session directory"));
    assert_eq!(
        directory,
        expected.as_path(),
        "{management} is not directly under {}",
        expected.display()
    );
    #[cfg(target_os = "linux")]
    assert_eq!(config, "/dev/null", "Linux argv changed");
    #[cfg(not(target_os = "linux"))]
    assert!(
        Path::new(config).starts_with(&expected),
        "{config} is outside {}",
        expected.display()
    );
}

/// The reviewer's parser probe: with `/usr/bin/true` in place of openvpn the
/// fixture must pass production inspection and reach the spawn, failing only
/// at the version check. The child re-enters this test with the substitute.
#[test]
fn fixture_profile_passes_inspection_and_reaches_spawn() {
    const CHILD: &str = "VPNT_PARSER_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let fixture = Fixture::new("parser-proof").unwrap();
        let ports = free_udp_ports();
        let path = fixture.client_config(ports, "");
        #[cfg(not(target_os = "linux"))]
        assert!(
            fs::read_to_string(&path).unwrap().contains("<ca>\n"),
            "the macOS fixture must use an inline CA"
        );
        let launch = Launch {
            openvpn: fixture.openvpn.clone(),
            config: config_source(&path),
            dev: None,
            signatures: Signatures::Any,
            extra: fixture.client_extra(ports, ""),
            env: Vec::new(),
        };
        let error =
            Session::start_with(launch, fixture.signer(), &session_base(), restart_policy())
                .err()
                .expect("/usr/bin/true cannot negotiate a management connection");
        assert!(
            error.to_string().contains("exited before connecting")
                || error.to_string().contains("version check failed"),
            "the fixture must pass inspection and reach spawn: {error}"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fixture_profile_passes_inspection_and_reaches_spawn",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("VPNT_TEST_OPENVPN", "/usr/bin/true")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn connect_and_stop(fixture: &Fixture, signatures: Signatures, profile: &str) -> Vec<Padding> {
    let ports = free_udp_ports();
    let _server = fixture.server(ports);
    let signer = fixture.signer();
    let paddings = Arc::clone(&signer.paddings);
    let launch = Launch {
        openvpn: fixture.openvpn.clone(),
        config: config_source(&fixture.client_config(ports, profile)),
        dev: None,
        signatures,
        extra: fixture.client_extra(ports, profile),
        env: Vec::new(),
    };
    let session = Session::start_with(launch, signer, &session_base(), restart_policy()).unwrap();
    wait_for_connected(&session, Duration::from_secs(30));
    session.stop().unwrap();
    let outcome = session.wait().unwrap();
    assert!(
        outcome.status.success(),
        "openvpn exit after stop: {:?}",
        outcome.status
    );
    paddings.lock().unwrap().clone()
}

fn wait_for_connected(session: &Session, limit: Duration) -> Vec<Progress> {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match session.progress().recv_timeout(left) {
            Ok(progress) => {
                #[cfg(target_os = "linux")]
                if let Progress::Restarting { epoch, .. } = &progress {
                    // This dev-null fixture has no network configuration to withdraw.
                    session.release_restart_hold(*epoch);
                }
                let connected =
                    matches!(&progress, Progress::State(state) if state.phase == Phase::Connected);
                seen.push(progress);
                if connected {
                    return seen;
                }
            }
            Err(_) => break,
        }
    }
    panic!("never connected; progress: {seen:?}");
}

#[test]
fn tls13_handshake_is_signed_with_pss_through_the_management_channel() {
    // Mutation captured: mapping a PSS request to PKCS#1 makes the server
    // reject the CertificateVerify, so the session never connects.
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("pss") else {
        return;
    };
    let paddings = connect_and_stop(&fixture, Signatures::Any, "");
    assert!(
        paddings.contains(&Padding::Pss(Hash::Sha256)),
        "{paddings:?}"
    );
}

#[test]
fn pkcs1_only_holds_when_the_server_offers_pss_and_tls13() {
    // The case of a cloud PKCS#11 token against a real server, with a profile
    // that asks for TLS 1.3. Mutation captured: without the OpenSSL override
    // or the trailing --tls-version-max, the server's PSS offer is taken,
    // openvpn refuses to ask for it and the handshake fails; sending a
    // DigestInfo to a PSS mechanism, or refusing it, fails as well.
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("pkcs1") else {
        return;
    };
    let paddings = connect_and_stop(&fixture, Signatures::Pkcs1Only, "tls-version-max 1.3\n");
    assert_eq!(paddings, [Padding::Pkcs1]);
}

#[test]
fn the_private_socket_directory_is_gone_after_the_session() {
    // Mutation captured: dropping PrivateDir's cleanup leaves one directory
    // per connection in the base the session really uses.
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("cleanup") else {
        return;
    };
    let base = session_base();
    let before = leftover_directories(&base);
    connect_and_stop(&fixture, Signatures::Any, "");
    assert_eq!(leftover_directories(&base), before);
}

fn leftover_directories(base: &Path) -> usize {
    let prefix = format!("vpnt-ovpn-{}-", std::process::id());
    fs::read_dir(base)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn receives_pushed_network() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("network") else {
        return;
    };
    let ports = free_udp_ports();
    let _server = fixture.server(ports);
    let log = fixture.path("client.log");
    let profile = format!("log {}\nverb 4\n", log.display());
    let launch = Launch {
        openvpn: fixture.openvpn.clone(),
        config: config_source(&fixture.client_config(ports, &profile)),
        dev: None,
        signatures: Signatures::Any,
        extra: fixture.client_extra(ports, &profile),
        env: Vec::new(),
    };
    let session =
        Session::start_with(launch, fixture.signer(), &session_base(), restart_policy()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut found = None;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match session.progress().recv_timeout(left) {
            Ok(Progress::Up(config)) => {
                found = Some(config);
                break;
            }
            Ok(Progress::BadNetwork(error)) => panic!("network: {error}"),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let c = found.expect("openvpn did not send UP network");
    assert_eq!(c.address.to_string(), "10.81.0.2");
    assert_eq!(c.prefix, 24);
    assert_eq!(c.mtu, Some(1500));
    assert_eq!(
        c.routes
            .iter()
            .map(|r| (r.network.to_string(), r.prefix))
            .collect::<Vec<_>>(),
        [("10.82.0.0".into(), 16), ("10.83.0.0".into(), 16)]
    );
    assert_eq!(
        c.dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.81.0.1", "10.81.0.3"]
    );
    assert_eq!(c.dns_domains, ["example.test"]);
    assert_eq!(c.server, Some("127.0.0.1".parse().unwrap()));
    session.stop().unwrap();
    session.wait().unwrap();
    let log = fs::read_to_string(log).expect("openvpn client log");
    // Proves the log is the client's real verbose log (the phrasing of the
    // device line differs between openvpn 2.6 and 2.7, this one does not).
    assert!(
        log.contains("Initialization Sequence Completed"),
        "openvpn client log is incomplete"
    );
    assert!(
        !log.contains("/usr/lib/openvpn/dns-updown"),
        "openvpn invoked dns-updown"
    );
    assert!(!log.contains("resolvectl"), "openvpn invoked resolvectl");
}

#[test]
fn soft_restart_reconnects_with_the_same_network() {
    check_soft_restart("restart", "", Ipv4Addr::new(10, 81, 0, 2));
}

#[test]
fn soft_restart_with_persist_tun_publishes_the_changed_address() {
    check_soft_restart(
        "persist-restart",
        "persist-tun\n",
        Ipv4Addr::new(10, 81, 0, 42),
    );
}

fn check_soft_restart(name: &str, profile: &str, next_address: Ipv4Addr) {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new(name) else {
        return;
    };
    let ports = free_udp_ports();
    let server = fixture.server(ports);
    let pid_file = fixture.path("client.pid");
    let launch = Launch {
        openvpn: fixture.openvpn.clone(),
        config: config_source(&fixture.client_config(ports, profile)),
        dev: None,
        signatures: Signatures::Pkcs1Only,
        extra: {
            let mut args = fixture.client_extra(ports, profile);
            args.push("--writepid".into());
            args.push(pid_file.clone().into_os_string());
            args
        },
        env: Vec::new(),
    };
    let signer = fixture.signer();
    let paddings = Arc::clone(&signer.paddings);
    let session = Session::start_with(launch, signer, &session_base(), restart_policy()).unwrap();
    let initial_events = wait_for_connected(&session, Duration::from_secs(15));
    let initial = initial_events
        .iter()
        .find_map(|event| match event {
            Progress::Up(network) => Some(network),
            _ => None,
        })
        .expect("initial connection did not publish a network");
    assert_eq!(initial.address, Ipv4Addr::new(10, 81, 0, 2));
    let pid: libc::pid_t = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(pid > 1);
    // The point-to-point fixture has one peer state. Start a fresh server to
    // exercise PUSH_REPLY for the new connection.
    drop(server);
    let _restarted_server = fixture.server_with_address(ports, next_address);
    // The private fixture PID file belongs to this client, whose Child is
    // still owned and unreaped by the session.
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGUSR1) },
        0,
        "{}",
        io::Error::last_os_error()
    );
    let events = wait_for_connected(&session, Duration::from_secs(15));
    let (up, network) = events
        .iter()
        .enumerate()
        .find_map(|(position, event)| match event {
            Progress::Up(network) if network.address == next_address => Some((position, network)),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("restart did not publish Up with {next_address} before Connected: {events:?}")
        });
    assert!(
        events[..up]
            .iter()
            .any(|event| matches!(event, Progress::Down)),
        "restart did not publish Down before Up: {events:?}"
    );
    let mut expected = initial.clone();
    expected.address = next_address;
    assert_eq!(*network, expected);
    assert_eq!(paddings.lock().unwrap().as_slice(), [Padding::Pkcs1; 2]);
    session.stop().unwrap();
    assert!(session.wait().unwrap().status.success());
}

#[cfg(target_os = "linux")]
#[test]
fn pdeathsig_stops_openvpn_when_starting_process_exits() {
    use std::{process::Command, thread};
    if let Some(dir) = std::env::var_os("VPNT_PDEATH_CHILD") {
        let dir = std::path::PathBuf::from(dir);
        let fixture = Fixture {
            directory: dir.clone(),
            openvpn: std::env::var_os("VPNT_TEST_OPENVPN").unwrap().into(),
        };
        let signer = fixture.signer();
        let launch = Launch {
            openvpn: std::env::var_os("VPNT_TEST_OPENVPN").unwrap().into(),
            config: config_source(&dir.join("client.ovpn")),
            dev: None,
            signatures: Signatures::Any,
            extra: Vec::new(),
            env: Vec::new(),
        };
        let _session = Session::start(launch, signer).unwrap();
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let children = fs::read_to_string(format!("/proc/self/task/{tid}/children")).unwrap();
        println!("VPNT_CHILD_PID={}", children.trim());
        std::process::exit(0);
    }
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("pdeath") else {
        return;
    };
    fixture.client_config(free_udp_ports(), "");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "pdeathsig_stops_openvpn_when_starting_process_exits",
            "--nocapture",
        ])
        .env("VPNT_PDEATH_CHILD", &fixture.directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let pid: u32 = text
        .lines()
        .find_map(|s| s.strip_prefix("VPNT_CHILD_PID="))
        .expect("missing pid")
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state = fs::read_to_string(format!("/proc/{pid}/stat"));
        if state.as_ref().is_err()
            || state
                .as_ref()
                .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, r)| r.starts_with('Z')))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "openvpn pid {pid} still running after two seconds"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn management_disconnect_stops_openvpn_after_starting_process_is_killed() {
    use std::{
        mem,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::ExitStatusExt,
        },
        process::{Child, Command, Stdio},
        ptr, thread,
    };

    const CHILD: &str = "VPNT_MANAGEMENT_DISCONNECT_CHILD";
    const BASE: &str = "VPNT_MANAGEMENT_DISCONNECT_BASE";
    const PORT: &str = "VPNT_MANAGEMENT_DISCONNECT_PORT";
    if let Some(directory) = std::env::var_os(CHILD) {
        let fixture = mem::ManuallyDrop::new(Fixture {
            directory: directory.into(),
            openvpn: std::env::var_os("VPNT_TEST_OPENVPN").unwrap().into(),
        });
        let base = PathBuf::from(std::env::var_os(BASE).unwrap());
        let port = std::env::var(PORT).unwrap().parse().unwrap();
        let launch = Launch {
            openvpn: fixture.openvpn.clone(),
            config: config_source(&fixture.path("client.ovpn")),
            dev: None,
            signatures: Signatures::Any,
            extra: fixture.client_extra((0, port), ""),
            env: Vec::new(),
        };
        let session =
            Session::start_with(launch, fixture.signer(), &base, restart_policy()).unwrap();
        wait_for_connected(&session, Duration::from_secs(20));
        let pid = session.pid().unwrap();
        fs::write(fixture.path("pid.tmp"), pid.to_string()).unwrap();
        fs::rename(fixture.path("pid.tmp"), fixture.path("pid")).unwrap();
        // The parent keeps stdin open until after SIGKILL. EOF lets Session
        // clean up its own openvpn if the parent fails before sending it.
        io::copy(&mut io::stdin().lock(), &mut io::sink()).unwrap();
        drop(session);
        return;
    }

    struct Starter(Child);
    impl Drop for Starter {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }

    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("management-disconnect") else {
        return;
    };
    let ports = free_udp_ports();
    let _server = fixture.server(ports);
    fixture.client_config(ports, "");
    // Keep the leaf short enough for the macOS management socket. Choose a
    // fresh base so cleanup owns every entry even if the starter is killed.
    let temp = std::env::temp_dir();
    let base = ('a'..='z')
        .filter(|&letter| letter != 's')
        .find_map(|letter| {
            let path = temp.join(letter.to_string());
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => Some(Scratch(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("couldn't make a private session base: {error}"),
            }
        })
        .expect("no free short session base");
    let mut starter = Starter(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "management_disconnect_stops_openvpn_after_starting_process_is_killed",
                "--nocapture",
            ])
            .env(CHILD, &fixture.directory)
            .env(BASE, base.path())
            .env(PORT, ports.1.to_string())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(40);
    let pid: u32 = loop {
        match fs::read_to_string(fixture.path("pid")) {
            Ok(value) => break value.parse().unwrap(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => panic!("couldn't read startup receipt: {error}"),
        }
        assert!(
            starter.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "starter did not report a connected OpenVPN process"
        );
        thread::sleep(Duration::from_millis(20));
    };

    // Register before killing the starter. The kernel associates NOTE_EXIT
    // with the original process, even if its numeric PID is later reused.
    let fd = unsafe { libc::kqueue() };
    assert!(fd >= 0, "kqueue: {}", io::Error::last_os_error());
    let queue = unsafe { OwnedFd::from_raw_fd(fd) };
    let watch = libc::kevent {
        ident: pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: ptr::null_mut(),
    };
    assert_eq!(
        unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &watch,
                1,
                ptr::null_mut(),
                0,
                ptr::null(),
            )
        },
        0,
        "OpenVPN exited before the starter was killed: {}",
        io::Error::last_os_error()
    );
    let observe = |seconds| {
        let timeout = libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        };
        let mut event: libc::kevent = unsafe { mem::zeroed() };
        let count =
            unsafe { libc::kevent(queue.as_raw_fd(), ptr::null(), 0, &mut event, 1, &timeout) };
        assert!(count >= 0, "kevent: {}", io::Error::last_os_error());
        (count == 1).then_some(event)
    };
    assert!(observe(0).is_none(), "OpenVPN exited before SIGKILL");
    starter.0.kill().unwrap();
    assert_eq!(starter.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    let event = observe(10).expect("OpenVPN did not exit within ten seconds of management EOF");
    assert!(event.ident == pid as usize && event.fflags & libc::NOTE_EXIT != 0);
    assert_eq!(event.flags & libc::EV_ERROR, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn pdeathsig_stops_peer_that_ignores_management_disconnect() {
    use std::{os::unix::fs::PermissionsExt, process::Command, thread};
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("pdeath-independent") else {
        return;
    };
    fixture.client_config(free_udp_ports(), "");
    let fake = fixture.path("fake-openvpn");
    fs::write(&fake, "#!/usr/bin/env python3\nimport socket,sys,time\nif '--version' in sys.argv: print('OpenVPN 2.6.19'); sys.exit(0)\ns=socket.socket(socket.AF_UNIX)\ns.connect(sys.argv[sys.argv.index('--management')+1])\ntime.sleep(30)\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "pdeathsig_stops_openvpn_when_starting_process_exits",
            "--nocapture",
        ])
        .env("VPNT_PDEATH_CHILD", &fixture.directory)
        .env("VPNT_TEST_OPENVPN", &fake)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let pid: u32 = text
        .lines()
        .find_map(|s| s.strip_prefix("VPNT_CHILD_PID="))
        .expect("missing pid")
        .parse()
        .unwrap();
    let proc = format!("/proc/{pid}/stat");
    let initial = fs::read_to_string(&proc).ok().and_then(|s| {
        s.rsplit_once(") ")
            .and_then(|(_, r)| r.split_whitespace().nth(19).map(str::to_owned))
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    let exited = loop {
        let stat = fs::read_to_string(&proc);
        if stat.as_ref().is_err()
            || stat
                .as_ref()
                .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, r)| r.starts_with('Z')))
        {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(20));
    };
    if !exited {
        let current = fs::read_to_string(&proc).ok().and_then(|s| {
            s.rsplit_once(") ")
                .and_then(|(_, r)| r.split_whitespace().nth(19).map(str::to_owned))
        });
        if initial.is_some() && initial == current {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
    }
    assert!(
        exited,
        "independent management peer pid {pid} survived for two seconds"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_config_connects_through_dev_fd_three() {
    use vpnt::connection::ovpn::session::ConfigSource;
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("sealed") else {
        return;
    };
    let ports = free_udp_ports();
    let _server = fixture.server(ports);
    let path = fixture.client_config(ports, "");
    let config = ConfigSource::sealed(&fs::read(&path).unwrap()).unwrap();
    fs::rename(&path, fixture.path("original.ovpn")).unwrap();
    fs::write(&path, b"not the sealed config").unwrap();
    let session = Session::start(
        Launch {
            openvpn: fixture.openvpn.clone(),
            config,
            dev: None,
            signatures: Signatures::Any,
            extra: vec![],
            env: vec![],
        },
        fixture.signer(),
    )
    .unwrap();
    wait_for_connected(&session, Duration::from_secs(30));
    session.stop().unwrap();
    assert!(session.wait().unwrap().status.success());
}
