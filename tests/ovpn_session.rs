//! Integration with a real openvpn: a point-to-point TLS server and a client
//! driven by the OVPN session, both on loopback with `--dev null`, so no
//! privilege or network change is needed. A key-file signer stands in for the
//! token.
//!
//! Runs when VPNT_TEST_OPENVPN names an openvpn binary (2.6 or later); without
//! it every test returns early and proves nothing.
#![cfg(unix)]

#[path = "ovpn_session/fixture.rs"]
mod fixture;

use fixture::{Fixture, free_udp_ports};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use vpnt::connection::ovpn::{
    management::Phase,
    session::{Launch, Progress, Session, Signatures},
    signing::{Hash, Padding},
};

/// Sessions share /tmp, which the cleanup test counts.
static SERIAL: Mutex<()> = Mutex::new(());

/// Connects, then stops; returns the paddings the token was asked for.
fn connect_and_stop(fixture: &Fixture, signatures: Signatures, profile: &str) -> Vec<Padding> {
    let ports = free_udp_ports();
    let _server = fixture.server(ports);
    let signer = fixture.signer();
    let paddings = Arc::clone(&signer.paddings);
    let launch = Launch {
        openvpn: fixture.openvpn.clone(),
        config: fixture.client_config(ports, profile),
        dev: None,
        signatures,
        extra: Vec::new(),
        env: Vec::new(),
    };
    let session = Session::start(launch, signer).unwrap();
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

fn wait_for_connected(session: &Session, limit: Duration) {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match session.progress().recv_timeout(left) {
            Ok(Progress::State(state)) if state.phase == Phase::Connected => return,
            Ok(progress) => seen.push(progress),
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
    // The case of the SerproID token against a real server, with a profile
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
    // per connection in /tmp.
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("cleanup") else {
        return;
    };
    let before = leftover_directories();
    connect_and_stop(&fixture, Signatures::Any, "");
    assert_eq!(leftover_directories(), before);
}

fn leftover_directories() -> usize {
    let prefix = format!("vpnt-ovpn-{}-", std::process::id());
    fs::read_dir(Path::new("/tmp"))
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
        config: fixture.client_config(ports, &profile),
        dev: None,
        signatures: Signatures::Any,
        extra: Vec::new(),
        env: Vec::new(),
    };
    let session = Session::start(launch, fixture.signer()).unwrap();
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
            config: dir.join("client.ovpn"),
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
