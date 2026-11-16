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
    session::{Launch, Progress, Session},
    signing::{Hash, Padding},
};

/// Sessions share /tmp, which the cleanup test counts.
static SERIAL: Mutex<()> = Mutex::new(());

/// Connects, then stops; returns the paddings the token was asked for.
fn connect_and_stop(fixture: &Fixture, pss: bool, tls_max: Option<&str>) -> Vec<Padding> {
    let ports = free_udp_ports();
    let _server = fixture.server(ports, !pss);
    let signer = fixture.signer();
    let paddings = Arc::clone(&signer.paddings);
    let launch = Launch {
        openvpn: fixture.openvpn.clone(),
        config: fixture.client_config(ports, tls_max),
        pss,
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
    let paddings = connect_and_stop(&fixture, true, None);
    assert!(
        paddings.contains(&Padding::Pss(Hash::Sha256)),
        "{paddings:?}"
    );
}

#[test]
fn tls12_without_pss_is_signed_with_pkcs1() {
    // Mutation captured: sending a DigestInfo to a PSS mechanism (or the
    // reverse), or refusing the real DigestInfo, fails the CertificateVerify.
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let Some(fixture) = Fixture::new("pkcs1") else {
        return;
    };
    let paddings = connect_and_stop(&fixture, false, Some("1.2"));
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
    connect_and_stop(&fixture, true, None);
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
