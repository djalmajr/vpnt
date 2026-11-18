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
