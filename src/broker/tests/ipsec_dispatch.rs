use super::*;
use crate::helper::client::tests::Peer;
use crate::secrets::{Credentials, SecretError};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Calls(Arc<Mutex<Vec<(String, VpnKind)>>>);
impl Calls {
    fn recorded(&self) -> Vec<(String, VpnKind)> {
        self.0.lock().unwrap().clone()
    }
}

struct IpsecSecrets {
    calls: Calls,
    psk: String,
}
impl IpsecSecrets {
    fn new(psk: &str) -> (Self, Calls) {
        let calls = Calls::default();
        (
            Self {
                calls: calls.clone(),
                psk: psk.into(),
            },
            calls,
        )
    }
}
impl SecretStore for IpsecSecrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        Ok(true)
    }
    fn load(&self, id: &str, kind: VpnKind) -> Result<Credentials, SecretError> {
        self.calls.0.lock().unwrap().push((id.into(), kind));
        Ok(Credentials {
            password: "fictional-client-secret".into(),
            psk: self.psk.clone().into(),
        })
    }
    fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
        Ok(())
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
        Ok(())
    }
}

fn dispatch(b: &mut Broker<IpsecSecrets>, c: Command) -> Result<Snapshot, &'static str> {
    b.dispatch(c, Instant::now() + Duration::from_secs(2))
}
fn state(snapshot: &Snapshot, id: &str) -> State {
    snapshot
        .vpns
        .iter()
        .find(|v| v.profile.id == id)
        .unwrap()
        .state
}
fn assert_not_connected(snapshot: &Snapshot, id: &str) {
    let vpn = snapshot.vpns.iter().find(|v| v.profile.id == id).unwrap();
    assert!(
        !vpn.log.iter().any(|entry| entry.state == State::Connected),
        "{id} must never claim connected"
    );
}
fn no_secret(snapshot: &Snapshot) {
    let text = serde_json::to_string(snapshot).unwrap();
    assert!(!text.contains("fictional-client-secret"));
    assert!(!text.contains("fictional-psk"));
}
fn commands(peer: &Peer) -> String {
    std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap_or_default()
}
fn command_count(peer: &Peer, command: &str) -> usize {
    commands(peer)
        .lines()
        .filter(|line| *line == command)
        .count()
}
fn no_secret_on_disk(peer: &Peer) {
    for entry in std::fs::read_dir(peer.root()).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("fictional-client-secret"));
        assert!(!text.contains("fictional-psk"));
    }
}

#[test]
fn ipsec_connect_loads_only_the_ipsec_profile_and_consumes_the_psk() {
    let mut peer = Peer::new("ipsec");
    let (secrets, calls) = IpsecSecrets::new("fictional-psk");
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    let snapshot = dispatch(&mut broker, Command::Toggle { id: "ipsec".into() }).unwrap();
    assert_eq!(state(&snapshot, "ipsec"), State::Connecting);
    assert_eq!(
        calls.recorded(),
        vec![("ipsec".to_string(), VpnKind::Ipsec)],
        "the broker must load the exact IPsec profile id and kind"
    );
    peer.advance();
    wait(&mut broker, |s| state(s, "ipsec") == State::Connected);
    assert_eq!(
        calls.recorded(),
        vec![("ipsec".to_string(), VpnKind::Ipsec)]
    );
    assert_eq!(command_count(&peer, "connect"), 1);
    no_secret(&broker.snapshot());
    assert!(!commands(&peer).contains("fictional-psk"));
    no_secret_on_disk(&peer);
}

#[test]
fn missing_ipsec_psk_yields_exact_invalid_secret_and_never_queues_connect() {
    let mut peer = Peer::new("ipsec");
    let (secrets, calls) = IpsecSecrets::new("");
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    let result = dispatch(&mut broker, Command::Toggle { id: "ipsec".into() });
    assert_eq!(result.err(), Some("invalid_secret"));
    assert_eq!(
        calls.recorded(),
        vec![("ipsec".to_string(), VpnKind::Ipsec)],
        "the guard must load the exact IPsec profile id and kind"
    );
    let snapshot = broker.snapshot();
    assert_eq!(state(&snapshot, "ipsec"), State::Off);
    assert_eq!(broker.connections["ipsec"].generation, 0);
    assert_eq!(command_count(&peer, "connect"), 0);
    no_secret(&snapshot);
}

#[test]
fn ipsec_reconnect_keeps_the_other_active_profile_and_generation() {
    let mut peer = Peer::new("ipsec");
    let (secrets, calls) = IpsecSecrets::new("fictional-psk");
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "one".into() }).unwrap();
    peer.advance();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    let one_generation = broker.connections["one"].generation;
    assert_eq!(calls.recorded(), vec![("one".to_string(), VpnKind::Ssl)]);
    dispatch(&mut broker, Command::Toggle { id: "ipsec".into() }).unwrap();
    peer.advance();
    wait(&mut broker, |s| state(s, "ipsec") == State::Connected);
    assert_eq!(state(&broker.snapshot(), "one"), State::Connected);
    assert_eq!(broker.connections["one"].generation, one_generation);
    let snapshot = dispatch(&mut broker, Command::Reconnect { id: "ipsec".into() }).unwrap();
    assert_eq!(state(&snapshot, "ipsec"), State::Reconnecting);
    peer.advance();
    wait(&mut broker, |s| state(s, "ipsec") == State::Connected);
    assert_eq!(state(&broker.snapshot(), "one"), State::Connected);
    assert_eq!(broker.connections["one"].generation, one_generation);
    assert_eq!(command_count(&peer, "connect"), 3);
    assert_eq!(command_count(&peer, "disconnect"), 0);
    assert_eq!(
        calls.recorded(),
        vec![
            ("one".to_string(), VpnKind::Ssl),
            ("ipsec".to_string(), VpnKind::Ipsec),
            ("ipsec".to_string(), VpnKind::Ipsec),
        ]
    );
    no_secret(&broker.snapshot());
    no_secret_on_disk(&peer);
}

#[test]
fn ipsec_helper_denial_rolls_back_without_success_and_preserves_ssl() {
    let mut peer = Peer::new("ipsec-denied");
    let (secrets, calls) = IpsecSecrets::new("fictional-psk");
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "one".into() }).unwrap();
    peer.advance();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    let one_generation = broker.connections["one"].generation;
    let ipsec_generation = broker.connections["ipsec"].generation;
    dispatch(&mut broker, Command::Toggle { id: "ipsec".into() }).unwrap();
    let until = Instant::now() + Duration::from_secs(4);
    while broker.connections["ipsec"].pending.is_some() {
        broker.poll();
        assert!(
            Instant::now() < until,
            "the broker did not process the helper denial"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let snapshot = broker.snapshot();
    assert_eq!(state(&snapshot, "ipsec"), State::Off);
    assert_eq!(
        broker.connections["ipsec"].generation, ipsec_generation,
        "a denied connect must restore the previous generation"
    );
    assert_not_connected(&snapshot, "ipsec");
    assert_eq!(state(&snapshot, "one"), State::Connected);
    assert_eq!(broker.connections["one"].generation, one_generation);
    let denied: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(peer.marker.with_extension("denied")).unwrap(),
    )
    .unwrap();
    assert_eq!(denied["error"].as_str(), Some("missing_program"));
    assert_eq!(denied["generation"].as_u64(), Some(ipsec_generation + 1));
    assert_eq!(
        calls.recorded(),
        vec![
            ("one".to_string(), VpnKind::Ssl),
            ("ipsec".to_string(), VpnKind::Ipsec),
        ]
    );
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(command_count(&peer, "disconnect"), 0);
    no_secret(&snapshot);
    no_secret_on_disk(&peer);
}

#[test]
fn ipsec_cancel_ignores_a_late_connected_generation_and_reconnects() {
    let mut peer = Peer::new("ipsec");
    let (secrets, calls) = IpsecSecrets::new("fictional-psk");
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "ipsec".into() }).unwrap();
    assert_eq!(broker.connections["ipsec"].generation, 1);
    dispatch(&mut broker, Command::Toggle { id: "ipsec".into() }).unwrap();
    wait(&mut broker, |s| state(s, "ipsec") == State::Off);
    assert_eq!(broker.connections["ipsec"].generation, 2);
    assert_not_connected(&broker.snapshot(), "ipsec");
    peer.advance();
    std::thread::sleep(Duration::from_millis(50));
    let snapshot = broker.snapshot();
    assert_eq!(state(&snapshot, "ipsec"), State::Off);
    assert_eq!(broker.connections["ipsec"].generation, 2);
    assert_not_connected(&snapshot, "ipsec");
    dispatch(&mut broker, Command::Toggle { id: "ipsec".into() }).unwrap();
    peer.advance();
    wait(&mut broker, |s| state(s, "ipsec") == State::Connected);
    assert_eq!(broker.connections["ipsec"].generation, 3);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(command_count(&peer, "disconnect"), 1);
    assert_eq!(
        calls.recorded(),
        vec![
            ("ipsec".to_string(), VpnKind::Ipsec),
            ("ipsec".to_string(), VpnKind::Ipsec),
        ]
    );
    no_secret(&broker.snapshot());
    no_secret_on_disk(&peer);
}
