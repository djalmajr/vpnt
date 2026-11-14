use super::automatic_support::*;
use super::*;
use crate::preferences::ProbeInterval;

#[test]
fn interval_reconciles_to_v3_and_the_next_connect_carries_it_without_loading() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    // The positive recording barrier: the peer has processed the startup
    // snapshot, so the absence checks below are not empty-file artifacts.
    assert!(
        commands(&peer).lines().any(|line| line == "snapshot"),
        "the peer command recorder must be live before negative assertions"
    );
    set_preferences(&mut broker, preferences(ProbeInterval::THIRTY, true, false));
    let until = Instant::now() + Duration::from_secs(4);
    while !intervals(&peer)
        .iter()
        .any(|value| value["type"] == "set_probe_interval" && value["interval"] == 30)
    {
        broker.poll();
        assert!(Instant::now() < until, "interval was not reconciled");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        calls.recorded().is_empty(),
        "changing settings must not load credentials"
    );
    let records = intervals(&peer);
    let thirty = records
        .iter()
        .position(|value| value["type"] == "set_probe_interval" && value["interval"] == 30)
        .expect("the explicit 30 s wire record");
    assert!(
        !records[..=thirty]
            .iter()
            .any(|value| value["type"] == "set_probe_interval" && value["interval"] == 10),
        "the default 10 s interval must not be sent before the explicit 30 s"
    );
    assert!(
        !records[thirty + 1..]
            .iter()
            .any(|value| value["type"] == "set_probe_interval" && value["interval"] == 10),
        "the default 10 s interval must not be sent after the explicit 30 s"
    );
    connect(&mut broker, &peer, "one");
    let connects: Vec<_> = intervals(&peer)
        .into_iter()
        .filter(|value| value["type"] == "connect")
        .collect();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0]["id"], "one");
    assert_eq!(connects[0]["generation"], 1);
    assert_eq!(connects[0]["interval"], 30);
    assert_eq!(calls.recorded(), vec![("one".to_string(), VpnKind::Ssl)]);
    no_secret(&broker.snapshot());
}

// This peer exercises the explicit version branch; separate Broker and Client
// tests cover the genuine protocol-2 body without the newer required fields.
#[test]
fn v3_shaped_old_protocol_version_is_incompatible_before_any_credential_or_connect() {
    let mut peer = Peer::new("old");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "outdated");
    assert!(calls.recorded().is_empty());
    assert!(run(&mut broker, Command::Toggle { id: "one".into() }).is_err());
    assert!(calls.recorded().is_empty());
    assert_eq!(command_count(&peer, "connect"), 0);
    assert!(broker.snapshot().vpns.is_empty());
    no_secret(&broker.snapshot());
}
