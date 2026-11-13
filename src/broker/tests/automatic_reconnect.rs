use super::automatic_support::*;
use super::*;
use crate::preferences::ProbeInterval;

#[test]
fn reconnect_off_never_loads_after_the_manual_connect_or_queues_an_attempt() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, false));
    connect(&mut broker, &peer, "one");
    assert_eq!(calls.recorded(), vec![("one".to_string(), VpnKind::Ssl)]);
    for failures in 1..=3 {
        probe(&mut broker, "one", failures);
        automatic(&mut broker);
        assert_eq!(command_count(&peer, "connect"), 1);
        assert_eq!(calls.recorded().len(), 1);
    }
    assert_eq!(state(&broker.snapshot(), "one"), State::Unresponsive);
    no_secret(&broker.snapshot());
}

#[test]
fn third_failure_reconnects_once_in_a_new_generation_and_preserves_the_other_profile() {
    let mut peer = Peer::new("ipsec");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    connect(&mut broker, &peer, "ipsec");
    let one_generation = broker.connections["one"].generation;
    let ipsec_generation = broker.connections["ipsec"].generation;
    for failures in 1..=2 {
        probe(&mut broker, "one", failures);
        automatic(&mut broker);
        assert_eq!(command_count(&peer, "connect"), 2, "no auto before three");
        assert_eq!(broker.connections["one"].generation, one_generation);
    }
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert_eq!(broker.connections["one"].generation, one_generation + 1);
    assert_eq!(state(&broker.snapshot(), "ipsec"), State::Connected);
    assert_eq!(broker.connections["ipsec"].generation, ipsec_generation);
    assert_eq!(command_count(&peer, "connect"), 3);
    assert_eq!(
        calls.recorded(),
        vec![
            ("one".to_string(), VpnKind::Ssl),
            ("ipsec".to_string(), VpnKind::Ipsec),
            ("one".to_string(), VpnKind::Ssl),
        ]
    );
    no_secret(&broker.snapshot());
    no_secret_on_disk(&peer);
}

#[test]
fn responsive_probe_resets_the_streak_and_a_new_episode_reconnects_once() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    for failures in 1..=2 {
        probe(&mut broker, "one", failures);
        automatic(&mut broker);
    }
    assert_eq!(command_count(&peer, "connect"), 1);
    std::fs::write(peer.marker.with_extension("probe_ok"), b"").unwrap();
    run(&mut broker, Command::Probe { id: "one".into() }).unwrap();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert_eq!(broker.connections["one"].failures, 0);
    std::fs::remove_file(peer.marker.with_extension("probe_ok")).unwrap();
    for failures in 1..=2 {
        probe(&mut broker, "one", failures);
        automatic(&mut broker);
        assert_eq!(command_count(&peer, "connect"), 1);
    }
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(calls.recorded().len(), 2);
    no_secret(&broker.snapshot());
}

#[test]
fn duplicate_and_old_generation_failure_events_cannot_queue_another_attempt() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    for failures in 1..=3 {
        probe(&mut broker, "one", failures);
    }
    // A duplicate current-generation failure-3 event must not enqueue twice.
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert_eq!(broker.connections["one"].generation, 2);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert!(
        broker.automatic.is_empty(),
        "duplicate failure-3 must not leave a queued automatic action"
    );
    // A late event for the replaced generation is ignored by the broker. The
    // Probe below is the ordered wire barrier: its request/answer follows the
    // stale frame on the same Client stream.
    std::fs::write(
        peer.marker.with_extension("stale"),
        br#"{"id":"one","generation":1,"state":"unresponsive","failures":3}"#,
    )
    .unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while !peer.marker.with_extension("stale.sent").exists() {
        assert!(Instant::now() < until, "late event was not consumed");
        std::thread::sleep(Duration::from_millis(5));
    }
    consume_stale_with_probe(&mut broker, &peer);
    assert_eq!(state(&broker.snapshot(), "one"), State::Connected);
    assert_eq!(broker.connections["one"].generation, 2);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(calls.recorded().len(), 2);
}

#[test]
fn helper_denial_restores_the_source_generation_and_does_not_loop() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    for failures in 1..=3 {
        probe(&mut broker, "one", failures);
    }
    std::fs::write(peer.marker.with_extension("deny_connect"), b"").unwrap();
    automatic(&mut broker);
    let until = Instant::now() + Duration::from_secs(4);
    while broker.connections["one"].generation != 1 || broker.connections["one"].pending.is_some() {
        broker.poll();
        assert!(Instant::now() < until, "helper denial was not processed");
        std::thread::sleep(Duration::from_millis(5));
    }
    let snapshot = broker.snapshot();
    assert_eq!(state(&snapshot, "one"), State::Unresponsive);
    assert_eq!(broker.connections["one"].generation, 1);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(calls.recorded().len(), 2);
    // The same source generation cannot loop after the denial.
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(calls.recorded().len(), 2);
    assert_eq!(broker.connections["one"].generation, 1);
    no_secret(&snapshot);
    no_secret_on_disk(&peer);
}

#[test]
fn secret_failure_does_not_loop_the_same_generation() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, fail) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    for failures in 1..=3 {
        probe(&mut broker, "one", failures);
    }
    fail.store(true, Ordering::Release);
    automatic(&mut broker);
    assert_eq!(command_count(&peer, "connect"), 1);
    assert_eq!(calls.recorded().len(), 2, "manual plus one failed attempt");
    assert_eq!(broker.connections["one"].generation, 1);
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    assert_eq!(command_count(&peer, "connect"), 1);
    assert_eq!(calls.recorded().len(), 2);
    assert_eq!(broker.connections["one"].generation, 1);
    no_secret(&broker.snapshot());
}

#[test]
fn late_old_generation_failure_does_not_reactivate() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    for failures in 1..=3 {
        probe(&mut broker, "one", failures);
    }
    automatic(&mut broker);
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert_eq!(broker.connections["one"].generation, 2);
    assert_eq!(command_count(&peer, "connect"), 2);
    std::fs::write(
        peer.marker.with_extension("stale"),
        br#"{"id":"one","generation":1,"state":"unresponsive","failures":3}"#,
    )
    .unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while !peer.marker.with_extension("stale.sent").exists() {
        assert!(Instant::now() < until, "late event was not consumed");
        std::thread::sleep(Duration::from_millis(5));
    }
    consume_stale_with_probe(&mut broker, &peer);
    let snapshot = broker.snapshot();
    assert_eq!(
        state(&snapshot, "one"),
        State::Connected,
        "an old-generation failure must not change the current tunnel"
    );
    assert_eq!(broker.connections["one"].generation, 2);
    assert_eq!(command_count(&peer, "connect"), 2);
    assert_eq!(calls.recorded().len(), 2);
}

fn reconnect_queued(broker: &Broker<RecordingSecrets>, id: &str) -> bool {
    broker.automatic.iter().any(|action| {
        matches!(action, super::super::automatic::Action::Reconnect { id: queued, .. } if queued == id)
    })
}

#[test]
fn a_manual_action_for_one_profile_preserves_the_other_profiles_pending_auto() {
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, true));
    connect(&mut broker, &peer, "one");
    connect(&mut broker, &peer, "two");
    for failures in 1..=3 {
        probe(&mut broker, "one", failures);
        probe(&mut broker, "two", failures);
    }
    assert!(
        reconnect_queued(&broker, "one") && reconnect_queued(&broker, "two"),
        "both profiles must have a queued Reconnect before the interrupt"
    );
    broker.interrupt_automatic(&Command::Toggle { id: "one".into() });
    assert!(
        !reconnect_queued(&broker, "one"),
        "the targeted action was removed"
    );
    assert!(
        reconnect_queued(&broker, "two"),
        "the unrelated profile's pending auto must survive"
    );
    automatic(&mut broker);
    wait(&mut broker, |s| state(s, "two") == State::Connected);
    let snapshot = broker.snapshot();
    assert_eq!(state(&snapshot, "one"), State::Unresponsive);
    assert_eq!(broker.connections["one"].generation, 1);
    assert_eq!(broker.connections["two"].generation, 2);
    assert_eq!(command_count(&peer, "connect"), 3);
    assert_eq!(
        calls.recorded(),
        vec![
            ("one".to_string(), VpnKind::Ssl),
            ("two".to_string(), VpnKind::Ssl),
            ("two".to_string(), VpnKind::Ssl),
        ]
    );
    no_secret(&snapshot);
}
