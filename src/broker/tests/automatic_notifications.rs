use super::automatic_support::*;
use super::*;
use crate::{localization::Locale, preferences::ProbeInterval};

#[test]
fn one_notice_per_episode_uses_the_shared_catalog_and_profile_name() {
    let mut peer = Peer::new("flow");
    let (secrets, _, _) = RecordingSecrets::new();
    let fake = FakeNotifier::default();
    let mut broker = broker_with(&mut peer, secrets).with_notifier(Box::new(fake.clone()));
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, true, false));
    connect(&mut broker, &peer, "one");
    // The worker now announces Unresponsive only from the second failed
    // probe, so that is the first failure that can open a notice episode.
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    let generation = broker.connections["one"].generation;
    let sent = fake.sent();
    assert_eq!(sent.len(), 1);
    let english = Locale::EnUs.native();
    assert_eq!(sent[0].id, format!("one-{generation}"));
    assert_eq!(sent[0].title, english.unresponsive_title);
    assert_eq!(
        sent[0].body,
        english.unresponsive_body.replace("{profile}", "one")
    );
    assert!(sent[0].current.load(Ordering::Acquire));
    for text in [&sent[0].id, &sent[0].title, &sent[0].body] {
        assert!(!text.contains("fictional-client-secret"));
        assert!(!text.contains("fictional-psk"));
    }
    // The same episode cannot notify again at failure three.
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    // Recovery revokes the live episode token.
    std::fs::write(peer.marker.with_extension("probe_ok"), b"").unwrap();
    run(&mut broker, Command::Probe { id: "one".into() }).unwrap();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert!(!sent[0].current.load(Ordering::Acquire));
    assert_eq!(fake.count(), 1);
    // A new episode in the other shared language notifies once more.
    broker.set_locale(Locale::PtBr);
    std::fs::remove_file(peer.marker.with_extension("probe_ok")).unwrap();
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    let sent = fake.sent();
    assert_eq!(sent.len(), 2);
    let portuguese = Locale::PtBr.native();
    assert_eq!(sent[1].id, format!("one-{generation}"));
    assert_eq!(sent[1].title, portuguese.unresponsive_title);
    assert_eq!(
        sent[1].body,
        portuguese.unresponsive_body.replace("{profile}", "one")
    );
    assert!(sent[1].current.load(Ordering::Acquire));
    no_secret(&broker.snapshot());
    no_secret_on_disk(&peer);
}

#[test]
fn notice_waits_for_the_second_failed_probe_on_the_wire() {
    let mut peer = Peer::new("notice");
    let (secrets, _, _) = RecordingSecrets::new();
    let fake = FakeNotifier::default();
    let mut broker = broker_with(&mut peer, secrets).with_notifier(Box::new(fake.clone()));
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, true, false));
    connect(&mut broker, &peer, "one");
    let generation = broker.connections["one"].generation;
    assert_eq!(broker.connections["one"].failures, 0);
    // First failed health sample: the peer sends the very same Connected/0
    // tuple as the successful connect. The diagnostics reply is the barrier
    // that proves this frame was consumed, not just written to the socket.
    probe_once_with_barrier(&mut broker, "one");
    automatic(&mut broker);
    assert_eq!(fake.count(), 0, "no notice before the second probe");
    assert_eq!(state(&broker.snapshot(), "one"), State::Connected);
    assert_eq!(broker.connections["one"].failures, 0);
    assert_eq!(command_count(&peer, "probe"), 1);
    // Only the second failed sample crosses the wire threshold.
    probe(&mut broker, "one", 2);
    assert_eq!(command_count(&peer, "probe"), 2);
    automatic(&mut broker);
    assert_eq!(state(&broker.snapshot(), "one"), State::Unresponsive);
    assert_eq!(fake.count(), 1);
    let sent = fake.sent();
    assert_eq!(sent[0].id, format!("one-{generation}"));
    let token = sent[0].current.clone();
    assert!(token.load(Ordering::Acquire));
    // The third sample does not open another episode.
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    assert!(token.load(Ordering::Acquire));
    // Recovery travels as Connected/0 and revokes the live token.
    std::fs::write(peer.marker.with_extension("probe_ok"), b"").unwrap();
    run(&mut broker, Command::Probe { id: "one".into() }).unwrap();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    assert_eq!(broker.connections["one"].failures, 0);
    assert!(!token.load(Ordering::Acquire));
    // A fresh episode starts with Connected/0 again and still notifies once.
    std::fs::remove_file(peer.marker.with_extension("probe_ok")).unwrap();
    probe_once_with_barrier(&mut broker, "one");
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    let sent = fake.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].id, format!("one-{generation}"));
    assert!(sent[1].current.load(Ordering::Acquire));
    no_secret(&broker.snapshot());
    no_secret_on_disk(&peer);
}

#[test]
fn notify_off_never_delivers_and_revokes_the_live_episode_token() {
    let mut peer = Peer::new("flow");
    let (secrets, _, _) = RecordingSecrets::new();
    let fake = FakeNotifier::default();
    let mut broker = broker_with(&mut peer, secrets).with_notifier(Box::new(fake.clone()));
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, true, false));
    connect(&mut broker, &peer, "one");
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    let token = fake.sent()[0].current.clone();
    assert!(token.load(Ordering::Acquire));
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, false, false));
    assert!(!token.load(Ordering::Acquire));
    probe(&mut broker, "one", 3);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    // A new episode with notifications off also delivers nothing.
    std::fs::write(peer.marker.with_extension("probe_ok"), b"").unwrap();
    run(&mut broker, Command::Probe { id: "one".into() }).unwrap();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    std::fs::remove_file(peer.marker.with_extension("probe_ok")).unwrap();
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    no_secret(&broker.snapshot());
}

#[test]
fn generation_change_and_channel_loss_revoke_the_live_token() {
    let mut peer = Peer::new("flow");
    let (secrets, _, _) = RecordingSecrets::new();
    let fake = FakeNotifier::default();
    let mut broker = broker_with(&mut peer, secrets).with_notifier(Box::new(fake.clone()));
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, true, false));
    connect(&mut broker, &peer, "one");
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    let first = fake.sent()[0].current.clone();
    run(&mut broker, Command::Reconnect { id: "one".into() }).unwrap();
    assert!(!first.load(Ordering::Acquire));
    peer.advance();
    wait(&mut broker, |s| state(s, "one") == State::Connected);
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    assert_eq!(fake.count(), 2);
    let second = fake.sent()[1].current.clone();
    assert!(second.load(Ordering::Acquire));
    std::fs::write(peer.marker.with_extension("close"), b"").unwrap();
    wait(&mut broker, |s| s.helper == "missing");
    assert!(!second.load(Ordering::Acquire));
    assert_eq!(fake.count(), 2);
    no_secret(&broker.snapshot());
}

#[test]
fn dropping_the_broker_revokes_the_live_notice_token() {
    let mut peer = Peer::new("flow");
    let (secrets, _, _) = RecordingSecrets::new();
    let fake = FakeNotifier::default();
    let mut broker = broker_with(&mut peer, secrets).with_notifier(Box::new(fake.clone()));
    wait(&mut broker, |s| s.helper == "installed");
    set_preferences(&mut broker, preferences(ProbeInterval::TEN, true, false));
    connect(&mut broker, &peer, "one");
    probe(&mut broker, "one", 2);
    automatic(&mut broker);
    assert_eq!(fake.count(), 1);
    let token = fake.sent()[0].current.clone();
    assert!(token.load(Ordering::Acquire));
    drop(broker);
    assert!(!token.load(Ordering::Acquire));
}
