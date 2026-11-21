use super::*;
mod host;
use crate::{
    preferences::ProbeInterval,
    secrets::{Credentials, SecretError},
};

/// Preferences are choice state only: any credential operation here is a defect.
struct NoSecrets;
impl SecretStore for NoSecrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        panic!("preferences must not query the keychain")
    }
    fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, SecretError> {
        panic!("preferences must not load credentials")
    }
    fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
        panic!("preferences must not save credentials")
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
        panic!("preferences must not remove credentials")
    }
}

fn broker() -> Broker<NoSecrets> {
    Broker::new(None, NoSecrets)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

fn submit(broker: &mut Broker<NoSecrets>, preferences: Preferences) -> Snapshot {
    broker
        .dispatch(Command::SetPreferences { preferences }, deadline())
        .unwrap()
}

// Mutations: invent a non-default choice before submission, or hide the stored
// choice from the snapshot the frontend reads.
#[test]
fn defaults_are_echoed_without_a_helper_or_credentials() {
    let mut broker = broker();
    let snapshot = broker.snapshot();
    assert_eq!(snapshot.preferences, Preferences::default());
    assert!(!snapshot.demo);
    assert_eq!(snapshot.helper, "missing");
    assert!(snapshot.vpns.is_empty());
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["preferences"],
        serde_json::json!({"interval":10,"notify":true,"reconnect":false,"startup":false})
    );
}

// Mutations: accept the command without keeping it, or echo a different set of
// values than the ones submitted.
#[test]
fn non_startup_choices_are_cached_and_echoed() {
    let mut broker = broker();
    let chosen = Preferences {
        interval: ProbeInterval::SIXTY,
        notify: false,
        reconnect: true,
        startup: false,
    };
    assert_eq!(submit(&mut broker, chosen).preferences, chosen);
    let snapshot = broker.snapshot();
    assert_eq!(snapshot.preferences, chosen);
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["preferences"],
        serde_json::to_value(chosen).unwrap()
    );
    assert!(snapshot.vpns.is_empty());
}

// Mutations: admit startup=true without the login adapter, or keep part of a
// rejected document (the previous interval/booleans must survive intact).
#[test]
fn startup_choice_is_rejected_atomically() {
    let mut broker = broker();
    let baseline = Preferences {
        interval: ProbeInterval::THIRTY,
        notify: false,
        reconnect: false,
        startup: false,
    };
    submit(&mut broker, baseline);
    let rejected = Preferences {
        interval: ProbeInterval::SIXTY,
        notify: true,
        reconnect: true,
        startup: true,
    };
    assert_eq!(
        broker
            .dispatch(
                Command::SetPreferences {
                    preferences: rejected
                },
                deadline()
            )
            .err(),
        Some("startup_unavailable")
    );
    assert_eq!(broker.snapshot().preferences, baseline);
    // A rejected document leaves no latch: a valid one still applies afterwards.
    let later = Preferences {
        interval: ProbeInterval::TEN,
        notify: true,
        reconnect: false,
        startup: false,
    };
    assert_eq!(submit(&mut broker, later).preferences, later);
}

// Mutations: apply the choice before the expiry gate, so a stale request changes
// state after the caller gave up.
#[test]
fn expired_request_does_not_change_choices() {
    let mut broker = broker();
    let baseline = Preferences {
        interval: ProbeInterval::THIRTY,
        notify: false,
        reconnect: false,
        startup: false,
    };
    submit(&mut broker, baseline);
    let stale = Preferences {
        interval: ProbeInterval::SIXTY,
        notify: true,
        reconnect: true,
        startup: false,
    };
    assert_eq!(
        broker
            .dispatch(
                Command::SetPreferences { preferences: stale },
                Instant::now() - Duration::from_millis(1)
            )
            .err(),
        Some("backend_unavailable")
    );
    assert_eq!(broker.snapshot().preferences, baseline);
}

#[cfg(target_os = "macos")]
#[test]
fn previous_session_notice_keeps_the_helper_during_a_thirty_second_recovery() {
    for announced in [false, true] {
        let (send_request, requests) = std::sync::mpsc::sync_channel(8);
        let (send_reply, replies) = std::sync::mpsc::sync_channel(8);
        let mut broker = Broker::new(
            Some(Client::fixture_channels(send_request, replies)),
            NoSecrets,
        );
        let initial = requests.try_recv().unwrap();
        assert_eq!(initial.id, protocol::WAIT_CAPABILITY_SNAPSHOT_ID);
        assert!(matches!(initial.command, protocol::Command::Snapshot {}));
        if announced {
            send_reply
                .send(Message::PreviousSessionFinishing {
                    protocol_version: protocol::VERSION,
                    version: env!("CARGO_PKG_VERSION").into(),
                })
                .unwrap();
            broker.poll();
            assert_eq!(broker.helper, "previous_session_finishing");
        }
        // Advance only the admission clock. The fixture stays connected and
        // withholds the first Snapshot throughout the simulated cleanup.
        broker.startup -= Duration::from_secs(30);
        broker.poll();
        assert_eq!(broker.dead, !announced);
        assert!(!broker.ready);
        if announced {
            send_reply
                .send(Message::Snapshot {
                    id: initial.id,
                    protocol_version: protocol::VERSION,
                    version: env!("CARGO_PKG_VERSION").into(),
                    build: None,
                    profiles: vec![],
                    connections: vec![],
                })
                .unwrap();
            broker.poll();
            assert!(broker.ready);
            assert!(!broker.dead);
            assert!(!broker.waiting_previous);
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn review_startup_deadline_without_a_wait_notice_retires_the_helper() {
    use std::sync::mpsc::sync_channel;

    for announced in [false, true] {
        let (requests, requests_rx) = sync_channel(4);
        let (replies, replies_rx) = sync_channel(4);
        let mut broker = Broker::new(
            Some(Client::fixture_channels(requests, replies_rx)),
            NoSecrets,
        );
        assert_eq!(
            requests_rx.try_recv().unwrap().id,
            protocol::WAIT_CAPABILITY_SNAPSHOT_ID
        );
        assert!(broker.starting());
        broker.startup = Instant::now();
        if announced {
            replies
                .try_send(Message::PreviousSessionFinishing {
                    protocol_version: protocol::VERSION,
                    version: env!("CARGO_PKG_VERSION").into(),
                })
                .unwrap();
        }
        broker.poll();
        if announced {
            assert_eq!(broker.helper, "previous_session_finishing");
            assert!(!broker.dead);
        } else {
            assert_eq!(broker.helper, "missing");
            assert!(broker.dead);
            assert!(
                broker
                    .client
                    .as_ref()
                    .unwrap()
                    .send(Request {
                        id: protocol::WAIT_CAPABILITY_SNAPSHOT_ID.into(),
                        command: protocol::Command::Snapshot {},
                    })
                    .is_err()
            );
        }
    }
}
