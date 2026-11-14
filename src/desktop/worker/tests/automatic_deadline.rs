use super::automatic_support::*;
use super::*;
use crate::helper::client::tests::Peer;
use std::sync::{Arc, Condvar, Mutex, atomic::AtomicUsize};

#[test]
fn expired_reconnect_off_does_not_reactivate_the_abandoned_auto() {
    let mut peer = Peer::new("flow");
    let (entered, entered_ready) = mpsc::sync_channel(1);
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let _release = Release::new(gate.clone());
    let loads = Arc::new(AtomicUsize::new(0));
    let secrets = BlockingSecrets {
        loads: loads.clone(),
        entered,
        gate: gate.clone(),
    };
    let client = peer.take();
    let (replies, receive) = mpsc::sync_channel(16);
    let worker = Worker::spawn(
        move || {
            let broker = Broker::transport_fixture(client, secrets);
            (None, Some(broker))
        },
        move |reply| {
            let _ = replies.send(reply);
        },
    )
    .unwrap();
    send(
        &worker,
        "initial",
        serde_json::json!({"type":"get_snapshot"}),
    );
    assert_eq!(
        receive
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .snapshot
            .unwrap()
            .helper,
        "installed"
    );
    send(
        &worker,
        "prefs-on",
        serde_json::json!({
            "type":"set_preferences",
            "preferences":{"interval":10,"notify":false,"reconnect":true,"startup":false}
        }),
    );
    assert!(
        receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .error
            .is_none()
    );
    send(
        &worker,
        "connect",
        serde_json::json!({"type":"toggle","id":"one"}),
    );
    assert!(
        receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .error
            .is_none()
    );
    peer.advance();
    wait_state(
        &worker,
        &receive,
        "one",
        crate::session::ConnectionState::Connected,
    );
    for _ in 0..3 {
        send(
            &worker,
            "probe",
            serde_json::json!({"type":"probe","id":"one"}),
        );
        assert!(
            receive
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .error
                .is_none()
        );
    }
    entered_ready
        .recv_timeout(Duration::from_secs(3))
        .expect("the automatic secret load did not block");
    send(
        &worker,
        "prefs-off",
        serde_json::json!({
            "type":"set_preferences",
            "preferences":{"interval":10,"notify":false,"reconnect":false,"startup":false}
        }),
    );
    std::thread::sleep(Duration::from_millis(9_100));
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let prefs_off = receive.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(prefs_off.id, "prefs-off");
    wait_idle(&worker);
    let settled = snapshot(&worker, &receive, "settled");
    assert_eq!(
        prefs_off.error.as_deref(),
        Some("backend_unavailable"),
        "an expired preference request remains an error"
    );
    assert!(
        settled.preferences.reconnect,
        "an expired preference must not be written as applied"
    );
    assert_eq!(
        command_count(&peer, "connect"),
        1,
        "the expired reconnect-off must not reactivate the abandoned automatic attempt"
    );
    assert_eq!(loads.load(Ordering::SeqCst), 2);
    assert_eq!(
        settled
            .vpns
            .iter()
            .find(|v| v.profile.id == "one")
            .unwrap()
            .state,
        crate::session::ConnectionState::Unresponsive
    );
}
