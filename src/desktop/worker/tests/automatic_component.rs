use super::automatic_support::*;
use super::*;
use crate::helper::client::tests::Peer;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn component_blocks_automatic(command: &'static str, id: &'static str, settle: bool) {
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
            let broker = Broker::transport_fixture(client, secrets).refuse_components();
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
        "prefs",
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
    // Queue the component and a post-component snapshot before releasing the
    // blocked automatic load. FIFO ensures the snapshot is observed before any
    // idle automatic retry.
    send(&worker, id, serde_json::json!({"type":command}));
    send(&worker, "post", serde_json::json!({"type":"get_snapshot"}));
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let reply = receive.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(reply.id, id);
    assert_eq!(
        reply.error.as_deref(),
        Some("component_busy"),
        "the fixture must refuse the component rather than start an installer"
    );
    let post = receive
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .snapshot
        .unwrap();
    assert_eq!(
        post.vpns
            .iter()
            .find(|v| v.profile.id == "one")
            .unwrap()
            .state,
        crate::session::ConnectionState::Unresponsive,
        "the queued component must cancel the blocked automatic connect"
    );
    assert_eq!(
        loads.load(Ordering::SeqCst),
        2,
        "the queued component must cancel the blocked automatic load"
    );
    assert_eq!(
        command_count(&peer, "connect"),
        1,
        "no automatic Connect may reach the peer"
    );
    if settle {
        wait_idle(&worker);
        let settled = snapshot(&worker, &receive, "settled");
        let state = settled
            .vpns
            .iter()
            .find(|v| v.profile.id == "one")
            .unwrap()
            .state;
        let connects = command_count(&peer, "connect");
        let loads_now = loads.load(Ordering::SeqCst);
        assert_eq!(
            connects, 1,
            "refused component reactivated the automatic connect              (state={state:?}, loads={loads_now})"
        );
        assert_eq!(
            state,
            crate::session::ConnectionState::Unresponsive,
            "the refused component must not reactivate the automatic connection"
        );
        assert_eq!(loads_now, 2);
    }
}

#[test]
fn install_helper_blocks_the_automatic_connect() {
    component_blocks_automatic("install_helper", "install", false);
}

#[test]
fn remove_helper_blocks_the_automatic_connect() {
    component_blocks_automatic("remove_helper", "remove", false);
}

#[test]
fn refused_install_does_not_reactivate_after_idle() {
    component_blocks_automatic("install_helper", "install", true);
}

#[test]
fn refused_remove_does_not_reactivate_after_idle() {
    component_blocks_automatic("remove_helper", "remove", true);
}
