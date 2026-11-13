use super::*;

#[test]
fn stale_connecting_cancel_must_not_start_a_second_connect() {
    stale_stop(State::Connecting, false);
}

#[test]
fn stale_connected_off_must_not_start_a_second_connect() {
    stale_stop(State::Connected, false);
}

#[test]
fn stale_connected_off_after_prior_stop_must_not_start_a_second_connect() {
    stale_stop(State::Connected, true);
}

fn until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "stale-stop setup/receipt barrier timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn stale_stop(rendered: State, prior_stop: bool) {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    until(|| {
        broker.poll();
        broker.connections["one"]
            .pending
            .as_ref()
            .is_some_and(|p| p.accepted)
            && broker.connections["one"].view.state == State::Connecting
    });
    if rendered == State::Connected {
        peer.advance();
        wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    }
    let caller_snapshot = broker.snapshot();
    assert!(!caller_snapshot.demo);
    assert_eq!(caller_snapshot.vpns[0].state, rendered);
    assert!(caller_snapshot.vpns[0].state.active());
    assert_eq!(loads.load(Ordering::Relaxed), 1);
    let mut generation = broker.connections["one"].generation;
    if prior_stop {
        // A prior stop is already in flight; its reply is not delivered to this
        // caller. The peer generates Off through its normal Disconnect branch.
        dispatch(&mut broker, Command::Toggle { id: "one".into() });
        generation += 1;
    } else {
        // Existing marker sends a current-generation frame on the real stream.
        // This proves protocol consumption, not spontaneous native Off provenance.
        std::fs::write(
            peer.marker.with_extension("stale"),
            serde_json::to_vec(&serde_json::json!({
                "id": "one", "generation": generation, "state": "off", "failures": 0
            }))
            .unwrap(),
        )
        .unwrap();
    }
    until(|| {
        broker.poll(); // actor work only: no new snapshot delivered to caller
        let c = &broker.connections["one"];
        (prior_stop || peer.marker.with_extension("stale.sent").exists())
            && c.generation == generation
            && c.view.state == State::Off
            && c.pending.as_ref().is_some_and(|p| p.accepted)
    });
    assert_eq!(broker.helper, "installed");
    assert_eq!(caller_snapshot.vpns[0].state, rendered);
    assert_eq!(loads.load(Ordering::Relaxed), 1);
    // Explicit stop preserves the intent of the retained active render.
    let result = dispatch(
        &mut broker,
        Command::Disconnect {
            id: caller_snapshot.vpns[0].profile.id.clone(),
        },
    );
    until(|| {
        broker.poll();
        let c = &broker.connections["one"];
        c.generation == generation + 1 && c.pending.as_ref().is_some_and(|p| p.accepted)
    });
    let commands = std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap();
    let connects = commands.lines().filter(|c| *c == "connect").count();
    let disconnects = commands.lines().filter(|c| *c == "disconnect").count();
    let load_count = loads.load(Ordering::Relaxed);
    if connects == 1 {
        until(|| {
            broker.poll();
            broker.connections["one"].view.state == State::Off
        });
    }
    eprintln!(
        "EXPLICIT_STOP rendered={rendered:?} prior_stop={prior_stop} current_before=Off generation={generation} returned={:?} connects={connects} disconnects={disconnects} credential_loads={load_count} stop_request_accepted=true",
        result.vpns[0].state
    );
    // Complete our own fixture lifecycle before the intentional negative oracle.
    let fixture_root = peer.root().to_path_buf();
    drop(broker);
    until(|| peer.cleaned());
    drop(peer); // waits Client.finished; reaps child and removes owned fixture dir
    assert!(
        !fixture_root.exists(),
        "fixture ownership not fully released"
    );
    eprintln!("EXPLICIT_STOP cleanup=finished_and_fixture_root_removed");
    assert_eq!(connects, 1, "explicit stop must not submit another Connect");
    assert_eq!(
        disconnects,
        1 + usize::from(prior_stop),
        "explicit stop must submit Disconnect even from Off"
    );
    assert_eq!(
        load_count, 1,
        "a user's stop intent from an active rendered snapshot must not load credentials again"
    );
}

#[test]
fn explicit_connect_from_stale_off_view_preserves_actual_active_connection() {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    let caller_snapshot = broker.snapshot();
    assert_eq!(caller_snapshot.vpns[0].state, State::Off);
    dispatch(&mut broker, Command::Connect { id: "one".into() });
    peer.advance();
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    let generation = broker.connections["one"].generation;
    let result = dispatch(
        &mut broker,
        Command::Connect {
            id: caller_snapshot.vpns[0].profile.id.clone(),
        },
    );
    // A later interval command is a FIFO wire barrier: the peer has processed
    // any preceding unexpected Disconnect before recording this interval.
    automatic_support::set_preferences(
        &mut broker,
        automatic_support::preferences(crate::preferences::ProbeInterval::THIRTY, false, false),
    );
    until(|| {
        broker.poll();
        automatic_support::intervals(&peer)
            .iter()
            .any(|v| v["type"] == "set_probe_interval" && v["interval"] == 30)
    });
    let connects = automatic_support::command_count(&peer, "connect");
    let disconnects = automatic_support::command_count(&peer, "disconnect");
    let actual_generation = broker.connections["one"].generation;
    let count = loads.load(Ordering::Relaxed);
    eprintln!(
        "EXPLICIT_CONNECT returned={:?} connects={connects} disconnects={disconnects} loads={count} generation={actual_generation}",
        result.vpns[0].state
    );
    let root = peer.root().to_path_buf();
    drop(broker);
    until(|| peer.cleaned());
    drop(peer);
    assert!(!root.exists());
    assert_eq!(
        disconnects, 0,
        "explicit Connect must never disconnect an active tunnel"
    );
    assert_eq!(connects, 1);
    assert_eq!(count, 1);
    assert_eq!(actual_generation, generation);
    assert_eq!(result.vpns[0].state, State::Connected);
}

#[test]
fn explicit_disconnect_direct_broker_cancels_queued_auto_without_secret_load() {
    use automatic_support as auto;
    let mut peer = Peer::new("flow");
    let (secrets, calls, _) = auto::RecordingSecrets::new();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    auto::set_preferences(
        &mut broker,
        auto::preferences(crate::preferences::ProbeInterval::TEN, false, true),
    );
    auto::connect(&mut broker, &peer, "one");
    for failures in 1..=3 {
        auto::probe(&mut broker, "one", failures);
    }
    assert!(broker.automatic.iter().any(|a| matches!(a,
        automatic::Action::Reconnect { id, .. } if id == "one")));
    let result = broker
        .dispatch(
            Command::Disconnect { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(result.vpns[0].state, State::Disconnecting);
    assert!(!broker.automatic.iter().any(|a| matches!(a,
        automatic::Action::Reconnect { id, .. } if id == "one")));
    until(|| {
        broker.poll();
        let c = &broker.connections["one"];
        c.view.state == State::Off && c.pending.as_ref().is_some_and(|p| p.accepted)
    });
    broker.perform_automatic(|| true);
    assert_eq!(calls.recorded().len(), 1);
    assert_eq!(auto::command_count(&peer, "connect"), 1);
    assert_eq!(auto::command_count(&peer, "disconnect"), 1);
    let root = peer.root().to_path_buf();
    drop(broker);
    until(|| peer.cleaned());
    drop(peer);
    assert!(!root.exists());
}

#[test]
fn explicit_intent_unknown_and_expired_commands_do_not_load_credentials() {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    for command in [
        Command::Connect {
            id: "absent".into(),
        },
        Command::Disconnect {
            id: "absent".into(),
        },
    ] {
        assert_eq!(
            broker
                .dispatch(command, Instant::now() + Duration::from_secs(2))
                .err(),
            Some("not_found")
        );
    }
    for command in [
        Command::Connect { id: "one".into() },
        Command::Disconnect { id: "one".into() },
    ] {
        assert_eq!(
            broker.dispatch(command, Instant::now()).err(),
            Some("backend_unavailable")
        );
    }
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    assert_eq!(automatic_support::command_count(&peer, "connect"), 0);
    assert_eq!(automatic_support::command_count(&peer, "disconnect"), 0);
    let root = peer.root().to_path_buf();
    drop(broker);
    until(|| peer.cleaned());
    drop(peer);
    assert!(!root.exists());
}

#[test]
fn explicit_intent_after_helper_loss_neither_loads_nor_fakes_off() {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    std::fs::write(peer.marker.with_extension("close"), b"").unwrap();
    until(|| {
        broker.poll();
        broker.helper == "missing"
    });
    for command in [
        Command::Connect { id: "one".into() },
        Command::Disconnect { id: "one".into() },
    ] {
        assert_eq!(
            broker
                .dispatch(command, Instant::now() + Duration::from_secs(2))
                .err(),
            Some("backend_unavailable")
        );
    }
    assert_eq!(broker.connections["one"].view.state, State::HelperMissing);
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    assert_eq!(automatic_support::command_count(&peer, "connect"), 0);
    assert_eq!(automatic_support::command_count(&peer, "disconnect"), 0);
    let root = peer.root().to_path_buf();
    drop(broker);
    until(|| peer.cleaned());
    drop(peer);
    assert!(!root.exists());
}
