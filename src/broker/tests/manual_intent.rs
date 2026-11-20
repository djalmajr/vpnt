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

// Synchronization guard, not a latency requirement: a 3 s pause anywhere in
// the fixture must pass, and a stalled stage still names itself.
fn until(stage: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready() {
        assert!(Instant::now() < deadline, "{stage} barrier timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}

// Synchronization guards, not latency requirements: allow a 3 s pause plus
// peer startup and scheduling, while still failing a stalled stage.
fn stale_until(
    broker: &mut Broker<Secrets>,
    peer: &Peer,
    stage: &str,
    mut ready: impl FnMut(&mut Broker<Secrets>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ready(broker) {
            return;
        }
        let c = broker.connections.get("one");
        assert!(
            Instant::now() < deadline,
            "{stage} timed out: pending={}, accepted={:?}, state={:?}, generation={:?}, stale.sent={}",
            c.is_some_and(|c| c.pending.is_some()),
            c.and_then(|c| c.pending.as_ref().map(|p| p.accepted)),
            c.map(|c| c.view.state),
            c.map(|c| c.generation),
            peer.marker.with_extension("stale.sent").exists(),
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn stale_dispatch(broker: &mut Broker<Secrets>, command: Command) -> Snapshot {
    broker
        .dispatch(command, Instant::now() + Duration::from_secs(15))
        .unwrap()
}

fn stale_stop(rendered: State, prior_stop: bool) {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    // `broker_with` waits for the fixture's read loop before arming the
    // broker's own startup deadline.
    let mut broker = broker_with(&mut peer, secrets);
    stale_until(&mut broker, &peer, "helper setup", |b| {
        b.snapshot().helper == "installed"
    });
    stale_dispatch(&mut broker, Command::Toggle { id: "one".into() });
    stale_until(&mut broker, &peer, "connecting setup", |broker| {
        broker.poll();
        broker.connections["one"]
            .pending
            .as_ref()
            .is_some_and(|p| p.accepted)
            && broker.connections["one"].view.state == State::Connecting
    });
    if rendered == State::Connected {
        peer.advance();
        stale_until(&mut broker, &peer, "connected setup", |b| {
            b.snapshot().vpns[0].state == State::Connected
        });
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
        stale_dispatch(&mut broker, Command::Toggle { id: "one".into() });
        generation += 1;
    } else {
        // Existing marker sends a current-generation frame on the real stream.
        // This proves protocol consumption, not spontaneous native Off provenance.
        write_stale(
            &peer,
            serde_json::to_vec(&serde_json::json!({
                "id": "one", "generation": generation, "state": "off", "failures": 0
            }))
            .unwrap(),
        );
    }
    stale_until(&mut broker, &peer, "stale stop receipt", |broker| {
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
    let result = stale_dispatch(
        &mut broker,
        Command::Disconnect {
            id: caller_snapshot.vpns[0].profile.id.clone(),
        },
    );
    stale_until(&mut broker, &peer, "explicit stop receipt", |broker| {
        broker.poll();
        let c = &broker.connections["one"];
        c.generation == generation + 1 && c.pending.as_ref().is_some_and(|p| p.accepted)
    });
    let commands = std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap();
    let connects = commands.lines().filter(|c| *c == "connect").count();
    let disconnects = commands.lines().filter(|c| *c == "disconnect").count();
    let load_count = loads.load(Ordering::Relaxed);
    if connects == 1 {
        stale_until(&mut broker, &peer, "explicit stop off", |broker| {
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
    until("fixture cleanup", || peer.cleaned());
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
    let mut broker = broker_with(&mut peer, secrets);
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
    until("set_probe_interval receipt", || {
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
    until("fixture cleanup", || peer.cleaned());
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
    let mut broker = broker_with(&mut peer, secrets);
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
    until("explicit disconnect receipt", || {
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
    until("fixture cleanup", || peer.cleaned());
    drop(peer);
    assert!(!root.exists());
}

#[test]
fn explicit_intent_unknown_and_expired_commands_do_not_load_credentials() {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = broker_with(&mut peer, secrets);
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
    until("fixture cleanup", || peer.cleaned());
    drop(peer);
    assert!(!root.exists());
}

#[test]
fn explicit_intent_after_helper_loss_neither_loads_nor_fakes_off() {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = broker_with(&mut peer, secrets);
    wait(&mut broker, |s| s.helper == "installed");
    std::fs::write(peer.marker.with_extension("close"), b"").unwrap();
    until("helper loss", || {
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
    until("fixture cleanup", || peer.cleaned());
    drop(peer);
    assert!(!root.exists());
}
