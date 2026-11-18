use super::*;

#[test]
fn newly_discovered_blocked_profile_requires_negotiated_capability() {
    let profile: crate::model::Profile = serde_json::from_value(serde_json::json!({"id":"one","name":"Fixture","kind":"ssl","gateway":"vpn.example.test","username":"fixture","networks":[],"port":443,"certificate":"","probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp"})).unwrap();
    for (id, expected) in [
        (protocol::CLEANUP_ACK_SNAPSHOT_ID, true),
        (protocol::CLEANUP_PROBE_SNAPSHOT_ID, false),
    ] {
        let mut broker = Broker::new(None, Secrets::new());
        broker.ready = true;
        broker.cleanup_probe = Some(BTreeMap::new());
        let result = broker.receive(Message::Snapshot {
            id: id.into(),
            protocol_version: protocol::VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
            build: None,
            profiles: vec![profile.clone()],
            connections: vec![protocol::TunnelStatus {
                id: "one".into(),
                generation: 0,
                state: State::CleanupUnconfirmed,
                failures: 0,
                cleaning: false,
                failure: None,
            }],
        });
        assert_eq!(result.is_ok(), expected);
        if expected {
            assert_eq!(
                broker.connections["one"].view.state,
                State::CleanupUnconfirmed
            );
        }
    }
}

#[test]
fn old_helper_echoes_probe_and_never_receives_verify_cleanup() {
    let mut peer = Peer::new("flow");
    let mut broker = Broker::new(Some(peer.take()), Secrets::new());
    let until = Instant::now() + Duration::from_secs(4);
    while !broker.ready || broker.cleanup_probe.is_some() {
        broker.poll();
        assert!(Instant::now() < until, "capability probe timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!broker.cleanup_capable);
    set_state(
        broker.connections.get_mut("one").unwrap(),
        State::CleanupUnconfirmed,
    );
    assert_eq!(
        broker
            .dispatch(
                Command::Probe { id: "one".into() },
                Instant::now() + Duration::from_secs(2)
            )
            .unwrap_err(),
        "unavailable"
    );
    let commands =
        std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap_or_default();
    assert!(!commands.lines().any(|line| line == "verify_cleanup"));
}

#[test]
fn busy_connect_after_capability_snapshot_requests_fresh_cleanup_state() {
    let mut peer = Peer::new("flow");
    let mut broker = Broker::new(Some(peer.take()), Secrets::new());
    let until = Instant::now() + Duration::from_secs(4);
    while !broker.ready || broker.cleanup_probe.is_some() {
        broker.poll();
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    broker.cleanup_capable = true;
    broker
        .dispatch(
            Command::Connect { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let id = broker.connections["one"]
        .pending
        .as_ref()
        .unwrap()
        .id
        .clone();
    broker
        .receive(Message::Failed {
            id,
            error: protocol::ErrorCode::ProfileBusy,
        })
        .unwrap();
    assert_eq!(broker.connections["one"].view.state, State::Off);
    assert!(
        broker.cleanup_probe.is_some(),
        "retry the state observation after the generation is rolled back"
    );
}

#[test]
fn previous_session_status_survives_busy_eof_and_clears_after_snapshot() {
    fn waiting() -> Message {
        Message::PreviousSessionFinishing {
            protocol_version: protocol::VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
    let mut broker = Broker::new(None, Secrets::new());
    broker.receive(waiting()).unwrap();
    assert_eq!(broker.helper, "previous_session_finishing");
    assert!(broker.startup > Instant::now() + Duration::from_secs(35));
    let deadline = broker.startup;
    broker.receive(waiting()).unwrap();
    assert_eq!(
        broker.startup, deadline,
        "repeat notices cannot extend the deadline"
    );
    broker.lost(false);
    assert_eq!(broker.helper, "previous_session_finishing");

    broker.dead = false;
    broker.receive(waiting()).unwrap();
    broker
        .receive(Message::Snapshot {
            id: protocol::WAIT_CAPABILITY_SNAPSHOT_ID.into(),
            protocol_version: protocol::VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
            build: None,
            profiles: vec![],
            connections: vec![],
        })
        .unwrap();
    assert!(broker.ready);
    assert!(!broker.waiting_previous);
    assert_eq!(broker.helper, "outdated");
    assert!(broker.receive(waiting()).is_err());
    broker.lost(false);
    assert_eq!(broker.helper, "missing");
}

#[test]
fn runtime_restarts_only_after_its_child_exits_and_never_replays_a_connection() {
    let mut first = Peer::new("restart");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(first.take()), secrets);
    let attempts = Arc::new(AtomicUsize::new(0));
    let calls = attempts.clone();
    let (send, receive) = std::sync::mpsc::channel();
    broker.retry = Some(retry::Retry::fixture(move || {
        calls.fetch_add(1, Ordering::Relaxed);
        let mut peer = Peer::new("flow");
        let client = peer.take();
        send.send(peer).unwrap();
        Ok(client)
    }));
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    first.advance();
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    std::fs::write(first.marker.with_extension("fault"), b"").unwrap();
    wait(&mut broker, |s| s.helper == "missing");
    let pending_until = Instant::now() + Duration::from_millis(100);
    while Instant::now() < pending_until {
        let s = broker.snapshot();
        assert!(s.vpns.iter().all(|v| v.state == State::HelperMissing));
        assert_eq!(attempts.load(Ordering::Relaxed), 0, "cleanup still pending");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(first.marker.with_extension("allow_cleanup"), b"").unwrap();
    wait(&mut broker, |s| s.helper == "installed");
    let second = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(first.cleaned());
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    assert_eq!(
        loads.load(Ordering::Relaxed),
        1,
        "no automatic secret reload"
    );
    assert_eq!(
        std::fs::read_to_string(second.marker.with_extension("commands")).unwrap(),
        "snapshot\n",
        "fresh channel must not replay credentials or connect"
    );
    assert!(broker.snapshot().vpns.iter().all(|v| v.state == State::Off));
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    second.advance();
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    assert_eq!(loads.load(Ordering::Relaxed), 2);
    dispatch(&mut broker, Command::Quit {});
    let until = Instant::now() + Duration::from_millis(400);
    while Instant::now() < until {
        assert_eq!(broker.snapshot().helper, "missing");
        assert_eq!(attempts.load(Ordering::Relaxed), 1, "quit cannot relaunch");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(second.cleaned());
    drop(broker);
    drop(second);
}

#[test]
fn runtime_recovery_revalidates_every_snapshot_and_backs_off_on_unavailable_launchers() {
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let calls = attempts.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let retry = retry::Retry::fixture(move || {
        let call = calls.fetch_add(1, Ordering::Relaxed);
        if call < 2 {
            return Err(Error::Unavailable);
        }
        let mut peer = Peer::new(if call == 2 { "version" } else { "flow" });
        let client = peer.take();
        send.send(peer).unwrap();
        Ok(client)
    });
    let mut broker = Broker::reconnecting(retry, secrets);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    for _ in 0..100 {
        assert_eq!(broker.snapshot().helper, "missing");
    }
    assert_eq!(attempts.load(Ordering::Relaxed), 1, "retry must be paced");
    wait(&mut broker, |s| s.helper == "outdated");
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    assert!(broker.snapshot().vpns.is_empty());
    assert!(
        broker
            .dispatch(
                Command::Toggle { id: "one".into() },
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
    );
    let incompatible = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    wait(&mut broker, |s| s.helper == "installed");
    let compatible = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(incompatible.cleaned());
    assert_eq!(attempts.load(Ordering::Relaxed), 4);
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    assert_eq!(
        std::fs::read_to_string(compatible.marker.with_extension("commands")).unwrap(),
        "snapshot\n"
    );
    drop(broker);
    drop(compatible);
}

#[test]
fn notice_then_eof_preserves_only_the_terminal_wait_cause() {
    use std::process::Command as Process;
    for (suffix, expected) in [
        ("", "previous_session_finishing"),
        ("b'{broken}\\n'", "missing"),
        ("snapshot", "missing"),
    ] {
        let script = format!(
            r#"import socket,json
s=socket.socket(fileno=0)
data=b''
while not data.endswith(b'\n'):
    part=s.recv(4096)
    if not part: break
    data+=part
s.sendall((json.dumps(dict(type='previous_session_finishing',protocol_version=3,version='{}'))+'\n').encode())
{}
s.shutdown(socket.SHUT_WR)
s.close()
"#,
            env!("CARGO_PKG_VERSION"),
            if suffix.is_empty() {
                String::new()
            } else if suffix == "snapshot" {
                format!(
                    "s.sendall((json.dumps(dict(type='snapshot',id='{}',protocol_version=3,version='{}',profiles=[],connections=[]))+'\\n').encode())",
                    protocol::WAIT_CAPABILITY_SNAPSHOT_ID,
                    env!("CARGO_PKG_VERSION")
                )
            } else {
                format!("s.sendall({suffix})")
            }
        );
        let mut command = Process::new("/usr/bin/python3");
        command.args(["-c", &script]);
        let client = Client::fixture(command).unwrap();
        let mut broker = Broker::new(Some(client), Secrets::new());
        let until = Instant::now() + Duration::from_secs(3);
        while !broker.client.as_ref().unwrap().finished() {
            assert!(Instant::now() < until, "fixture child did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.helper, expected);
        assert!(snapshot.vpns.is_empty());
        assert!(!broker.ready);
    }
}

#[test]
fn terminal_notice_after_ready_does_not_reclassify_a_lost_live_session() {
    let script = format!(
        r#"import socket,json
s=socket.socket(fileno=0)
def read():
    data=b''
    while not data.endswith(b'\n'):
        part=s.recv(4096)
        if not part: return None
        data+=part
    return json.loads(data)
r=read()
s.sendall((json.dumps(dict(type='snapshot',id=r['id'],protocol_version=3,version='{}',build='a'*64,profiles=[],connections=[]))+'\n').encode())
read()
s.sendall((json.dumps(dict(type='previous_session_finishing',protocol_version=3,version='{}'))+'\n').encode())
s.shutdown(socket.SHUT_WR)
s.close()
"#,
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION")
    );
    let mut command = std::process::Command::new("/usr/bin/python3");
    command.args(["-c", &script]);
    let mut broker = Broker::new(Some(Client::fixture(command).unwrap()), Secrets::new());
    wait(&mut broker, |snapshot| snapshot.helper == "installed");
    assert!(broker.ready);
    broker
        .client
        .as_ref()
        .unwrap()
        .send(Request {
            id: "wake".into(),
            command: protocol::Command::Snapshot {},
        })
        .unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while !broker.client.as_ref().unwrap().finished() {
        assert!(Instant::now() < until, "fixture child did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(broker.snapshot().helper, "missing");
    assert!(!broker.ready);
}

#[test]
fn cleanup_verification_snapshot_tracks_correlation_failure_and_channel_loss() {
    let profiles: Vec<crate::model::Profile> = ["one", "two"].into_iter().map(|id| {
        serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fixture","networks":[],"port":443,"certificate":"","probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp"})).unwrap()
    }).collect();
    let (send_request, requests) = std::sync::mpsc::sync_channel(32);
    let (send_reply, replies) = std::sync::mpsc::sync_channel(64);
    let client = Client::fixture_channels(send_request, replies);
    let mut broker = Broker::new(Some(client), Secrets::new());
    let initial = requests.recv().unwrap();
    let response = |id: String, blocked: bool| Message::Snapshot {
        id,
        protocol_version: protocol::VERSION,
        version: env!("CARGO_PKG_VERSION").into(),
        build: None,
        profiles: profiles.clone(),
        connections: profiles
            .iter()
            .map(|profile| protocol::TunnelStatus {
                id: profile.id.clone(),
                generation: 0,
                state: if blocked && profile.id == "one" {
                    State::CleanupUnconfirmed
                } else {
                    State::Off
                },
                failures: 0,
                cleaning: false,
                failure: None,
            })
            .collect(),
    };
    send_reply.send(response(initial.id, false)).unwrap();
    broker.poll();
    let capability = requests.recv().unwrap();
    assert_eq!(capability.id, protocol::CLEANUP_PROBE_SNAPSHOT_ID);
    // The failure-note probe follows; this helper predates it and echoes it.
    let notes = requests.recv().unwrap();
    assert_eq!(notes.id, protocol::FAILURE_NOTE_PROBE_SNAPSHOT_ID);
    send_reply
        .send(response(protocol::CLEANUP_ACK_SNAPSHOT_ID.into(), true))
        .unwrap();
    send_reply.send(response(notes.id, true)).unwrap();
    broker.poll();
    assert!(broker.cleanup_capable);
    assert!(!broker.failure_capable);
    let started = broker
        .dispatch(
            Command::Probe { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    let verify = requests.recv().unwrap();
    assert!(
        matches!(verify.command, protocol::Command::VerifyCleanup { ref profile } if profile == "one")
    );
    assert!(
        started
            .vpns
            .iter()
            .find(|v| v.profile.id == "one")
            .unwrap()
            .cleanup_verifying
    );
    assert!(
        !started
            .vpns
            .iter()
            .find(|v| v.profile.id == "two")
            .unwrap()
            .cleanup_verifying
    );
    let json = serde_json::to_value(&started).unwrap();
    assert_eq!(json["vpns"][0]["cleanupVerifying"], true);
    assert!(json["vpns"][0].get("cleanup_verifying").is_none());
    send_reply
        .send(Message::Accepted {
            id: "unrelated".into(),
        })
        .unwrap();
    assert!(broker.snapshot().vpns[0].cleanup_verifying);
    send_reply.send(response(verify.id, true)).unwrap();
    let completed = broker.snapshot();
    assert_eq!(completed.vpns[0].state, State::CleanupUnconfirmed);
    assert!(!completed.vpns[0].cleanup_verifying);
    let started = broker
        .dispatch(
            Command::Probe { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    assert!(started.vpns[0].cleanup_verifying);
    let verify = requests.recv().unwrap();
    send_reply
        .send(Message::Failed {
            id: verify.id,
            error: protocol::ErrorCode::Unavailable,
        })
        .unwrap();
    assert!(!broker.snapshot().vpns[0].cleanup_verifying);
    assert_eq!(broker.snapshot().vpns[0].state, State::CleanupUnconfirmed);
    // Replace the channel fixture with an owned real child that closes its
    // transport while the verification is pending.
    let mut command = std::process::Command::new("/usr/bin/python3");
    command.args(["-c", "import time; time.sleep(0.5)"]);
    let client = Client::fixture(command).unwrap();
    let finished = client.fixture_finished();
    broker.client = Some(client);
    let started = broker
        .dispatch(
            Command::Probe { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    assert!(started.vpns[0].cleanup_verifying);
    let deadline = Instant::now() + Duration::from_secs(5);
    let lost = loop {
        let snapshot = broker.snapshot();
        if snapshot.helper == "missing" {
            break snapshot;
        }
        assert!(Instant::now() < deadline, "helper channel did not close");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(lost.helper, "missing");
    assert!(lost.vpns.iter().all(|v| !v.cleanup_verifying));
    while !finished() {
        assert!(Instant::now() < deadline, "fixture child did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}
