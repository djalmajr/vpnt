//! The helper's failure note, from the negotiated wire messages to the card and
//! the log entry the UI reads (`ui/src/model.ts`, `FailureView`).
use super::*;
use crate::helper::protocol::{
    ErrorCode, FAILURE_NOTE_ACK_SNAPSHOT_ID, FAILURE_NOTE_PROBE_SNAPSHOT_ID, FailureNote, Step,
    TunnelStatus,
};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

fn profile() -> crate::model::Profile {
    serde_json::from_value(serde_json::json!({"id":"one","name":"Example","kind":"ssl","gateway":"vpn.example.com","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
}
fn reply(id: &str, generation: u64, state: State, failure: Option<FailureNote>) -> Message {
    Message::Snapshot {
        id: id.into(),
        protocol_version: protocol::VERSION,
        version: env!("CARGO_PKG_VERSION").into(),
        build: None,
        profiles: vec![profile()],
        connections: vec![TunnelStatus {
            id: "one".into(),
            generation,
            state,
            failures: 0,
            cleaning: false,
            failure,
        }],
    }
}
fn changed(generation: u64, state: State, cleaning: bool, failure: Option<FailureNote>) -> Message {
    Message::Changed {
        profile_id: "one".into(),
        generation,
        state,
        failures: 0,
        cleaning,
        failure,
    }
}
fn note(step: Step) -> FailureNote {
    FailureNote {
        code: ErrorCode::BackendFailure,
        step,
    }
}

struct Wire {
    broker: Broker<Secrets>,
    requests: Receiver<Request>,
    replies: SyncSender<Message>,
}
impl Wire {
    /// Startup handshake; `ack` is whether the helper knows the note probe.
    fn new(ack: bool) -> Self {
        let (send_request, requests) = sync_channel(32);
        let (replies, receive) = sync_channel(64);
        let mut broker = Broker::new(
            Some(crate::helper::client::Client::fixture_channels(
                send_request,
                receive,
            )),
            Secrets::new(),
        );
        let initial = requests.recv().unwrap();
        replies
            .send(reply(&initial.id, 0, State::Off, None))
            .unwrap();
        broker.poll();
        let cleanup = requests.recv().unwrap();
        assert_eq!(cleanup.id, protocol::CLEANUP_PROBE_SNAPSHOT_ID);
        let probe = requests.recv().unwrap();
        assert_eq!(probe.id, FAILURE_NOTE_PROBE_SNAPSHOT_ID);
        assert!(matches!(probe.command, protocol::Command::Snapshot {}));
        replies
            .send(reply(&cleanup.id, 0, State::Off, None))
            .unwrap();
        // An older helper echoes the probe ID; a current one answers the ack.
        let answer = if ack {
            FAILURE_NOTE_ACK_SNAPSHOT_ID
        } else {
            FAILURE_NOTE_PROBE_SNAPSHOT_ID
        };
        replies.send(reply(answer, 0, State::Off, None)).unwrap();
        broker.poll();
        assert!(broker.ready);
        assert!(broker.failure_probe.is_none());
        assert_eq!(broker.failure_capable, ack);
        Self {
            broker,
            requests,
            replies,
        }
    }
    /// Connect through the UI command and let the helper accept it.
    fn connect(&mut self) -> u64 {
        self.broker
            .dispatch(
                Command::Connect { id: "one".into() },
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        let request = self.requests.recv().unwrap();
        let protocol::Command::Connect { generation, .. } = request.command else {
            panic!("connect expected");
        };
        self.replies
            .send(Message::Accepted { id: request.id })
            .unwrap();
        self.replies
            .send(changed(generation, State::Connecting, false, None))
            .unwrap();
        self.broker.poll();
        generation
    }
    fn send(&mut self, message: Message) {
        self.replies.send(message).unwrap();
        self.broker.poll();
    }
}

#[test]
fn a_negotiated_note_reaches_the_card_and_the_failure_log_entry_as_the_ui_reads_it() {
    let mut wire = Wire::new(true);
    let generation = wire.connect();
    wire.send(changed(
        generation,
        State::Dropped,
        true,
        Some(note(Step::Routes)),
    ));
    wire.send(changed(
        generation,
        State::Dropped,
        false,
        Some(note(Step::Routes)),
    ));
    assert!(!wire.broker.dead, "a negotiated note is a valid message");
    let snapshot = wire.broker.snapshot();
    let view = &snapshot.vpns[0];
    let expected = Some(FailureView {
        code: ErrorCode::BackendFailure,
        step: Step::Routes,
    });
    assert_eq!(view.state, State::Dropped);
    assert_eq!(view.failure, expected);
    // One entry for the transition; the cleanup end does not add another.
    let dropped: Vec<_> = view
        .log
        .iter()
        .filter(|entry| entry.state == State::Dropped)
        .collect();
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].failure, expected);
    assert!(
        view.log
            .iter()
            .filter(|entry| entry.state != State::Dropped)
            .all(|entry| entry.failure.is_none())
    );
    let json = serde_json::to_value(&snapshot).unwrap();
    let ui = serde_json::json!({"code":"backend_failure","step":"routes"});
    assert_eq!(json["vpns"][0]["failure"], ui);
    let log = json["vpns"][0]["log"].as_array().unwrap();
    assert_eq!(log.last().unwrap()["failure"], ui);
    assert_eq!(log.last().unwrap()["state"], "dropped");
    assert!(
        log[..log.len() - 1]
            .iter()
            .all(|e| e.get("failure").is_none())
    );

    // A fresh probe snapshot carries the note in `TunnelStatus` too.
    wire.broker.request_failure_snapshot();
    let probe = wire.requests.recv().unwrap();
    assert_eq!(probe.id, FAILURE_NOTE_PROBE_SNAPSHOT_ID);
    wire.send(reply(
        FAILURE_NOTE_ACK_SNAPSHOT_ID,
        generation,
        State::Dropped,
        Some(note(Step::Dns)),
    ));
    assert_eq!(
        wire.broker.snapshot().vpns[0].failure.map(|f| f.step),
        Some(Step::Dns)
    );

    // A new attempt clears the note at once, before the helper answers.
    let next = wire.connect();
    assert!(next > generation);
    let snapshot = wire.broker.snapshot();
    assert_eq!(snapshot.vpns[0].state, State::Connecting);
    assert_eq!(snapshot.vpns[0].failure, None);
    assert_eq!(snapshot.vpns[0].log.last().unwrap().failure, None);
    let json = serde_json::to_value(&snapshot).unwrap();
    assert!(json["vpns"][0].get("failure").is_none());
}

#[test]
fn a_note_from_a_helper_that_did_not_acknowledge_the_probe_is_refused() {
    // An older helper never sends the field; its messages stay valid.
    let mut wire = Wire::new(false);
    let generation = wire.connect();
    wire.send(changed(generation, State::Dropped, false, None));
    assert!(!wire.broker.dead);
    assert_eq!(wire.broker.snapshot().vpns[0].state, State::Dropped);
    assert_eq!(wire.broker.snapshot().vpns[0].failure, None);
    // A note that was never negotiated is a contract violation.
    assert!(
        wire.broker
            .receive(changed(
                generation,
                State::Dropped,
                false,
                Some(note(Step::Routes))
            ))
            .is_err()
    );
    wire.broker.request_failure_snapshot();
    let probe = wire.requests.recv().unwrap();
    assert!(
        wire.broker
            .receive(reply(
                &probe.id,
                generation,
                State::Dropped,
                Some(note(Step::Routes))
            ))
            .is_err()
    );
    // Nor before the probe at all: the startup snapshot may not carry one.
    for (failure, accepted) in [(Some(note(Step::Profile)), false), (None, true)] {
        let mut broker = Broker::new(None, Secrets::new());
        let result = broker.receive(reply(
            protocol::WAIT_CAPABILITY_SNAPSHOT_ID,
            0,
            State::Off,
            failure,
        ));
        assert_eq!(result.is_ok(), accepted);
    }
}

#[test]
fn a_rejected_attempt_restores_the_previous_note() {
    let mut wire = Wire::new(true);
    let generation = wire.connect();
    wire.send(changed(
        generation,
        State::Dropped,
        false,
        Some(note(Step::Egress)),
    ));
    wire.broker
        .dispatch(
            Command::Connect { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(wire.broker.snapshot().vpns[0].failure, None);
    let request = wire.requests.recv().unwrap();
    wire.send(Message::Failed {
        id: request.id,
        error: ErrorCode::InvalidSecret,
    });
    let view = &wire.broker.snapshot().vpns[0];
    assert_eq!(view.state, State::Dropped);
    assert_eq!(view.failure.map(|f| f.step), Some(Step::Egress));
}

#[test]
fn losing_the_helper_forgets_the_capability_and_the_note() {
    let mut wire = Wire::new(true);
    let generation = wire.connect();
    wire.send(changed(
        generation,
        State::Dropped,
        false,
        Some(note(Step::Tunnel)),
    ));
    wire.broker.lost(false);
    assert!(!wire.broker.failure_capable);
    assert!(wire.broker.failure_probe.is_none());
    let view = &wire.broker.connections["one"].view;
    assert_eq!(view.state, State::HelperMissing);
    assert_eq!(view.failure, None);
}

#[test]
fn sign_request_is_dropped_without_a_reply_or_a_credential_load() {
    let mut wire = Wire::new(false);
    assert!(wire.broker.ready);
    let frame = b"{\"type\":\"sign_request\",\"id\":1,\"profile\":\"one\",\"generation\":1,\"epoch\":1,\"op\":{\"op\":\"certificate\"}}\n";
    let message = protocol::read_message(&mut &frame[..]).unwrap().unwrap();
    wire.replies.send(message).unwrap();
    wire.broker.poll();
    assert!(!wire.broker.ready);
    assert!(wire.broker.dead);
    assert!(
        wire.broker
            .connections
            .values()
            .all(|c| c.view.state == State::HelperMissing)
    );
    assert_eq!(wire.broker.secrets.loads.load(Ordering::Relaxed), 0);
    assert!(wire.requests.try_recv().is_err());
}
