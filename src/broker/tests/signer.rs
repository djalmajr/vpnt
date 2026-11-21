use super::*;
use crate::broker::signer::AppSigner;
use crate::{
    connection::ovpn::{
        session::SignError,
        signing::{Hash, Padding},
    },
    helper::protocol::{
        ErrorCode, PssHashName, PssOperation, PssPaddingName, SignDataBytes, SignFields,
        SignOperation, SignOperationName, TunnelStatus,
    },
};
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::AtomicBool,
        mpsc::{self, Receiver, Sender, SyncSender, TryRecvError},
    },
    thread,
};

const BUDGET: Duration = Duration::from_secs(15);
const EPOCH: u64 = 73;

#[derive(Debug, Eq, PartialEq)]
enum Event {
    Open(String, String),
    Certificate,
    Sign,
    Close,
}

#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);
impl Gate {
    fn wait(&self) {
        let (lock, condition) = &*self.0;
        let (open, _) = condition
            .wait_timeout_while(lock.lock().unwrap(), BUDGET, |open| !*open)
            .unwrap();
        assert!(*open, "the fixture did not release the signer");
    }

    fn release(&self) {
        let (lock, condition) = &*self.0;
        *lock.lock().unwrap() = true;
        condition.notify_all();
    }
}

struct Fake {
    events: Sender<Event>,
    gate: Option<Gate>,
    error: Option<SignError>,
}
impl AppSigner for Fake {
    fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
        self.events.send(Event::Certificate).unwrap();
        Ok(vec![48, 42])
    }

    fn sign(
        &mut self,
        padding: Padding,
        data: &[u8],
        _: &AtomicBool,
        _: Instant,
    ) -> Result<Option<Vec<u8>>, SignError> {
        self.events.send(Event::Sign).unwrap();
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        assert_eq!(padding, Padding::Pss(Hash::Sha256));
        if data != [0; 32] {
            return Err(SignError::Unavailable);
        }
        self.error.map_or_else(|| Ok(Some(vec![42, 48])), Err)
    }
}
impl Drop for Fake {
    fn drop(&mut self) {
        let _ = self.events.send(Event::Close);
    }
}

struct Wire {
    broker: Broker<Secrets>,
    requests: Receiver<Request>,
    messages: SyncSender<Message>,
    events: Receiver<Event>,
    gate: Option<Gate>,
}
impl Drop for Wire {
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            gate.release();
        }
    }
}

impl Wire {
    fn new(
        gate: Option<Gate>,
        open_error: Option<SignError>,
        sign_error: Option<SignError>,
    ) -> Self {
        let (send_request, requests) = mpsc::sync_channel(32);
        let (messages, receive) = mpsc::sync_channel(64);
        let (send_event, events) = mpsc::channel();
        let mut broker = Broker::new(
            Some(Client::fixture_channels(send_request, receive)),
            Secrets::new(),
        );
        let fake_gate = gate.clone();
        broker.signing.open = Arc::new(move |settings, _, _| {
            send_event
                .send(Event::Open(
                    settings.module.clone(),
                    settings.certificate_id.clone(),
                ))
                .unwrap();
            if let Some(error) = open_error {
                return Err(error);
            }
            Ok(Some(Box::new(Fake {
                events: send_event.clone(),
                gate: fake_gate.clone(),
                error: sign_error,
            })))
        });
        let wire = Self {
            broker,
            requests,
            messages,
            events,
            gate,
        };
        wire.start()
    }

    fn start(mut self) -> Self {
        let profiles = vec![
            profile("one", "ovpn", "/fixture/one.dylib", "01"),
            profile("two", "ovpn", "/fixture/two.dylib", "02"),
            profile("ssl", "ssl", "", ""),
        ];
        let snapshot = |id: String| Message::Snapshot {
            id,
            protocol_version: protocol::VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
            build: None,
            connections: profiles
                .iter()
                .map(|profile| TunnelStatus {
                    id: profile.id.clone(),
                    generation: 0,
                    state: State::Off,
                    failures: 0,
                    cleaning: false,
                    failure: None,
                })
                .collect(),
            profiles: profiles.clone(),
        };
        let probe = self.request();
        self.send(snapshot(probe.id));
        for _ in 0..2 {
            self.messages.send(snapshot(self.request().id)).unwrap();
        }
        self.broker.poll();
        assert!(self.broker.ready);
        self
    }

    // Arrange signer tests at the command transport boundary, including states
    // that a normal Connect or Reconnect does not set immediately.
    fn submit_connect(&mut self, profile: &str, state: State) -> String {
        let generation = self.broker.connections[profile].generation + 1;
        let starting = if state == State::AwaitingApproval {
            State::Connecting
        } else {
            state
        };
        self.broker
            .submit(
                profile,
                generation,
                protocol::Command::Connect {
                    id: profile.into(),
                    generation,
                    credentials: Credentials {
                        password: "".into(),
                        psk: "".into(),
                    },
                    interval: self.broker.preferences.interval,
                },
                Some(starting),
            )
            .unwrap();
        let request = self.request();
        assert!(
            matches!(request.command, protocol::Command::Connect { id, generation: sent, .. } if id == profile && sent == generation)
        );
        if state == State::AwaitingApproval {
            self.messages
                .send(Message::Changed {
                    profile_id: profile.into(),
                    generation,
                    state,
                    failures: 0,
                    cleaning: false,
                    failure: None,
                })
                .unwrap();
        }
        request.id
    }

    fn accept(&mut self, profile: &str, state: State) -> u64 {
        let id = self.submit_connect(profile, state);
        self.send(Message::Accepted { id });
        self.broker.connections[profile].generation
    }

    fn request(&self) -> Request {
        self.requests.recv_timeout(BUDGET).unwrap()
    }

    fn event(&self, expected: Event) {
        assert_eq!(self.events.recv_timeout(BUDGET).unwrap(), expected);
    }

    fn send(&mut self, message: Message) {
        self.messages.send(message).unwrap();
        self.broker.poll();
    }

    fn change_state(&mut self, profile: &str, generation: u64, state: State) {
        self.send(Message::Changed {
            profile_id: profile.into(),
            generation,
            state,
            failures: 0,
            cleaning: false,
            failure: None,
        });
    }

    fn sign(&mut self, id: u64, profile: &str, generation: u64, op: serde_json::Value) {
        let frame = serde_json::json!({
            "type": "sign_request", "id": id, "profile": profile,
            "generation": generation, "epoch": EPOCH, "op": op,
        })
        .to_string()
            + "\n";
        let message = protocol::read_message(&mut frame.as_bytes())
            .unwrap()
            .unwrap();
        self.send(message);
    }

    fn reply(&mut self, id: u64, profile: &str, generation: u64) -> serde_json::Value {
        let until = Instant::now() + BUDGET;
        let request = loop {
            self.broker.poll();
            match self.requests.try_recv() {
                Ok(request) => break request,
                Err(TryRecvError::Empty) => {
                    assert!(Instant::now() < until, "missing SignReply for {id}");
                    thread::yield_now();
                }
                Err(TryRecvError::Disconnected) => panic!("transport closed"),
            }
        };
        Self::parse_reply(request, id, profile, generation)
    }

    fn immediate_reply(&self, id: u64, profile: &str, generation: u64) -> serde_json::Value {
        let request = self
            .requests
            .try_recv()
            .expect("expected an immediate SignReply");
        Self::parse_reply(request, id, profile, generation)
    }

    fn parse_reply(request: Request, id: u64, profile: &str, generation: u64) -> serde_json::Value {
        let bytes = serde_json::to_vec(&request).unwrap();
        let parsed = protocol::parse_request(&bytes).unwrap();
        let protocol::Command::SignReply {
            id: reply_id,
            profile: reply_profile,
            generation: reply_generation,
            epoch,
            result,
        } = parsed.command
        else {
            panic!("SignReply expected");
        };
        assert_eq!(
            (reply_id, reply_profile.as_str(), reply_generation, epoch),
            (id, profile, generation, EPOCH)
        );
        serde_json::to_value(result).unwrap()
    }

    fn assert_no_reply(&mut self) {
        self.broker.poll();
        assert!(matches!(
            self.requests.try_recv(),
            Err(TryRecvError::Empty | TryRecvError::Disconnected)
        ));
    }
}

fn profile(id: &str, kind: &str, module: &str, certificate: &str) -> crate::model::Profile {
    let mut value = serde_json::json!({
        "id": id, "name": id, "kind": kind, "gateway":"vpn.example.com",
        "username":if kind == "ovpn" { "" } else { "fictional" }, "networks":[], "port":443, "certificate":"",
        "probeHost":"10.20.0.15", "probePort":8443, "probeMethod":"tcp",
    });
    if kind == "ovpn" {
        value["ovpn"] = serde_json::json!({"module":module, "certificateId":certificate});
    }
    serde_json::from_value(value).unwrap()
}

fn certificate() -> serde_json::Value {
    serde_json::json!({"op":"certificate"})
}

fn signature() -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::STANDARD};
    serde_json::json!({"op":"sign", "padding":"pss", "hash":"sha256", "data":STANDARD.encode([0; 32])})
}

fn error(name: &str) -> serde_json::Value {
    serde_json::json!({"error":name})
}

// The closable MissingProgram warning exists only on macOS (`broker/mod.rs`).
#[cfg(target_os = "macos")]
#[test]
fn ovpn_component_missing_program_sets_the_card_state() {
    let mut wire = Wire::new(None, None, None);
    let before = wire.broker.connections["one"].generation;
    wire.broker
        .dispatch(
            Command::Connect { id: "one".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    assert_eq!(wire.broker.connections["one"].view.state, State::Connecting);
    let request = wire.request();
    assert!(
        matches!(request.command, protocol::Command::Connect { generation, .. } if generation == before + 1)
    );
    wire.send(Message::Failed {
        id: request.id,
        error: ErrorCode::MissingProgram,
    });
    assert!(wire.broker.connections["one"].pending.is_none());
    assert_eq!(wire.broker.connections["one"].generation, before);
    assert_eq!(
        wire.broker.connections["one"].view.state,
        State::MissingProgram
    );
}

#[cfg(target_os = "macos")]
#[test]
fn ovpn_reconnect_missing_program_sets_the_card_state() {
    let mut wire = Wire::new(None, None, None);
    let before = wire.accept("one", State::Connecting);
    wire.change_state("one", before, State::Connected);
    wire.broker
        .dispatch(
            Command::Reconnect { id: "one".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    assert_eq!(
        wire.broker.connections["one"].view.state,
        State::Reconnecting
    );
    let request = wire.request();
    assert!(matches!(
        request.command,
        protocol::Command::Connect { id, generation, .. } if id == "one" && generation == before + 1
    ));
    wire.send(Message::Failed {
        id: request.id,
        error: ErrorCode::MissingProgram,
    });
    let restored = &wire.broker.connections["one"];
    assert_eq!(restored.view.state, State::MissingProgram);
    assert_eq!(restored.generation, before);
}

// The contrast case for the macOS-only warning above.
#[cfg(target_os = "macos")]
#[test]
fn ssl_component_missing_program_restores_previous_state() {
    let mut wire = Wire::new(None, None, None);
    let before = wire.broker.connections["ssl"].generation;
    wire.broker
        .dispatch(
            Command::Connect { id: "ssl".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    let request = wire.request();
    assert!(matches!(
        request.command,
        protocol::Command::Connect { id, generation, .. } if id == "ssl" && generation == before + 1
    ));
    wire.send(Message::Failed {
        id: request.id,
        error: ErrorCode::MissingProgram,
    });
    let restored = &wire.broker.connections["ssl"];
    assert_eq!(restored.view.state, State::Off);
    assert_eq!(restored.generation, before);
    assert!(restored.pending.is_none());
}

#[test]
fn accepted_ovpn_connect_ignores_late_missing_program() {
    let mut wire = Wire::new(None, None, None);
    let request_id = wire.submit_connect("one", State::Connecting);
    wire.send(Message::Accepted {
        id: request_id.clone(),
    });
    let generation = wire.broker.connections["one"].generation;
    assert!(
        wire.broker.connections["one"]
            .pending
            .as_ref()
            .unwrap()
            .accepted
    );

    wire.send(Message::Failed {
        id: request_id,
        error: ErrorCode::MissingProgram,
    });
    assert_eq!(wire.broker.connections["one"].view.state, State::Connecting);
    assert_eq!(wire.broker.connections["one"].generation, generation);
}

#[test]
fn ovpn_disconnect_missing_program_restores_previous_state() {
    let mut wire = Wire::new(None, None, None);
    let before = wire.accept("one", State::Connecting);
    wire.change_state("one", before, State::Connected);
    wire.broker
        .dispatch(
            Command::Disconnect { id: "one".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    let request = wire.request();
    assert!(matches!(
        request.command,
        protocol::Command::Disconnect { id, generation } if id == "one" && generation == before + 1
    ));
    wire.send(Message::Failed {
        id: request.id,
        error: ErrorCode::MissingProgram,
    });
    let restored = &wire.broker.connections["one"];
    assert_eq!(restored.view.state, State::Connected);
    assert_eq!(restored.generation, before);
    assert!(restored.pending.is_none());
}

#[test]
fn ovpn_connect_sends_empty_credentials_and_registers_the_signer() {
    let mut wire = Wire::new(None, None, None);
    let before = wire.broker.connections["one"].generation;
    let loads = wire.broker.secrets.loads.clone();
    wire.broker
        .dispatch(
            Command::Connect { id: "one".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    assert_eq!(wire.broker.connections["one"].view.state, State::Connecting);
    let request = wire.request();
    let protocol::Command::Connect {
        id,
        generation,
        credentials,
        interval,
    } = request.command
    else {
        panic!("expected a Connect request");
    };
    assert_eq!(id, "one");
    assert_eq!(generation, before + 1);
    assert_eq!(generation, wire.broker.connections["one"].generation);
    assert!(credentials.password.expose().is_empty());
    assert!(credentials.psk.expose().is_empty());
    assert_eq!(interval, wire.broker.preferences.interval);
    assert_eq!(loads.load(Ordering::Relaxed), 0);

    wire.send(Message::Accepted { id: request.id });
    wire.sign(1, "one", generation, certificate());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Certificate);
}

#[test]
fn accepted_attempt_uses_its_own_profile_and_reuses_the_same_token() {
    let mut wire = Wire::new(None, None, None);
    wire.accept("one", State::Connecting);
    let generation = wire.accept("two", State::Reconnecting);
    wire.sign(1, "two", generation, certificate());
    assert_eq!(
        wire.reply(1, "two", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.sign(2, "two", generation, signature());
    assert_eq!(
        wire.reply(2, "two", generation),
        serde_json::json!({"signature":"KjA="})
    );
    wire.event(Event::Open("/fixture/two.dylib".into(), "02".into()));
    wire.event(Event::Certificate);
    wire.event(Event::Sign);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
    let events = std::mem::replace(&mut wire.events, mpsc::channel().1);
    drop(wire);
    assert_eq!(events.recv_timeout(BUDGET).unwrap(), Event::Close);
}

#[test]
fn refuses_unknown_non_ovpn_stale_and_unaccepted_attempts() {
    let mut wire = Wire::new(None, None, None);
    let ssl = wire.accept("ssl", State::Connecting);
    wire.accept("one", State::Connecting);
    let current = wire.accept("one", State::Connecting);
    let unaccepted = wire.submit_connect("two", State::Connecting);
    for (id, profile, generation) in [
        (1, "unknown", current),
        (2, "ssl", ssl),
        (3, "one", current - 1),
        (4, "one", current + 1),
        (5, "two", 1),
    ] {
        wire.sign(id, profile, generation, certificate());
        assert_eq!(wire.reply(id, profile, generation), error("unavailable"));
    }
    wire.send(Message::Accepted {
        id: "wrong-id".into(),
    });
    wire.sign(6, "two", 1, certificate());
    assert_eq!(wire.reply(6, "two", 1), error("unavailable"));
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
    wire.send(Message::Accepted { id: unaccepted });
    wire.sign(7, "two", 1, certificate());
    assert_eq!(
        wire.reply(7, "two", 1),
        serde_json::json!({"certificate":"MCo="})
    );
    assert_eq!(wire.broker.secrets.loads.load(Ordering::Relaxed), 0);
}

#[test]
fn renegotiation_reuses_the_token_after_the_connection_becomes_connected() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, signature());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"signature":"KjA="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);

    wire.change_state("one", generation, State::Connected);
    wire.sign(2, "one", generation, signature());
    assert_eq!(
        wire.reply(2, "one", generation),
        serde_json::json!({"signature":"KjA="})
    );
    wire.event(Event::Sign);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn verifying_and_unresponsive_attempts_can_sign() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    for (id, state) in [(1, State::Verifying), (2, State::Unresponsive)] {
        wire.change_state("one", generation, state);
        wire.sign(id, "one", generation, signature());
        assert_eq!(
            wire.reply(id, "one", generation),
            serde_json::json!({"signature":"KjA="}),
            "{state:?}"
        );
    }
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);
    wire.event(Event::Sign);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn disconnecting_dropped_and_other_inactive_states_refuse_without_opening_the_token() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    let inactive = [
        State::Disconnecting,
        State::Dropped,
        State::Off,
        State::CredentialsRejected,
        State::GatewayTimeout,
        State::MissingSecret,
        State::MissingProgram,
        State::Offline,
        State::HelperMissing,
        State::CleanupUnconfirmed,
    ];
    for (id, state) in (1..).zip(inactive) {
        wire.change_state("one", generation, state);
        wire.sign(id, "one", generation, signature());
        assert_eq!(
            wire.reply(id, "one", generation),
            error("unavailable"),
            "{state:?}"
        );
        assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[test]
fn disconnect_receipt_cannot_authorize_signing_even_with_active_progress() {
    let mut wire = Wire::new(None, None, None);
    wire.accept("one", State::Connecting);
    wire.broker
        .dispatch(
            Command::Disconnect { id: "one".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    let request = wire.request();
    let protocol::Command::Disconnect { generation, .. } = request.command else {
        panic!("Disconnect expected");
    };
    wire.send(Message::Changed {
        profile_id: "one".into(),
        generation,
        state: State::Connecting,
        failures: 0,
        cleaning: false,
        failure: None,
    });
    wire.send(Message::Accepted { id: request.id });
    wire.sign(1, "one", generation, certificate());
    assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn second_request_is_refused_while_the_signer_is_blocked_and_the_first_completes() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let generation = wire.accept("one", State::AwaitingApproval);
    // Keep a bounded release path even if a regression blocks the broker poll.
    let (polled, observed) = mpsc::channel();
    thread::scope(|scope| {
        let guard = scope.spawn(move || {
            let result = observed.recv_timeout(BUDGET / 2);
            gate.release();
            result
        });
        wire.sign(1, "one", generation, signature());
        wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
        wire.event(Event::Sign);
        wire.sign(2, "one", generation, certificate());
        assert_eq!(wire.reply(2, "one", generation), error("unavailable"));
        polled.send(()).unwrap();
        guard
            .join()
            .unwrap()
            .expect("poll must return while C_Sign is blocked");
    });
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"signature":"KjA="})
    );
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn disconnect_and_new_generation_discard_late_success_and_close_the_token() {
    for disconnect in [true, false] {
        let gate = Gate::default();
        let mut wire = Wire::new(Some(gate.clone()), None, None);
        let generation = wire.accept("one", State::Connecting);
        wire.sign(1, "one", generation, signature());
        wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
        wire.event(Event::Sign);
        let next_generation = if disconnect {
            wire.broker
                .dispatch(
                    Command::Disconnect { id: "one".into() },
                    Instant::now() + BUDGET,
                )
                .unwrap();
            let request = wire.request();
            assert!(matches!(
                request.command,
                protocol::Command::Disconnect { .. }
            ));
            // Release after dispatch and before reading the response so a
            // mutant that forwards the late result yields the wrong payload.
            gate.release();
            generation + 1
        } else {
            wire.accept("one", State::Reconnecting)
        };
        assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
        gate.release();
        wire.event(Event::Close);
        wire.assert_no_reply();
        if !disconnect {
            wire.sign(2, "one", next_generation, certificate());
            assert_eq!(
                wire.reply(2, "one", next_generation),
                serde_json::json!({"certificate":"MCo="})
            );
            wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
            wire.event(Event::Certificate);
        }
    }
}

#[test]
fn lost_discards_pending_success_and_closes_the_token() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, signature());
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);
    wire.send(Message::Fatal {
        error: ErrorCode::Unavailable,
    });
    assert!(wire.broker.dead);
    gate.release();
    wire.event(Event::Close);
    wire.assert_no_reply();
}

#[test]
fn worker_rejects_bad_padding_before_calling_the_signer() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, certificate());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Certificate);
    // This typed fixture bypasses the parser specifically to exercise the
    // worker's independent padding check on an already-open signer.
    let op = SignOperation::Sign(SignFields::Pss(PssOperation {
        op: SignOperationName::Sign,
        padding: PssPaddingName::Pss,
        hash: PssHashName::Sha256,
        data: serde_json::from_str::<SignDataBytes>("\"AA==\"").unwrap(),
    }));
    wire.send(Message::SignRequest {
        id: 2,
        profile: "one".into(),
        generation,
        epoch: EPOCH,
        op,
    });
    assert_eq!(wire.reply(2, "one", generation), error("unsupported"));
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn opening_and_signing_map_errors_and_failed_open_leaves_no_signer() {
    for (cause, reply) in [
        (SignError::Canceled, "canceled"),
        (SignError::PinRequired, "pin_required"),
        (SignError::Unavailable, "unavailable"),
        (SignError::Unsupported, "unavailable"),
    ] {
        let mut wire = Wire::new(None, Some(cause), None);
        let generation = wire.accept("one", State::Connecting);
        wire.sign(1, "one", generation, certificate());
        assert_eq!(wire.reply(1, "one", generation), error(reply));
        wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
        wire.sign(2, "one", generation, signature());
        assert_eq!(wire.reply(2, "one", generation), error(reply));
        assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));

        let mut wire = Wire::new(None, None, Some(cause));
        let generation = wire.accept("one", State::Connecting);
        wire.sign(1, "one", generation, signature());
        assert_eq!(wire.reply(1, "one", generation), error(reply));
        wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
        wire.event(Event::Sign);
    }
}

#[test]
fn a_full_reply_transport_preserves_the_refusal_and_keeps_the_helper_connected() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    let queued = fill_reply_transport(&wire);
    wire.sign(1, "one", generation + 1, certificate());
    assert!(wire.broker.ready, "a full queue must keep the helper ready");
    drain_reply_transport(&wire, queued);
    assert_eq!(wire.reply(1, "one", generation + 1), error("unavailable"));
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn reading_resumes_after_retained_replies_drain() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    let queued = fill_reply_transport(&wire);
    for id in 1..=64 {
        wire.sign(id, "one", generation + 1, certificate());
    }
    wire.change_state("one", generation, State::Connected);
    assert_eq!(
        wire.broker.connections["one"].view.state,
        State::Connecting,
        "a full backlog pauses the next receive"
    );

    drain_reply_transport(&wire, queued);
    wire.broker.poll();
    assert_eq!(wire.broker.connections["one"].view.state, State::Connecting);
    let first_batch = u64::try_from(queued).unwrap();
    for id in 1..=first_batch {
        assert_eq!(
            wire.immediate_reply(id, "one", generation + 1),
            error("unavailable")
        );
    }
    wire.broker.poll();
    assert_eq!(wire.broker.connections["one"].view.state, State::Connected);
    for id in first_batch + 1..=64 {
        assert_eq!(
            wire.immediate_reply(id, "one", generation + 1),
            error("unavailable")
        );
    }
    wire.assert_no_reply();
    assert!(wire.broker.ready);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

fn fill_reply_transport(wire: &Wire) -> usize {
    let client = wire.broker.client.as_ref().unwrap();
    let mut queued = 0;
    loop {
        match client.send(Request {
            id: format!("fixture-{queued}"),
            command: protocol::Command::Snapshot {},
        }) {
            Ok(()) => queued += 1,
            Err(Error::Busy) => break,
            Err(error) => panic!("unexpected send error: {error:?}"),
        }
    }
    assert!(queued > 0);
    queued
}

fn drain_reply_transport(wire: &Wire, queued: usize) {
    for id in 0..queued {
        assert_eq!(wire.request().id, format!("fixture-{id}"));
    }
}

#[test]
fn dropped_revokes_a_pending_call_and_later_active_progress_cannot_restore_it() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, signature());
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);
    wire.change_state("one", generation, State::Dropped);
    assert_eq!(
        wire.immediate_reply(1, "one", generation),
        error("unavailable")
    );
    gate.release();
    wire.event(Event::Close);
    wire.assert_no_reply();

    wire.change_state("one", generation, State::Connected);
    wire.sign(2, "one", generation, certificate());
    assert_eq!(wire.reply(2, "one", generation), error("unavailable"));
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn dropped_invalidates_token_payloads_already_waiting_for_transport() {
    for (op, event) in [
        (signature(), Event::Sign),
        (certificate(), Event::Certificate),
    ] {
        let mut wire = Wire::new(None, None, None);
        let generation = wire.accept("one", State::Connecting);
        wire.change_state("one", generation, State::Connected);
        let queued = fill_reply_transport(&wire);
        wire.sign(1, "one", generation, op);
        wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
        wire.event(event);
        let until = Instant::now() + BUDGET;
        loop {
            wire.broker.poll_signing();
            if !wire.broker.flush_signing().unwrap() {
                break;
            }
            assert!(Instant::now() < until, "the token payload was not retained");
            thread::yield_now();
        }
        wire.change_state("one", generation, State::Dropped);
        drain_reply_transport(&wire, queued);
        assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
        wire.event(Event::Close);
    }
}

#[test]
fn rejected_reconnect_preserves_the_previous_active_attempt() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.change_state("one", generation, State::Connected);
    wire.sign(1, "one", generation, certificate());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Certificate);

    let replacement = wire.submit_connect("one", State::Reconnecting);
    wire.sign(2, "one", generation, certificate());
    assert_eq!(
        wire.immediate_reply(2, "one", generation),
        error("unavailable")
    );
    wire.send(Message::Failed {
        id: replacement,
        error: ErrorCode::ProfileBusy,
    });
    let restored = &wire.broker.connections["one"];
    assert_eq!(restored.generation, generation);
    assert_eq!(restored.view.state, State::Connected);
    wire.sign(3, "one", generation, certificate());
    assert_eq!(
        wire.reply(3, "one", generation),
        serde_json::json!({"certificate":"MCo="}),
        "the restored connected attempt must still answer certificate requests"
    );
    wire.event(Event::Certificate);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn terminal_suspended_generation_revokes_signing_before_reconnect_rollback() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.change_state("one", generation, State::Connected);
    wire.sign(1, "one", generation, signature());
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);

    let replacement = wire.submit_connect("one", State::Reconnecting);
    wire.change_state("one", generation, State::Unresponsive);
    assert_eq!(
        wire.immediate_reply(1, "one", generation),
        error("unavailable")
    );
    wire.change_state("one", generation, State::Dropped);
    wire.assert_no_reply();
    assert_eq!(
        wire.broker.connections["one"].view.state,
        State::Reconnecting
    );
    gate.release();
    wire.event(Event::Close);

    wire.send(Message::Failed {
        id: replacement,
        error: ErrorCode::ProfileBusy,
    });
    let restored = &wire.broker.connections["one"];
    assert_eq!(restored.generation, generation);
    assert_eq!(restored.view.state, State::Connected);
    wire.sign(2, "one", generation, signature());
    assert_eq!(
        wire.immediate_reply(2, "one", generation),
        error("unavailable")
    );
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn reconnect_rollback_cannot_reauthorize_a_terminal_suspended_generation() {
    let mut wire = Wire::new(None, None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.change_state("one", generation, State::Connected);
    wire.sign(1, "one", generation, signature());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"signature":"KjA="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);

    let replacement = wire.submit_connect("one", State::Reconnecting);
    wire.change_state("one", generation, State::Dropped);
    wire.send(Message::Failed {
        id: replacement,
        error: ErrorCode::ProfileBusy,
    });
    wire.sign(2, "one", generation, signature());
    assert_eq!(wire.reply(2, "one", generation), error("unavailable"));
    wire.event(Event::Close);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn accepted_reconnect_revokes_the_suspended_token_only_after_the_ack() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, signature());
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);
    let replacement = wire.submit_connect("one", State::Reconnecting);
    assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
    wire.send(Message::Accepted { id: replacement });
    gate.release();
    wire.event(Event::Close);
    wire.sign(2, "one", generation + 1, certificate());
    assert_eq!(
        wire.reply(2, "one", generation + 1),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Certificate);
}

#[test]
fn disconnect_releases_the_production_opener_while_the_module_gate_is_held() {
    use crate::connection::ovpn::pkcs11::TokenKey;
    use std::{fs, path::PathBuf};

    struct Module(PathBuf);
    impl Drop for Module {
        fn drop(&mut self) {
            fs::remove_file(&self.0).unwrap();
        }
    }

    let path = crate::connection::ovpn::pkcs11::tests::admitted_fixture_base()
        .canonicalize()
        .unwrap()
        .join(format!("vpnt-opener-gate-{}.dylib", std::process::id()));
    fs::File::create_new(&path).unwrap();
    let module = Module(path);
    let gate = TokenKey::module_gate(&module.0);
    let held = gate.write().unwrap();
    let mut wire = Wire::new(None, None, None);
    let mut settings = wire.broker.connections["one"]
        .view
        .profile
        .ovpn
        .clone()
        .unwrap();
    settings.module = module.0.to_str().unwrap().into();
    wire.broker
        .connections
        .get_mut("one")
        .unwrap()
        .view
        .profile
        .ovpn = Some(settings);
    let opener = Arc::clone(&crate::broker::signer::Signing::default().open);
    let (started, starting) = mpsc::channel();
    let (finished, finishing) = mpsc::channel();
    wire.broker.signing.open = Arc::new(move |settings, canceled, expires| {
        started.send(expires).unwrap();
        let result = opener(settings, canceled, expires);
        let _ = finished.send(matches!(&result, Ok(None)));
        result
    });
    let generation = wire.accept("one", State::Connecting);
    let before_request = Instant::now();
    wire.sign(1, "one", generation, certificate());
    let after_request = Instant::now();
    let expires = starting.recv_timeout(BUDGET).unwrap();
    let opening_window = Duration::from_secs(60);
    assert!((before_request + opening_window..=after_request + opening_window).contains(&expires));
    wire.broker
        .dispatch(
            Command::Disconnect { id: "one".into() },
            Instant::now() + BUDGET,
        )
        .unwrap();
    assert!(matches!(
        wire.request().command,
        protocol::Command::Disconnect { .. }
    ));
    assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
    assert!(
        finishing
            .recv_timeout(BUDGET)
            .expect("opening must return before the held gate releases"),
        "canceling the gate wait must produce no token",
    );
    drop(held);
}

#[test]
fn revoked_open_drops_the_token_without_using_it() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let (events, observe) = mpsc::channel();
    let (started, starting) = mpsc::channel();
    let opening = gate.clone();
    wire.broker.signing.open = Arc::new(move |_, canceled, _| {
        started.send(()).unwrap();
        opening.wait();
        assert!(canceled.load(Ordering::Acquire));
        Ok(Some(Box::new(Fake {
            events: events.clone(),
            gate: None,
            error: None,
        })))
    });
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, certificate());
    starting.recv_timeout(BUDGET).unwrap();
    wire.change_state("one", generation, State::Dropped);
    assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
    gate.release();
    assert_eq!(observe.recv_timeout(BUDGET).unwrap(), Event::Close);
    wire.assert_no_reply();
}

#[test]
fn opening_without_a_token_replies_unavailable_without_retrying() {
    let mut wire = Wire::new(None, None, None);
    let (opened, openings) = mpsc::channel();
    wire.broker.signing.open = Arc::new(move |_, canceled, _| {
        assert!(!canceled.load(Ordering::Acquire));
        opened.send(()).unwrap();
        Ok(None)
    });
    let generation = wire.accept("one", State::Connecting);
    for id in [1, 2] {
        wire.sign(id, "one", generation, certificate());
        assert_eq!(wire.reply(id, "one", generation), error("unavailable"));
    }
    openings.recv_timeout(BUDGET).unwrap();
    assert!(matches!(openings.try_recv(), Err(TryRecvError::Empty)));
}

#[test]
fn revocation_releases_a_waiting_signer_before_its_gate_opens() {
    struct WaitingSigner {
        started: Sender<Instant>,
        gate: Receiver<()>,
        closed: Sender<()>,
    }

    impl AppSigner for WaitingSigner {
        fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
            Ok(vec![48, 42])
        }

        fn sign(
            &mut self,
            _: Padding,
            _: &[u8],
            canceled: &AtomicBool,
            expires: Instant,
        ) -> Result<Option<Vec<u8>>, SignError> {
            self.started.send(expires).unwrap();
            while !canceled.load(Ordering::Acquire) {
                assert_eq!(
                    self.gate.recv_timeout(Duration::from_millis(10)),
                    Err(mpsc::RecvTimeoutError::Timeout),
                    "the fixture must keep the signing gate closed"
                );
            }
            Ok(None)
        }
    }

    impl Drop for WaitingSigner {
        fn drop(&mut self) {
            let _ = self.closed.send(());
        }
    }

    let (started, starting) = mpsc::channel();
    let (closed, closing) = mpsc::channel();
    let (gate, held) = mpsc::channel();
    let held = Mutex::new(Some(held));
    let mut wire = Wire::new(None, None, None);
    wire.broker.signing.open = Arc::new(move |_, _, _| {
        Ok(Some(Box::new(WaitingSigner {
            started: started.clone(),
            gate: held.lock().unwrap().take().unwrap(),
            closed: closed.clone(),
        })))
    });
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, certificate());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );

    let before = Instant::now();
    wire.sign(2, "one", generation, signature());
    let after = Instant::now();
    let expires = starting.recv_timeout(BUDGET).unwrap();
    let window = Duration::from_secs(60);
    assert!((before + window..=after + window).contains(&expires));
    wire.change_state("one", generation, State::Dropped);
    assert_eq!(
        wire.immediate_reply(2, "one", generation),
        error("unavailable")
    );
    closing.recv_timeout(BUDGET).unwrap();
    drop(gate);
    wire.assert_no_reply();
}

fn wire_with_pending_gate_sign() -> (Wire, Gate, Receiver<bool>, u64) {
    struct GateSigner {
        token: Fake,
        gate: Gate,
        waiting: Sender<()>,
        finished: Sender<bool>,
    }

    impl AppSigner for GateSigner {
        fn certificate(&mut self) -> Result<Vec<u8>, SignError> {
            self.token.certificate()
        }

        fn sign(
            &mut self,
            padding: Padding,
            data: &[u8],
            canceled: &AtomicBool,
            expires: Instant,
        ) -> Result<Option<Vec<u8>>, SignError> {
            self.waiting.send(()).unwrap();
            self.gate.wait();
            let result = if canceled.load(Ordering::Acquire) {
                Ok(None)
            } else {
                self.token.sign(padding, data, canceled, expires)
            };
            let _ = self.finished.send(matches!(result, Ok(Some(_))));
            result
        }
    }

    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let (waiting, wait) = mpsc::channel();
    let (finished, finish) = mpsc::channel();
    let (events, observe) = mpsc::channel();
    wire.events = observe;
    let held = gate.clone();
    wire.broker.signing.open = Arc::new(move |settings, _, _| {
        events
            .send(Event::Open(
                settings.module.clone(),
                settings.certificate_id.clone(),
            ))
            .unwrap();
        Ok(Some(Box::new(GateSigner {
            token: Fake {
                events: events.clone(),
                gate: None,
                error: None,
            },
            gate: held.clone(),
            waiting: waiting.clone(),
            finished: finished.clone(),
        })))
    });
    let generation = wire.accept("one", State::Connecting);
    wire.change_state("one", generation, State::Connected);
    wire.sign(1, "one", generation, signature());
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wait.recv_timeout(BUDGET).unwrap();
    (wire, gate, finish, generation)
}

#[test]
fn disconnect_stops_pending_gate_work_before_the_next_poll() {
    let (mut wire, gate, finish, generation) = wire_with_pending_gate_sign();
    // Dispatch also polls to produce the snapshot, hiding the transition.
    wire.broker.disconnect("one").unwrap();
    assert!(matches!(
        wire.request().command,
        protocol::Command::Disconnect { .. }
    ));
    gate.release();
    assert!(
        !finish.recv_timeout(BUDGET).unwrap(),
        "sign started after Disconnect"
    );
    assert!(wire.broker.flush_signing().unwrap());
    assert_eq!(
        wire.immediate_reply(1, "one", generation),
        error("unavailable")
    );
    wire.event(Event::Close);
    wire.assert_no_reply();
}

#[test]
fn reconnect_stops_pending_gate_work_before_ack_and_rollback_reuses_the_token() {
    let (mut wire, gate, finish, generation) = wire_with_pending_gate_sign();
    let replacement = wire.submit_connect("one", State::Reconnecting);
    gate.release();
    assert!(
        !finish.recv_timeout(BUDGET).unwrap(),
        "sign started before Reconnect was acknowledged"
    );
    assert!(wire.broker.flush_signing().unwrap());
    assert_eq!(
        wire.immediate_reply(1, "one", generation),
        error("unavailable")
    );
    wire.send(Message::Failed {
        id: replacement,
        error: ErrorCode::ProfileBusy,
    });
    wire.sign(2, "one", generation, certificate());
    assert_eq!(
        wire.reply(2, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Certificate);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
    wire.assert_no_reply();
}

#[test]
fn disconnect_and_reconnect_pause_signing_before_the_command_is_published() {
    for disconnect in [true, false] {
        let (mut wire, gate, finish, generation) = wire_with_pending_gate_sign();
        let next_generation = generation + 1;
        let (command, state) = if disconnect {
            (
                protocol::Command::Disconnect {
                    id: "one".into(),
                    generation: next_generation,
                },
                State::Disconnecting,
            )
        } else {
            (
                protocol::Command::Connect {
                    id: "one".into(),
                    generation: next_generation,
                    credentials: Credentials {
                        password: "".into(),
                        psk: "".into(),
                    },
                    interval: wire.broker.preferences.interval,
                },
                State::Reconnecting,
            )
        };
        let requests = &wire.requests;
        wire.broker
            .submit_with_send(
                "one",
                next_generation,
                command,
                Some(state),
                |client, request| {
                    let id = request.id.clone();
                    client.send(request)?;
                    assert_eq!(requests.recv_timeout(BUDGET).unwrap().id, id);
                    gate.release();
                    assert!(
                        !finish.recv_timeout(BUDGET).unwrap(),
                        "sign started after {state:?} was published but before send returned"
                    );
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
    }
}

#[test]
fn failed_disconnect_send_resumes_the_pending_request_with_the_same_token() {
    let (mut wire, gate, finish, generation) = wire_with_pending_gate_sign();
    let queued = fill_reply_transport(&wire);
    assert_eq!(wire.broker.disconnect("one"), Err("backend_unavailable"));
    drain_reply_transport(&wire, queued);
    assert_eq!(wire.broker.connections["one"].generation, generation);
    assert_eq!(wire.broker.connections["one"].view.state, State::Connected);
    gate.release();
    assert!(finish.recv_timeout(BUDGET).unwrap());
    assert_eq!(
        wire.reply(1, "one", generation),
        serde_json::json!({"signature":"KjA="})
    );
    wire.event(Event::Sign);
    wire.sign(2, "one", generation, certificate());
    assert_eq!(
        wire.reply(2, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Certificate);
    wire.assert_no_reply();
}

#[test]
fn failed_disconnect_send_does_not_cache_an_open_interrupted_by_the_pause() {
    let mut wire = Wire::new(None, None, None);
    let original = Arc::clone(&wire.broker.signing.open);
    let (entered, opening) = mpsc::channel();
    let (check_pause, check) = mpsc::channel();
    let (observed, observe) = mpsc::channel();
    let (resume, released) = mpsc::channel();
    let first = Mutex::new(Some((check, released)));
    wire.broker.signing.open = Arc::new(move |settings, canceled, expires| {
        let first = first.lock().unwrap().take();
        if let Some((check, released)) = first {
            entered.send(()).unwrap();
            check.recv_timeout(BUDGET).unwrap();
            observed.send(canceled.load(Ordering::Acquire)).unwrap();
            released.recv_timeout(BUDGET).unwrap();
            assert!(!canceled.load(Ordering::Acquire));
            Ok(None)
        } else {
            original(settings, canceled, expires)
        }
    });
    let generation = wire.accept("one", State::Connecting);
    wire.sign(1, "one", generation, certificate());
    opening.recv_timeout(BUDGET).unwrap();
    let queued = fill_reply_transport(&wire);
    let result = wire.broker.submit_with_send(
        "one",
        generation + 1,
        protocol::Command::Disconnect {
            id: "one".into(),
            generation: generation + 1,
        },
        Some(State::Disconnecting),
        |client, request| {
            check_pause.send(()).unwrap();
            assert!(observe.recv_timeout(BUDGET).unwrap());
            client.send(request)
        },
    );
    assert_eq!(result, Err("backend_unavailable"));
    resume.send(()).unwrap();
    drain_reply_transport(&wire, queued);
    assert_eq!(wire.reply(1, "one", generation), error("unavailable"));
    wire.sign(2, "one", generation, certificate());
    assert_eq!(
        wire.reply(2, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Certificate);
    wire.assert_no_reply();
}

#[test]
fn reconnect_rollback_cannot_deliver_a_late_signature_to_the_next_request() {
    let gate = Gate::default();
    let mut wire = Wire::new(Some(gate.clone()), None, None);
    let generation = wire.accept("one", State::Connecting);
    wire.change_state("one", generation, State::Connected);
    wire.sign(1, "one", generation, signature());
    wire.event(Event::Open("/fixture/one.dylib".into(), "01".into()));
    wire.event(Event::Sign);

    let replacement = wire.submit_connect("one", State::Reconnecting);
    wire.send(Message::Failed {
        id: replacement,
        error: ErrorCode::ProfileBusy,
    });
    assert_eq!(
        wire.immediate_reply(1, "one", generation),
        error("unavailable")
    );
    wire.sign(2, "one", generation, certificate());
    gate.release();
    assert_eq!(
        wire.reply(2, "one", generation),
        serde_json::json!({"certificate":"MCo="})
    );
    wire.event(Event::Certificate);
    assert!(matches!(wire.events.try_recv(), Err(TryRecvError::Empty)));
    wire.assert_no_reply();
}
