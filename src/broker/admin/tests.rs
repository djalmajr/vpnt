use super::*;
use crate::helper::client::tests::Peer;
use std::{
    fs,
    panic::Location,
    process::Command as Process,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::sync_channel,
    },
};
struct Secrets {
    loads: Arc<AtomicUsize>,
    removes: Arc<AtomicUsize>,
    fail_removal: bool,
}
impl SecretStore for Secrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, crate::secrets::SecretError> {
        Ok(true)
    }
    fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, crate::secrets::SecretError> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        Ok(Credentials {
            password: "fictional-client-secret".into(),
            psk: "".into(),
        })
    }
    fn save(
        &self,
        _: &str,
        _: VpnKind,
        _: &Credentials,
    ) -> Result<(), crate::secrets::SecretError> {
        Ok(())
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), crate::secrets::SecretError> {
        self.removes.fetch_add(1, Ordering::Relaxed);
        if self.fail_removal {
            Err(crate::secrets::SecretError::Unavailable)
        } else {
            Ok(())
        }
    }
}
struct Harness {
    broker: Broker<Secrets>,
    peer: Peer,
    starts: Arc<AtomicUsize>,
    loads: Arc<AtomicUsize>,
    removes: Arc<AtomicUsize>,
    connector_deadline: Arc<Mutex<Option<Instant>>>,
}
impl Harness {
    fn new(mode: &str) -> Self {
        let mut peer = Peer::new("flow");
        // Arm the broker's 5 s startup deadline only after the Python peer has
        // entered its read loop; the marker is written by the fixture itself.
        let marker = peer.marker.clone();
        wait("runtime fixture read loop", || {
            marker.with_extension("started").exists()
        });
        let loads = Arc::new(AtomicUsize::new(0));
        let removes = Arc::new(AtomicUsize::new(0));
        let mut broker = Broker::new(
            Some(peer.take()),
            Secrets {
                loads: loads.clone(),
                removes: removes.clone(),
                fail_removal: false,
            },
        );
        wait("initial installed snapshot", || {
            broker.snapshot().helper == "installed"
        });
        fs::write(
            peer.marker.with_extension("catalog"),
            serde_json::to_vec(
                &broker
                    .snapshot()
                    .vpns
                    .iter()
                    .map(|v| v.profile.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        let marker = peer.marker.clone();
        let starts = Arc::new(AtomicUsize::new(0));
        let calls = starts.clone();
        let connector_deadline = Arc::new(Mutex::new(None));
        let observed_deadline = connector_deadline.clone();
        let mode = mode.to_string();
        broker.administration.connect = Box::new(move |request, locale, expires| {
            calls.fetch_add(1, Ordering::Relaxed);
            *observed_deadline.lock().unwrap() = Some(expires);
            let mut command = Process::new("/usr/bin/python3");
            command
                .arg(
                    std::env::current_dir()
                        .unwrap()
                        .join("tests/fixtures/broker-admin/peer.py"),
                )
                .arg(&marker)
                .arg(&mode);
            Admin::fixture(command, request, locale, expires)
        });
        Self {
            peer,
            broker,
            starts,
            loads,
            removes,
            connector_deadline,
        }
    }
    fn command(&mut self, command: Command) -> Snapshot {
        self.broker
            .dispatch(command, Instant::now() + Duration::from_secs(45))
            .unwrap()
    }
    fn assert_connector_deadline(&self, expires: Instant) {
        assert_eq!(
            *self.connector_deadline.lock().unwrap(),
            Some(expires),
            "connector must receive exactly the operation deadline"
        );
    }
    fn begin(&mut self, command: Command) -> u64 {
        let expires = Instant::now() + Duration::from_secs(45);
        let token = self
            .broker
            .begin_admin(command, Locale::PtBr, expires)
            .unwrap();
        self.assert_connector_deadline(expires);
        token
    }
    fn authorize(&self) {
        fs::write(self.peer.marker.with_extension("authorize"), b"").unwrap();
    }
    #[track_caller]
    fn result(&mut self) -> (u64, Result<Snapshot, &'static str>) {
        let mut result = None;
        wait("admin result", || {
            self.broker.poll();
            result = self.broker.take_admin_result();
            result.is_some()
        });
        result.unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(op) = &mut self.broker.administration.current {
            op.client.close();
            let started = Instant::now();
            let until = started + Duration::from_secs(20);
            while !op.client.finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !op.client.finished() {
                eprintln!(
                    "admin harness drop: client not finished after {:?}",
                    started.elapsed()
                );
            }
        }
    }
}
#[track_caller]
fn wait(stage: &str, mut predicate: impl FnMut() -> bool) {
    let caller = Location::caller();
    let started = Instant::now();
    let until = started + Duration::from_secs(60);
    while !predicate() {
        assert!(
            Instant::now() < until,
            "{stage}: broker admin condition timed out after {:?} at {caller}",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn a_profile_change_waits_for_reap_and_fresh_metadata_while_another_profile_remains_controllable() {
    let mut h = Harness::new("save");
    h.command(Command::Toggle { id: "one".into() });
    h.peer.advance();
    wait("connected after toggle", || {
        h.broker.snapshot().vpns[0].state == State::Connected
    });
    let mut edited = h.broker.snapshot().vpns[1].profile.clone();
    edited.name = "Edited by administrator".into();
    let token = h.begin(Command::SaveProfile {
        profile: edited.clone(),
        ovpn_config: None,
    });
    h.command(Command::Probe { id: "one".into() });
    wait("unresponsive after probe", || {
        h.broker.snapshot().vpns[0].state == State::Unresponsive
    });
    assert!(h.broker.take_admin_result().is_none());
    assert_ne!(h.broker.snapshot().vpns[1].profile, edited);
    h.authorize();
    let (done, result) = h.result();
    assert_eq!(done, token);
    let snapshot = result.unwrap();
    assert_eq!(snapshot.vpns[1].profile, edited);
    assert_eq!(snapshot.vpns[0].state, State::Unresponsive);
    assert_eq!(h.loads.load(Ordering::Relaxed), 1);
    assert_eq!(h.removes.load(Ordering::Relaxed), 0);
    h.command(Command::Toggle { id: "one".into() });
    wait("off after disconnect", || {
        h.broker.snapshot().vpns[0].state == State::Off
    });
}
#[test]
fn active_profiles_do_not_prompt_and_secrets_are_removed_only_after_confirmed_removal() {
    let mut h = Harness::new("save");
    h.command(Command::Toggle { id: "one".into() });
    h.peer.advance();
    wait("connected after toggle", || {
        h.broker.snapshot().vpns[0].state == State::Connected
    });
    assert_eq!(
        h.broker.begin_admin(
            Command::RemoveProfile { id: "one".into() },
            Locale::EnUs,
            Instant::now() + Duration::from_secs(20)
        ),
        Err("profile_busy")
    );
    assert_eq!(h.starts.load(Ordering::Relaxed), 0);
    h.begin(Command::RemoveProfile { id: "two".into() });
    assert_eq!(h.removes.load(Ordering::Relaxed), 0);
    assert!(matches!(
        h.broker.dispatch(
            Command::Toggle { id: "two".into() },
            Instant::now() + Duration::from_secs(20)
        ),
        Err("admin_busy")
    ));
    assert!(matches!(
        h.broker.dispatch(
            Command::SaveSecrets {
                id: "two".into(),
                password: "fictional".into(),
                psk: "".into()
            },
            Instant::now() + Duration::from_secs(20)
        ),
        Err("admin_busy")
    ));
    assert_eq!(h.starts.load(Ordering::Relaxed), 1);
    h.authorize();
    let result = h.result().1.unwrap();
    assert!(result.vpns.iter().all(|v| v.profile.id != "two"));
    assert_eq!(h.removes.load(Ordering::Relaxed), 1);
    assert_eq!(result.vpns[0].state, State::Connected);
}
#[test]
fn acceptance_without_persistence_or_a_rejected_operation_never_deletes_credentials() {
    for (mode, expected) in [("lie", "admin_unconfirmed"), ("reject", "profile_busy")] {
        let mut h = Harness::new(mode);
        h.begin(Command::RemoveProfile { id: "two".into() });
        h.authorize();
        assert!(matches!(h.result().1,Err(error)if error==expected));
        assert_eq!(h.removes.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn expired_administration_never_sends_a_document_or_replays_after_a_late_authorization() {
    let mut h = Harness::new("save");
    let p = h.broker.snapshot().vpns[0].profile.clone();
    // Margem: 3 s de pausa suportada + partida Python < 8 s; a operação
    // expira antes da autorização e o conector recebe este mesmo `expires`.
    let expires = Instant::now() + Duration::from_secs(8);
    h.broker
        .begin_admin(
            Command::SaveProfile {
                profile: p,
                ovpn_config: None,
            },
            Locale::PtBr,
            expires,
        )
        .unwrap();
    h.assert_connector_deadline(expires);
    assert!(matches!(h.result().1, Err("admin_expired")));
    h.authorize();
    wait("administration cleared after expiration", || {
        h.broker.poll();
        h.broker.administration.current.is_none()
    });
    assert_eq!(h.loads.load(Ordering::Relaxed), 0);
    assert_eq!(h.removes.load(Ordering::Relaxed), 0);
    assert_eq!(h.starts.load(Ordering::Relaxed), 1);
}

#[test]
fn a_partial_keychain_cleanup_reports_failure_after_the_profile_was_removed() {
    let mut h = Harness::new("save");
    h.broker.secrets.fail_removal = true;
    h.begin(Command::RemoveProfile { id: "two".into() });
    h.authorize();
    assert!(matches!(h.result().1, Err("secret_cleanup_failed")));
    assert!(
        h.broker
            .snapshot()
            .vpns
            .iter()
            .all(|v| v.profile.id != "two")
    );
    assert_eq!(h.removes.load(Ordering::Relaxed), 1);
    assert_eq!(h.loads.load(Ordering::Relaxed), 0);
}

#[test]
fn losing_the_runtime_during_authorization_never_replays_or_deletes_secrets() {
    let mut h = Harness::new("save");
    let before = fs::read(h.peer.marker.with_extension("catalog")).unwrap();
    h.begin(Command::RemoveProfile { id: "two".into() });
    h.command(Command::Quit {});
    assert!(matches!(h.result().1, Err("backend_unavailable")));
    h.authorize();
    wait("admin client finished after late authorization", || {
        h.broker.poll();
        h.broker
            .administration
            .current
            .as_ref()
            .unwrap()
            .client
            .finished()
    });
    assert_eq!(
        fs::read(h.peer.marker.with_extension("catalog")).unwrap(),
        before
    );
    assert_eq!(h.starts.load(Ordering::Relaxed), 1);
    assert_eq!(h.removes.load(Ordering::Relaxed), 0);
}

fn ovpn_profile(id: &str) -> Profile {
    serde_json::from_value(serde_json::json!({
        "id": id, "name": id, "kind": "ovpn", "gateway": "vpn.example.test",
        "username": "", "networks": [], "port": 1194, "certificate": "",
        "probeHost": "192.0.2.1", "probePort": 8443, "probeMethod": "tcp",
        "ovpn": {"module": "/fixture/token.dylib", "certificateId": "01", "tls": "pkcs1_only"}
    }))
    .unwrap()
}

fn normalized(text: &str) -> String {
    crate::connection::ovpn::profile::inspect(text.as_bytes())
        .unwrap()
        .normalized
}

/// The document the fictional administrative helper actually received.
fn received_document(h: &Harness) -> serde_json::Value {
    serde_json::from_slice(&fs::read(h.peer.marker.with_extension("document")).unwrap()).unwrap()
}

#[test]
fn ovpn_config_reaches_the_admin_helper_for_a_new_profile_and_an_edit() {
    let mut h = Harness::new("save");
    let first = "remote vpn.example.test 1194\r\n<ca>\r\nfirst\r\n</ca>\r\n";
    let second = "remote vpn.example.test 1194\n<ca>\nsecond\n</ca>\n";
    let created = ovpn_profile("review-ovpn");
    let token = h.begin(Command::SaveProfile {
        profile: created.clone(),
        ovpn_config: Some(first.into()),
    });
    h.authorize();
    let (done, result) = h.result();
    assert_eq!(done, token);
    let snapshot = result.unwrap();
    assert_eq!(
        snapshot
            .vpns
            .iter()
            .find(|vpn| vpn.profile.id == created.id)
            .unwrap()
            .profile,
        created
    );
    assert_eq!(h.starts.load(Ordering::Relaxed), 1);
    let document = received_document(&h);
    assert_eq!(document["command"]["type"], "save_profile");
    assert_eq!(document["command"]["profile"]["id"], "review-ovpn");
    assert_eq!(document["command"]["ovpn_config"], normalized(first));
    assert_ne!(normalized(first), first);

    // The same profile, edited with a config that replaces the first one.
    fs::remove_file(h.peer.marker.with_extension("document")).unwrap();
    let mut edited = created.clone();
    edited.name = "Edited fixture".into();
    h.begin(Command::SaveProfile {
        profile: edited.clone(),
        ovpn_config: Some(second.into()),
    });
    h.authorize();
    let snapshot = h.result().1.unwrap();
    assert_eq!(
        snapshot
            .vpns
            .iter()
            .find(|vpn| vpn.profile.id == edited.id)
            .unwrap()
            .profile,
        edited
    );
    assert_eq!(h.starts.load(Ordering::Relaxed), 2);
    let document = received_document(&h);
    assert_eq!(document["command"]["profile"]["name"], "Edited fixture");
    assert_eq!(document["command"]["ovpn_config"], normalized(second));
}

#[test]
fn a_local_missing_program_warning_survives_an_unrelated_admin_snapshot() {
    let mut h = Harness::new("save");
    let ovpn = ovpn_profile("review-ovpn");
    h.begin(Command::SaveProfile {
        profile: ovpn.clone(),
        ovpn_config: None,
    });
    h.authorize();
    assert!(h.result().1.is_ok());
    let state = |snapshot: Snapshot, id: &str| {
        snapshot
            .vpns
            .iter()
            .find(|vpn| vpn.profile.id == id)
            .unwrap()
            .state
    };
    refuse_ovpn_connect(&mut h.broker, &ovpn.id);
    assert_eq!(state(h.broker.snapshot(), &ovpn.id), State::MissingProgram);
    // The local poll keeps the card off without reading credentials.
    assert_eq!(
        state(h.command(Command::GetSnapshot {}), &ovpn.id),
        State::MissingProgram
    );
    assert_eq!(h.loads.load(Ordering::Relaxed), 0);

    // An unrelated administrative edit changes the generation of its profile only.
    let other = h
        .broker
        .snapshot()
        .vpns
        .iter()
        .find(|vpn| vpn.profile.id == "one")
        .unwrap()
        .profile
        .clone();
    let mut edited = other.clone();
    edited.name = "Edited unrelated fixture".into();
    h.begin(Command::SaveProfile {
        profile: edited.clone(),
        ovpn_config: None,
    });
    h.authorize();
    let snapshot = h.result().1.unwrap();
    assert_eq!(state(snapshot.clone(), &ovpn.id), State::MissingProgram);
    assert_eq!(
        snapshot
            .vpns
            .iter()
            .find(|vpn| vpn.profile.id == "one")
            .unwrap()
            .profile,
        edited
    );
}

#[test]
fn the_missing_program_warning_holds_only_for_a_same_generation_off_snapshot() {
    use crate::helper::{protocol, protocol::TunnelStatus};
    let mut broker = Broker::new(
        None,
        Secrets {
            loads: Arc::new(AtomicUsize::new(0)),
            removes: Arc::new(AtomicUsize::new(0)),
            fail_removal: false,
        },
    );
    let ovpn = ovpn_profile("review-ovpn");
    let status = |generation: u64, state: State| TunnelStatus {
        id: ovpn.id.clone(),
        generation,
        state,
        failures: 0,
        cleaning: false,
        failure: None,
    };
    let state_of = |broker: &mut Broker<Secrets>| broker.snapshot().vpns[0].state;
    broker
        .receive_snapshot(
            protocol::WAIT_CAPABILITY_SNAPSHOT_ID.into(),
            env!("CARGO_PKG_VERSION").into(),
            None,
            vec![ovpn.clone()],
            vec![status(0, State::Off)],
        )
        .unwrap();
    let warn = |broker: &mut Broker<Secrets>| {
        refuse_ovpn_connect(broker, &ovpn.id);
        assert_eq!(state_of(broker), State::MissingProgram);
    };
    // The merge runs through the cleanup verification seam: it is the existing
    // path that accepts a same-generation snapshot for a known profile.
    let merge = |broker: &mut Broker<Secrets>, profile: Profile, generation: u64, state: State| {
        let observed = broker
            .connections
            .iter()
            .map(|(id, connection)| (id.clone(), connection.generation))
            .collect();
        broker.cleanup_verify = Some(CleanupVerify {
            request: "merge".into(),
            profile: ovpn.id.clone(),
            observed,
        });
        broker.receive_snapshot(
            "merge".into(),
            env!("CARGO_PKG_VERSION").into(),
            None,
            vec![profile],
            vec![TunnelStatus {
                id: ovpn.id.clone(),
                generation,
                state,
                failures: 0,
                cleaning: false,
                failure: None,
            }],
        )
    };

    warn(&mut broker);
    merge(&mut broker, ovpn.clone(), 0, State::Off).unwrap();
    assert_eq!(state_of(&mut broker), State::MissingProgram);

    // Another helper state at the same generation is still authoritative.
    merge(&mut broker, ovpn.clone(), 0, State::Dropped).unwrap();
    assert_eq!(state_of(&mut broker), State::Dropped);

    // A new generation follows the ordinary rule even for the same OVPN profile.
    warn(&mut broker);
    merge(&mut broker, ovpn.clone(), 1, State::Off).unwrap();
    assert_eq!(state_of(&mut broker), State::Off);

    // A profile that is no longer OVPN returns to the ordinary rule.
    warn(&mut broker);
    let mut ssl = ovpn.clone();
    ssl.kind = VpnKind::Ssl;
    ssl.ovpn = None;
    ssl.username = "fictional".into();
    merge(&mut broker, ssl, 1, State::Off).unwrap();
    assert_eq!(state_of(&mut broker), State::Off);
}

fn refuse_ovpn_connect(broker: &mut Broker<Secrets>, profile: &str) {
    let (send, requests) = sync_channel(8);
    let (replies, receive) = sync_channel(8);
    // Use the channel peer for this Connect so the admin peer can still
    // publish the unrelated catalog changes on its original transport.
    let client = broker
        .client
        .replace(Client::fixture_channels(send, receive));
    let before = broker.connections[profile].generation;
    broker
        .dispatch(
            Command::Toggle { id: profile.into() },
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
    let request = requests.recv_timeout(Duration::from_secs(15)).unwrap();
    assert!(matches!(
        request.command,
        protocol::Command::Connect { id, generation, .. }
            if id == profile && generation == before + 1
    ));
    replies
        .send(Message::Failed {
            id: request.id,
            error: ErrorCode::MissingProgram,
        })
        .unwrap();
    broker.poll();
    broker.client = client;
    assert!(broker.connections[profile].pending.is_none());
    assert_eq!(broker.connections[profile].generation, before);
}
