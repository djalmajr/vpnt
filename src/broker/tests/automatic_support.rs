use super::*;
use crate::{
    helper::client::tests::Peer,
    notifications::{Notice, Notifier},
    preferences::ProbeInterval,
    secrets::{Credentials, SecretError},
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
pub(super) struct Calls(Arc<Mutex<Vec<(String, VpnKind)>>>);
impl Calls {
    pub(super) fn recorded(&self) -> Vec<(String, VpnKind)> {
        self.0.lock().unwrap().clone()
    }
}

pub(super) struct RecordingSecrets {
    calls: Calls,
    psk: String,
    fail: Arc<AtomicBool>,
}
impl RecordingSecrets {
    pub(super) fn new() -> (Self, Calls, Arc<AtomicBool>) {
        let calls = Calls::default();
        let fail = Arc::new(AtomicBool::new(false));
        (
            Self {
                calls: calls.clone(),
                psk: "fictional-psk".into(),
                fail: fail.clone(),
            },
            calls,
            fail,
        )
    }
}
impl SecretStore for RecordingSecrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        Ok(true)
    }
    fn load(&self, id: &str, kind: VpnKind) -> Result<Credentials, SecretError> {
        self.calls.0.lock().unwrap().push((id.into(), kind));
        if self.fail.load(Ordering::Acquire) {
            return Err(SecretError::Unavailable);
        }
        Ok(Credentials {
            password: "fictional-client-secret".into(),
            psk: self.psk.clone().into(),
        })
    }
    fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
        Ok(())
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
        Ok(())
    }
}

pub(super) fn run<S: SecretStore>(
    broker: &mut Broker<S>,
    command: Command,
) -> Result<Snapshot, &'static str> {
    broker.dispatch(command, Instant::now() + Duration::from_secs(2))
}

pub(super) fn preferences(interval: ProbeInterval, notify: bool, reconnect: bool) -> Preferences {
    Preferences {
        interval,
        notify,
        reconnect,
        startup: false,
    }
}

pub(super) fn set_preferences<S: SecretStore>(broker: &mut Broker<S>, value: Preferences) {
    run(broker, Command::SetPreferences { preferences: value }).unwrap();
}

pub(super) fn state(snapshot: &Snapshot, id: &str) -> State {
    snapshot
        .vpns
        .iter()
        .find(|v| v.profile.id == id)
        .unwrap()
        .state
}

pub(super) fn connect<S: SecretStore>(broker: &mut Broker<S>, peer: &Peer, id: &str) {
    run(broker, Command::Toggle { id: id.into() }).unwrap();
    peer.advance();
    wait(broker, |s| state(s, id) == State::Connected);
}

pub(super) fn probe<S: SecretStore>(broker: &mut Broker<S>, id: &str, failures: u32) {
    run(broker, Command::Probe { id: id.into() }).unwrap();
    // Synchronization guard, not a latency requirement: the peer may take a
    // 3 s pause, while a stalled poll still fails with the state it observed.
    let until = Instant::now() + Duration::from_secs(15);
    while broker.connections[id].failures != failures {
        broker.poll();
        assert!(
            Instant::now() < until,
            "the helper failure counter did not reach {failures} for {id}: helper={}, states={:?}, generations={:?}",
            broker.helper,
            super::states(broker),
            super::generations(broker),
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(state(&broker.snapshot(), id), State::Unresponsive);
}

pub(super) fn automatic<S: SecretStore>(broker: &mut Broker<S>) {
    broker.perform_automatic(|| true);
}

/// Any frame the peer sent before it answers this diagnostics request is
/// already on the ordered Client stream, so the correlated reply is the FIFO
/// barrier that proves the Broker consumed it. The reply carries no tunnel
/// state (`src/broker/mod.rs` Message::Diagnostics), so it cannot restore the
/// state the caller asserts after it returns. The peer stays fake/in-process.
pub(super) fn consume_stale_with_diagnostics<S: SecretStore>(broker: &mut Broker<S>) {
    // An earlier request would make the barrier prove nothing about the stale
    // frame, so the request that clears must be the one made here.
    assert!(
        broker.diagnostics.pending.is_none(),
        "the diagnostics barrier requires no earlier pending request"
    );
    broker.request_diagnostics();
    let request = broker
        .diagnostics
        .pending
        .clone()
        .expect("the diagnostics barrier requires a pending request");
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        broker.poll();
        assert_eq!(
            broker.helper, "installed",
            "the diagnostics barrier requires an intact helper"
        );
        if broker.diagnostics.pending.as_deref() != Some(request.as_str()) {
            return;
        }
        assert!(
            Instant::now() < until,
            "diagnostics barrier timed out: helper={}, state={:?}, generation={:?}, diagnostics_pending={:?}",
            broker.helper,
            broker.connections.get("one").map(|c| c.view.state),
            broker.connections.get("one").map(|c| c.generation),
            broker.diagnostics.pending,
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub(super) fn commands(peer: &Peer) -> String {
    std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap_or_default()
}

pub(super) fn command_count(peer: &Peer, command: &str) -> usize {
    commands(peer)
        .lines()
        .filter(|line| *line == command)
        .count()
}

pub(super) fn intervals(peer: &Peer) -> Vec<serde_json::Value> {
    std::fs::read_to_string(peer.marker.with_extension("intervals"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

pub(super) fn no_secret(snapshot: &Snapshot) {
    let text = serde_json::to_string(snapshot).unwrap();
    assert!(!text.contains("fictional-client-secret"));
    assert!(!text.contains("fictional-psk"));
}

pub(super) fn no_secret_on_disk(peer: &Peer) {
    for entry in std::fs::read_dir(peer.root()).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("fictional-client-secret"));
        assert!(!text.contains("fictional-psk"));
    }
}

#[derive(Clone)]
pub(super) struct Delivered {
    pub id: String,
    pub title: String,
    pub body: String,
    pub current: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
pub(super) struct FakeNotifier(Arc<Mutex<Vec<Delivered>>>);
impl FakeNotifier {
    pub(super) fn sent(&self) -> Vec<Delivered> {
        self.0.lock().unwrap().clone()
    }
    pub(super) fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}
impl Notifier for FakeNotifier {
    fn send(&mut self, notice: Notice) {
        self.0.lock().unwrap().push(Delivered {
            id: notice.id,
            title: notice.title,
            body: notice.body,
            current: notice.current,
        });
    }
}
