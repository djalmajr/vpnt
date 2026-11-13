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
    let until = Instant::now() + Duration::from_secs(4);
    while broker.connections[id].failures != failures {
        broker.poll();
        assert!(
            Instant::now() < until,
            "the helper failure counter did not reach {failures}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(state(&broker.snapshot(), id), State::Unresponsive);
}

pub(super) fn automatic<S: SecretStore>(broker: &mut Broker<S>) {
    broker.perform_automatic(|| true);
}

/// The peer sends the injected stale frame before it answers this probe; the
/// probe request/answer are the FIFO barrier that proves the Broker consumed
/// the stale frame on the ordered Client stream. The peer stays fake/in-process.
pub(super) fn consume_stale_with_probe<S: SecretStore>(broker: &mut Broker<S>, peer: &Peer) {
    std::fs::write(peer.marker.with_extension("probe_ok"), b"").unwrap();
    run(broker, Command::Probe { id: "one".into() }).unwrap();
    let probe = broker.connections["one"]
        .pending
        .as_ref()
        .expect("probe pending")
        .id
        .clone();
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        broker.poll();
        assert_eq!(
            broker.helper, "installed",
            "the probe barrier requires an intact helper"
        );
        if broker.connections["one"]
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == probe && pending.accepted)
        {
            return;
        }
        assert!(Instant::now() < until, "probe barrier timed out");
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
