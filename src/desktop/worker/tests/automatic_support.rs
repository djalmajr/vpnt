use super::*;
use crate::{helper::client::tests::Peer, model::Snapshot};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};

pub(super) struct BlockingSecrets {
    pub loads: Arc<AtomicUsize>,
    pub entered: mpsc::SyncSender<()>,
    pub gate: Arc<(Mutex<bool>, Condvar)>,
}
impl SecretStore for BlockingSecrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        Ok(true)
    }
    fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, SecretError> {
        let count = self.loads.fetch_add(1, Ordering::SeqCst) + 1;
        if count == 2 {
            let _ = self.entered.send(());
            let (lock, released) = &*self.gate;
            let mut ready = lock.lock().unwrap();
            while !*ready {
                ready = released.wait(ready).unwrap();
            }
        }
        Ok(Credentials {
            password: "fictional-client-secret".into(),
            psk: "".into(),
        })
    }
    fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
        Ok(())
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
        Ok(())
    }
}

pub(super) struct Release(Arc<(Mutex<bool>, Condvar)>);
impl Release {
    pub(super) fn new(gate: Arc<(Mutex<bool>, Condvar)>) -> Self {
        Self(gate)
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        let (lock, released) = &*self.0;
        *lock.lock().unwrap() = true;
        released.notify_all();
    }
}

pub(super) fn send(worker: &Worker, id: &str, command: serde_json::Value) {
    let body = serde_json::json!({"id":id,"command":command}).to_string();
    worker
        .send(crate::bridge::parse_request(&body).unwrap(), Instant::now())
        .unwrap();
}
pub(super) fn snapshot(worker: &Worker, replies: &mpsc::Receiver<Reply>, id: &str) -> Snapshot {
    send(worker, id, serde_json::json!({"type":"get_snapshot"}));
    let reply = replies.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(reply.id, id);
    reply.snapshot.unwrap()
}
pub(super) fn wait_idle(worker: &Worker) {
    let start = worker.idle_cycles.load(Ordering::Acquire);
    let until = Instant::now() + Duration::from_secs(3);
    while worker
        .idle_cycles
        .load(Ordering::Acquire)
        .saturating_sub(start)
        < 2
    {
        assert!(
            Instant::now() < until,
            "actor did not complete two idle turns"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
pub(super) fn wait_state(
    worker: &Worker,
    replies: &mpsc::Receiver<Reply>,
    id: &str,
    expected: crate::session::ConnectionState,
) -> Snapshot {
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        let current = snapshot(worker, replies, "state");
        if current
            .vpns
            .iter()
            .any(|v| v.profile.id == id && v.state == expected)
        {
            return current;
        }
        assert!(Instant::now() < until, "worker state was not reached");
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(super) fn command_count(peer: &Peer, command: &str) -> usize {
    std::fs::read_to_string(peer.marker.with_extension("commands"))
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == command)
        .count()
}
