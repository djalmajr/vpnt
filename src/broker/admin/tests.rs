use super::*;
use crate::helper::client::tests::Peer;
use std::{
    fs,
    process::Command as Process,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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
}
impl Harness {
    fn new(mode: &str) -> Self {
        let mut peer = Peer::new("flow");
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
        wait(|| broker.snapshot().helper == "installed");
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
        let mode = mode.to_string();
        broker.administration.connect = Box::new(move |request, locale, expires| {
            calls.fetch_add(1, Ordering::Relaxed);
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
        }
    }
    fn command(&mut self, command: Command) -> Snapshot {
        self.broker
            .dispatch(command, Instant::now() + Duration::from_secs(2))
            .unwrap()
    }
    fn begin(&mut self, command: Command) -> u64 {
        self.broker
            .begin_admin(
                command,
                Locale::PtBr,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap()
    }
    fn authorize(&self) {
        fs::write(self.peer.marker.with_extension("authorize"), b"").unwrap();
    }
    fn result(&mut self) -> (u64, Result<Snapshot, &'static str>) {
        let mut result = None;
        wait(|| {
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
            let until = Instant::now() + Duration::from_secs(3);
            while !op.client.finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
fn wait(mut predicate: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(4);
    while !predicate() {
        assert!(Instant::now() < until, "broker admin condition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn a_profile_change_waits_for_reap_and_fresh_metadata_while_another_profile_remains_controllable() {
    let mut h = Harness::new("save");
    h.command(Command::Toggle { id: "one".into() });
    h.peer.advance();
    wait(|| h.broker.snapshot().vpns[0].state == State::Connected);
    let mut edited = h.broker.snapshot().vpns[1].profile.clone();
    edited.name = "Edited by administrator".into();
    let token = h.begin(Command::SaveProfile {
        profile: edited.clone(),
    });
    h.command(Command::Probe { id: "one".into() });
    wait(|| h.broker.snapshot().vpns[0].state == State::Unresponsive);
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
    wait(|| h.broker.snapshot().vpns[0].state == State::Off);
}
#[test]
fn active_profiles_do_not_prompt_and_secrets_are_removed_only_after_confirmed_removal() {
    let mut h = Harness::new("save");
    h.command(Command::Toggle { id: "one".into() });
    h.peer.advance();
    wait(|| h.broker.snapshot().vpns[0].state == State::Connected);
    assert_eq!(
        h.broker.begin_admin(
            Command::RemoveProfile { id: "one".into() },
            Locale::EnUs,
            Instant::now() + Duration::from_secs(2)
        ),
        Err("profile_busy")
    );
    assert_eq!(h.starts.load(Ordering::Relaxed), 0);
    h.begin(Command::RemoveProfile { id: "two".into() });
    assert_eq!(h.removes.load(Ordering::Relaxed), 0);
    assert!(matches!(
        h.broker.dispatch(
            Command::Toggle { id: "two".into() },
            Instant::now() + Duration::from_secs(2)
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
            Instant::now() + Duration::from_secs(2)
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
    h.broker
        .begin_admin(
            Command::SaveProfile { profile: p },
            Locale::PtBr,
            Instant::now() + Duration::from_millis(150),
        )
        .unwrap();
    assert!(matches!(h.result().1, Err("admin_expired")));
    h.authorize();
    wait(|| {
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
    wait(|| {
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
