use super::*;
use crate::{
    helper::client::tests::Peer,
    secrets::{Credentials, SecretError},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod automatic_interval;
mod automatic_notifications;
mod automatic_reconnect;
mod automatic_support;
mod failure_note;
mod ipsec_dispatch;
mod manual_intent;
mod recovery;
#[derive(Clone)]
struct Secrets {
    loads: Arc<AtomicUsize>,
    delay: Duration,
}
impl Secrets {
    fn new() -> Self {
        Self {
            loads: Arc::new(AtomicUsize::new(0)),
            delay: Duration::ZERO,
        }
    }
}
impl SecretStore for Secrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        Ok(true)
    }
    fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, SecretError> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(self.delay);
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
fn wait<S: SecretStore>(b: &mut Broker<S>, mut predicate: impl FnMut(&Snapshot) -> bool) {
    let until = Instant::now() + Duration::from_secs(4);
    loop {
        let s = b.snapshot();
        if predicate(&s) {
            return;
        }
        assert!(Instant::now() < until, "broker condition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn dispatch(b: &mut Broker<Secrets>, c: Command) -> Snapshot {
    b.dispatch(c, Instant::now() + Duration::from_secs(2))
        .unwrap()
}
#[test]
fn build_identity_marks_old_helpers_outdated_without_disabling_tunnels() {
    for (mode, expected, packaged) in [
        ("flow", "installed", true),
        ("build-different", "outdated", true),
        ("build-missing", "outdated", true),
        ("flow", "outdated", false),
    ] {
        let mut peer = Peer::new(mode);
        let root = peer.root().to_owned();
        let mut broker = Broker::new(Some(peer.take()), Secrets::new());
        if !packaged {
            broker.expected_build = None;
        }
        let until = Instant::now() + Duration::from_secs(4);
        while !broker.ready {
            broker.poll();
            assert!(
                Instant::now() < until,
                "{mode} did not produce an initial snapshot"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(broker.snapshot().helper, expected, "mode: {mode}");
        dispatch(&mut broker, Command::Connect { id: "one".into() });
        peer.advance();
        wait(&mut broker, |s| s.vpns[0].state == State::Connected);
        assert_eq!(broker.snapshot().helper, expected);
        assert!(!peer.retiring(), "{mode} must keep its helper alive");
        dispatch(&mut broker, Command::Disconnect { id: "one".into() });
        wait(&mut broker, |s| s.vpns[0].state == State::Off);
        assert_eq!(broker.snapshot().helper, expected);
        if expected == "outdated" {
            let commands = std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap();
            assert!(
                !commands.lines().any(|line| line == "diagnostics"),
                "old helper must never receive an unsupported diagnostic command"
            );
        }
        drop(broker);
        drop(peer);
        assert!(!root.exists(), "fixture {mode} did not clean up");
    }
}

#[test]
fn completed_attempts_request_diagnostics_and_publish_the_redacted_reply() {
    for case in ["credentials_rejected", "dropped", "disconnect"] {
        let mut peer = Peer::new("flow");
        let root = peer.root().to_owned();
        let home = root.join("fixture-home");
        std::fs::create_dir(&home).unwrap();
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(home.join("Library")).unwrap();
        std::fs::create_dir(home.join("Library/Application Support")).unwrap();
        let saved = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = saved.clone();
        let uid = unsafe { libc::geteuid() };
        let sink_home = home.clone();
        let mut broker = Broker::new(Some(peer.take()), Secrets::new());
        broker.diagnostics.with_sink(move |text| {
            diagnostics::save_at(&sink_home, uid, &text).unwrap();
            sink.lock().unwrap().push(text);
        });
        wait(&mut broker, |snapshot| snapshot.helper == "installed");
        dispatch(&mut broker, Command::Connect { id: "one".into() });
        wait(&mut broker, |snapshot| {
            snapshot.vpns[0].state == State::Connecting
        });
        assert!(
            saved.lock().unwrap().is_empty(),
            "no diagnostic before an attempt finishes: {case}"
        );
        if case != "credentials_rejected" {
            peer.advance();
            wait(&mut broker, |snapshot| {
                snapshot.vpns[0].state == State::Connected
            });
        }
        if case == "disconnect" {
            dispatch(&mut broker, Command::Disconnect { id: "one".into() });
        } else {
            let generation = broker.connections["one"].generation;
            std::fs::write(peer.marker.with_extension("stale"), serde_json::to_vec(&serde_json::json!({"id":"one", "generation":generation, "state":case, "failures":0})).unwrap()).unwrap();
        }
        let until = Instant::now() + Duration::from_secs(4);
        while saved.lock().unwrap().is_empty() {
            broker.poll();
            assert!(Instant::now() < until, "diagnostic not saved after {case}");
            std::thread::sleep(Duration::from_millis(5));
        }
        let text = saved.lock().unwrap()[0].clone();
        assert!(text.contains("== openfortivpn.log"));
        assert!(text.contains("== charon.previous.log"));
        assert!(text.contains("ausente"));
        let file = home
            .join("Library/Application Support")
            .join(crate::identifiers::APP)
            .join("diagnostics.txt");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o7777, 0o600);
        let commands = std::fs::read_to_string(peer.marker.with_extension("commands")).unwrap();
        assert_eq!(
            commands
                .lines()
                .filter(|line| *line == "diagnostics")
                .count(),
            1,
            "{case}: {commands}"
        );
        drop(broker);
        drop(peer);
        assert!(!root.exists(), "fixture cleanup: {case}");
    }
}

#[test]
fn helper_acceptance_never_claims_traffic_and_cancel_rejects_late_connected_generations() {
    let mut peer = Peer::new("flow");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    let s = dispatch(&mut broker, Command::Toggle { id: "one".into() });
    assert_eq!(s.vpns[0].state, State::Connecting);
    // Observe the real Broker consumer, not elapsed time or a peer send marker.
    // Keep the request identity so another acceptance cannot satisfy the barrier.
    let request = broker.connections["one"]
        .pending
        .as_ref()
        .unwrap()
        .id
        .clone();
    let deadline = Instant::now() + Duration::from_secs(4);
    let waiting = loop {
        let snapshot = broker.snapshot();
        if broker.connections["one"]
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == request && pending.accepted)
        {
            break snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "Broker did not consume the connect Accepted receipt"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    // Changed(Connecting) may overwrite a transient invented Connected state;
    // the retained history must also remain free of fabricated traffic proof.
    assert_eq!(waiting.vpns[0].state, State::Connecting);
    assert!(
        !waiting.vpns[0]
            .log
            .iter()
            .any(|entry| entry.state == State::Connected),
        "acceptance cannot invent a traffic check in the log"
    );
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    wait(&mut broker, |s| s.vpns[0].state == State::Off);
    peer.advance();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(broker.snapshot().vpns[0].state, State::Off);
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    dispatch(&mut broker, Command::Probe { id: "one".into() });
    wait(&mut broker, |s| s.vpns[0].state != State::Connected);
    assert_eq!(broker.snapshot().vpns[0].state, State::Unresponsive);
    dispatch(&mut broker, Command::Toggle { id: "two".into() });
    wait(&mut broker, |s| {
        s.vpns
            .iter()
            .all(|v| matches!(v.state, State::Connected | State::Unresponsive))
    });
    dispatch(&mut broker, Command::DisconnectAll {});
    wait(&mut broker, |s| {
        s.vpns.iter().all(|v| v.state != State::Disconnecting)
    });
    assert!(broker.snapshot().vpns.iter().all(|v| v.state == State::Off));
    assert_eq!(loads.load(Ordering::Relaxed), 3);
    assert!(
        !serde_json::to_string(&broker.snapshot())
            .unwrap()
            .contains("fictional-client-secret")
    );
}
#[test]
fn incompatible_helper_or_expired_keychain_load_cannot_receive_credentials_or_start_a_tunnel() {
    for mode in ["version", "old2"] {
        let mut peer = Peer::new(mode);
        let secrets = Secrets::new();
        let loads = secrets.loads.clone();
        let mut broker = Broker::new(Some(peer.take()), secrets);
        wait(&mut broker, |s| s.helper == "outdated");
        assert_eq!(
            broker
                .dispatch(
                    Command::Toggle { id: "one".into() },
                    Instant::now() + Duration::from_secs(1)
                )
                .err(),
            Some("not_found")
        );
        assert_eq!(loads.load(Ordering::Relaxed), 0);
    }
    let mut peer = Peer::new("flow");
    let mut secrets = Secrets::new();
    secrets.delay = Duration::from_millis(30);
    let mut broker = Broker::new(Some(peer.take()), secrets);
    wait(&mut broker, |s| s.helper == "installed");
    assert!(
        broker
            .dispatch(
                Command::Toggle { id: "one".into() },
                Instant::now() + Duration::from_millis(10)
            )
            .is_err()
    );
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(broker.snapshot().vpns[0].state, State::Off);
}
#[test]
fn helper_loss_removes_connected_indications_without_turning_process_exit_into_off() {
    let mut peer = Peer::new("exit");
    let mut broker = Broker::new(Some(peer.take()), Secrets::new());
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    wait(&mut broker, |s| {
        s.helper == "missing" && s.vpns.iter().all(|v| v.state == State::HelperMissing)
    });
    assert!(
        broker
            .dispatch(
                Command::SetDemoState {
                    id: "one".into(),
                    state: State::Connected
                },
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
    );
}

#[test]
fn native_isolated_keychain_supplies_the_child_without_putting_credentials_in_the_snapshot() {
    use core_foundation::base::TCFType;
    use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainDelete(keychain: security_framework_sys::base::SecKeychainRef) -> i32;
    }
    struct Disposable(Option<SecKeychain>);
    impl Disposable {
        fn cleanup(&mut self) -> i32 {
            self.0
                .take()
                .map_or(0, |k| unsafe { SecKeychainDelete(k.as_concrete_TypeRef()) })
        }
    }
    impl Drop for Disposable {
        fn drop(&mut self) {
            self.cleanup();
        }
    }
    let mut peer = Peer::new("flow");
    let default = SecKeychain::default().unwrap();
    let before = std::process::Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .output()
        .unwrap();
    assert!(before.status.success());
    let _interaction = SecKeychain::disable_user_interaction().unwrap();
    let mut chain = Disposable(Some(
        CreateOptions::new()
            .password("fictional-broker-database")
            .prompt_user(false)
            .create(peer.root().join("broker.keychain"))
            .unwrap(),
    ));
    let store = crate::keychain::MacKeychain::from_keychain(chain.0.as_ref().unwrap().clone());
    let mut broker = Broker::new(Some(peer.take()), store);
    wait(&mut broker, |s| s.helper == "installed");
    assert!(broker.snapshot().vpns.iter().all(|v| !v.has_password));
    broker
        .dispatch(
            Command::SaveSecrets {
                id: "one".into(),
                password: "fictional-client-secret".into(),
                psk: "".into(),
            },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    broker
        .dispatch(
            Command::Toggle { id: "one".into() },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    peer.advance();
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    let s = broker.snapshot();
    assert!(s.vpns[0].has_password && !s.vpns[1].has_password && !s.demo);
    assert!(
        !serde_json::to_string(&s)
            .unwrap()
            .contains("fictional-client-secret")
    );
    drop(broker);
    assert_eq!(chain.cleanup(), 0);
    drop(chain);
    assert!(default == SecKeychain::default().unwrap());
    let after = std::process::Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .output()
        .unwrap();
    assert!(after.status.success());
    assert!(before.stdout == after.stdout);
}

#[test]
fn an_initial_connected_snapshot_is_rejected_before_any_credential_load() {
    let mut peer = Peer::new("unearned");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut b = Broker::new(Some(peer.take()), secrets);
    let until = Instant::now() + Duration::from_secs(4);
    while b.starting() {
        b.poll();
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    let s = b.snapshot();
    assert_eq!(s.helper, "missing");
    assert!(s.vpns.is_empty());
    assert_eq!(loads.load(Ordering::Relaxed), 0);
}
