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
