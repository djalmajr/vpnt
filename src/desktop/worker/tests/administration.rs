use super::*;
use crate::{
    helper::{admin_client::Admin, client::tests::Peer},
    model::Snapshot,
};
use core_foundation::base::TCFType;
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use std::{fs, process::Command};
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainDelete(keychain: security_framework_sys::base::SecKeychainRef) -> i32;
}
struct Disposable(Option<SecKeychain>);
impl Disposable {
    fn cleanup(&mut self) -> i32 {
        self.0
            .take()
            .map_or(0, |c| unsafe { SecKeychainDelete(c.as_concrete_TypeRef()) })
    }
}
impl Drop for Disposable {
    fn drop(&mut self) {
        self.cleanup();
    }
}
fn wait(mut predicate: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(4);
    while !predicate() {
        assert!(
            Instant::now() < until,
            "native administrative worker condition timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn send(worker: &Worker, id: &str, command: serde_json::Value) {
    let body =
        serde_json::to_string(&serde_json::json!({"id":id,"command":command,"locale":"pt-BR"}))
            .unwrap();
    worker
        .send(crate::bridge::parse_request(&body).unwrap(), Instant::now())
        .unwrap();
}
#[test]
fn administrative_reply_waits_for_commit_while_native_commands_and_the_keychain_keep_working() {
    let default = SecKeychain::default().unwrap();
    let search = Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .output()
        .unwrap();
    assert!(search.status.success());
    let _interaction = SecKeychain::disable_user_interaction().unwrap();
    let mut peer = Peer::new("flow");
    let mut chain = Disposable(Some(
        CreateOptions::new()
            .password("fictional-admin-fixture")
            .prompt_user(false)
            .create(peer.root().join("actor.keychain"))
            .unwrap(),
    ));
    let keychain = Keychain(Ok(MacKeychain::from_keychain(
        chain.0.as_ref().unwrap().clone(),
    )));
    let client = peer.take();
    let marker = peer.marker.clone();
    let (replies, receive) = mpsc::sync_channel(8);
    let worker = Worker::spawn(
        move || {
            let broker = Broker::administrative_fixture(
                client,
                keychain,
                move |request, locale, expires| {
                    let mut command = Command::new("/usr/bin/python3");
                    command
                        .arg(
                            std::env::current_dir()
                                .unwrap()
                                .join("tests/fixtures/broker-admin/peer.py"),
                        )
                        .arg(&marker)
                        .arg("save");
                    Admin::fixture(command, request, locale, expires)
                },
            );
            (None, Some(broker))
        },
        move |reply| replies.send(reply).unwrap(),
    )
    .unwrap();
    send(
        &worker,
        "initial",
        serde_json::json!({"type":"get_snapshot"}),
    );
    let initial = receive
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .snapshot
        .unwrap();
    assert!(!initial.demo);
    fs::write(
        peer.marker.with_extension("catalog"),
        serde_json::to_vec(
            &initial
                .vpns
                .iter()
                .map(|v| v.profile.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    )
    .unwrap();
    send(
        &worker,
        "credentials",
        serde_json::json!({"type":"save_secrets","id":"one","password":"fictional-client-secret","psk":""}),
    );
    assert!(
        receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .error
            .is_none()
    );
    send(
        &worker,
        "connect",
        serde_json::json!({"type":"toggle","id":"one"}),
    );
    assert!(
        receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .error
            .is_none()
    );
    peer.advance();
    let mut current: Option<Snapshot> = None;
    wait(|| {
        send(&worker, "state", serde_json::json!({"type":"get_snapshot"}));
        current = receive
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .snapshot;
        current.as_ref().unwrap().vpns[0].state == crate::session::ConnectionState::Connected
    });
    let mut edited = current.unwrap().vpns[1].profile.clone();
    edited.name = "Native actor confirmed".into();
    send(
        &worker,
        "save",
        serde_json::json!({"type":"save_profile","profile":edited}),
    );
    wait(|| peer.marker.with_extension("admin_started").exists());
    send(
        &worker,
        "probe",
        serde_json::json!({"type":"probe","id":"one"}),
    );
    let probe = receive.recv_timeout(Duration::from_secs(2));
    assert!(
        probe
            .as_ref()
            .is_ok_and(|r| r.id == "probe" && r.error.is_none()),
        "administration cannot block native commands"
    );
    assert!(!peer.marker.with_extension("admin_finished").exists());
    fs::write(peer.marker.with_extension("authorize"), b"").unwrap();
    let saved = receive.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(saved.id, "save");
    assert!(saved.error.is_none());
    let snapshot = saved.snapshot.unwrap();
    assert_eq!(snapshot.vpns[1].profile, edited);
    assert_eq!(
        snapshot.vpns[0].state,
        crate::session::ConnectionState::Unresponsive
    );
    assert!(snapshot.vpns[0].has_password);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("fictional-client-secret")
    );
    send(&worker, "quit", serde_json::json!({"type":"quit"}));
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(2)).unwrap().id,
        "quit"
    );
    drop(worker);
    wait(|| peer.cleaned());
    assert_eq!(chain.cleanup(), 0);
    assert!(SecKeychain::default().unwrap() == default);
    let after = Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .output()
        .unwrap();
    assert!(after.status.success());
    assert!(after.stdout == search.stdout);
}
