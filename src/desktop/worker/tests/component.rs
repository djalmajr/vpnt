use super::*;
use crate::{helper::client::tests::Peer, install::client::Operation, localization::Locale};
use std::{fs, path::PathBuf, process::Command};

fn wait(mut condition: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(4);
    while !condition() {
        assert!(Instant::now() < until, "component actor timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
struct Release(PathBuf);
impl Drop for Release {
    fn drop(&mut self) {
        let _ = fs::write(self.0.join("release"), b"");
        let until = Instant::now() + Duration::from_secs(3);
        while self.0.join("started").exists()
            && !self.0.join("finished").exists()
            && Instant::now() < until
        {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
fn send(worker: &Worker, id: &str, command: serde_json::Value) {
    let body = serde_json::json!({"id":id,"command":command,"locale":"pt-BR"}).to_string();
    worker
        .send(crate::bridge::parse_request(&body).unwrap(), Instant::now())
        .unwrap();
}

#[test]
fn component_reply_keeps_its_native_request_id_and_waits_without_blocking_snapshot_or_hide() {
    let mut old = Peer::new("flow");
    let mut next = Peer::new("flow");
    let root = old.root().to_owned();
    let script = root.join("component.py");
    fs::write(&script, "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nassert (p/'peer.cleaned').exists()\n(p/'started').touch()\ndeadline=time.monotonic()+5\nwhile not (p/'release').exists() and time.monotonic()<deadline:time.sleep(0.005)\nassert (p/'release').exists()\n(p/'finished').touch()\n").unwrap();
    let directory = root.clone();
    let client = old.take();
    let mut new = Some(next.take());
    let (replies, receive) = mpsc::sync_channel(8);
    let worker = Worker::spawn(
        move || {
            let broker = Broker::component_fixture(
                client,
                Keychain(Err(SecretError::Unavailable)),
                move |kind, id, locale, expires| {
                    assert_eq!(locale, Locale::PtBr);
                    let mut command = Command::new("/usr/bin/python3");
                    command.arg(&script).arg(&directory);
                    Operation::fixture(kind, command, id, locale, expires)
                },
                move || new.take().ok_or(crate::helper::client::Error::Unavailable),
            );
            (None, Some(broker))
        },
        move |r| replies.send(r).unwrap(),
    )
    .unwrap();
    let _release = Release(root.clone());
    send(
        &worker,
        "initial",
        serde_json::json!({"type":"get_snapshot"}),
    );
    assert_eq!(
        receive
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .snapshot
            .unwrap()
            .helper,
        "installed"
    );
    send(
        &worker,
        "install-native",
        serde_json::json!({"type":"install_helper"}),
    );
    wait(|| root.join("started").exists());
    assert!(old.cleaned());
    send(
        &worker,
        "read-pending",
        serde_json::json!({"type":"get_snapshot"}),
    );
    let pending = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(pending.id, "read-pending");
    assert_eq!(
        serde_json::to_value(pending.snapshot.unwrap()).unwrap()["componentOperation"],
        "installing"
    );
    send(&worker, "hide-pending", serde_json::json!({"type":"hide"}));
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(1)).unwrap().id,
        "hide-pending"
    );
    send(
        &worker,
        "competing-remove",
        serde_json::json!({"type":"remove_helper"}),
    );
    let busy = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(busy.id, "competing-remove");
    assert_eq!(busy.error.as_deref(), Some("component_busy"));
    assert!(
        receive.try_recv().is_err(),
        "no installation receipt before child exit"
    );
    fs::write(root.join("release"), b"").unwrap();
    let installed = receive.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(installed.id, "install-native");
    assert!(installed.error.is_none());
    let snapshot = installed.snapshot.unwrap();
    assert_eq!(snapshot.helper, "installed");
    assert!(
        serde_json::to_value(snapshot)
            .unwrap()
            .get("componentOperation")
            .is_none()
    );
    assert!(root.join("finished").exists());
    send(&worker, "quit", serde_json::json!({"type":"quit"}));
    assert_eq!(
        receive.recv_timeout(Duration::from_secs(1)).unwrap().id,
        "quit"
    );
    drop(worker);
    wait(|| next.cleaned());
}
