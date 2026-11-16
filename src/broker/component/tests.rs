use super::*;
use crate::{helper::client::tests::Peer, secrets::SecretError};
use std::{
    fs,
    process::Command as Process,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
mod lifecycle;
struct Secrets(Arc<AtomicUsize>);
impl SecretStore for Secrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        Ok(true)
    }
    fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, SecretError> {
        Err(SecretError::Unavailable)
    }
    fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
        Ok(())
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
fn wait(mut check: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(4);
    while !check() {
        assert!(Instant::now() < end, "component broker timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn component_install_refuses_live_or_cleaning_connections_before_admission() {
    let mut peer = Peer::new("flow");
    let root = peer.root().to_owned();
    let mut broker = Broker::new(Some(peer.take()), Secrets(Arc::new(AtomicUsize::new(0))));
    wait(|| broker.snapshot().helper == "installed");
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    broker.component.connect = Box::new(move |_, _, _, _| {
        observed.fetch_add(1, Ordering::Relaxed);
        Err(ComponentError::Unavailable)
    });
    for state in [
        State::Connecting,
        State::Verifying,
        State::Connected,
        State::Unresponsive,
        State::Reconnecting,
        State::Disconnecting,
    ] {
        broker.connections.get_mut("one").unwrap().view.state = state;
        assert_eq!(
            broker.begin_component(
                Command::InstallHelper {},
                Locale::EnUs,
                Instant::now() + Duration::from_secs(2)
            ),
            Err("component_busy"),
            "state: {state:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(!peer.retiring());
    }
    let connection = broker.connections.get_mut("one").unwrap();
    connection.view.state = State::Dropped;
    connection.view.cleaning = true;
    assert_eq!(
        broker.begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(2)
        ),
        Err("component_busy")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    broker.connections.get_mut("one").unwrap().view.cleaning = false;
    assert_eq!(
        broker.begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(2)
        ),
        Err("component_unconfirmed")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!peer.retiring());
    drop(broker);
    drop(peer);
    assert!(!root.exists(), "fixture peer did not finish and clean up");
}

#[test]
fn component_install_rechecks_activity_after_admission_before_runtime_handoff() {
    let mut peer = Peer::new("flow");
    let mut broker = Broker::new(Some(peer.take()), Secrets(Arc::new(AtomicUsize::new(0))));
    wait(|| broker.snapshot().helper == "installed");
    let root = peer.root().to_owned();
    let script = root.join("must-not-start.py");
    fs::write(
        &script,
        "import pathlib,sys\npathlib.Path(sys.argv[1]).joinpath('must-not-start').touch()\n",
    )
    .unwrap();
    let directory = root.clone();
    broker.component.connect = Box::new(move |kind, id, locale, expires| {
        let mut command = Process::new("/usr/bin/python3");
        command.arg(&script).arg(&directory);
        Operation::fixture(kind, command, id, locale, expires)
    });
    let token = broker
        .begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    wait(|| broker.component.current.as_ref().unwrap().client.prepared());
    broker.connections.get_mut("one").unwrap().view.state = State::Connecting;
    let mut result = None;
    wait(|| {
        broker.poll();
        result = broker.take_component_result();
        result.is_some()
    });
    let (actual, result) = result.unwrap();
    assert_eq!(actual, token);
    assert_eq!(result.unwrap_err(), "component_busy");
    assert!(!peer.retiring());
    assert!(!root.join("must-not-start").exists());
    wait(|| {
        broker.poll();
        !broker.component_busy()
    });
    assert_eq!(broker.snapshot().helper, "installed");
    drop(broker);
    drop(peer);
    assert!(!root.exists(), "fixture peer did not finish and clean up");
}

#[test]
fn installation_waits_for_runtime_cleanup_then_for_its_child_and_a_fresh_authenticated_snapshot() {
    let mut old = Peer::new("flow");
    let mut new = Peer::new("flow");
    let removes = Arc::new(AtomicUsize::new(0));
    let mut broker = Broker::new(Some(old.take()), Secrets(removes.clone()));
    wait(|| broker.snapshot().helper == "installed");
    let calls = Arc::new(AtomicUsize::new(0));
    let attempts = calls.clone();
    let mut next = Some(new.take());
    broker.retry = Some(retry::Retry::fixture(move || {
        attempts.fetch_add(1, Ordering::Relaxed);
        next.take().ok_or(Error::Unavailable)
    }));
    let root = old.root().to_owned();
    let script = root.join("install.py");
    fs::write(&script,"import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nassert (p/'peer.cleaned').exists()\n(p/'component_started').touch()\ndeadline=time.monotonic()+5\nwhile not (p/'component_release').exists() and time.monotonic()<deadline:time.sleep(0.005)\nassert (p/'component_release').exists()\n(p/'component_finished').touch()\n").unwrap();
    let directory = root.clone();
    broker.component.connect = Box::new(move |kind, id, locale, expires| {
        let mut command = Process::new("/usr/bin/python3");
        command.arg(&script).arg(&directory);
        Operation::fixture(kind, command, id, locale, expires)
    });
    let token = broker
        .begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_secs(3),
        )
        .expect("install must start through the asynchronous component flow");
    wait(|| {
        broker.poll();
        root.join("component_started").exists()
    });
    assert!(old.cleaned());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(broker.take_component_result().is_none());
    let snapshot = broker
        .dispatch(
            Command::GetSnapshot {},
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(snapshot.helper, "missing");
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["componentOperation"],
        "installing"
    );
    assert!(
        broker
            .begin_component(
                Command::RemoveHelper {},
                Locale::PtBr,
                Instant::now() + Duration::from_secs(2)
            )
            .is_err()
    );
    fs::write(root.join("component_release"), b"").unwrap();
    let mut result = None;
    wait(|| {
        broker.poll();
        result = broker.take_component_result();
        result.is_some()
    });
    let (got, done) = result.unwrap();
    assert_eq!(got, token);
    assert_eq!(done.unwrap().helper, "installed");
    assert!(root.join("component_finished").exists());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(removes.load(Ordering::Relaxed), 0);
}
