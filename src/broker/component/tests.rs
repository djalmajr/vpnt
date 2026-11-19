use super::*;
use crate::{helper::client::tests::Peer, secrets::SecretError};
use std::{
    fs,
    panic::Location,
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
#[track_caller]
fn wait_stage(stage: &str, mut check: impl FnMut() -> bool) {
    // Hang guard only. Every condition below is reachable: the fixture marks
    // its read loop before the broker arms the 5 s startup deadline, the
    // installer publishes `prepared` before waiting for `proceed`, and the
    // test sets the busy state before polling.
    let started = Instant::now();
    let end = started + Duration::from_secs(60);
    while !check() {
        assert!(
            Instant::now() < end,
            "{stage}: component broker condition timed out after {:?} at {}",
            started.elapsed(),
            Location::caller()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
/// Compatibility for the lifecycle submodule, whose waits are outside this
/// slice; it still gets stage, elapsed time and caller through `wait_stage`.
#[track_caller]
fn wait(check: impl FnMut() -> bool) {
    wait_stage("component lifecycle condition", check)
}
/// The fixture writes `.started` from inside its read loop; the broker's
/// startup deadline is armed only after this returns.
fn flow_peer() -> Peer {
    let peer = Peer::new("flow");
    let marker = peer.marker.with_extension("started");
    wait_stage("runtime fixture read loop", || marker.exists());
    peer
}

#[test]
fn component_install_refuses_live_or_cleaning_connections_before_admission() {
    let mut peer = flow_peer();
    let root = peer.root().to_owned();
    let mut broker = Broker::new(Some(peer.take()), Secrets(Arc::new(AtomicUsize::new(0))));
    wait_stage("initial installed snapshot", || {
        broker.snapshot().helper == "installed"
    });
    // The installed snapshot triggers two capability queries. Their replies
    // carry the fixture's `off` state and would overwrite the states this test
    // forces below if they arrived during `begin_component`. The local
    // fixture answers at once, so the wait keeps the 3.5 s bound the first
    // admission used to impose on these polls: one 3 s pause fits, a slower
    // `poll` does not.
    let replies = Instant::now();
    wait_stage("initial capability replies", || {
        broker.poll();
        broker.cleanup_probe.is_none() && broker.failure_probe.is_none()
    });
    assert!(
        replies.elapsed() <= Duration::from_millis(3500),
        "initial capability replies took {:?}, limit 3.5 s",
        replies.elapsed()
    );
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
                Instant::now() + Duration::from_millis(3500)
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
            Instant::now() + Duration::from_millis(3500)
        ),
        Err("component_busy")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    broker.connections.get_mut("one").unwrap().view.cleaning = false;
    assert_eq!(
        broker.begin_component(
            Command::InstallHelper {},
            Locale::EnUs,
            Instant::now() + Duration::from_millis(3500)
        ),
        Err("component_unconfirmed")
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(!peer.retiring());
    drop(broker);
    // `Peer::drop` waits only 3 s for the worker; observe cleanup first.
    wait_stage("runtime worker cleanup", || peer.cleaned());
    drop(peer);
    assert!(!root.exists(), "fixture peer did not finish and clean up");
}

#[test]
fn component_install_rechecks_activity_after_admission_before_runtime_handoff() {
    let mut peer = flow_peer();
    let mut broker = Broker::new(Some(peer.take()), Secrets(Arc::new(AtomicUsize::new(0))));
    wait_stage("initial installed snapshot", || {
        broker.snapshot().helper == "installed"
    });
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
            // Guard for fixture preparation, not the property under test: the
            // installer stays prepared until the recheck calls `proceed`.
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
    wait_stage("installer prepared", || {
        broker.component.current.as_ref().unwrap().client.prepared()
    });
    broker.connections.get_mut("one").unwrap().view.state = State::Connecting;
    broker.poll_component();
    let (actual, result) = broker
        .take_component_result()
        .expect("an already-prepared install must reject activity on this poll");
    assert_eq!(actual, token);
    assert_eq!(result.unwrap_err(), "component_busy");
    assert!(!peer.retiring());
    assert!(!root.join("must-not-start").exists());
    wait_stage("component operation cleared", || {
        broker.poll();
        !broker.component_busy()
    });
    assert_eq!(broker.snapshot().helper, "installed");
    drop(broker);
    wait_stage("runtime worker cleanup", || peer.cleaned());
    drop(peer);
    assert!(!root.exists(), "fixture peer did not finish and clean up");
}

#[test]
fn installation_waits_for_runtime_cleanup_then_for_its_child_and_a_fresh_authenticated_snapshot() {
    let mut old = flow_peer();
    let mut new = flow_peer();
    let removes = Arc::new(AtomicUsize::new(0));
    let mut broker = Broker::new(Some(old.take()), Secrets(removes.clone()));
    wait_stage("initial installed snapshot", || {
        broker.snapshot().helper == "installed"
    });
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
            // Guard for cleanup + preparation + child spawn: 3 s pause < 15 s.
            Instant::now() + Duration::from_secs(15),
        )
        .expect("install must start through the asynchronous component flow");
    wait_stage("installer child started", || {
        broker.poll();
        root.join("component_started").exists()
    });
    assert!(old.cleaned());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(broker.take_component_result().is_none());
    let snapshot = broker
        .dispatch(
            Command::GetSnapshot {},
            Instant::now() + Duration::from_millis(3500),
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
    wait_stage("installer completion after release", || {
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

#[test]
fn installation_requires_a_fresh_installed_snapshot_even_if_old_session_was_installed() {
    struct Release(std::path::PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = fs::write(&self.0, b"");
        }
    }

    let mut old = flow_peer();
    let mut new = flow_peer();
    let mut broker = Broker::new(Some(old.take()), Secrets(Arc::new(AtomicUsize::new(0))));
    wait_stage("initial installed snapshot", || {
        broker.snapshot().helper == "installed"
    });
    let old_epoch = broker.epoch;
    assert!(broker.ready);
    let mut next = Some(new.take());
    broker.retry = Some(retry::Retry::fixture(move || {
        next.take().ok_or(Error::Unavailable)
    }));
    let root = old.root().to_owned();
    let script = root.join("fresh-snapshot-install.py");
    fs::write(&script, "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\n(p/'started').touch()\ndeadline=time.monotonic()+10\nwhile not (p/'release').exists() and time.monotonic()<deadline: time.sleep(0.005)\nassert (p/'release').exists()\n").unwrap();
    let release = Release(root.join("release"));
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
            Instant::now() + Duration::from_secs(8),
        )
        .unwrap();
    wait_stage("fresh installer started", || {
        broker.poll();
        root.join("started").exists()
    });
    assert!(old.cleaned());
    assert_eq!(broker.epoch, old_epoch);
    // Reproduce a retained installed snapshot from the old epoch, without
    // delivering a new helper message while the installer finishes.
    broker.helper = "installed";
    broker.ready = true;
    fs::write(&release.0, b"").unwrap();
    wait_stage("installer verifying fresh snapshot", || {
        broker.poll_component();
        assert!(
            broker.take_component_result().is_none(),
            "old installed snapshot must not confirm installation"
        );
        broker
            .component
            .current
            .as_ref()
            .is_some_and(|op| op.phase == Phase::Verifying)
    });
    assert_eq!(broker.epoch, old_epoch);
    assert_eq!(broker.component.current.as_ref().unwrap().epoch, old_epoch);
    let mut completion = None;
    wait_stage("fresh installer completion", || {
        broker.poll();
        completion = broker.take_component_result();
        completion.is_some()
    });
    let (actual, result) = completion.unwrap();
    assert_eq!(actual, token);
    assert_eq!(result.unwrap().helper, "installed");
    assert!(broker.ready);
    assert!(broker.epoch > old_epoch);
}

#[test]
fn previous_session_finishing_installer_error_round_trips_and_maps_distinctly() {
    let reply = crate::install::protocol::Reply::Failed {
        id: Some("fixture".into()),
        error: crate::install::Error::PreviousSessionFinishing,
    };
    let wire = serde_json::to_vec(&reply).unwrap();
    let decoded: crate::install::protocol::Reply = serde_json::from_slice(&wire).unwrap();
    assert!(matches!(
        decoded,
        crate::install::protocol::Reply::Failed {
            error: crate::install::Error::PreviousSessionFinishing,
            ..
        }
    ));
    assert_eq!(
        map_error(ComponentError::Rejected(
            crate::install::Error::PreviousSessionFinishing
        )),
        "previous_session_finishing"
    );
    assert_eq!(
        map_error(ComponentError::Rejected(crate::install::Error::Busy)),
        "component_busy"
    );
}
