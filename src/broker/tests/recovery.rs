use super::*;

#[test]
fn runtime_restarts_only_after_its_child_exits_and_never_replays_a_connection() {
    let mut first = Peer::new("restart");
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let mut broker = Broker::new(Some(first.take()), secrets);
    let attempts = Arc::new(AtomicUsize::new(0));
    let calls = attempts.clone();
    let (send, receive) = std::sync::mpsc::channel();
    broker.retry = Some(retry::Retry::fixture(move || {
        calls.fetch_add(1, Ordering::Relaxed);
        let mut peer = Peer::new("flow");
        let client = peer.take();
        send.send(peer).unwrap();
        Ok(client)
    }));
    wait(&mut broker, |s| s.helper == "installed");
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    first.advance();
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    std::fs::write(first.marker.with_extension("fault"), b"").unwrap();
    wait(&mut broker, |s| s.helper == "missing");
    let pending_until = Instant::now() + Duration::from_millis(100);
    while Instant::now() < pending_until {
        let s = broker.snapshot();
        assert!(s.vpns.iter().all(|v| v.state == State::HelperMissing));
        assert_eq!(attempts.load(Ordering::Relaxed), 0, "cleanup still pending");
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(first.marker.with_extension("allow_cleanup"), b"").unwrap();
    wait(&mut broker, |s| s.helper == "installed");
    let second = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(first.cleaned());
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    assert_eq!(
        loads.load(Ordering::Relaxed),
        1,
        "no automatic secret reload"
    );
    assert_eq!(
        std::fs::read_to_string(second.marker.with_extension("commands")).unwrap(),
        "snapshot\n",
        "fresh channel must not replay credentials or connect"
    );
    assert!(broker.snapshot().vpns.iter().all(|v| v.state == State::Off));
    dispatch(&mut broker, Command::Toggle { id: "one".into() });
    second.advance();
    wait(&mut broker, |s| s.vpns[0].state == State::Connected);
    assert_eq!(loads.load(Ordering::Relaxed), 2);
    dispatch(&mut broker, Command::Quit {});
    let until = Instant::now() + Duration::from_millis(400);
    while Instant::now() < until {
        assert_eq!(broker.snapshot().helper, "missing");
        assert_eq!(attempts.load(Ordering::Relaxed), 1, "quit cannot relaunch");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(second.cleaned());
    drop(broker);
    drop(second);
}

#[test]
fn runtime_recovery_revalidates_every_snapshot_and_backs_off_on_unavailable_launchers() {
    let secrets = Secrets::new();
    let loads = secrets.loads.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let calls = attempts.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let retry = retry::Retry::fixture(move || {
        let call = calls.fetch_add(1, Ordering::Relaxed);
        if call < 2 {
            return Err(Error::Unavailable);
        }
        let mut peer = Peer::new(if call == 2 { "version" } else { "flow" });
        let client = peer.take();
        send.send(peer).unwrap();
        Ok(client)
    });
    let mut broker = Broker::reconnecting(retry, secrets);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    for _ in 0..100 {
        assert_eq!(broker.snapshot().helper, "missing");
    }
    assert_eq!(attempts.load(Ordering::Relaxed), 1, "retry must be paced");
    wait(&mut broker, |s| s.helper == "outdated");
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    assert!(broker.snapshot().vpns.is_empty());
    assert!(
        broker
            .dispatch(
                Command::Toggle { id: "one".into() },
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
    );
    let incompatible = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    wait(&mut broker, |s| s.helper == "installed");
    let compatible = receive.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(incompatible.cleaned());
    assert_eq!(attempts.load(Ordering::Relaxed), 4);
    assert_eq!(loads.load(Ordering::Relaxed), 0);
    assert_eq!(
        std::fs::read_to_string(compatible.marker.with_extension("commands")).unwrap(),
        "snapshot\n"
    );
    drop(broker);
    drop(compatible);
}
