use super::*;
use crate::model::VpnKind;
use std::{
    cell::{Cell, RefCell},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    os::fd::OwnedFd,
};

struct Loopback {
    interface: Interface,
    live: Cell<bool>,
    // In the loss test the listener's accepted connection, rather than a call
    // count or sleep, discriminates the post-handshake link check.
    lose_after_accept: Option<TcpListener>,
}
impl Loopback {
    fn new() -> Self {
        let interface = Interfaces::read().unwrap().entries.remove("lo0").unwrap();
        Self {
            interface,
            live: Cell::new(true),
            lose_after_accept: None,
        }
    }
}
impl Link for Loopback {
    fn interface(&self) -> &Interface {
        &self.interface
    }
    fn current(&self) -> bool {
        if let Some(listener) = &self.lose_after_accept
            && accepted(listener, Duration::from_millis(100))
        {
            self.live.set(false);
        }
        self.live.get()
    }
}
fn accepted(listener: &TcpListener, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(_) => return true,
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(1));
    }
}
fn profile(host: &str, port: u16) -> Profile {
    Profile {
        ovpn: None,
        dns_domains: Vec::new(),
        id: "probe-fixture".into(),
        name: "Probe fixture".into(),
        kind: VpnKind::Ssl,
        gateway: "vpn.invalid".into(),
        username: "fixture".into(),
        networks: vec!["10.0.0.0/8".into()],
        port: 443,
        certificate: String::new(),
        probe_host: host.into(),
        probe_port: port,
        probe_method: "tcp".into(),
    }
}

#[test]
fn tcp_attempt_deadline_shares_the_remaining_budget_between_untried_targets() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(5);
    // The normal, single-target case uses the whole remaining probe budget.
    assert_eq!(tcp_attempt_deadline(now, deadline, 1), deadline);
    // Two targets split the remaining time; the 1 s floor still wins when the
    // share is smaller, but only while the absolute deadline permits it.
    assert_eq!(
        tcp_attempt_deadline(now, deadline, 2),
        now + Duration::from_millis(2500)
    );
    assert_eq!(
        tcp_attempt_deadline(now, now + Duration::from_millis(1500), 2),
        now + Duration::from_secs(1)
    );
    // With less than a second left, the deadline itself is the attempt cap.
    let short = now + Duration::from_millis(800);
    assert_eq!(tcp_attempt_deadline(now, short, 1), short);
    assert_eq!(tcp_attempt_deadline(now, short, 2), short);
    assert_eq!(
        tcp_attempt_deadline(now + Duration::from_secs(6), deadline, 1),
        deadline
    );
}

#[test]
fn native_probe_reaches_only_its_numeric_or_local_dns_fixture_listener() {
    let link = Loopback::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let canceled = AtomicBool::new(false);
    for host in ["127.0.0.1", "localhost"] {
        let profile = profile(host, listener.local_addr().unwrap().port());
        assert_eq!(
            run(&link, &profile, &canceled, Duration::from_secs(3), true),
            Outcome::Responsive(Method::Tcp),
            "{host}"
        );
        assert!(accepted(&listener, Duration::from_secs(1)));
    }
}

#[test]
fn invalid_canceled_or_local_production_target_cannot_report_responsive() {
    let link = Loopback::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut profile = profile("127.0.0.1", listener.local_addr().unwrap().port());
    let canceled = AtomicBool::new(false);
    assert_eq!(
        run(&link, &profile, &canceled, Duration::from_secs(1), false),
        Outcome::InvalidTarget
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    profile.probe_host = "::ffff:127.0.0.1".into();
    assert_eq!(
        run(&link, &profile, &canceled, Duration::from_secs(1), false),
        Outcome::InvalidTarget
    );
    profile.probe_host = "127.0.0.1".into();
    canceled.store(true, Ordering::Release);
    assert_eq!(
        run(&link, &profile, &canceled, Duration::from_secs(1), true),
        Outcome::Canceled
    );
    canceled.store(false, Ordering::Release);
    link.live.set(false);
    assert_eq!(
        run(&link, &profile, &canceled, Duration::from_secs(1), true),
        Outcome::InvalidLink
    );
    link.live.set(true);
    profile.probe_port = 22;
    assert_eq!(
        run(&link, &profile, &canceled, Duration::from_secs(1), true),
        Outcome::InvalidTarget
    );
}

#[test]
fn losing_the_link_after_a_real_tcp_handshake_invalidates_the_result() {
    let mut link = Loopback::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let profile = profile("127.0.0.1", listener.local_addr().unwrap().port());
    link.lose_after_accept = Some(listener);
    assert_eq!(
        run(
            &link,
            &profile,
            &AtomicBool::new(false),
            Duration::from_secs(1),
            true
        ),
        Outcome::InvalidLink
    );
    assert!(!link.live.get());
}

#[test]
fn fixed_system_ping_can_supply_native_loopback_fixture_evidence() {
    let link = Loopback::new();
    for host in ["127.0.0.1", "::1"] {
        let mut profile = profile(host, 443);
        profile.probe_method = "ping_tcp".into();
        assert_eq!(
            run(
                &link,
                &profile,
                &AtomicBool::new(false),
                Duration::from_secs(2),
                true
            ),
            Outcome::Responsive(Method::Ping),
            "{host}"
        );
    }
}

#[test]
fn ipv6_tcp_uses_the_native_interface_and_matching_source() {
    let link = Loopback::new();
    let listener = TcpListener::bind("[::1]:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let profile = profile("::1", listener.local_addr().unwrap().port());
    assert_eq!(
        run(
            &link,
            &profile,
            &AtomicBool::new(false),
            Duration::from_secs(1),
            true
        ),
        Outcome::Responsive(Method::Tcp)
    );
    assert!(accepted(&listener, Duration::from_secs(1)));
}

#[derive(Clone, Copy, Debug)]
struct Dial {
    index: u32,
    source: IpAddr,
    target: SocketAddr,
    attempt: Instant,
}

/// The real run loop with only its clock and TCP dial replaced. No socket is
/// connected: each dial records the deadline the loop handed it and simulates
/// one second of consumed budget.
fn dial_budget(
    link: &Loopback,
    host: &str,
    consume: Duration,
    cancel_in_dial: bool,
    canceled: &AtomicBool,
) -> (Outcome, Instant, Vec<Dial>) {
    let profile = profile(host, 8443);
    let base = Instant::now();
    let deadline = base + Duration::from_secs(5);
    let elapsed = Cell::new(Duration::ZERO);
    let attempts = RefCell::new(Vec::new());
    let outcome = run_with(
        link,
        &profile,
        canceled,
        deadline,
        true,
        || base + elapsed.get(),
        |index, source, target, attempt, canceled| {
            attempts.borrow_mut().push(Dial {
                index,
                source,
                target,
                attempt,
            });
            elapsed.set(elapsed.get() + consume);
            if cancel_in_dial {
                canceled.store(true, Ordering::Release);
            }
            Err::<OwnedFd, _>(tcp::Error::Failed)
        },
    );
    (outcome, base, attempts.into_inner())
}

#[test]
fn the_real_loop_splits_the_budget_between_two_eligible_targets() {
    let link = Loopback::new();
    let canceled = AtomicBool::new(false);
    let (outcome, base, attempts) =
        dial_budget(&link, "localhost", Duration::from_secs(1), false, &canceled);
    assert_eq!(outcome, Outcome::Unresponsive);
    assert_eq!(attempts.len(), 2, "localhost has one address per family");
    let mut targets: Vec<IpAddr> = attempts.iter().map(|dial| dial.target.ip()).collect();
    targets.sort();
    assert_eq!(
        targets,
        [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        ]
    );
    assert_eq!(
        attempts[0].attempt,
        base + Duration::from_millis(2500),
        "the first of two eligible targets receives half the remaining budget"
    );
    assert_eq!(
        attempts[1].attempt,
        base + Duration::from_secs(5),
        "the second receives the balance after the consumed second"
    );
    for dial in &attempts {
        assert_eq!(dial.index, link.interface.index);
        assert_eq!(dial.source.is_ipv4(), dial.target.is_ipv4());
        assert_eq!(dial.target.port(), 8443);
    }
}

#[test]
fn a_target_without_a_usable_source_does_not_take_a_share_of_the_budget() {
    let mut link = Loopback::new();
    // `localhost` still resolves both families, but this link has no source
    // for the AAAA answer: fe80::1 is link-local while ::1 is not.
    link.interface
        .addresses
        .remove(&IpAddr::V6(Ipv6Addr::LOCALHOST));
    link.interface
        .addresses
        .insert(IpAddr::V6("fe80::1".parse().unwrap()));
    let canceled = AtomicBool::new(false);
    let (outcome, base, attempts) =
        dial_budget(&link, "localhost", Duration::from_secs(1), false, &canceled);
    assert_eq!(outcome, Outcome::Unresponsive);
    assert_eq!(attempts.len(), 1, "the filtered target must not be dialed");
    assert_eq!(attempts[0].target.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        attempts[0].attempt,
        base + Duration::from_secs(5),
        "one eligible candidate receives the whole remaining budget"
    );
}

#[test]
fn a_single_numeric_candidate_keeps_the_absolute_deadline() {
    let link = Loopback::new();
    let canceled = AtomicBool::new(false);
    let (outcome, base, attempts) =
        dial_budget(&link, "127.0.0.1", Duration::from_secs(1), false, &canceled);
    assert_eq!(outcome, Outcome::Unresponsive);
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].attempt, base + Duration::from_secs(5));
}

#[test]
fn cancellation_from_the_injected_dial_is_reported_by_the_shared_loop() {
    let link = Loopback::new();
    let canceled = AtomicBool::new(false);
    let (outcome, _, attempts) =
        dial_budget(&link, "localhost", Duration::from_secs(1), true, &canceled);
    assert_eq!(outcome, Outcome::Canceled);
    assert_eq!(attempts.len(), 1);
}
