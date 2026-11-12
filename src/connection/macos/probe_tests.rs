use super::*;
use crate::model::VpnKind;
use std::{cell::Cell, net::TcpListener};

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
