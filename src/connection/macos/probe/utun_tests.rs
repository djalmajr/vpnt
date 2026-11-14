//! Shared run-loop tests with a private fake link: no real utun/context.
use super::{Kind, Link, Outcome, run};
use crate::connection::macos::interfaces::Interface;
use crate::model::{Profile, VpnKind};
use std::{
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

enum Current {
    Fixed(bool),
    After(Arc<AtomicUsize>, usize),
}
impl Current {
    fn get(&self) -> bool {
        match self {
            Current::Fixed(value) => *value,
            Current::After(calls, limit) => calls.fetch_add(1, Ordering::SeqCst) < *limit,
        }
    }
}

struct FakeLink {
    interface: Interface,
    current: Current,
    kind: Kind,
}
impl Link for FakeLink {
    fn interface(&self) -> &Interface {
        &self.interface
    }
    fn current(&self) -> bool {
        self.current.get()
    }
    fn kind(&self) -> Kind {
        self.kind
    }
}

pub(super) fn profile(kind: VpnKind, host: &str, port: u16) -> Profile {
    Profile {
        id: "fixture".into(),
        name: "Fixture".into(),
        kind,
        gateway: "fixture.invalid".into(),
        username: "fixture-user".into(),
        port: 500,
        networks: Vec::new(),
        certificate: String::new(),
        probe_host: host.into(),
        probe_port: port,
        probe_method: "tcp".into(),
    }
}

pub(super) fn interface(index: u32, addresses: &[&str]) -> Interface {
    Interface {
        name: "utun9".into(),
        index,
        flags: libc::IFF_UP as u32 | libc::IFF_POINTOPOINT as u32,
        addresses: addresses.iter().map(|text| text.parse().unwrap()).collect(),
    }
}

pub(super) fn canceled(value: bool) -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(value))
}

// Mutation: drop the link-kind check, so an SSL link runs an IPsec profile.
#[test]
fn ssl_link_kind_denies_an_ipsec_profile() {
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ssl,
    };
    let profile = profile(VpnKind::Ipsec, "localhost", 9);
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_secs(1),
            true
        ),
        Outcome::InvalidTarget
    );
}

#[test]
fn cancel_before_any_target_is_reported_first() {
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ipsec,
    };
    let profile = profile(VpnKind::Ipsec, "localhost", 9);
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(true).as_ref(),
            Duration::from_secs(1),
            true
        ),
        Outcome::Canceled
    );
}

#[test]
fn stale_link_before_traffic_is_invalid() {
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(false),
        kind: Kind::Ipsec,
    };
    let profile = profile(VpnKind::Ipsec, "localhost", 9);
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_secs(1),
            true
        ),
        Outcome::InvalidLink
    );
}

#[test]
fn loopback_positive_is_responsive_and_then_stale_is_invalid() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let profile = profile(VpnKind::Ipsec, "localhost", port);

    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ipsec,
    };
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_secs(2),
            true
        ),
        Outcome::Responsive(super::Method::Tcp)
    );

    // Stale before traffic is invalid.
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(false),
        kind: Kind::Ipsec,
    };
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_secs(1),
            true
        ),
        Outcome::InvalidLink
    );
}

#[test]
fn unresponsive_target_is_reported_without_a_default_source() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ipsec,
    };
    let profile = profile(VpnKind::Ipsec, "localhost", port);
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_millis(600),
            true
        ),
        Outcome::Unresponsive
    );
}

#[test]
fn v6_only_view_has_no_v4_source_and_never_falls_back() {
    let interface = interface(1, &["::1"]);
    assert_eq!(
        super::source(&interface, "127.0.0.1".parse().unwrap()),
        None
    );
    assert_eq!(
        super::source(&interface, "::1".parse().unwrap()),
        Some("::1".parse().unwrap())
    );
}

#[test]
fn production_target_rules_reject_loopback_and_unspecified() {
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ipsec,
    };
    let local = super::super::Interfaces::read().unwrap();
    assert!(!super::remote("127.0.0.1".parse().unwrap(), &local, false));
    assert!(!super::remote("0.0.0.0".parse().unwrap(), &local, false));
    assert!(!super::remote("224.0.0.1".parse().unwrap(), &local, false));
    let profile = profile(VpnKind::Ipsec, "localhost", 9);
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_secs(1),
            false
        ),
        Outcome::InvalidTarget
    );
}

// Mutation: drop the post-handshake current check in finish(), so a link that
// dies between the handshake and the final check still reports Responsive.
#[test]
fn handshake_then_stale_link_is_invalid_not_responsive() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let profile = profile(VpnKind::Ipsec, "localhost", port);
    // Two checks (early and pre-traffic) succeed, the post-handshake one fails.
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::After(Arc::new(AtomicUsize::new(0)), 3),
        kind: Kind::Ipsec,
    };
    assert_eq!(
        run(
            &link,
            &profile,
            canceled(false).as_ref(),
            Duration::from_secs(2),
            true
        ),
        Outcome::InvalidLink
    );
}

// Mutation: ignore the finish deadline, so an expired total budget still
// reports Responsive after a handshake. Deterministic: no sleep.
#[test]
fn expired_deadline_in_finish_never_reports_responsive() {
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ipsec,
    };
    let past = Instant::now() - Duration::from_millis(1);
    assert_eq!(
        super::finish(&link, super::Method::Tcp, canceled(false).as_ref(), past),
        Outcome::Unresponsive
    );
}

// Mutation: ignore the finish cancel gate, so a canceled call still reports a
// link verdict. Deterministic: no traffic involved.
#[test]
fn canceled_finish_is_canceled_before_any_link_verdict() {
    let link = FakeLink {
        interface: interface(1, &["127.0.0.1"]),
        current: Current::Fixed(true),
        kind: Kind::Ipsec,
    };
    let future = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        super::finish(&link, super::Method::Tcp, canceled(true).as_ref(), future),
        Outcome::Canceled
    );
}
