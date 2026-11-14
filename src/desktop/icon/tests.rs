//! Focused tests for the menu-bar selector. They consume the same
//! [`super::icon_for`] the UI adapter calls, so no selection rule is duplicated
//! here. The AppKit test resolves the symbols creation preloads; it creates no
//! status item, launches no app and captures no screen.

use super::{Icon, icon_for};
use crate::model::{Profile, Snapshot, VpnKind, VpnView};
use crate::preferences::Preferences;
use crate::session::ConnectionState;
use objc2_foundation::NSSize;

const INSTALLED: &str = "installed";

fn profile(id: &str, kind: VpnKind) -> Profile {
    Profile {
        id: id.into(),
        name: id.into(),
        kind,
        gateway: "vpn.example.com".into(),
        username: "user.name".into(),
        networks: Vec::new(),
        port: 443,
        certificate: String::new(),
        probe_host: "10.20.0.15".into(),
        probe_port: 8443,
        probe_method: "ping_tcp".into(),
    }
}

fn view(id: &str, kind: VpnKind, state: ConnectionState) -> VpnView {
    VpnView {
        profile: profile(id, kind),
        state,
        has_password: true,
        has_psk: kind == VpnKind::Ipsec,
        log: Vec::new(),
    }
}

fn snapshot(demo: bool, helper: &'static str, vpns: Vec<VpnView>) -> Snapshot {
    Snapshot {
        version: "0.1.0",
        demo,
        helper,
        component_operation: None,
        preferences: Preferences::default(),
        vpns,
    }
}

/// A real helper with the given profiles, none of them in an operation.
fn ready(vpns: Vec<VpnView>) -> Snapshot {
    snapshot(false, INSTALLED, vpns)
}

const IPSEC: VpnKind = VpnKind::Ipsec;
const SSL: VpnKind = VpnKind::Ssl;

#[test]
fn no_snapshot_yet_is_the_open_lock() {
    assert_eq!(icon_for(None, false), Icon::Open);
}

#[test]
fn a_failed_reply_never_keeps_a_closed_lock() {
    // A reply that carries an error must show attention even if it also carries
    // a snapshot that says "connected": a failed request proves nothing.
    let connected = ready(vec![view("a", IPSEC, ConnectionState::Connected)]);
    assert_eq!(icon_for(Some(&connected), true), Icon::Warning);
    assert_eq!(icon_for(None, true), Icon::Warning);
}

#[test]
fn every_connection_state_has_one_expected_icon() {
    // Listed exhaustively on purpose: a new ConnectionState must decide its
    // tray reading here instead of falling through to a closed lock.
    let table = [
        (ConnectionState::Off, Icon::Open),
        (ConnectionState::Connecting, Icon::Warning),
        (ConnectionState::Verifying, Icon::Warning),
        (ConnectionState::Connected, Icon::Ipsec),
        (ConnectionState::Unresponsive, Icon::Warning),
        (ConnectionState::Reconnecting, Icon::Warning),
        (ConnectionState::Disconnecting, Icon::Warning),
        (ConnectionState::Dropped, Icon::Warning),
        (ConnectionState::CredentialsRejected, Icon::Warning),
        (ConnectionState::GatewayTimeout, Icon::Warning),
        (ConnectionState::MissingSecret, Icon::Warning),
        (ConnectionState::MissingProgram, Icon::Warning),
        (ConnectionState::Offline, Icon::Warning),
        (ConnectionState::HelperMissing, Icon::Warning),
    ];
    for (state, expected) in table {
        let snapshot = ready(vec![view("a", IPSEC, state)]);
        assert_eq!(
            icon_for(Some(&snapshot), false),
            expected,
            "state {state:?} must read as {expected:?}"
        );
    }
}

#[test]
fn each_kind_alone_keeps_its_own_symbol() {
    let ipsec = ready(vec![view("a", IPSEC, ConnectionState::Connected)]);
    assert_eq!(icon_for(Some(&ipsec), false), Icon::Ipsec);
    let ssl = ready(vec![view("b", SSL, ConnectionState::Connected)]);
    assert_eq!(icon_for(Some(&ssl), false), Icon::Ssl);
}

#[test]
fn several_profiles_of_one_kind_keep_that_kind_symbol() {
    let ipsec = ready(vec![
        view("a", IPSEC, ConnectionState::Connected),
        view("b", IPSEC, ConnectionState::Connected),
    ]);
    assert_eq!(icon_for(Some(&ipsec), false), Icon::Ipsec);
    let ssl = ready(vec![
        view("a", SSL, ConnectionState::Connected),
        view("b", SSL, ConnectionState::Connected),
    ]);
    assert_eq!(icon_for(Some(&ssl), false), Icon::Ssl);
}

#[test]
fn all_profiles_off_is_the_open_lock() {
    let snapshot = ready(vec![
        view("a", IPSEC, ConnectionState::Off),
        view("b", SSL, ConnectionState::Off),
    ]);
    assert_eq!(icon_for(Some(&snapshot), false), Icon::Open);
    assert_eq!(icon_for(Some(&ready(Vec::new())), false), Icon::Open);
}

#[test]
fn both_kinds_connected_use_the_stack() {
    let snapshot = ready(vec![
        view("a", IPSEC, ConnectionState::Connected),
        view("b", SSL, ConnectionState::Connected),
    ]);
    assert_eq!(icon_for(Some(&snapshot), false), Icon::Both);
}

#[test]
fn attention_outranks_a_connected_profile() {
    let mixed = ready(vec![
        view("a", IPSEC, ConnectionState::Connected),
        view("b", SSL, ConnectionState::Unresponsive),
    ]);
    assert_eq!(icon_for(Some(&mixed), false), Icon::Warning);
    // Even the kind that is still up does not get a closed lock.
    let connected_first = ready(vec![
        view("a", SSL, ConnectionState::Connected),
        view("b", IPSEC, ConnectionState::Connecting),
    ]);
    assert_eq!(icon_for(Some(&connected_first), false), Icon::Warning);
}

#[test]
fn only_the_installed_helper_marker_closes_the_lock() {
    for marker in ["missing", "outdated", "ready", ""] {
        let snapshot = snapshot(
            false,
            marker,
            vec![view("a", IPSEC, ConnectionState::Connected)],
        );
        assert_eq!(
            icon_for(Some(&snapshot), false),
            Icon::Warning,
            "helper marker {marker:?} is not proof of an installed helper"
        );
    }
    let installed = ready(vec![view("a", IPSEC, ConnectionState::Connected)]);
    assert_eq!(icon_for(Some(&installed), false), Icon::Ipsec);
}

#[test]
fn a_component_operation_requires_attention() {
    let mut snapshot = ready(vec![view("a", IPSEC, ConnectionState::Connected)]);
    snapshot.component_operation = Some("install");
    assert_eq!(icon_for(Some(&snapshot), false), Icon::Warning);
}

#[test]
fn a_demonstration_always_shows_the_open_lock() {
    for state in [
        ConnectionState::Connected,
        ConnectionState::Unresponsive,
        ConnectionState::Off,
    ] {
        let snapshot = snapshot(
            true,
            INSTALLED,
            vec![
                view("a", IPSEC, state),
                view("b", SSL, ConnectionState::Connected),
            ],
        );
        assert_eq!(
            icon_for(Some(&snapshot), false),
            Icon::Open,
            "demo state {state:?} must never look like a real tunnel"
        );
    }
    // Even a demo whose helper marker is wrong stays an open lock: the demo is
    // masked before any helper or state rule runs.
    let demo = snapshot(
        true,
        "missing",
        vec![view("a", IPSEC, ConnectionState::Connected)],
    );
    assert_eq!(icon_for(Some(&demo), false), Icon::Open);
}

#[test]
fn fitting_keeps_the_symbol_aspect_ratio() {
    let square = super::fitted(NSSize::new(20.0, 20.0));
    assert_eq!((square.width, square.height), (18.0, 18.0));
    // A wider symbol keeps its ratio instead of being squashed to 18 x 18.
    let wide = super::fitted(NSSize::new(30.0, 20.0));
    assert!((wide.width - 27.0).abs() < 0.001);
    assert!((wide.height - 18.0).abs() < 0.001);
    assert!((wide.width / wide.height - 1.5).abs() < 0.001);
    // A symbol that reports no height is never divided by zero.
    let empty = super::fitted(NSSize::new(0.0, 0.0));
    assert_eq!((empty.width, empty.height), (0.0, 0.0));
}

#[test]
fn every_icon_names_a_distinct_symbol() {
    let mut names: Vec<&str> = Icon::ALL.iter().map(|icon| icon.symbol()).collect();
    assert_eq!(names.len(), 5);
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 5, "two icons share one symbol");
    assert_eq!(Icon::Open.symbol(), "lock.open");
    assert_eq!(Icon::Ipsec.symbol(), "lock.shield.fill");
    assert_eq!(Icon::Ssl.symbol(), "lock.fill");
    assert_eq!(Icon::Both.symbol(), "lock.square.stack.fill");
    assert_eq!(Icon::Warning.symbol(), "exclamationmark.triangle.fill");
}

/// Resolves every symbol the selector can produce through the production
/// [`super::load`], i.e. the real AppKit lookup and the real menu-bar fitting.
/// It creates no status item, no window and no screen capture; only an immutable
/// symbol image is read from the system catalog.
#[test]
fn every_symbol_resolves_through_appkit() {
    for icon in Icon::ALL {
        let image = super::load(icon).expect("every selector symbol must resolve");
        let size = image.size();
        assert!(
            size.height > 0.0 && size.width > 0.0,
            "{} has an empty size",
            icon.symbol()
        );
        assert!(
            (size.height - super::SYMBOL_HEIGHT).abs() < 0.001,
            "{} is not fitted to the menu bar",
            icon.symbol()
        );
        assert!(
            image.isTemplate(),
            "{} must use template ink",
            icon.symbol()
        );
    }
}
