//! Shared-predicate cases with synthetic metadata. The typed production origin
//! is static-only; this module builds `RetiredUtun` privately for tests.
use super::{RetiredUtun, observed};
use crate::connection::{
    macos::{
        Interfaces,
        interfaces::Interface,
        routing::{Record, Snapshot},
    },
    routes::{Key, Network},
};
use std::collections::BTreeMap;

fn interface(name: &str, index: u32, flags: u32, addresses: &[&str]) -> (String, Interface) {
    (
        name.to_owned(),
        Interface {
            name: name.to_owned(),
            index,
            flags,
            addresses: addresses.iter().map(|text| text.parse().unwrap()).collect(),
        },
    )
}

fn interfaces(entries: &[(&str, u32, u32, &[&str])]) -> Interfaces {
    Interfaces {
        entries: entries
            .iter()
            .map(|(name, index, flags, addresses)| interface(name, *index, *flags, addresses))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn route(prefix: &str, mask: u8, interface: u16, flags: i32) -> Record {
    Record {
        key: Key {
            network: Network::new(prefix.parse().unwrap(), mask).unwrap(),
            scope: 0,
        },
        interface,
        flags: libc::RTF_UP | flags,
        gateway: None,
        source: None,
    }
}

fn table(records: Vec<Record>) -> Snapshot {
    Snapshot { records }
}

const UP: u32 = libc::IFF_UP as u32;

#[test]
fn old_name_index_or_implicit_route_blocks_absence() {
    let vips = Vec::new();
    let by_name = interfaces(&[("utun3", 4, UP, &[])]);
    assert!(!observed("utun3", 9, &vips, &by_name, &table(vec![])));
    let by_index = interfaces(&[("utun9", 9, UP, &[])]);
    assert!(!observed("utun3", 9, &vips, &by_index, &table(vec![])));
    let residual = interfaces(&[("en0", 2, UP, &[])]);
    assert!(!observed(
        "utun3",
        9,
        &vips,
        &residual,
        &table(vec![route("10.0.0.0", 24, 9, 0)])
    ));
}

#[test]
fn foreign_up_owner_index_preserves_its_vip_host_route() {
    let now = interfaces(&[("en0", 2, UP, &["192.0.2.10"])]);
    let now_t = table(vec![route("192.0.2.10", 32, 2, 0)]);
    assert!(observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn unknown_host_index_with_the_same_foreign_vip_is_busy() {
    let now = interfaces(&[("en0", 2, UP, &["192.0.2.10"])]);
    let now_t = table(vec![route("192.0.2.10", 32, 7, 0)]);
    assert!(!observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn local_route_on_an_up_loopback_index_is_preserved() {
    let loopback = libc::IFF_LOOPBACK as u32 | UP;
    let now = interfaces(&[
        ("en0", 2, UP, &["192.0.2.10"]),
        ("lo0", 1, loopback, &["127.0.0.1"]),
    ]);
    let now_t = table(vec![route("192.0.2.10", 32, 1, libc::RTF_LOCAL)]);
    assert!(observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn orphan_vip_host_route_and_down_owner_are_busy() {
    let no_owner = interfaces(&[("en0", 2, UP, &[])]);
    assert!(!observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &no_owner,
        &table(vec![route("192.0.2.10", 32, 2, 0)])
    ));
    let down = interfaces(&[("en0", 2, 0, &["192.0.2.10"])]);
    assert!(!observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &down,
        &table(vec![route("192.0.2.10", 32, 2, 0)])
    ));
}

#[test]
fn unrelated_new_ppp_route_and_index_never_block_known_absence() {
    // The reason for the typed API: a newly connected SSL PPP interface with
    // its own routes is not in the known UTUN domain and must not block.
    let now = interfaces(&[("en0", 2, UP, &[]), ("ppp0", 12, UP, &["10.99.0.2"])]);
    let now_t = table(vec![
        route("10.99.0.0", 24, 12, 0),
        route("10.99.0.2", 32, 12, libc::RTF_LOCAL),
    ]);
    assert!(observed("utun9", 9, &[], &now, &now_t));
}

// Read-only native path with synthetic metadata: reports the real verdict, does
// not claim native ownership or a positive UTUN.
#[test]
fn gone_reads_the_live_tables_and_reports_a_verdict() {
    let retired = RetiredUtun {
        name: "utun-none-fixture".into(),
        index: 4094,
        vips: vec!["192.0.2.250".parse().unwrap()],
    };
    let verdict = retired.gone();
    eprintln!("synthetic RetiredUtun gone verdict: {verdict:?}");
    assert!(verdict.is_ok(), "gone must not fail on a healthy host");
}

#[test]
fn constructor_union_keeps_intended_and_every_observed_address() {
    let now = interfaces(&[("utun3", 3, UP, &["10.0.0.2", "fe80::1"])]);
    let retired = super::from_view("utun3", 3, &["10.0.0.2".parse().unwrap()], &now).unwrap();
    assert_eq!(
        retired.vips,
        vec![
            "10.0.0.2".parse::<std::net::IpAddr>().unwrap(),
            "fe80::1".parse().unwrap()
        ],
        "implicit observed address was dropped"
    );
}

#[test]
fn constructor_rejects_a_missing_or_mismatched_view() {
    let now = interfaces(&[("utun3", 4, UP, &["10.0.0.2"])]);
    assert_eq!(
        super::from_view("utun3", 3, &[], &now).err(),
        Some(crate::connection::ipsec::Error::Changed)
    );
    assert_eq!(
        super::from_view("utun9", 9, &[], &now).err(),
        Some(crate::connection::ipsec::Error::Changed)
    );
}

#[test]
fn orphan_implicit_linklocal_host_route_on_lo0_stays_busy() {
    // The old utun is gone and no interface owns the implicit LL address; the
    // residual host route must still block the known domain.
    let now = interfaces(&[("lo0", 1, libc::IFF_LOOPBACK as u32 | UP, &["127.0.0.1"])]);
    let now_t = table(vec![route("fe80::1", 128, 1, libc::RTF_LOCAL)]);
    assert!(!super::observed(
        "utun9",
        9,
        &["fe80::1".parse().unwrap()],
        &now,
        &now_t
    ));
}
