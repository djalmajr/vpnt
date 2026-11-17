//! Shared-predicate cases over the real structures: foreign index and loopback
//! evidence. No fake configured link and no fake producer context.
use super::super::utun_absence::observed;
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
fn foreign_index_holding_the_vip_preserves_its_host_route() {
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
fn unknown_host_route_index_with_the_same_foreign_ip_is_busy() {
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
fn host_route_without_any_foreign_address_is_busy() {
    let now = interfaces(&[("en0", 2, UP, &[])]);
    let now_t = table(vec![route("192.0.2.10", 32, 2, 0)]);
    assert!(!observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn reused_old_index_or_name_is_busy() {
    let vips: Vec<std::net::IpAddr> = Vec::new();
    let by_index = interfaces(&[("utun9", 9, UP, &[])]);
    assert!(!observed("utun3", 9, &vips, &by_index, &table(vec![])));
    let by_name = interfaces(&[("utun3", 4, UP, &[])]);
    assert!(!observed("utun3", 9, &vips, &by_name, &table(vec![])));
}

#[test]
fn route_on_the_old_index_is_busy_even_without_the_interface() {
    let now = interfaces(&[("en0", 2, UP, &[])]);
    let now_t = table(vec![route("10.0.0.0", 24, 9, 0)]);
    assert!(!observed("utun9", 9, &[], &now, &now_t));
}

#[test]
fn local_route_on_a_real_up_loopback_holding_the_vip_is_preserved() {
    let loopback = libc::IFF_LOOPBACK as u32 | UP;
    let now = interfaces(&[("lo0", 1, loopback, &["127.0.0.1"])]);
    let now_t = table(vec![route("127.0.0.1", 32, 1, libc::RTF_LOCAL)]);
    assert!(observed(
        "utun9",
        9,
        &["127.0.0.1".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn non_local_route_on_the_owning_foreign_index_is_preserved() {
    let now = interfaces(&[("en0", 2, UP, &["192.0.2.10"])]);
    let now_t = table(vec![route("192.0.2.10", 32, 2, libc::RTF_LOCAL)]);
    assert!(observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn local_route_on_loopback_is_preserved_while_a_foreign_owner_holds_the_vip() {
    // en0 owns the VIP; lo0 only has 127.0.0.1 and the LOCAL route points at lo0.
    let now = interfaces(&[
        ("en0", 2, UP, &["192.0.2.10"]),
        ("lo0", 1, libc::IFF_LOOPBACK as u32 | UP, &["127.0.0.1"]),
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
fn local_route_on_an_unknown_index_is_busy_even_with_a_foreign_owner() {
    let now = interfaces(&[
        ("en0", 2, UP, &["192.0.2.10"]),
        ("lo0", 1, libc::IFF_LOOPBACK as u32 | UP, &["127.0.0.1"]),
    ]);
    let now_t = table(vec![route("192.0.2.10", 32, 999, libc::RTF_LOCAL)]);
    assert!(!observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn loopback_holding_the_vip_does_not_excuse_an_unknown_route_index() {
    let loopback = libc::IFF_LOOPBACK as u32 | UP;
    let now = interfaces(&[("lo0", 1, loopback, &["127.0.0.1"])]);
    let now_t = table(vec![route("127.0.0.1", 32, 999, libc::RTF_LOCAL)]);
    assert!(!observed(
        "utun9",
        9,
        &["127.0.0.1".parse().unwrap()],
        &now,
        &now_t
    ));
}

#[test]
fn down_foreign_owner_never_certifies_a_host_route() {
    let down = interfaces(&[
        ("en0", 2, 0, &["192.0.2.10"]),
        ("lo0", 1, libc::IFF_LOOPBACK as u32 | UP, &["127.0.0.1"]),
    ]);
    let now_t = table(vec![route("192.0.2.10", 32, 1, libc::RTF_LOCAL)]);
    assert!(!observed(
        "utun9",
        9,
        &["192.0.2.10".parse().unwrap()],
        &down,
        &now_t
    ));
}
