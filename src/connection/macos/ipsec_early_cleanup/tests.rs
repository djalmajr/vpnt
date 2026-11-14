//! Synthetic tests over the real structures; no native probe, no fake producer.
use super::*;
use crate::connection::{
    macos::interfaces::Interface,
    routes::{Key, Network},
};
use std::collections::BTreeMap;

fn entry(name: &str, index: u32, addresses: &[&str]) -> (String, Interface) {
    (
        name.to_owned(),
        Interface {
            name: name.to_owned(),
            index,
            flags: libc::IFF_UP as u32 | libc::IFF_POINTOPOINT as u32,
            addresses: addresses.iter().map(|text| text.parse().unwrap()).collect(),
        },
    )
}

fn interfaces(entries: &[(&str, u32, &[&str])]) -> Interfaces {
    Interfaces {
        entries: entries
            .iter()
            .map(|(name, index, addresses)| entry(name, *index, addresses))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn route(network: &str, prefix: u8, interface: u16, flags: i32) -> Record {
    Record {
        key: Key {
            network: Network::new(network.parse().unwrap(), prefix).unwrap(),
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

fn empty() -> Snapshot {
    table(Vec::new())
}

fn local(address: &str, interface: u16) -> Snapshot {
    table(vec![route(address, 32, interface, libc::RTF_LOCAL)])
}

#[test]
fn unchanged_foreign_utun_and_routes_are_preserved() {
    let before = interfaces(&[("utun3", 3, &["10.0.0.1"]), ("en0", 1, &["192.0.2.1"])]);
    let now = interfaces(&[("utun3", 3, &["10.0.0.1"]), ("en0", 1, &["192.0.2.1"])]);
    assert!(observed(
        &before,
        &local("192.0.2.1", 1),
        &now,
        &local("192.0.2.1", 1)
    ));
}

#[test]
fn any_new_or_changed_utun_is_busy() {
    let before = interfaces(&[("utun3", 3, &["10.0.0.1"])]);
    for now in [
        interfaces(&[("utun3", 3, &["10.0.0.1"]), ("utun4", 4, &[])]),
        interfaces(&[("utun3", 5, &["10.0.0.1"])]),
        interfaces(&[("utun3", 3, &["10.0.0.2"])]),
    ] {
        assert!(!observed(&before, &empty(), &now, &empty()));
    }
    // A before utun that disappeared is allowed.
    let gone = interfaces(&[("en0", 1, &[])]);
    assert!(observed(&before, &empty(), &gone, &empty()));
}

#[test]
fn old_index_reused_by_a_new_name_is_busy() {
    let before = interfaces(&[("utun3", 3, &[])]);
    let now = interfaces(&[("utun9", 3, &[])]);
    assert!(!observed(&before, &empty(), &now, &empty()));
}

#[test]
fn orphan_local_route_is_busy_but_incidental_ones_are_allowed() {
    let before = interfaces(&[("lo0", 1, &["127.0.0.1"]), ("en0", 2, &[])]);
    let now = interfaces(&[("lo0", 1, &["127.0.0.1"]), ("en0", 2, &[])]);
    // LOCAL host route for an address nobody owns.
    assert!(!observed(&before, &empty(), &now, &local("169.254.7.7", 1)));
    // Incidental LLINFO on the unchanged physical interface.
    let neighbor = table(vec![route("169.254.7.7", 32, 2, libc::RTF_LLINFO)]);
    assert!(observed(&before, &empty(), &now, &neighbor));
    // LOCAL host route for the address still assigned on lo0.
    assert!(observed(&before, &empty(), &now, &local("127.0.0.1", 1)));
}

#[test]
fn preserved_foreign_address_route_is_not_new() {
    let before = interfaces(&[("en0", 2, &["192.0.2.10"])]);
    let table_before = local("192.0.2.10", 2);
    assert!(observed(
        &before,
        &table_before,
        &before,
        &local("192.0.2.10", 2)
    ));
}

#[test]
fn static_default_nonhost_and_new_index_routes_are_refused() {
    let before = interfaces(&[("en0", 2, &[])]);
    let now = interfaces(&[("en0", 2, &[])]);
    for record in [
        route("192.0.2.50", 32, 2, libc::RTF_STATIC),
        route("0.0.0.0", 0, 2, 0),
        route("192.0.2.0", 24, 2, 0),
        route("192.0.2.60", 32, 9, 0),
        route("169.254.7.7", 32, 2, libc::RTF_LLINFO | libc::RTF_STATIC),
    ] {
        assert!(!observed(&before, &empty(), &now, &table(vec![record])));
    }
}

#[test]
fn disappeared_interface_with_leftover_route_stays_busy() {
    let before = interfaces(&[("utun3", 3, &[]), ("en0", 2, &[])]);
    let now = interfaces(&[("en0", 2, &[])]);
    assert!(!observed(&before, &empty(), &now, &local("169.254.7.7", 3)));
}

#[test]
fn exact_new_resources_removed_returns_true() {
    let before = interfaces(&[("en0", 2, &[])]);
    let now = interfaces(&[("en0", 2, &[])]);
    assert!(observed(&before, &empty(), &now, &empty()));
}

#[test]
fn changed_interface_address_must_not_count_for_local_routes() {
    let before = interfaces(&[("en0", 2, &["192.0.2.10"])]);
    let now = interfaces(&[("en0", 2, &["192.0.2.11"])]);
    assert!(!observed(&before, &empty(), &now, &local("192.0.2.11", 2)));
}

#[test]
fn ipv6_slash_32_is_not_a_host_route() {
    let before = interfaces(&[("en0", 2, &[])]);
    let now = interfaces(&[("en0", 2, &[])]);
    let record = table(vec![route("2001:db8::", 32, 2, libc::RTF_LLINFO)]);
    assert!(!observed(&before, &empty(), &now, &record));
}

#[test]
fn local_route_requires_the_same_full_interface_image() {
    let before = interfaces(&[("en0", 2, &["192.0.2.10"])]);
    let mut now = interfaces(&[("en0", 2, &["192.0.2.10"])]);
    if let Some(interface) = now.entries.get_mut("en0") {
        interface.flags ^= libc::IFF_UP as u32;
    }
    assert!(!observed(&before, &empty(), &now, &local("192.0.2.10", 2)));
}

#[test]
fn native_capture_and_complete_are_read_only() {
    let before = capture().expect("native interface/route read must succeed");
    let verdict = before.complete();
    eprintln!("native early-absence verdict: {verdict:?}");
    assert!(verdict.is_ok(), "complete must not fail on a healthy host");
}
