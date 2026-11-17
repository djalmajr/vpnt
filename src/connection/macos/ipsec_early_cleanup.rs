//! Conservative, read-only absence evidence for an admitted attempt whose
//! original child failed before the utun metadata could be observed.
//!
//! This is **not** producer or ownership proof and never authorizes deletes: the
//! Driver may call it only after `NativePeer::retire` returned true and every
//! own `ConfiguredUtun`/`RetainedInterface`/sink reference is dropped. It never
//! marks a namespace complete and never stops a child.
use super::{
    interfaces::Interfaces,
    routing::{Record, Snapshot},
};
use crate::connection::{
    macos::vip,
    routes::{Error, Network, ppp_networks},
};
use std::net::IpAddr;

/// The observed before-image of interfaces and the route table.
pub(crate) struct Before {
    interfaces: Interfaces,
    table: Snapshot,
}

/// Read both views once, without mutation.
pub(crate) fn capture() -> Result<Before, Error> {
    let interfaces = read_interfaces()?;
    let table = Snapshot::read()?;
    Ok(Before { interfaces, table })
}

impl Before {
    /// Fresh reads and the conservative delta comparison. Any read failure or
    /// ambiguity is an error, never `true`.
    pub(crate) fn complete(&self) -> Result<bool, Error> {
        let interfaces = read_interfaces()?;
        let table = Snapshot::read()?;
        Ok(observed(&self.interfaces, &self.table, &interfaces, &table))
    }
}

fn read_interfaces() -> Result<Interfaces, Error> {
    Interfaces::read().map_err(|_| Error::Unavailable)
}

/// Startup has no in-memory route registry or pinned descriptor. The claim's
/// networks cover both the retained backend's tunnel routes and its sink
/// routes (including expanded defaults). An ambiguous match stays pending.
/// The caller supplies fresh reads; a read failure never reaches here as `true`.
pub(crate) fn orphan_observed(
    link: Option<(&str, u16, &[IpAddr])>,
    networks: &[String],
    interfaces: &Interfaces,
    table: &Snapshot,
) -> Result<bool, Error> {
    // The indexes are placeholders: only the destination keys are examined.
    let planned = ppp_networks(networks, 1, true, true, None)?;
    if table.records.iter().any(|row| {
        planned
            .iter()
            .any(|route| route.key.network == row.key.network)
    }) {
        return Ok(false);
    }
    if let Some((name, index, vips)) = link
        && (!vip::retired::observed(name, index, vips, interfaces, table)
            || interfaces
                .entries
                .values()
                .any(|entry| vips.iter().any(|vip| entry.addresses.contains(vip))))
    {
        return Ok(false);
    }
    if !needs_fallback(link, networks) {
        return Ok(true);
    }
    // Legacy/no-link claims and possible sinks have no recorded unit or VIP.
    // A remaining UTUN, unknown route index or unowned LOCAL host route could
    // be residue of that domain. A fresh view that contains any is inconclusive.
    Ok(!interfaces.entries.keys().any(|name| is_utun(name))
        && !table.records.iter().any(|row| {
            let index_known = interfaces
                .entries
                .values()
                .any(|entry| entry.index == u32::from(row.interface));
            let orphan_local = row.flags & libc::RTF_LOCAL != 0
                && row.key.network == Network::host(row.key.network.address())
                && !interfaces.entries.values().any(|entry| {
                    entry.addresses.contains(&row.key.network.address())
                        && entry.flags & libc::IFF_UP as u32 != 0
                });
            !index_known || orphan_local
        }))
}

/// Whether the claim's own evidence cannot settle host absence, so the
/// conservative fallback (no UTUN, no unknown index, no orphan LOCAL route)
/// decides: a claim without a recorded link, or one whose controller may have
/// opened a sink. The sink follows the retained backend (`networks.is_empty()
/// && ipv4 != ipv6` on the selected route networks): a full tunnel (both
/// defaults, see `config::selection::is_full_tunnel`) with a single VIP
/// family. It is its own UTUN with a private host address, which the planned
/// destinations do not cover and the claim does not name.
pub(crate) fn needs_fallback(link: Option<(&str, u16, &[IpAddr])>, networks: &[String]) -> bool {
    link.is_none_or(|(_, _, vips)| vips.len() == 1 && full_tunnel(networks))
}

fn full_tunnel(networks: &[String]) -> bool {
    let parsed: Vec<Network> = networks
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    parsed.len() == 2
        && parsed.len() == networks.len()
        && parsed
            .iter()
            .any(|network| network.address().is_ipv4() && network.prefix() == 0)
        && parsed
            .iter()
            .any(|network| !network.address().is_ipv4() && network.prefix() == 0)
}

/// Pure predicate shared by production `complete` and the synthetic tests.
pub(crate) fn observed(
    before: &Interfaces,
    before_table: &Snapshot,
    now: &Interfaces,
    now_table: &Snapshot,
) -> bool {
    // Every current utun must reproduce a complete before entry; a before utun
    // that is gone is allowed, a new/changed/reused one is not.
    for (name, current) in now.entries.iter().filter(|(name, _)| is_utun(name)) {
        match before.entries.get(name) {
            Some(previous) if previous == current => {}
            _ => return false,
        }
    }
    for route in &now_table.records {
        if before_table.records.contains(route) {
            continue;
        }
        if !allowed_new(route, before, now) {
            return false;
        }
    }
    true
}

fn is_utun(name: &str) -> bool {
    name.starts_with("utun")
}

/// A new or changed route is incidental at most: it must sit on an interface
/// that already existed unchanged, never on a utun, and only host LLINFO or a
/// host LOCAL route whose address is still assigned there are tolerated.
fn allowed_new(route: &Record, before: &Interfaces, now: &Interfaces) -> bool {
    let Some(current) = now
        .entries
        .values()
        .find(|interface| interface.index == route.interface as u32)
    else {
        return false;
    };
    let Some(previous) = before.entries.get(&current.name) else {
        return false;
    };
    if previous.index != current.index || is_utun(&current.name) {
        return false;
    }
    if route.flags & libc::RTF_STATIC != 0
        || route.key.scope != 0
        || route.key.network != Network::host(route.key.network.address())
    {
        return false;
    }
    if route.flags & libc::RTF_LLINFO != 0
        && route.flags & (libc::RTF_STATIC | libc::RTF_LOCAL) == 0
    {
        return true;
    }
    if route.flags & libc::RTF_LOCAL != 0 {
        // The interface must be identical to its before image (flags and
        // addresses included), not merely share the address.
        return previous == current && current.addresses.contains(&route.key.network.address());
    }
    false
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod orphan_tests {
    use super::*;
    use crate::connection::routes::Key;

    fn interfaces(entries: &[(&str, u32, &[&str])]) -> Interfaces {
        let entries: Vec<_> = entries
            .iter()
            .map(|&(name, index, addresses)| (name, index, libc::IFF_UP as u32, addresses))
            .collect();
        vip::RetiredUtun::view_for_test(&entries)
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
    fn startup_orphan_checks_the_retained_utun_vip_and_every_planned_route() {
        let vips = ["192.0.2.10".parse().unwrap()];
        let link = Some(("utun7", 7, vips.as_slice()));
        let networks = ["10.20.0.0/24".into()];
        let foreign = interfaces(&[("utun8", 8, &[]), ("en0", 2, &[])]);
        let gone = |interfaces: &Interfaces, table: &Snapshot| {
            orphan_observed(link, &networks, interfaces, table).unwrap()
        };

        assert!(gone(&foreign, &empty()));
        assert!(!gone(&interfaces(&[("utun7", 8, &[])]), &empty()));
        assert!(!gone(&interfaces(&[("utun8", 7, &[])]), &empty()));
        assert!(!gone(&interfaces(&[("en0", 2, &["192.0.2.10"])]), &empty()));
        assert!(!gone(&foreign, &local("192.0.2.10", 2)));
        assert!(!gone(&foreign, &table(vec![route("10.20.0.0", 24, 7, 0)])));
        assert!(!gone(&foreign, &table(vec![route("10.20.0.0", 24, 2, 0)])));
        assert!(!gone(&foreign, &table(vec![route("10.30.0.0", 24, 7, 0)])));
    }

    #[test]
    fn startup_orphan_sink_follows_the_retained_backend_condition() {
        // A system UTUN is present: only a possible sink falls back to "busy".
        let host = interfaces(&[("en0", 2, &[]), ("utun0", 9, &[])]);
        let v4: [IpAddr; 1] = ["192.0.2.10".parse().unwrap()];
        let dual: [IpAddr; 2] = [
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ];
        let captured: [IpAddr; 0] = [];
        let full: [String; 2] = ["0.0.0.0/0".into(), "::/0".into()];
        let explicit_v4: [String; 1] = ["0.0.0.0/0".into()];
        let split: [String; 1] = ["10.20.0.0/24".into()];
        let absent = |vips: &[IpAddr], networks: &[String]| {
            orphan_observed(Some(("utun7", 7, vips)), networks, &host, &empty()).unwrap()
        };
        // Full tunnel with one VIP family: the backend creates a sink.
        assert!(!absent(&v4, &full));
        // No sink: an explicit single default, both families, a split, or a
        // capture that never configured VIPs.
        assert!(absent(&v4, &explicit_v4));
        assert!(absent(&dual, &full));
        assert!(absent(&v4, &split));
        assert!(absent(&captured, &full));
        assert!(!full_tunnel(&["0.0.0.0/0".into(), "0.0.0.0/0".into()]));
        assert!(!full_tunnel(&[
            "0.0.0.0/0".into(),
            "::/0".into(),
            "10.0.0.0/8".into()
        ]));
    }

    #[test]
    fn startup_orphan_keeps_ambiguous_legacy_resources_and_a_possible_sink() {
        let networks = ["0.0.0.0/0".into(), "::/0".into()];
        let en = interfaces(&[("en0", 2, &[])]);
        let utun = interfaces(&[("en0", 2, &[]), ("utun8", 8, &[])]);
        let sink_route = table(vec![route("8000::", 1, 8, libc::RTF_BLACKHOLE)]);
        let unknown_route = table(vec![route("10.30.0.0", 24, 9, 0)]);
        let vips = ["192.0.2.10".parse().unwrap()];

        for link in [None, Some(("utun7", 7, vips.as_slice()))] {
            assert!(orphan_observed(link, &networks, &en, &empty()).unwrap());
            assert!(!orphan_observed(link, &networks, &utun, &empty()).unwrap());
            assert!(!orphan_observed(link, &networks, &en, &sink_route).unwrap());
            assert!(!orphan_observed(link, &networks, &en, &unknown_route).unwrap());
            assert!(!orphan_observed(link, &networks, &en, &local("169.254.7.7", 2)).unwrap());
        }
    }
}
