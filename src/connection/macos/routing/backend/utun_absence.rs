//! Shared fresh-absence predicate for the retained UTUN. Pure: production
//! passes the live `Interfaces`/`Snapshot`, tests pass real-structure values.
use crate::connection::macos::{Interfaces, routing::Snapshot};
use crate::connection::routes::Network;
use std::net::IpAddr;

/// `true` only when the old utun and its artefacts are genuinely gone.
///
/// A host route for a remaining VIP is preserved only when it demonstrably
/// belongs to a foreign interface that still carries that address, or when it
/// is a `RTF_LOCAL` route on a real loopback while a foreign interface carrying
/// the VIP is up. Any other index — even with the foreign address present — is
/// unknown evidence and returns `false` (Busy), never a delete.
pub(super) fn observed(
    name: &str,
    index: u16,
    vips: &[IpAddr],
    interfaces: &Interfaces,
    table: &Snapshot,
) -> bool {
    if interfaces
        .entries
        .values()
        .any(|entry| entry.name == name || entry.index == u32::from(index))
    {
        return false;
    }
    if table.records.iter().any(|record| record.interface == index) {
        return false;
    }
    for vip in vips {
        // Only an UP foreign interface carrying the VIP is an owner; a down
        // owner certifies nothing.
        let owners: Vec<_> = interfaces
            .entries
            .values()
            .filter(|entry| entry.addresses.contains(vip) && entry.flags & libc::IFF_UP as u32 != 0)
            .collect();
        let host = Network::host(*vip);
        let host_routes: Vec<_> = table
            .records
            .iter()
            .filter(|record| record.key.network == host)
            .collect();
        if !host_routes.is_empty() && owners.is_empty() {
            return false;
        }
        for record in host_routes {
            let belongs_to_owner = owners
                .iter()
                .any(|entry| entry.index == u32::from(record.interface));
            // A LOCAL route is incidental only when it sits on the real
            // loopback interface it names (that interface must be UP and
            // loopback; the loopback does not have to carry the VIP, the
            // foreign owner must exist and be UP).
            let loopback_local = record.flags & libc::RTF_LOCAL != 0
                && interfaces.entries.values().any(|entry| {
                    entry.index == u32::from(record.interface)
                        && entry.flags & libc::IFF_LOOPBACK as u32 != 0
                        && entry.flags & libc::IFF_UP as u32 != 0
                })
                && !owners.is_empty();
            if !belongs_to_owner && !loopback_local {
                return false;
            }
        }
    }
    true
}
