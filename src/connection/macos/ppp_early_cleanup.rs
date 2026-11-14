//! Read-only fallback when the retained process receipt predates discovery of
//! an addressed PPP link. Never deletes/destroys by a name, key or guessed PID.
use super::{
    Interfaces,
    process::{Identity, Process},
    routing::Snapshot,
    store,
};
use crate::connection::routes::{Error, Network};
use std::collections::BTreeSet;

pub(crate) fn complete(
    before: &Interfaces,
    table: &Snapshot,
    child: &Identity,
) -> Result<bool, Error> {
    let now = Interfaces::read().map_err(|_| Error::Unavailable)?;
    let routes = Snapshot::read()?;
    let records = store::read().map_err(|_| Error::Unavailable)?;
    let mut foreign = BTreeSet::new();
    let mut ours = BTreeSet::new();
    for interface in now
        .entries
        .values()
        .filter(|interface| ppp(&interface.name))
    {
        let matching: Vec<_> = records
            .iter()
            .filter(|record| record.interface.as_str() == interface.name)
            .collect();
        if matching.iter().any(|record| record.pid == child.pid) {
            ours.insert(interface.index);
        }
        if matching.len() != 1 {
            continue;
        }
        let Ok(owner) = Process::read(matching[0].pid) else {
            continue;
        };
        if owner.running
            && owner.uid == 0
            && owner.real_uid == 0
            && owner.executable == std::path::Path::new(crate::helper::ppp_supervisor::SYSTEM_PPP)
            && owner.identity != *child
        {
            foreign.insert(interface.index);
            ours.remove(&interface.index);
        }
    }
    Ok(observed(before, table, &now, &routes, &foreign, &ours))
}
fn ppp(name: &str) -> bool {
    name.starts_with("ppp")
}
fn observed(
    before: &Interfaces,
    table: &Snapshot,
    now: &Interfaces,
    routes: &Snapshot,
    foreign: &BTreeSet<u32>,
    ours: &BTreeSet<u32>,
) -> bool {
    for interface in now
        .entries
        .values()
        .filter(|interface| ppp(&interface.name))
    {
        if ours.contains(&interface.index) {
            return false;
        }
        if before.entries.get(&interface.name) != Some(interface)
            && !foreign.contains(&interface.index)
        {
            return false;
        }
    }
    let unchanged: BTreeSet<_> = table.records.iter().collect();
    for route in &routes.records {
        // Equality only preserves an unchanged preexisting observation; it is
        // never used as route ownership or authorization to mutate a key.
        if unchanged.contains(route) || foreign.contains(&u32::from(route.interface)) {
            continue;
        }
        let address = route.key.network.address();
        let host = route.key.network == Network::host(address);
        if host
            && route.flags & libc::RTF_LOCAL != 0
            && now
                .entries
                .values()
                .any(|interface| interface.addresses.contains(&address))
        {
            continue;
        }
        // Kernel neighbor-cache additions on an existing physical interface
        // are not new privileged routing policy. Static/PPP/unknown additions
        // remain pending, including a route whose ifnet already disappeared.
        if host
            && route.flags & libc::RTF_LLINFO != 0
            && route.flags & (libc::RTF_STATIC | libc::RTF_LOCAL) == 0
            && now.entries.values().any(|interface| {
                interface.index == u32::from(route.interface)
                    && !ppp(&interface.name)
                    && before
                        .entries
                        .get(&interface.name)
                        .is_some_and(|old| old.index == interface.index)
            })
        {
            continue;
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{
        macos::{interfaces::Interface, routing::Record},
        routes::Key,
    };
    use std::collections::BTreeMap;
    fn interface(name: &str, index: u32, ip: &str) -> Interface {
        Interface {
            name: name.into(),
            index,
            flags: libc::IFF_UP as u32,
            addresses: BTreeSet::from([ip.parse().unwrap()]),
        }
    }
    fn record(network: &str, index: u16, flags: i32) -> Record {
        Record {
            key: Key {
                network: network.parse().unwrap(),
                scope: 0,
            },
            interface: index,
            flags,
            gateway: None,
            source: None,
        }
    }
    #[test]
    fn early_cleanup_preserves_before_and_foreign_ppp_but_waits_for_our_or_unattributed_link() {
        let before = Interfaces {
            entries: BTreeMap::from([("en0".into(), interface("en0", 2, "192.0.2.2"))]),
        };
        let table = Snapshot {
            records: vec![record("0.0.0.0/0", 2, libc::RTF_UP)],
        };
        let mut now = before.clone();
        let routes = Snapshot {
            records: table.records.clone(),
        };
        assert!(observed(
            &before,
            &table,
            &now,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        now.entries
            .insert("ppp42".into(), interface("ppp42", 42, "10.20.0.2"));
        assert!(!observed(
            &before,
            &table,
            &now,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        assert!(observed(
            &before,
            &table,
            &now,
            &routes,
            &BTreeSet::from([42]),
            &BTreeSet::new()
        ));
        assert!(!observed(
            &before,
            &table,
            &now,
            &routes,
            &BTreeSet::from([42]),
            &BTreeSet::from([42])
        ));
        let mut old = now.clone();
        old.entries.get_mut("ppp42").unwrap().flags = 0;
        assert!(!observed(
            &old,
            &table,
            &now,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
    }
    #[test]
    fn early_cleanup_requires_implicit_local_and_unknown_policy_routes_to_disappear() {
        let before = Interfaces {
            entries: BTreeMap::from([("en0".into(), interface("en0", 2, "192.0.2.2"))]),
        };
        let table = Snapshot { records: vec![] };
        let mut routes = Snapshot {
            records: vec![record("10.20.0.2/32", 1, libc::RTF_LOCAL)],
        };
        assert!(!observed(
            &before,
            &table,
            &before,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        routes.records[0] = record("192.0.2.2/32", 1, libc::RTF_LOCAL);
        assert!(observed(
            &before,
            &table,
            &before,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        routes.records[0] = record("192.0.2.1/32", 2, libc::RTF_LLINFO);
        assert!(observed(
            &before,
            &table,
            &before,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        routes.records[0].flags |= libc::RTF_STATIC;
        assert!(!observed(
            &before,
            &table,
            &before,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        routes.records[0] = record("10.20.0.0/16", 42, libc::RTF_STATIC);
        assert!(!observed(
            &before,
            &table,
            &before,
            &routes,
            &BTreeSet::new(),
            &BTreeSet::new()
        ));
        assert!(observed(
            &before,
            &table,
            &before,
            &routes,
            &BTreeSet::from([42]),
            &BTreeSet::new()
        ));
    }
}
