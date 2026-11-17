//! Read-only fallback when the retained process receipt predates discovery of
//! an addressed PPP link. Never deletes/destroys by a name, key or guessed PID.
use super::{Interfaces, ppp_control::ChildIdentity, process::Process, routing::Snapshot, store};
use crate::connection::routes::{Error, Network};
use std::collections::BTreeSet;

#[cfg(test)]
thread_local! {
    static OBSERVATION: std::cell::RefCell<Option<(Interfaces, Snapshot, Vec<store::Record>)>> = const { std::cell::RefCell::new(None) };
    static PROCESS: std::cell::RefCell<Option<Process>> = const { std::cell::RefCell::new(None) };
}

fn observe() -> Result<(Interfaces, Snapshot, Vec<store::Record>), Error> {
    #[cfg(test)]
    if let Some(observation) = OBSERVATION.with(|slot| slot.borrow_mut().take()) {
        return Ok(observation);
    }
    Ok((
        Interfaces::read().map_err(|_| Error::Unavailable)?,
        Snapshot::read()?,
        store::read().map_err(|_| Error::Unavailable)?,
    ))
}

fn observe_process(pid: u32) -> std::io::Result<Process> {
    #[cfg(test)]
    if let Some(process) = PROCESS.with(|slot| slot.borrow_mut().take()) {
        return Ok(process);
    }
    Process::read(pid)
}

pub(crate) fn complete(
    before: &Interfaces,
    table: &Snapshot,
    child: &ChildIdentity,
) -> Result<bool, Error> {
    let (now, routes, records) = observe()?;
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
        if matching
            .iter()
            .any(|record| record.key == child.service().key())
        {
            ours.insert(interface.index);
        }
        if matching.len() != 1 || matching[0].key == child.service().key() {
            continue;
        }
        let Some(pid) = matching[0].pid else {
            continue;
        };
        let Ok(owner) = observe_process(pid) else {
            continue;
        };
        if owner.running
            && owner.uid == 0
            && owner.real_uid == 0
            && owner.executable == std::path::Path::new(crate::helper::ppp_supervisor::SYSTEM_PPP)
            && owner.identity != **child
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
    fn complete_does_not_authorize_our_conflicting_pid_or_unattributed_foreign_link() {
        use crate::{connection::ssl::InterfaceName, helper::ppp_supervisor::ServiceId};
        let service = ServiceId::parse("12345678-1234-4123-8123-123456789ABC").unwrap();
        let child = ChildIdentity::fixture(
            super::super::process::Identity {
                pid: 42,
                start: (1, 0),
            },
            service,
        );
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                OBSERVATION.with(|slot| *slot.borrow_mut() = None);
                PROCESS.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        let fake_process = || Process {
            identity: super::super::process::Identity {
                pid: 99,
                start: (2, 0),
            },
            parent: 1,
            uid: 0,
            real_uid: 0,
            running: true,
            executable: crate::helper::ppp_supervisor::SYSTEM_PPP.into(),
        };
        let before = Interfaces::default();
        let table = Snapshot { records: vec![] };
        let now = Interfaces {
            entries: BTreeMap::from([("ppp42".into(), interface("ppp42", 42, "10.20.0.2"))]),
        };
        let record = store::Record {
            key: child.service().key(),
            interface: InterfaceName::parse("ppp42").unwrap(),
            pid: Some(99),
        };
        PROCESS.with(|slot| *slot.borrow_mut() = Some(fake_process()));
        OBSERVATION.with(|slot| {
            *slot.borrow_mut() = Some((
                now.clone(),
                Snapshot { records: vec![] },
                vec![record.clone()],
            ))
        });
        assert!(!complete(&before, &table, &child).unwrap());
        let mut foreign = record;
        foreign.key = "State:/Network/Service/other/PPP".into();
        PROCESS.with(|slot| *slot.borrow_mut() = Some(fake_process()));
        OBSERVATION.with(|slot| {
            *slot.borrow_mut() = Some((
                now.clone(),
                Snapshot { records: vec![] },
                vec![foreign.clone()],
            ))
        });
        assert!(complete(&before, &table, &child).unwrap());
        foreign.pid = None;
        OBSERVATION.with(|slot| {
            *slot.borrow_mut() = Some((now, Snapshot { records: vec![] }, vec![foreign]))
        });
        assert!(!complete(&before, &table, &child).unwrap());
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
