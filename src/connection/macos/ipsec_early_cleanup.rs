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
use crate::connection::routes::{Error, Network};

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
