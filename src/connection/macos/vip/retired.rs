//! Typed passive absence metadata for a configured or failed retained UTUN.
//!
//! The value carries only name/index and the whole intended VIP list. It does
//! not pin a descriptor, borrow the controller, grant alias/route authority or
//! authorize deletes. Production origins (`ConfiguredUtun`/`VipFailure`) remain
//! opaque; only the private `cfg(test)` module may build one synthetically.
use super::{ConfiguredUtun, VipFailure};
use crate::connection::{
    ipsec::Error,
    macos::{Interfaces, routing::Snapshot},
    routes::Network,
};
use std::{fmt, net::IpAddr};

/// Opaque, passive retirement metadata: no ownership, no delete authority.
#[derive(Clone)]
pub struct RetiredUtun {
    name: String,
    index: u16,
    vips: Vec<IpAddr>,
}

impl fmt::Debug for RetiredUtun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetiredUtun")
            .field("name", &self.name)
            .field("index", &self.index)
            .field("vips", &self.vips)
            .finish()
    }
}

/// Union the whole intended list with every address the live interface really
/// has (implicit link-local included). No address is filtered or dropped; a
/// missing name/index or a read failure is an error, never partial metadata.
fn from_view(
    name: &str,
    index: u16,
    intended: &[IpAddr],
    interfaces: &Interfaces,
) -> Result<RetiredUtun, Error> {
    let entry = interfaces.entries.get(name).ok_or(Error::Changed)?;
    if entry.index != u32::from(index) {
        return Err(Error::Changed);
    }
    let mut vips = intended.to_vec();
    for address in &entry.addresses {
        if !vips.contains(address) {
            vips.push(*address);
        }
    }
    Ok(RetiredUtun {
        name: name.to_owned(),
        index,
        vips,
    })
}

impl ConfiguredUtun<'_> {
    /// Capture the actual retained name/index and the union of the whole VIP
    /// intention with every address the pinned interface really has. The same
    /// retained pin is revalidated before and after the fresh view; no
    /// controller/runtime gate runs during teardown, and a failure never
    /// consumes or closes the pin. On error the caller keeps its before-image
    /// fallback; incomplete metadata is never returned.
    pub fn retirement(&self) -> Result<RetiredUtun, Error> {
        self.retained.validate()?;
        let index = typed_index(self.index())?;
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let retired = from_view(self.name(), index, &self.vips, &interfaces)?;
        self.retained.validate()?;
        Ok(retired)
    }
}

impl VipFailure {
    pub fn retirement(&self) -> Result<RetiredUtun, Error> {
        self.retained.validate()?;
        let index = typed_index(self.retained.index())?;
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let retired = from_view(self.retained.name(), index, &self.intended, &interfaces)?;
        self.retained.validate()?;
        Ok(retired)
    }
}

fn typed_index(index: u32) -> Result<u16, Error> {
    u16::try_from(index)
        .ok()
        .filter(|index| *index > 0)
        .ok_or(Error::Invalid)
}

impl RetiredUtun {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    /// Fresh passive absence of this known domain only; unknown indexes are
    /// Busy and a read error is never `true`.
    pub fn gone(&self) -> Result<bool, Error> {
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let table = Snapshot::read().map_err(|_| Error::Unavailable)?;
        Ok(observed(
            self.name(),
            self.index(),
            &self.vips,
            &interfaces,
            &table,
        ))
    }
}

pub(in crate::connection::macos) fn observed(
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

#[cfg(test)]
mod tests;
