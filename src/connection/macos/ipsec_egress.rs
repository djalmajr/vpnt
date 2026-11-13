//! Read-only selection of the original IPsec egress before charon starts.
//!
//! The token records the exact interface, source and resolved remote observed
//! before any tunnel route exists. It grants no route, cleanup or BYPASS
//! authority. `is_current` revalidates through the captured interface scope and
//! never falls back to a default lookup or DNS.
use super::{
    interfaces::{Interface, Interfaces},
    routing::Record,
};
use crate::{
    connection::routes::{Address, Error, Route},
    model::{Profile, VpnKind},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub struct IpsecEgress {
    profile: String,
    host: String,
    port: u16,
    local: IpAddr,
    remote: IpAddr,
    interface: Interface,
    route: Route,
    source: Option<Address>,
}

impl IpsecEgress {
    pub fn select(
        profile: &Profile,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<Self, Error> {
        select_with(&mut native::Native, profile, cancel, timeout)
    }

    pub fn is_current(
        &self,
        profile: &Profile,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<bool, Error> {
        self.is_current_with(&mut native::Native, profile, cancel, timeout)
    }

    pub fn local(&self) -> IpAddr {
        self.local
    }

    pub fn remote(&self) -> IpAddr {
        self.remote
    }

    pub fn interface_index(&self) -> u16 {
        self.route.interface
    }

    pub fn interface_name(&self) -> &str {
        &self.interface.name
    }

    pub fn gateway_route(&self) -> Route {
        self.route
    }

    fn is_current_with<S: Source>(
        &self,
        source: &mut S,
        profile: &Profile,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<bool, Error> {
        if timeout.is_zero() || timeout > Duration::from_secs(5) {
            return Err(Error::Invalid);
        }
        let deadline = Instant::now() + timeout;
        cancel_check(cancel)?;
        if profile.kind != VpnKind::Ipsec
            || profile.id != self.profile
            || profile.gateway != self.host
            || profile.port != self.port
        {
            return Ok(false);
        }
        let interfaces = source.interfaces(deadline, cancel)?;
        cancel_check(cancel)?;
        left(deadline)?;
        let Some(now) = interfaces.entries.get(&self.interface.name) else {
            return Ok(false);
        };
        if now.index != self.interface.index
            || now.flags & libc::IFF_UP as u32 == 0
            || now.addresses != self.interface.addresses
        {
            return Ok(false);
        }
        let index = u16::try_from(now.index).map_err(|_| Error::Invalid)?;
        let record = source.route(
            Address::unscoped(self.remote),
            index,
            left(deadline)?,
            cancel,
        )?;
        cancel_check(cancel)?;
        left(deadline)?;
        if record.key.scope != 0 && record.key.scope != index {
            return Ok(false);
        }
        let pin = record.gateway_pin(Address::unscoped(self.remote))?;
        if pin != self.route || record.source != self.source {
            return Ok(false);
        }
        let local = source.source(self.remote, self.port, index, left(deadline)?, cancel)?;
        cancel_check(cancel)?;
        left(deadline)?;
        Ok(local == self.local)
    }
}

pub(super) trait Source {
    fn resolve(
        &mut self,
        host: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Vec<IpAddr>, Error>;
    fn interfaces(&mut self, deadline: Instant, cancel: &AtomicBool) -> Result<Interfaces, Error>;
    fn route(
        &mut self,
        address: Address,
        scope: u16,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<Record, Error>;
    fn source(
        &mut self,
        remote: IpAddr,
        port: u16,
        index: u16,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<IpAddr, Error>;
}

fn select_with<S: Source>(
    source: &mut S,
    profile: &Profile,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<IpsecEgress, Error> {
    if profile.validate().is_err()
        || profile.kind != VpnKind::Ipsec
        || timeout.is_zero()
        || timeout > Duration::from_secs(5)
    {
        return Err(Error::Invalid);
    }
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    let deadline = Instant::now() + timeout;
    cancel_check(cancel)?;
    let remotes = source.resolve(&profile.gateway, deadline, cancel)?;
    cancel_check(cancel)?;
    left(deadline)?;
    let interfaces = source.interfaces(deadline, cancel)?;
    cancel_check(cancel)?;
    left(deadline)?;
    for remote in remotes {
        if !eligible(remote, &interfaces) {
            continue;
        }
        let remaining = left(deadline)?;
        let record = source.route(
            Address::unscoped(remote),
            0,
            remaining.min(Duration::from_secs(2)),
            cancel,
        )?;
        cancel_check(cancel)?;
        left(deadline)?;
        if record.key.scope != 0 && record.key.scope != record.interface {
            return Err(Error::Changed);
        }
        let pin = record.gateway_pin(Address::unscoped(remote))?;
        let index = pin.interface;
        let interface = interfaces
            .entries
            .values()
            .find(|interface| interface.index == u32::from(index))
            .ok_or(Error::Changed)?;
        if !usable(interface, remote) {
            return Err(Error::Unavailable);
        }
        if let Some(supplied) = record.source
            && (supplied.ip.is_ipv4() != remote.is_ipv4()
                || !interface.addresses.contains(&supplied.ip)
                || !supplied.valid_gateway())
        {
            return Err(Error::Changed);
        }
        let local = source.source(remote, profile.port, index, left(deadline)?, cancel)?;
        cancel_check(cancel)?;
        left(deadline)?;
        if local.is_ipv4() != remote.is_ipv4() || !interface.addresses.contains(&local) {
            return Err(Error::Changed);
        }
        if let Some(supplied) = record.source
            && supplied.ip != local
        {
            return Err(Error::Changed);
        }
        let egress = IpsecEgress {
            profile: profile.id.clone(),
            host: profile.gateway.clone(),
            port: profile.port,
            local,
            remote,
            interface: interface.clone(),
            route: pin,
            source: record.source,
        };
        if !egress.is_current_with(source, profile, cancel, left(deadline)?)? {
            return Err(Error::Changed);
        }
        return Ok(egress);
    }
    Err(Error::Invalid)
}

fn cancel_check(cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    Ok(())
}

fn left(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(Error::TimedOut)
}

fn eligible(address: IpAddr, interfaces: &Interfaces) -> bool {
    let link_local = matches!(address, IpAddr::V6(value) if value.is_unicast_link_local());
    !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_loopback()
        && address != IpAddr::V4(Ipv4Addr::BROADCAST)
        && !link_local
        && !interfaces
            .entries
            .values()
            .any(|interface| interface.addresses.contains(&address))
}

fn usable(interface: &Interface, remote: IpAddr) -> bool {
    interface.index != 0
        && interface.index <= u16::MAX as u32
        && interface.flags & libc::IFF_UP as u32 != 0
        && interface.flags & libc::IFF_LOOPBACK as u32 == 0
        && interface
            .addresses
            .iter()
            .any(|address| address.is_ipv4() == remote.is_ipv4())
}

pub(super) fn resolve_error(error: super::tcp::Error) -> Error {
    match error {
        super::tcp::Error::Canceled => Error::Canceled,
        super::tcp::Error::TimedOut => Error::TimedOut,
        super::tcp::Error::Invalid => Error::Invalid,
        _ => Error::Unavailable,
    }
}

mod native;
#[cfg(test)]
mod tests;
