//! Read-only selection of the SSL transport path before tunnel routes exist.
//! The resulting token is not deserializable or constructible by the IPC peer.
use super::{
    interfaces::{Interface, Interfaces},
    resolve,
    routing::Reader,
    tcp,
};
use crate::{
    connection::{
        routes::{Address, Error, NextHop},
        ssl::Binding,
    },
    model::{Profile, VpnKind},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
pub struct Egress {
    profile: String,
    host: String,
    port: u16,
    interface: Interface,
    gateway: Ipv4Addr,
    next_hop: NextHop,
    source: Option<Address>,
}
impl Egress {
    pub fn select(
        profile: &Profile,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if profile.validate().is_err()
            || profile.kind != VpnKind::Ssl
            || timeout.is_zero()
            || timeout > Duration::from_secs(5)
        {
            return Err(Error::Invalid);
        }
        let deadline = Instant::now() + timeout;
        let addresses =
            resolve::gateway_ipv4(&profile.gateway, deadline, canceled).map_err(resolve_error)?;
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let mut reader = Reader::open()?;
        for address in addresses {
            let IpAddr::V4(gateway) = address else {
                continue;
            };
            if !remote(gateway, &interfaces) {
                continue;
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::TimedOut)?;
            let record = reader.lookup(
                Address::unscoped(address),
                0,
                remaining.min(Duration::from_secs(2)),
                canceled,
            )?;
            let route = record.route()?;
            if route.next_hop == NextHop::Blackhole {
                return Err(Error::Conflict);
            }
            let interface = interfaces
                .entries
                .values()
                .find(|interface| interface.index == route.interface as u32)
                .ok_or(Error::Changed)?;
            if interface.flags & libc::IFF_UP as u32 == 0
                || interface.flags & libc::IFF_LOOPBACK as u32 != 0
                || !interface.addresses.iter().any(IpAddr::is_ipv4)
            {
                return Err(Error::Unavailable);
            }
            if let Some(source) = record.source
                && (!source.ip.is_ipv4() || !interface.addresses.contains(&source.ip))
            {
                return Err(Error::Changed);
            }
            let result = Self {
                profile: profile.id.clone(),
                host: profile.gateway.clone(),
                port: profile.port,
                interface: interface.clone(),
                gateway,
                next_hop: route.next_hop,
                source: record.source,
            };
            if !result.is_current(profile)? {
                return Err(Error::Changed);
            }
            if canceled.load(Ordering::Acquire) {
                return Err(Error::Canceled);
            }
            return Ok(result);
        }
        Err(Error::Invalid)
    }
    /// Scoped lookup ignores the tunnel's later global /1 routes. The original
    /// egress interface, addresses, next hop and source must remain usable.
    pub fn is_current(&self, profile: &Profile) -> Result<bool, Error> {
        if profile.kind != VpnKind::Ssl
            || profile.id != self.profile
            || profile.gateway != self.host
            || profile.port != self.port
        {
            return Ok(false);
        }
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
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
        let record = Reader::open()?.lookup(
            Address::unscoped(IpAddr::V4(self.gateway)),
            index,
            Duration::from_secs(1),
            &AtomicBool::new(false),
        )?;
        let route = record.route()?;
        Ok(route.interface == index
            && route.next_hop == self.next_hop
            && record.source == self.source)
    }
    pub(crate) fn binding(&self, profile: &Profile) -> Result<Binding, Error> {
        if !self.is_current(profile)? {
            return Err(Error::Changed);
        }
        Ok(Binding {
            interface: self.interface.name.clone(),
            index: self.interface.index,
            gateway: self.gateway,
        })
    }
}
fn remote(address: Ipv4Addr, interfaces: &Interfaces) -> bool {
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
        && !interfaces
            .entries
            .values()
            .any(|interface| interface.addresses.contains(&IpAddr::V4(address)))
}
fn resolve_error(error: tcp::Error) -> Error {
    match error {
        tcp::Error::Canceled => Error::Canceled,
        tcp::Error::TimedOut => Error::TimedOut,
        tcp::Error::Invalid => Error::Invalid,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile(host: &str) -> Profile {
        Profile {
            id: "egress-fixture".into(),
            name: "Egress fixture".into(),
            kind: VpnKind::Ssl,
            gateway: host.into(),
            username: "fixture".into(),
            networks: vec![],
            port: 443,
            certificate: String::new(),
            probe_host: "192.0.2.1".into(),
            probe_port: 443,
            probe_method: "tcp".into(),
        }
    }
    #[test]
    fn native_route_selection_is_read_only_and_profile_bound() {
        // TEST-NET is queried only via RTM_GET, never connected to or probed.
        let profile = profile("192.0.2.200");
        let canceled = AtomicBool::new(false);
        let egress = Egress::select(&profile, &canceled, Duration::from_secs(2)).unwrap();
        assert!(egress.is_current(&profile).unwrap());
        let binding = egress.binding(&profile).unwrap();
        assert!(binding.index > 0);
        assert_eq!(binding.gateway, "192.0.2.200".parse::<Ipv4Addr>().unwrap());
        let mut other = profile.clone();
        other.port = 444;
        assert!(!egress.is_current(&other).unwrap());
        other = profile.clone();
        other.gateway = "198.51.100.200".into();
        assert!(!egress.is_current(&other).unwrap());
        other = profile.clone();
        other.id = "other-profile".into();
        assert!(!egress.is_current(&other).unwrap());
        other = profile.clone();
        other.kind = VpnKind::Ipsec;
        assert!(!egress.is_current(&other).unwrap());
    }
    #[test]
    fn local_destinations_and_canceled_gateway_work_cannot_start_a_transport() {
        for host in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            assert!(matches!(
                Egress::select(
                    &profile(host),
                    &AtomicBool::new(false),
                    Duration::from_secs(1)
                ),
                Err(Error::Invalid)
            ));
        }
        assert!(matches!(
            Egress::select(
                &profile("localhost"),
                &AtomicBool::new(true),
                Duration::from_secs(1)
            ),
            Err(Error::Canceled)
        ));
    }
}
