//! Native read-only routing evidence. This module cannot add/delete routes.
mod codec;
mod read;
use crate::connection::routes::{Address, Error, Key, Network, NextHop, Route};
pub use read::{Reader, Snapshot};

#[derive(Clone, Debug)]
pub struct Record {
    pub key: Key,
    pub interface: u16,
    pub flags: i32,
    pub gateway: Option<Gateway>,
    pub source: Option<Address>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gateway {
    Address(Address),
    Link(u16),
}
impl Record {
    pub fn route(&self) -> Result<Route, Error> {
        if self.flags & libc::RTF_UP == 0
            || self.flags
                & (libc::RTF_REJECT
                    | libc::RTF_CONDEMNED
                    | libc::RTF_DEAD
                    | libc::RTF_LOCAL
                    | libc::RTF_BROADCAST
                    | libc::RTF_MULTICAST)
                != 0
        {
            return Err(Error::Conflict);
        }
        let next_hop = if self.flags & libc::RTF_BLACKHOLE != 0 {
            NextHop::Blackhole
        } else if self.flags & libc::RTF_GATEWAY != 0 {
            match self.gateway {
                Some(Gateway::Address(value)) => NextHop::Gateway(value),
                _ => return Err(Error::Invalid),
            }
        } else {
            NextHop::Interface
        };
        let route = Route {
            key: self.key,
            interface: self.interface,
            next_hop,
        };
        route.validate()?;
        Ok(route)
    }
    pub fn gateway_pin(&self, gateway: Address) -> Result<Route, Error> {
        if !gateway.valid_gateway()
            || !self.key.network.contains(gateway.ip)
            || (self.key.scope != 0 && gateway.zone != 0 && self.key.scope as u32 != gateway.zone)
        {
            return Err(Error::Invalid);
        }
        let mut route = self.route()?;
        if route.next_hop == NextHop::Blackhole {
            return Err(Error::Conflict);
        }
        route.key = Key {
            network: Network::host(gateway.ip),
            scope: 0,
        };
        Ok(route)
    }
}
