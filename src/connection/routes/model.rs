use std::{net::IpAddr, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Conflict,
    Busy,
    Unavailable,
    Changed,
    Limit,
    Canceled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}
impl Network {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, Error> {
        let address = match address {
            IpAddr::V4(address) if prefix <= 32 => IpAddr::V4(
                (u32::from(address) & u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0)).into(),
            ),
            IpAddr::V6(address) if prefix <= 128 => IpAddr::V6(
                (u128::from(address) & u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0))
                    .into(),
            ),
            _ => return Err(Error::Invalid),
        };
        Ok(Self { address, prefix })
    }
    pub fn host(address: IpAddr) -> Self {
        Self {
            address,
            prefix: if address.is_ipv4() { 32 } else { 128 },
        }
    }
    pub fn address(self) -> IpAddr {
        self.address
    }
    pub fn prefix(self) -> u8 {
        self.prefix
    }
    pub fn contains(self, address: IpAddr) -> bool {
        Self::new(address, self.prefix) == Ok(self)
    }
}
impl FromStr for Network {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Error> {
        let (address, prefix) = value.split_once('/').ok_or(Error::Invalid)?;
        let prefix = prefix.parse::<u8>().map_err(|_| Error::Invalid)?;
        // The profile parser already enforces this; retain the boundary for
        // callers of route policy that do not originate in a stored profile.
        if value.len() > 49
            || prefix.to_string() != value.rsplit('/').next().ok_or(Error::Invalid)?
        {
            return Err(Error::Invalid);
        }
        Self::new(address.parse().map_err(|_| Error::Invalid)?, prefix)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Address {
    pub ip: IpAddr,
    pub zone: u32,
}
impl Address {
    pub fn unscoped(ip: IpAddr) -> Self {
        Self { ip, zone: 0 }
    }
    pub fn valid_gateway(self) -> bool {
        !self.ip.is_unspecified()
            && !self.ip.is_multicast()
            && self.ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            && match self.ip {
                IpAddr::V4(_) => self.zone == 0,
                IpAddr::V6(value) => {
                    if value.is_unicast_link_local() {
                        self.zone > 0
                    } else {
                        self.zone == 0
                    }
                }
            }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key {
    pub network: Network,
    pub scope: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextHop {
    Interface,
    Gateway(Address),
    Blackhole,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub key: Key,
    pub interface: u16,
    pub next_hop: NextHop,
}
impl Route {
    pub fn validate(self) -> Result<(), Error> {
        if self.interface == 0 {
            return Err(Error::Invalid);
        }
        if let NextHop::Gateway(address) = self.next_hop
            && (!address.valid_gateway()
                || address.ip.is_ipv4() != self.key.network.address().is_ipv4())
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
