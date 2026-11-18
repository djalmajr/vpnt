//! Validation of the network settings received from OpenVPN.
use std::{collections::BTreeMap, fmt, net::Ipv4Addr};

#[derive(Clone, Eq, PartialEq)]
pub struct NetworkConfig {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub mtu: Option<u16>,
    pub routes: Vec<Route>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_domains: Vec<String>,
    pub server: Option<Ipv4Addr>,
}
impl fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkConfig([redacted])")
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub network: Ipv4Addr,
    pub prefix: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    Malformed,
    MissingAddress,
    UnsupportedTopology,
    InvalidAddress,
    InvalidRoute,
    DefaultRoute,
    RouteCoversServer,
    InvalidDns,
    TooLarge,
}
impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed environment",
            Self::MissingAddress => "missing address",
            Self::UnsupportedTopology => "unsupported topology",
            Self::InvalidAddress => "invalid address",
            Self::InvalidRoute => "invalid route",
            Self::DefaultRoute => "default route",
            Self::RouteCoversServer => "route covers server",
            Self::InvalidDns => "invalid DNS",
            Self::TooLarge => "network configuration too large",
        })
    }
}
impl std::error::Error for NetworkError {}
fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && ip.octets()[0] != 0
}
fn mask_prefix(mask: &str) -> Option<u8> {
    let n = u32::from(mask.parse::<Ipv4Addr>().ok()?);
    let p = n.leading_ones() as u8;
    (n == u32::MAX.checked_shl(32 - u32::from(p)).unwrap_or(0)).then_some(p)
}
fn domain(s: &str) -> Option<String> {
    let s = s.to_ascii_lowercase();
    if s.len() > 253
        || !s.is_ascii()
        || s.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        None
    } else {
        Some(s)
    }
}
fn index(s: &str) -> Result<Option<usize>, NetworkError> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }
    let n = s.parse::<usize>().map_err(|_| NetworkError::TooLarge)?;
    if n > 256 {
        return Err(NetworkError::TooLarge);
    }
    Ok(Some(n))
}
pub fn from_env(pairs: &[(String, String)]) -> Result<NetworkConfig, NetworkError> {
    use NetworkError::*;
    if pairs.len() > 1024 {
        return Err(TooLarge);
    }
    let mut vars = BTreeMap::new();
    for (k, v) in pairs {
        vars.insert(k.as_str(), v.as_str());
    }
    let address = vars
        .get("ifconfig_local")
        .ok_or(MissingAddress)?
        .parse::<Ipv4Addr>()
        .map_err(|_| InvalidAddress)?;
    if !unicast(address) {
        return Err(InvalidAddress);
    }
    let mask = match vars.get("ifconfig_netmask") {
        Some(mask) => *mask,
        None if vars.contains_key("ifconfig_remote") => return Err(UnsupportedTopology),
        None => return Err(InvalidAddress),
    };
    let prefix = mask_prefix(mask).filter(|p| *p > 0).ok_or(InvalidAddress)?;
    let mtu = vars
        .get("tun_mtu")
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|v| (576..=9000).contains(v));
    let server = vars
        .get("trusted_ip")
        .and_then(|v| v.parse::<Ipv4Addr>().ok());
    let mut indexed = BTreeMap::<usize, (&str, Option<&str>)>::new();
    for (&key, &value) in &vars {
        if let Some(n) = key
            .strip_prefix("route_network_")
            .or_else(|| key.strip_prefix("route_netmask_"))
        {
            let Some(n) = index(n)? else { continue };
            if n == 0 {
                continue;
            }
            let e = indexed.entry(n).or_insert(("", None));
            if key.starts_with("route_network_") {
                e.0 = value;
            } else {
                e.1 = Some(value);
            }
        }
    }
    let mut routes = Vec::new();
    for (_, (net, mask)) in indexed {
        let ip = net.parse::<Ipv4Addr>().map_err(|_| InvalidRoute)?;
        let p = mask_prefix(mask.ok_or(InvalidRoute)?).ok_or(InvalidRoute)?;
        if p < 8 {
            return Err(DefaultRoute);
        }
        let bits = u32::from(ip);
        let mask = u32::MAX.checked_shl(32 - u32::from(p)).unwrap_or(0);
        if bits & !mask != 0 || ip.octets()[0] == 0 || ip.is_loopback() || ip.is_multicast() {
            return Err(InvalidRoute);
        }
        if server.is_some_and(|s| u32::from(s) & mask == bits) {
            return Err(RouteCoversServer);
        }
        let route = Route {
            network: ip,
            prefix: p,
        };
        if !routes.contains(&route) {
            routes.push(route);
        }
    }
    let mut dns_servers = Vec::new();
    let mut dns_domains = Vec::new();
    let mut foreign = Vec::new();
    for (&key, &value) in &vars {
        if let Some(suffix) = key.strip_prefix("foreign_option_") {
            if let Some(n) = index(suffix)? {
                foreign.push((n, value));
            }
        }
    }
    foreign.sort_by_key(|entry| entry.0);
    for (_, value) in foreign {
        let mut fields = value.split_whitespace();
        if fields.next() != Some("dhcp-option") {
            continue;
        }
        match fields.next() {
            Some("DNS") => {
                let ip = fields
                    .next()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .filter(|ip| unicast(*ip))
                    .ok_or(InvalidDns)?;
                if fields.next().is_some() || dns_servers.len() == 4 {
                    return Err(InvalidDns);
                }
                dns_servers.push(ip);
            }
            Some("DOMAIN" | "DOMAIN-SEARCH") => {
                let d = fields.next().and_then(domain).ok_or(InvalidDns)?;
                if fields.next().is_some() || dns_domains.len() == 16 {
                    return Err(InvalidDns);
                }
                dns_domains.push(d);
            }
            _ => {}
        }
    }
    Ok(NetworkConfig {
        address,
        prefix,
        mtu,
        routes,
        dns_servers,
        dns_domains,
        server,
    })
}
#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;
