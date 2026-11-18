//! Version-one JSON-line protocol. Only validated values reach the network backend.
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, net::Ipv4Addr};

pub const VERSION: u32 = 1;
pub const MAX_LINE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    UnsupportedVersion,
    NotOwned,
    Limit,
    InvalidAddress,
    InvalidRoute,
    InvalidDns,
    Backend,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunName(String);
impl TunName {
    pub fn parse(name: &str) -> Result<Self, ErrorCode> {
        let suffix = name.strip_prefix("vpnt").ok_or(ErrorCode::BadRequest)?;
        if !(1..=2).contains(&suffix.len())
            || !suffix.bytes().all(|c| c.is_ascii_digit())
            || (suffix.len() > 1 && suffix.starts_with('0'))
        {
            return Err(ErrorCode::BadRequest);
        }
        Ok(Self(name.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for TunName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Hello { version: u32 },
    OpenTun,
    Configure(Configure),
    CloseTun { ifname: String },
}
impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
        enum WireRequest {
            Hello { version: u32 },
            OpenTun {},
            Configure(Configure),
            CloseTun { ifname: String },
        }
        Ok(match WireRequest::deserialize(deserializer)? {
            WireRequest::Hello { version } => Self::Hello { version },
            WireRequest::OpenTun {} => Self::OpenTun,
            WireRequest::Configure(c) => Self::Configure(c),
            WireRequest::CloseTun { ifname } => Self::CloseTun { ifname },
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configure {
    pub ifname: String,
    pub address: String,
    pub prefix: u8,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    routes: Vec<WireRoute>,
    dns: WireDns,
}
fn default_mtu() -> u16 {
    1500
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoute {
    network: String,
    prefix: u8,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDns {
    servers: Vec<String>,
    domains: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub name: TunName,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    pub routes: Vec<Route>,
    pub dns: Dns,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub network: Ipv4Addr,
    pub prefix: u8,
}
#[derive(Debug, Clone)]
pub struct Dns {
    pub servers: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
}

fn unicast(address: Ipv4Addr) -> bool {
    address.octets()[0] != 0
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_loopback()
}
fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
impl Configure {
    pub fn validate(&self) -> Result<Config, ErrorCode> {
        let name = TunName::parse(&self.ifname)?;
        let address = self
            .address
            .parse::<Ipv4Addr>()
            .map_err(|_| ErrorCode::InvalidAddress)?;
        let routes = self
            .routes
            .iter()
            .map(|r| {
                Ok(Route {
                    network: r.network.parse().map_err(|_| ErrorCode::InvalidRoute)?,
                    prefix: r.prefix,
                })
            })
            .collect::<Result<Vec<_>, ErrorCode>>()?;
        let servers = self
            .dns
            .servers
            .iter()
            .map(|s| s.parse().map_err(|_| ErrorCode::InvalidDns))
            .collect::<Result<Vec<_>, _>>()?;
        let config = Config {
            name,
            address,
            prefix: self.prefix,
            mtu: self.mtu,
            routes,
            dns: Dns {
                servers,
                domains: self.dns.domains.clone(),
            },
        };
        config.validate()?;
        Ok(config)
    }
}
impl Config {
    // Public fields are required by the contract; recheck them at the backend boundary
    // so a caller cannot bypass validation by constructing or modifying a Config.
    pub(super) fn validate(&self) -> Result<(), ErrorCode> {
        if !unicast(self.address)
            || !(1..=32).contains(&self.prefix)
            || !(576..=9000).contains(&self.mtu)
        {
            return Err(ErrorCode::InvalidAddress);
        }
        if self.routes.len() > 256 {
            return Err(ErrorCode::InvalidRoute);
        }
        let mut routes = HashSet::new();
        for route in &self.routes {
            if !(8..=32).contains(&route.prefix)
                || route.network.octets()[0] == 0
                || route.network.is_loopback()
                || route.network.is_multicast()
                || u32::from(route.network)
                    & u32::MAX.checked_shr(u32::from(route.prefix)).unwrap_or(0)
                    != 0
                || !routes.insert(route)
            {
                return Err(ErrorCode::InvalidRoute);
            }
        }
        if self.dns.servers.len() > 4
            || self.dns.domains.len() > 16
            || self.dns.servers.iter().any(|s| !unicast(*s))
            || (!self.dns.domains.is_empty() && self.dns.servers.is_empty())
        {
            return Err(ErrorCode::InvalidDns);
        }
        let mut domains = HashSet::new();
        for domain in &self.dns.domains {
            if !valid_domain(domain) || !domains.insert(domain) {
                return Err(ErrorCode::InvalidDns);
            }
        }
        Ok(())
    }
}

pub fn parse_request(line: &[u8]) -> Result<Request, ErrorCode> {
    if line.len() > MAX_LINE || !line.ends_with(b"\n") || line[..line.len() - 1].contains(&b'\n') {
        return Err(ErrorCode::BadRequest);
    }
    let text = std::str::from_utf8(line).map_err(|_| ErrorCode::BadRequest)?;
    let request: Request = serde_json::from_str(text).map_err(|_| ErrorCode::BadRequest)?;
    match &request {
        Request::Hello { version } if *version != VERSION => {
            return Err(ErrorCode::UnsupportedVersion);
        }
        Request::CloseTun { ifname } => {
            TunName::parse(ifname)?;
        }
        _ => {}
    }
    Ok(request)
}

#[derive(Debug)]
pub enum Response {
    Ok,
    Version(u32),
    Opened(TunName),
    Error(ErrorCode),
}
pub fn encode_response(response: &Response) -> Vec<u8> {
    // Serialize each fixed wire shape in field order, rather than a sorted JSON map.
    #[derive(Serialize)]
    struct OkResponse {
        ok: bool,
    }
    #[derive(Serialize)]
    struct VersionResponse {
        ok: bool,
        version: u32,
    }
    #[derive(Serialize)]
    struct OpenedResponse<'a> {
        ok: bool,
        ifname: &'a str,
    }
    #[derive(Serialize)]
    struct ErrorResponse {
        ok: bool,
        error: ErrorCode,
    }
    let mut bytes = match response {
        Response::Ok => serde_json::to_vec(&OkResponse { ok: true }),
        Response::Version(version) => serde_json::to_vec(&VersionResponse {
            ok: true,
            version: *version,
        }),
        Response::Opened(name) => serde_json::to_vec(&OpenedResponse {
            ok: true,
            ifname: name.as_str(),
        }),
        Response::Error(error) => serde_json::to_vec(&ErrorResponse {
            ok: false,
            error: *error,
        }),
    }
    .expect("fixed response types serialize infallibly");
    bytes.push(b'\n');
    bytes
}
#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;

impl From<&Config> for Configure {
    fn from(config: &Config) -> Self {
        Self {
            ifname: config.name.to_string(),
            address: config.address.to_string(),
            prefix: config.prefix,
            mtu: config.mtu,
            routes: config
                .routes
                .iter()
                .map(|route| WireRoute {
                    network: route.network.to_string(),
                    prefix: route.prefix,
                })
                .collect(),
            dns: WireDns {
                servers: config.dns.servers.iter().map(ToString::to_string).collect(),
                domains: config.dns.domains.clone(),
            },
        }
    }
}

pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(request).expect("request fields serialize infallibly");
    bytes.push(b'\n');
    bytes
}

pub fn decode_response(line: &[u8]) -> Result<Response, ErrorCode> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireResponse {
        Version(VersionReply),
        Opened(OpenedReply),
        Error(ErrorReply),
        Ok(OkReply),
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VersionReply {
        ok: bool,
        version: u32,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OpenedReply {
        ok: bool,
        ifname: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ErrorReply {
        ok: bool,
        error: ErrorCode,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OkReply {
        ok: bool,
    }

    if line.len() > MAX_LINE || !line.ends_with(b"\n") || line[..line.len() - 1].contains(&b'\n') {
        return Err(ErrorCode::BadRequest);
    }
    match serde_json::from_slice(line).map_err(|_| ErrorCode::BadRequest)? {
        WireResponse::Version(reply) if reply.ok => Ok(Response::Version(reply.version)),
        WireResponse::Opened(reply) if reply.ok => {
            Ok(Response::Opened(TunName::parse(&reply.ifname)?))
        }
        WireResponse::Error(reply) if !reply.ok => Ok(Response::Error(reply.error)),
        WireResponse::Ok(reply) if reply.ok => Ok(Response::Ok),
        _ => Err(ErrorCode::BadRequest),
    }
}

// Read at most MAX_LINE bytes, leaving following frames in the buffered reader.
// An incomplete frame will be rejected by the wire decoder.
pub(super) fn read_line(reader: &mut impl std::io::BufRead) -> std::io::Result<Vec<u8>> {
    use std::io::{BufRead, Read};
    let mut bytes = Vec::new();
    reader.take(MAX_LINE as u64).read_until(b'\n', &mut bytes)?;
    Ok(bytes)
}
