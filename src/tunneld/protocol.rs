//! Versioned control and credential frames for a single tunnel generation.
use crate::helper::local_socket::{Budget, TimedStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt,
    io::{self, Read, Write},
    net::Ipv4Addr,
    num::NonZeroU32,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const VERSION: u32 = 1;
pub const CLEANUP_VERSION: u32 = 2;
/// Maximum encoded control frame size, including LF.
pub const MAX_LINE: usize = 16 * 1024;
pub(super) const MAX_CONFIRMATION: Duration = Duration::from_secs(1);

// The endpoints run in the same Linux time namespace as the writer.
pub(super) fn monotonic_ms() -> io::Result<u64> {
    Ok(monotonic()?.as_millis() as u64)
}

fn monotonic() -> io::Result<Duration> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into a valid timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Duration::new(now.tv_sec as u64, now.tv_nsec as u32))
}

#[derive(Clone, Copy)]
pub(super) struct FortinetDeadline {
    pub monotonic_ms: u64,
    pub instant: Instant,
}

impl FortinetDeadline {
    const LIMIT: Duration = Duration::from_secs(35);

    pub(super) fn new() -> io::Result<Self> {
        let instant = Instant::now();
        let now = monotonic()?;
        let monotonic_ms = (now + Self::LIMIT).as_millis() as u64;
        Self::from_sample(monotonic_ms, now, instant)
    }

    pub(super) fn from_wire(monotonic_ms: u64) -> io::Result<Self> {
        let instant = Instant::now();
        Self::from_sample(monotonic_ms, monotonic()?, instant)
    }

    pub(super) fn from_sample(
        monotonic_ms: u64,
        now: Duration,
        instant: Instant,
    ) -> io::Result<Self> {
        let remaining = Duration::from_millis(monotonic_ms)
            .checked_sub(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Fortinet Start expired"))?;
        if remaining > Self::LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Fortinet Start exceeds the establishment window",
            ));
        }
        // Sample Instant first so projection cannot extend the wire deadline.
        Ok(Self {
            monotonic_ms,
            instant: instant + remaining,
        })
    }
}

const IPSEC_SECRET_LIMIT: usize = 4096;
const FORTINET_SECRET_LIMIT: usize = 256;
const SPECIAL_NETWORKS: [(u32, u8); 6] = [
    (0x0000_0000, 8),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
    (0xffff_ffff, 32),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Prepared,
    Starting,
    NetworkReady,
    Stopping,
    Stopped,
    CleanupPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    UnsupportedVersion,
    PermissionDenied,
    Busy,
    MissingProgram,
    Timeout,
    Backend,
    CleanupPending,
    PolicyReapprovalRequired,
    FortinetLocalAddressDenied,
}

/// Transport errors expose only the OS error kind, never frame contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Io(io::ErrorKind),
    Protocol(ErrorCode),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "tunneld I/O: {kind}"),
            Self::Protocol(code) => write!(f, "tunneld protocol: {code:?}"),
        }
    }
}
impl std::error::Error for FrameError {}
impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}
impl From<ErrorCode> for FrameError {
    fn from(code: ErrorCode) -> Self {
        Self::Protocol(code)
    }
}

// Serde's derived struct and tagged enum visitors also accept positional
// sequences. Require a map first, then use the derived field validation.
macro_rules! named_object {
    (
        $(#[$outer:meta])*
        serde($($serde:tt)*)
        $visibility:vis $kind:ident $name:ident $body:tt
    ) => {
        $(#[$outer])*
        $visibility $kind $name $body

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                type Target = $name;

                #[derive(Deserialize)]
                #[serde(remote = "Target", $($serde)*)]
                $kind Wire $body

                struct NamedObjectVisitor;

                impl<'de> serde::de::Visitor<'de> for NamedObjectVisitor {
                    type Value = Target;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("an object with named fields")
                    }

                    fn visit_map<A: serde::de::MapAccess<'de>>(
                        self,
                        map: A,
                    ) -> Result<Self::Value, A::Error> {
                        Wire::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    }
                }

                deserializer.deserialize_map(NamedObjectVisitor)
            }
        }
    };
}

/// Server-assigned generation, also safe as a single private path component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Generation(String);

impl Generation {
    pub(crate) fn parse(text: String) -> Option<Self> {
        (text.len() == 32
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then_some(Self(text))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Generation {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(decoder)?)
            .ok_or_else(|| serde::de::Error::custom("invalid generation"))
    }
}

fn present_generation<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Generation>, D::Error> {
    Generation::deserialize(decoder).map(Some)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Pending,
    Stopped,
    Unknown,
}

pub(crate) enum InitialRequest {
    Prepare(Prepare),
    CleanupStatus(Generation),
}

named_object! {
    #[derive(Debug, Serialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)
    pub enum Request {
        Hello { version: u32 },
        PrepareIpsec(IpsecRequest),
        PrepareFortinet(FortinetRequest),
        Status {},
        Confirm { expires_ms: u64 },
        Stop {},
        CleanupStatus { generation: Generation },
    }
}

named_object! {
    #[derive(Debug, Serialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)
    pub enum Response {
        Version { version: u32 },
        Prepared {
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present_generation")]
            generation: Option<Generation>,
        },
        CleanupStatus { state: CleanupState },
        NetworkReady { binding: ProbeBinding },
        Status { state: State },
        Error { code: ErrorCode },
    }
}

// Both the negotiated IPsec selectors and the Fortinet split-route feed
// already have a 64-route ceiling.
const MAX_PROBE_ROUTES: usize = 64;

named_object! {
    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    serde(deny_unknown_fields)
    pub struct ProbeBinding {
        generation: Generation,
        ifindex: NonZeroU32,
        #[serde(deserialize_with = "deserialize_probe_local")]
        local: Ipv4Addr,
        #[serde(deserialize_with = "deserialize_probe_routes")]
        routes: Vec<CidrV4>,
    }
}

impl ProbeBinding {
    pub(crate) fn new(
        generation: Generation,
        ifindex: u32,
        local: Ipv4Addr,
        routes: Vec<CidrV4>,
    ) -> Option<Self> {
        if !valid_probe_local(local) || !valid_probe_routes(&routes) {
            return None;
        }
        Some(Self {
            generation,
            ifindex: NonZeroU32::new(ifindex)?,
            local,
            routes,
        })
    }

    pub(crate) fn generation(&self) -> &Generation {
        &self.generation
    }

    pub(crate) fn ifindex(&self) -> NonZeroU32 {
        self.ifindex
    }

    pub(crate) fn allows(&self, destination: Ipv4Addr) -> bool {
        destination != self.local
            && CidrV4::new(destination, 32).is_ok()
            && self.routes.iter().any(|route| {
                overlaps(
                    destination.into(),
                    32,
                    route.network().into(),
                    route.prefix(),
                )
            })
    }
}

fn valid_probe_local(local: Ipv4Addr) -> bool {
    !local.is_unspecified()
        && !local.is_loopback()
        && !local.is_multicast()
        && !local.is_broadcast()
}

fn valid_probe_routes(routes: &[CidrV4]) -> bool {
    routes.len() <= MAX_PROBE_ROUTES
        && routes
            .iter()
            .enumerate()
            .all(|(index, route)| !routes[..index].contains(route))
}

fn deserialize_probe_local<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Ipv4Addr, D::Error> {
    let local = Ipv4Addr::deserialize(decoder)?;
    valid_probe_local(local)
        .then_some(local)
        .ok_or_else(|| serde::de::Error::custom("invalid probe local address"))
}

fn deserialize_probe_routes<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<CidrV4>, D::Error> {
    let routes = Vec::deserialize(decoder)?;
    if valid_probe_routes(&routes) {
        Ok(routes)
    } else {
        Err(serde::de::Error::custom("invalid probe routes"))
    }
}

named_object! {
    #[derive(Debug, PartialEq, Eq, Serialize)]
    serde(deny_unknown_fields)
    pub struct Endpoint {
        #[serde(deserialize_with = "deserialize_host")]
        host: String,
        port: std::num::NonZeroU16,
    }
}
impl Endpoint {
    pub fn new(host: String, port: u16) -> Result<Self, ErrorCode> {
        let port = std::num::NonZeroU16::new(port).ok_or(ErrorCode::BadRequest)?;
        if !valid_host(&host) {
            return Err(ErrorCode::BadRequest);
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireCidr")]
pub struct CidrV4 {
    network: Ipv4Addr,
    prefix: u8,
}
named_object! {
    serde(deny_unknown_fields)
    struct WireCidr {
        network: Ipv4Addr,
        prefix: u8,
    }
}
impl TryFrom<WireCidr> for CidrV4 {
    type Error = FrameError;

    fn try_from(value: WireCidr) -> Result<Self, Self::Error> {
        Ok(Self::new(value.network, value.prefix)?)
    }
}

impl std::str::FromStr for CidrV4 {
    type Err = ErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (network, prefix) = value.split_once('/').ok_or(ErrorCode::BadRequest)?;
        let network = network.parse().map_err(|_| ErrorCode::BadRequest)?;
        let prefix = prefix.parse().map_err(|_| ErrorCode::BadRequest)?;
        let cidr = Self::new(network, prefix)?;
        if cidr.to_string() != value {
            return Err(ErrorCode::BadRequest);
        }
        Ok(cidr)
    }
}

impl fmt::Display for CidrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}
impl CidrV4 {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self, ErrorCode> {
        let base = u32::from(network);
        if !(8..=32).contains(&prefix)
            || base & mask(prefix) != base
            || SPECIAL_NETWORKS
                .iter()
                .any(|&(net, bits)| overlaps(base, prefix, net, bits))
        {
            return Err(ErrorCode::BadRequest);
        }
        Ok(Self { network, prefix })
    }

    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

named_object! {
    #[derive(Debug, Serialize)]
    serde(deny_unknown_fields)
    pub struct IpsecRequest {
        endpoint: Endpoint,
        #[serde(deserialize_with = "deserialize_username::<_, 200>")]
        username: String,
        #[serde(deserialize_with = "deserialize_networks")]
        networks: Vec<CidrV4>,
    }
}
impl IpsecRequest {
    pub fn new(
        endpoint: Endpoint,
        username: String,
        networks: Vec<CidrV4>,
    ) -> Result<Self, ErrorCode> {
        if !valid_username(&username, 200) || !valid_networks(&networks) {
            return Err(ErrorCode::BadRequest);
        }
        Ok(Self {
            endpoint,
            username,
            networks,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn networks(&self) -> &[CidrV4] {
        &self.networks
    }
}

named_object! {
    #[derive(Debug, Serialize)]
    serde(deny_unknown_fields)
    pub struct FortinetRequest {
        endpoint: Endpoint,
        #[serde(deserialize_with = "deserialize_username::<_, 64>")]
        username: String,
        #[serde(with = "pin")]
        certificate_sha256: [u8; 32],
    }
}
impl FortinetRequest {
    pub fn new(
        endpoint: Endpoint,
        username: String,
        certificate_sha256: [u8; 32],
    ) -> Result<Self, ErrorCode> {
        if !valid_username(&username, 64) {
            return Err(ErrorCode::BadRequest);
        }
        Ok(Self {
            endpoint,
            username,
            certificate_sha256,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }
}

fn mask(prefix: u8) -> u32 {
    u32::MAX << (32 - prefix)
}

fn overlaps(left: u32, left_prefix: u8, right: u32, right_prefix: u8) -> bool {
    let common = mask(left_prefix.min(right_prefix));
    left & common == right & common
}

fn valid_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return !SPECIAL_NETWORKS
            .iter()
            .any(|&(base, prefix)| u32::from(ip) & mask(prefix) == base);
    }

    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    // Keep legacy numeric address spellings out of the hostname path.
    let numeric_label = |label: &str| {
        label.bytes().all(|byte| byte.is_ascii_digit())
            || label.strip_prefix("0x").is_some_and(|hex| {
                !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    };
    host.len() <= 253 && host.split('.').all(valid_label) && !host.split('.').all(numeric_label)
}

fn valid_username(username: &str, max: usize) -> bool {
    (1..=max).contains(&username.len()) && !username.chars().any(char::is_control)
}

fn valid_networks(networks: &[CidrV4]) -> bool {
    (1..=64).contains(&networks.len())
        && networks.iter().enumerate().all(|(index, net)| {
            networks[..index].iter().all(|seen| {
                !overlaps(
                    u32::from(net.network),
                    net.prefix,
                    u32::from(seen.network),
                    seen.prefix,
                )
            })
        })
}

fn deserialize_host<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let host = String::deserialize(d)?;
    if valid_host(&host) {
        Ok(host)
    } else {
        Err(serde::de::Error::custom("invalid host"))
    }
}

fn deserialize_username<'de, D: serde::Deserializer<'de>, const MAX: usize>(
    d: D,
) -> Result<String, D::Error> {
    let username = String::deserialize(d)?;
    if valid_username(&username, MAX) {
        Ok(username)
    } else {
        Err(serde::de::Error::custom("invalid username"))
    }
}

fn deserialize_networks<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<CidrV4>, D::Error> {
    let networks = Vec::deserialize(d)?;
    if valid_networks(&networks) {
        Ok(networks)
    } else {
        Err(serde::de::Error::custom("invalid networks"))
    }
}

mod pin {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 64
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom("invalid certificate pin"));
        }
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte - b'a' + 10,
        };
        let mut pin = [0; 32];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (target, &[high, low]) in pin.iter_mut().zip(pairs) {
            *target = nibble(high) << 4 | nibble(low);
        }
        Ok(pin)
    }

    pub fn serialize<S: Serializer>(pin: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write;
        let mut text = String::with_capacity(64);
        for byte in pin {
            write!(text, "{byte:02x}").expect("writing to a String cannot fail");
        }
        serializer.serialize_str(&text)
    }
}

pub fn decode_request(line: &[u8]) -> Result<Request, ErrorCode> {
    match decode(line)? {
        Request::Hello { version } if !matches!(version, VERSION | CLEANUP_VERSION) => {
            Err(ErrorCode::UnsupportedVersion)
        }
        request => Ok(request),
    }
}

pub fn decode_response(line: &[u8]) -> Result<Response, ErrorCode> {
    decode(line)
}

fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, ErrorCode> {
    let payload = line.strip_suffix(b"\n").ok_or(ErrorCode::BadRequest)?;
    if line.len() > MAX_LINE || payload.contains(&b'\n') {
        return Err(ErrorCode::BadRequest);
    }
    serde_json::from_slice(line).map_err(|_| ErrorCode::BadRequest)
}

pub(super) fn write_control(
    writer: &mut impl Write,
    message: &impl Serialize,
) -> Result<(), FrameError> {
    let mut line = serde_json::to_vec(message).map_err(|_| ErrorCode::BadRequest)?;
    line.push(b'\n');
    if line.len() > MAX_LINE {
        return Err(ErrorCode::BadRequest.into());
    }
    writer.write_all(&line)?;
    Ok(())
}

pub(super) fn read_control<T>(
    reader: &mut impl Read,
    decode: impl FnOnce(&[u8]) -> Result<T, ErrorCode>,
) -> Result<T, FrameError> {
    // Read through LF only. An adjacent binary credential stays in the socket.
    let mut line = Zeroizing::new(vec![0; MAX_LINE]);
    for index in 0..line.len() {
        reader.read_exact(&mut line[index..=index])?;
        if line[index] == b'\n' {
            return Ok(decode(&line[..=index])?);
        }
    }
    Err(ErrorCode::BadRequest.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Ipsec,
    Fortinet,
}

#[derive(Debug)]
pub enum Prepare {
    Ipsec(IpsecRequest),
    Fortinet(FortinetRequest),
}
impl Prepare {
    pub fn backend(&self) -> Backend {
        match self {
            Self::Ipsec(_) => Backend::Ipsec,
            Self::Fortinet(_) => Backend::Fortinet,
        }
    }
}
impl From<Prepare> for Request {
    fn from(prepare: Prepare) -> Self {
        match prepare {
            Prepare::Ipsec(request) => Self::PrepareIpsec(request),
            Prepare::Fortinet(request) => Self::PrepareFortinet(request),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Status,
    Confirm(u64),
    Stop,
}

struct Secret<const CAPACITY: usize> {
    bytes: Zeroizing<Box<[u8]>>,
    length: usize,
}
impl<const CAPACITY: usize> Secret<CAPACITY> {
    fn empty(length: usize) -> Result<Self, ErrorCode> {
        if !(1..=CAPACITY).contains(&length) {
            return Err(ErrorCode::BadRequest);
        }
        Ok(Self {
            bytes: Zeroizing::new(vec![0; CAPACITY].into_boxed_slice()),
            length,
        })
    }

    fn new(value: &str) -> Result<Self, ErrorCode> {
        Self::validate(value.as_bytes())?;
        let mut secret = Self::empty(value.len())?;
        secret.bytes[..secret.length].copy_from_slice(value.as_bytes());
        Ok(secret)
    }

    fn read(reader: &mut impl Read) -> Result<Self, FrameError> {
        let mut length = Zeroizing::new([0; 2]);
        reader.read_exact(length.as_mut())?;
        let mut secret = Self::empty(usize::from(u16::from_be_bytes(*length)))?;
        reader.read_exact(&mut secret.bytes[..secret.length])?;
        Self::validate(secret.as_bytes())?;
        Ok(secret)
    }

    fn validate(bytes: &[u8]) -> Result<(), ErrorCode> {
        if std::str::from_utf8(bytes).is_err()
            || bytes.iter().any(|&byte| matches!(byte, b'\r' | b'\n' | 0))
        {
            return Err(ErrorCode::BadRequest);
        }
        Ok(())
    }

    fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&(self.length as u16).to_be_bytes())?;
        writer.write_all(self.as_bytes())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("validated credential UTF-8")
    }
}

enum CredentialFields {
    Ipsec {
        password: Secret<IPSEC_SECRET_LIMIT>,
        psk: Secret<IPSEC_SECRET_LIMIT>,
    },
    Fortinet(Secret<FORTINET_SECRET_LIMIT>),
}

pub struct Credentials(CredentialFields);
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials([redacted])")
    }
}
impl Credentials {
    pub fn ipsec(password: &str, psk: &str) -> Result<Self, ErrorCode> {
        Ok(Self(CredentialFields::Ipsec {
            password: Secret::new(password)?,
            psk: Secret::new(psk)?,
        }))
    }

    pub fn fortinet(password: &str) -> Result<Self, ErrorCode> {
        Ok(Self(CredentialFields::Fortinet(Secret::new(password)?)))
    }

    pub fn backend(&self) -> Backend {
        match self.0 {
            CredentialFields::Ipsec { .. } => Backend::Ipsec,
            CredentialFields::Fortinet(_) => Backend::Fortinet,
        }
    }

    pub fn password(&self) -> &str {
        match &self.0 {
            CredentialFields::Ipsec { password, .. } => password.as_str(),
            CredentialFields::Fortinet(password) => password.as_str(),
        }
    }

    pub fn psk(&self) -> Option<&str> {
        match &self.0 {
            CredentialFields::Ipsec { psk, .. } => Some(psk.as_str()),
            CredentialFields::Fortinet(_) => None,
        }
    }

    fn read(reader: &mut impl Read, backend: Backend) -> Result<Self, FrameError> {
        Ok(Self(match backend {
            Backend::Ipsec => CredentialFields::Ipsec {
                password: Secret::read(reader)?,
                psk: Secret::read(reader)?,
            },
            Backend::Fortinet => CredentialFields::Fortinet(Secret::read(reader)?),
        }))
    }

    pub(super) fn write(&self, writer: &mut impl Write) -> Result<(), FrameError> {
        match &self.0 {
            CredentialFields::Ipsec { password, psk } => {
                password.write(writer)?;
                psk.write(writer)?;
            }
            CredentialFields::Fortinet(password) => password.write(writer)?,
        }
        Ok(())
    }
}

pub(super) fn timed(stream: &UnixStream, deadline: Instant) -> Result<TimedStream, FrameError> {
    Ok(TimedStream::with_budget(
        stream.try_clone()?,
        Budget::until(deadline, None)?,
        MAX_LINE,
    )?)
}

// Linux's UnixStream::peek is unstable. Peek into zeroizing storage so an
// out-of-phase byte is never copied into a regular userspace buffer.
fn has_queued_byte(stream: &UnixStream, deadline: Instant) -> Result<bool, FrameError> {
    let budget = Budget::until(deadline, None)?;
    let mut byte = Zeroizing::new([0]);
    loop {
        budget.check()?;
        // SAFETY: the live stream owns the fd and byte is writable for 1 byte.
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        match count {
            1 => return Ok(true),
            0 => return Err(FrameError::Io(io::ErrorKind::UnexpectedEof)),
            _ => match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(false),
                kind => return Err(FrameError::Io(kind)),
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Hello,
    Prepare,
    Admission(Backend),
    Credentials(Backend),
    CleanupStatus,
    Active,
}

/// Wire decoder for the server. Authenticate the stream before constructing
/// this decoder, and admit the returned preparation before acknowledging it.
/// Errors consume the stream and discard any partially received credentials.
pub struct ServerDecoder {
    stream: Option<UnixStream>,
    phase: Phase,
    version: u32,
}
impl ServerDecoder {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream: Some(stream),
            phase: Phase::Hello,
            version: VERSION,
        }
    }

    fn in_phase<T>(
        &mut self,
        phase: Phase,
        deadline: Instant,
        operation: impl FnOnce(&UnixStream, &mut TimedStream) -> Result<(T, Phase), FrameError>,
    ) -> Result<T, FrameError> {
        let stream = self.stream.take().ok_or(ErrorCode::BadRequest)?;
        if self.phase != phase {
            return Err(ErrorCode::BadRequest.into());
        }
        let (result, next) = operation(&stream, &mut timed(&stream, deadline)?)?;
        self.phase = next;
        self.stream = Some(stream);
        Ok(result)
    }

    pub fn hello(&mut self, deadline: Instant) -> Result<(), FrameError> {
        let version = self.in_phase(Phase::Hello, deadline, |_, io| {
            match read_control(io, decode_request) {
                Ok(Request::Hello { version }) => {
                    write_control(io, &Response::Version { version })?;
                    Ok((version, Phase::Prepare))
                }
                Err(FrameError::Protocol(ErrorCode::UnsupportedVersion)) => {
                    write_control(
                        io,
                        &Response::Error {
                            code: ErrorCode::UnsupportedVersion,
                        },
                    )?;
                    Err(ErrorCode::UnsupportedVersion.into())
                }
                Ok(_) => Err(ErrorCode::BadRequest.into()),
                Err(error) => Err(error),
            }
        })?;
        self.version = version;
        Ok(())
    }

    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn initial_request(
        &mut self,
        deadline: Instant,
    ) -> Result<InitialRequest, FrameError> {
        let v2 = self.version == CLEANUP_VERSION;
        self.in_phase(Phase::Prepare, deadline, |_, io| {
            let prepare = match read_control(io, decode_request)? {
                Request::PrepareIpsec(request) => Prepare::Ipsec(request),
                Request::PrepareFortinet(request) => Prepare::Fortinet(request),
                Request::CleanupStatus { generation } if v2 => {
                    return Ok((
                        InitialRequest::CleanupStatus(generation),
                        Phase::CleanupStatus,
                    ));
                }
                _ => return Err(ErrorCode::BadRequest.into()),
            };
            let backend = prepare.backend();
            Ok((InitialRequest::Prepare(prepare), Phase::Admission(backend)))
        })
    }

    pub(crate) fn reply_cleanup(
        &mut self,
        state: CleanupState,
        deadline: Instant,
    ) -> Result<(), FrameError> {
        self.in_phase(Phase::CleanupStatus, deadline, |_, io| {
            write_control(io, &Response::CleanupStatus { state })?;
            Ok(((), Phase::CleanupStatus))
        })
    }

    #[cfg(test)]
    pub fn prepare(&mut self, deadline: Instant) -> Result<Prepare, FrameError> {
        match self.initial_request(deadline)? {
            InitialRequest::Prepare(offer) => Ok(offer),
            InitialRequest::CleanupStatus(_) => {
                self.stream.take();
                Err(ErrorCode::BadRequest.into())
            }
        }
    }

    #[cfg(test)]
    pub fn prepared(&mut self, deadline: Instant) -> Result<(), FrameError> {
        self.acknowledge(None, deadline)
    }

    pub(crate) fn acknowledge(
        &mut self,
        generation: Option<Generation>,
        deadline: Instant,
    ) -> Result<(), FrameError> {
        if generation.is_some() != (self.version == CLEANUP_VERSION) {
            self.stream.take();
            return Err(ErrorCode::BadRequest.into());
        }
        let Phase::Admission(backend) = self.phase else {
            self.stream.take();
            return Err(ErrorCode::BadRequest.into());
        };
        self.in_phase(Phase::Admission(backend), deadline, |stream, io| {
            // Reject pipelining already visible in the socket. This check
            // cannot establish whether the client has received the ACK.
            if has_queued_byte(stream, deadline)? {
                return Err(ErrorCode::BadRequest.into());
            }
            write_control(io, &Response::Prepared { generation })?;
            Ok(((), Phase::Credentials(backend)))
        })
    }

    pub fn credentials(&mut self, deadline: Instant) -> Result<Credentials, FrameError> {
        let Phase::Credentials(backend) = self.phase else {
            self.stream.take();
            return Err(ErrorCode::BadRequest.into());
        };
        self.in_phase(Phase::Credentials(backend), deadline, |_, io| {
            let credentials = Credentials::read(io, backend)?;
            Ok((credentials, Phase::Active))
        })
    }

    pub fn command(&mut self, deadline: Instant) -> Result<Command, FrameError> {
        let v2 = self.version == CLEANUP_VERSION;
        self.in_phase(Phase::Active, deadline, |_, io| {
            let command = match read_control(io, decode_request)? {
                Request::Status {} => Command::Status,
                Request::Confirm { expires_ms } if v2 => Command::Confirm(expires_ms),
                Request::Stop {} => Command::Stop,
                _ => return Err(ErrorCode::BadRequest.into()),
            };
            Ok((command, Phase::Active))
        })
    }

    pub(crate) fn reply_ready(
        &mut self,
        binding: ProbeBinding,
        deadline: Instant,
    ) -> Result<(), FrameError> {
        if self.version != CLEANUP_VERSION {
            self.stream.take();
            return Err(ErrorCode::BadRequest.into());
        }
        self.in_phase(Phase::Active, deadline, |_, io| {
            write_control(io, &Response::NetworkReady { binding })?;
            Ok(((), Phase::Active))
        })
    }

    pub fn reply_status(&mut self, state: State, deadline: Instant) -> Result<(), FrameError> {
        self.in_phase(Phase::Active, deadline, |_, io| {
            write_control(io, &Response::Status { state })?;
            Ok(((), Phase::Active))
        })
    }

    pub(super) fn reply_unconfirmed(&mut self, deadline: Instant) -> Result<(), FrameError> {
        self.in_phase(Phase::Active, deadline, |_, io| {
            write_control(
                io,
                &Response::Error {
                    code: ErrorCode::Timeout,
                },
            )?;
            Ok(((), Phase::Active))
        })
    }

    pub fn reject(mut self, code: ErrorCode, deadline: Instant) -> Result<(), FrameError> {
        let stream = self.stream.take().ok_or(ErrorCode::BadRequest)?;
        write_control(&mut timed(&stream, deadline)?, &Response::Error { code })
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
