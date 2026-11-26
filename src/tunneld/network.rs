//! Journaled Linux XFRM effects serialized by the shared network writer lock.
use super::protocol::{CidrV4, Generation, ProbeBinding};
use crate::netlease::NetworkGuard;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub(super) const RECEIPT: &str = "network.json";
const MAX_REQID: u16 = 0x3fff;
// iproute2 defaults to RTPROT_BOOT for the explicit routes added by netd.
const PROTOCOL: &str = "boot";
const MAX_OUTPUT: usize = 1024 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Egress {
    dev: String,
    prefsrc: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    ifindex: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    generation: String,
    boot: String,
    netns: (u64, u64),
    pub(super) reqid: u16,
    pub(super) if_id: u32,
    remote: Ipv4Addr,
    egress: Egress,
    routes: Vec<CidrV4>,
    vip: Option<Ipv4Addr>,
    creating: bool,
    ifindex: Option<u32>,
    routes_intended: usize,
    address_intended: bool,
    confirmed: bool,
    pub(super) complete: bool,
}

struct Namespace {
    _fd: File,
    id: (u64, u64),
    boot: String,
}

impl Namespace {
    fn current() -> io::Result<Self> {
        let fd = File::open("/proc/self/ns/net")?;
        let meta = fd.metadata()?;
        Ok(Self {
            _fd: fd,
            id: (meta.dev(), meta.ino()),
            boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
        })
    }
}

pub(super) fn valid_generation(name: &str) -> bool {
    name.len() == 32
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Receipt {
    pub(super) fn select_routes(&mut self, selectors: Vec<CidrV4>) -> io::Result<()> {
        if selectors.is_empty()
            || !selectors.iter().enumerate().all(|(index, selected)| {
                !selectors[..index].contains(selected)
                    && self.routes.iter().any(|r| contains(r, selected))
            })
        {
            return Err(invalid("negotiated selectors do not match the policy"));
        }
        self.routes = selectors;
        Ok(())
    }

    fn name(&self) -> String {
        format!("vpnti{}", self.reqid)
    }

    fn marker(&self) -> String {
        format!("vpnt:{}", self.generation)
    }

    fn validate(&self, directory: &Path, namespace: &Namespace) -> io::Result<()> {
        if !valid_generation(&self.generation)
            || directory.file_name().and_then(|n| n.to_str()) != Some(&self.generation)
            || !(1..=MAX_REQID).contains(&self.reqid)
            || self.if_id != u32::from(self.reqid)
            || self.routes_intended > self.routes.len()
            || self.address_intended && self.vip.is_none()
            || self.netns != namespace.id
            || self.boot != namespace.boot
        {
            return Err(invalid(
                "receipt identity does not match generation and namespace",
            ));
        }
        Ok(())
    }

    pub(super) fn load(directory: &Path, _guard: &NetworkGuard) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(RECEIPT))?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != directory.metadata()?.uid()
            || meta.mode() & 0o7777 != 0o600
        {
            return Err(invalid("unprotected network receipt"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut bytes)?;
        let receipt: Self = decode(&bytes)?;
        receipt.validate(directory, &Namespace::current()?)?;
        Ok(receipt)
    }

    pub(super) fn save(&self, directory: &Path, _guard: &NetworkGuard) -> io::Result<()> {
        // Only the renamed receipt is authoritative after interruption.
        let temp = directory.join("network.tmp");
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.sync_all()?;
        fs::rename(temp, directory.join(RECEIPT))?;
        File::open(directory)?.sync_all()
    }
}

/// Order cancellation with the start of admission effects. Polling can
/// observe the flag without waiting for the current effect to start.
#[derive(Default)]
pub(super) struct SetupCancellation {
    cancelled: Arc<AtomicBool>,
    effects: Mutex<()>,
}

impl SetupCancellation {
    pub(super) fn cancel(&self) {
        let _effects = self.effects.lock().expect("setup effects");
        self.cancelled.store(true, Ordering::Release);
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(super) fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub(super) fn check(&self) -> io::Result<()> {
        if self.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "client canceled setup",
            ));
        }
        Ok(())
    }

    pub(super) fn start<T>(&self, start: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let _effects = self.effects.lock().expect("setup effects");
        self.check()?;
        start()
    }
}

type Run = dyn Fn(&str, &[&str], Option<&SetupCancellation>, Option<Instant>) -> io::Result<Vec<u8>>
    + Send
    + Sync;

pub(super) struct Network(Box<Run>);

impl Default for Network {
    fn default() -> Self {
        Self(Box::new(run_command))
    }
}

#[derive(Deserialize)]
struct Link {
    ifname: String,
    ifindex: u32,
    link: Option<String>,
    ifalias: Option<String>,
    flags: Vec<String>,
    linkinfo: Option<LinkInfo>,
}

#[derive(Deserialize)]
struct LinkInfo {
    info_kind: String,
    info_data: Option<serde_json::Value>,
}

impl Link {
    fn xfrm_id(&self) -> io::Result<Option<u32>> {
        let Some(info) = self
            .linkinfo
            .as_ref()
            .filter(|info| info.info_kind == "xfrm")
        else {
            return Ok(None);
        };
        let id = info
            .info_data
            .as_ref()
            .and_then(|data| data.get("if_id"))
            .and_then(|id| id.as_str())
            .ok_or_else(|| invalid("unrecognized XFRM link ID"))?;
        number(id).map(Some)
    }
}

#[derive(Deserialize)]
struct Route {
    dst: String,
    dev: Option<String>,
    protocol: Option<String>,
    table: Option<String>,
    scope: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    nexthops: Option<serde_json::Value>,
    gateway: Option<std::net::IpAddr>,
    nhid: Option<u32>,
    metric: Option<u32>,
    prefsrc: Option<std::net::IpAddr>,
    encap: Option<serde_json::Value>,
    via: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AddressList {
    ifindex: u32,
    addr_info: Vec<Address>,
}

#[derive(Deserialize)]
struct Address {
    family: String,
    local: Ipv4Addr,
    prefixlen: u8,
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > MAX_OUTPUT {
        return Err(invalid("network response exceeds limit"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid("invalid network JSON response"))
}

fn number(s: &str) -> io::Result<u32> {
    s.strip_prefix("0x")
        .map_or_else(|| s.parse(), |hex| u32::from_str_radix(hex, 16))
        .map_err(|_| invalid("invalid XFRM identifier"))
}

fn xfrm_mark(text: &str) -> io::Result<(u32, u32)> {
    let (value, mask) = text
        .split_once('/')
        .ok_or_else(|| invalid("missing XFRM mark mask"))?;
    Ok((number(value)?, number(mask)?))
}

#[derive(PartialEq, Eq)]
struct EspState {
    src: IpAddr,
    dst: IpAddr,
    spi: u32,
    reqid: u32,
    if_id: Option<u32>,
    mark: Option<(u32, u32)>,
    tunnel: bool,
}

fn esp_states(text: &str) -> io::Result<Vec<EspState>> {
    let mut lines = text.lines().filter(|line| !line.is_empty()).peekable();
    let mut states = Vec::new();
    while let Some(header) = lines.next() {
        let fields: Vec<_> = header.split_ascii_whitespace().collect();
        let ["src", src, "dst", dst] = fields.as_slice() else {
            return Err(invalid("unrecognized XFRM state header"));
        };
        let mut identity = None;
        let mut if_id = None;
        let mut mark = None;
        for line in std::iter::from_fn(|| lines.next_if(|line| line.starts_with('\t'))) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            match fields.as_slice() {
                ["proto", _, ..] if identity.is_none() => identity = Some(fields),
                ["proto", ..] => return Err(invalid("ambiguous XFRM state protocol")),
                ["if_id", value] if if_id.is_none() => if_id = Some(number(value)?),
                ["if_id", ..] => return Err(invalid("invalid XFRM state if_id")),
                ["mark", value, ..] if mark.is_none() => mark = Some(xfrm_mark(value)?),
                ["mark", ..] => return Err(invalid("invalid XFRM state mark")),
                _ => {}
            }
        }
        let fields = identity.ok_or_else(|| invalid("missing XFRM state protocol"))?;
        if fields[1] != "esp" {
            continue;
        }
        let field = |name| {
            fields
                .windows(2)
                .find(|pair| pair[0] == name)
                .ok_or_else(|| invalid("incomplete ESP state key"))
                .and_then(|pair| number(pair[1]))
        };
        let src: IpAddr = src
            .parse()
            .map_err(|_| invalid("invalid ESP source address"))?;
        let dst: IpAddr = dst
            .parse()
            .map_err(|_| invalid("invalid ESP destination address"))?;
        if src.is_ipv4() != dst.is_ipv4() {
            return Err(invalid("inconsistent ESP address family"));
        }
        states.push(EspState {
            src,
            dst,
            spi: field("spi")?,
            reqid: field("reqid")?,
            if_id,
            mark,
            tunnel: fields.windows(2).any(|pair| pair == ["mode", "tunnel"]),
        });
    }
    Ok(states)
}

struct XfrmPolicyKey<'a> {
    index: u32,
    direction: &'a str,
    if_id: u32,
    policy_type: Option<&'a str>,
}

fn xfrm_policy_keys<'a>(text: &'a str, receipt: &Receipt) -> io::Result<Vec<XfrmPolicyKey<'a>>> {
    let Some(vip) = receipt.vip else {
        return Ok(Vec::new());
    };
    let vip = (u32::from(vip), 32);
    let mut lines = text.lines().filter(|line| !line.is_empty()).peekable();
    let mut keys = Vec::new();
    while let Some(header) = lines.next() {
        if !header.starts_with("src ") {
            return Err(invalid("unrecognized XFRM policy dump"));
        }
        let mut direction = None;
        let mut mark = None;
        let mut if_id = None;
        let mut templates = 0;
        let mut owned_template = false;
        while let Some(line) = lines.next_if(|line| line.starts_with('\t')) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            match fields.as_slice() {
                ["tmpl", "src", src, "dst", dst] => {
                    templates += 1;
                    let details = lines
                        .next_if(|line| line.starts_with("\t\t"))
                        .unwrap_or_default();
                    let details: Vec<_> = details.split_ascii_whitespace().collect();
                    owned_template = details.starts_with(&["proto", "esp"])
                        && details.windows(2).any(|pair| pair == ["mode", "tunnel"])
                        && src
                            .parse()
                            .ok()
                            .zip(dst.parse().ok())
                            .is_some_and(|(src, dst)| matches_transport(receipt, src, dst));
                }
                ["tmpl", ..] => templates += 1,
                ["if_id", value] if if_id.is_none() => if_id = Some(number(value)?),
                ["if_id", ..] => return Err(invalid("invalid XFRM policy if_id")),
                ["dir", ..] if direction.is_none() => direction = Some(fields),
                ["dir", ..] => return Err(invalid("ambiguous XFRM policy direction")),
                ["mark", value, ..] if mark.is_none() => mark = Some(xfrm_mark(value)?),
                ["mark", ..] => return Err(invalid("invalid XFRM policy mark")),
                _ => {}
            }
        }
        let Some(if_id) = if_id.filter(|if_id| *if_id == receipt.if_id) else {
            continue;
        };
        if mark.unwrap_or_default() != (0, 0) || templates != 1 || !owned_template {
            continue;
        }
        let selectors: Vec<_> = header.split_ascii_whitespace().collect();
        let (src, dst) = match selectors.as_slice() {
            ["src", src, "dst", dst] => (*src, *dst),
            ["src", src, "dst", dst, "uid", uid] if uid.parse::<u32>().is_ok() => (*src, *dst),
            _ => continue,
        };
        let (Ok(src), Ok(dst)) = (prefix(src), prefix(dst)) else {
            continue;
        };
        if !receipt
            .routes
            .iter()
            .map(route_key)
            .any(|route| (src == vip && dst == route) || (dst == vip && src == route))
        {
            continue;
        }
        let Some(fields) = direction else {
            return Err(invalid("missing XFRM policy direction"));
        };
        let ["dir", direction @ ("out" | "in" | "fwd"), ..] = fields.as_slice() else {
            return Err(invalid("invalid XFRM policy direction"));
        };
        let field = |name| {
            fields
                .windows(2)
                .find(|pair| pair[0] == name)
                .map(|pair| pair[1])
        };
        let index = field("index")
            .map(number)
            .transpose()?
            .filter(|index| *index != 0)
            .ok_or_else(|| invalid("missing XFRM policy index"))?;
        let policy_type = field("ptype");
        if !matches!(policy_type, None | Some("main" | "sub")) {
            return Err(invalid("invalid XFRM policy type"));
        }
        keys.push(XfrmPolicyKey {
            index,
            direction,
            if_id,
            policy_type,
        });
    }
    Ok(keys)
}

fn matches_transport(receipt: &Receipt, src: IpAddr, dst: IpAddr) -> bool {
    let local = IpAddr::V4(receipt.egress.prefsrc);
    let remote = IpAddr::V4(receipt.remote);
    (src == local && dst == remote) || (src == remote && dst == local)
}

pub(super) fn cidr_text(cidr: &CidrV4) -> String {
    format!("{}/{}", cidr.network(), cidr.prefix())
}

pub(super) fn prefix(text: &str) -> io::Result<(u32, u8)> {
    let (address, length) = text.split_once('/').unwrap_or((text, "32"));
    let addr = address
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid("invalid FIB address"))?;
    let bits = length
        .parse::<u8>()
        .ok()
        .filter(|n| *n <= 32)
        .ok_or_else(|| invalid("invalid FIB prefix"))?;
    Ok((u32::from(addr), bits))
}

pub(super) fn parse_cidr(text: &str) -> io::Result<CidrV4> {
    let (base, length) = prefix(text)?;
    CidrV4::new(base.into(), length).map_err(|_| invalid("invalid policy route"))
}

pub(super) fn overlaps(a: (u32, u8), b: (u32, u8)) -> bool {
    let shift = 32 - a.1.min(b.1);
    shift == 32 || (a.0 >> shift) == (b.0 >> shift)
}

pub(super) fn route_key(route: &CidrV4) -> (u32, u8) {
    (route.network().into(), route.prefix())
}

fn contains(route: &CidrV4, selected: &CidrV4) -> bool {
    route.prefix() <= selected.prefix() && overlaps(route_key(route), route_key(selected))
}

fn rule_word(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| number(value.as_str()?).ok())
}

#[derive(PartialEq)]
pub(super) struct PolicyInventory {
    rules: Vec<Value>,
    additional_tables: BTreeMap<String, Vec<Value>>,
}

impl PolicyInventory {
    pub(super) fn require_unchanged(&self, current: &Self) -> io::Result<()> {
        if self != current {
            return Err(invalid(
                "IPv4 policy routing inventory changed during configuration",
            ));
        }
        Ok(())
    }
}

pub(super) fn check_ipv4_rules(
    read_ip: impl Fn(&[&str]) -> io::Result<Vec<u8>>,
    protected: &[(u32, u8)],
) -> io::Result<PolicyInventory> {
    let rules: Vec<Value> = decode(&read_ip(&["-4", "-j", "rule", "show"])?)?;
    let standard = [(0, "local"), (32766, "main"), (32767, "default")];
    let mut seen = [false; 3];
    let mut additional_tables = BTreeMap::new();
    for rule in &rules {
        let priority = rule.get("priority").and_then(Value::as_u64);
        let table = rule.get("table").and_then(Value::as_str).filter(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                && name.as_bytes()[0].is_ascii_alphanumeric()
        });
        let reject = |reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "IPv4 policy rule priority {} table {}: {reason}",
                    priority.map_or_else(|| "unknown".into(), |n| n.to_string()),
                    table.unwrap_or("-")
                ),
            )
        };
        let Some(fields) = rule.as_object() else {
            return Err(reject("invalid rule"));
        };
        if !priority.is_some_and(|n| u32::try_from(n).is_ok())
            || rule["src"] != "all"
            || rule.get("dst").is_some_and(|dst| dst != "all")
        {
            return Err(reject("unsupported selector"));
        }
        if fields.len() == 3
            && let Some(index) = standard
                .iter()
                .position(|&(pref, name)| priority == Some(pref) && table == Some(name))
        {
            if std::mem::replace(&mut seen[index], true) {
                return Err(reject("duplicate standard rule"));
            }
            continue;
        }

        let plain = |key: &str| matches!(key, "priority" | "src" | "dst" | "table");
        if let Some(mark) = rule.get("fwmark") {
            // iproute2 omits the mask for an exact mark match. The effective
            // mark must exclude zero, and the rule must not negate the match.
            let mask = rule.get("fwmask").map_or(Some(u32::MAX), rule_word);
            let marked_only = rule_word(mark)
                .zip(mask)
                .is_some_and(|(mark, mask)| mark & mask != 0);
            let has_table = rule.get("table").is_some();
            let has_action = rule.get("action").is_some();
            let lookup = !has_action && matches!(table, Some("main" | "default" | "254" | "253"));
            let terminal = !has_table
                && matches!(
                    rule["action"].as_str(),
                    Some("unreachable" | "blackhole" | "prohibit")
                );
            if marked_only
                && (lookup || terminal)
                && fields
                    .keys()
                    .all(|key| plain(key) || matches!(key.as_str(), "fwmark" | "fwmask" | "action"))
            {
                continue;
            }
            return Err(reject("unsupported marked rule"));
        }

        let Some(table) = table.filter(|name| {
            !matches!(*name, "local" | "main" | "default" | "all" | "unspec")
                && !matches!(name.parse::<u32>(), Ok(0 | 253..=255))
        }) else {
            return Err(reject("unsupported table"));
        };
        if !fields.keys().all(|key| plain(key)) {
            return Err(reject("unsupported rule fields"));
        }
        if let Entry::Vacant(entry) = additional_tables.entry(table.to_owned()) {
            let routes: Vec<Value> = read_ip(&["-4", "-j", "route", "show", "table", table])
                .and_then(|bytes| decode(&bytes))
                .map_err(|_| reject("could not read the routing table"))?;
            for route in &routes {
                let dst = route["dst"]
                    .as_str()
                    .ok_or_else(|| reject("could not read the routing table"))?;
                if dst == "default" {
                    return Err(reject("default route in an additional table"));
                }
                let dst = prefix(dst).map_err(|_| reject("invalid route destination"))?;
                if dst.1 == 0 {
                    return Err(reject("default route in an additional table"));
                }
                if protected.iter().any(|scope| overlaps(*scope, dst)) {
                    return Err(reject("route overlaps protected destinations"));
                }
            }
            entry.insert(routes);
        }
    }
    if let Some(index) = seen.iter().position(|present| !present) {
        let (priority, table) = standard[index];
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing IPv4 policy rule priority {priority} table {table}"),
        ));
    }
    Ok(PolicyInventory {
        rules,
        additional_tables,
    })
}

pub(super) fn verify_tunnel_routes(
    read_ip: impl Fn(&[&str]) -> io::Result<Vec<u8>>,
    routes: &[CidrV4],
    interface: &str,
) -> io::Result<()> {
    #[derive(Deserialize)]
    struct SelectedDevice {
        dev: String,
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    for route in routes {
        let first = route.network().to_string();
        let selected: Vec<SelectedDevice> =
            decode(&read_ip(&["-4", "-j", "route", "get", &first])?)?;
        let [selected] = selected.as_slice() else {
            return Err(invalid("ambiguous tunnel route lookup"));
        };
        if selected.dev != interface
            || selected
                .kind
                .as_deref()
                .is_some_and(|kind| kind != "unicast")
        {
            return Err(invalid(
                "tunnel route lookup selected a different interface",
            ));
        }
    }
    Ok(())
}

pub(super) fn rollback_error(error: io::Error, cleanup: io::Result<()>) -> io::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup) => io::Error::new(
            error.kind(),
            format!("{error}; network rollback failed: {cleanup}"),
        ),
    }
}

impl Network {
    #[cfg(test)]
    pub(super) fn fake(
        run: impl Fn(&str, &[&str]) -> io::Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self(Box::new(move |program, args, cancel, deadline| {
            check_deadline(deadline)?;
            match cancel {
                Some(cancel) => cancel.start(|| run(program, args)),
                None => run(program, args),
            }
        }))
    }

    fn ip(&self, args: &[&str]) -> io::Result<Vec<u8>> {
        self.run_ip(args, None)
    }

    fn run_ip(&self, args: &[&str], cancel: Option<&SetupCancellation>) -> io::Result<Vec<u8>> {
        (self.0)("/usr/bin/ip", args, cancel, None)
    }

    fn json<T: DeserializeOwned>(&self, args: &[&str]) -> io::Result<T> {
        decode(&self.ip(args)?)
    }

    fn json_until<T: DeserializeOwned>(
        &self,
        args: &[&str],
        deadline: Option<Instant>,
    ) -> io::Result<T> {
        decode(&(self.0)("/usr/bin/ip", args, None, deadline)?)
    }

    pub(super) fn resolve(&self, hostname: &str, approved: &[Ipv4Addr]) -> io::Result<Ipv4Addr> {
        if let Ok(address) = hostname.parse() {
            return approved
                .contains(&address)
                .then_some(address)
                .ok_or_else(|| invalid("literal transport is outside policy"));
        }
        type ResolveAddress = (i32, i32, [u8; 4]);
        #[derive(Deserialize)]
        struct Resolved {
            data: (Vec<ResolveAddress>, String, u64),
        }
        let reply: Resolved = decode(&(self.0)(
            "/usr/bin/busctl",
            &[
                "--system",
                "--json=short",
                "--timeout=3s",
                "call",
                "org.freedesktop.resolve1",
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
                "ResolveHostname",
                "isit",
                "0",
                hostname,
                "2",
                "1",
            ],
            None,
            None,
        )?)?;
        if reply
            .data
            .0
            .iter()
            .any(|(_, family, _)| *family != libc::AF_INET)
        {
            return Err(invalid("resolver returned a non-IPv4 record"));
        }
        reply
            .data
            .0
            .into_iter()
            .map(|(_, _, bytes)| Ipv4Addr::from(bytes))
            .filter(|ip| approved.contains(ip))
            .min()
            .ok_or_else(|| invalid("no resolved transport is authorized"))
    }

    fn links(&self, deadline: Option<Instant>) -> io::Result<Vec<Link>> {
        self.json_until(&["-j", "-d", "link", "show"], deadline)
    }

    fn routes(&self, family: &str) -> io::Result<Vec<Route>> {
        self.json(&[family, "-j", "-d", "route", "show", "table", "all"])
    }

    fn egress(&self, remote: Ipv4Addr) -> io::Result<Egress> {
        #[derive(Deserialize)]
        struct SelectedRoute {
            dev: String,
            prefsrc: Ipv4Addr,
            gateway: Option<Ipv4Addr>,
        }
        let routes: Vec<SelectedRoute> =
            self.json(&["-4", "-j", "route", "get", &remote.to_string()])?;
        let [route] = routes.as_slice() else {
            return Err(invalid("ambiguous egress lookup"));
        };
        let links = self.links(None)?;
        let link = links
            .iter()
            .find(|link| link.ifname == route.dev && link.flags.iter().any(|flag| flag == "UP"))
            .ok_or_else(|| invalid("egress link unavailable"))?;
        if link.ifindex == 0 || link.ifname.starts_with("vpnt") || link.xfrm_id()?.is_some() {
            return Err(invalid("egress is a VPN link"));
        }
        Ok(Egress {
            dev: route.dev.clone(),
            prefsrc: route.prefsrc,
            gateway: route.gateway,
            ifindex: link.ifindex,
        })
    }

    fn xfrm_ids(&self) -> io::Result<(Vec<u32>, Vec<u32>)> {
        let mut ids = (Vec::new(), Vec::new());
        for args in [
            &["xfrm", "state", "list", "nokeys"][..],
            &["xfrm", "policy", "list"][..],
        ] {
            let bytes = self.ip(args)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid XFRM dump"))?;
            // iproute2 prints XFRM inventories as text, even in JSON mode.
            for line in text.lines() {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                match fields.as_slice() {
                    ["if_id", value] => ids.0.push(number(value)?),
                    ["if_id", ..] => return Err(invalid("invalid XFRM if_id field")),
                    ["proto", ..] => {
                        let reqid = fields
                            .windows(2)
                            .find(|pair| pair[0] == "reqid")
                            .ok_or_else(|| invalid("missing XFRM reqid field"))?;
                        ids.1.push(number(reqid[1])?);
                    }
                    _ if line.starts_with('\t') || line.starts_with("src ") || line.is_empty() => {}
                    _ => return Err(invalid("unrecognized XFRM dump")),
                }
            }
        }
        Ok(ids)
    }

    fn policy_inventory(
        &self,
        requested: &[(u32, u8)],
        vip: Option<Ipv4Addr>,
        approved: &[Ipv4Addr],
        remote: Ipv4Addr,
        egress: &Egress,
    ) -> io::Result<PolicyInventory> {
        let protected = approved
            .iter()
            .copied()
            .chain([remote, egress.prefsrc])
            .chain(egress.gateway);
        if protected
            .clone()
            .any(|ip| requested.iter().any(|r| overlaps(*r, (ip.into(), 32))) || vip == Some(ip))
        {
            return Err(invalid("VPN scope conflicts with protected transport"));
        }
        let mut policy_scope = requested.to_vec();
        policy_scope.extend(protected.chain(vip).map(|ip| (ip.into(), 32)));
        check_ipv4_rules(|args| self.ip(args), &policy_scope)
    }

    fn fib_clear(
        &self,
        requested: &[(u32, u8)],
        vip: Option<Ipv4Addr>,
        approved: &[Ipv4Addr],
        remote: Ipv4Addr,
        egress: &Egress,
    ) -> io::Result<PolicyInventory> {
        let inventory = self.policy_inventory(requested, vip, approved, remote, egress)?;
        let mut default_count = 0;
        let mut has_egress_device = false;
        let mut has_egress_default = false;
        for existing in self.routes("-4")? {
            if matches!(existing.dst.as_str(), "default" | "0.0.0.0/0") {
                if existing.kind.as_deref() != Some("unicast")
                    || existing.dev.as_deref().is_none_or(str::is_empty)
                    || existing.nexthops.is_some()
                    || existing.nhid.is_some()
                    || existing.encap.is_some()
                    || existing.via.is_some()
                    || existing
                        .table
                        .as_deref()
                        .is_some_and(|table| table != "main")
                {
                    return Err(invalid("nonstandard default route"));
                }
                for address in existing.gateway.into_iter().chain(existing.prefsrc) {
                    let std::net::IpAddr::V4(ip) = address else {
                        return Err(invalid("nonstandard default route"));
                    };
                    if requested
                        .iter()
                        .any(|route| overlaps(*route, (ip.into(), 32)))
                        || vip == Some(ip)
                    {
                        return Err(invalid("VPN scope conflicts with protected transport"));
                    }
                }
                default_count += 1;
                let same_device = existing.dev.as_deref() == Some(&egress.dev);
                has_egress_device |= same_device;
                has_egress_default |= same_device
                    && existing.gateway == egress.gateway.map(Into::into)
                    && existing
                        .prefsrc
                        .is_none_or(|src| src == std::net::IpAddr::V4(egress.prefsrc));
                continue;
            }
            let existing = prefix(&existing.dst)?;
            if requested.iter().any(|route| overlaps(*route, existing))
                || vip.is_some_and(|ip| overlaps((ip.into(), 32), existing))
            {
                return Err(invalid("VPN scope conflicts with an existing route"));
            }
        }
        // Preserve the direct/no-default cases; with competing defaults the
        // full egress must identify one of the default paths.
        if default_count > 0 && (!has_egress_device || default_count > 1 && !has_egress_default) {
            return Err(invalid("default routes do not match the proved egress"));
        }
        Ok(inventory)
    }

    pub(super) fn plan(
        &self,
        _guard: &NetworkGuard,
        generation: &str,
        remote: Ipv4Addr,
        approved: &[Ipv4Addr],
        routes: Vec<CidrV4>,
    ) -> io::Result<Receipt> {
        let namespace = Namespace::current()?;
        let egress = self.egress(remote)?;
        let requested: Vec<_> = routes.iter().map(route_key).collect();
        self.fib_clear(&requested, None, approved, remote, &egress)?;
        let links = self.links(None)?;
        let ids = self.xfrm_ids()?;
        let link_ids: Vec<_> = links.iter().map(Link::xfrm_id).collect::<io::Result<_>>()?;
        let reqid = (1..=MAX_REQID)
            .find(|n| {
                let id = u32::from(*n);
                !ids.0.contains(&id)
                    && !ids.1.contains(&id)
                    && !link_ids.contains(&Some(id))
                    && !links.iter().any(|link| link.ifname == format!("vpnti{n}"))
            })
            .ok_or_else(|| invalid("no XFRM identifier is available"))?;
        Ok(Receipt {
            generation: generation.into(),
            boot: namespace.boot,
            netns: namespace.id,
            reqid,
            if_id: reqid.into(),
            remote,
            egress,
            routes,
            vip: None,
            creating: false,
            ifindex: None,
            routes_intended: 0,
            address_intended: false,
            confirmed: false,
            complete: false,
        })
    }

    #[cfg(test)]
    pub(super) fn install(
        &self,
        guard: &NetworkGuard,
        directory: &Path,
        receipt: &mut Receipt,
        vip: Ipv4Addr,
        approved: &[Ipv4Addr],
    ) -> io::Result<()> {
        self.install_checked(
            guard,
            directory,
            receipt,
            vip,
            approved,
            &SetupCancellation::default(),
        )
    }

    pub(super) fn install_checked(
        &self,
        guard: &NetworkGuard,
        directory: &Path,
        receipt: &mut Receipt,
        vip: Ipv4Addr,
        approved: &[Ipv4Addr],
        cancel: &SetupCancellation,
    ) -> io::Result<()> {
        cancel.check()?;
        let namespace = Namespace::current()?;
        receipt.validate(directory, &namespace)?;
        CidrV4::new(vip, 32).map_err(|_| invalid("invalid virtual IPv4"))?;
        if self.egress(receipt.remote)? != receipt.egress {
            return Err(invalid("egress changed between start and establishment"));
        }
        let requested: Vec<_> = receipt.routes.iter().map(route_key).collect();
        let inventory = self.fib_clear(
            &requested,
            Some(vip),
            approved,
            receipt.remote,
            &receipt.egress,
        )?;
        let name = receipt.name();
        if self.link(receipt)?.is_some() {
            return Err(invalid("reserved interface name is already in use"));
        }
        receipt.vip = Some(vip);
        // Record the link intent first, then advance the same receipt before
        // each address or route write. Unattempted keys cannot be removed.
        receipt.creating = true;
        receipt.save(directory, guard)?;
        // Keep add and ownership marking in the same cancellation scope.
        // Cleanup can only delete a marked link, and ip link add does not
        // install the alias on a newly created XFRM link.
        receipt.ifindex = Some(cancel.start(|| {
            self.ip(&[
                "link",
                "add",
                "name",
                &name,
                "type",
                "xfrm",
                "dev",
                &receipt.egress.dev,
                "if_id",
                &receipt.if_id.to_string(),
            ])?;
            let link = self
                .link(receipt)?
                .ok_or_else(|| invalid("XFRM link missing after add"))?;
            if link.ifalias.is_some() {
                return Err(invalid("new XFRM link unexpectedly marked"));
            }
            self.ip(&["link", "set", "dev", &name, "alias", &receipt.marker()])?;
            Ok(link.ifindex)
        })?);
        self.owned_link(receipt)?
            .ok_or_else(|| invalid("XFRM link missing after marking"))?;
        receipt.save(directory, guard)?;
        self.run_ip(
            &["link", "set", "dev", &name, "addrgenmode", "none"],
            Some(cancel),
        )?;
        receipt.address_intended = true;
        receipt.save(directory, guard)?;
        self.run_ip(
            &[
                "-4",
                "addr",
                "add",
                &format!("{vip}/32"),
                "dev",
                &name,
                "noprefixroute",
            ],
            Some(cancel),
        )?;
        self.run_ip(&["link", "set", "dev", &name, "up"], Some(cancel))?;
        for (index, route) in receipt.routes.iter().enumerate() {
            receipt.routes_intended = index + 1;
            receipt.save(directory, guard)?;
            self.route_change("add", route, &name, Some(cancel))?;
        }
        let current = self
            .owned_link(receipt)?
            .ok_or_else(|| invalid("XFRM link missing after configuration"))?;
        if !current.flags.iter().any(|flag| flag == "UP")
            || !self.address_present(receipt, &current)?
            || self.applied_routes(receipt)?.len() != receipt.routes.len()
        {
            return Err(invalid("network configuration confirmation failed"));
        }
        let paths = (|| {
            if self.egress(receipt.remote)? != receipt.egress {
                return Err(invalid("network configuration confirmation failed"));
            }
            verify_tunnel_routes(|args| self.ip(args), &receipt.routes, &name)?;
            // Recheck the entire protected scope after the sampled lookups.
            let current_inventory = self.policy_inventory(
                &requested,
                Some(vip),
                approved,
                receipt.remote,
                &receipt.egress,
            )?;
            inventory.require_unchanged(&current_inventory)
        })();
        if let Err(error) = paths {
            return Err(rollback_error(error, self.clean_link(receipt)));
        }
        cancel.check()?;
        receipt.confirmed = true;
        receipt.save(directory, guard)
    }

    fn link(&self, receipt: &Receipt) -> io::Result<Option<Link>> {
        self.link_until(receipt, None)
    }

    fn link_until(&self, receipt: &Receipt, deadline: Option<Instant>) -> io::Result<Option<Link>> {
        let name = receipt.name();
        let mut owned = None;
        for link in self.links(deadline)? {
            if link.ifname == name {
                if owned.is_some()
                    || link.ifindex == 0
                    || link.xfrm_id()? != Some(receipt.if_id)
                    || link.link.as_deref() != Some(&receipt.egress.dev)
                {
                    return Err(invalid("reserved XFRM link identity changed"));
                }
                owned = Some(link);
            } else if link.ifalias.as_deref() == Some(&receipt.marker())
                || link.xfrm_id()? == Some(receipt.if_id)
                || receipt.ifindex == Some(link.ifindex)
            {
                return Err(invalid("XFRM link identity found under a different name"));
            }
        }
        Ok(owned)
    }

    fn owned_link(&self, receipt: &Receipt) -> io::Result<Option<Link>> {
        self.owned_link_until(receipt, None)
    }

    fn owned_link_until(
        &self,
        receipt: &Receipt,
        deadline: Option<Instant>,
    ) -> io::Result<Option<Link>> {
        let link = self.link_until(receipt, deadline)?;
        if link.as_ref().is_some_and(|link| {
            link.ifalias.as_deref() != Some(&receipt.marker())
                || receipt.ifindex.is_some_and(|index| index != link.ifindex)
        }) {
            return Err(invalid("XFRM link ownership cannot be proven"));
        }
        Ok(link)
    }

    /// A fresh identity observation for the already confirmed receipt.
    pub(super) fn probe_binding(
        &self,
        _guard: &NetworkGuard,
        receipt: &Receipt,
        deadline: Instant,
    ) -> io::Result<ProbeBinding> {
        if !receipt.confirmed || receipt.complete || receipt.routes_intended != receipt.routes.len()
        {
            return Err(invalid("XFRM probe scope is unconfirmed"));
        }
        let link = self
            .owned_link_until(receipt, Some(deadline))?
            .filter(|link| {
                receipt.ifindex == Some(link.ifindex) && link.flags.iter().any(|flag| flag == "UP")
            })
            .ok_or_else(|| invalid("XFRM probe link is unproven"))?;
        if !self.address_present_until(receipt, &link, Some(deadline))? {
            return Err(invalid("XFRM probe address is unproven"));
        }
        let generation = Generation::parse(receipt.generation.clone())
            .ok_or_else(|| invalid("invalid probe generation"))?;
        let local = receipt
            .vip
            .ok_or_else(|| invalid("missing probe address"))?;
        ProbeBinding::new(generation, link.ifindex, local, receipt.routes.clone())
            .ok_or_else(|| invalid("invalid XFRM probe scope"))
    }

    fn route_change(
        &self,
        op: &str,
        route: &CidrV4,
        name: &str,
        cancel: Option<&SetupCancellation>,
    ) -> io::Result<()> {
        self.run_ip(
            &[
                "-4",
                "route",
                op,
                &cidr_text(route),
                "dev",
                name,
                "table",
                "main",
                "proto",
                PROTOCOL,
                "scope",
                "link",
            ],
            cancel,
        )?;
        Ok(())
    }

    fn applied_routes(&self, receipt: &Receipt) -> io::Result<Vec<CidrV4>> {
        let name = receipt.name();
        let mut applied: Vec<CidrV4> = Vec::new();
        for existing in self
            .routes("-4")?
            .into_iter()
            .filter(|r| r.dev.as_deref() == Some(&name))
        {
            let dst = prefix(&existing.dst)?;
            if existing.table.as_deref() == Some("local")
                && existing.kind.as_deref() == Some("local")
                && existing.protocol.as_deref() == Some("kernel")
                && receipt.address_intended
                && receipt.vip.is_some_and(|vip| dst == (vip.into(), 32))
            {
                continue;
            }
            let route = receipt.routes[..receipt.routes_intended]
                .iter()
                .find(|r| route_key(r) == dst)
                .filter(|r| !applied.contains(r))
                .filter(|_| {
                    existing.table.as_deref().is_none_or(|t| t == "main")
                        && existing.kind.as_deref() == Some("unicast")
                        && existing.protocol.as_deref() == Some(PROTOCOL)
                        && existing.scope.as_deref() == Some("link")
                        && existing.gateway.is_none()
                        && existing.metric.is_none()
                        && existing.nhid.is_none()
                        && existing.nexthops.is_none()
                        && existing.prefsrc.is_none()
                        && existing.encap.is_none()
                        && existing.via.is_none()
                })
                .ok_or_else(|| invalid("unexpected IPv4 route on XFRM link"))?;
            applied.push(*route);
        }
        if self.routes("-6")?.iter().any(|r| {
            r.dev.as_deref() == Some(&name)
                && !(r.dst == "ff00::/8"
                    && r.kind.as_deref() == Some("multicast")
                    && r.table.as_deref() == Some("local")
                    && r.protocol.as_deref() == Some("kernel"))
        }) {
            return Err(invalid("unexpected IPv6 route on XFRM link"));
        }
        Ok(applied)
    }

    fn address_present(&self, receipt: &Receipt, link: &Link) -> io::Result<bool> {
        self.address_present_until(receipt, link, None)
    }

    fn address_present_until(
        &self,
        receipt: &Receipt,
        link: &Link,
        deadline: Option<Instant>,
    ) -> io::Result<bool> {
        let result: Vec<AddressList> =
            self.json_until(&["-j", "addr", "show", "dev", &link.ifname], deadline)?;
        let [row] = result.as_slice() else {
            return Err(invalid("ambiguous address inventory"));
        };
        if row.ifindex != link.ifindex {
            return Err(invalid("address inventory link changed"));
        }
        match row.addr_info.as_slice() {
            [] => Ok(false),
            [addr]
                if receipt.address_intended
                    && addr.family == "inet"
                    && addr.prefixlen == 32
                    && Some(addr.local) == receipt.vip =>
            {
                Ok(true)
            }
            _ => Err(invalid("unexpected address on XFRM link")),
        }
    }

    pub(super) fn clean(
        &self,
        guard: &NetworkGuard,
        directory: &Path,
        receipt: &Receipt,
    ) -> io::Result<()> {
        self.clean_interface(guard, directory, receipt)?;
        self.clean_stopped_xfrm(guard, receipt)
    }

    pub(super) fn clean_interface(
        &self,
        _guard: &NetworkGuard,
        directory: &Path,
        receipt: &Receipt,
    ) -> io::Result<()> {
        let namespace = Namespace::current()?;
        receipt.validate(directory, &namespace)?;
        self.clean_link(receipt)
    }

    // State and policies belong to the still-running instance. The immediate
    // rollback only removes the link, address and routes owned by this writer.
    fn clean_link(&self, receipt: &Receipt) -> io::Result<()> {
        if receipt.creating {
            if let Some(link) = self.owned_link(receipt)? {
                let routes = self.applied_routes(receipt)?;
                let has_address = self.address_present(receipt, &link)?;
                for route in receipt.routes.iter().rev().filter(|r| routes.contains(r)) {
                    self.route_change("del", route, &link.ifname, None)?;
                }
                if has_address {
                    let vip = receipt
                        .vip
                        .ok_or_else(|| invalid("missing virtual address in receipt"))?;
                    self.ip(&[
                        "-4",
                        "addr",
                        "del",
                        &format!("{vip}/32"),
                        "dev",
                        &link.ifname,
                    ])?;
                }
                let current = self
                    .owned_link(receipt)?
                    .ok_or_else(|| invalid("XFRM link disappeared during cleanup"))?;
                if self.address_present(receipt, &current)?
                    || !self.applied_routes(receipt)?.is_empty()
                {
                    return Err(invalid("address or route remains after deletion"));
                }
                self.ip(&["link", "del", "dev", &link.ifname])?;
            }
            if self.link(receipt)?.is_some()
                || self
                    .routes("-4")?
                    .iter()
                    .any(|r| r.dev.as_deref() == Some(&receipt.name()))
                || self
                    .routes("-6")?
                    .iter()
                    .any(|r| r.dev.as_deref() == Some(&receipt.name()))
            {
                return Err(invalid("XFRM interface or route remains after deletion"));
            }
        }
        Ok(())
    }

    pub(super) fn verify_xfrm_clear(&self, receipt: &Receipt) -> io::Result<()> {
        Self::verify_xfrm_ids(receipt, self.xfrm_ids()?)
    }

    fn verify_xfrm_ids(
        receipt: &Receipt,
        (if_ids, reqids): (Vec<u32>, Vec<u32>),
    ) -> io::Result<()> {
        if if_ids.contains(&receipt.if_id) || reqids.contains(&u32::from(receipt.reqid)) {
            return Err(invalid("XFRM state or policy still occupies reserved IDs"));
        }
        Ok(())
    }

    /// The producer's unit has stopped and the writer lock is held.
    pub(super) fn clean_stopped_xfrm(
        &self,
        _guard: &NetworkGuard,
        receipt: &Receipt,
    ) -> io::Result<()> {
        let ids = self.xfrm_ids()?;
        if !ids.0.contains(&receipt.if_id) {
            return Self::verify_xfrm_ids(receipt, ids);
        }
        self.delete_orphaned_esp(receipt)?;
        let bytes = self.ip(&["-s", "xfrm", "policy", "list", "nosock"])?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid XFRM policy dump"))?;
        for key in xfrm_policy_keys(text, receipt)? {
            // The kernel matches if_id under its policy lock, even if the
            // policy disappeared or its index was reused after the dump.
            let index = key.index.to_string();
            let if_id = key.if_id.to_string();
            let mut args = vec![
                "xfrm",
                "policy",
                "delete",
                "index",
                &index,
                "dir",
                key.direction,
                "if_id",
                &if_id,
            ];
            if let Some(policy_type) = key.policy_type {
                args.extend(["ptype", policy_type]);
            }
            if let Err(error) = self.ip(&args)
                && !matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
            {
                return Err(io::Error::new(
                    error.kind(),
                    format!("delete XFRM policy {index} {}: {error}", key.direction),
                ));
            }
        }
        self.verify_xfrm_clear(receipt)
    }

    fn esp_inventory(&self) -> io::Result<Vec<EspState>> {
        let bytes = self.ip(&["xfrm", "state", "list", "nokeys"])?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("invalid XFRM state dump"))?;
        esp_states(text)
    }

    fn delete_orphaned_esp(&self, receipt: &Receipt) -> io::Result<()> {
        let owned = |state: &EspState| {
            state.reqid == u32::from(receipt.reqid)
                && state.if_id == Some(receipt.if_id)
                && state.tunnel
                && state.mark.unwrap_or_default() == (0, 0)
                && matches_transport(receipt, state.src, state.dst)
        };
        for state in self.esp_inventory()?.into_iter().filter(owned) {
            if state.spi == 0 {
                return Err(invalid("ESP state key is not representable by iproute2"));
            }
            let fresh = self.esp_inventory()?;
            if !fresh
                .iter()
                .any(|current| current == &state && owned(current))
            {
                continue;
            }
            if fresh
                .iter()
                .filter(|other| {
                    other.dst == state.dst
                        && other.spi == state.spi
                        && other.mark.unwrap_or_default().0 == 0
                })
                .count()
                > 1
            {
                return Err(invalid("ambiguous ESP state deletion key"));
            }
            // The fresh dump narrows the window. Kernel key replacement and
            // a privileged XFRM_MSG_MIGRATE can still race the deletion.
            let src = state.src.to_string();
            let dst = state.dst.to_string();
            let spi = format!("{:#x}", state.spi);
            let args = [
                "xfrm", "state", "delete", "src", &src, "dst", &dst, "proto", "esp", "spi", &spi,
            ];
            if let Err(error) = self.ip(&args)
                && !matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
            {
                return Err(io::Error::new(
                    error.kind(),
                    format!("delete XFRM ESP state SPI {spi}: {error}"),
                ));
            }
        }
        Ok(())
    }
}

fn drain(pipe: &mut impl Read, captured: &mut Vec<u8>) -> io::Result<()> {
    let mut buffer = [0; 8192];
    // Bound each drain to keep the absolute command deadline effective.
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) if captured.len() + n <= MAX_OUTPUT => captured.extend_from_slice(&buffer[..n]),
            Ok(_) => return Err(invalid("network command output limit")),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub(super) fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(())
}

fn run_command(
    program: &str,
    args: &[&str],
    cancel: Option<&SetupCancellation>,
    deadline: Option<Instant>,
) -> io::Result<Vec<u8>> {
    let ordinary_deadline = Instant::now() + Duration::from_secs(4);
    let deadline = deadline.map_or(ordinary_deadline, |deadline| {
        deadline.min(ordinary_deadline)
    });
    check_deadline(Some(deadline))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cancel {
        Some(cancel) => cancel.start(|| command.spawn()),
        None => command.spawn(),
    }?;
    let result = (|| {
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            // SAFETY: each descriptor is a live, exclusively owned pipe.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            drain(&mut stdout, &mut output)?;
            drain(&mut stderr, &mut diagnostics)?;
            if let Some(status) = child.try_wait()? {
                drain(&mut stdout, &mut output)?;
                drain(&mut stderr, &mut diagnostics)?;
                if !status.success() {
                    if program == "/usr/bin/ip"
                        && matches!(args, ["xfrm", "policy" | "state", "delete", ..])
                        && status.code() == Some(2)
                    {
                        match diagnostics.as_slice() {
                            b"RTNETLINK answers: No such file or directory\n" => {
                                return Err(io::Error::from_raw_os_error(libc::ENOENT));
                            }
                            b"RTNETLINK answers: No such process\n" => {
                                return Err(io::Error::from_raw_os_error(libc::ESRCH));
                            }
                            _ => {}
                        }
                    }
                    return Err(io::Error::other(format!("{program} exited with {status}")));
                }
                // iproute2 can print an interrupted-dump warning with a zero exit.
                if !diagnostics.is_empty() {
                    return Err(invalid("network command reported diagnostics"));
                }
                check_deadline(Some(deadline))?;
                return Ok(output);
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
            );
        }
    })();
    if result.is_err() {
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::sync::{TryLockError, mpsc};

    #[test]
    fn cancel_orders_with_the_start_of_network_effects() {
        let cancel = SetupCancellation::default();
        let (entered, executing) = mpsc::channel();
        let (resume, release) = mpsc::channel();
        let release = Mutex::new(release);
        let network = Network::fake(move |_, args| {
            assert_eq!(args, ["first"]);
            entered.send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Ok(Vec::new())
        });

        thread::scope(|scope| {
            let effect = scope.spawn(|| network.run_ip(&["first"], Some(&cancel)));
            executing.recv_timeout(Duration::from_secs(5)).unwrap();

            // This competing thread probes the gate while the executor is
            // still paused, then attempts to record cancellation.
            let (probe, contended) = mpsc::sync_channel(0);
            let gate = &cancel;
            let cancelling = scope.spawn(move || {
                probe
                    .send(matches!(
                        gate.effects.try_lock(),
                        Err(TryLockError::WouldBlock)
                    ))
                    .unwrap();
                gate.cancel();
            });
            let gate_held_at_start = contended.recv().unwrap();
            resume.send(()).unwrap();
            effect.join().unwrap().unwrap();
            cancelling.join().unwrap();

            assert!(
                gate_held_at_start,
                "effect began outside the cancellation gate"
            );
            assert_eq!(
                network
                    .run_ip(&["second"], Some(&cancel))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::ConnectionAborted
            );
        });
    }
}

#[cfg(test)]
pub(super) mod coexistence_tests {
    use super::*;
    use crate::netlease::NetworkLock;
    use serde_json::{Value, json};

    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);
    const APPROVED: &[Ipv4Addr] = &[REMOTE, Ipv4Addr::new(192, 0, 2, 21)];

    pub(super) fn standard_rules() -> Vec<Value> {
        vec![
            json!({"priority":0,"src":"all","table":"local"}),
            json!({"priority":32766,"src":"all","table":"main"}),
            json!({"priority":32767,"src":"all","table":"default"}),
        ]
    }

    pub(crate) fn tailscale_rules() -> Vec<Value> {
        let mut rules = standard_rules();
        rules.splice(1..1, [
            json!({"priority":5210,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","table":"main"}),
            json!({"priority":5230,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","table":"default"}),
            json!({"priority":5250,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","action":"unreachable"}),
            json!({"priority":5270,"src":"all","table":"52"}),
        ]);
        rules
    }

    pub(crate) fn unsupported_rules() -> Vec<Value> {
        vec![
            json!({"priority":500,"src":"all","table":"52","iif":"eth-other"}),
            json!({"priority":500,"src":"all","table":"52","oif":"eth-other"}),
            json!({"priority":500,"src":"all","table":"52","uid_start":1000,"uid_end":1000}),
            json!({"priority":500,"src":"all","goto":32766}),
            json!({"priority":500,"src":"203.0.113.0/24","table":"main"}),
            json!({"priority":500,"src":"all","dst":"203.0.113.0/24","table":"main"}),
            json!({"priority":500,"src":"all","table":"52","suppress_prefixlen":0}),
            json!({"priority":500,"src":"all","table":"52","protocol":"static"}),
            json!({"priority":500,"src":"all","l3mdev":null}),
            json!({"priority":500,"src":"all","nop":null}),
            json!({"priority":500,"src":"all","table":"main","fwmark":"0x0"}),
            json!({"priority":500,"src":"all","table":"main","fwmark":"0x80000","fwmask":"0x0"}),
            json!({"priority":500,"src":"all","table":"main","fwmark":"0x80000","not":null}),
        ]
    }

    pub(crate) fn defaults(dev: &str) -> Vec<Value> {
        vec![
            json!({"dst":"default","type":"unicast","table":"main","dev":dev,"gateway":"192.0.2.1","metric":100}),
            json!({"dst":"default","type":"unicast","table":"main","dev":"wlan-fixture","gateway":"198.51.100.1","metric":600}),
        ]
    }

    struct Root(std::path::PathBuf);

    impl Root {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "vpnt-xfrm-coexistence-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn guard(&self) -> NetworkGuard {
            NetworkLock::acquire_test(&self.0, Instant::now() + Duration::from_secs(2)).unwrap()
        }
    }

    fn plan(rules: Vec<Value>, extra: Vec<Value>, defaults: Vec<Value>) -> io::Result<Receipt> {
        let root = Root::new();
        let network = Network::fake(move |_, args| {
            let data = match args {
                ["-4", "-j", "route", "get", "192.0.2.20"] => json!([
                    {"dev":"eth-fixture","gateway":"192.0.2.1","prefsrc":"192.0.2.2"}
                ]),
                ["-j", "-d", "link", "show"] => {
                    json!([{"ifname":"eth-fixture","ifindex":2,"flags":["UP"]}])
                }
                ["-4", "-j", "rule", "show"] => json!(rules),
                ["-4", "-j", "route", "show", "table", "52"] => json!(extra),
                ["-4", "-j", "-d", "route", "show", "table", "all"] => {
                    json!(defaults.iter().chain(&extra).collect::<Vec<_>>())
                }
                ["xfrm", "state", "list", "nokeys"] | ["xfrm", "policy", "list"] => {
                    return Ok(vec![]);
                }
                _ => panic!("unexpected command: {args:?}"),
            };
            Ok(serde_json::to_vec(&data).unwrap())
        });
        network.plan(
            &root.guard(),
            GENERATION,
            REMOTE,
            APPROVED,
            vec![parse_cidr("10.20.0.0/16").unwrap()],
        )
    }

    impl Drop for Root {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn tailscale_rules_admit_disjoint_routes_in_table_52() {
        assert!(
            plan(
                tailscale_rules(),
                vec![
                    json!({"dst":"100.64.0.0/10","dev":"tailscale0","table":"52"}),
                    json!({"dst":"100.110.20.1","dev":"tailscale0","table":"52"}),
                ],
                defaults("eth-fixture")[..1].to_vec()
            )
            .is_ok()
        );
    }

    #[test]
    fn extra_policy_tables_refuse_default_and_protected_destinations() {
        for (dst, kind) in [
            ("default", "unicast"),
            ("0.0.0.0/0", "throw"),
            ("192.0.2.1", "unicast"),
            ("192.0.2.20", "unicast"),
            ("192.0.2.21", "unreachable"),
            ("10.20.1.0/24", "throw"),
        ] {
            let error = plan(
                tailscale_rules(),
                vec![json!({"dst":dst,"type":kind,"table":"52"})],
                defaults("eth-fixture")[..1].to_vec(),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("priority 5270 table 52"),
                "{error}"
            );
            if dst != "default" {
                assert!(!error.to_string().contains(dst));
            }
        }
    }

    #[test]
    fn unsupported_policy_rules_identify_priority_without_selector_addresses() {
        for rule in unsupported_rules() {
            let mut rules = standard_rules();
            rules.insert(1, rule);
            let error = plan(rules, vec![], defaults("eth-fixture")).unwrap_err();
            assert!(error.to_string().contains("priority 500 table"), "{error}");
            assert!(!error.to_string().contains("203.0.113.0"));
        }
    }

    #[test]
    fn distinct_defaults_are_admitted_when_the_kernel_egress_matches() {
        plan(standard_rules(), vec![], defaults("eth-fixture")).unwrap();
    }

    fn check_xfrm_confirmation(
        tunnel_device: &str,
        late_destination: Option<&str>,
        expected_error: Option<&str>,
    ) {
        #[derive(Default)]
        struct Kernel {
            alias: Option<String>,
            link: bool,
            address: bool,
            route: bool,
            late_destination: Option<String>,
            ops: Vec<String>,
        }

        let root = Root::new();
        let directory = root.0.join(GENERATION);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let guard = root.guard();
        let kernel = Arc::new(Mutex::new(Kernel::default()));
        let state = kernel.clone();
        let tunnel_device = tunnel_device.to_owned();
        let destination_on_add = late_destination.map(str::to_owned);
        let network = Network::fake(move |_, args| {
            let mut state = state.lock().unwrap();
            state.ops.push(args.join(" "));
            let extra_routes = || {
                [Some("100.64.0.0/10"), state.late_destination.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(|dst| json!({"dst":dst,"table":"52","dev":"tailscale0"}))
                    .collect::<Vec<_>>()
            };
            let data = match args {
                ["-4", "-j", "route", "get", "192.0.2.20"] => json!([
                    {"dev":"eth-fixture","gateway":"192.0.2.1","prefsrc":"192.0.2.2"}
                ]),
                ["-4", "-j", "route", "get", "10.20.0.0"] if state.route => {
                    json!([{"dev":tunnel_device}])
                }
                ["-j", "-d", "link", "show"] => {
                    let mut links =
                        vec![json!({"ifname":"eth-fixture","ifindex":2,"flags":["UP"]})];
                    if state.link {
                        links.push(json!({
                            "ifname":"vpnti1","ifindex":3,"flags":["UP"],"link":"eth-fixture",
                            "ifalias":state.alias,"linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0x1"}}
                        }));
                    }
                    json!(links)
                }
                ["-4", "-j", "rule", "show"] => json!(tailscale_rules()),
                ["-4", "-j", "route", "show", "table", "52"] => json!(extra_routes()),
                ["-4", "-j", "-d", "route", "show", "table", "all"] => {
                    let mut rows = defaults("eth-fixture");
                    rows.truncate(1);
                    rows.extend(extra_routes());
                    if state.route {
                        rows.push(json!({
                            "dst":"10.20.0.0/16","dev":"vpnti1","type":"unicast","table":"main",
                            "scope":"link","protocol":"boot"
                        }));
                    }
                    json!(rows)
                }
                ["-6", "-j", "-d", "route", "show", "table", "all"] => json!([]),
                ["-j", "addr", "show", "dev", "vpnti1"] => {
                    let addresses = if state.address {
                        vec![json!({"family":"inet","local":"10.99.0.2","prefixlen":32})]
                    } else {
                        vec![]
                    };
                    json!([{"ifindex":3,"addr_info":addresses}])
                }
                ["xfrm", "state", "list", "nokeys"] | ["xfrm", "policy", "list"] => {
                    return Ok(vec![]);
                }
                [
                    "link",
                    "add",
                    "name",
                    "vpnti1",
                    "type",
                    "xfrm",
                    "dev",
                    "eth-fixture",
                    "if_id",
                    "1",
                ] => {
                    state.link = true;
                    return Ok(vec![]);
                }
                ["link", "set", "dev", "vpnti1", "alias", alias] => {
                    state.alias = Some((*alias).into());
                    return Ok(vec![]);
                }
                ["link", "set", "dev", "vpnti1", "addrgenmode", "none"]
                | ["link", "set", "dev", "vpnti1", "up"] => return Ok(vec![]),
                [
                    "-4",
                    "addr",
                    "add",
                    "10.99.0.2/32",
                    "dev",
                    "vpnti1",
                    "noprefixroute",
                ] => {
                    state.address = true;
                    return Ok(vec![]);
                }
                ["-4", "addr", "del", "10.99.0.2/32", "dev", "vpnti1"] => {
                    state.address = false;
                    return Ok(vec![]);
                }
                [
                    "-4",
                    "route",
                    "add",
                    "10.20.0.0/16",
                    "dev",
                    "vpnti1",
                    "table",
                    "main",
                    "proto",
                    "boot",
                    "scope",
                    "link",
                ] => {
                    state.route = true;
                    state.late_destination.clone_from(&destination_on_add);
                    return Ok(vec![]);
                }
                [
                    "-4",
                    "route",
                    "del",
                    "10.20.0.0/16",
                    "dev",
                    "vpnti1",
                    "table",
                    "main",
                    "proto",
                    "boot",
                    "scope",
                    "link",
                ] => {
                    state.route = false;
                    return Ok(vec![]);
                }
                ["link", "del", "dev", "vpnti1"] if !state.route && !state.address => {
                    state.link = false;
                    return Ok(vec![]);
                }
                _ => panic!("unexpected command: {args:?}"),
            };
            Ok(serde_json::to_vec(&data).unwrap())
        });
        let mut receipt = network
            .plan(
                &guard,
                GENERATION,
                REMOTE,
                APPROVED,
                vec![parse_cidr("10.20.0.0/16").unwrap()],
            )
            .unwrap();
        let result = network.install(
            &guard,
            &directory,
            &mut receipt,
            "10.99.0.2".parse().unwrap(),
            APPROVED,
        );
        if let Some(message) = expected_error {
            assert_eq!(result.unwrap_err().to_string(), message);
        } else {
            result.unwrap();
        }
        let confirmed = expected_error.is_none();
        assert_eq!(receipt.confirmed, confirmed);
        let persisted = Receipt::load(&directory, &guard).unwrap();
        assert_eq!(persisted.confirmed, confirmed);
        let state = kernel.lock().unwrap();
        assert_eq!(state.late_destination.as_deref(), late_destination);
        assert_eq!(
            (state.link, state.route, state.address),
            (confirmed, confirmed, confirmed)
        );
        assert!(state.ops.iter().any(|op| op.starts_with("-4 route add ")));
        assert_eq!(
            state.ops.iter().any(|op| op.starts_with("-4 route del ")),
            !confirmed
        );
    }

    #[test]
    fn a_policy_lookup_outside_xfrm_after_installation_rolls_back() {
        check_xfrm_confirmation(
            "eth-other",
            None,
            Some("tunnel route lookup selected a different interface"),
        );
    }

    #[test]
    fn xfrm_rechecks_additional_tables_before_confirmation() {
        for (destination, error) in [
            (None, None),
            (
                Some("10.20.1.0/24"),
                Some(
                    "IPv4 policy rule priority 5270 table 52: route overlaps protected destinations",
                ),
            ),
            (
                Some("203.0.113.0/24"),
                Some("IPv4 policy routing inventory changed during configuration"),
            ),
        ] {
            check_xfrm_confirmation("vpnti1", destination, error);
        }
    }

    #[test]
    fn every_default_must_be_simple_and_its_addresses_clear_of_the_tunnel_scope() {
        for (field, value) in [
            ("nhid", json!(8)),
            ("nexthops", json!([{"dev":"wlan-fixture"}])),
            ("encap", json!({"type":"mpls"})),
            ("table", json!("52")),
            ("gateway", json!("10.20.1.1")),
            ("prefsrc", json!("10.20.1.2")),
        ] {
            let mut rows = defaults("eth-fixture");
            rows[1][field] = value;
            assert!(plan(standard_rules(), vec![], rows).is_err(), "{field}");
        }
        assert!(plan(standard_rules(), vec![], defaults("other-device")).is_err());
    }
}
