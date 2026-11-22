//! Journaled Linux XFRM effects serialized by the shared network writer lock.
use super::protocol::{CidrV4, Generation, ProbeBinding};
use crate::netlease::NetworkGuard;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::Ipv4Addr,
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

type Run = dyn Fn(&str, &[&str], Option<&SetupCancellation>) -> io::Result<Vec<u8>> + Send + Sync;

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

pub(super) fn check_standard_ipv4_rules(rules: &[serde_json::Value]) -> io::Result<()> {
    let standard = serde_json::json!([
        {"priority":0,"src":"all","table":"local"},
        {"priority":32766,"src":"all","table":"main"},
        {"priority":32767,"src":"all","table":"default"}
    ]);
    if rules != standard.as_array().expect("rules array").as_slice() {
        return Err(invalid("nonstandard IPv4 policy rules"));
    }
    Ok(())
}

impl Network {
    #[cfg(test)]
    pub(super) fn fake(
        run: impl Fn(&str, &[&str]) -> io::Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self(Box::new(move |program, args, cancel| match cancel {
            Some(cancel) => cancel.start(|| run(program, args)),
            None => run(program, args),
        }))
    }

    fn ip(&self, args: &[&str]) -> io::Result<Vec<u8>> {
        self.run_ip(args, None)
    }

    fn run_ip(&self, args: &[&str], cancel: Option<&SetupCancellation>) -> io::Result<Vec<u8>> {
        (self.0)("/usr/bin/ip", args, cancel)
    }

    fn json<T: DeserializeOwned>(&self, args: &[&str]) -> io::Result<T> {
        decode(&self.ip(args)?)
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

    fn links(&self) -> io::Result<Vec<Link>> {
        self.json(&["-j", "-d", "link", "show"])
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
        let links = self.links()?;
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

    fn fib_clear(
        &self,
        routes: &[CidrV4],
        vip: Option<Ipv4Addr>,
        approved: &[Ipv4Addr],
        egress: &Egress,
    ) -> io::Result<()> {
        let rules: Vec<serde_json::Value> = self.json(&["-4", "-j", "rule", "show"])?;
        check_standard_ipv4_rules(&rules)?;
        let protected = approved
            .iter()
            .copied()
            .chain([egress.prefsrc])
            .chain(egress.gateway);
        let requested: Vec<_> = routes.iter().map(route_key).collect();
        if protected
            .into_iter()
            .any(|ip| requested.iter().any(|r| overlaps(*r, (ip.into(), 32))) || vip == Some(ip))
        {
            return Err(invalid("VPN scope conflicts with protected transport"));
        }
        let mut has_default = false;
        for existing in self.routes("-4")? {
            if existing.dst == "default" {
                if has_default
                    || existing.kind.as_deref() != Some("unicast")
                    || existing.nexthops.is_some()
                    || existing.nhid.is_some()
                    || existing.dev.as_deref() != Some(&egress.dev)
                    || existing
                        .table
                        .as_deref()
                        .is_some_and(|table| table != "main")
                {
                    return Err(invalid("nonstandard default route"));
                }
                has_default = true;
                continue;
            }
            let existing = prefix(&existing.dst)?;
            if requested.iter().any(|route| overlaps(*route, existing))
                || vip.is_some_and(|ip| overlaps((ip.into(), 32), existing))
            {
                return Err(invalid("VPN scope conflicts with an existing route"));
            }
        }
        Ok(())
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
        self.fib_clear(&routes, None, approved, &egress)?;
        let links = self.links()?;
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
        self.fib_clear(&receipt.routes, Some(vip), approved, &receipt.egress)?;
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
            || self.egress(receipt.remote)? != receipt.egress
        {
            return Err(invalid("network configuration confirmation failed"));
        }
        cancel.check()?;
        receipt.confirmed = true;
        receipt.save(directory, guard)
    }

    fn link(&self, receipt: &Receipt) -> io::Result<Option<Link>> {
        let name = receipt.name();
        let mut owned = None;
        for link in self.links()? {
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
        let link = self.link(receipt)?;
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
    ) -> io::Result<ProbeBinding> {
        if !receipt.confirmed || receipt.complete || receipt.routes_intended != receipt.routes.len()
        {
            return Err(invalid("XFRM probe scope is unconfirmed"));
        }
        let link = self
            .owned_link(receipt)?
            .filter(|link| {
                receipt.ifindex == Some(link.ifindex) && link.flags.iter().any(|flag| flag == "UP")
            })
            .ok_or_else(|| invalid("XFRM probe link is unproven"))?;
        if !self.address_present(receipt, &link)? {
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
        let result: Vec<AddressList> = self.json(&["-j", "addr", "show", "dev", &link.ifname])?;
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
        _guard: &NetworkGuard,
        directory: &Path,
        receipt: &Receipt,
    ) -> io::Result<()> {
        let namespace = Namespace::current()?;
        receipt.validate(directory, &namespace)?;
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
        self.verify_xfrm_clear(receipt)
    }

    pub(super) fn verify_xfrm_clear(&self, receipt: &Receipt) -> io::Result<()> {
        let ids = self.xfrm_ids()?;
        if ids.0.contains(&receipt.if_id) || ids.1.contains(&u32::from(receipt.reqid)) {
            return Err(invalid("XFRM state or policy still occupies reserved IDs"));
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

fn run_command(
    program: &str,
    args: &[&str],
    cancel: Option<&SetupCancellation>,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(4);
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
                    return Err(io::Error::other(format!("{program} exited with {status}")));
                }
                // iproute2 can print an interrupted-dump warning with a zero exit.
                if !diagnostics.is_empty() {
                    return Err(invalid("network command reported diagnostics"));
                }
                return Ok(output);
            }
            thread::sleep(Duration::from_millis(5));
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
