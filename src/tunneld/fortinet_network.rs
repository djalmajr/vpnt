//! Network effects of the Fortinet PPP link: the routes and DNS of the gateway
//! that policy accepts, journaled by a receipt and serialized by the shared
//! network writer lock (the caller holds the `NetworkGuard`).
//!
//! The PPP link itself belongs to the instance (the client starts `pppd`, which
//! creates and removes it). The writer never creates or deletes it: it plans
//! the interface name and the egress, waits for the instance to observe the
//! link, then adds only the accepted routes and the per-link DNS, and removes
//! them by the receipt. DNS uses the same `resolvectl` per-link commands as the
//! netd backend (`netd::iproute`); that backend is bound to `TunName` links and
//! flushes addresses, so it cannot configure a PPP link and is not reused as is.
use super::{
    fortinet_instance::{Event, Failure},
    network::{
        PolicyInventory, SetupCancellation, check_deadline, check_ipv4_rules, cidr_text, overlaps,
        prefix, rollback_error, route_key, valid_generation, verify_tunnel_routes,
    },
    policy::Entry,
    protocol::{CidrV4, Generation, ProbeBinding},
};
use crate::netlease::NetworkGuard;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) const RECEIPT: &str = "fortinet.json";
const IP: &str = "/usr/bin/ip";
const RESOLVECTL: &str = "/usr/bin/resolvectl";
const MAX_ORDINAL: u32 = 99;
const MAX_OUTPUT: usize = 1024 * 1024;
// Fixed by the packaged openfortivpn argv to pppd, without ipcp-accept-remote.
const PPP_PEER: Ipv4Addr = Ipv4Addr::new(169, 254, 2, 1);
const PPP_PEER_PREFIX: (u32, u8) = (PPP_PEER.to_bits(), 32);
// Same protocol and scope as the routes netd adds.
const PROTOCOL: &str = "boot";
const COMMAND_DEADLINE: Duration = Duration::from_secs(4);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Egress {
    dev: String,
    prefsrc: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    ifindex: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dns {
    servers: Vec<Ipv4Addr>,
    domains: Vec<String>,
}

/// What the writer did and may have to undo, saved before each step.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    generation: String,
    boot: String,
    netns: (u64, u64),
    /// The PPP interface name the instance is told to configure.
    pub(super) ifname: String,
    remote: Ipv4Addr,
    egress: Egress,
    /// The policy's transport addresses: no accepted route may cover them.
    approved: Vec<Ipv4Addr>,
    /// Identity of the link once the writer saw it; cleanup touches only it.
    ifindex: Option<u32>,
    local: Option<Ipv4Addr>,
    peer: Option<Ipv4Addr>,
    routes: Vec<CidrV4>,
    routes_intended: usize,
    dns: Option<Dns>,
    dns_intended: bool,
    refused_routes: usize,
    refused_dns: usize,
    confirmed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    probe_marked: bool,
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

impl Receipt {
    fn validate(&self, directory: &Path, namespace: &Namespace) -> io::Result<()> {
        if !valid_generation(&self.generation)
            || directory.file_name().and_then(|n| n.to_str()) != Some(&self.generation)
            || !valid_ifname(&self.ifname)
            || self.routes_intended > self.routes.len()
            || (self.routes_intended > 0 || self.dns_intended) && self.ifindex.is_none()
            || self.probe_marked && (!self.confirmed || self.ifindex.is_none())
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
        let temp = directory.join("fortinet.tmp");
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

    /// The egress the client must bind to: policy-resolved gateway, planned link.
    pub(super) fn binding(&self) -> (&str, u32, Ipv4Addr) {
        (&self.egress.dev, self.egress.ifindex, self.remote)
    }

    fn marker(&self) -> String {
        format!("vpnt:{}", self.generation)
    }

    fn protected_transport(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.approved
            .iter()
            .copied()
            .chain([self.egress.prefsrc, self.remote])
            .chain(self.egress.gateway)
    }

    pub(super) fn report(&self) -> Report {
        Report {
            accepted_routes: self.routes.len(),
            refused_routes: self.refused_routes,
            dns_servers: self.dns.as_ref().map_or(0, |dns| dns.servers.len()),
            refused_dns: self.refused_dns,
        }
    }
}

/// Counts only: nothing the gateway printed reaches it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Report {
    pub accepted_routes: usize,
    pub refused_routes: usize,
    pub dns_servers: usize,
    pub refused_dns: usize,
}

fn valid_ifname(name: &str) -> bool {
    name.strip_prefix("vpntp").is_some_and(|ordinal| {
        ordinal
            .parse::<u32>()
            .is_ok_and(|n| (1..=MAX_ORDINAL).contains(&n) && n.to_string() == ordinal)
    })
}

/// Projection of the canonical policy entry (the entry's own fields are private).
#[derive(Debug, Deserialize)]
pub(super) struct Grant {
    pub hostname: String,
    pub transport_ipv4: Vec<Ipv4Addr>,
    pub port: u16,
    pub certificate_sha256: String,
    #[serde(deserialize_with = "deserialize_local_scope")]
    pub fortinet_local_cidr: CidrV4,
    route_cidrs: Vec<String>,
    pub dns_domains: Vec<String>,
    pub dns_servers: Vec<Ipv4Addr>,
}

impl Grant {
    pub(super) fn from_entry(entry: &Entry) -> io::Result<Self> {
        serde_json::to_value(entry)
            .and_then(serde_json::from_value)
            .map_err(|_| invalid("unreadable policy entry"))
    }
}

fn deserialize_local_scope<'de, D: serde::Deserializer<'de>>(input: D) -> Result<CidrV4, D::Error> {
    String::deserialize(input)?
        .parse()
        .map_err(|_| serde::de::Error::custom("invalid Fortinet local IPv4 scope"))
}

/// What the instance reported for this attempt, from its typed events.
#[derive(Debug, Default)]
pub(super) struct Delivered {
    interface: Option<String>,
    routes: Vec<(Ipv4Addr, u8)>,
    route_count: Option<usize>,
    split_invalid: bool,
    dns_servers: Vec<Ipv4Addr>,
    dns_domains: Vec<String>,
    dns_count: Option<(usize, usize)>,
    dns_invalid: bool,
    mismatch: bool,
    failure: Option<Failure>,
    exited: bool,
}

/// Why an attempt cannot go on, from what the instance reported.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Fatal {
    /// The client announced another interface than the planned one.
    InterfaceMismatch,
    Failure(Failure),
    /// The client ended before the network was ready.
    Exited,
    /// Contradictory or invalid data from the gateway.
    Invalid,
}

impl Delivered {
    pub(super) fn absorb(&mut self, event: Event) {
        match event {
            Event::Started => {}
            Event::Interface { name } => self.interface = Some(name),
            Event::Failure { kind } => self.failure = Some(kind),
            Event::SplitRoute { network, prefix } => self.routes.push((network, prefix)),
            Event::SplitRoutes { count } => {
                // The count line is sent once; a second one is a contradiction.
                self.split_invalid |= self.route_count.replace(count).is_some();
            }
            Event::SplitInvalid => self.split_invalid = true,
            Event::InterfaceMismatch => self.mismatch = true,
            Event::DnsServer { address } => self.dns_servers.push(address),
            Event::DnsDomain { name } => self.dns_domains.push(name),
            Event::DnsCount { servers, domains } => {
                self.dns_invalid |= self.dns_count.replace((servers, domains)).is_some();
            }
            Event::DnsInvalid => self.dns_invalid = true,
            Event::Exited { .. } => self.exited = true,
        }
    }

    /// Anything that ends the attempt, whatever else was delivered.
    pub(super) fn fatal(&self) -> Option<Fatal> {
        if self.mismatch {
            Some(Fatal::InterfaceMismatch)
        } else if let Some(kind) = self.failure {
            Some(Fatal::Failure(kind))
        } else if self.exited {
            Some(Fatal::Exited)
        } else if self.split_invalid
            || self
                .route_count
                .is_some_and(|count| count != self.routes.len())
            || self
                .dns_count
                .is_some_and(|count| count != (self.dns_servers.len(), self.dns_domains.len()))
        {
            Some(Fatal::Invalid)
        } else {
            None
        }
    }

    /// The interface is up and both lists are complete (their count lines seen).
    pub(super) fn ready(&self) -> bool {
        self.interface.is_some()
            && self.route_count.is_some()
            && (self.dns_count.is_some() || self.dns_invalid)
    }
}

/// The policy as the writer enforces it: the entry's own decisions plus the
/// projection that carries its DNS fields.
pub(super) struct Scope<'a> {
    pub entry: &'a Entry,
    pub grant: &'a Grant,
}

/// Every privileged effect carries the setup's cancellation, so that it
/// begins under the same lock as the cancellation mark.
type Run = dyn Fn(&str, &[&str], Option<&SetupCancellation>, Option<Instant>) -> io::Result<Vec<u8>>
    + Send
    + Sync;

pub(super) struct FortinetNetwork(Box<Run>);

impl Default for FortinetNetwork {
    fn default() -> Self {
        Self(Box::new(run_command))
    }
}

#[derive(Deserialize)]
struct Link {
    ifname: String,
    ifindex: u32,
    #[serde(default)]
    link_type: Option<String>,
    ifalias: Option<String>,
    flags: Vec<String>,
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
    gateway: Option<Ipv4Addr>,
    nhid: Option<u32>,
    metric: Option<u32>,
    prefsrc: Option<Ipv4Addr>,
    encap: Option<serde_json::Value>,
    via: Option<serde_json::Value>,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

impl Route {
    fn main_table(&self) -> bool {
        self.table.as_deref().is_none_or(|table| table == "main")
    }

    /// Every host address the route names: next hop, source and the next hops
    /// of a multipath route. A hop that is not an IPv4 address is refused.
    fn named_addresses(&self) -> io::Result<Vec<Ipv4Addr>> {
        let mut named: Vec<Ipv4Addr> = self.gateway.into_iter().chain(self.prefsrc).collect();
        if let Some(hops) = &self.nexthops {
            let hops = hops
                .as_array()
                .ok_or_else(|| invalid("unreadable multipath route"))?;
            for hop in hops {
                if let Some(gateway) = hop.get("gateway") {
                    named.push(
                        gateway
                            .as_str()
                            .and_then(|text| text.parse().ok())
                            .ok_or_else(|| invalid("unreadable multipath next hop"))?,
                    );
                }
            }
        }
        Ok(named)
    }

    fn direct(&self) -> bool {
        self.gateway.is_none()
            && self.metric.is_none()
            && self.nhid.is_none()
            && self.nexthops.is_none()
            && self.encap.is_none()
            && self.via.is_none()
            && self.flags.is_empty()
            && self.extra.is_empty()
    }

    fn is_simple_default(&self) -> bool {
        self.main_table()
            && self.kind.as_deref() == Some("unicast")
            && self.dev.as_deref().is_some_and(|dev| !dev.is_empty())
            && self
                .scope
                .as_deref()
                .is_none_or(|scope| scope == "global" || scope == "link" && self.gateway.is_none())
            && self.nhid.is_none()
            && self.nexthops.is_none()
            && self.encap.is_none()
            && self.via.is_none()
            && self.flags.iter().all(|flag| flag == "onlink")
            && self.extra.keys().all(|field| field == "metrics")
    }

    fn is_ppp_kernel_route(&self, receipt: &Receipt, dst: (u32, u8)) -> bool {
        if self.protocol.as_deref() != Some("kernel")
            || dst.1 != 32
            || !self.direct()
            || self.prefsrc.is_some_and(|src| Some(src) != receipt.local)
        {
            return false;
        }
        if dst == PPP_PEER_PREFIX {
            return receipt.peer == Some(PPP_PEER)
                && self.table.as_deref() == Some("main")
                && self.kind.as_deref() == Some("unicast")
                && self.scope.as_deref() == Some("link");
        }
        Some(Ipv4Addr::from(dst.0)) == receipt.local
            && self.table.as_deref() == Some("local")
            && self.kind.as_deref() == Some("local")
            && self.scope.as_deref() == Some("host")
    }
}

#[derive(Default)]
struct Applied {
    routes: Vec<CidrV4>,
    technical_peer: bool,
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
    /// The peer of a point-to-point link.
    address: Option<Ipv4Addr>,
    prefixlen: u8,
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    if bytes.len() > MAX_OUTPUT {
        return Err(invalid("network response exceeds limit"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid("invalid network JSON response"))
}

fn contains(route: &CidrV4, ip: Ipv4Addr) -> bool {
    overlaps(route_key(route), (ip.into(), 32))
}

impl FortinetNetwork {
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
        (self.0)(IP, args, None, None)
    }

    fn json<T: DeserializeOwned>(&self, args: &[&str]) -> io::Result<T> {
        decode(&self.ip(args)?)
    }

    fn json_until<T: DeserializeOwned>(
        &self,
        args: &[&str],
        deadline: Option<Instant>,
    ) -> io::Result<T> {
        decode(&(self.0)(IP, args, None, deadline)?)
    }

    fn resolvectl(&self, args: &[&str], cancel: Option<&SetupCancellation>) -> io::Result<Vec<u8>> {
        (self.0)(RESOLVECTL, args, cancel, None)
    }

    fn links(&self, deadline: Option<Instant>) -> io::Result<Vec<Link>> {
        self.json_until(&["-j", "-d", "link", "show"], deadline)
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
        if link.ifindex == 0
            || link.ifname.starts_with("vpnt")
            || link.link_type.as_deref() == Some("ppp")
        {
            return Err(invalid("egress is a VPN link"));
        }
        Ok(Egress {
            dev: route.dev.clone(),
            prefsrc: route.prefsrc,
            gateway: route.gateway,
            ifindex: link.ifindex,
        })
    }

    /// Choose the egress and the PPP name for one attempt. Call under the lock,
    /// before the lease is registered; save the receipt right after.
    pub(super) fn plan(
        &self,
        _guard: &NetworkGuard,
        generation: &str,
        remote: Ipv4Addr,
        grant: &Grant,
    ) -> io::Result<Receipt> {
        let namespace = Namespace::current()?;
        let egress = self.egress(remote)?;
        let links = self.links(None)?;
        let ordinal = (1..=MAX_ORDINAL)
            .find(|n| !links.iter().any(|link| link.ifname == format!("vpntp{n}")))
            .ok_or_else(|| invalid("no PPP interface name is available"))?;
        let receipt = Receipt {
            generation: generation.into(),
            boot: namespace.boot,
            netns: namespace.id,
            ifname: format!("vpntp{ordinal}"),
            remote,
            egress,
            approved: grant.transport_ipv4.clone(),
            ifindex: None,
            local: None,
            peer: None,
            routes: Vec::new(),
            routes_intended: 0,
            dns: None,
            dns_intended: false,
            refused_routes: 0,
            refused_dns: 0,
            confirmed: false,
            probe_marked: false,
            complete: false,
        };
        // Prove the technical peer is clear before pppd can assign it.
        if receipt.protected_transport().any(|ip| ip == PPP_PEER) {
            return Err(invalid("PPP peer conflicts with protected transport"));
        }
        let scope = grant.fortinet_local_cidr;
        if receipt
            .protected_transport()
            .chain(grant.dns_servers.iter().copied())
            .chain([PPP_PEER])
            .any(|ip| contains(&scope, ip))
        {
            return Err(invalid("Fortinet local scope overlaps protected addresses"));
        }
        let addresses: Vec<AddressList> = self.json(&["-j", "-4", "addr", "show"])?;
        for address in addresses.into_iter().flat_map(|link| link.addr_info) {
            if address.family != "inet" || address.prefixlen > 32 {
                return Err(invalid("invalid host address inventory"));
            }
            if contains(&scope, address.local)
                || address.address.is_some_and(|ip| contains(&scope, ip))
            {
                return Err(invalid("Fortinet local scope overlaps a host address"));
            }
        }
        self.fib_clear(&receipt, grant)?;
        Ok(receipt)
    }

    /// The link of this attempt as it stands now. A link that answers to the
    /// name under another identity than the recorded one is not ours.
    fn link(&self, receipt: &Receipt) -> io::Result<Option<Link>> {
        self.link_until(receipt, None)
    }

    fn link_until(&self, receipt: &Receipt, deadline: Option<Instant>) -> io::Result<Option<Link>> {
        let mut found = None;
        for link in self.links(deadline)? {
            if link.ifname == receipt.ifname {
                if found.is_some() || link.ifindex == 0 {
                    return Err(invalid("PPP link identity is ambiguous"));
                }
                found = Some(link);
            }
        }
        Ok(found)
    }

    fn address(&self, link: &Link) -> io::Result<Ipv4Addr> {
        self.address_until(link, None)
    }

    fn address_until(&self, link: &Link, deadline: Option<Instant>) -> io::Result<Ipv4Addr> {
        let result: Vec<AddressList> =
            self.json_until(&["-j", "-4", "addr", "show", "dev", &link.ifname], deadline)?;
        let [row] = result.as_slice() else {
            return Err(invalid("ambiguous address inventory"));
        };
        if row.ifindex != link.ifindex {
            return Err(invalid("address inventory link changed"));
        }
        match row.addr_info.as_slice() {
            [addr]
                if addr.family == "inet"
                    && addr.prefixlen == 32
                    && addr.address == Some(PPP_PEER)
                    && addr.local != PPP_PEER
                    && !addr.local.is_unspecified()
                    && !addr.local.is_loopback()
                    && !addr.local.is_multicast() =>
            {
                Ok(addr.local)
            }
            _ => Err(invalid("unexpected addresses on the PPP link")),
        }
    }

    fn route_change(
        &self,
        op: &str,
        route: &CidrV4,
        name: &str,
        cancel: Option<&SetupCancellation>,
    ) -> io::Result<()> {
        (self.0)(
            IP,
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
            None,
        )?;
        Ok(())
    }

    fn routes(&self) -> io::Result<Vec<Route>> {
        self.json(&["-4", "-j", "-d", "route", "show", "table", "all"])
    }

    /// Prove each route on the identified PPP link against the saved intent.
    /// Kernel address entries are identified independently of the policy CIDRs.
    fn applied(receipt: &Receipt, routes: &[Route]) -> io::Result<Applied> {
        let mut applied = Applied::default();
        for existing in routes
            .iter()
            .filter(|r| r.dev.as_deref() == Some(&receipt.ifname))
        {
            let dst = prefix(&existing.dst)?;
            if existing.is_ppp_kernel_route(receipt, dst) {
                if dst == PPP_PEER_PREFIX && std::mem::replace(&mut applied.technical_peer, true) {
                    return Err(invalid("ambiguous PPP peer route"));
                }
                continue;
            }
            let route = receipt.routes[..receipt.routes_intended]
                .iter()
                .find(|r| route_key(r) == dst)
                .filter(|r| !applied.routes.contains(*r))
                .filter(|_| {
                    existing.main_table()
                        && existing.kind.as_deref() == Some("unicast")
                        && existing.protocol.as_deref() == Some(PROTOCOL)
                        && existing.scope.as_deref() == Some("link")
                        && existing.direct()
                        && existing.prefsrc.is_none()
                })
                .ok_or_else(|| invalid("unexpected IPv4 route on the PPP link"))?;
            applied.routes.push(*route);
        }
        Ok(applied)
    }

    fn fib_clear(&self, receipt: &Receipt, grant: &Grant) -> io::Result<PolicyInventory> {
        let local_scope = grant.fortinet_local_cidr;
        let mut policy_scope = grant
            .route_cidrs
            .iter()
            .map(|route| prefix(route))
            .collect::<io::Result<Vec<_>>>()?;
        policy_scope.extend(
            receipt
                .protected_transport()
                .map(|ip| (ip.into(), 32))
                .chain([PPP_PEER_PREFIX, route_key(&local_scope)]),
        );
        let inventory = check_ipv4_rules(|args| self.ip(args), &policy_scope)?;
        let routes = self.routes()?;
        // Planning has no PPP link. Once identified, the technical peer
        // and all intended routes must be present in this same snapshot.
        let applied = Self::applied(receipt, &routes)?;
        if receipt.ifindex.is_some() && !applied.technical_peer {
            return Err(invalid("missing PPP peer route"));
        }
        if applied.routes.len() != receipt.routes_intended {
            return Err(invalid("network configuration confirmation failed"));
        }
        let mut default_count = 0;
        let mut has_egress_device = false;
        let mut has_egress_default = false;
        for existing in routes
            .iter()
            .filter(|r| r.dev.as_deref() != Some(&receipt.ifname))
        {
            if matches!(existing.dst.as_str(), "default" | "0.0.0.0/0") {
                if !existing.is_simple_default() {
                    return Err(invalid("nonstandard default route"));
                }
                if existing
                    .gateway
                    .into_iter()
                    .chain(existing.prefsrc)
                    .any(|ip| {
                        ip == PPP_PEER || receipt.routes.iter().any(|route| contains(route, ip))
                    })
                {
                    return Err(invalid("VPN scope conflicts with protected transport"));
                }
                // The default route's next hop and source are host addresses
                // too: the approved range must not hand one to the PPP peer.
                if existing
                    .named_addresses()?
                    .into_iter()
                    .any(|ip| contains(&local_scope, ip))
                {
                    return Err(invalid("Fortinet local scope overlaps the default route"));
                }
                default_count += 1;
                let same_device = existing.dev.as_deref() == Some(&receipt.egress.dev);
                has_egress_device |= same_device;
                has_egress_default |= same_device
                    && existing.gateway == receipt.egress.gateway
                    && existing
                        .prefsrc
                        .is_none_or(|src| src == receipt.egress.prefsrc);
                continue;
            }
            // So are the next hops and sources of every other route.
            if existing
                .named_addresses()?
                .into_iter()
                .any(|ip| contains(&local_scope, ip))
            {
                return Err(invalid("Fortinet local scope overlaps a host route"));
            }
            let dst = prefix(&existing.dst)?;
            if dst.1 == 0 || dst.0.trailing_zeros() < u32::from(32 - dst.1) {
                return Err(invalid("invalid FIB destination"));
            }
            if overlaps(PPP_PEER_PREFIX, dst) {
                return Err(invalid("PPP peer conflicts with an existing route"));
            }
            if overlaps(route_key(&local_scope), dst) {
                return Err(invalid("Fortinet local scope overlaps a host route"));
            }
            if receipt
                .routes
                .iter()
                .any(|route| overlaps(route_key(route), dst))
            {
                return Err(invalid("VPN scope conflicts with an existing route"));
            }
        }
        if default_count == 0 {
            return Err(invalid("missing default route"));
        }
        if !has_egress_device || default_count > 1 && !has_egress_default {
            return Err(invalid("default routes do not match the proved egress"));
        }
        Ok(inventory)
    }

    fn dns_state(&self, name: &str) -> io::Result<Dns> {
        fn words(output: &[u8]) -> io::Result<Vec<String>> {
            let text =
                std::str::from_utf8(output).map_err(|_| invalid("invalid resolver output"))?;
            // `Link 7 (name): value value`
            Ok(text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .flat_map(|(_, rest)| rest.split_ascii_whitespace().map(str::to_owned))
                .collect())
        }
        let servers = words(&self.resolvectl(&["dns", name], None)?)?
            .iter()
            .map(|word| word.parse().map_err(|_| invalid("unreadable DNS server")))
            .collect::<io::Result<Vec<Ipv4Addr>>>()?;
        let domains = words(&self.resolvectl(&["domain", name], None)?)?
            .into_iter()
            .map(|word| word.strip_prefix('~').map_or(word.clone(), str::to_owned))
            .collect();
        Ok(Dns { servers, domains })
    }

    fn dns_default_route_disabled(&self, name: &str) -> io::Result<bool> {
        let output = self.resolvectl(&["default-route", name], None)?;
        let text = std::str::from_utf8(&output).map_err(|_| invalid("invalid resolver output"))?;
        Ok(text
            .split_once(':')
            .is_some_and(|(_, value)| value.trim() == "no"))
    }

    /// Apply what policy accepts of what the instance delivered. The receipt is
    /// saved before every write, so cleanup undoes at most what was attempted.
    pub(super) fn apply(
        &self,
        guard: &NetworkGuard,
        directory: &Path,
        receipt: &mut Receipt,
        delivered: &Delivered,
        scope: &Scope<'_>,
        cancel: &SetupCancellation,
    ) -> io::Result<()> {
        cancel.check()?;
        let namespace = Namespace::current()?;
        receipt.validate(directory, &namespace)?;
        if delivered.fatal().is_some() || !delivered.ready() {
            return Err(invalid("the instance did not deliver a complete network"));
        }
        if delivered.interface.as_deref() != Some(receipt.ifname.as_str()) {
            return Err(invalid("the instance announced another interface"));
        }
        if self.egress(receipt.remote)? != receipt.egress {
            return Err(invalid("egress changed between start and establishment"));
        }
        let link = self
            .link(receipt)?
            .filter(|link| {
                link.link_type.as_deref() == Some("ppp")
                    && link.ifindex != receipt.egress.ifindex
                    && link.flags.iter().any(|flag| flag == "UP")
            })
            .ok_or_else(|| invalid("PPP link is not up or is not a PPP link"))?;
        let local = self.address(&link)?;
        let local_scope = scope.grant.fortinet_local_cidr;
        if !contains(&local_scope, local) {
            return Err(invalid(
                "PPP local address is outside the approved Fortinet scope",
            ));
        }
        receipt.ifindex = Some(link.ifindex);
        receipt.local = Some(local);
        receipt.peer = Some(PPP_PEER);

        // Routes: only what policy accepts; the rest is refused and counted.
        let mut accepted: Vec<CidrV4> = Vec::new();
        let mut refused = 0;
        for &(network, prefix) in &delivered.routes {
            match CidrV4::new(network, prefix) {
                Ok(route) if scope.entry.route_allowed(route) => {
                    if !accepted.contains(&route) {
                        accepted.push(route);
                    }
                }
                _ => refused += 1,
            }
        }
        if receipt
            .protected_transport()
            .any(|ip| accepted.iter().any(|route| contains(route, ip)))
        {
            return Err(invalid("VPN scope conflicts with protected transport"));
        }
        receipt.routes = accepted.clone();
        receipt.refused_routes = refused;
        let inventory = self.fib_clear(receipt, scope.grant)?;

        // Fixed servers take precedence. Either source must be reachable via
        // an accepted route. Domains always come from policy.
        let domains = scope.grant.dns_domains.clone();
        let servers: Vec<Ipv4Addr> = if !scope.grant.dns_servers.is_empty() {
            let servers: Vec<_> = scope
                .grant
                .dns_servers
                .iter()
                .copied()
                .filter(|&server| {
                    server != local && accepted.iter().any(|route| contains(route, server))
                })
                .collect();
            receipt.refused_dns = scope.grant.dns_servers.len() - servers.len();
            servers
        } else if delivered.dns_invalid {
            receipt.refused_dns = delivered.dns_servers.len().max(1);
            Vec::new()
        } else {
            let (allowed, denied): (Vec<_>, Vec<_>) =
                delivered.dns_servers.iter().partition(|&&server| {
                    server != local && scope.entry.gateway_dns_allowed(server, &accepted)
                });
            receipt.refused_dns = denied.len();
            allowed.into_iter().copied().collect()
        };
        if !domains.is_empty() && servers.is_empty() {
            return Err(invalid("no reachable DNS server for policy domains"));
        }
        let dns = (!domains.is_empty()).then_some(Dns { servers, domains });
        receipt.dns = dns.clone();
        receipt.save(directory, guard)?;

        for (index, route) in accepted.iter().enumerate() {
            receipt.routes_intended = index + 1;
            receipt.save(directory, guard)?;
            self.route_change("add", route, &link.ifname, Some(cancel))?;
        }
        if dns.is_some() {
            // Prove the installed FIB entries before publishing resolver state.
            self.fib_clear(receipt, scope.grant)?;
        }
        if let Err(error) =
            verify_tunnel_routes(|args| self.ip(args), &receipt.routes, &link.ifname)
        {
            return Err(rollback_error(error, self.clean(guard, directory, receipt)));
        }
        if let Some(dns) = &dns {
            receipt.dns_intended = true;
            receipt.save(directory, guard)?;
            self.resolvectl(&["revert", &link.ifname], Some(cancel))?;
            // Publish routing restrictions before the link gains any servers.
            self.resolvectl(&["default-route", &link.ifname, "false"], Some(cancel))?;
            let mut args = vec!["domain", link.ifname.as_str()];
            let domains: Vec<String> = dns.domains.iter().map(|d| format!("~{d}")).collect();
            args.extend(domains.iter().map(String::as_str));
            self.resolvectl(&args, Some(cancel))?;
            let mut args = vec!["dns", link.ifname.as_str()];
            let servers: Vec<String> = dns.servers.iter().map(ToString::to_string).collect();
            args.extend(servers.iter().map(String::as_str));
            self.resolvectl(&args, Some(cancel))?;
        }

        let current = self
            .link(receipt)?
            .filter(|current| {
                current.ifindex == link.ifindex
                    && current.link_type.as_deref() == Some("ppp")
                    && current.flags.iter().any(|flag| flag == "UP")
            })
            .ok_or_else(|| invalid("PPP link changed during configuration"))?;
        if self.address(&current)? != local {
            return Err(invalid("network configuration confirmation failed"));
        }
        let gateway = self.egress(receipt.remote).and_then(|egress| {
            if egress != receipt.egress {
                return Err(invalid("network configuration confirmation failed"));
            }
            Ok(())
        });
        if let Err(error) = gateway {
            return Err(rollback_error(error, self.clean(guard, directory, receipt)));
        }
        if let Some(dns) = &dns
            && (self.dns_state(&current.ifname)? != *dns
                || !self.dns_default_route_disabled(&current.ifname)?)
        {
            return Err(invalid("DNS confirmation failed"));
        }
        let confirmation = self
            .fib_clear(receipt, scope.grant)
            .and_then(|current_inventory| inventory.require_unchanged(&current_inventory));
        if let Err(error) = confirmation {
            return Err(rollback_error(error, self.clean(guard, directory, receipt)));
        }
        receipt.confirmed = true;
        receipt.save(directory, guard)
    }

    fn probe_link(&self, receipt: &Receipt, deadline: Option<Instant>) -> io::Result<Link> {
        if !receipt.confirmed || receipt.complete || receipt.routes_intended != receipt.routes.len()
        {
            return Err(invalid("PPP probe scope is unconfirmed"));
        }
        let link = self
            .link_until(receipt, deadline)?
            .filter(|link| {
                receipt.ifindex == Some(link.ifindex)
                    && link.link_type.as_deref() == Some("ppp")
                    && link.flags.iter().any(|flag| flag == "UP")
            })
            .ok_or_else(|| invalid("PPP probe link is unproven"))?;
        if Some(self.address_until(&link, deadline)?) != receipt.local {
            return Err(invalid("PPP probe address is unproven"));
        }
        Ok(link)
    }

    pub(super) fn mark_probe_link(
        &self,
        guard: &NetworkGuard,
        directory: &Path,
        receipt: &mut Receipt,
        cancel: &SetupCancellation,
    ) -> io::Result<()> {
        let link = self.probe_link(receipt, None)?;
        if link.ifalias.is_some() {
            return Err(invalid("PPP probe link is already marked"));
        }
        receipt.probe_marked = true;
        receipt.save(directory, guard)?;
        (self.0)(
            IP,
            &[
                "link",
                "set",
                "dev",
                &link.ifname,
                "alias",
                &receipt.marker(),
            ],
            Some(cancel),
            None,
        )?;
        self.probe_binding(guard, receipt, None).map(|_| ())
    }

    pub(super) fn probe_binding(
        &self,
        _guard: &NetworkGuard,
        receipt: &Receipt,
        deadline: Option<Instant>,
    ) -> io::Result<ProbeBinding> {
        let link = self.probe_link(receipt, deadline)?;
        if !receipt.probe_marked || link.ifalias.as_deref() != Some(&receipt.marker()) {
            return Err(invalid("PPP probe ownership is unproven"));
        }
        let generation = Generation::parse(receipt.generation.clone())
            .ok_or_else(|| invalid("invalid probe generation"))?;
        let local = receipt
            .local
            .ok_or_else(|| invalid("missing probe address"))?;
        ProbeBinding::new(generation, link.ifindex, local, receipt.routes.clone())
            .ok_or_else(|| invalid("invalid PPP probe scope"))
    }

    fn cleanup_link(&self, receipt: &Receipt, ifindex: u32) -> io::Result<Option<Link>> {
        let marker = receipt.marker();
        let mut owned = None;
        for link in self.links(None)? {
            let recorded = link.ifname == receipt.ifname && link.ifindex == ifindex;
            let marked = link.ifalias.as_deref() == Some(marker.as_str());
            if receipt.probe_marked && recorded != marked {
                return Err(invalid("PPP cleanup ownership is unproven"));
            }
            if recorded && owned.replace(link).is_some() {
                return Err(invalid("PPP cleanup link identity is ambiguous"));
            }
        }
        Ok(owned)
    }

    /// Remove what the receipt says was attempted, then prove it is gone. A
    /// link that disappeared took its routes and DNS with it; a link that now
    /// answers to the name with another identity is not touched.
    pub(super) fn clean(
        &self,
        _guard: &NetworkGuard,
        directory: &Path,
        receipt: &Receipt,
    ) -> io::Result<()> {
        receipt.validate(directory, &Namespace::current()?)?;
        let Some(ifindex) = receipt.ifindex else {
            return Ok(());
        };
        if let Some(link) = self.cleanup_link(receipt, ifindex)? {
            let present = Self::applied(receipt, &self.routes()?)?;
            for route in receipt.routes[..receipt.routes_intended]
                .iter()
                .rev()
                .filter(|route| present.routes.contains(route))
            {
                self.route_change("del", route, &link.ifname, None)?;
            }
            if receipt.dns_intended {
                self.resolvectl(&["revert", &link.ifname], None)?;
            }
        }
        // Prove it: nothing of ours is left under the recorded identity.
        if let Some(link) = self.cleanup_link(receipt, ifindex)? {
            if !Self::applied(receipt, &self.routes()?)?.routes.is_empty() {
                return Err(invalid("a route remains on the PPP link"));
            }
            if receipt.dns_intended {
                let state = self.dns_state(&link.ifname)?;
                if !state.servers.is_empty() || !state.domains.is_empty() {
                    return Err(invalid("DNS remains on the PPP link"));
                }
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

/// Fixed program, clean environment, absolute deadline, bounded output.
fn run_command(
    program: &str,
    args: &[&str],
    cancel: Option<&SetupCancellation>,
    deadline: Option<Instant>,
) -> io::Result<Vec<u8>> {
    let ordinary_deadline = Instant::now() + COMMAND_DEADLINE;
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
    // The effect begins under the cancellation lock: once cancelled, nothing starts.
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

/// A fake kernel and resolver for this module's tests and for the launcher's.
#[cfg(test)]
pub(super) mod fixture {
    use super::*;
    use crate::netlease::NetworkLock;
    use serde_json::json;
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    pub(in crate::tunneld) struct Kernel {
        pub ops: Vec<String>,
        /// The PPP link exists (the instance's pppd made it).
        pub ppp: bool,
        pub up: bool,
        pub link_type: &'static str,
        pub ifindex: u32,
        pub ifalias: Option<String>,
        pub peer: Option<&'static str>,
        pub peer_route: Option<&'static str>,
        pub routes: Vec<String>,
        pub host_address: &'static str,
        pub foreign: Vec<serde_json::Value>,
        pub wrong_tunnel_path: bool,
        pub default_override: Option<Vec<serde_json::Value>>,
        pub rules: Vec<serde_json::Value>,
        pub foreign_on_add: Option<serde_json::Value>,
        pub rule_on_add: Option<serde_json::Value>,
        pub foreign_after_dns: Option<serde_json::Value>,
        pub dns: Vec<String>,
        pub domains: Vec<String>,
        pub dns_default_route: bool,
        pub ignore_dns_default_route: bool,
        pub egress_dev: &'static str,
        pub egress_index: u32,
        pub refuse_delete: bool,
        pub ignore_revert: bool,
        /// Fail the n-th (1-based) route add.
        pub fail_add: Option<usize>,
        pub adds: usize,
        pub resolver_fails: bool,
    }

    impl Default for Kernel {
        fn default() -> Self {
            Self {
                ops: Vec::new(),
                ppp: false,
                up: true,
                link_type: "ppp",
                ifindex: 9,
                ifalias: None,
                peer: Some(PEER),
                peer_route: Some(PEER),
                routes: Vec::new(),
                host_address: "192.0.2.2",
                foreign: Vec::new(),
                wrong_tunnel_path: false,
                default_override: None,
                rules: vec![
                    json!({"priority": 0, "src": "all", "table": "local"}),
                    json!({"priority": 32766, "src": "all", "table": "main"}),
                    json!({"priority": 32767, "src": "all", "table": "default"}),
                ],
                foreign_on_add: None,
                rule_on_add: None,
                foreign_after_dns: None,
                dns: Vec::new(),
                domains: Vec::new(),
                dns_default_route: true,
                ignore_dns_default_route: false,
                egress_dev: "eth-fixture",
                egress_index: 2,
                refuse_delete: false,
                ignore_revert: false,
                fail_add: None,
                adds: 0,
                resolver_fails: false,
            }
        }
    }

    pub(in crate::tunneld) const LOCAL: &str = "10.99.0.2";
    pub(in crate::tunneld) const PEER: &str = "169.254.2.1";
    pub(in crate::tunneld) const NAME: &str = "vpntp1";

    /// A kernel whose every command is checked against the writer lock when a
    /// runtime directory is given.
    pub(in crate::tunneld) fn network(
        kernel: Arc<Mutex<Kernel>>,
        runtime: Option<PathBuf>,
    ) -> FortinetNetwork {
        FortinetNetwork::fake(move |program, args| {
            if let Some(runtime) = &runtime {
                assert_eq!(
                    NetworkLock::acquire_test(runtime, Instant::now() + Duration::from_millis(12))
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::TimedOut,
                    "network operation outside the writer lock: {args:?}",
                );
            }
            let mut k = kernel.lock().unwrap();
            k.ops.push(format!("{} {}", program, args.join(" ")));
            let say = |value: serde_json::Value| Ok(serde_json::to_vec(&value).unwrap());
            if program == RESOLVECTL {
                if k.resolver_fails {
                    return Err(io::Error::other("fixture resolver failure"));
                }
                let name = NAME;
                return match args {
                    ["revert", n] if *n == name => {
                        if !k.ignore_revert {
                            k.dns.clear();
                            k.domains.clear();
                            k.dns_default_route = true;
                        }
                        Ok(vec![])
                    }
                    ["dns", n] if *n == name => {
                        Ok(
                            format!("Link {} ({name}): {}\n", k.ifindex, k.dns.join(" "))
                                .into_bytes(),
                        )
                    }
                    ["domain", n] if *n == name => {
                        Ok(
                            format!("Link {} ({name}): {}\n", k.ifindex, k.domains.join(" "))
                                .into_bytes(),
                        )
                    }
                    ["dns", n, servers @ ..] if *n == name => {
                        k.dns = servers.iter().map(|s| (*s).to_owned()).collect();
                        if let Some(route) = k.foreign_after_dns.take() {
                            k.foreign.push(route);
                        }
                        Ok(vec![])
                    }
                    ["domain", n, domains @ ..] if *n == name => {
                        k.domains = domains.iter().map(|s| (*s).to_owned()).collect();
                        Ok(vec![])
                    }
                    ["default-route", n] if *n == name => {
                        let value = if k.dns_default_route { "yes" } else { "no" };
                        Ok(format!("Link {} ({name}): {value}\n", k.ifindex).into_bytes())
                    }
                    ["default-route", n, "false"] if *n == name => {
                        if !k.ignore_dns_default_route {
                            k.dns_default_route = false;
                        }
                        Ok(vec![])
                    }
                    _ => panic!("unexpected resolver operation: {args:?}"),
                };
            }
            assert_eq!(program, IP);
            match args {
                ["-4", "-j", "route", "get", dst]
                    if k.routes.iter().any(|route| {
                        prefix(route).unwrap().0 == dst.parse::<Ipv4Addr>().unwrap().to_bits()
                    }) =>
                {
                    say(json!([{"dev": if k.wrong_tunnel_path { k.egress_dev } else { NAME }}]))
                }
                ["-4", "-j", "route", "get", _] => say(json!([
                    {"dev": k.egress_dev, "prefsrc": "192.0.2.2", "gateway": "192.0.2.1"}
                ])),
                ["-j", "-d", "link", "show"] => {
                    let mut links = vec![json!({
                        "ifname": k.egress_dev, "ifindex": k.egress_index,
                        "link_type": "ether", "flags": ["UP"]
                    })];
                    if k.ppp {
                        links.push(json!({
                            "ifname": NAME, "ifindex": k.ifindex, "link_type": k.link_type, "ifalias": k.ifalias,
                            "flags": if k.up { vec!["POINTOPOINT", "UP"] } else { vec!["POINTOPOINT"] }
                        }));
                    }
                    say(json!(links))
                }
                ["link", "set", "dev", NAME, "alias", alias] if k.ppp => {
                    k.ifalias = Some((*alias).into());
                    Ok(vec![])
                }
                ["-j", "-4", "addr", "show", "dev", NAME] => say(json!([{
                    "ifindex": k.ifindex,
                    "addr_info": [{"family": "inet", "local": LOCAL, "address": k.peer, "prefixlen": 32}]
                }])),
                ["-j", "-4", "addr", "show"] => say(json!([{
                    "ifindex": k.egress_index,
                    "addr_info": [{"family": "inet", "local": k.host_address, "prefixlen": 24}]
                }])),
                ["-4", "-j", "rule", "show"] => say(json!(k.rules)),
                ["-4", "-j", "route", "show", "table", table] => say(json!(
                    k.foreign
                        .iter()
                        .filter(|route| route["table"] == *table)
                        .collect::<Vec<_>>()
                )),
                ["-4", "-j", "-d", "route", "show", "table", "all"] => {
                    let mut routes = k.default_override.clone().unwrap_or_else(|| {
                        vec![json!({
                            "dst": "default", "dev": k.egress_dev, "type": "unicast",
                            "table": "main", "protocol": "dhcp", "scope": "global",
                            "gateway": "192.0.2.1", "metric": 100, "flags": []
                        })]
                    });
                    routes.extend(k.foreign.iter().cloned());
                    if k.ppp {
                        if let Some(peer_route) = k.peer_route {
                            routes.push(json!({
                                "dst": peer_route, "dev": NAME, "type": "unicast", "table": "main",
                                "protocol": "kernel", "scope": "link", "prefsrc": LOCAL, "flags": []
                            }));
                        }
                        routes.push(json!({
                            "dst": LOCAL, "dev": NAME, "type": "local", "table": "local",
                            "protocol": "kernel", "scope": "host", "prefsrc": LOCAL, "flags": []
                        }));
                        routes.extend(k.routes.iter().map(|dst| {
                            json!({
                                "dst": dst, "dev": NAME, "type": "unicast", "table": "main",
                                "protocol": "boot", "scope": "link", "flags": []
                            })
                        }));
                    }
                    say(json!(routes))
                }
                [
                    "-4",
                    "route",
                    "add",
                    dst,
                    "dev",
                    NAME,
                    "table",
                    "main",
                    "proto",
                    "boot",
                    "scope",
                    "link",
                ] => {
                    k.adds += 1;
                    if k.fail_add == Some(k.adds) {
                        return Err(io::Error::other("fixture refused add"));
                    }
                    k.routes.push((*dst).to_owned());
                    if let Some(route) = k.foreign_on_add.take() {
                        k.foreign.push(route);
                    }
                    if let Some(rule) = k.rule_on_add.take() {
                        k.rules.push(rule);
                    }
                    Ok(vec![])
                }
                [
                    "-4",
                    "route",
                    "del",
                    dst,
                    "dev",
                    NAME,
                    "table",
                    "main",
                    "proto",
                    "boot",
                    "scope",
                    "link",
                ] => {
                    if k.refuse_delete {
                        return Err(io::Error::other("fixture refused delete"));
                    }
                    k.routes.retain(|route| route != dst);
                    Ok(vec![])
                }
                _ => panic!("unexpected network operation: {args:?}"),
            }
        })
    }

    pub(in crate::tunneld) fn entry(
        routes: &[&str],
        dns_servers: &[&str],
        domains: &[&str],
    ) -> Entry {
        serde_json::from_value(json!({
            "backend": "fortinet", "uid": 1000, "hostname": "vpn.example",
            "peer_identity": "vpn.example", "transport_ipv4": ["192.0.2.20"], "port": 443,
            "certificate_sha256": "ab".repeat(32), "route_cidrs": routes,
            "fortinet_local_cidr": "10.99.0.0/24",
            "dns_domains": domains, "dns_servers": dns_servers
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{fixture::*, *};
    use crate::netlease::NetworkLock;
    use crate::tunneld::network::coexistence_tests;
    use serde_json::{Value, json};
    use std::{
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

    struct Root(PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        root: Root,
        directory: PathBuf,
        kernel: Arc<Mutex<Kernel>>,
        network: FortinetNetwork,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "vpnt-fnet-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let root = Root(root);
            let directory = root.0.join(GENERATION);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let kernel = Arc::new(Mutex::new(Kernel::default()));
            let network = network(kernel.clone(), Some(root.0.clone()));
            Self {
                root,
                directory,
                kernel,
                network,
            }
        }

        fn guard(&self) -> NetworkGuard {
            NetworkLock::acquire_test(&self.root.0, Instant::now() + Duration::from_secs(2))
                .unwrap()
        }

        fn plan(&self) -> Receipt {
            let guard = self.guard();
            let receipt = self
                .network
                .plan(&guard, GENERATION, REMOTE, &self.grant())
                .unwrap();
            receipt.save(&self.directory, &guard).unwrap();
            receipt
        }

        fn grant(&self) -> Grant {
            Grant::from_entry(&entry(&[], &[], &[])).unwrap()
        }

        fn ops(&self) -> Vec<String> {
            self.kernel.lock().unwrap().ops.clone()
        }

        fn writes(&self) -> Vec<String> {
            self.ops()
                .into_iter()
                .filter(|op| {
                    op.contains(" route add ")
                        || op.contains(" route del ")
                        || op.contains(" revert ")
                        || op.starts_with(&format!("{RESOLVECTL} dns {NAME} "))
                        || op.starts_with(&format!("{RESOLVECTL} domain {NAME} "))
                        || op.starts_with(&format!("{RESOLVECTL} default-route {NAME} "))
                })
                .collect()
        }
    }

    fn ready(routes: &[(&str, u8)], dns: &[&str]) -> Delivered {
        let mut delivered = Delivered::default();
        delivered.absorb(Event::Interface { name: NAME.into() });
        for (network, prefix) in routes {
            delivered.absorb(Event::SplitRoute {
                network: network.parse().unwrap(),
                prefix: *prefix,
            });
        }
        delivered.absorb(Event::SplitRoutes {
            count: routes.len(),
        });
        for server in dns {
            delivered.absorb(Event::DnsServer {
                address: server.parse().unwrap(),
            });
        }
        delivered.absorb(Event::DnsCount {
            servers: dns.len(),
            domains: 0,
        });
        delivered
    }

    fn apply(
        fixture: &Fixture,
        receipt: &mut Receipt,
        delivered: &Delivered,
        entry: &Entry,
    ) -> io::Result<()> {
        let grant = Grant::from_entry(entry).unwrap();
        fixture.network.apply(
            &fixture.guard(),
            &fixture.directory,
            receipt,
            delivered,
            &Scope {
                entry,
                grant: &grant,
            },
            &SetupCancellation::default(),
        )
    }

    fn up(fixture: &Fixture) {
        fixture.kernel.lock().unwrap().ppp = true;
    }

    #[test]
    fn the_plan_picks_the_egress_and_a_free_ppp_name() {
        let fixture = Fixture::new();
        let receipt = fixture.plan();
        assert_eq!(receipt.ifname, NAME);
        assert_eq!(receipt.binding(), ("eth-fixture", 2, REMOTE));
        let reloaded = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
        assert_eq!(reloaded.ifname, NAME);
        assert!(!reloaded.complete);
    }

    #[test]
    fn planning_refuses_preexisting_routes_covering_the_technical_peer() {
        for (dst, table) in [
            (PEER, "local"),
            ("169.254.0.0/16", "main"),
            ("169.254.2.1/32", "100"),
        ] {
            let fixture = Fixture::new();
            let competing = external_route(dst, table);
            fixture
                .kernel
                .lock()
                .unwrap()
                .foreign
                .push(competing.clone());
            let result =
                fixture
                    .network
                    .plan(&fixture.guard(), GENERATION, REMOTE, &fixture.grant());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(!fixture.directory.join(RECEIPT).exists());
            assert!(fixture.writes().is_empty());
            let kernel = fixture.kernel.lock().unwrap();
            assert!(!kernel.ppp);
            assert_eq!(kernel.foreign, [competing]);
        }
    }

    #[test]
    fn planning_refuses_local_scope_overlapping_a_host_route() {
        let fixture = Fixture::new();
        fixture
            .kernel
            .lock()
            .unwrap()
            .foreign
            .push(external_route("10.99.0.128/25", "main"));
        let error = fixture
            .network
            .plan(&fixture.guard(), GENERATION, REMOTE, &fixture.grant())
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Fortinet local scope overlaps a host route"
        );
        assert!(!fixture.directory.join(RECEIPT).exists());
        assert!(fixture.writes().is_empty());
    }

    #[test]
    fn planning_refuses_host_addresses_and_policy_dns_in_the_local_scope() {
        let fixture = Fixture::new();
        let mut grant = fixture.grant();
        fixture.kernel.lock().unwrap().host_address = LOCAL;
        let error = fixture
            .network
            .plan(&fixture.guard(), GENERATION, REMOTE, &grant)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Fortinet local scope overlaps a host address"
        );

        grant.dns_servers = vec![LOCAL.parse().unwrap()];
        let error = fixture
            .network
            .plan(&fixture.guard(), GENERATION, REMOTE, &grant)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Fortinet local scope overlaps protected addresses"
        );
        assert!(!fixture.directory.join(RECEIPT).exists());
        assert!(fixture.writes().is_empty());
    }

    #[test]
    fn apply_refuses_a_local_address_outside_the_grant_before_network_writes() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let mut grant = fixture.grant();
        grant.fortinet_local_cidr = "10.99.0.3/32".parse().unwrap();
        let entry = entry(&["10.20.0.0/15"], &[], &[]);
        let error = fixture
            .network
            .apply(
                &fixture.guard(),
                &fixture.directory,
                &mut receipt,
                &ready(&[("10.20.0.0", 16)], &[]),
                &Scope {
                    entry: &entry,
                    grant: &grant,
                },
                &SetupCancellation::default(),
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "PPP local address is outside the approved Fortinet scope"
        );
        assert!(fixture.writes().is_empty());
    }

    #[test]
    fn apply_requires_the_fixed_peer_address_and_its_kernel_route() {
        for (peer, route) in [
            (Some("10.99.0.1"), Some("10.99.0.1")),
            (None, None),
            (Some(PEER), None),
            (Some(PEER), Some("169.254.2.0/31")),
        ] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            {
                let mut kernel = fixture.kernel.lock().unwrap();
                kernel.ppp = true;
                kernel.peer = peer;
                kernel.peer_route = route;
            }
            assert_rejected_before_writes(&fixture, &mut receipt);
        }
    }

    #[test]
    fn routes_inside_the_ceiling_are_applied_and_the_rest_refused_and_counted() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let entry = entry(&["10.20.0.0/15"], &[], &[]);
        let delivered = ready(
            &[
                ("10.20.0.0", 16),
                ("192.168.0.0", 16),
                // Host bits set: not a route at all.
                ("10.20.0.1", 16),
                ("10.20.0.0", 16),
                // Wider than the ceiling.
                ("10.0.0.0", 8),
                // The technical peer is never a policy route.
                (PEER, 32),
            ],
            &[],
        );
        apply(&fixture, &mut receipt, &delivered, &entry).unwrap();
        assert_eq!(fixture.kernel.lock().unwrap().routes, ["10.20.0.0/16"]);
        assert_eq!(
            receipt.report(),
            Report {
                accepted_routes: 1,
                refused_routes: 4,
                dns_servers: 0,
                refused_dns: 0
            }
        );
        // No DNS without a policy domain, and none was written.
        assert!(!fixture.ops().iter().any(|op| op.starts_with(RESOLVECTL)));
        let saved = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
        assert_eq!((saved.routes_intended, saved.confirmed), (1, true));
        assert_eq!(saved.ifindex, Some(9));
        assert_eq!(saved.peer, Some(PEER.parse().unwrap()));
    }

    #[test]
    fn a_gateway_dns_inside_the_accepted_routes_is_published_with_the_policy_domains() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let entry = entry(&["10.20.0.0/15"], &[], &["corp.example"]);
        let delivered = ready(&[("10.20.0.0", 16)], &["10.20.1.53", "10.21.0.53"]);
        apply(&fixture, &mut receipt, &delivered, &entry).unwrap();
        let k = fixture.kernel.lock().unwrap();
        assert_eq!(k.dns, ["10.20.1.53"]);
        assert_eq!(k.domains, ["~corp.example"]);
        assert!(!k.dns_default_route);
        assert_eq!(receipt.report().dns_servers, 1);
        assert_eq!(receipt.report().refused_dns, 1);
        drop(k);
        let writes = fixture.writes();
        let dns: Vec<_> = writes
            .iter()
            .filter(|op| op.starts_with(RESOLVECTL))
            .collect();
        assert_eq!(
            dns,
            [
                &format!("{RESOLVECTL} revert {NAME}"),
                &format!("{RESOLVECTL} default-route {NAME} false"),
                &format!("{RESOLVECTL} domain {NAME} ~corp.example"),
                &format!("{RESOLVECTL} dns {NAME} 10.20.1.53"),
            ]
        );
    }

    #[test]
    fn a_resolver_that_leaves_default_route_enabled_is_not_confirmed_and_is_reverted() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        fixture.kernel.lock().unwrap().ignore_dns_default_route = true;
        let entry = entry(&["10.20.0.0/16"], &[], &["corp.example"]);
        let delivered = ready(&[("10.20.0.0", 16)], &["10.20.1.53"]);
        let error = apply(&fixture, &mut receipt, &delivered, &entry).unwrap_err();
        assert_eq!(error.to_string(), "DNS confirmation failed");

        let guard = fixture.guard();
        let saved = Receipt::load(&fixture.directory, &guard).unwrap();
        assert!(saved.dns_intended && !saved.confirmed);
        fixture
            .network
            .clean(&guard, &fixture.directory, &saved)
            .unwrap();
        let kernel = fixture.kernel.lock().unwrap();
        assert!(kernel.dns.is_empty() && kernel.domains.is_empty());
    }

    #[test]
    fn policy_domains_require_a_valid_reachable_gateway_offer_when_dns_is_not_fixed() {
        let entry = entry(&["10.20.0.0/15"], &[], &["corp.example"]);
        for (servers, invalid) in [
            (&[][..], false),
            (&["198.51.100.53", "10.21.0.53", PEER][..], false),
            (&["10.20.1.53"][..], true),
        ] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            let mut delivered = ready(&[("10.20.0.0", 16)], servers);
            if invalid {
                delivered.absorb(Event::DnsInvalid);
            }
            assert_missing_policy_dns(&fixture, &mut receipt, &delivered, &entry);
        }
    }

    #[test]
    fn a_policy_that_fixes_the_servers_prevails_over_the_gateway() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        fixture
            .kernel
            .lock()
            .unwrap()
            .foreign
            .push(external_route("198.51.100.0/24", "main"));
        let entry = entry(
            &["10.20.0.0/15"],
            &["10.20.9.9", "10.21.0.53"],
            &["corp.example"],
        );
        let delivered = ready(&[("10.20.0.0", 16)], &["10.20.1.53"]);
        apply(&fixture, &mut receipt, &delivered, &entry).unwrap();
        assert_eq!(fixture.kernel.lock().unwrap().dns, ["10.20.9.9"]);
        assert_eq!(receipt.report().refused_dns, 1);
        assert!(
            Receipt::load(&fixture.directory, &fixture.guard())
                .unwrap()
                .confirmed
        );
        assert!(
            !fixture.ops().iter().any(|op| op.contains("10.20.1.53")),
            "the gateway's server was used"
        );
    }

    #[test]
    fn unreachable_fixed_dns_never_falls_back_to_gateway_dns() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let entry = entry(&["10.20.0.0/15"], &["10.21.0.53"], &["corp.example"]);
        let delivered = ready(&[("10.20.0.0", 16)], &["10.20.1.53"]);
        assert_missing_policy_dns(&fixture, &mut receipt, &delivered, &entry);
    }

    #[test]
    fn the_ppp_local_address_is_not_a_tunnel_dns_destination() {
        for fixed in [false, true] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            let servers = [LOCAL];
            let fixed_servers = if fixed { &servers[..] } else { &[] };
            let entry = entry(&["10.99.0.0/24"], fixed_servers, &["corp.example"]);
            let delivered = ready(&[("10.99.0.0", 24)], &servers);
            assert_missing_policy_dns(&fixture, &mut receipt, &delivered, &entry);
        }
    }

    #[test]
    fn dns_needs_a_policy_domain_even_with_fixed_servers_in_the_grant() {
        // Policy canonicalization forbids servers without domains; the writer
        // still never publishes a link with servers and no domain scope.
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let entry = entry(&["10.20.0.0/15"], &["10.20.9.9"], &[]);
        let delivered = ready(&[("10.20.0.0", 16)], &[]);
        apply(&fixture, &mut receipt, &delivered, &entry).unwrap();
        assert!(!fixture.ops().iter().any(|op| op.starts_with(RESOLVECTL)));
        let saved = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
        assert_eq!(
            (saved.routes_intended, saved.dns_intended, saved.confirmed),
            (1, false, true)
        );
        assert_eq!(fixture.kernel.lock().unwrap().routes, ["10.20.0.0/16"]);
    }

    #[test]
    fn a_route_over_the_transport_is_a_fatal_conflict_and_nothing_is_written() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        // The ceiling allows it, and it covers the gateway's own address.
        let entry = entry(&["192.0.0.0/8"], &[], &[]);
        let delivered = ready(&[("192.0.0.0", 8)], &[]);
        let error = apply(&fixture, &mut receipt, &delivered, &entry).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(fixture.writes().is_empty(), "{:?}", fixture.writes());
    }

    fn external_route(dst: &str, table: &str) -> Value {
        json!({"dst": dst, "dev": "eth-other", "type": "unicast", "table": table})
    }

    fn custom_rule() -> Value {
        json!({"priority": 100, "src": "all", "fwmark": "0x1", "table": "100"})
    }

    fn assert_rejected_before_writes(fixture: &Fixture, receipt: &mut Receipt) {
        let entry = entry(&["10.20.0.0/15"], &[], &["corp.example"]);
        let delivered = ready(&[("10.20.0.0", 16)], &["10.20.1.53"]);
        let result = apply(fixture, receipt, &delivered, &entry);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_no_network_effects(fixture);
    }

    fn assert_missing_policy_dns(
        fixture: &Fixture,
        receipt: &mut Receipt,
        delivered: &Delivered,
        entry: &Entry,
    ) {
        let error = apply(fixture, receipt, delivered, entry).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "no reachable DNS server for policy domains"
        );
        assert_eq!(
            (
                receipt.routes_intended,
                receipt.dns_intended,
                receipt.confirmed
            ),
            (0, false, false)
        );
        assert_no_network_effects(fixture);
    }

    fn assert_no_network_effects(fixture: &Fixture) {
        let saved = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
        assert_eq!(
            (saved.routes_intended, saved.dns_intended, saved.confirmed),
            (0, false, false)
        );
        fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &saved)
            .unwrap();
        assert!(fixture.writes().is_empty());
        let kernel = fixture.kernel.lock().unwrap();
        assert!(kernel.routes.is_empty() && kernel.dns.is_empty() && kernel.domains.is_empty());
    }

    #[test]
    fn same_prefix_supernet_and_subnet_in_any_table_are_conflicts() {
        for (dst, table) in [
            ("10.20.0.0/16", "main"),
            ("10.0.0.0/8", "main"),
            ("10.20.1.0/24", "100"),
            ("10.20.1.53", "local"),
        ] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            fixture
                .kernel
                .lock()
                .unwrap()
                .foreign
                .push(external_route(dst, table));
            assert_rejected_before_writes(&fixture, &mut receipt);
        }
    }

    #[test]
    fn nonstandard_ipv4_rules_refuse_routes_and_dns() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        fixture.kernel.lock().unwrap().rules.push(custom_rule());
        assert_rejected_before_writes(&fixture, &mut receipt);
    }

    #[test]
    fn unreadable_external_route_refuses_routes_and_dns() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        fixture
            .kernel
            .lock()
            .unwrap()
            .foreign
            .push(external_route("10.20.0.0/33", "main"));
        assert_rejected_before_writes(&fixture, &mut receipt);
    }

    #[test]
    fn tailscale_rules_admit_disjoint_routes_in_table_52() {
        let fixture = Fixture::new();
        {
            let mut kernel = fixture.kernel.lock().unwrap();
            kernel.rules = coexistence_tests::tailscale_rules();
            kernel.foreign.push(external_route("100.64.0.0/10", "52"));
            kernel.foreign.push(external_route("100.110.20.1", "52"));
        }
        let mut receipt = fixture.plan();
        up(&fixture);
        apply(
            &fixture,
            &mut receipt,
            &ready(&[("10.20.0.0", 16)], &[]),
            &entry(&["10.20.0.0/15"], &[], &[]),
        )
        .unwrap();
    }

    #[test]
    fn extra_policy_tables_refuse_default_and_protected_destinations() {
        for dst in ["default", "192.0.2.20", "10.20.1.0/24", PEER, "10.99.0.8"] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            {
                let mut kernel = fixture.kernel.lock().unwrap();
                kernel.rules = coexistence_tests::tailscale_rules();
                kernel.foreign.push(external_route(dst, "52"));
            }
            let error = apply(
                &fixture,
                &mut receipt,
                &ready(&[("10.20.0.0", 16)], &[]),
                &entry(&["10.20.0.0/15"], &[], &[]),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("priority 5270 table 52"),
                "{error}"
            );
            assert_no_network_effects(&fixture);
        }
    }

    #[test]
    fn planning_checks_the_approved_route_ceiling_before_ppp_starts() {
        let fixture = Fixture::new();
        let grant = Grant::from_entry(&entry(&["10.20.0.0/15"], &[], &[])).unwrap();
        {
            let mut kernel = fixture.kernel.lock().unwrap();
            kernel.rules = coexistence_tests::tailscale_rules();
            kernel.foreign.push(external_route("10.21.1.0/24", "52"));
        }
        let result = fixture
            .network
            .plan(&fixture.guard(), GENERATION, REMOTE, &grant);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("priority 5270 table 52")
        );
        assert!(!fixture.directory.join(RECEIPT).exists());
        assert!(fixture.writes().is_empty());
    }

    #[test]
    fn unsupported_policy_rules_identify_priority_without_selector_addresses() {
        for rule in coexistence_tests::unsupported_rules() {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            fixture.kernel.lock().unwrap().rules.insert(1, rule);
            let error = apply(
                &fixture,
                &mut receipt,
                &ready(&[("10.20.0.0", 16)], &[]),
                &entry(&["10.20.0.0/15"], &[], &[]),
            )
            .unwrap_err();
            assert!(error.to_string().contains("priority 500 table"), "{error}");
            assert!(!error.to_string().contains("203.0.113.0"));
            assert_no_network_effects(&fixture);
        }
    }

    #[test]
    fn distinct_defaults_are_admitted_when_the_kernel_egress_matches() {
        let fixture = Fixture::new();
        fixture.kernel.lock().unwrap().default_override =
            Some(coexistence_tests::defaults("eth-fixture"));
        let mut receipt = fixture.plan();
        up(&fixture);
        apply(
            &fixture,
            &mut receipt,
            &ready(&[("10.20.0.0", 16)], &[]),
            &entry(&["10.20.0.0/15"], &[], &[]),
        )
        .unwrap();
    }

    #[test]
    fn a_policy_lookup_outside_ppp_after_installation_rolls_back_before_dns() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        fixture.kernel.lock().unwrap().wrong_tunnel_path = true;
        let error = apply(
            &fixture,
            &mut receipt,
            &ready(&[("10.20.0.0", 16)], &[]),
            &entry(&["10.20.0.0/15"], &["10.20.0.53"], &["corp.example"]),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "tunnel route lookup selected a different interface"
        );
        let kernel = fixture.kernel.lock().unwrap();
        assert!(kernel.routes.is_empty());
        assert!(kernel.dns.is_empty());
        assert!(kernel.ops.iter().any(|op| op.contains(" route add ")));
        assert!(kernel.ops.iter().any(|op| op.contains(" route del ")));
        assert!(!receipt.confirmed);
    }

    #[test]
    fn ppp_rechecks_additional_tables_before_confirmation() {
        for (destination, message) in [
            (
                "10.20.1.0/24",
                "IPv4 policy rule priority 5270 table 52: route overlaps protected destinations",
            ),
            (
                "203.0.113.0/24",
                "IPv4 policy routing inventory changed during configuration",
            ),
        ] {
            let fixture = Fixture::new();
            {
                let mut kernel = fixture.kernel.lock().unwrap();
                kernel.rules = coexistence_tests::tailscale_rules();
                kernel.foreign.push(external_route("100.64.0.0/10", "52"));
                kernel.foreign_after_dns = Some(external_route(destination, "52"));
            }
            let mut receipt = fixture.plan();
            up(&fixture);
            let error = apply(
                &fixture,
                &mut receipt,
                &ready(&[("10.20.0.0", 16)], &[]),
                &entry(&["10.20.0.0/15"], &["10.20.0.53"], &["corp.example"]),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), message);
            assert!(!receipt.confirmed);
            let saved = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
            assert!(!saved.confirmed);
            let kernel = fixture.kernel.lock().unwrap();
            assert!(kernel.routes.is_empty());
            assert!(kernel.dns.is_empty() && kernel.domains.is_empty() && kernel.dns_default_route);
            assert!(kernel.foreign.contains(&external_route(destination, "52")));
        }
    }

    #[test]
    fn defaults_must_be_unicast_main_and_include_the_proved_egress() {
        let defaults = coexistence_tests::defaults;
        let mut variants = vec![vec![], defaults("eth-other")];
        for (key, value) in [
            ("type", json!("blackhole")),
            ("table", json!("default")),
            ("nhid", json!(12)),
            ("nexthops", json!([{"dev": "eth-other"}])),
            ("encap", json!({"type":"mpls"})),
            ("tos", json!("0x10")),
            ("gateway", json!("10.20.1.1")),
            ("gateway", json!(PEER)),
            ("prefsrc", json!("10.20.1.2")),
        ] {
            let mut rows = defaults("eth-fixture");
            rows[1][key] = value;
            variants.push(rows);
        }
        let mut wrong_gateway = defaults("eth-fixture");
        wrong_gateway[0]["gateway"] = json!("192.0.2.3");
        variants.push(wrong_gateway);
        for defaults in variants {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            fixture.kernel.lock().unwrap().default_override = Some(defaults);
            assert_rejected_before_writes(&fixture, &mut receipt);
        }
    }

    fn onlink_default(key: &str, address: &str) -> Vec<Value> {
        let mut default = json!({
            "dst": "default", "dev": "eth-fixture", "type": "unicast", "table": "main",
            "protocol": "dhcp", "scope": "global", "gateway": "192.0.2.1",
            "metric": 100, "flags": ["onlink"]
        });
        default[key] = json!(address);
        vec![default]
    }

    #[test]
    fn planning_refuses_a_local_scope_holding_the_default_route_next_hop_or_source() {
        for (key, address) in [
            ("gateway", "10.99.0.7"),
            ("prefsrc", "10.99.0.9"),
            // First and last address of the approved range.
            ("gateway", "10.99.0.0"),
            ("prefsrc", "10.99.0.255"),
        ] {
            let fixture = Fixture::new();
            fixture.kernel.lock().unwrap().default_override = Some(onlink_default(key, address));
            let error = fixture
                .network
                .plan(&fixture.guard(), GENERATION, REMOTE, &fixture.grant())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{key} {address}");
            assert_eq!(
                error.to_string(),
                "Fortinet local scope overlaps the default route"
            );
            assert!(!fixture.directory.join(RECEIPT).exists());
            assert!(fixture.writes().is_empty());
        }
    }

    #[test]
    fn apply_refuses_a_local_scope_holding_the_default_route_next_hop_or_source() {
        for (key, address) in [("gateway", "10.99.0.7"), ("prefsrc", "10.99.0.9")] {
            // The default route changes after planning: apply() sees it first.
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            fixture.kernel.lock().unwrap().default_override = Some(onlink_default(key, address));
            let entry = entry(&["10.20.0.0/15"], &[], &[]);
            let error = apply(
                &fixture,
                &mut receipt,
                &ready(&[("10.20.0.0", 16)], &[]),
                &entry,
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{key} {address}");
            assert_eq!(
                error.to_string(),
                "Fortinet local scope overlaps the default route"
            );
            assert_no_network_effects(&fixture);
        }
    }

    fn routed_through(key: &str, value: Value) -> Value {
        let mut route = json!({
            "dst": "10.50.0.0/16", "dev": "eth-fixture", "type": "unicast", "table": "main",
            "protocol": "static", "scope": "global", "flags": ["onlink"]
        });
        route[key] = value;
        route
    }

    #[test]
    fn a_specific_route_naming_a_local_scope_address_is_refused_by_plan_and_apply() {
        for (label, route) in [
            ("gateway", routed_through("gateway", json!("10.99.0.9"))),
            ("prefsrc", routed_through("prefsrc", json!("10.99.0.9"))),
            (
                "multipath hop",
                routed_through(
                    "nexthops",
                    json!([{"gateway": "10.99.0.9", "dev": "eth-fixture"}]),
                ),
            ),
        ] {
            let fixture = Fixture::new();
            fixture.kernel.lock().unwrap().foreign.push(route.clone());
            let error = fixture
                .network
                .plan(&fixture.guard(), GENERATION, REMOTE, &fixture.grant())
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Fortinet local scope overlaps a host route",
                "plan, {label}"
            );
            assert!(!fixture.directory.join(RECEIPT).exists());
            assert!(fixture.writes().is_empty());

            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            fixture.kernel.lock().unwrap().foreign.push(route);
            let entry = entry(&["10.20.0.0/15"], &[], &[]);
            let error = apply(
                &fixture,
                &mut receipt,
                &ready(&[("10.20.0.0", 16)], &[]),
                &entry,
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "Fortinet local scope overlaps a host route",
                "apply, {label}"
            );
            assert_no_network_effects(&fixture);
        }
    }

    #[test]
    fn a_route_with_an_unreadable_multipath_hop_is_refused_and_one_outside_the_scope_is_not() {
        for hops in [
            json!({"gateway": "10.99.0.9"}),
            json!([{"gateway": "fe80::1"}]),
            json!([{"gateway": 7}]),
        ] {
            let fixture = Fixture::new();
            fixture
                .kernel
                .lock()
                .unwrap()
                .foreign
                .push(routed_through("nexthops", hops));
            let error = fixture
                .network
                .plan(&fixture.guard(), GENERATION, REMOTE, &fixture.grant())
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        // Control: next hop and source outside the approved range.
        let fixture = Fixture::new();
        fixture.kernel.lock().unwrap().foreign.extend([
            routed_through("gateway", json!("10.98.255.9")),
            routed_through(
                "nexthops",
                json!([{"gateway": "10.100.0.9", "dev": "eth-fixture"}]),
            ),
        ]);
        fixture.plan();
    }

    #[test]
    fn a_default_route_outside_the_local_scope_is_still_accepted() {
        // Control: the same shape, with the next hop and source outside the range.
        let fixture = Fixture::new();
        fixture.kernel.lock().unwrap().default_override =
            Some(onlink_default("gateway", "10.98.255.254"));
        fixture.plan();
        let fixture = Fixture::new();
        fixture.kernel.lock().unwrap().default_override =
            Some(onlink_default("prefsrc", "10.100.0.1"));
        fixture.plan();
    }

    #[test]
    fn only_the_proved_ppp_kernel_shapes_are_excluded() {
        let peer = json!({
            "dst": PEER, "dev": NAME, "type": "unicast", "table": "main",
            "protocol": "kernel", "scope": "link", "prefsrc": LOCAL, "flags": []
        });
        for (key, value) in [
            ("table", json!("100")),
            ("scope", json!("global")),
            ("type", json!("blackhole")),
            ("prefsrc", json!("192.0.2.2")),
            ("tos", json!("0x10")),
        ] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            let mut route = peer.clone();
            route[key] = value;
            fixture.kernel.lock().unwrap().foreign.push(route);
            assert_rejected_before_writes(&fixture, &mut receipt);
        }
    }

    #[test]
    fn a_route_or_rule_added_during_configuration_prevents_confirmation_and_cleanup_converges() {
        let route = external_route("10.20.1.0/24", "main");
        for (foreign_on_add, rule, foreign_after_dns) in [
            (Some(route.clone()), None, None),
            (Some(external_route(PEER, "local")), None, None),
            (None, Some(custom_rule()), None),
            (None, None, Some(route)),
        ] {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            up(&fixture);
            {
                let mut k = fixture.kernel.lock().unwrap();
                k.foreign_on_add = foreign_on_add.clone();
                k.rule_on_add = rule.clone();
                k.foreign_after_dns = foreign_after_dns.clone();
            }
            let entry = entry(&["10.20.0.0/15"], &[], &["corp.example"]);
            let delivered = ready(&[("10.20.0.0", 16)], &["10.20.1.53"]);
            assert_eq!(
                apply(&fixture, &mut receipt, &delivered, &entry)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            let saved = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
            let dns_written = foreign_after_dns.is_some();
            assert_eq!(
                (saved.routes_intended, saved.dns_intended, saved.confirmed),
                (1, dns_written, false)
            );
            {
                let k = fixture.kernel.lock().unwrap();
                if dns_written {
                    assert!(k.routes.is_empty() && k.dns.is_empty() && k.domains.is_empty());
                } else {
                    assert_eq!(k.routes, ["10.20.0.0/16"]);
                    assert!(k.dns.is_empty() && k.domains.is_empty());
                    assert!(k.ops.iter().all(|op| !op.starts_with(RESOLVECTL)));
                }
            }
            for _ in 0..2 {
                fixture
                    .network
                    .clean(&fixture.guard(), &fixture.directory, &saved)
                    .unwrap();
                let k = fixture.kernel.lock().unwrap();
                assert!(k.routes.is_empty() && k.dns.is_empty() && k.domains.is_empty());
                let foreign = foreign_on_add.as_ref().or(foreign_after_dns.as_ref());
                assert_eq!(k.foreign.first(), foreign);
                assert_eq!(k.foreign.len(), usize::from(foreign.is_some()));
                assert_eq!(k.rules.get(3), rule.as_ref());
            }
        }
    }

    #[test]
    fn a_changed_egress_or_a_foreign_link_is_refused_before_any_write() {
        let entry = entry(&["10.20.0.0/15"], &[], &[]);
        let delivered = ready(&[("10.20.0.0", 16)], &[]);
        type Mutate = fn(&mut Kernel);
        let cases: [(&str, Mutate); 4] = [
            ("egress moved", |k| k.egress_dev = "eth-other"),
            ("link is down", |k| k.up = false),
            ("link is not ppp", |k| k.link_type = "ether"),
            ("link took the egress index", |k| k.ifindex = 2),
        ];
        for (label, mutate) in cases {
            let fixture = Fixture::new();
            let mut receipt = fixture.plan();
            {
                let mut k = fixture.kernel.lock().unwrap();
                k.ppp = true;
                if label == "egress moved" {
                    // The new egress must exist as an UP link for the lookup.
                    k.egress_dev = "eth-fixture";
                }
                mutate(&mut k);
            }
            assert!(
                apply(&fixture, &mut receipt, &delivered, &entry).is_err(),
                "{label}"
            );
            assert!(
                fixture.writes().is_empty(),
                "{label}: {:?}",
                fixture.writes()
            );
        }
    }

    #[test]
    fn another_interface_than_the_planned_one_is_not_applied() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let mut delivered = Delivered::default();
        delivered.absorb(Event::Interface {
            name: "vpntp2".into(),
        });
        delivered.absorb(Event::SplitRoutes { count: 0 });
        delivered.absorb(Event::DnsCount {
            servers: 0,
            domains: 0,
        });
        assert!(
            apply(
                &fixture,
                &mut receipt,
                &delivered,
                &entry(&["10.20.0.0/15"], &[], &[])
            )
            .is_err()
        );
        assert!(fixture.writes().is_empty());
    }

    fn applied_fixture() -> (Fixture, Receipt) {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        let entry = entry(&["10.20.0.0/15"], &[], &["corp.example"]);
        let delivered = ready(&[("10.20.0.0", 16), ("10.21.0.0", 16)], &["10.20.1.53"]);
        apply(&fixture, &mut receipt, &delivered, &entry).unwrap();
        assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 2);
        (fixture, receipt)
    }

    #[test]
    fn a_recycled_ppp_link_with_the_same_name_and_index_cannot_prove_the_probe() {
        let (fixture, mut receipt) = applied_fixture();
        let guard = fixture.guard();
        fixture
            .network
            .mark_probe_link(
                &guard,
                &fixture.directory,
                &mut receipt,
                &SetupCancellation::default(),
            )
            .unwrap();
        let saved = Receipt::load(&fixture.directory, &guard).unwrap();
        let binding = fixture.network.probe_binding(&guard, &saved, None).unwrap();
        assert_eq!(binding.ifindex().get(), 9);
        assert_eq!(binding.generation().as_str(), GENERATION);
        assert!(binding.allows("10.20.0.5".parse().unwrap()));
        assert!(!binding.allows("10.22.0.5".parse().unwrap()));
        fixture.kernel.lock().unwrap().ifalias = None;
        assert!(fixture.network.probe_binding(&guard, &saved, None).is_err());
        let writes = fixture.writes();
        assert!(
            fixture
                .network
                .clean(&guard, &fixture.directory, &saved)
                .is_err()
        );
        assert_eq!(fixture.writes(), writes);
        assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 2);
        {
            let mut kernel = fixture.kernel.lock().unwrap();
            kernel.ifindex += 1;
            kernel.ifalias = Some(saved.marker());
        }
        assert!(
            fixture
                .network
                .clean(&guard, &fixture.directory, &saved)
                .is_err()
        );
        assert_eq!(fixture.writes(), writes);
    }

    #[test]
    fn cleanup_removes_routes_and_dns_by_the_receipt_and_proves_their_absence() {
        let (fixture, receipt) = applied_fixture();
        let before = fixture.ops().len();
        fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &receipt)
            .unwrap();
        {
            let k = fixture.kernel.lock().unwrap();
            assert!(k.routes.is_empty());
            assert!(k.dns.is_empty() && k.domains.is_empty());
        }
        let after: Vec<_> = fixture.ops().split_off(before);
        // Last route first, then DNS, and no write beyond the receipt.
        let dels: Vec<_> = after
            .iter()
            .filter(|op| op.contains(" route del "))
            .collect();
        assert_eq!(dels.len(), 2);
        assert!(dels[0].contains("10.21.0.0/16") && dels[1].contains("10.20.0.0/16"));
        assert!(
            after
                .iter()
                .any(|op| op == &format!("{RESOLVECTL} revert {NAME}"))
        );
        // Repeating it converges and writes nothing more.
        let again = fixture.ops().len();
        fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &receipt)
            .unwrap();
        let repeated: Vec<_> = fixture.ops().split_off(again);
        assert!(
            repeated.iter().all(|op| !op.contains(" route del ")),
            "{repeated:?}"
        );
    }

    #[test]
    fn a_refused_delete_or_a_surviving_dns_is_an_error_not_a_pass() {
        let (fixture, receipt) = applied_fixture();
        fixture.kernel.lock().unwrap().refuse_delete = true;
        assert!(
            fixture
                .network
                .clean(&fixture.guard(), &fixture.directory, &receipt)
                .is_err()
        );
        fixture.kernel.lock().unwrap().refuse_delete = false;
        fixture.kernel.lock().unwrap().ignore_revert = true;
        let error = fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &receipt)
            .unwrap_err();
        assert!(error.to_string().contains("DNS remains"), "{error}");
    }

    #[test]
    fn a_link_that_vanished_took_its_routes_and_a_recycled_name_is_left_alone() {
        let (fixture, receipt) = applied_fixture();
        fixture.kernel.lock().unwrap().ppp = false;
        let before = fixture.ops().len();
        fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &receipt)
            .unwrap();
        assert!(
            fixture
                .ops()
                .split_off(before)
                .iter()
                .all(|op| !op.starts_with(RESOLVECTL) && !op.contains(" route del "))
        );

        // Same name, another identity: not ours, nothing is deleted or reverted.
        let (fixture, receipt) = applied_fixture();
        {
            let mut k = fixture.kernel.lock().unwrap();
            k.ifindex = 42;
        }
        let before = fixture.ops().len();
        fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &receipt)
            .unwrap();
        assert!(
            fixture
                .ops()
                .split_off(before)
                .iter()
                .all(|op| !op.starts_with(RESOLVECTL) && !op.contains(" route del "))
        );
        assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 2);
    }

    #[test]
    fn a_failed_second_route_leaves_a_receipt_that_covers_exactly_what_was_attempted() {
        let fixture = Fixture::new();
        let mut receipt = fixture.plan();
        up(&fixture);
        fixture.kernel.lock().unwrap().fail_add = Some(2);
        let entry = entry(&["10.20.0.0/15"], &[], &[]);
        let delivered = ready(&[("10.20.0.0", 16), ("10.21.0.0", 16)], &[]);
        assert!(apply(&fixture, &mut receipt, &delivered, &entry).is_err());
        let saved = Receipt::load(&fixture.directory, &fixture.guard()).unwrap();
        assert_eq!((saved.routes.len(), saved.routes_intended), (2, 2));
        assert_eq!(fixture.kernel.lock().unwrap().routes, ["10.20.0.0/16"]);
        fixture
            .network
            .clean(&fixture.guard(), &fixture.directory, &saved)
            .unwrap();
        assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    }

    #[test]
    fn a_receipt_of_another_generation_or_with_loose_modes_is_not_loaded() {
        let fixture = Fixture::new();
        fixture.plan();
        let other = fixture.root.0.join("fedcba9876543210fedcba9876543210");
        fs::create_dir(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(fixture.directory.join(RECEIPT), other.join(RECEIPT)).unwrap();
        assert!(Receipt::load(&other, &fixture.guard()).is_err());
        fs::set_permissions(
            fixture.directory.join(RECEIPT),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Receipt::load(&fixture.directory, &fixture.guard()).is_err());
    }

    #[test]
    fn what_the_instance_reports_decides_whether_the_attempt_can_go_on() {
        let base = || {
            let mut delivered = Delivered::default();
            delivered.absorb(Event::Interface { name: NAME.into() });
            delivered.absorb(Event::SplitRoutes { count: 0 });
            delivered.absorb(Event::DnsCount {
                servers: 0,
                domains: 0,
            });
            delivered
        };
        assert!(base().ready() && base().fatal().is_none());
        // Not ready until every part arrived.
        for missing in 0..3 {
            let mut delivered = Delivered::default();
            if missing != 0 {
                delivered.absorb(Event::Interface { name: NAME.into() });
            }
            if missing != 1 {
                delivered.absorb(Event::SplitRoutes { count: 0 });
            }
            if missing != 2 {
                delivered.absorb(Event::DnsCount {
                    servers: 0,
                    domains: 0,
                });
            }
            assert!(!delivered.ready(), "missing part {missing}");
        }
        let fatal = |event: Event| {
            let mut delivered = base();
            delivered.absorb(event);
            delivered.fatal()
        };
        assert_eq!(
            fatal(Event::InterfaceMismatch),
            Some(Fatal::InterfaceMismatch)
        );
        assert_eq!(
            fatal(Event::Failure {
                kind: Failure::CredentialsRejected
            }),
            Some(Fatal::Failure(Failure::CredentialsRejected))
        );
        assert_eq!(
            fatal(Event::Exited {
                code: Some(1),
                signal: None
            }),
            Some(Fatal::Exited)
        );
        assert_eq!(fatal(Event::SplitInvalid), Some(Fatal::Invalid));
        assert_eq!(fatal(Event::SplitRoutes { count: 0 }), Some(Fatal::Invalid));
        assert_eq!(
            fatal(Event::DnsCount {
                servers: 0,
                domains: 0
            }),
            None
        );
        // A count that disagrees with the routes seen.
        assert_eq!(
            fatal(Event::SplitRoute {
                network: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8
            }),
            Some(Fatal::Invalid)
        );
        // A mismatch is fatal even when everything else looks ready.
        let mut delivered = base();
        delivered.absorb(Event::InterfaceMismatch);
        assert!(delivered.ready() && delivered.fatal().is_some());
        // Invalid DNS alone completes the report without gateway DNS.
        let mut delivered = Delivered::default();
        delivered.absorb(Event::Interface { name: NAME.into() });
        delivered.absorb(Event::SplitRoutes { count: 0 });
        delivered.absorb(Event::DnsInvalid);
        assert!(delivered.ready());
    }
}
