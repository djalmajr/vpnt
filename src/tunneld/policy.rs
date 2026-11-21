//! Version-one administrative tunnel grants and canonical snapshots.
use super::protocol::{self, CidrV4, Endpoint, Prepare};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::{fmt, io, net::Ipv4Addr, str::FromStr};

pub(super) const MAX_SNAPSHOT: usize = 16 * 1024;
pub(super) const MAX_POLICY: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum Backend {
    Ipsec,
    Fortinet,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Key {
    uid: u32,
    backend: Backend,
    hostname: String,
    port: u16,
}

impl Key {
    pub(super) fn from_args(
        uid: &str,
        backend: &str,
        hostname: &str,
        port: &str,
    ) -> io::Result<Self> {
        let backend = match backend {
            "ipsec" => Backend::Ipsec,
            "fortinet" => Backend::Fortinet,
            _ => return Err(invalid("invalid backend")),
        };
        let key = Self {
            uid: uid.parse().map_err(|_| invalid("invalid UID"))?,
            backend,
            hostname: hostname.to_owned(),
            port: port.parse().map_err(|_| invalid("invalid port"))?,
        };
        if key.uid.to_string() != uid || key.port.to_string() != port {
            return Err(invalid("UID and port must be canonical decimal numbers"));
        }
        key.validate()?;
        Ok(key)
    }

    fn validate(&self) -> io::Result<()> {
        if self.uid == 0 || self.uid == u32::MAX {
            return Err(invalid("invalid UID"));
        }
        if Endpoint::new(self.hostname.clone(), self.port).is_err() {
            return Err(invalid("invalid hostname or port"));
        }
        Ok(())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = match self.backend {
            Backend::Ipsec => "ipsec",
            Backend::Fortinet => "fortinet",
        };
        write!(
            output,
            "{} {backend} {} {}",
            self.uid, self.hostname, self.port
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    backend: Backend,
    uid: u32,
    hostname: String,
    peer_identity: String,
    transport_ipv4: Vec<Ipv4Addr>,
    port: u16,
    #[serde(
        default,
        deserialize_with = "present_pin",
        skip_serializing_if = "Option::is_none"
    )]
    certificate_sha256: Option<String>,
    route_cidrs: Vec<String>,
    dns_domains: Vec<String>,
    dns_servers: Vec<Ipv4Addr>,
}

fn present_pin<'de, D: Deserializer<'de>>(input: D) -> Result<Option<String>, D::Error> {
    String::deserialize(input).map(Some)
}

#[derive(Clone, Copy)]
struct Network {
    base: u32,
    prefix: u8,
}

impl Network {
    fn contains(self, other: Self) -> bool {
        self.prefix <= other.prefix && other.base & mask(self.prefix) == self.base
    }
}

impl FromStr for Network {
    type Err = io::Error;

    fn from_str(text: &str) -> io::Result<Self> {
        let error = || invalid("invalid route CIDR");
        let (host, prefix) = text.split_once('/').ok_or_else(error)?;
        let ip = host.parse::<Ipv4Addr>().map_err(|_| error())?;
        let bits = prefix.parse::<u8>().map_err(|_| error())?;
        let base = u32::from(ip);
        if !(8..=32).contains(&bits) || base & mask(bits) != base || format!("{ip}/{bits}") != text
        {
            return Err(error());
        }
        Ok(Self { base, prefix: bits })
    }
}

fn mask(prefix: u8) -> u32 {
    u32::MAX << (32 - prefix)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn sort_unique<T: Ord>(items: &mut [T], maximum: usize) -> io::Result<()> {
    if items.len() > maximum {
        return Err(invalid("too many items in policy list"));
    }
    items.sort_unstable();
    if items.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("duplicate item in policy list"));
    }
    Ok(())
}

fn validate_addresses(addresses: &mut [Ipv4Addr], maximum: usize) -> io::Result<()> {
    sort_unique(addresses, maximum)?;
    if addresses.iter().any(|&ip| CidrV4::new(ip, 32).is_err()) {
        return Err(invalid("invalid unicast IPv4 address"));
    }
    Ok(())
}

fn literal_ike_identity(identity: &str) -> bool {
    let Some((kind, text)) = identity.split_once(':') else {
        return false;
    };
    matches!(kind, "fqdn" | "email")
        && !text.is_empty()
        && !text.starts_with('#')
        && !(text.starts_with('^') && text.ends_with('$'))
        && !text.contains('*')
        && !text.chars().any(char::is_control)
}

impl Entry {
    pub(super) fn key(&self) -> Key {
        Key {
            uid: self.uid,
            backend: self.backend,
            hostname: self.hostname.clone(),
            port: self.port,
        }
    }

    fn canonicalize(&mut self) -> io::Result<()> {
        self.key().validate()?;
        match (self.backend, self.certificate_sha256.as_deref()) {
            (Backend::Ipsec, None)
                if self.dns_domains.is_empty()
                    && self.dns_servers.is_empty()
                    && literal_ike_identity(&self.peer_identity) => {}
            (Backend::Fortinet, Some(pin))
                if self.peer_identity == self.hostname
                    && pin.len() == 64
                    && pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
            _ => return Err(invalid("invalid backend identity, pin or DNS scope")),
        }
        validate_addresses(&mut self.transport_ipv4, 16)?;
        if self.transport_ipv4.is_empty() {
            return Err(invalid("missing transport IPv4"));
        }
        sort_unique(&mut self.route_cidrs, 256)?;
        let networks = self.networks().collect::<io::Result<Vec<_>>>()?;
        for (index, network) in networks.iter().enumerate() {
            if networks[..index]
                .iter()
                .any(|other| network.contains(*other) || other.contains(*network))
            {
                return Err(invalid("overlapping route CIDRs"));
            }
        }
        sort_unique(&mut self.dns_domains, 16)?;
        validate_addresses(&mut self.dns_servers, 4)?;
        if self.dns_domains.is_empty() != self.dns_servers.is_empty()
            || self.dns_domains.iter().any(|domain| {
                domain.parse::<Ipv4Addr>().is_ok() || Endpoint::new(domain.clone(), 1).is_err()
            })
        {
            return Err(invalid("invalid DNS scope"));
        }
        Ok(())
    }

    fn networks(&self) -> impl Iterator<Item = io::Result<Network>> + '_ {
        self.route_cidrs.iter().map(|cidr| cidr.parse())
    }

    fn permits(&self, uid: u32, offer: &Prepare) -> bool {
        let (backend, endpoint) = match offer {
            Prepare::Ipsec(offer) => (Backend::Ipsec, offer.endpoint()),
            Prepare::Fortinet(offer) => (Backend::Fortinet, offer.endpoint()),
        };
        if self.uid != uid
            || self.backend != backend
            || self.hostname != endpoint.host()
            || self.port != endpoint.port()
        {
            return false;
        }
        // The wire offer has no transport or peer identity of its own. They
        // belong to the exact grant returned by authorization.
        match offer {
            Prepare::Ipsec(offer) => offer.networks().iter().all(|route| {
                let route = Network {
                    base: u32::from(route.network()),
                    prefix: route.prefix(),
                };
                self.networks()
                    .flatten()
                    .any(|allowed| allowed.contains(route))
            }),
            Prepare::Fortinet(offer) => {
                use std::fmt::Write;
                let mut pin = String::with_capacity(64);
                for byte in offer.certificate_sha256() {
                    write!(pin, "{byte:02x}").expect("writing to a String cannot fail");
                }
                self.certificate_sha256.as_deref() == Some(pin.as_str())
            }
        }
    }
}

// Serde's struct visitor also accepts positional arrays by default. Require
// named objects at both levels while preserving duplicate field detection.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
struct Named<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Named<T> {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct Map<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Map<T> {
            type Value = Named<T>;

            fn expecting(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                output.write_str("an object with named fields")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Named)
            }
        }

        input.deserialize_map(Map(std::marker::PhantomData))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    version: u32,
    entries: Vec<Named<Entry>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: protocol::VERSION,
            entries: Vec::new(),
        }
    }
}

impl Policy {
    fn parse(bytes: &[u8], maximum: usize) -> io::Result<Self> {
        if bytes.len() > maximum {
            return Err(invalid("policy exceeds byte limit"));
        }
        let Named(mut policy) = serde_json::from_slice::<Named<Self>>(bytes)
            .map_err(|_| invalid("invalid policy document"))?;
        if policy.version != protocol::VERSION || policy.entries.len() > MAX_ENTRIES {
            return Err(invalid("unsupported policy version or too many entries"));
        }
        for entry in &mut policy.entries {
            entry.0.canonicalize()?;
        }
        policy.entries.sort_by_cached_key(|entry| entry.0.key());
        if policy
            .entries
            .windows(2)
            .any(|pair| pair[0].0.key() == pair[1].0.key())
        {
            return Err(invalid("duplicate policy key"));
        }
        Ok(policy)
    }

    pub(super) fn snapshot(bytes: &[u8]) -> io::Result<Entry> {
        let mut policy = Self::parse(bytes, MAX_SNAPSHOT)?;
        if policy.entries.len() != 1 || policy.bytes()?.len() > MAX_SNAPSHOT {
            return Err(invalid(
                "snapshot must contain one entry within the byte limit",
            ));
        }
        Ok(policy.entries.pop().expect("one snapshot entry").0)
    }

    pub(super) fn from_disk(bytes: &[u8]) -> io::Result<Self> {
        let policy = Self::parse(bytes, MAX_POLICY)?;
        if policy.bytes()? != bytes {
            return Err(invalid("policy is not in canonical form"));
        }
        Ok(policy)
    }

    pub(super) fn bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_POLICY {
            return Err(invalid("policy exceeds byte limit"));
        }
        Ok(bytes)
    }

    pub(super) fn apply(&mut self, grant: Entry) -> io::Result<()> {
        let key = grant.key();
        match self
            .entries
            .binary_search_by_key(&key, |entry| entry.0.key())
        {
            Ok(index) => self.entries[index] = Named(grant),
            Err(index) if self.entries.len() < MAX_ENTRIES => {
                self.entries.insert(index, Named(grant))
            }
            Err(_) => return Err(invalid("too many entries")),
        }
        Ok(())
    }

    pub(super) fn revoke(&mut self, key: &Key) -> io::Result<()> {
        let index = self
            .entries
            .binary_search_by_key(key, |entry| entry.0.key())
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "policy key not found"))?;
        self.entries.remove(index);
        Ok(())
    }

    pub(super) fn authorize(&self, uid: u32, offer: &Prepare) -> Option<&Entry> {
        self.entries
            .iter()
            .map(|entry| &entry.0)
            .find(|entry| entry.permits(uid, offer))
    }
}

/// Validate and serialize a single v1 authorization snapshot.
pub fn canonical_snapshot(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut policy = Policy::default();
    policy.apply(Policy::snapshot(bytes)?)?;
    policy.bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunneld::{admin::IPSEC_SNAPSHOT, protocol::FortinetRequest};
    use serde_json::{Value, json};

    fn ipsec() -> Value {
        serde_json::from_slice::<Value>(IPSEC_SNAPSHOT).unwrap()["entries"][0].clone()
    }

    fn fortinet() -> Value {
        let mut entry = ipsec();
        entry["backend"] = json!("fortinet");
        entry["port"] = json!(443);
        entry["peer_identity"] = entry["hostname"].clone();
        entry["certificate_sha256"] = json!("a".repeat(64));
        entry["dns_domains"] = json!(["internal.example"]);
        entry["dns_servers"] = json!(["10.20.0.53"]);
        entry
    }

    fn document(entries: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec(&json!({"version":1,"entries":entries})).unwrap()
    }

    fn snapshot(entry: Value) -> io::Result<Vec<u8>> {
        canonical_snapshot(&document(vec![entry]))
    }

    #[test]
    fn validates_every_snapshot_field_and_required_shape() {
        let control = ipsec();
        assert!(snapshot(control.clone()).is_ok());
        for (field, value) in [
            ("backend", json!("other")),
            ("uid", json!(0)),
            ("uid", json!(4294967295_u32)),
            ("uid", json!("1000")),
            ("hostname", json!("VPN.example")),
            ("hostname", json!("vpn.example.")),
            ("hostname", json!("192.0.02.20")),
            ("hostname", json!("a".repeat(64))),
            ("hostname", json!(vec!["a".repeat(63); 4].join("."))),
            ("peer_identity", json!("fqdn:*")),
            ("peer_identity", json!("fqdn:#123")),
            ("peer_identity", json!("fqdn:^example$")),
            ("peer_identity", json!("fqdn:broken\nidentity")),
            ("peer_identity", json!("vpn.example")),
            ("transport_ipv4", json!([])),
            ("transport_ipv4", json!(["192.0.02.20"])),
            ("transport_ipv4", json!(["224.0.0.1"])),
            ("transport_ipv4", json!(["192.0.2.20", "192.0.2.20"])),
            ("transport_ipv4", json!(vec!["192.0.2.20"; 17])),
            ("port", json!(0)),
            ("port", json!(65536)),
            ("certificate_sha256", json!("a".repeat(64))),
            ("certificate_sha256", Value::Null),
            ("route_cidrs", json!(["10.20.0.0/07"])),
            ("route_cidrs", json!(["10.20.0.1/24"])),
            ("route_cidrs", json!(["10.20.0.0/33"])),
            ("route_cidrs", json!(["10.20.0.0/16", "10.20.16.0/24"])),
            ("route_cidrs", json!(["10.20.0.0/16", "10.20.0.0/16"])),
            ("route_cidrs", json!(vec!["10.20.0.0/16"; 257])),
            ("dns_domains", json!(["internal.example"])),
            ("dns_servers", json!(["10.20.0.53"])),
            ("unrecognized", json!(true)),
        ] {
            let mut entry = control.clone();
            entry[field] = value.clone();
            assert!(snapshot(entry).is_err(), "{field} accepted {value}");
        }
        for field in control.as_object().unwrap().keys() {
            let mut entry = control.clone();
            entry.as_object_mut().unwrap().remove(field);
            assert!(snapshot(entry).is_err(), "missing {field}");
        }
        for shape in [
            br#"{"version":2,"entries":[]}"#.as_slice(),
            br#"{"version":1,"version":1,"entries":[]}"#,
            br#"{"version":1,"entries":[],"unknown":false}"#,
            br#"[1,[]]"#,
            br#"{"version":1,"entries":[["ipsec",1000,"vpn.example","fqdn:vpn.example",["192.0.2.20"],500,null,[],[],[]]]}"#,
        ] {
            assert!(Policy::parse(shape, MAX_POLICY).is_err(), "{shape:?}");
        }
        let duplicate = String::from_utf8(IPSEC_SNAPSHOT.to_vec())
            .unwrap()
            .replace("\"uid\":1000", "\"uid\":1000,\"uid\":1000");
        assert!(canonical_snapshot(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn backend_pin_identity_and_dns_are_bound_to_fortinet() {
        let control = fortinet();
        assert!(snapshot(control.clone()).is_ok());
        let mut no_dns = control.clone();
        no_dns["dns_domains"] = json!([]);
        no_dns["dns_servers"] = json!([]);
        assert!(snapshot(no_dns).is_ok());
        let mut no_pin = control.clone();
        no_pin.as_object_mut().unwrap().remove("certificate_sha256");
        assert!(snapshot(no_pin).is_err());
        for (field, value) in [
            ("peer_identity", json!("other.example")),
            ("certificate_sha256", json!("A".repeat(64))),
            ("certificate_sha256", json!("a".repeat(63))),
            ("certificate_sha256", Value::Null),
            ("dns_domains", json!([])),
            ("dns_domains", json!(["Internal.example"])),
            ("dns_domains", json!(["internal.example."])),
            (
                "dns_domains",
                json!(["internal.example", "internal.example"]),
            ),
            ("dns_domains", json!(vec!["internal.example"; 17])),
            ("dns_servers", json!([])),
            ("dns_servers", json!(["10.20.0.53", "10.20.0.53"])),
            ("dns_servers", json!(["255.255.255.255"])),
            ("dns_servers", json!(vec!["10.20.0.53"; 5])),
        ] {
            let mut entry = control.clone();
            entry[field] = value.clone();
            assert!(snapshot(entry).is_err(), "{field} accepted {value}");
        }
        let mut ipsec_dns = ipsec();
        ipsec_dns["dns_servers"] = json!(["10.20.0.53"]);
        ipsec_dns["dns_domains"] = json!(["internal.example"]);
        assert!(snapshot(ipsec_dns).is_err());
    }

    #[test]
    fn canonical_order_and_final_lf_are_stable() {
        let bytes = canonical_snapshot(IPSEC_SNAPSHOT).unwrap();
        assert_eq!(
            bytes,
            concat!(
                r#"{"version":1,"entries":[{"backend":"ipsec","uid":1000,"hostname":"vpn.example","peer_identity":"fqdn:vpn.example","transport_ipv4":["192.0.2.20","192.0.2.22"],"port":500,"route_cidrs":["10.20.0.0/15","172.16.0.0/12"],"dns_domains":[],"dns_servers":[]}]}"#,
                "\n"
            ).as_bytes()
        );
        assert_eq!(canonical_snapshot(&bytes).unwrap(), bytes);
        assert_eq!(Policy::from_disk(&bytes).unwrap().bytes().unwrap(), bytes);
        assert!(Policy::from_disk(IPSEC_SNAPSHOT).is_err());

        let input = document(vec![fortinet(), ipsec()]);
        let reversed = document(vec![ipsec(), fortinet()]);
        let first = Policy::parse(&input, MAX_POLICY).unwrap().bytes().unwrap();
        let second = Policy::parse(&reversed, MAX_POLICY)
            .unwrap()
            .bytes()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            serde_json::from_slice::<Value>(&first).unwrap()["entries"][0]["backend"],
            "ipsec"
        );
    }

    #[test]
    fn enforces_byte_and_entry_limits_and_whole_document_key_uniqueness() {
        assert!(canonical_snapshot(&document(vec![])).is_err());
        assert!(canonical_snapshot(&document(vec![ipsec(), fortinet()])).is_err());
        for limit in [MAX_SNAPSHOT, MAX_POLICY] {
            let mut input = document(vec![ipsec()]);
            input.resize(limit, b' ');
            assert!(Policy::parse(&input, limit).is_ok());
            input.push(b' ');
            assert!(Policy::parse(&input, limit).is_err());
        }

        let mut entries: Vec<_> = (1..=256)
            .map(|uid| {
                let mut entry = ipsec();
                entry["uid"] = json!(uid);
                entry
            })
            .collect();
        assert!(Policy::parse(&document(entries.clone()), MAX_POLICY).is_ok());
        let mut overflow = ipsec();
        overflow["uid"] = json!(257);
        entries.push(overflow);
        assert!(Policy::parse(&document(entries), MAX_POLICY).is_err());
        assert!(Policy::parse(&document(vec![ipsec(), ipsec()]), MAX_POLICY).is_err());
        let mut conflict = ipsec();
        conflict["route_cidrs"] = json!([]);
        assert!(Policy::parse(&document(vec![ipsec(), conflict]), MAX_POLICY).is_err());
    }

    #[test]
    fn authorizes_fortinet_only_for_the_exact_backend_uid_endpoint_and_pin() {
        let policy = Policy::parse(&document(vec![fortinet()]), MAX_POLICY).unwrap();
        let offer = |host: &str, port, pin| {
            Prepare::Fortinet(
                FortinetRequest::new(
                    Endpoint::new(host.into(), port).unwrap(),
                    "fixture".into(),
                    [pin; 32],
                )
                .unwrap(),
            )
        };
        let allowed = offer("vpn.example", 443, 0xaa);
        assert!(policy.authorize(1000, &allowed).is_some());
        assert!(policy.authorize(1001, &allowed).is_none());
        assert!(
            policy
                .authorize(1000, &offer("other.example", 443, 0xaa))
                .is_none()
        );
        assert!(
            policy
                .authorize(1000, &offer("vpn.example", 444, 0xaa))
                .is_none()
        );
        assert!(
            policy
                .authorize(1000, &offer("vpn.example", 443, 0xab))
                .is_none()
        );
        assert!(
            Policy::parse(&document(vec![ipsec()]), MAX_POLICY)
                .unwrap()
                .authorize(1000, &allowed)
                .is_none()
        );
    }
}
