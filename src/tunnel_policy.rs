//! Generate a validated, unprivileged proposal for tunneld policy apply.
use crate::{
    model::{Profile, VpnKind, valid_profile_id},
    storage::ProfileStore,
    tunneld::{
        policy::canonical_snapshot,
        protocol::{CidrV4, Endpoint},
    },
};
use serde_json::json;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    sync::mpsc,
    thread,
    time::Duration,
};

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(3);
const FORTINET_PRIVATE_ROUTE_CEILINGS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// Load the caller's saved profile and return one canonical authorization entry.
pub fn for_profile_id(id: &str, dns_servers: &[Ipv4Addr]) -> io::Result<Vec<u8>> {
    if !valid_profile_id(id) {
        return Err(invalid("invalid profile ID"));
    }
    let store = ProfileStore::for_current_user()
        .map_err(|_| io::Error::other("could not open profile store"))?;
    let profile = store
        .load()
        .map_err(|_| io::Error::other("could not read profiles"))?
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "profile ID not found"))?;
    // SAFETY: geteuid has no preconditions.
    snapshot(
        &profile,
        unsafe { libc::geteuid() },
        dns_servers,
        resolve_ipv4,
    )
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub(crate) fn certificate_pin(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("Fortinet requires a SHA-256 certificate pin"));
    }
    let mut pin = [0; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid SHA-256 certificate pin"))?;
    }
    Ok(pin)
}

fn snapshot(
    profile: &Profile,
    uid: u32,
    dns_servers: &[Ipv4Addr],
    resolve: impl FnOnce(&str, u16) -> io::Result<Vec<Ipv4Addr>>,
) -> io::Result<Vec<u8>> {
    profile.validate().map_err(invalid)?;
    let endpoint = Endpoint::new(profile.gateway.clone(), profile.port)
        .map_err(|_| invalid("invalid tunneld endpoint"))?;
    if uid == 0 || uid == u32::MAX {
        return Err(invalid("invalid policy UID"));
    }
    if dns_servers.len() > 4
        || dns_servers.iter().enumerate().any(|(index, &address)| {
            CidrV4::new(address, 32).is_err() || dns_servers[..index].contains(&address)
        })
    {
        return Err(invalid(
            "Provide up to four distinct unicast IPv4 DNS servers.",
        ));
    }
    let literal = endpoint.host().parse::<Ipv4Addr>().ok();
    let (backend, peer_identity) = match profile.kind {
        VpnKind::Ipsec => {
            if !profile.certificate.is_empty() {
                return Err(invalid("IPsec does not accept a certificate pin"));
            }
            let identity = match literal {
                Some(address) => format!("ipv4:{address}"),
                None => format!("fqdn:{}", endpoint.host()),
            };
            ("ipsec", identity)
        }
        VpnKind::Ssl => {
            certificate_pin(&profile.certificate)?;
            ("fortinet", endpoint.host().to_owned())
        }
        VpnKind::Ovpn => return Err(invalid("OpenVPN does not use the tunneld policy")),
    };
    let addresses = match literal {
        Some(ip) => vec![ip],
        None => resolve(endpoint.host(), endpoint.port()).map_err(|error| {
            let message = if error.kind() == io::ErrorKind::TimedOut {
                "Gateway IPv4 resolution timed out."
            } else {
                "Could not resolve gateway IPv4 addresses."
            };
            io::Error::new(error.kind(), message)
        })?,
    };
    let dns_servers = if profile.dns_domains.is_empty() {
        &[]
    } else {
        dns_servers
    };
    let mut entry = json!({
        "backend": backend,
        "uid": uid,
        "hostname": endpoint.host(),
        "peer_identity": peer_identity,
        "transport_ipv4": addresses,
        "port": endpoint.port(),
        "route_cidrs": profile.networks,
        "dns_domains": profile.dns_domains,
        "dns_servers": dns_servers
    });
    if profile.kind == VpnKind::Ssl {
        entry["certificate_sha256"] = json!(profile.certificate.to_ascii_lowercase());
        if profile.networks.is_empty() {
            entry["route_cidrs"] = json!(FORTINET_PRIVATE_ROUTE_CEILINGS);
        }
    }
    canonical_snapshot(&serde_json::to_vec(
        &json!({"version": 1, "entries": [entry]}),
    )?)
}

fn resolve_ipv4(host: &str, port: u16) -> io::Result<Vec<Ipv4Addr>> {
    let host = host.to_owned();
    let (send, receive) = mpsc::sync_channel(1);
    // libc resolution can block. Only the CLI caller waits on this channel,
    // and it returns with a deadline while the resolver owns its input.
    thread::Builder::new()
        .name("vpnt-tunnel-policy-dns".into())
        .spawn(move || {
            let result = (host.as_str(), port).to_socket_addrs().map(|addresses| {
                let mut ipv4: Vec<_> = addresses
                    .filter_map(|address| match address.ip() {
                        IpAddr::V4(ip) => Some(ip),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
                ipv4.sort_unstable();
                ipv4.dedup();
                ipv4
            });
            let _ = send.send(result);
        })?;
    match receive.recv_timeout(RESOLUTION_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other("resolver exited")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunneld::policy::canonical_snapshot;
    use serde_json::{Value, json};

    fn profile(kind: &str, certificate: &str) -> Profile {
        serde_json::from_value(json!({
            "id": "fixture-policy",
            "name": "Fixture policy",
            "kind": kind,
            "gateway": "vpn.example.test",
            "username": "fixture-username",
            "networks": ["10.20.0.0/24"],
            "port": if kind == "ipsec" {500} else {443},
            "certificate": certificate,
            "probeHost": "10.20.0.15",
            "probePort": 8443,
            "probeMethod": "tcp"
        }))
        .unwrap()
    }

    fn fixture_resolve(host: &str, port: u16) -> io::Result<Vec<Ipv4Addr>> {
        assert_eq!(host, "vpn.example.test");
        assert!(matches!(port, 500 | 443));
        Ok(vec![
            Ipv4Addr::new(192, 0, 2, 22),
            Ipv4Addr::new(192, 0, 2, 20),
        ])
    }

    #[test]
    fn snapshots_are_canonical_and_exclude_profile_metadata() {
        for (kind, pin, backend, identity) in [
            ("ipsec", String::new(), "ipsec", "fqdn:vpn.example.test"),
            ("ssl", "AB".repeat(32), "fortinet", "vpn.example.test"),
        ] {
            let bytes = snapshot(&profile(kind, &pin), 1000, &[], fixture_resolve).unwrap();
            assert_eq!(bytes, canonical_snapshot(&bytes).unwrap());
            assert!(bytes.ends_with(b"\n"));
            let doc: Value = serde_json::from_slice(&bytes).unwrap();
            let entry = &doc["entries"][0];
            assert_eq!(doc["version"], 1);
            assert_eq!(entry["backend"], backend);
            assert_eq!(entry["uid"], 1000);
            assert_eq!(entry["hostname"], "vpn.example.test");
            assert_eq!(entry["peer_identity"], identity);
            assert_eq!(entry["transport_ipv4"], json!(["192.0.2.20", "192.0.2.22"]));
            assert_eq!(entry["route_cidrs"], json!(["10.20.0.0/24"]));
            assert_eq!(entry["dns_domains"], json!([]));
            assert_eq!(entry["dns_servers"], json!([]));
            if kind == "ssl" {
                assert_eq!(entry["certificate_sha256"], pin.to_ascii_lowercase());
            } else {
                assert!(entry.get("certificate_sha256").is_none());
            }
            assert!(!String::from_utf8(bytes).unwrap().contains("fixture-"));
        }
    }

    #[test]
    fn validates_backend_pin_before_resolving() {
        for (kind, pin) in [("ipsec", "ab".repeat(32)), ("ssl", String::new())] {
            assert!(
                snapshot(&profile(kind, &pin), 1000, &[], |_, _| panic!(
                    "unexpected DNS"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn ssl_snapshot_uses_private_route_ceilings_for_gateway_dns() {
        let mut ssl = profile("ssl", &"AB".repeat(32));
        ssl.networks.clear();
        ssl.dns_domains = vec!["vpn.example.test".into()];
        let bytes = snapshot(&ssl, 1000, &[], fixture_resolve).unwrap();
        assert_eq!(bytes, canonical_snapshot(&bytes).unwrap());
        let data: Value = serde_json::from_slice(&bytes).unwrap();
        let entry = &data["entries"][0];
        assert_eq!(
            entry["route_cidrs"],
            json!(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
        );
        assert_eq!(entry["dns_domains"], json!(["vpn.example.test"]));
        assert_eq!(entry["dns_servers"], json!([]));

        ssl.networks = vec!["198.51.100.0/24".into()];
        let bytes = snapshot(&ssl, 1000, &[], fixture_resolve).unwrap();
        let data: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            data["entries"][0]["route_cidrs"],
            json!(["198.51.100.0/24"])
        );
    }

    #[test]
    fn ssl_snapshot_keeps_explicit_dns_servers_for_profiles_with_domains() {
        let mut ssl = profile("ssl", &"AB".repeat(32));
        ssl.gateway = "192.0.2.22".into();
        ssl.dns_domains = vec!["vpn.example.test".into()];
        let no_lookup = |_: &str, _: u16| panic!("unexpected DNS lookup");
        let dns_servers = [
            "198.51.100.53".parse().unwrap(),
            "192.0.2.53".parse().unwrap(),
        ];
        let bytes = snapshot(&ssl, 1000, &dns_servers, no_lookup).unwrap();
        assert_eq!(bytes, canonical_snapshot(&bytes).unwrap());
        let data: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            data["entries"][0]["dns_servers"],
            json!(["192.0.2.53", "198.51.100.53"])
        );
        assert_eq!(
            data["entries"][0]["dns_domains"],
            json!(["vpn.example.test"])
        );

        for servers in [
            vec![Ipv4Addr::LOCALHOST],
            vec![Ipv4Addr::UNSPECIFIED],
            vec!["224.0.0.1".parse().unwrap()],
            vec![dns_servers[0]; 2],
            (1..=5).map(|n| Ipv4Addr::new(192, 0, 2, n)).collect(),
        ] {
            assert!(snapshot(&ssl, 1000, &servers, no_lookup).is_err());
        }

        ssl.dns_domains.clear();
        let bytes = snapshot(&ssl, 1000, &dns_servers, no_lookup).unwrap();
        let data: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data["entries"][0]["dns_domains"], json!([]));
        assert_eq!(data["entries"][0]["dns_servers"], json!([]));
    }

    #[test]
    fn ipv4_ipsec_snapshot_uses_the_typed_literal_without_resolving() {
        let mut ipsec = profile("ipsec", "");
        ipsec.gateway = "192.0.2.10".into();
        let bytes = snapshot(&ipsec, 1000, &[], |_, _| {
            panic!("unexpected lookup for a literal")
        })
        .unwrap();
        assert_eq!(canonical_snapshot(&bytes).unwrap(), bytes);
        let data: Value = serde_json::from_slice(&bytes).unwrap();
        let entry = &data["entries"][0];
        assert_eq!(entry["backend"], "ipsec");
        assert_eq!(entry["hostname"], "192.0.2.10");
        assert_eq!(entry["peer_identity"], "ipv4:192.0.2.10");
        assert_eq!(entry["transport_ipv4"], json!(["192.0.2.10"]));
    }
}
