use super::*;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
mod invalid;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vpnt-pfkey-sdk-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let result = Command::new("/usr/bin/xcrun")
            .args(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ipsec/pfkey.c"))
            .arg("-o")
            .arg(path.join("fixture"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "SDK fixture compile: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        Self(path)
    }
    fn bytes(&self, mode: &str) -> Vec<u8> {
        let r = Command::new(self.0.join("fixture"))
            .arg(mode)
            .output()
            .unwrap();
        assert!(r.status.success(), "SDK fixture execution failed");
        r.stdout
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Mutations: interpret SPI as native or reqid as 16-bit, or reject the kernel
// refcount stored in reserved. The independent producer uses SDK structures.
#[test]
fn sdk_sa_records_preserve_mixed_endianness_lifetimes_and_scoped_ipv6_without_key_payloads() {
    let f = Fixture::new();
    let abi: serde_json::Value = serde_json::from_slice(&f.bytes("abi")).unwrap();
    for (key, value) in [
        ("header", 16),
        ("sa", 16),
        ("sa2", 16),
        ("address", 8),
        ("policy", 16),
        ("request", 8),
        ("lifetime", 32),
        ("reqid", 12),
        ("requestReqid", 6),
        ("v4", 16),
        ("v6", 28),
    ] {
        assert_eq!(abi[key], value, "SDK field: {key}");
    }
    for mode in ["sa4", "sa6", "sa6-scoped"] {
        let p = decode(&f.bytes(mode)).expect("SDK SA frame");
        assert_eq!((p.kind, p.sequence, p.pid), (Kind::Sad, 7, 4242));
        let Entry::Sa(s) = p.entry else {
            panic!("SA expected")
        };
        assert_eq!(
            (s.spi, s.reqid, s.replay_sequence),
            (0x1234abcd, 0x10001, 0x33221199)
        );
        assert_eq!(
            (s.protocol, s.state, s.mode, s.flags, s.natt_port),
            (3, 1, 2, 0, None)
        );
        assert_eq!((s.source.port, s.destination.port), (4501, 4500));
        assert_eq!(
            s.lifetime,
            Some(Lifetime {
                allocations: 0x40302010,
                bytes: 0x0102030405060708,
                added: 42,
                used: 84
            })
        );
        let expected = match mode {
            "sa4" => "192.0.2.10",
            "sa6" => "2001:db8::1",
            _ => "fe80::1",
        };
        assert_eq!(
            s.source.address.ip,
            expected.parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            s.source.address.zone,
            if mode == "sa6-scoped" { 7 } else { 0 }
        );
        assert!(s.extra_extensions.is_empty());
        assert!(!format!("{s:?}").contains("fake-sa-key-0001"));
    }
}

// Mutations: read request lengths as 64-bit units, lose a chained reqid or
// range bound, or treat kernel errno as an empty successful observation.
#[test]
fn sdk_policies_preserve_requests_selectors_ranges_and_explicit_errors() {
    let f = Fixture::new();
    for mode in [
        "spd4",
        "spd6",
        "range",
        "transport",
        "wildcard",
        "multi",
        "none",
    ] {
        let p = decode(&f.bytes(mode)).expect("SDK SPD frame");
        assert_eq!((p.kind, p.sequence, p.pid), (Kind::Spd, 7, 4242));
        let Entry::Policy(p) = p.entry else {
            panic!("policy expected")
        };
        assert_eq!((p.id, p.direction), (0x10203040, 2));
        assert_eq!((p.source.start.port, p.destination.start.port), (8443, 443));
        assert_eq!(p.source.protocol, 6);
        assert_eq!(p.kind, if mode == "none" { 1 } else { 2 });
        let source = if mode == "spd6" {
            "2001:db8:20::/64"
        } else {
            "10.20.0.0/24"
        };
        let destination = if mode == "spd6" {
            "2001:db8:30::/64"
        } else {
            "10.30.0.0/24"
        };
        assert_eq!(p.source.network().unwrap(), source.parse().unwrap());
        assert_eq!(
            p.destination.network().unwrap(),
            destination.parse().unwrap()
        );
        assert_eq!(p.source.prefix, if mode == "spd6" { 64 } else { 24 });
        assert_eq!(p.source.end.is_some(), mode == "range");
        if let Some(end) = p.source.end {
            assert_eq!(end.port, 8444);
            assert_eq!(
                end.address.ip,
                "10.20.0.99".parse::<std::net::IpAddr>().unwrap()
            );
        }
        assert_eq!(
            p.requests.len(),
            if mode == "none" {
                0
            } else if mode == "multi" {
                2
            } else {
                1
            }
        );
        if let Some(r) = p.requests.first() {
            assert_eq!((r.protocol, r.reqid, r.level), (50, 0x3fff, 3));
            assert_eq!(r.mode, if mode == "transport" { 1 } else { 2 });
            assert_eq!(
                r.endpoints.is_some(),
                !matches!(mode, "transport" | "wildcard")
            );
            if let Some((a, b)) = r.endpoints {
                let (local, remote) = if mode == "spd6" {
                    ("2001:db8::1", "2001:db8::2")
                } else {
                    ("192.0.2.10", "198.51.100.20")
                };
                assert_eq!(a.address.ip, local.parse::<std::net::IpAddr>().unwrap());
                assert_eq!(b.address.ip, remote.parse::<std::net::IpAddr>().unwrap());
                assert_eq!((a.port, b.port), (0, 0));
            }
        }
        if mode == "multi" {
            assert_eq!(p.requests[1].reqid, 0x4001);
            assert_eq!(p.requests[1].protocol, 51);
        }
    }
    assert_eq!(
        decode(&f.bytes("error")).unwrap().entry,
        Entry::KernelError(libc::ENOENT as u8)
    );
}
