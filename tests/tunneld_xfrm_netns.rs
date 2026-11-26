#![cfg(target_os = "linux")]
//! Exercises the writer against real iproute2 in a private user and network namespace.
use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::PathBuf,
    process::{Command, Output},
    time::{Duration, Instant},
};

// Compile the same writer without exposing runtime internals as public APIs.
#[allow(dead_code)]
#[path = "../src/netlease.rs"]
mod netlease;
#[allow(dead_code)]
#[path = "../src/tunneld/network.rs"]
mod network;
#[allow(dead_code)]
mod protocol {
    use std::net::Ipv4Addr;

    pub use vpnt::tunneld::protocol::CidrV4;

    // The probe types are crate-private in the library; the writer test only
    // needs them to carry the observed scope, so it keeps minimal stand-ins.
    pub struct Generation(String);

    impl Generation {
        pub fn parse(text: String) -> Option<Self> {
            (!text.is_empty()).then_some(Self(text))
        }
    }

    pub struct ProbeBinding {
        pub generation: Generation,
        pub ifindex: u32,
        pub local: Ipv4Addr,
        pub routes: Vec<CidrV4>,
    }

    impl ProbeBinding {
        pub fn new(
            generation: Generation,
            ifindex: u32,
            local: Ipv4Addr,
            routes: Vec<CidrV4>,
        ) -> Option<Self> {
            Some(Self {
                generation,
                ifindex,
                local,
                routes,
            })
        }
    }
}

const OPT_IN: &str = "VPNT_TEST_NETNS";
const PARENT_NS: &str = "VPNT_XFRM_PARENT_NETNS";

fn netns() -> String {
    let status = fs::metadata("/proc/self/ns/net").unwrap();
    format!("{}:{}", status.dev(), status.ino())
}

fn ip(args: &[&str]) -> Output {
    let output = Command::new("/usr/bin/ip")
        .args(args)
        .env_clear()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn isolated_xfrm_writer_creates_and_removes_kernel_objects() {
    if std::env::var(OPT_IN).as_deref() != Ok("1") {
        eprintln!("set {OPT_IN}=1 to exercise the XFRM writer in a private netns");
        return;
    }
    let Ok(parent_ns) = std::env::var(PARENT_NS) else {
        let result = Command::new("/usr/bin/unshare")
            .args(["-Urn", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "isolated_xfrm_writer_creates_and_removes_kernel_objects",
                "--nocapture",
            ])
            .env_clear()
            .env(OPT_IN, "1")
            .env(PARENT_NS, netns())
            .env("TMPDIR", std::env::temp_dir())
            .status()
            .unwrap();
        assert!(result.success(), "namespace fixture: {result}");
        return;
    };
    assert_ne!(netns(), parent_ns, "must run in a new network namespace");
    let mapping = fs::read_to_string("/proc/self/uid_map").unwrap();
    let mapping: Vec<_> = mapping.split_whitespace().collect();
    assert!(matches!(mapping.as_slice(), ["0", _, "1"]), "{mapping:?}");

    ip(&["link", "add", "dummy0", "type", "dummy"]);
    ip(&["link", "set", "dev", "dummy0", "up"]);
    ip(&["addr", "add", "192.0.2.2/24", "dev", "dummy0"]);

    let root = std::env::temp_dir().join(format!("vpnt-xfrm-netns-{}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    let root = Temp(root);
    let guard =
        netlease::NetworkLock::acquire_test(&root.0, Instant::now() + Duration::from_secs(1))
            .unwrap();
    let generation = "0123456789abcdef0123456789abcdef";
    let directory = root.0.join(generation);
    DirBuilder::new().mode(0o700).create(&directory).unwrap();
    let backend = network::Network::default();
    let remote = "192.0.2.1".parse().unwrap();
    let vip = "10.99.0.2".parse().unwrap();
    let routes = ["10.20.0.0/15", "172.16.0.0/12"]
        .into_iter()
        .map(network::parse_cidr)
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    let mut receipt = backend
        .plan(&guard, generation, remote, &[remote], routes)
        .unwrap();
    guard.register(generation).unwrap();
    receipt.save(&directory, &guard).unwrap();
    backend
        .install(&guard, &directory, &mut receipt, vip, &[remote])
        .unwrap();

    let routes = ip(&[
        "-4", "-j", "-d", "route", "show", "table", "main", "dev", "vpnti1",
    ]);
    let rows: serde_json::Value = serde_json::from_slice(&routes.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r["protocol"] == "boot")
    );

    // This fixture has no charon. Seed the SAD and SPD entries a dead producer
    // would leave, alongside foreign objects with both distinct and reused IDs.
    for (src, dst, spi, reqid, id) in [
        ("192.0.2.1", "192.0.2.2", "0x126", "1", "1"),
        ("192.0.2.2", "192.0.2.1", "0x127", "1", "1"),
        ("192.0.2.1", "192.0.2.2", "0x129", "2", "2"),
        ("192.0.2.77", "192.0.2.2", "0x12a", "1", "1"),
    ] {
        ip(&[
            "xfrm",
            "state",
            "add",
            "src",
            src,
            "dst",
            dst,
            "proto",
            "esp",
            "spi",
            spi,
            "reqid",
            reqid,
            "if_id",
            id,
            "mode",
            "tunnel",
            "aead",
            "rfc4106(gcm(aes))",
            "0x0123456789abcdef0123456789abcdef01234567",
            "128",
        ]);
    }
    let states = ip(&["xfrm", "state", "list", "nokeys"]);
    let states = String::from_utf8(states.stdout).unwrap();
    for spi in ["0x00000126", "0x00000127", "0x00000129", "0x0000012a"] {
        assert!(states.contains(spi), "{states}");
    }

    for (direction, id, route, remote) in [
        ("out", "1", "10.20.0.0/15", "192.0.2.1"),
        ("in", "1", "10.20.0.0/15", "192.0.2.1"),
        ("fwd", "1", "10.20.0.0/15", "192.0.2.1"),
        ("out", "2", "10.20.0.0/15", "192.0.2.1"),
        ("out", "1", "172.16.0.0/12", "192.0.2.77"),
        ("out", "1", "10.50.0.0/16", "192.0.2.1"),
    ] {
        let (src, dst, outer_src, outer_dst) = if direction == "out" {
            ("10.99.0.2/32", route, "192.0.2.2", remote)
        } else {
            (route, "10.99.0.2/32", remote, "192.0.2.2")
        };
        ip(&[
            "xfrm", "policy", "add", "src", src, "dst", dst, "dir", direction, "if_id", id, "tmpl",
            "src", outer_src, "dst", outer_dst, "proto", "esp", "mode", "tunnel",
        ]);
    }
    let receipt = network::Receipt::load(&directory, &guard).unwrap();
    assert!(backend.verify_xfrm_clear(&receipt).is_err());
    assert!(backend.clean(&guard, &directory, &receipt).is_err());
    assert!(guard.tunnels_present().unwrap());

    let states = ip(&["xfrm", "state", "list", "nokeys"]);
    let states = String::from_utf8(states.stdout).unwrap();
    for spi in ["0x00000129", "0x0000012a"] {
        assert!(states.contains(spi), "{states}");
    }
    for spi in ["0x00000126", "0x00000127"] {
        assert!(!states.contains(spi), "{states}");
    }

    let policies = ip(&["xfrm", "policy", "list"]);
    let policies = String::from_utf8(policies.stdout).unwrap();
    assert_eq!(policies.matches("if_id 0x2").count(), 1, "{policies}");
    assert_eq!(policies.matches("if_id 0x1").count(), 2, "{policies}");
    assert!(policies.contains("172.16.0.0/12"), "{policies}");
    assert!(policies.contains("10.50.0.0/16"), "{policies}");
    assert!(policies.contains("192.0.2.77"), "{policies}");

    ip(&[
        "xfrm",
        "state",
        "delete",
        "dst",
        "192.0.2.2",
        "proto",
        "esp",
        "spi",
        "0x12a",
    ]);
    for route in ["172.16.0.0/12", "10.50.0.0/16"] {
        ip(&[
            "xfrm",
            "policy",
            "delete",
            "src",
            "10.99.0.2/32",
            "dst",
            route,
            "dir",
            "out",
            "if_id",
            "1",
        ]);
    }
    backend.clean(&guard, &directory, &receipt).unwrap();
    backend.verify_xfrm_clear(&receipt).unwrap();
    guard.withdraw(generation).unwrap();
    assert!(!guard.tunnels_present().unwrap());

    let links = ip(&["-j", "link", "show"]);
    let links: serde_json::Value = serde_json::from_slice(&links.stdout).unwrap();
    assert!(
        links
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["ifname"] == "dummy0")
    );
    assert!(
        links
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l["ifname"] != "vpnti1")
    );
}
