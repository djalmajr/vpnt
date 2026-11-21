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
mod protocol {
    pub use vpnt::tunneld::protocol::CidrV4;
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
    let receipt = network::Receipt::load(&directory, &guard).unwrap();
    backend.clean(&guard, &directory, &receipt).unwrap();
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
