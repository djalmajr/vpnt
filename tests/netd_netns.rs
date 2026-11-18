#![cfg(target_os = "linux")]
//! Kernel integration isolated in a new user/network namespace; never touches host links.
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command, time::Duration};
use vpnt::netd::{
    iproute::{Backend, IpRoute},
    protocol::{Config, Request, TunName, parse_request},
};

struct Fixture {
    root: PathBuf,
    backend: IpRoute,
    name: TunName,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.backend.delete_tun(&self.name);
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn ip(args: &[&str]) -> serde_json::Value {
    let output = Command::new("/usr/bin/ip")
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(output.status.success(), "ip {args:?}: {:?}", output.status);
    serde_json::from_slice(&output.stdout).unwrap()
}
fn config(address: &str, routes: serde_json::Value, domains: serde_json::Value) -> Config {
    let wire = serde_json::json!({"op":"configure","ifname":"vpnt0","address":address,"prefix":24,
        "routes":routes,"dns":{"servers":["10.200.0.1"],"domains":domains}});
    let Request::Configure(c) = parse_request(format!("{wire}\n").as_bytes()).unwrap() else {
        panic!()
    };
    c.validate().unwrap()
}
#[test]
fn isolated_network_replacement_and_cleanup() {
    if std::env::var("VPNT_TEST_NETNS").as_deref() != Ok("1") {
        eprintln!("skipped: set VPNT_TEST_NETNS=1 to run the isolated kernel fixture");
        return;
    }
    if std::env::var("VPNT_TEST_NETNS_CHILD").as_deref() != Ok("1") {
        let status = Command::new("/usr/bin/unshare")
            .args(["-r", "-n"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "isolated_network_replacement_and_cleanup",
                "--nocapture",
            ])
            .env("VPNT_TEST_NETNS_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success(), "unshare fixture failed: {status}");
        return;
    }
    // Refuse to operate if invoked with the marker outside a user namespace.
    let mapping = fs::read_to_string("/proc/self/uid_map").unwrap();
    let fields: Vec<_> = mapping.split_whitespace().collect();
    assert_eq!(fields.len(), 3, "expected a single mapped uid");
    assert_eq!(fields[0], "0");
    assert_eq!(fields[2], "1");
    // An entirely empty namespace has no main IPv4 FIB table: ip route flush
    // returns status 2 there. Model an ordinary host with a connected lo route.
    for args in [
        vec!["link", "set", "lo", "up"],
        vec!["addr", "add", "192.0.2.1/24", "dev", "lo"],
    ] {
        assert!(
            Command::new("/usr/bin/ip")
                .args(args)
                .env_clear()
                .env("LC_ALL", "C")
                .status()
                .unwrap()
                .success()
        );
    }
    let root = std::env::temp_dir().join(format!("vpnt-netd-netns-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fake = root.join("resolvectl");
    let log = root.join("dns.log");
    fs::write(
        &fake,
        format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n", log.display()),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = Fixture {
        root,
        backend: IpRoute::with_paths("/usr/bin/ip".into(), fake, Duration::from_secs(5)),
        name: TunName::parse("vpnt0").unwrap(),
    };
    fixture.backend.create_tun(&fixture.name, 0).unwrap();
    let first = config(
        "10.9.0.2",
        serde_json::json!([{"network":"10.20.0.0","prefix":16},{"network":"172.16.0.0","prefix":12}]),
        serde_json::json!(["serpro"]),
    );
    fixture.backend.configure(&first).unwrap();
    let routes = ip(&["-j", "route", "show", "dev", "vpnt0"]);
    for network in ["10.20.0.0/16", "172.16.0.0/12"] {
        assert!(
            routes
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["dst"] == network),
            "missing {network}: {routes}"
        );
    }
    let second = config(
        "10.10.0.2",
        serde_json::json!([{"network":"192.168.40.0","prefix":24}]),
        serde_json::json!([]),
    );
    fixture.backend.configure(&second).unwrap();
    let routes = ip(&["-j", "route", "show", "dev", "vpnt0"]);
    let destinations: Vec<_> = routes
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["dst"].as_str())
        .collect();
    assert!(destinations.contains(&"192.168.40.0/24"), "{routes}");
    for old in ["10.20.0.0/16", "172.16.0.0/12", "10.9.0.0/24"] {
        assert!(!destinations.contains(&old), "old route remains: {routes}");
    }
    let addresses = ip(&["-j", "addr", "show", "dev", "vpnt0"]);
    let addresses = addresses[0]["addr_info"].as_array().unwrap();
    assert!(addresses.iter().any(|a| a["local"] == "10.10.0.2"));
    assert!(!addresses.iter().any(|a| a["local"] == "10.9.0.2"));
    assert!(fixture.backend.existing().unwrap().contains(&fixture.name));
    fixture.backend.delete_tun(&fixture.name).unwrap();
    assert!(!fixture.backend.existing().unwrap().contains(&fixture.name));
    assert!(
        !ip(&["-j", "link", "show"])
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["ifname"] == "vpnt0")
    );
    assert!(
        !ip(&["-j", "route", "show", "table", "all"])
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["dev"] == "vpnt0")
    );
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        "revert vpnt0\ndns vpnt0 10.200.0.1\ndomain vpnt0 ~serpro\ndefault-route vpnt0 false\nrevert vpnt0\ndns vpnt0 10.200.0.1\ndefault-route vpnt0 true\nrevert vpnt0\n"
    );
}
