use super::*;
use crate::netd::protocol::{Request, parse_request};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};

fn config(servers: &str, domains: &str) -> Config {
    let wire = format!(
        r#"{{"op":"configure","ifname":"vpnt0","address":"10.9.0.2","prefix":24,"mtu":1400,"routes":[{{"network":"10.0.0.0","prefix":8}},{{"network":"172.16.0.0","prefix":12}}],"dns":{{"servers":{servers},"domains":{domains}}}}}"#
    );
    let Request::Configure(c) = parse_request(format!("{wire}\n").as_bytes()).unwrap() else {
        panic!()
    };
    c.validate().unwrap()
}
#[test]
fn exact_argv_and_dns_branches() {
    let name = TunName::parse("vpnt0").unwrap();
    assert_eq!(
        create_args(&name, 1234),
        [
            "tuntap", "add", "dev", "vpnt0", "mode", "tun", "user", "1234"
        ]
    );
    assert_eq!(delete_args(&name), ["link", "del", "dev", "vpnt0"]);
    assert_eq!(existing_args(), ["-j", "link", "show"]);
    let c = config(r#"["10.200.0.1","1.1.1.1"]"#, r#"["serpro","example.org"]"#);
    let commands = configure_commands(&c);
    let actual: Vec<_> = commands
        .iter()
        .map(|c| (c.dns, c.args.iter().map(String::as_str).collect::<Vec<_>>()))
        .collect();
    assert_eq!(
        actual,
        vec![
            (false, vec!["addr", "flush", "dev", "vpnt0"]),
            (false, vec!["route", "flush", "dev", "vpnt0"]),
            (
                false,
                vec!["link", "set", "dev", "vpnt0", "mtu", "1400", "up"]
            ),
            (false, vec!["addr", "add", "10.9.0.2/24", "dev", "vpnt0"]),
            (
                false,
                vec!["route", "replace", "10.0.0.0/8", "dev", "vpnt0"]
            ),
            (
                false,
                vec!["route", "replace", "172.16.0.0/12", "dev", "vpnt0"]
            ),
            (true, vec!["dns", "vpnt0", "10.200.0.1", "1.1.1.1"]),
            (true, vec!["domain", "vpnt0", "~serpro", "~example.org"]),
            (true, vec!["default-route", "vpnt0", "false"]),
        ]
    );
    let commands = configure_commands(&config(r#"["1.1.1.1"]"#, "[]"));
    assert_eq!(
        commands.last().unwrap().args,
        ["default-route", "vpnt0", "true"]
    );
    let commands = configure_commands(&config("[]", "[]"));
    assert_eq!(commands.len(), 7);
    assert!(commands.last().unwrap().dns);
    assert_eq!(commands.last().unwrap().args, ["revert", "vpnt0"]);
}
#[test]
fn existing_filters_names_and_rejects_malformed_output() {
    let names=parse_existing(r#"[{"ifname":"vpnt0"},{"ifname":"eth0"},{"ifname":"vpnt99"},{"ifname":"vpnt00"},{"ifname":"vpnt123"},{"ifname":"vpnt١"}]"#.as_bytes()).unwrap();
    assert_eq!(
        names.iter().map(TunName::as_str).collect::<Vec<_>>(),
        ["vpnt0", "vpnt99"]
    );
    for bytes in [
        b"{}".as_slice(),
        b"garbage",
        b"[{}]",
        b"[{\"ifname\":3}]",
        b"[{\"ifname\":\"vpnt0\"},{}]",
    ] {
        assert!(parse_existing(bytes).is_err());
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vpnt-netd-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn execution_stops_on_failure_and_delete_ignores_dns_failure() {
    let f = Fixture::new();
    let log = f.0.join("argv");
    let ip = f.script(
        "ip",
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\n[ \"$1 $2\" != 'route flush' ]",
            log.display()
        ),
    );
    let dns = f.script("dns", "exit 9");
    let backend = IpRoute::with_paths(ip, dns, Duration::from_secs(1));
    let error = backend.configure(&config("[]", "[]")).unwrap_err();
    assert!(error.to_string().contains("ip"));
    assert!(error.to_string().contains('1'));
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        "addr flush dev vpnt0\nroute flush dev vpnt0\n"
    );
    backend
        .delete_tun(&TunName::parse("vpnt0").unwrap())
        .unwrap();
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .ends_with("link del dev vpnt0\n")
    );
}
#[test]
fn runner_clears_environment_captures_output_and_does_not_echo_stderr() {
    let f = Fixture::new();
    let ip=f.script("ip", "[ \"$LC_ALL\" = C ] || exit 2\n[ -z \"${HOME+x}\" ] || exit 3\n[ -z \"${XDG_CONFIG_HOME+x}\" ] || exit 4\n[ -z \"${TMPDIR+x}\" ] || exit 5\n[ -z \"${USERPROFILE+x}\" ] || exit 6\nprintf '[{\"ifname\":\"vpnt0\"}]'");
    let backend = IpRoute::with_paths(ip, f.0.join("unused"), Duration::from_secs(1));
    assert_eq!(backend.existing().unwrap()[0].as_str(), "vpnt0");
    let bad = f.script("bad", "printf 'private-client-input' >&2\nexit 7");
    let backend = IpRoute::with_paths(bad, f.0.join("unused"), Duration::from_secs(1));
    let message = backend.existing().unwrap_err().to_string();
    assert!(!message.contains("private-client-input"));
    assert!(message.len() <= 256);
}
#[test]
fn runner_enforces_deadline_and_drains_full_pipes() {
    let f = Fixture::new();
    let ip = f.script("ip", "while :; do :; done");
    let backend = IpRoute::with_paths(ip, f.0.join("unused"), Duration::from_millis(30));
    let start = Instant::now();
    assert_eq!(
        backend.existing().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    let ip=f.script("flood","i=0; while [ \"$i\" -lt 10000 ]; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n' >&2; i=$((i+1)); done\nprintf '[]'");
    assert!(
        IpRoute::with_paths(ip, f.0.join("unused"), Duration::from_secs(3))
            .existing()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn backend_revalidates_public_config_before_any_effect() {
    let f = Fixture::new();
    let ip = f.script("never", "exit 99");
    let backend = IpRoute::with_paths(ip.clone(), ip, Duration::from_secs(1));
    let mut c = config("[]", "[]");
    c.mtu = 575;
    assert_eq!(
        backend.configure(&c).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}
