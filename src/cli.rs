#[derive(Debug)]
pub enum Options {
    #[cfg(target_os = "linux")]
    Helper(crate::helper::server::Mode),
    #[cfg(target_os = "linux")]
    TunnelPolicy {
        profile_id: String,
        dns_servers: Vec<std::net::Ipv4Addr>,
    },
    Help,
    Version,
    InspectComponent,
    App {
        demo: bool,
        show: bool,
    },
    DemoServer {
        port: u16,
    },
}

pub const USAGE: &str = "vpnt [--demo] [--show]\nvpnt --demo-server <port>\nvpnt --inspect-component\nvpnt --help\nvpnt --version";
#[cfg(target_os = "linux")]
pub const TUNNEL_POLICY_USAGE: &str = "vpnt tunnel-policy <profile-id> [--dns-server <ipv4>]...";

pub fn parse(args: &[String]) -> Result<Options, &'static str> {
    #[cfg(target_os = "linux")]
    if args.first().map(String::as_str) == Some("helper") {
        let args: Vec<std::ffi::OsString> =
            args[1..].iter().map(std::ffi::OsString::from).collect();
        return crate::helper::server::Mode::parse(&args)
            .map(Options::Helper)
            .ok_or("Unknown argument.");
    }
    #[cfg(target_os = "linux")]
    if let [command, rest @ ..] = args
        && command == "tunnel-policy"
    {
        let [profile_id, flags @ ..] = rest else {
            return Err("Provide a tunnel policy profile ID.");
        };
        if !crate::model::valid_profile_id(profile_id) {
            return Err("Invalid tunnel policy profile ID.");
        }
        let (pairs, remainder) = flags.as_chunks::<2>();
        if !remainder.is_empty() || pairs.len() > 4 {
            return Err("Provide up to four --dns-server <ipv4> options.");
        }
        let dns_servers = pairs
            .iter()
            .map(|[flag, address]| {
                if flag != "--dns-server" {
                    return Err("Expected --dns-server <ipv4>.");
                }
                address
                    .parse()
                    .map_err(|_| "Invalid DNS server IPv4 address.")
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Options::TunnelPolicy {
            profile_id: profile_id.clone(),
            dns_servers,
        });
    }
    if args == ["--help"] || args == ["-h"] {
        return Ok(Options::Help);
    }
    if args == ["--version"] {
        return Ok(Options::Version);
    }
    if args == ["--inspect-component"] {
        return Ok(Options::InspectComponent);
    }
    if args.first().map(String::as_str) == Some("--demo-server") {
        if args.len() != 2 {
            return Err("Provide a loopback demo server port.");
        }
        let port = args[1]
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or("Invalid demo server port.")?;
        return Ok(Options::DemoServer { port });
    }
    if args.len() <= 2
        && args
            .iter()
            .all(|arg| matches!(arg.as_str(), "--demo" | "--show"))
    {
        return Ok(Options::App {
            demo: args.iter().any(|arg| arg == "--demo"),
            show: args.iter().any(|arg| arg == "--show"),
        });
    }
    Err("Unknown argument.")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn parse_fixture(args: &[&str]) -> Result<Options, &'static str> {
        parse(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn accepts_repeated_tunnel_policy_dns_server_flags() {
        let Options::TunnelPolicy {
            profile_id,
            dns_servers,
        } = parse_fixture(&[
            "tunnel-policy",
            "fixture-policy",
            "--dns-server",
            "192.0.2.53",
            "--dns-server",
            "198.51.100.53",
        ])
        .unwrap()
        else {
            panic!("expected tunnel-policy options");
        };
        assert_eq!(profile_id, "fixture-policy");
        assert_eq!(
            dns_servers,
            [
                std::net::Ipv4Addr::new(192, 0, 2, 53),
                std::net::Ipv4Addr::new(198, 51, 100, 53),
            ]
        );
    }

    #[test]
    fn rejects_malformed_tunnel_policy_arguments() {
        for args in [
            &["tunnel-policy"][..],
            &["tunnel-policy", "../fixture"],
            &["tunnel-policy", "fixture", "--dns-server"],
            &["tunnel-policy", "fixture", "--server", "192.0.2.53"],
            &["tunnel-policy", "fixture", "--dns-server", "2001:db8::53"],
            &["tunnel-policy", "fixture", "--dns-server", "'192.0.2.53'"],
            &[
                "tunnel-policy",
                "fixture",
                "--dns-server",
                "192.0.2.53 trailing",
            ],
            &[
                "tunnel-policy",
                "fixture",
                "--dns-server",
                "192.0.2.1",
                "--dns-server",
                "192.0.2.2",
                "--dns-server",
                "192.0.2.3",
                "--dns-server",
                "192.0.2.4",
                "--dns-server",
                "192.0.2.5",
            ],
        ] {
            assert!(parse_fixture(args).is_err(), "{args:?}");
        }
    }
}
