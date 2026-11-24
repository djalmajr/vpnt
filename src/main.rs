use vpnt::cli::{Options, USAGE};

fn main() {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<_>, _>>();
    let options = match args
        .map_err(|_| "Invalid argument encoding.")
        .and_then(|args| vpnt::cli::parse(&args))
    {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            #[cfg(target_os = "linux")]
            eprintln!("{}", vpnt::cli::TUNNEL_POLICY_USAGE);
            std::process::exit(2);
        }
    };
    match options {
        #[cfg(target_os = "linux")]
        Options::Helper(mode) => {
            if let Err(error) = unsafe { vpnt::helper::server::linux_run(mode) } {
                std::process::exit(
                    if error == vpnt::helper::protocol::ErrorCode::PermissionDenied {
                        77
                    } else {
                        1
                    },
                );
            }
        }
        #[cfg(target_os = "linux")]
        Options::TunnelPolicy {
            profile_id,
            dns_servers,
        } => {
            use std::io::Write;
            let result =
                vpnt::tunnel_policy::for_profile_id(&profile_id, &dns_servers).and_then(|bytes| {
                    std::io::stdout().lock().write_all(&bytes).map_err(|_| {
                        std::io::Error::other("Could not write the tunnel policy snapshot.")
                    })
                });
            if let Err(error) = result {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Options::Help => {
            println!("{USAGE}");
            #[cfg(target_os = "linux")]
            println!("{}", vpnt::cli::TUNNEL_POLICY_USAGE);
        }
        Options::Version => println!("vpnt {}", env!("CARGO_PKG_VERSION")),
        Options::InspectComponent => {
            #[cfg(target_os = "macos")]
            match vpnt::install::bundle::Component::current() {
                Ok(component) => {
                    println!("{}", serde_json::to_string(component.metadata()).unwrap())
                }
                Err(error) => {
                    eprintln!("{}", serde_json::to_string(&error).unwrap());
                    std::process::exit(if error == vpnt::install::Error::PermissionDenied {
                        77
                    } else {
                        1
                    });
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("Component admission requires macOS.");
                std::process::exit(1);
            }
        }
        #[cfg(feature = "desktop")]
        Options::DemoServer { port } => {
            if let Err(error) = vpnt::preview::serve(port) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        #[cfg(all(any(target_os = "macos", target_os = "linux"), feature = "desktop"))]
        Options::App { demo, show } => {
            if let Err(error) = vpnt::desktop::run(demo, show) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        #[allow(unreachable_patterns)]
        _ => {
            eprintln!("The desktop app currently requires macOS or Linux and the desktop feature.");
            std::process::exit(1);
        }
    }
}
