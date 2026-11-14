use vpnt::cli::{Options, USAGE};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match vpnt::cli::parse(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    match options {
        Options::Help => println!("{USAGE}"),
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
        #[cfg(all(target_os = "macos", feature = "desktop"))]
        Options::App { demo, show } => {
            if let Err(error) = vpnt::desktop::run(demo, show) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        #[allow(unreachable_patterns)]
        _ => {
            eprintln!("The desktop app currently requires macOS and the desktop feature.");
            std::process::exit(1);
        }
    }
}
