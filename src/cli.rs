#[derive(Debug)]
pub enum Options {
    Help,
    Version,
    App { demo: bool, show: bool },
    DemoServer { port: u16 },
}

pub const USAGE: &str =
    "vpnt [--demo] [--show]\nvpnt --demo-server <port>\nvpnt --help\nvpnt --version";

pub fn parse(args: &[String]) -> Result<Options, &'static str> {
    if args == ["--help"] || args == ["-h"] {
        return Ok(Options::Help);
    }
    if args == ["--version"] {
        return Ok(Options::Version);
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
