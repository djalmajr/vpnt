//! Fixed-path iproute2/resolved backend. Each command has a separate deadline.
use super::protocol::{Config, TunName};
use serde::Deserialize;
use std::{
    error::Error,
    fmt,
    io::{self, Read},
    os::fd::AsRawFd,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub trait Backend: Send + Sync {
    fn create_tun(&self, name: &TunName, owner: u32) -> io::Result<()>;
    fn configure(&self, config: &Config) -> io::Result<()>;
    fn delete_tun(&self, name: &TunName) -> io::Result<()>;
    fn existing(&self) -> io::Result<Vec<Existing>>;
    fn retry_wait(&self) -> Duration {
        Duration::from_secs(5)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Existing {
    pub name: TunName,
    pub owned: bool,
}

pub struct IpRoute {
    ip: PathBuf,
    resolvectl: PathBuf,
    deadline: Duration,
}
impl IpRoute {
    pub fn system() -> Self {
        Self::with_paths(
            "/usr/bin/ip".into(),
            "/usr/bin/resolvectl".into(),
            Duration::from_secs(5),
        )
    }
    #[doc(hidden)]
    pub fn with_paths(ip: PathBuf, resolvectl: PathBuf, deadline: Duration) -> Self {
        Self {
            ip,
            resolvectl,
            deadline,
        }
    }
    fn run(&self, dns: bool, args: &[String]) -> io::Result<Vec<u8>> {
        let (path, label) = if dns {
            (&self.resolvectl, "resolvectl")
        } else {
            (&self.ip, "ip")
        };
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| command_error(label, e.kind(), "spawn failed"))?;
        let result = (|| {
            let mut stdout = child.stdout.take().expect("piped stdout");
            let mut stderr = child.stderr.take().expect("piped stderr");
            nonblocking(&stdout)?;
            nonblocking(&stderr)?;
            let start = Instant::now();
            let mut output = Vec::new();
            let mut overflow = false;
            loop {
                drain(&mut stdout, Some(&mut output), &mut overflow)?;
                drain(&mut stderr, None, &mut overflow)?;
                if let Some(status) = child.try_wait()? {
                    // The direct child is gone; consume the remaining pipe data without
                    // waiting for EOF (a descendant could retain an inherited descriptor).
                    drain(&mut stdout, Some(&mut output), &mut overflow)?;
                    drain(&mut stderr, None, &mut overflow)?;
                    if !status.success() {
                        return Err(command_error(
                            label,
                            io::ErrorKind::Other,
                            &format!("status {status}"),
                        ));
                    }
                    if overflow {
                        return Err(command_error(
                            label,
                            io::ErrorKind::InvalidData,
                            "output limit",
                        ));
                    }
                    return Ok(output);
                }
                if start.elapsed() >= self.deadline {
                    return Err(command_error(
                        label,
                        io::ErrorKind::TimedOut,
                        "deadline exceeded",
                    ));
                }
                thread::sleep(
                    Duration::from_millis(5).min(self.deadline.saturating_sub(start.elapsed())),
                );
            }
        })();
        // Always reap the process, including read/try_wait errors and deadline expiry.
        if result.is_err() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        result.map_err(|e| {
            if e.get_ref()
                .is_some_and(|inner| inner.is::<CommandFailure>())
            {
                e
            } else {
                io::Error::new(
                    e.kind(),
                    CommandFailure {
                        label,
                        detail: e.to_string(),
                        source: Some(e),
                    },
                )
            }
        })
    }
}
#[derive(Debug)]
struct CommandFailure {
    label: &'static str,
    detail: String,
    source: Option<io::Error>,
}
impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Retain the cause; bound only the presentation, at a UTF-8 boundary.
        let message = format!("{}: {}", self.label, self.detail);
        let mut end = message.len().min(256);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        f.write_str(&message[..end])
    }
}
impl Error for CommandFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|e| e as &(dyn Error + 'static))
    }
}
fn command_error(label: &'static str, kind: io::ErrorKind, detail: &str) -> io::Error {
    // No client arguments or stderr are included in a diagnostic.
    io::Error::new(
        kind,
        CommandFailure {
            label,
            detail: detail.to_owned(),
            source: None,
        },
    )
}
fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on a live, owned pipe descriptor without retaining it.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same live descriptor; preserve flags while adding nonblocking reads.
    if unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn drain(
    pipe: &mut impl Read,
    mut output: Option<&mut Vec<u8>>,
    overflow: &mut bool,
) -> io::Result<()> {
    // Bound each drain so a continuously writing command cannot defeat its deadline.
    let mut buffer = [0; 8192];
    for _ in 0..128 {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(bytes) = output.as_deref_mut() {
                    if bytes.len() + n > 1_048_576 {
                        *overflow = true;
                    } else {
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}
fn create_args(name: &TunName, owner: u32) -> Vec<String> {
    strings(&[
        "tuntap",
        "add",
        "dev",
        name.as_str(),
        "mode",
        "tun",
        "user",
        &owner.to_string(),
    ])
}
fn delete_args(name: &TunName) -> Vec<String> {
    strings(&["link", "del", "dev", name.as_str()])
}
fn existing_args() -> Vec<String> {
    strings(&["-j", "-d", "link", "show"])
}
fn alias_args(name: &TunName) -> Vec<String> {
    strings(&["link", "set", "dev", name.as_str(), "alias", "vpnt-helper"])
}
fn exact_route_args(prefix: &str) -> Vec<String> {
    strings(&["-j", "route", "show", "exact", prefix, "table", "main"])
}
struct NetworkCommand {
    dns: bool,
    args: Vec<String>,
    exact_route: Option<String>,
}
impl NetworkCommand {
    fn ip(args: &[&str]) -> Self {
        Self {
            dns: false,
            args: strings(args),
            exact_route: None,
        }
    }
    fn dns(args: Vec<String>) -> Self {
        Self {
            dns: true,
            args,
            exact_route: None,
        }
    }
}
fn configure_commands(config: &Config) -> Vec<NetworkCommand> {
    let name = config.name.as_str();
    let mut commands = vec![
        NetworkCommand::ip(&["addr", "flush", "dev", name]),
        NetworkCommand::ip(&["route", "flush", "dev", name]),
        NetworkCommand::ip(&[
            "link",
            "set",
            "dev",
            name,
            "mtu",
            &config.mtu.to_string(),
            "up",
        ]),
        NetworkCommand::ip(&[
            "addr",
            "add",
            &format!("{}/{}", config.address, config.prefix),
            "dev",
            name,
        ]),
    ];
    for route in &config.routes {
        let prefix = format!("{}/{}", route.network, route.prefix);
        let mut command = NetworkCommand::ip(&["route", "add", &prefix, "dev", name]);
        command.exact_route = Some(prefix);
        commands.push(command);
    }
    // Revert first so that nothing from the previous configure survives: a
    // replacement without domains must not keep the old routing domains.
    commands.push(NetworkCommand::dns(strings(&["revert", name])));
    if !config.dns.servers.is_empty() {
        let mut args = strings(&["dns", name]);
        args.extend(config.dns.servers.iter().map(ToString::to_string));
        commands.push(NetworkCommand::dns(args));
        if !config.dns.domains.is_empty() {
            let mut args = strings(&["domain", name]);
            args.extend(config.dns.domains.iter().map(|d| format!("~{d}")));
            commands.push(NetworkCommand::dns(args));
        }
        commands.push(NetworkCommand::dns(strings(&[
            "default-route",
            name,
            if config.dns.domains.is_empty() {
                "true"
            } else {
                "false"
            },
        ])));
    }
    commands
}
fn parse_existing(bytes: &[u8]) -> io::Result<Vec<Existing>> {
    #[derive(Deserialize)]
    struct Link {
        ifname: String,
        ifalias: Option<String>,
        linkinfo: Option<LinkInfo>,
    }
    #[derive(Deserialize)]
    struct LinkInfo {
        info_kind: Option<String>,
    }
    let links: Vec<Link> = serde_json::from_slice(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ip: invalid link JSON"))?;
    Ok(links
        .into_iter()
        .filter_map(|link| {
            let name = TunName::parse(&link.ifname).ok()?;
            let owned = link.ifalias.as_deref() == Some("vpnt-helper")
                && link.linkinfo.and_then(|info| info.info_kind).as_deref() == Some("tun");
            Some(Existing { name, owned })
        })
        .collect())
}
impl Backend for IpRoute {
    fn create_tun(&self, name: &TunName, owner: u32) -> io::Result<()> {
        self.run(false, &create_args(name, owner))?;
        if let Err(alias_error) = self.run(false, &alias_args(name)) {
            if self.run(false, &delete_args(name)).is_err() {
                // Surface the failed rollback without disclosing command output.
                return Err(command_error(
                    "ip",
                    alias_error.kind(),
                    "alias and rollback failed",
                ));
            }
            return Err(alias_error);
        }
        Ok(())
    }
    fn configure(&self, config: &Config) -> io::Result<()> {
        config.validate().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid network configuration")
        })?;
        for command in configure_commands(config) {
            if let Some(prefix) = &command.exact_route {
                if self.route_exists_on(prefix, &config.name)? {
                    continue;
                }
                if let Err(add_error) = self.run(false, &command.args) {
                    // The kernel's add is exclusive. Requery to classify a concurrent addition.
                    match self.route_exists_on(prefix, &config.name) {
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            return Err(error);
                        }
                        Ok(true) => continue,
                        _ => return Err(add_error),
                    }
                }
            } else {
                self.run(command.dns, &command.args)?;
            }
        }
        Ok(())
    }
    fn delete_tun(&self, name: &TunName) -> io::Result<()> {
        let _ = self.run(true, &strings(&["revert", name.as_str()]));
        self.run(false, &delete_args(name)).map(|_| ())
    }
    fn existing(&self) -> io::Result<Vec<Existing>> {
        parse_existing(&self.run(false, &existing_args())?)
    }
    fn retry_wait(&self) -> Duration {
        self.deadline
    }
}
impl IpRoute {
    fn route_exists_on(&self, prefix: &str, name: &TunName) -> io::Result<bool> {
        #[derive(Deserialize)]
        struct RouteDevice {
            dev: Option<String>,
        }
        let routes: Vec<RouteDevice> =
            serde_json::from_slice(&self.run(false, &exact_route_args(prefix))?).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "ip: invalid route JSON")
            })?;
        if routes
            .iter()
            .any(|route| route.dev.as_deref() != Some(name.as_str()))
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "route conflict",
            ));
        }
        Ok(!routes.is_empty())
    }
}
#[cfg(test)]
#[path = "iproute_tests.rs"]
mod tests;
