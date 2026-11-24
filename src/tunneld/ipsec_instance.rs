//! Lifecycle of the stock charon inside an authenticated Linux IPsec unit.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use super::{
    handshake::{AuthenticatedChannel, Datagram},
    instance_protocol::{Order, Reply, Start, decode_credentials},
    protocol::{CidrV4, ErrorCode},
};
use crate::{
    connection::{ipsec::Config, routes::Network},
    helper::{
        local_socket::{Budget, Canceled, connect_deadline},
        vici::{self, Client, CommandResult, Message},
    },
    secrets::Credentials,
};

const CHARON: &str = "/usr/lib/strongswan/charon";
const CONFIG_NAME: &str = "strongswan.conf";
const VICI_SOCKET_NAME: &str = "vici.sock";
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_INTERVAL: Duration = Duration::from_millis(20);
// Same manual reqid range as connection/ipsec/namespace.rs.
const MAX_MANUAL_REQID: u16 = 0x3fff;
const TERM_GRACE: Duration = Duration::from_secs(3);
/// How often negotiation re-checks the control channel; also bounds how long
/// a cancellation takes to reach a VICI exchange in progress.
const CONTROL_POLL: Duration = Duration::from_millis(50);

/// Local unit configuration. The directory comes from the service manager's
/// RUNTIME_DIRECTORY and must be private and empty.
pub struct Params {
    pub directory: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Exit {
    Stopped,
    Eof,
}

/// Run in the instance's main thread after `handshake::connect_instance`.
/// The unit must provide a private view of stock charon's compiled PIDDIR
/// and contain descendants in its cgroup, including during supervisor loss.
pub fn run(channel: AuthenticatedChannel, params: Params) -> io::Result<Exit> {
    // SAFETY: these calls take no arguments or pointers.
    if unsafe { (libc::geteuid(), libc::getegid()) } != (0, 0) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPsec supervisor requires root:root",
        ));
    }
    validate_path(&params.directory)?;
    for parent in params.directory.ancestors().skip(1) {
        check_parent(parent, 0)?;
    }
    run_authenticated(channel, &params, Path::new(CHARON), (0, 0))
}

fn run_authenticated(
    mut channel: AuthenticatedChannel,
    params: &Params,
    program: &Path,
    owner: (u32, u32),
) -> io::Result<Exit> {
    run_with(&mut channel, params, program, owner)
}

trait InstanceChannel: Send {
    /// Datagrams may carry credentials and always arrive in a wiping buffer.
    fn receive(&mut self, child: Option<BorrowedFd<'_>>) -> io::Result<Datagram>;
    fn send(&mut self, reply: &Reply) -> io::Result<()>;
    /// Wait up to `timeout` for a pending datagram without consuming it. The
    /// peer's exit is an UnexpectedEof error.
    fn wait_control(&mut self, timeout: Duration) -> io::Result<bool>;
}

impl InstanceChannel for AuthenticatedChannel {
    fn receive(&mut self, child: Option<BorrowedFd<'_>>) -> io::Result<Datagram> {
        match child {
            Some(pidfd) => self.receive_while_running(pidfd),
            None => self.receive(),
        }
    }

    fn send(&mut self, reply: &Reply) -> io::Result<()> {
        self.send(&serde_json::to_vec(reply)?)
    }

    fn wait_control(&mut self, timeout: Duration) -> io::Result<bool> {
        AuthenticatedChannel::wait_control(self, timeout)
    }
}

fn get_order(
    channel: &mut impl InstanceChannel,
    child: Option<BorrowedFd<'_>>,
) -> io::Result<Order> {
    let bytes = channel.receive(child)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid IPsec instance order"))
}

fn run_with(
    channel: &mut impl InstanceChannel,
    params: &Params,
    program: &Path,
    owner: (u32, u32),
) -> io::Result<Exit> {
    // SAFETY: PR_SET_DUMPABLE takes an integer value. The handshake applies
    // the same protection before it opens the channel.
    checked(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    let result = run_attempt(channel, params, program, owner);
    match result {
        Ok(Exit::Stopped) => channel.send(&Reply::Stopped {})?,
        Ok(Exit::Eof) => {}
        Err(ref error) => {
            let code = match error.kind() {
                io::ErrorKind::InvalidData => ErrorCode::BadRequest,
                io::ErrorKind::TimedOut => ErrorCode::Timeout,
                io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
                io::ErrorKind::NotFound => ErrorCode::MissingProgram,
                _ => ErrorCode::Backend,
            };
            let notify = channel.send(&Reply::Failed { code });
            return with_cleanup(result, notify);
        }
    }
    result
}

fn run_attempt(
    channel: &mut impl InstanceChannel,
    params: &Params,
    program: &Path,
    owner: (u32, u32),
) -> io::Result<Exit> {
    let start = match get_order(channel, None) {
        Ok(Order::Start(start)) => start,
        Ok(Order::Stop {}) => return Err(invalid("expected IPsec start")),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(Exit::Eof),
        Err(error) => return Err(error),
    };
    let attempt = Attempt::new(start)?;
    let mut frame = match channel.receive(None) {
        Ok(frame) => frame,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(Exit::Eof),
        Err(error) => return Err(error),
    };
    let credentials =
        decode_credentials(&mut frame).map_err(|_| invalid("invalid IPsec credentials"))?;
    drop(frame);

    let directory = &params.directory;
    let socket = validate_path(directory)?;
    check_parent(
        directory
            .parent()
            .ok_or_else(|| invalid("missing parent"))?,
        owner.0,
    )?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || (metadata.uid(), metadata.gid()) != owner
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPsec runtime directory must be private and owned by the supervisor",
        ));
    }
    if fs::read_dir(directory)?.next().transpose()?.is_some() {
        return Err(invalid("IPsec runtime directory must be empty"));
    }

    let result = run_in_directory(
        channel,
        directory,
        &socket,
        program,
        attempt,
        credentials,
        owner,
    );
    let cleanup = with_cleanup(
        remove_if_present(&directory.join(VICI_SOCKET_NAME)),
        remove_if_present(&directory.join(CONFIG_NAME)),
    );
    with_cleanup(result, cleanup)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn run_in_directory(
    channel: &mut impl InstanceChannel,
    directory: &Path,
    socket: &str,
    program: &Path,
    attempt: Attempt,
    credentials: Credentials,
    owner: (u32, u32),
) -> io::Result<Exit> {
    let path = directory.join(CONFIG_NAME);
    let mut config = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    config.set_permissions(fs::Permissions::from_mode(0o600))?;
    write!(
        config,
        r#"charon {{
    load_modular = no
    load = aes sha1 sha2 md4 hmac kdf random nonce openssl eap-identity eap-mschapv2 kernel-netlink socket-default vici
    follow_redirects = no
    install_routes = no
    install_virtual_ip = no
    routing_table = 0
    plugins {{
        kernel-netlink {{
            install_routes_xfrmi = no
            port_bypass = no
        }}
        vici {{
            socket = "unix://{socket}"
        }}
    }}
    syslog {{
        daemon {{ default = -1 }}
        auth {{ default = -1 }}
    }}
}}
"#
    )?;
    drop(config);

    let mut child = spawn_charon(program, directory, &path)?;
    let pidfd = match pidfd_open(child.id()) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            // The Child still owns the uncollected PID.
            let cleanup = child.kill().and_then(|()| child.wait().map(drop));
            return with_cleanup(Err(error), cleanup);
        }
    };

    let mut vici = PrivateVici {
        path: Path::new(socket),
        child: &pidfd,
        pid: child.id(),
        owner,
        loaded: false,
        cancel: Arc::default(),
    };
    let result =
        establish_watched(channel, &mut vici, &attempt, credentials).and_then(|settled| {
            match settled {
                Settled::Done(exit) => Ok(exit),
                Settled::Publish(reply) => channel.send(&reply).and_then(|()| {
                    match get_order(channel, Some(pidfd.as_fd())) {
                        Ok(Order::Stop {}) => Ok(Exit::Stopped),
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(Exit::Eof),
                        Ok(Order::Start(_)) => Err(invalid("IPsec instance already started")),
                        Err(error) => Err(error),
                    }
                }),
            }
        });
    let unload = vici.cleanup(&attempt.config);
    let stop = stop_child(&mut child, &pidfd);
    with_cleanup(result, with_cleanup(unload, stop))
}

enum Settled {
    /// The negotiation finished with no order pending: publish its result.
    Publish(Reply),
    /// An order or the end of the channel arrived first: publish nothing.
    Done(Exit),
}

struct Finished<'a>(&'a AtomicBool);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Run the negotiation while a second thread watches the control channel. A
/// `Stop`, an error or the end of the channel cancels the VICI exchange in
/// progress; cleanup then runs under its own budget in the caller.
fn establish_watched(
    channel: &mut impl InstanceChannel,
    vici: &mut PrivateVici<'_>,
    attempt: &Attempt,
    credentials: Credentials,
) -> io::Result<Settled> {
    let cancel = Arc::clone(&vici.cancel);
    let done = AtomicBool::new(false);
    let (established, observed) = std::thread::scope(|scope| {
        let watcher = scope.spawn(|| watch_control(channel, &cancel, &done));
        let established = {
            let _finished = Finished(&done);
            vici.establish(attempt, credentials)
        };
        let observed = watcher
            .join()
            .unwrap_or_else(|_| Some(Err(io::Error::other("IPsec control watcher panicked"))));
        (established, observed)
    });
    settle(established, observed)
}

/// Returns what the channel delivered while the negotiation ran, if anything.
/// After the negotiation ends it looks once more, so an order that arrived
/// before the result was known is never overtaken by the result.
fn watch_control(
    channel: &mut impl InstanceChannel,
    cancel: &AtomicBool,
    done: &AtomicBool,
) -> Option<io::Result<Order>> {
    loop {
        let finished = done.load(Ordering::Acquire);
        let order = match channel.wait_control(if finished {
            Duration::ZERO
        } else {
            CONTROL_POLL
        }) {
            Ok(false) if finished => return None,
            Ok(false) => continue,
            Ok(true) => get_order(channel, None),
            Err(error) => Err(error),
        };
        cancel.store(true, Ordering::Release);
        return Some(order);
    }
}

fn settle(
    established: io::Result<Reply>,
    observed: Option<io::Result<Order>>,
) -> io::Result<Settled> {
    let Some(order) = observed else {
        return established.map(Settled::Publish);
    };
    // A reply for a negotiation that an order has overtaken is never sent.
    // A real failure of the negotiation still surfaces.
    if let Err(error) = established
        && !cancel_induced(&error)
    {
        return Err(error);
    }
    match order {
        Ok(Order::Stop {}) => Ok(Settled::Done(Exit::Stopped)),
        Ok(Order::Start(_)) => Err(invalid("IPsec instance already started")),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(Settled::Done(Exit::Eof)),
        Err(error) => Err(error),
    }
}

fn cancel_induced(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted
}

fn canceled(error: io::Error) -> io::Error {
    if error
        .get_ref()
        .is_some_and(|source| source.is::<Canceled>())
    {
        return io::Error::new(io::ErrorKind::Interrupted, "IPsec negotiation canceled");
    }
    error
}

struct Attempt {
    start: Start,
    config: Config,
}

impl Attempt {
    fn new(start: Start) -> io::Result<Self> {
        let locals = &start.local_ts;
        let remotes = &start.remote_ts;
        if start.if_id == 0
            || !(1..=MAX_MANUAL_REQID).contains(&start.reqid)
            || CidrV4::new(start.remote_ipv4, 32).is_err()
            // D0r2 requires a native proof before admitting custom IKE ports.
            || start.port != 500
            || !(1..=64).contains(&locals.len())
            || !(1..=64).contains(&remotes.len())
            || (locals != &["dynamic"]
                && locals.iter().any(|ts| {
                    ts.parse::<Network>().map_or(true, |net| {
                        !net.address().is_ipv4()
                            || *ts != format!("{}/{}", net.address(), net.prefix())
                    })
                }))
        {
            return Err(invalid("invalid IPsec instance parameters"));
        }
        let remote_ts = remotes
            .iter()
            .map(|net| format!("{}/{}", net.network(), net.prefix()))
            .collect();
        let config = Config::linux(
            SocketAddrV4::new(start.remote_ipv4, start.port),
            &start.peer_identity,
            &start.username,
            start.if_id,
            start.reqid,
            start.local_ts.clone(),
            remote_ts,
        )
        .map_err(|_| invalid("invalid IPsec identity"))?;
        Ok(Self { start, config })
    }

    fn established(&self, list: CommandResult) -> io::Result<Reply> {
        let invalid_sa = || io::Error::other("unexpected IPsec SA metadata");
        if !list.response.is_empty() || list.events.len() != 1 {
            return Err(invalid_sa());
        }
        let (event, root) = &list.events[0];
        let ike = root
            .get_section(self.config.name())
            .ok_or_else(invalid_sa)?;
        if event != "list-sa"
            || root.len() != 1
            || ike.get_text("state") != Some("ESTABLISHED")
            || ike.get_text("version") != Some("2")
            || ike.get_text("initiator") != Some("yes")
            || ike.get_text("remote-host").and_then(|ip| ip.parse().ok())
                != Some(self.start.remote_ipv4)
            || !matches!(ike.get_text("remote-port"), Some("500" | "4500"))
        {
            return Err(invalid_sa());
        }
        let [vip] = ike.get_list("local-vips").ok_or_else(invalid_sa)? else {
            return Err(invalid_sa());
        };
        let virtual_ipv4 = parse_vici::<Ipv4Addr>(vip).ok_or_else(invalid_sa)?;
        CidrV4::new(virtual_ipv4, 32).map_err(|_| invalid_sa())?;

        let children = ike.get_section("child-sas").ok_or_else(invalid_sa)?;
        let (key, child) = children.sections().next().ok_or_else(invalid_sa)?;
        let child_id = child
            .get_text("uniqueid")
            .and_then(|value| value.parse::<u32>().ok());
        let if_id = |field| {
            child.get_text(field).and_then(|value| {
                u32::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
            })
        };
        if children.len() != 1
            || !child_id
                .is_some_and(|id| id != 0 && key == format!("{}-{id}", self.config.child_name()))
            || child.get_text("name") != Some(self.config.child_name())
            || child.get_text("state") != Some("INSTALLED")
            || child.get_text("mode") != Some("TUNNEL")
            || child.get_text("protocol") != Some("ESP")
            || child.get_text("reqid").and_then(|value| value.parse().ok())
                != Some(self.start.reqid)
            || if_id("if-id-in") != Some(self.start.if_id)
            || if_id("if-id-out") != Some(self.start.if_id)
        {
            return Err(invalid_sa());
        }

        let [local] = child.get_list("local-ts").ok_or_else(invalid_sa)? else {
            return Err(invalid_sa());
        };
        if selector(local) != Some(Network::host(IpAddr::V4(virtual_ipv4)))
            || (self.start.local_ts != ["dynamic"]
                && !self.start.local_ts.iter().any(|ts| {
                    ts.parse::<Network>()
                        .is_ok_and(|net| net.contains(IpAddr::V4(virtual_ipv4)))
                }))
        {
            return Err(invalid_sa());
        }
        let selectors = child.get_list("remote-ts").ok_or_else(invalid_sa)?;
        if !(1..=64).contains(&selectors.len()) {
            return Err(invalid_sa());
        }
        let mut seen = BTreeSet::new();
        let mut remote_ts = Vec::with_capacity(selectors.len());
        for item in selectors {
            let net = selector(item).ok_or_else(invalid_sa)?;
            let IpAddr::V4(address) = net.address() else {
                return Err(invalid_sa());
            };
            if !seen.insert(net)
                || !self.start.remote_ts.iter().any(|allowed| {
                    allowed.prefix() <= net.prefix()
                        && Network::new(allowed.network().into(), allowed.prefix())
                            .is_ok_and(|allowed| allowed.contains(net.address()))
                })
            {
                return Err(invalid_sa());
            }
            remote_ts.push(CidrV4::new(address, net.prefix()).map_err(|_| invalid_sa())?);
        }
        Ok(Reply::Established {
            if_id: self.start.if_id,
            reqid: self.start.reqid,
            virtual_ipv4,
            remote_ts,
        })
    }
}

fn parse_vici<T: std::str::FromStr>(bytes: &[u8]) -> Option<T> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn selector(bytes: &[u8]) -> Option<Network> {
    parse_vici(bytes).or_else(|| parse_vici(bytes).map(Network::host))
}

struct PrivateVici<'a> {
    path: &'a Path,
    child: &'a OwnedFd,
    pid: u32,
    owner: (u32, u32),
    loaded: bool,
    /// Observed by every exchange of the negotiation. Cleanup uses its own.
    cancel: Arc<AtomicBool>,
}

impl PrivateVici<'_> {
    fn open(&self, deadline: Instant) -> io::Result<Client> {
        if poll_until(self.child, Instant::now())? {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "charon exited"));
        }
        let metadata = fs::symlink_metadata(self.path)?;
        if !metadata.file_type().is_socket()
            || (metadata.uid(), metadata.gid()) != self.owner
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe IPsec VICI socket",
            ));
        }
        let budget = Budget::until(deadline, Some(Arc::clone(&self.cancel))).map_err(canceled)?;
        let stream = connect_deadline(self.path, &budget).map_err(canceled)?;
        // SAFETY: credential and len are writable buffers for SO_PEERCRED.
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&peer) as libc::socklen_t;
        checked(unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut len,
            )
        })?;
        if len as usize != std::mem::size_of_val(&peer)
            || u32::try_from(peer.pid).ok() != Some(self.pid)
            || (peer.uid, peer.gid) != self.owner
            || poll_until(self.child, Instant::now())?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected IPsec VICI peer",
            ));
        }
        Client::from_stream_until(stream, self.owner.0, deadline, Arc::clone(&self.cancel))
            .map_err(vici_error)
    }

    fn establish(&mut self, attempt: &Attempt, credentials: Credentials) -> io::Result<Reply> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let version = loop {
            match self.open(deadline) {
                Ok(client) => {
                    break client
                        .command("version", Message::new(), &[])
                        .map_err(vici_error)?
                        .response;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    if poll_until(
                        self.child,
                        (Instant::now() + STARTUP_INTERVAL).min(deadline),
                    )? {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "charon exited before VICI readiness",
                        ));
                    }
                    remaining(deadline)?;
                }
                Err(error) => return Err(error),
            }
        };
        let stats = self
            .exchange(deadline, "stats", Message::new(), &[])?
            .response;
        Config::admit_linux(&version, &stats)
            .map_err(|_| io::Error::other("incompatible IPsec VICI backend"))?;
        let config = &attempt.config;
        let shared = config
            .shared(credentials)
            .map_err(|_| invalid("invalid IPsec credentials"))?;
        // A lost ACK leaves the load uncertain. Clean up even if it failed.
        self.loaded = true;
        self.ack(deadline, "load-conn", config.connection())?;
        for message in shared {
            self.ack(deadline, "load-shared", message)?;
        }
        let initiate = config
            .initiate(remaining(deadline)?)
            .map_err(|_| io::Error::other("invalid IPsec initiate deadline"))?;
        self.ack(deadline, "initiate", initiate)?;
        let mut request = Message::new();
        request.value("ike", config.name().as_bytes());
        attempt.established(self.exchange(deadline, "list-sas", request, &["list-sa"])?)
    }

    fn cleanup(&self, config: &Config) -> io::Result<()> {
        if !self.loaded || poll_until(self.child, Instant::now())? {
            return Ok(());
        }
        // Cancellation of the negotiation must not cancel its own cleanup.
        let this = Self {
            path: self.path,
            child: self.child,
            pid: self.pid,
            owner: self.owner,
            loaded: self.loaded,
            cancel: Arc::default(),
        };
        let this = &this;
        let deadline = Instant::now() + TERM_GRACE;
        let terminate = config
            .terminate(remaining(deadline)?)
            .map_err(|_| io::Error::other("invalid IPsec terminate deadline"))?;
        let terminated = this.ack(deadline, "terminate", terminate);
        let unloaded = this.ack(deadline, "unload-conn", config.unload_connection());
        let mut result = with_cleanup(terminated, unloaded);
        for message in config.unload_shared() {
            result = with_cleanup(result, this.ack(deadline, "unload-shared", message));
        }
        result
    }

    fn ack(&self, deadline: Instant, name: &'static str, request: Message) -> io::Result<()> {
        let response = self.exchange(deadline, name, request, &[])?.response;
        if response.get_text("success") != Some("yes") {
            return Err(io::Error::other(format!(
                "IPsec VICI {name} did not succeed"
            )));
        }
        Ok(())
    }

    fn exchange(
        &self,
        deadline: Instant,
        name: &'static str,
        request: Message,
        events: &[&str],
    ) -> io::Result<CommandResult> {
        self.open(deadline)?
            .command(name, request, events)
            .map_err(vici_error)
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(remaining)
}

fn vici_error(error: vici::Error) -> io::Error {
    let kind = match error {
        vici::Error::Canceled => io::ErrorKind::Interrupted,
        vici::Error::Timeout => io::ErrorKind::TimedOut,
        vici::Error::UntrustedPeer => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("IPsec VICI: {error:?}"))
}

fn validate_path(directory: &Path) -> io::Result<String> {
    let path = directory
        .to_str()
        .filter(|path| {
            path.starts_with('/')
                && path[1..]
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | ".."))
                && !path
                    .chars()
                    .any(|ch| ch.is_control() || matches!(ch, '"' | '\\'))
        })
        .ok_or_else(|| invalid("unsafe IPsec instance directory"))?;
    let socket = format!("{path}/{VICI_SOCKET_NAME}");
    let path_capacity = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path);
    if socket.len() >= path_capacity {
        return Err(invalid(
            "IPsec VICI path exceeds Unix socket address capacity",
        ));
    }
    Ok(socket)
}

fn check_parent(path: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPsec instance ancestry must be owned by the supervisor and not writable by others",
        ));
    }
    Ok(())
}

fn spawn_charon(program: &Path, directory: &Path, config: &Path) -> io::Result<Child> {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("STRONGSWAN_CONF", config)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    // SAFETY: getpid has no arguments.
    let parent = unsafe { libc::getpid() };
    // SAFETY: Only async-signal-safe operations run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            checked(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0))?;
            // Register first, then check for death between fork and prctl.
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            // Preserve the exec error pipe until exec, while closing it and
            // every other non-stdio descriptor at successful exec.
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            // Linux creates Unix sockets with mode 0777 masked by umask.
            libc::umask(0o177);
            Ok(())
        });
    }
    command.spawn()
}

fn stop_child(child: &mut Child, pidfd: &OwnedFd) -> io::Result<()> {
    let grace = match poll_until(pidfd, Instant::now()) {
        Ok(true) => {
            let status = child.wait()?;
            return Err(io::Error::other(format!("charon exited early: {status}")));
        }
        Ok(false) => pidfd_signal(pidfd, libc::SIGTERM)
            .and_then(|()| poll_until(pidfd, Instant::now() + TERM_GRACE)),
        Err(error) => Err(error),
    };
    if matches!(grace, Ok(true)) {
        child.wait()?;
        return Ok(());
    }
    let kill = match pidfd_signal(pidfd, libc::SIGKILL) {
        Ok(()) => child.wait().map(drop),
        Err(error) => {
            let cleanup = child.kill().and_then(|()| child.wait().map(drop));
            with_cleanup(Err(error), cleanup)
        }
    };
    with_cleanup(grace.map(drop), kill)
}

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a PID and flags and returns an owned fd.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) })
}

fn pidfd_signal(pidfd: &OwnedFd, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: signal only the process bound to the owned descriptor.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn poll_until(pidfd: &OwnedFd, deadline: Instant) -> io::Result<bool> {
    let mut entry = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let millis = timeout.as_nanos().div_ceil(1_000_000) as libc::c_int;
        // SAFETY: poll reads and updates just the supplied pollfd.
        let rc = unsafe { libc::poll(&mut entry, 1, millis) };
        if rc >= 0 {
            if entry.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("invalid child pidfd poll result"));
            }
            return Ok(entry.revents & (libc::POLLIN | libc::POLLHUP) != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn checked(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn with_cleanup<T>(result: io::Result<T>, cleanup: io::Result<()>) -> io::Result<T> {
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; cleanup: {cleanup}"),
        )),
    }
}

#[cfg(test)]
#[path = "ipsec_instance_tests.rs"]
mod tests;
