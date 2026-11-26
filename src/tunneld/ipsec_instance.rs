//! Lifecycle of the stock charon inside an authenticated Linux IPsec unit.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, PipeReader, Read, Write};
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
use zeroize::{Zeroize, Zeroizing};

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
const CONTROL_LOG_LEVEL: &[u8] = b"1";
const CONTROL_LOG_LINES: usize = 8;
const CHARON_LOG_LINES: usize = 60;
// Drop oversized records as a whole. Never interpret an incomplete message.
const CHARON_LOG_INPUT_BYTES: usize = 8 * 1024;
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
    filelog {{
        stderr {{
            default = 1
            json = yes
            dmn = 1
            mgr = 1
            ike = 1
            chd = 1
            job = 1
            wch = 1
            cfg = 1
            knl = 1
            net = 1
            asn = 1
            enc = 1
            tnc = 1
            imc = 1
            imv = 1
            pts = 1
            tls = 1
            app = 1
            esp = 1
            lib = 1
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

    let (stderr, writer) = io::pipe()?;
    // Only the reader is nonblocking. strongSwan writes a line in multiple
    // calls, so dropping individual writes would lose its line boundaries.
    // SAFETY: F_SETFL takes a valid fd and integer flags.
    checked(unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
    let (stop, stop_writer) = io::pipe()?;
    let mut tail = VecDeque::with_capacity(CHARON_LOG_LINES);
    let result = std::thread::scope(|scope| {
        let finish = stop_writer;
        let reader = std::thread::Builder::new().spawn_scoped(scope, || {
            drain_charon_log(stderr, stop, &credentials, &mut tail)
        })?;
        let result =
            spawn_charon(program, directory, &path, writer.into()).and_then(|mut child| {
                run_child(channel, socket, attempt, &credentials, owner, &mut child)
            });
        drop(finish);
        let capture = reader
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("charon stderr reader panicked")));
        with_cleanup(result, capture)
    });
    result.map_err(|error| append_charon_log(error, tail))
}

fn run_child(
    channel: &mut impl InstanceChannel,
    socket: &str,
    attempt: Attempt,
    credentials: &Credentials,
    owner: (u32, u32),
    child: &mut Child,
) -> io::Result<Exit> {
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
        credentials,
    };
    let result =
        establish_watched(channel, &mut vici, &attempt).and_then(|settled| match settled {
            Settled::Done(exit) => Ok(exit),
            Settled::Publish(reply) => {
                channel
                    .send(&reply)
                    .and_then(|()| match get_order(channel, Some(pidfd.as_fd())) {
                        Ok(Order::Stop {}) => Ok(Exit::Stopped),
                        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(Exit::Eof),
                        Ok(Order::Start(_)) => Err(invalid("IPsec instance already started")),
                        Err(error) => Err(error),
                    })
            }
        });
    let unload = vici.cleanup(&attempt.config);
    let stop = stop_child(child, &pidfd);
    with_cleanup(result, with_cleanup(unload, stop))
}

fn drain_charon_log(
    mut stderr: PipeReader,
    stop: PipeReader,
    credentials: &Credentials,
    tail: &mut VecDeque<String>,
) -> io::Result<()> {
    let mut chunk = Zeroizing::new([0; 4096]);
    let mut line = Zeroizing::new([0; CHARON_LOG_INPUT_BYTES]);
    let mut len = 0;
    let mut oversized = false;
    let mut pending = None;
    let mut events = [
        libc::pollfd {
            fd: stderr.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stop.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        if pending.is_none() {
            // SAFETY: poll updates only the two supplied entries.
            let ready = unsafe { libc::poll(events.as_mut_ptr(), 2, -1) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if events
                .iter()
                .any(|entry| entry.revents & (libc::POLLERR | libc::POLLNVAL) != 0)
            {
                return Err(io::Error::other("invalid charon stderr poll result"));
            }
        }
        if pending.is_none() && events[1].revents & libc::POLLHUP != 0 {
            // The direct child has been stopped. Drain bytes already queued
            // without waiting for descendants that may still hold the writer.
            let mut queued: libc::c_int = 0;
            // SAFETY: FIONREAD writes a single c_int to the supplied pointer.
            checked(unsafe { libc::ioctl(stderr.as_raw_fd(), libc::FIONREAD, &mut queued) })?;
            pending = Some(queued as usize);
        }
        let count = pending.unwrap_or(chunk.len()).min(chunk.len());
        if count == 0 {
            break;
        }
        let read = match stderr.read(&mut chunk[..count]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && pending.is_none() => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Some(remaining) = &mut pending {
            *remaining -= read;
        }
        for part in chunk[..read].split_inclusive(|&byte| byte == b'\n') {
            let complete = part.strip_suffix(b"\n");
            let bytes = complete.unwrap_or(part);
            if !oversized && bytes.len() <= line.len() - len {
                line[len..len + bytes.len()].copy_from_slice(bytes);
                len += bytes.len();
            } else {
                line[..len].zeroize();
                len = 0;
                oversized = true;
            }
            if complete.is_some() {
                if !oversized && let Some(safe) = charon_diagnostic(&line[..len], credentials) {
                    if tail.len() == CHARON_LOG_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(safe);
                }
                line[..len].zeroize();
                oversized = false;
                len = 0;
            }
        }
        chunk[..read].zeroize();
    }
    // An unterminated line may contain only the prefix of a secret.
    Ok(())
}

#[derive(serde::Deserialize)]
struct CharonLog<'a> {
    level: u8,
    msg: &'a str,
}

fn charon_diagnostic(line: &[u8], credentials: &Credentials) -> Option<String> {
    // strongSwan's JSON logger keeps embedded newlines within a single record.
    // Discard escaped records so the parser can borrow directly from the wiping
    // buffer without creating an unprotected decoded copy of the message.
    if line.contains(&b'\\') {
        return None;
    }
    let entry: CharonLog<'_> = serde_json::from_slice(line).ok()?;
    if entry.level > 1 {
        return None;
    }
    safe_diagnostic(entry.msg, credentials, charon_message)
}

fn append_charon_log(error: io::Error, tail: VecDeque<String>) -> io::Error {
    if tail.is_empty() {
        return error;
    }
    let mut message = error.to_string();
    for line in tail {
        message.push_str("\ncharon-log: ");
        message.push_str(&line);
    }
    io::Error::new(error.kind(), message)
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
) -> io::Result<Settled> {
    let cancel = Arc::clone(&vici.cancel);
    let done = AtomicBool::new(false);
    let (established, observed) = std::thread::scope(|scope| {
        let watcher = scope.spawn(|| watch_control(channel, &cancel, &done));
        let established = {
            let _finished = Finished(&done);
            vici.establish(attempt)
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
    credentials: &'a Credentials,
}

impl PrivateVici<'_> {
    fn open(&self, deadline: Instant) -> io::Result<Client> {
        if poll_until(self.child, Instant::now())? {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "charon exited"));
        }
        let metadata = fs::symlink_metadata(self.path)?;
        // strongSwan 6.1.0 binds with umask 0117, yielding 0660 inside the
        // private 0700 runtime directory. A socket restricted to 0600 also works.
        if !metadata.file_type().is_socket()
            || (metadata.uid(), metadata.gid()) != self.owner
            || !matches!(metadata.mode() & 0o7777, 0o600 | 0o660)
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

    fn establish(&mut self, attempt: &Attempt) -> io::Result<Reply> {
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
        // Keep the original zeroizing credentials available to filter replies,
        // including ACKs received during cleanup.
        let shared = config
            .shared(Credentials {
                password: self.credentials.password.expose().into(),
                psk: self.credentials.psk.expose().into(),
            })
            .map_err(|_| invalid("invalid IPsec credentials"))?;
        // A lost ACK leaves the load uncertain. Clean up even if it failed.
        self.loaded = true;
        self.ack(deadline, "load-conn", config.connection())?;
        for message in shared {
            self.ack(deadline, "load-shared", message)?;
        }
        self.initiate(deadline, config)?;
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
            credentials: self.credentials,
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
        self.check_ack(name, &response)
    }

    fn check_ack(&self, name: &'static str, response: &Message) -> io::Result<()> {
        if response.get_text("success") == Some("yes") {
            return Ok(());
        }
        let mut error = format!("IPsec VICI {name} did not succeed");
        if let Some(detail) = response
            .get_text("errmsg")
            .and_then(|text| safe_diagnostic(text, self.credentials, ack_message))
        {
            error.push_str("\nerrmsg: ");
            error.push_str(&detail);
        }
        Err(io::Error::other(error))
    }

    fn initiate(&self, deadline: Instant, config: &Config) -> io::Result<()> {
        let mut request = config
            .initiate(remaining(deadline)?)
            .map_err(|_| io::Error::other("invalid IPsec initiate deadline"))?;
        // strongSwan's LEVEL_CTRL excludes raw blobs and private key material.
        request
            .replace_value("loglevel", CONTROL_LOG_LEVEL)
            .map_err(vici_error)?;
        let mut tail = VecDeque::with_capacity(CONTROL_LOG_LINES);
        let result = self
            .open(deadline)?
            .command_with_events("initiate", request, &["control-log"], |_, event| {
                if matches!(event.get_text("level"), Some("0" | "1"))
                    && let Some(text) = event.get_text("msg")
                    && let Some(line) = safe_diagnostic(text, self.credentials, charon_message)
                {
                    if tail.len() == CONTROL_LOG_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(line);
                }
                Ok(())
            })
            .map_err(vici_error)
            .and_then(|response| self.check_ack("initiate", &response));
        result.map_err(|error| {
            if tail.is_empty() || cancel_induced(&error) {
                return error;
            }
            // The instance entry point writes this single error to stderr.
            let mut diagnostic = error.to_string();
            for line in tail {
                diagnostic.push_str("\ncontrol-log: ");
                diagnostic.push_str(&line);
            }
            io::Error::new(error.kind(), diagnostic)
        })
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

// Project strongSwan 6.1 diagnostics onto fixed text. Even prefixes from
// known formats authorize only the label, never any bytes from the peer.
fn charon_message(text: &str) -> Option<&'static str> {
    let label = match text {
        "no acceptable proposal found" => "no acceptable proposal found",
        "received AUTHENTICATION_FAILED notify error" => {
            "received AUTHENTICATION_FAILED notify error"
        }
        "received NO_PROPOSAL_CHOSEN notify error" => "received NO_PROPOSAL_CHOSEN notify error",
        "remote host is behind NAT" => "remote host is behind NAT",
        "local host is behind NAT, sending keep alives" => {
            "local host is behind NAT, sending keep alives"
        }
        "peer supports MOBIKE" => "peer supports MOBIKE",
        "establishing IKE_SA failed, peer not responding" => {
            "establishing IKE_SA failed, peer not responding"
        }
        _ => [
            (
                "Starting IKE charon daemon (strongSwan ",
                "Starting IKE charon daemon",
            ),
            ("initiating IKE_SA ", "initiating IKE_SA"),
            (
                "generating IKE_SA_INIT request ",
                "generating IKE_SA_INIT request",
            ),
            (
                "parsed IKE_SA_INIT response ",
                "parsed IKE_SA_INIT response",
            ),
            (
                "generating IKE_AUTH request ",
                "generating IKE_AUTH request",
            ),
            ("parsed IKE_AUTH response ", "parsed IKE_AUTH response"),
            ("selected proposal: ", "selected proposal"),
            (
                "EAP-MS-CHAPv2 failed with error ",
                "EAP-MS-CHAPv2 failed: <peer-text>",
            ),
            (
                "no shared key found for '",
                "no shared key found: <peer-text>",
            ),
            (
                "received EAP identity '",
                "received EAP identity: <peer-text>",
            ),
            (
                "client got redirected from ",
                "peer redirect identity: <peer-text>",
            ),
            (
                "received unknown vendor ID: ",
                "received unknown vendor ID: <peer-text>",
            ),
        ]
        .into_iter()
        .find_map(|(prefix, label)| text.starts_with(prefix).then_some(label))
        .or_else(|| {
            let (count, identities) = text.strip_prefix("tried ")?.split_once(" shared key")?;
            let identities = identities.strip_prefix('s').unwrap_or(identities);
            (!count.is_empty()
                && count.bytes().all(|byte| byte.is_ascii_digit())
                && identities.starts_with(" for '")
                && identities.ends_with("', but MAC mismatched"))
            .then_some("shared-key MAC mismatch: <peer-text>")
        })?,
    };
    Some(label)
}

fn ack_message(text: &str) -> Option<&'static str> {
    match text {
        "missing configuration name" => Some("missing configuration name"),
        "no matching SAs to terminate found" => Some("no matching SAs to terminate found"),
        "terminating SA failed" => Some("terminating SA failed"),
        "not all matching SAs could be terminated" => {
            Some("not all matching SAs could be terminated")
        }
        _ if text.starts_with("establishing IKE_SA '") && text.ends_with("' failed") => {
            Some("establishing IKE_SA failed")
        }
        _ => None,
    }
}

fn safe_diagnostic(
    text: &str,
    credentials: &Credentials,
    known_message: fn(&str) -> Option<&'static str>,
) -> Option<String> {
    let credentials = [credentials.password.expose(), credentials.psk.expose()];
    let contains_credential = |text: &str| {
        credentials
            .iter()
            .any(|secret| !secret.is_empty() && text.contains(secret))
    };
    // Retain the literal credential and sensitive-label checks from the raw log filter.
    if contains_credential(text)
        || text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| {
                [
                    "password", "psk", "ppk", "data", "private", "secret", "keymat", "skeyseed",
                    "msk", "emsk",
                ]
                .iter()
                .any(|label| word.eq_ignore_ascii_case(label))
                    || word
                        .get(..3)
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SK_"))
            })
    {
        return None;
    }
    let label = known_message(text)?;
    (!contains_credential(label)).then(|| label.to_owned())
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

fn spawn_charon(
    program: &Path,
    directory: &Path,
    config: &Path,
    stderr: Stdio,
) -> io::Result<Child> {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("STRONGSWAN_CONF", config)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
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
            format!("{error}\ncleanup: {cleanup}"),
        )),
    }
}

#[cfg(test)]
#[path = "ipsec_instance_tests.rs"]
mod tests;
