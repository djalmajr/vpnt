//! Supervisor of one `vpnt-tunneld-fortinet@` instance.
//!
//! After the handshake (instance side) the supervisor waits for exactly one
//! credential frame on the authenticated channel, then starts the packaged
//! openfortivpn with a fixed argv. The password never appears in argv, in the
//! environment or in a file: the client reads it from the pinentry, which asks
//! for it over a single-use descriptor 3 created after authentication.
//!
//! Lifecycle: the client leads its own process group, dies with the supervisor
//! (`PR_SET_PDEATHSIG`), and is stopped with SIGTERM to the group, then SIGKILL
//! after a grace period, and reaped exactly once. Descendants left in the group
//! are swept with SIGKILL before the leader is reaped, while the zombie leader
//! still reserves the group id. A SIGKILL of the supervisor itself reaches only
//! the client (the kernel offers no group-wide death signal); descendants that
//! left it rely on the unit's `KillMode=control-group`.
//!
//! The PPP fence (`vpnt-pppd` and the supervised `pppd`) is not wired here: its
//! macOS mechanism depends on Apple-only options and controller, see the slice
//! report.

use std::{
    ffi::OsString,
    fs::File,
    io,
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::PathBuf,
    process::{Command, ExitStatus},
    time::{Duration, Instant},
};

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use super::protocol::{Credentials, Endpoint, FortinetRequest};
use crate::{helper::pinentry_channel::PinentryChild, secrets::Secret};

/// Packaged client, with the macOS patches and the mandatory pin patch.
pub const OPENFORTIVPN: &str = "/usr/lib/vpnt/openfortivpn";
/// Packaged Assuan adapter that asks the supervisor for the password.
pub const PINENTRY: &str = "/usr/lib/vpnt/vpnt-pinentry";

const MESSAGE_CREDENTIAL: u8 = 1;
const MESSAGE_STOP: u8 = 2;
const PASSWORD_LIMIT: usize = 256;
/// Same datagram ceiling as the authenticated channel.
const MAX_DATAGRAM: usize = 4096;
const TICK: Duration = Duration::from_millis(50);
const GROUP_GONE_WAIT: Duration = Duration::from_millis(500);
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

/// The authenticated datagram channel to the writer, as the supervisor needs it.
///
/// `fd` must be pollable for readability and `receive` must not discard the
/// channel when it is called without pending data. The real channel
/// (`AuthenticatedChannel`) exposes neither yet, see the slice report.
pub trait Channel {
    fn fd(&self) -> io::Result<BorrowedFd<'_>>;
    /// Read one datagram. `WouldBlock` means nothing was pending.
    fn receive(&mut self) -> io::Result<Vec<u8>>;
    fn send(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// Typed, bounded view of the client output, independent of its raw text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    pub candidate: Option<String>,
    pub failure: Option<Failure>,
    pub split: Vec<(Ipv4Addr, u8)>,
    pub split_count: Option<usize>,
    pub split_invalid: bool,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_domains: Vec<String>,
    pub dns_count: Option<(usize, usize)>,
    pub dns_invalid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    CredentialsRejected,
    GatewayTimeout,
}

/// Parser of the client output. The production implementation is the
/// `ssl_output` parser shared with macOS; raw lines never leave it.
pub trait Observer {
    /// Drain this pipe on the observer's own thread.
    fn attach(&mut self, pipe: File) -> io::Result<()>;
    fn snapshot(&self) -> Observation;
    /// Drain what is left, within a short bound, and stop reading.
    fn finish(&mut self);
}

/// Typed observations and lifecycle facts sent to the writer. Nothing raw.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Started,
    Interface {
        name: String,
    },
    Failure {
        kind: Failure,
    },
    SplitRoute {
        network: Ipv4Addr,
        prefix: u8,
    },
    SplitRoutes {
        count: usize,
    },
    SplitInvalid,
    DnsServer {
        address: Ipv4Addr,
    },
    DnsDomain {
        name: String,
    },
    DnsCount {
        servers: usize,
        domains: usize,
    },
    DnsInvalid,
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

/// Egress binding frozen by the writer for this attempt (F2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub interface: String,
    pub index: u32,
    pub gateway: Ipv4Addr,
}

/// Typed parameters taken from the already validated policy entry. Nothing in
/// it is free text from the client, and the pin is never optional to run.
#[derive(Debug)]
pub struct Params {
    endpoint: Endpoint,
    username: String,
    certificate_sha256: Option<[u8; 32]>,
    binding: Binding,
    ca_file: Option<PathBuf>,
}

impl Params {
    pub fn new(
        endpoint: Endpoint,
        username: String,
        certificate_sha256: Option<[u8; 32]>,
        binding: Binding,
        ca_file: Option<PathBuf>,
    ) -> io::Result<Self> {
        let interface = &binding.interface;
        if !(1..=64).contains(&username.len())
            || username.chars().any(char::is_control)
            || interface.is_empty()
            || interface.len() >= libc::IFNAMSIZ
            || !interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || binding.index == 0
            || binding.gateway.is_unspecified()
            || binding.gateway.is_multicast()
            || binding.gateway == Ipv4Addr::BROADCAST
            || ca_file.as_deref().is_some_and(|path| !path.is_absolute())
        {
            return Err(invalid("invalid fortinet parameters"));
        }
        Ok(Self {
            endpoint,
            username,
            certificate_sha256,
            binding,
            ca_file,
        })
    }

    pub fn from_request(
        request: &FortinetRequest,
        binding: Binding,
        ca_file: Option<PathBuf>,
    ) -> io::Result<Self> {
        let endpoint = Endpoint::new(
            request.endpoint().host().to_owned(),
            request.endpoint().port(),
        )
        .map_err(|_| invalid("invalid fortinet endpoint"))?;
        Self::new(
            endpoint,
            request.username().to_owned(),
            Some(*request.certificate_sha256()),
            binding,
            ca_file,
        )
    }

    /// The patched client accepts a valid PKI chain instead of the digest, so
    /// the pin is required here and refused when absent or empty.
    fn pin(&self) -> io::Result<&[u8; 32]> {
        self.certificate_sha256
            .as_ref()
            .filter(|pin| pin.iter().any(|&byte| byte != 0))
            .ok_or_else(|| invalid("certificate pin required"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// The writer closed the channel, or the channel failed.
    ChannelClosed,
    /// The writer sent the stop command.
    Stop,
    /// The client ended by itself.
    ClientExited,
}

#[derive(Debug)]
pub struct Exit {
    pub reason: Reason,
    /// `None` when no client was ever started.
    pub status: Option<ExitStatus>,
    /// SIGKILL was needed because the group ignored SIGTERM.
    pub escalated: bool,
    /// The client's process group was empty after the sweep.
    pub descendants_gone: bool,
    /// Cause of a `ChannelClosed` reason.
    pub channel_error: Option<io::Error>,
}

#[derive(Clone, Copy)]
struct Limits {
    credential_wait: Duration,
    grace: Duration,
    kill_wait: Duration,
}

impl Limits {
    const PRODUCTION: Self = Self {
        credential_wait: Duration::from_secs(10),
        grace: Duration::from_secs(3),
        kill_wait: Duration::from_secs(2),
    };
}

#[derive(Clone, Copy)]
struct Config<'a> {
    client: &'a str,
    pinentry: &'a str,
    limits: Limits,
}

impl Config<'static> {
    const PRODUCTION: Self = Self {
        client: OPENFORTIVPN,
        pinentry: PINENTRY,
        limits: Limits::PRODUCTION,
    };
}

/// Run one instance until the channel ends, the writer stops it or the client
/// exits. Call from the supervisor's main thread: the death signal of the
/// client follows the thread that spawned it.
pub fn run(
    channel: &mut impl Channel,
    params: Params,
    observer: &mut impl Observer,
) -> io::Result<Exit> {
    protect()?;
    run_with(channel, params, observer, Config::PRODUCTION)
}

/// Other processes of the same UID must not read the supervisor's memory.
fn protect() -> io::Result<()> {
    // SAFETY: prctl takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn run_with(
    channel: &mut impl Channel,
    params: Params,
    observer: &mut impl Observer,
    config: Config<'_>,
) -> io::Result<Exit> {
    // Refuse before reading the credential or starting anything.
    let pin = *params.pin()?;
    let (command, null) = command(&config, &params, &pin)?;

    let password = match wait_credential(channel, config.limits.credential_wait)? {
        Waited::Credential(password) => password,
        Waited::Closed(error) => return Ok(never_started(Reason::ChannelClosed, Some(error))),
        Waited::Stop => return Ok(never_started(Reason::Stop, None)),
    };
    let spawned = Client::spawn(command, password);
    drop(null);
    let mut client = spawned?;
    for pipe in [client.take_stdout(), client.take_stderr()]
        .into_iter()
        .flatten()
    {
        observer.attach(pipe)?;
    }

    let mut sent = Observation::default();
    // A failure below drops `client`, which kills its group.
    let end = supervise(channel, observer, &client, &mut sent)?;
    let stopped = client.terminate(config.limits);
    observer.finish();
    let (reason, channel_error) = match end {
        End::Violation(error) => {
            return Err(match stopped {
                Ok(_) => error,
                Err(cleanup) => {
                    io::Error::new(error.kind(), format!("{error}; cleanup: {cleanup}"))
                }
            });
        }
        End::Done(reason, channel_error) => (reason, channel_error),
    };
    let stopped = stopped?;
    if reason != Reason::ChannelClosed {
        // The writer is still there: the last observations, then the exit.
        report(channel, observer, &mut sent)?;
        send(
            channel,
            &Event::Exited {
                code: stopped.status.code(),
                signal: stopped.status.signal(),
            },
        )?;
    }
    Ok(Exit {
        reason,
        status: Some(stopped.status),
        escalated: stopped.escalated,
        descendants_gone: stopped.descendants_gone,
        channel_error,
    })
}

enum End {
    Done(Reason, Option<io::Error>),
    /// The writer broke the message contract: stop, then fail.
    Violation(io::Error),
}

fn supervise(
    channel: &mut impl Channel,
    observer: &impl Observer,
    client: &Client,
    sent: &mut Observation,
) -> io::Result<End> {
    if let Err(error) = send(channel, &Event::Started) {
        return Ok(End::Done(Reason::ChannelClosed, Some(error)));
    }
    loop {
        let mut fds = [
            poll_entry(channel.fd()?.as_raw_fd()),
            poll_entry(client.pidfd.as_raw_fd()),
        ];
        poll_fds(&mut fds, TICK)?;
        if fds[1].revents != 0 {
            return Ok(End::Done(Reason::ClientExited, None));
        }
        if fds[0].revents != 0 {
            match channel.receive() {
                Ok(bytes) => {
                    return Ok(match decode(&mut Zeroizing::new(bytes)) {
                        Ok(Message::Stop) => End::Done(Reason::Stop, None),
                        // The only credential was already delivered.
                        Ok(Message::Credential(_)) => End::Violation(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "credential repeated",
                        )),
                        Err(error) => End::Violation(error),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Ok(End::Done(Reason::ChannelClosed, Some(error))),
            }
        }
        if let Err(error) = report(channel, observer, sent) {
            return Ok(End::Done(Reason::ChannelClosed, Some(error)));
        }
    }
}

fn never_started(reason: Reason, channel_error: Option<io::Error>) -> Exit {
    Exit {
        reason,
        status: None,
        escalated: false,
        descendants_gone: true,
        channel_error,
    }
}

/// The argv is fixed. The password is not part of it and the environment is
/// rebuilt by the spawn layer. Mirrors the macOS command, with the pin always.
fn command(config: &Config<'_>, params: &Params, pin: &[u8; 32]) -> io::Result<(Command, OwnedFd)> {
    let mut command = Command::new(config.client);
    command
        .args([
            "--config=/dev/null",
            "--no-routes",
            "--no-dns",
            "--pppd-no-peerdns",
            "--pppd-accept-remote=0",
            "--persistent=0",
        ])
        .arg(format!("--username={}", params.username))
        .arg(format!("--pinentry={}", config.pinentry));
    if let Some(ca_file) = &params.ca_file {
        // Appended as bytes: a path is not necessarily UTF-8.
        let mut argument = OsString::from("--ca-file=");
        argument.push(ca_file);
        command.arg(argument);
    }
    command
        .arg(format!("--ifname={}", params.binding.interface))
        .arg(format!("--vpnt-ifindex={}", params.binding.index))
        .arg(format!("--vpnt-gateway-ip={}", params.binding.gateway))
        .arg(format!("--trusted-cert={}", hex(pin)))
        .arg("--")
        .arg(format!(
            "{}:{}",
            params.endpoint.host(),
            params.endpoint.port()
        ));

    // The client leads its group, dies with the supervisor, reads nothing from
    // stdin and keeps no descriptor above 3: the pinentry channel is installed
    // later, by the spawn layer, on top of this hook.
    let parent = std::process::id() as libc::pid_t;
    let null = descriptor_above_stdio(File::open("/dev/null")?)?;
    let null_fd = null.as_raw_fd();
    command.process_group(0);
    // SAFETY: the hook only calls async-signal-safe functions on integers.
    // `null_fd` stays open through spawn: the caller holds the returned owner.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // The supervisor may have died between fork and prctl.
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::dup2(null_fd, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_close_range,
                4 as libc::c_uint,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok((command, null))
}

/// Keeps `/dev/null` away from the stdio slots, whatever the supervisor had
/// closed, so that installing it as stdin is a real change.
fn descriptor_above_stdio(file: File) -> io::Result<OwnedFd> {
    // SAFETY: duplicates a live descriptor above the stdio slots.
    let duplicate = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

enum Message {
    Credential(Secret),
    Stop,
}

enum Waited {
    Credential(Secret),
    Stop,
    Closed(io::Error),
}

/// One credential datagram: kind 1, `u16` big-endian length, the password.
/// Stop is kind 2 with no payload. The datagram is zeroed on every path.
fn decode(bytes: &mut Vec<u8>) -> io::Result<Message> {
    let message = parse(bytes);
    bytes.zeroize();
    message
}

fn parse(bytes: &[u8]) -> io::Result<Message> {
    let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed message");
    match bytes {
        [MESSAGE_STOP] => Ok(Message::Stop),
        [MESSAGE_CREDENTIAL, high, low, password @ ..]
            if usize::from(u16::from_be_bytes([*high, *low])) == password.len()
                && (1..=PASSWORD_LIMIT).contains(&password.len()) =>
        {
            let password = std::str::from_utf8(password).map_err(|_| malformed())?;
            // The wire type owns the validation shared with the writer.
            let credentials = Credentials::fortinet(password).map_err(|_| malformed())?;
            Ok(Message::Credential(Secret::from(credentials.password())))
        }
        _ => Err(malformed()),
    }
}

fn wait_credential(channel: &mut impl Channel, limit: Duration) -> io::Result<Waited> {
    let deadline = Instant::now() + limit;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "credential not received"))?;
        let mut fds = [poll_entry(channel.fd()?.as_raw_fd())];
        poll_fds(&mut fds, remaining)?;
        if fds[0].revents == 0 {
            continue;
        }
        let mut bytes = Zeroizing::new(match channel.receive() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Ok(Waited::Closed(error)),
        });
        return Ok(match decode(&mut bytes)? {
            Message::Credential(password) => Waited::Credential(password),
            Message::Stop => Waited::Stop,
        });
    }
}

fn poll_entry(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

fn poll_fds(fds: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    let millis = timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
    // SAFETY: poll reads and updates the supplied live entries.
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) } < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        fds.iter_mut().for_each(|fd| fd.revents = 0);
    }
    Ok(())
}

fn send(channel: &mut impl Channel, event: &Event) -> io::Result<()> {
    let bytes = serde_json::to_vec(event)?;
    debug_assert!(bytes.len() <= MAX_DATAGRAM);
    channel.send(&bytes)
}

/// Send what changed in the typed observation since the last report.
fn report(
    channel: &mut impl Channel,
    observer: &impl Observer,
    sent: &mut Observation,
) -> io::Result<()> {
    let current = observer.snapshot();
    for event in changes(sent, &current) {
        send(channel, &event)?;
    }
    *sent = current;
    Ok(())
}

fn changes(sent: &Observation, current: &Observation) -> Vec<Event> {
    let mut events = Vec::new();
    if let Some(name) = current
        .candidate
        .as_ref()
        .filter(|_| current.candidate != sent.candidate)
    {
        events.push(Event::Interface { name: name.clone() });
    }
    if let Some(kind) = current.failure.filter(|_| current.failure != sent.failure) {
        events.push(Event::Failure { kind });
    }
    for &(network, prefix) in current.split.iter().skip(sent.split.len()) {
        events.push(Event::SplitRoute { network, prefix });
    }
    if let Some(count) = current
        .split_count
        .filter(|_| current.split_count != sent.split_count)
    {
        events.push(Event::SplitRoutes { count });
    }
    if current.split_invalid && !sent.split_invalid {
        events.push(Event::SplitInvalid);
    }
    for &address in current.dns_servers.iter().skip(sent.dns_servers.len()) {
        events.push(Event::DnsServer { address });
    }
    for name in current.dns_domains.iter().skip(sent.dns_domains.len()) {
        events.push(Event::DnsDomain { name: name.clone() });
    }
    if let Some((servers, domains)) = current
        .dns_count
        .filter(|_| current.dns_count != sent.dns_count)
    {
        events.push(Event::DnsCount { servers, domains });
    }
    if current.dns_invalid && !sent.dns_invalid {
        events.push(Event::DnsInvalid);
    }
    events
}

/// The spawned client and the identity needed to stop its whole group.
struct Client {
    child: PinentryChild,
    pidfd: OwnedFd,
    group: libc::pid_t,
    reaped: bool,
}

struct Stopped {
    status: ExitStatus,
    escalated: bool,
    descendants_gone: bool,
}

impl Client {
    fn spawn(command: Command, password: Secret) -> io::Result<Self> {
        let mut child = PinentryChild::spawn(command, password)?;
        let group = child.id() as libc::pid_t;
        // The child is not reaped until `poll`, so its pid is still ours.
        match pidfd_open(group) {
            Ok(pidfd) => Ok(Self {
                child,
                pidfd,
                group,
                reaped: false,
            }),
            Err(error) => {
                kill_group(group, libc::SIGKILL);
                let _ = child.poll();
                Err(error)
            }
        }
    }

    fn take_stdout(&mut self) -> Option<File> {
        self.child
            .take_stdout()
            .map(|pipe| File::from(OwnedFd::from(pipe)))
    }

    fn take_stderr(&mut self) -> Option<File> {
        self.child
            .take_stderr()
            .map(|pipe| File::from(OwnedFd::from(pipe)))
    }

    /// The pidfd becomes readable when the client exits, before it is reaped.
    fn wait_exit(&self, limit: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + limit;
        loop {
            let mut fds = [poll_entry(self.pidfd.as_raw_fd())];
            let remaining = deadline.saturating_duration_since(Instant::now());
            poll_fds(&mut fds, remaining.min(TICK))?;
            if fds[0].revents != 0 {
                return Ok(true);
            }
            if remaining.is_zero() {
                return Ok(false);
            }
        }
    }

    /// Only while the leader is unreaped: its zombie keeps the group id ours.
    fn signal_group(&self, signal: libc::c_int) -> io::Result<()> {
        assert!(!self.reaped, "signalling a reaped client's group");
        // SAFETY: kill takes integers; the group leader has not been reaped.
        if unsafe { libc::kill(-self.group, signal) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    /// SIGTERM to the group, SIGKILL after the grace, a final SIGKILL sweep of
    /// whatever outlived the leader, then one reap and a check of the group.
    fn terminate(&mut self, limits: Limits) -> io::Result<Stopped> {
        self.child.revoke_password();
        let mut escalated = false;
        if !self.wait_exit(Duration::ZERO)? {
            self.signal_group(libc::SIGTERM)?;
            if !self.wait_exit(limits.grace)? {
                escalated = true;
                self.signal_group(libc::SIGKILL)?;
                if !self.wait_exit(limits.kill_wait)? {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "client exit unconfirmed",
                    ));
                }
            }
        }
        self.signal_group(libc::SIGKILL)?;
        let deadline = Instant::now() + limits.kill_wait;
        let status = loop {
            if let Some(status) = self.child.poll()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "client exit status unconfirmed",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        self.reaped = true;
        Ok(Stopped {
            status,
            escalated,
            descendants_gone: self.group_gone(),
        })
    }

    fn group_gone(&self) -> bool {
        let deadline = Instant::now() + GROUP_GONE_WAIT;
        loop {
            // SAFETY: signal 0 only checks that the group has members.
            let missing = unsafe { libc::kill(-self.group, 0) } != 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            if missing {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.reaped {
            // Leader still unreaped: the group id is ours. Dropping the child
            // then kills and reaps the leader itself.
            kill_group(self.group, libc::SIGKILL);
        }
    }
}

fn kill_group(group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: kill takes integers; callers hold an unreaped group leader.
    unsafe { libc::kill(-group, signal) };
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes integers and returns a new close-on-exec fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0 as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

#[cfg(test)]
#[path = "fortinet_instance_tests.rs"]
mod tests;
