//! Supervisor of one `vpnt-tunneld-fortinet@` instance.
//!
//! After the handshake (instance side) the supervisor waits for exactly one
//! credential frame on the authenticated channel, then starts the packaged
//! openfortivpn with a fixed argv. The password never appears in argv, in the
//! environment or in a file: the client reads it from the pinentry, which asks
//! for it over a single-use descriptor 3 created after authentication.
//!
//! Lifecycle: the client leads its own process group, dies with the supervisor
//! (`PR_SET_PDEATHSIG`), and is stopped with SIGTERM, then SIGKILL after a grace
//! period, and reaped exactly once. The signals go to the group and to every
//! other descendant, tracked by pidfd: the distribution's `pppd`, started by the
//! client on a pty, runs in its own session and so leaves the group. Descendants
//! are swept with SIGKILL before the leader is reaped, while the zombie leader
//! still reserves the group id. In a process dedicated to the client (`run`
//! makes it a child subreaper), orphaned descendants are adopted, found from
//! this process, stopped and reaped. A SIGKILL of the supervisor itself reaches
//! only the client (the kernel offers no tree-wide death signal); descendants
//! that left its group rely on the unit's `KillMode=control-group`.
//!
//! There is no PPP fence on Linux: the client runs the distribution's `pppd`
//! (`--with-pppd`) with its default argv, and the macOS `vpnt-pppd` wrapper is
//! not used. The supervisor only fixes the interface name (`--pppd-ifname`).

use std::{
    fs::{self, File},
    io,
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::{Command, ExitStatus},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{
    handshake::Datagram,
    protocol::{Credentials, Endpoint, FortinetRequest},
};
use crate::{helper::pinentry_channel::PinentryChild, secrets::Secret};

/// Packaged client, with the macOS patches and the mandatory pin patch.
pub const OPENFORTIVPN: &str = "/usr/lib/vpnt/openfortivpn";
/// Packaged Assuan adapter that asks the supervisor for the password.
pub const PINENTRY: &str = "/usr/lib/vpnt/vpnt-pinentry";

pub(super) const MESSAGE_CREDENTIAL: u8 = 1;
pub(super) const MESSAGE_STOP: u8 = 2;
const PASSWORD_LIMIT: usize = 256;

/// The credential datagram the writer sends after `Start`: kind 1, the length
/// as a big-endian `u16`, the password. The caller keeps the buffer owned
/// through send so it is wiped on every path.
pub(super) fn credential_frame(password: &str) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    if !(1..=PASSWORD_LIMIT).contains(&password.len()) {
        return Err(invalid("invalid password length"));
    }
    let mut frame = zeroize::Zeroizing::new(Vec::with_capacity(3 + password.len()));
    frame.push(MESSAGE_CREDENTIAL);
    frame.extend_from_slice(&(password.len() as u16).to_be_bytes());
    frame.extend_from_slice(password.as_bytes());
    Ok(frame)
}
/// Same datagram ceiling as the authenticated channel.
const MAX_DATAGRAM: usize = 4096;
const TICK: Duration = Duration::from_millis(50);
const GROUP_GONE_WAIT: Duration = Duration::from_millis(500);
const SWEEP_PASSES: usize = 8;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;

/// The authenticated datagram channel to the writer, as the supervisor needs it.
///
/// `fd` must be pollable for readability and `receive` must not discard the
/// channel when it is called without pending data. The real channel
/// (`AuthenticatedChannel`) exposes neither yet, see the slice report.
pub trait Channel {
    fn fd(&self) -> io::Result<BorrowedFd<'_>>;
    /// Read one datagram, in a buffer that wipes itself when released.
    /// `WouldBlock` means nothing was pending.
    fn receive(&mut self) -> io::Result<Datagram>;
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
    /// The client announced another PPP interface than the one configured.
    pub interface_mismatch: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    CredentialsRejected,
    GatewayTimeout,
}

/// Parser of the client output. The production implementation is the
/// `ssl_output` parser shared with macOS; raw lines never leave it.
pub trait Observer {
    /// The PPP interface name the supervisor configured (`--pppd-ifname`), given
    /// before any pipe is attached: only that exact name may be reported, and any
    /// other becomes `Observation::interface_mismatch`.
    fn expect_interface(&mut self, name: &str) -> io::Result<()>;
    /// Drain this pipe on the observer's own thread.
    fn attach(&mut self, pipe: File) -> io::Result<()>;
    fn snapshot(&self) -> Observation;
    /// Drain what is left, within a short bound, and stop reading.
    fn finish(&mut self);
}

/// Typed observations and lifecycle facts sent to the writer. Nothing raw.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
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
    /// The client announced a PPP interface other than the configured one: the
    /// observations of this attempt are not to be trusted.
    InterfaceMismatch,
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
    pppd_ifname: String,
}

impl Params {
    /// Default name of the PPP interface for the attempt's ordinal.
    pub fn default_pppd_ifname(ordinal: u32) -> String {
        format!("vpntp{ordinal}")
    }

    pub fn new(
        endpoint: Endpoint,
        username: String,
        certificate_sha256: Option<[u8; 32]>,
        binding: Binding,
        pppd_ifname: String,
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
            || !(1..libc::IFNAMSIZ).contains(&pppd_ifname.len())
            || !pppd_ifname
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(invalid("invalid fortinet parameters"));
        }
        Ok(Self {
            endpoint,
            username,
            certificate_sha256,
            binding,
            pppd_ifname,
        })
    }

    pub fn from_request(
        request: &FortinetRequest,
        binding: Binding,
        pppd_ifname: String,
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
            pppd_ifname,
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
    /// A fatal event was reported (`interface_mismatch` or a failure): the
    /// client was stopped and the instance ends. The writer treats the
    /// instance's exit as a stop and cleans up.
    Fatal,
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
    /// This process exists for this one client: every child it ever has is
    /// one of the client's orphaned descendants (see `harden`).
    own_process: bool,
}

impl Config<'static> {
    const PRODUCTION: Self = Self {
        client: OPENFORTIVPN,
        pinentry: PINENTRY,
        limits: Limits::PRODUCTION,
        own_process: true,
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
    harden()?;
    run_with(channel, params, observer, Config::PRODUCTION)
}

/// First datagram of an instance, from the writer: everything the client needs
/// except the password. The values come from the policy entry and from the
/// writer's own egress lookup, never from the user's request text.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Lowercase hex SHA-256 of the gateway leaf certificate.
    pub certificate_sha256: String,
    pub interface: String,
    pub index: u32,
    pub gateway: Ipv4Addr,
    pub ppp_ifname: String,
}

impl Start {
    fn params(&self) -> io::Result<Params> {
        let pin = (self.certificate_sha256.len() == 64)
            .then(|| {
                let mut pin = [0_u8; 32];
                for (byte, pair) in pin
                    .iter_mut()
                    .zip(self.certificate_sha256.as_bytes().chunks(2))
                {
                    let text = std::str::from_utf8(pair).ok()?;
                    if !text
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    {
                        return None;
                    }
                    *byte = u8::from_str_radix(text, 16).ok()?;
                }
                Some(pin)
            })
            .flatten()
            .ok_or_else(|| invalid("invalid certificate pin"))?;
        Params::new(
            Endpoint::new(self.host.clone(), self.port).map_err(|_| invalid("invalid endpoint"))?,
            self.username.clone(),
            Some(pin),
            Binding {
                interface: self.interface.clone(),
                index: self.index,
                gateway: self.gateway,
            },
            self.ppp_ifname.clone(),
        )
    }
}

/// Entry of `vpnt-tunneld instance fortinet`, after the handshake: wait for the
/// writer's `Start`, then run the supervisor with the shared parser.
pub fn serve(channel: &mut impl Channel, observer: &mut impl Observer) -> io::Result<Exit> {
    harden()?;
    serve_with(channel, observer, Config::PRODUCTION)
}

fn serve_with(
    channel: &mut impl Channel,
    observer: &mut impl Observer,
    config: Config<'_>,
) -> io::Result<Exit> {
    let deadline = Instant::now() + config.limits.credential_wait;
    let start = loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "start not received"))?;
        let mut fds = [poll_entry(channel.fd()?.as_raw_fd())];
        poll_fds(&mut fds, remaining)?;
        if fds[0].revents == 0 {
            continue;
        }
        let bytes = match channel.receive() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Ok(never_started(Reason::ChannelClosed, Some(error))),
        };
        if *bytes == [MESSAGE_STOP] {
            return Ok(never_started(Reason::Stop, None));
        }
        if bytes.first() != Some(&b'{') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected the Start order",
            ));
        }
        break serde_json::from_slice::<Start>(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Start order"))?;
    };
    run_with(channel, start.params()?, observer, config)
}

/// What the `instance fortinet` subcommand runs after its handshake, with the
/// parser shared with macOS.
pub fn run_instance(mut channel: super::handshake::AuthenticatedChannel) -> io::Result<Exit> {
    serve(
        &mut channel,
        &mut crate::connection::ssl_output::Output::default(),
    )
}

/// Other processes of the same UID must not read the supervisor's memory, and
/// the supervisor adopts the client's orphaned descendants (the PPP daemon runs
/// in its own session, so it leaves the client's group and, once the client is
/// gone, would be left to init) so that it can find, stop and reap them.
fn harden() -> io::Result<()> {
    // SAFETY: prctl takes integer arguments only.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
        {
            return Err(io::Error::last_os_error());
        }
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
    observer.expect_interface(&params.pppd_ifname)?;

    let password = match wait_credential(channel, config.limits.credential_wait)? {
        Waited::Credential(password) => password,
        Waited::Closed(error) => return Ok(never_started(Reason::ChannelClosed, Some(error))),
        Waited::Stop => return Ok(never_started(Reason::Stop, None)),
    };
    let spawned = Client::spawn(command, password, config.own_process);
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
    let end = supervise(channel, observer, &mut client, &mut sent)?;
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
    client: &mut Client,
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
        client.track()?;
        if fds[1].revents != 0 {
            return Ok(End::Done(Reason::ClientExited, None));
        }
        if fds[0].revents != 0 {
            match channel.receive() {
                Ok(mut bytes) => {
                    return Ok(match decode(&mut bytes) {
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
        // Reported first, then the instance ends: nothing observed after a
        // wrong interface or a failure is worth keeping the client alive for.
        if sent.interface_mismatch || sent.failure.is_some() {
            return Ok(End::Done(Reason::Fatal, None));
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
        ])
        .arg(format!("--pppd-ifname={}", params.pppd_ifname))
        .arg("--persistent=0")
        .arg(format!("--username={}", params.username))
        .arg(format!("--pinentry={}", config.pinentry))
        // No --ca-file on Linux: the mandatory pin is the trust anchor.
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
fn decode(bytes: &mut [u8]) -> io::Result<Message> {
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
        let mut bytes = match channel.receive() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Ok(Waited::Closed(error)),
        };
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
    if current.interface_mismatch && !sent.interface_mismatch {
        events.push(Event::InterfaceMismatch);
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

/// A descendant of the client, held by pidfd so a recycled pid is never signalled.
struct Member {
    pid: libc::pid_t,
    pidfd: OwnedFd,
}

/// The spawned client and what it takes to stop everything it started: its
/// process group, plus every other descendant (the PPP daemon leaves the group
/// by starting its own session), tracked by pidfd while it is alive.
struct Client {
    child: PinentryChild,
    pidfd: OwnedFd,
    group: libc::pid_t,
    reaped: bool,
    /// Where the descendant search starts: this process when it is dedicated
    /// to the client (orphans are reparented to it), else the client itself.
    own_process: bool,
    members: Vec<Member>,
}

struct Stopped {
    status: ExitStatus,
    escalated: bool,
    descendants_gone: bool,
}

impl Client {
    fn spawn(command: Command, password: Secret, own_process: bool) -> io::Result<Self> {
        let mut child = PinentryChild::spawn(command, password)?;
        let group = child.id() as libc::pid_t;
        // The child is not reaped until `poll`, so its pid is still ours.
        let pidfd = match pidfd_open(group) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                kill_group(group, libc::SIGKILL);
                let _ = child.poll();
                return Err(error);
            }
        };
        let mut client = Self {
            child,
            pidfd,
            group,
            reaped: false,
            own_process,
            members: Vec::new(),
        };
        // Fail closed where the kernel cannot list children: the client is
        // dropped (group killed, leader reaped) and the error returned.
        client.track()?;
        Ok(client)
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

    /// Add every live descendant not yet held. Returns how many were new.
    fn track(&mut self) -> io::Result<usize> {
        self.track_in(children_of)
    }

    /// `list` gives the direct children of a pid. A listed pid is held only
    /// after the process behind the opened pidfd is confirmed to be that
    /// parent's child: the pid number comes from an earlier observation, and
    /// between it and `pidfd_open` the process may have exited and the number
    /// been given to an unrelated one. The pidfd names the exact process from
    /// the open on, so reading its parent afterwards is not a second race: a
    /// process that exits first leaves a pidfd that can no longer signal anyone.
    fn track_in(
        &mut self,
        list: impl Fn(libc::pid_t) -> io::Result<Vec<libc::pid_t>>,
    ) -> io::Result<usize> {
        let root = if self.own_process {
            std::process::id() as libc::pid_t
        } else {
            self.group
        };
        let mut pending = vec![root];
        let mut added = 0;
        while let Some(parent) = pending.pop() {
            for pid in list(parent)? {
                pending.push(pid);
                if pid == self.group || self.members.iter().any(|member| member.pid == pid) {
                    continue;
                }
                match pidfd_open(pid) {
                    Ok(pidfd) => {
                        if parent_of(pid)? != Some(parent) {
                            // Not this parent's child any more: dropped, never signalled.
                            continue;
                        }
                        self.members.push(Member { pid, pidfd });
                        added += 1;
                    }
                    // Gone between the listing and the open.
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(added)
    }

    /// Signal the tracked descendants from index `from` on.
    fn signal_members(&self, signal: libc::c_int, from: usize) -> io::Result<()> {
        for member in &self.members[from..] {
            // SAFETY: the pidfd names the exact process; no pointers are used.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    member.pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0 as libc::c_uint,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// The pidfd becomes readable when the client exits, before it is reaped.
    fn wait_exit(&self, limit: Duration) -> io::Result<bool> {
        wait_readable(&self.pidfd, limit)
    }

    /// The leader is gone or a zombie: its group id is still ours, and its
    /// children now belong to this process (or to init). SIGKILL the group and
    /// every descendant, repeating until no new one shows up. `true` when a
    /// process that was still alive had to be killed here, without any grace.
    fn sweep(&mut self) -> io::Result<bool> {
        let mut killed = false;
        for _ in 0..SWEEP_PASSES {
            killed |= self.alive();
            self.signal_group(libc::SIGKILL)?;
            let added = self.track()?;
            killed |= self.alive();
            self.signal_members(libc::SIGKILL, 0)?;
            if added == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(killed)
    }

    /// Wait until the leader and every descendant have exited, for at most
    /// `limit`. Descendants that show up meanwhile get SIGTERM at once and are
    /// waited for too. `false` when something is still alive at the limit.
    fn wait_all_exit(&mut self, limit: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + limit;
        loop {
            let known = self.members.len();
            self.track()?;
            self.signal_members(libc::SIGTERM, known)?;
            if !self.alive() {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let mut fds: Vec<libc::pollfd> = std::iter::once(&self.pidfd)
                .chain(self.members.iter().map(|member| &member.pidfd))
                .filter(|fd| !exited(fd))
                .map(|fd| poll_entry(fd.as_raw_fd()))
                .collect();
            poll_fds(&mut fds, remaining.min(TICK))?;
        }
    }

    /// The leader or a tracked descendant has not exited yet.
    fn alive(&self) -> bool {
        !exited(&self.pidfd) || self.members.iter().any(|member| !exited(&member.pidfd))
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

    /// SIGTERM to the group and to every tracked descendant, then the whole set
    /// (leader and descendants, also those that appear meanwhile) gets the full
    /// grace, even when the leader exits first. SIGKILL only for what is still
    /// alive after it, and any SIGKILL of a live process is an escalation. Then a
    /// sweep that repeats until no new descendant shows up, one reap of the
    /// leader and of the orphans this process adopted.
    fn terminate(&mut self, limits: Limits) -> io::Result<Stopped> {
        self.child.revoke_password();
        let mut escalated = false;
        self.track()?;
        // The group id is ours while the leader is unreaped, zombie or not.
        self.signal_group(libc::SIGTERM)?;
        self.signal_members(libc::SIGTERM, 0)?;
        if !self.wait_all_exit(limits.grace)? {
            escalated = true;
            self.track()?;
            self.signal_group(libc::SIGKILL)?;
            self.signal_members(libc::SIGKILL, 0)?;
            if !self.wait_exit(limits.kill_wait)? {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "client exit unconfirmed",
                ));
            }
        }
        escalated |= self.sweep()?;
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
        let members_gone = self.reap_members(limits.kill_wait);
        Ok(Stopped {
            status,
            escalated,
            descendants_gone: members_gone && self.group_gone() && self.no_orphans(),
        })
    }

    /// Every tracked descendant has exited; the ones this process adopted are
    /// reaped (a pidfd of a process that is not our child gives ECHILD).
    fn reap_members(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        self.members.iter().all(|member| {
            let left = deadline.saturating_duration_since(Instant::now());
            let exited = wait_readable(&member.pidfd, left).unwrap_or(false);
            if exited {
                // SAFETY: waitid takes a pidfd and a null-able info pointer.
                unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        member.pidfd.as_raw_fd() as libc::id_t,
                        std::ptr::null_mut(),
                        libc::WEXITED | libc::WNOHANG,
                    );
                }
            }
            exited
        })
    }

    /// In a dedicated process nothing may be left under it once the client and
    /// its descendants are reaped.
    fn no_orphans(&self) -> bool {
        !self.own_process
            || children_of(std::process::id() as libc::pid_t).is_ok_and(|left| left.is_empty())
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
            let _ = self.signal_members(libc::SIGKILL, 0);
        }
    }
}

/// The pidfd is readable: the process exited (it may still be a zombie). A
/// failed poll counts as alive, the conservative answer for an escalation.
fn exited(fd: &OwnedFd) -> bool {
    wait_readable(fd, Duration::ZERO).unwrap_or(false)
}

/// Wait until the descriptor is readable (a pidfd: the process exited).
fn wait_readable(fd: &OwnedFd, limit: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + limit;
    loop {
        let mut fds = [poll_entry(fd.as_raw_fd())];
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

/// Direct children of every thread of `pid`, from `/proc/<pid>/task/*/children`.
/// A vanished process or thread has none; a kernel without the file is an error.
fn children_of(pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
    let mut found = Vec::new();
    let tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(tasks) => tasks,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(found),
        Err(error) => return Err(error),
    };
    for task in tasks {
        let path = match task {
            Ok(task) => task.path().join("children"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        match fs::read_to_string(&path) {
            Ok(text) => {
                for word in text.split_ascii_whitespace() {
                    found.push(word.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "unreadable children list")
                    })?);
                }
            }
            // The thread ended meanwhile, or the kernel lacks CONFIG_PROC_CHILDREN.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !Path::new(&format!("/proc/{pid}")).exists() {
                    continue;
                }
                let own = std::process::id();
                if !Path::new(&format!("/proc/self/task/{own}/children")).exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "kernel does not list children in /proc",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(found)
}

/// Parent of `pid` from `/proc/<pid>/stat`; `None` when the process is gone.
fn parent_of(pid: libc::pid_t) -> io::Result<Option<libc::pid_t>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        // The process exited while it was read.
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
        Err(error) => return Err(error),
    };
    // `pid (comm) state ppid ...`, and comm may hold spaces and parentheses.
    let rest = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unreadable stat"))?;
    rest.split_ascii_whitespace()
        .nth(1)
        .and_then(|word| word.parse().ok())
        .map(Some)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unreadable stat"))
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

impl Channel for super::handshake::AuthenticatedChannel {
    fn fd(&self) -> io::Result<BorrowedFd<'_>> {
        self.readable_fd()
    }

    fn receive(&mut self) -> io::Result<Datagram> {
        super::handshake::AuthenticatedChannel::receive(self)
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        super::handshake::AuthenticatedChannel::send(self, bytes)
    }
}

/// Production observer: the `ssl_output` parser shared with macOS.
impl Observer for crate::connection::ssl_output::Output {
    fn expect_interface(&mut self, name: &str) -> io::Result<()> {
        crate::connection::ssl_output::Output::expect_interface(self, name)
    }

    fn attach(&mut self, pipe: File) -> io::Result<()> {
        crate::connection::ssl_output::Output::attach(self, pipe)
    }

    fn snapshot(&self) -> Observation {
        use crate::connection::ssl::SslFailure;
        let seen = crate::connection::ssl_output::Output::snapshot(self);
        Observation {
            // The parser was told the configured name: only it is ever confirmed.
            candidate: seen.confirmed_interface,
            interface_mismatch: seen.interface_mismatch,
            failure: seen.failure.map(|failure| match failure {
                SslFailure::CredentialsRejected => Failure::CredentialsRejected,
                SslFailure::GatewayTimeout => Failure::GatewayTimeout,
            }),
            split: seen.split,
            split_count: seen.split_count,
            split_invalid: seen.split_invalid,
            dns_servers: seen.dns_servers,
            dns_domains: seen.dns_domains,
            dns_count: seen.dns_count,
            dns_invalid: seen.dns_invalid,
        }
    }

    fn finish(&mut self) {
        crate::connection::ssl_output::Output::finish(self)
    }
}

#[cfg(test)]
#[path = "fortinet_instance_tests.rs"]
mod tests;
