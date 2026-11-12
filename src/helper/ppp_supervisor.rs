//! One-shot PPP parent. A private inherited channel must authorize both this
//! supervisor and its forked child before the system PPP executable can run.
//! Only this parent holds/signals/reaps Child; the controller observes identity
//! and exit, never signals a PID from a log or configuration record.
mod raw;
mod signals;
use super::{local_socket::peer_uid, process::ManagedChild};
use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Command, ExitStatus},
    sync::atomic::Ordering,
    time::Duration,
};
pub const INHERITED_FD: i32 = 4;
pub const SYSTEM_PPP: &str = "/usr/sbin/pppd";
// openfortivpn 1.24.1 pppd_run with our fixed no-peerdns/accept-remote options.
// Validate the entire caller argv, then build a new command from these values.
pub const ARGUMENTS: &[&str] = &[
    "230400",
    ":169.254.2.1",
    "noipdefault",
    "ipcp-accept-local",
    "noaccomp",
    "noauth",
    "default-asyncmap",
    "nopcomp",
    "receive-all",
    "nodefaultroute",
    "nodetach",
    "lcp-max-configure",
    "40",
    "mru",
    "1354",
    "logfd",
    "2",
];
// Private safety options are appended by our entrypoint, never accepted from
// the C caller or IPC. ACSP is enabled by default in Apple's ppp-884 and may
// install routes/domains independently from nodefaultroute.
pub const SYSTEM_OPTIONS: &[&str] = &[
    "noacsp",
    "no-use-dhcp",
    "no-intercept-dhcp",
    "noproxyarp",
    "nopersist",
];
/// Fixed production command. Configuration admission is performed by the
/// root entrypoint before using this builder; callers cannot supply paths.
pub fn system_command() -> Command {
    let mut command = Command::new(SYSTEM_PPP);
    command.args(ARGUMENTS).args(SYSTEM_OPTIONS);
    command
}
pub fn valid_arguments(arguments: &[std::ffi::OsString]) -> bool {
    arguments.len() == ARGUMENTS.len()
        && arguments
            .iter()
            .zip(ARGUMENTS)
            .all(|(actual, expected)| actual == expected)
}

/// Reserved for a standalone supervisor executable, not a controller thread.
/// The executable must admit a fixed command before this call. Production
/// always checks real/effective root and passes expected_owner=0. Fixture
/// adapters supply their own unprivileged command/owner, never through IPC.
///
/// # Safety
/// FD 4 must be an inherited stream capability with no Rust owner/aliases.
/// FD 3 must be the inherited pinentry capability, or closed. This function
/// takes FD 4, closes FD 3, and temporarily changes process-wide signal handlers.
/// Call once, with no other threads in this supervisor process.
pub unsafe fn inherited_supervise(
    expected_owner: u32,
    mut command: Command,
) -> io::Result<ExitStatus> {
    let channel = inherited()?;
    if peer_uid(&channel)? != expected_owner {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // SAFETY: the one-shot caller reserves FD 3 as documented; never forward
    // its password capability into the PPP process, even after delivery.
    unsafe {
        libc::close(3);
    }
    let _signals = signals::Guard::install()?;
    channel.set_nonblocking(true)?;
    let fd = channel.as_raw_fd();
    let pid = std::process::id();
    raw::exchange(fd, raw::frame(*b"VPS1", pid), *b"VPA1", pid)?;
    if signals::INTERRUPTED.load(Ordering::Acquire) {
        return finish(fd, 0, Err(io::ErrorKind::Interrupted.into()));
    }
    let (read_pid, write_pid) = pipe()?;
    let announce = write_pid.as_raw_fd();
    // SAFETY: only native descriptor IO, clock/poll and lock-free atomic reads
    // run after fork. Both borrowed descriptors remain owned through spawn.
    unsafe {
        command.pre_exec(move || {
            let child = libc::getpid() as u32;
            raw::write(announce, &child.to_be_bytes(), raw::deadline()?)?;
            if signals::INTERRUPTED.load(Ordering::Acquire) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            raw::exchange(fd, raw::frame(*b"VPB1", child), *b"VPC1", child)?;
            if signals::INTERRUPTED.load(Ordering::Acquire) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        });
    }
    // Consume the command: its pre_exec captures live descriptors and cannot
    // be reused for a later spawn after their owners have closed them.
    let spawned = ManagedChild::spawn_terminal(&mut command);
    drop(command);
    drop(write_pid);
    let mut bytes = [0u8; 4];
    let announced = raw::read(read_pid.as_raw_fd(), &mut bytes, raw::deadline()?);
    let child_pid = if announced.is_ok() {
        u32::from_be_bytes(bytes)
    } else {
        0
    };
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => return finish(fd, child_pid, Err(error)),
    };
    if child_pid != child.id() {
        // The owned Child still cleans up even if its announcement was lost.
        let _ = child.stop(Duration::from_secs(1));
        return finish(fd, child.id(), Err(io::ErrorKind::InvalidData.into()));
    }
    let result = loop {
        match child.poll() {
            Ok(Some(status)) => break Ok(status),
            Err(error) => break Err(error),
            Ok(None) => {}
        }
        let revoked = match canceled(&channel) {
            Ok(revoked) => revoked,
            Err(error) => break Err(error),
        };
        if signals::INTERRUPTED.load(Ordering::Acquire) || revoked {
            break child
                .stop(Duration::from_secs(1))
                .map(|outcome| outcome.status);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // No final receipt until the direct child has actually been waited. Even
    // an IO error must attempt owned-handle cleanup before reporting failure.
    let result = match result {
        Ok(status) => Ok(status),
        Err(error) => {
            child.stop(Duration::from_secs(1))?;
            Err(error)
        }
    };
    finish(fd, child_pid, result)
}
fn finish(fd: i32, child: u32, result: io::Result<ExitStatus>) -> io::Result<ExitStatus> {
    raw::write(fd, &raw::frame(*b"VPF1", child), raw::deadline()?)?;
    result
}
fn canceled(channel: &UnixStream) -> io::Result<bool> {
    let mut byte = [0u8];
    // SAFETY: the owned nonblocking socket and byte output remain live. EOF
    // and any unexpected control data revoke this supervisor's child lease.
    let count = unsafe {
        libc::recv(
            channel.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK,
        )
    };
    if count >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(false),
        _ => Err(error),
    }
}
fn inherited() -> io::Result<UnixStream> {
    // SAFETY: descriptor queries have no memory preconditions.
    if unsafe { libc::fcntl(INHERITED_FD, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut kind = 0i32;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: SO_TYPE writes to a correctly sized live integer output.
    if unsafe {
        libc::getsockopt(
            INHERITED_FD,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
        || length as usize != std::mem::size_of_val(&kind)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: the caller transfers this verified descriptor exactly once.
    let channel = unsafe { UnixStream::from_raw_fd(INHERITED_FD) };
    // SAFETY: set close-on-exec on the live owned capability. The fork gate
    // can use it before exec, but the PPP program cannot inherit it.
    if unsafe { libc::fcntl(INHERITED_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(channel)
}
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: pipe initializes exactly two descriptor outputs.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: each new descriptor is transferred to one owner, including error cleanup.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    for fd in [&read, &write] {
        // SAFETY: integer flags on live owned descriptors only.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}
