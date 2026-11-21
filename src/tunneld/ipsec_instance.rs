//! Lifecycle of the stock charon inside an authenticated Linux IPsec unit.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::handshake::AuthenticatedChannel;

const CHARON: &str = "/usr/lib/strongswan/charon";
const TERM_GRACE: Duration = Duration::from_secs(3);

/// Local unit configuration. The directory must be unused and below the
/// unit's trusted mounts. It must never be taken from a channel datagram.
pub struct Params {
    pub directory: PathBuf,
}

/// One command per authenticated datagram. No parameters cross this channel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Order {
    Start,
    Stop,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Exit {
    Stopped,
    Eof,
}

/// Run in the instance's main thread after `handshake::connect_instance`.
/// The unit must provide a private view of stock charon's compiled PIDDIR
/// and contain descendants in its cgroup, including during supervisor loss.
pub fn run(mut channel: AuthenticatedChannel, params: Params) -> io::Result<Exit> {
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
    run_with(
        || decode_order(&channel.receive()?),
        &params,
        Path::new(CHARON),
        (0, 0),
    )
}

fn decode_order(bytes: &[u8]) -> io::Result<Order> {
    serde_json::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn run_with(
    mut receive: impl FnMut() -> io::Result<Order>,
    params: &Params,
    program: &Path,
    owner: (u32, u32),
) -> io::Result<Exit> {
    // SAFETY: PR_SET_DUMPABLE takes an integer value. The handshake applies
    // the same protection before it opens the channel.
    checked(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    match receive() {
        Ok(Order::Start) => {}
        Ok(Order::Stop) => return Err(invalid("expected IPsec start")),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(Exit::Eof),
        Err(error) => return Err(error),
    }

    let directory = &params.directory;
    let socket = validate_path(directory)?;
    check_parent(
        directory
            .parent()
            .ok_or_else(|| invalid("missing parent"))?,
        owner.0,
    )?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    let result = run_in_directory(receive, directory, &socket, program, owner);
    with_cleanup(result, fs::remove_dir_all(directory))
}

fn run_in_directory(
    mut receive: impl FnMut() -> io::Result<Order>,
    directory: &Path,
    socket: &str,
    program: &Path,
    owner: (u32, u32),
) -> io::Result<Exit> {
    let metadata = fs::symlink_metadata(directory)?;
    if (metadata.uid(), metadata.gid()) != owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected IPsec instance directory owner",
        ));
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let path = directory.join("strongswan.conf");
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

    let result = match receive() {
        Ok(Order::Stop) => Ok(Exit::Stopped),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(Exit::Eof),
        Ok(Order::Start) => Err(invalid("IPsec instance already started")),
        Err(error) => Err(error),
    };
    let cleanup = stop_child(&mut child, &pidfd);
    with_cleanup(result, cleanup)
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
    let socket = format!("{path}/vici.sock");
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
