//! Private FD3 datagram capability for the owned charon child.
//!
//! The helper creates an anonymous `SOCK_DGRAM` pair, remaps the child endpoint
//! to FD 3 in `pre_exec`, and keeps only the parent endpoint. The child sends
//! exactly one descriptor with one fixed payload. The received descriptor is an
//! unadmitted capability: this module grants no UTUN, route, type or cleanup
//! authority, and it never reads or writes the received object.
//!
//! Authentication is the inherited anonymous socket itself. Datagram peer
//! credentials are not a boundary on this host (`getpeereid` returns EINVAL for
//! a `UnixDatagram` pair), so nothing here reads a peer UID or PID; the
//! admission is bound to the original `ManagedChild` instead, and the later
//! producer slice must check the same socket through the SDK.

use super::{
    fd_guard,
    local_socket::Budget,
    process::{Authority, Environment, ManagedChild},
};
use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{net::UnixDatagram, process::CommandExt},
    },
    path::Path,
    process::Command,
};

mod receive;

/// The only inherited descriptor slot of this protocol.
const INHERITED_FD: RawFd = 3;
/// Longest single readiness wait, so a silent child cannot delay its own exit
/// signal past one poll slice.
const POLL_SLICE: i32 = 25;

/// An owned descriptor from our child. Fields stay private so no caller can
/// turn it into a name/path lookup or assume a type.
pub(crate) struct Descriptor(OwnedFd);

impl Descriptor {
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Single-use admission bound to the exact child spawn authority.
pub(crate) struct Receiver {
    pid: u32,
    /// The exact allocation the returned `ManagedChild` was spawned with. A
    /// recycled PID cannot reproduce it, so identity survives `reap`; the
    /// handle keeps the allocation alive as long as this receiver exists.
    authority: Authority,
    /// Taken by the first `receive`, which makes every outcome terminal and
    /// drops the endpoint so rights queued later have no reader.
    socket: Option<UnixDatagram>,
}

impl Receiver {
    /// Any call consumes the admission, including a wrong-child or exited-child
    /// check, so a failure can never be replayed. The child must be the exact
    /// `ManagedChild` returned by `spawn`; no lookup by name or PID exists.
    pub(crate) fn receive(
        &mut self,
        child: &mut ManagedChild,
        budget: &Budget,
    ) -> io::Result<Descriptor> {
        let Some(socket) = self.socket.take() else {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        };
        if child.id() != self.pid || !child.authority().matches(&self.authority) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        loop {
            await_message(socket.as_raw_fd(), child, budget)?;
            // Only the kernel install and the CLOEXEC marking of already
            // delivered descriptors stay inside the helper-wide guard; every
            // readiness wait happened outside it.
            let collected = {
                let _guard = fd_guard::receive(budget)?;
                receive::collect(socket.as_raw_fd())?
            };
            match collected {
                receive::Collected::Ready(descriptor) => {
                    if child.poll()?.is_some() {
                        // The descriptor is dropped here, so a child that dies
                        // after sending still hands nothing over.
                        return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                    }
                    return Ok(Descriptor(descriptor));
                }
                receive::Collected::Retry => continue,
            }
        }
    }
}

fn await_message(fd: RawFd, child: &mut ManagedChild, budget: &Budget) -> io::Result<()> {
    loop {
        if child.poll()?.is_some() {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        budget.check()?;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = budget.poll_timeout()?.min(POLL_SLICE);
        // SAFETY: one live descriptor and an initialized output struct.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
            continue;
        }
        if result > 0 {
            // Readiness is handled without re-checking the budget: a datagram
            // may already be queued, and it must be received and closed rather
            // than abandoned on a deadline.
            return Ok(());
        }
    }
}

/// Spawns the owned charon command with the capability on FD 3 and returns its
/// single-use receiver. The caller still owns the child handle and the normal
/// stop path; this function neither reaps nor signals anything.
pub(crate) fn spawn(
    command: Command,
    configuration: &Path,
) -> io::Result<(ManagedChild, Receiver)> {
    // The pair is not created atomically close-on-exec, so endpoint creation,
    // flagging and duplication share the same helper-wide guard as spawning and
    // reception: no fork can observe an endpoint that is not yet CLOEXEC.
    let (parent, child_socket, child_copy) = {
        let _guard = fd_guard::spawn();
        let (parent, child_socket) = UnixDatagram::pair()?;
        set_cloexec(parent.as_raw_fd())?;
        set_cloexec(child_socket.as_raw_fd())?;
        let child_copy = high(child_socket.as_raw_fd())?;
        (parent, child_socket, child_copy)
    };
    // Keep the source above the fixed target so assigning FD 3 cannot overwrite
    // the descriptor this closure later duplicates.
    let source = child_copy.as_raw_fd();
    let mut command = command;
    // SAFETY: only dup2/fcntl run after fork; both descriptors stay live through
    // spawn; Command is consumed so this hook cannot be reused.
    unsafe {
        command.pre_exec(move || {
            if source != INHERITED_FD && libc::dup2(source, INHERITED_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(INHERITED_FD, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = ManagedChild::spawn_with_environment(
        &mut command,
        Environment::Charon(configuration.to_owned()),
    )?;
    // The child owns its inherited endpoint; the helper keeps only the parent.
    drop(child_copy);
    drop(child_socket);
    let receiver = Receiver {
        pid: child.id(),
        authority: child.authority(),
        socket: Some(parent),
    };
    Ok((child, receiver))
}

fn high(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: duplicate a live descriptor above the stdio and protocol targets.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the duplicate is a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(test)]
mod tests;

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: the socket pair owns these live descriptors.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
