//! One inherited socket capability per owned SSL child. No filesystem endpoint,
//! password argument/environment, or hint-based credential lookup is involved.
use super::{
    local_socket::{TimedStream, peer_uid},
    pinentry,
    process::{ManagedChild, StopOutcome},
};
use crate::{
    model::VpnKind,
    secrets::{Credentials, Secret},
};
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{ChildStderr, ChildStdout, Command, ExitStatus},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use zeroize::Zeroizing;

const INHERITED_FD: libc::c_int = 3;
const TIMEOUT: Duration = Duration::from_secs(5);
const MAGIC: &[u8; 4] = b"VPT1";

/// A driver must admit the executable first. Command is consumed so its
/// pre_exec closure, which borrows a live socket descriptor, cannot be reused.
pub struct PinentryChild {
    child: ManagedChild,
    lease: Lease,
}

impl PinentryChild {
    pub fn spawn(mut command: Command, password: Secret) -> io::Result<Self> {
        let credentials = Credentials {
            password,
            psk: Secret::from(""),
        };
        credentials
            .validate(VpnKind::Ssl)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let (server, child_socket) = UnixStream::pair()?;
        let descriptor = child_socket.as_raw_fd();
        // SAFETY: only async-signal-safe descriptor operations run after fork.
        // child_socket stays owned/live through spawn. All stdio descriptors
        // have already been set by Command before this hook runs. Command is
        // local and consumed; no stale raw descriptor remains for another spawn.
        unsafe {
            command.pre_exec(move || {
                if descriptor != INHERITED_FD && libc::dup2(descriptor, INHERITED_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(INHERITED_FD, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = ManagedChild::spawn(&mut command)?;
        drop(child_socket);
        // Unexpected interactive input must fail instead of waiting on the UI.
        drop(child.take_stdin());
        let lease = Lease::start(server, child.id(), credentials.password)?;
        Ok(Self { child, lease })
    }
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.take_stdout()
    }
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.take_stderr()
    }
    pub fn revoke_password(&mut self) {
        self.lease.revoke();
    }
    pub fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.poll()?;
        if status.is_some() {
            self.lease.revoke();
        }
        Ok(status)
    }
    pub fn stop(&mut self, grace: Duration) -> io::Result<StopOutcome> {
        self.lease.revoke();
        self.child.stop(grace)
    }
}
impl Drop for PinentryChild {
    fn drop(&mut self) {
        self.lease.revoke();
    }
}

struct Lease {
    shutdown: Arc<Mutex<Option<UnixStream>>>,
    worker: Option<JoinHandle<()>>,
}
impl Lease {
    fn start(socket: UnixStream, pid: u32, password: Secret) -> io::Result<Self> {
        let shutdown = Arc::new(Mutex::new(Some(socket.try_clone()?)));
        let worker_shutdown = Arc::clone(&shutdown);
        let mut stream = TimedStream::new(socket, TIMEOUT, 9)?;
        let worker = thread::Builder::new()
            .name("vpnt-pinentry".into())
            .spawn(move || {
                let _ = deliver(&mut stream, pid, password);
                // Darwin may return ENOTCONN for SHUT_RDWR after the peer has
                // half-closed its request. Close every server-side descriptor
                // after delivery instead of relying on shutdown to signal EOF.
                close_control(&worker_shutdown);
            })?;
        Ok(Self {
            shutdown,
            worker: Some(worker),
        })
    }
    fn revoke(&mut self) {
        close_control(&self.shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // After this returns no worker can deliver another byte. A request
        // already delivered before revocation cannot be retracted.
    }
}

fn close_control(control: &Mutex<Option<UnixStream>>) {
    let socket = control
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(socket) = socket {
        let _ = socket.shutdown(Shutdown::Both);
    }
}

fn deliver(stream: &mut TimedStream, pid: u32, password: Secret) -> io::Result<()> {
    let mut request = [0; 8];
    stream.read_exact(&mut request)?;
    let mut extra = [0];
    if &request[..4] != MAGIC
        || u32::from_be_bytes(request[4..].try_into().unwrap()) != pid
        || stream.read(&mut extra)? != 0
    {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut response = Zeroizing::new(Vec::with_capacity(258));
    response.extend_from_slice(&(password.expose().len() as u16).to_be_bytes());
    response.extend_from_slice(password.expose().as_bytes());
    stream.write_all(&response)?;
    stream.flush()
}

/// Used only by the fixed pinentry executable. In production expected_owner is
/// always 0. The socket was inherited from our owned openfortivpn parent, not
/// discovered by path or selected by SETKEYINFO. Taking FD 3 sets CLOEXEC so
/// this adapter cannot pass the capability to a subsequent exec.
///
/// # Safety
/// FD 3 must be reserved for this inherited capability, with no Rust owner and
/// no concurrent use. This function takes/closes it and must be called once.
pub unsafe fn inherited_password(expected_owner: u32) -> Result<Secret, pinentry::Error> {
    inherited()
        .and_then(|socket| fetch(socket, expected_owner))
        .map_err(|_| pinentry::Error::Unavailable)
}

fn inherited() -> io::Result<UnixStream> {
    // Check validity before transferring ownership; FromRawFd requires a live FD.
    // SAFETY: fcntl reads flags and takes no pointer.
    if unsafe { libc::fcntl(INHERITED_FD, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut kind: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: the live FD is queried into a correctly sized integer buffer.
    if unsafe {
        libc::getsockopt(
            INHERITED_FD,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
        || length as usize != std::mem::size_of_val(&kind)
    {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: FD 3 is a valid stream socket provided to this one-shot adapter.
    let socket = unsafe { UnixStream::from_raw_fd(INHERITED_FD) };
    // SAFETY: socket owns the descriptor and F_SETFD takes integer flags.
    if unsafe { libc::fcntl(INHERITED_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn fetch(socket: UnixStream, owner: u32) -> io::Result<Secret> {
    if peer_uid(&socket)? != owner {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let mut stream = TimedStream::new(socket, TIMEOUT, 259)?;
    let mut request = [0; 8];
    request[..4].copy_from_slice(MAGIC);
    // SAFETY: getppid has no memory preconditions. A reparented adapter cannot
    // match the still-owned child PID and therefore receives no credentials.
    let parent = unsafe { libc::getppid() } as u32;
    request[4..].copy_from_slice(&parent.to_be_bytes());
    stream.write_all(&request)?;
    stream.shutdown_write()?;
    let mut header = [0; 2];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes(header) as usize;
    if !(1..=256).contains(&length) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut bytes)?;
    let mut extra = [0];
    if stream.read(&mut extra)? != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let value =
        std::str::from_utf8(&bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let credentials = Credentials {
        password: Secret::from(value),
        psk: Secret::from(""),
    };
    credentials
        .validate(VpnKind::Ssl)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(credentials.password)
}
