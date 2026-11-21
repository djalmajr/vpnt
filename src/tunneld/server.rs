//! Linux socket activation, bounded admission, and the closed v1 dialogue.
use super::protocol::{
    ErrorCode, FrameError, Request, Response, VERSION, decode_request, read_control, timed,
    write_control,
};
use crate::helper::local_socket::peer_uid;
use std::{
    collections::HashMap,
    ffi::OsString,
    io,
    os::{
        fd::{FromRawFd, RawFd},
        unix::net::{UnixListener, UnixStream},
    },
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PER_UID: usize = 2;
const MAX_CONNECTIONS: usize = 8;
const LISTEN_FD: RawFd = 3;

#[derive(Default)]
struct Server {
    connections: Mutex<Connections>,
}

#[derive(Default)]
struct Connections {
    active: HashMap<u32, usize>,
    rejecting: bool,
}

enum Admission {
    Session(u32),
    Busy,
}

struct Slot {
    server: Arc<Server>,
    admission: Admission,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut connections = self.server.connections.lock().expect("connection slots");
        match self.admission {
            Admission::Session(uid) => {
                let count = connections.active.get_mut(&uid).expect("reserved UID");
                *count -= 1;
                if *count == 0 {
                    connections.active.remove(&uid);
                }
            }
            Admission::Busy => connections.rejecting = false,
        }
    }
}

impl Server {
    fn reserve(self: &Arc<Self>, uid: u32) -> Option<Slot> {
        let mut connections = self.connections.lock().expect("connection slots");
        let count = connections.active.get(&uid).copied().unwrap_or_default();
        let admission = if count < MAX_PER_UID
            && connections.active.values().sum::<usize>() < MAX_CONNECTIONS
        {
            *connections.active.entry(uid).or_default() += 1;
            Admission::Session(uid)
        } else {
            // A separate slot lets one over-limit peer finish its hello without
            // occupying the listener or starting unbounded refusal workers.
            if connections.rejecting {
                return None;
            }
            connections.rejecting = true;
            Admission::Busy
        };
        Some(Slot {
            server: Arc::clone(self),
            admission,
        })
    }

    fn dispatch(
        self: &Arc<Self>,
        stream: UnixStream,
        identify: impl FnOnce(&UnixStream) -> io::Result<u32>,
    ) -> Option<thread::JoinHandle<()>> {
        let accepted = Instant::now();
        let uid = identify(&stream).ok()?;
        if uid == 0 {
            return None;
        }
        let slot = self.reserve(uid)?;
        match thread::Builder::new().spawn(move || {
            // Peers can close either phase or fail to send a complete frame.
            let _ = serve(stream, &slot.admission, accepted);
            drop(slot);
        }) {
            Ok(worker) => Some(worker),
            Err(error) => {
                eprintln!("vpnt-tunneld: could not start connection worker: {error}");
                None
            }
        }
    }
}

fn serve(stream: UnixStream, admission: &Admission, accepted: Instant) -> Result<(), FrameError> {
    // The protocol's stateful decoder consumes the connection on a parse
    // error. Use its framing and request parser so we can reply before closing.
    let mut hello_io = timed(&stream, accepted + FRAME_TIMEOUT)?;
    let hello_error = match read_control(&mut hello_io, decode_request) {
        Ok(Request::Hello { .. }) if matches!(admission, Admission::Busy) => Some(ErrorCode::Busy),
        Ok(Request::Hello { .. }) => None,
        Err(FrameError::Protocol(ErrorCode::UnsupportedVersion)) => {
            Some(ErrorCode::UnsupportedVersion)
        }
        Ok(_) | Err(FrameError::Protocol(_)) => Some(ErrorCode::BadRequest),
        Err(error) => return Err(error),
    };
    if let Some(code) = hello_error {
        return write_control(&mut hello_io, &Response::Error { code });
    }
    write_control(&mut hello_io, &Response::Version { version: VERSION })?;
    drop(hello_io);

    let mut request_io = timed(&stream, Instant::now() + FRAME_TIMEOUT)?;
    let code = match read_control(&mut request_io, decode_request) {
        Ok(Request::PrepareIpsec(_) | Request::PrepareFortinet(_)) => ErrorCode::PermissionDenied,
        Ok(_) | Err(FrameError::Protocol(_)) => ErrorCode::BadRequest,
        Err(error) => return Err(error),
    };
    write_control(&mut request_io, &Response::Error { code })
}

fn activation_requested() -> bool {
    std::env::var("LISTEN_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
        == Some(std::process::id())
        && std::env::var("LISTEN_FDS").as_deref() == Ok("1")
}

fn check_listener(fd: RawFd) -> io::Result<()> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_STREAM),
        (libc::SO_ACCEPTCONN, 1),
    ] {
        let mut value: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: value and size point to writable storage for this socket option.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if value != expected || size as usize != std::mem::size_of_val(&value) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(())
}

/// Run the standalone daemon on its inherited systemd socket.
///
/// # Safety
/// Call only from standalone main before starting threads. If activation is
/// valid, this call takes exclusive ownership of descriptor 3.
pub unsafe fn run_linux(args: &[OsString]) -> i32 {
    let activated = activation_requested();
    // SAFETY: the caller guarantees standalone, single-threaded startup.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    if !args.is_empty() || !activated || check_listener(LISTEN_FD).is_err() {
        return 64;
    }
    // SAFETY: descriptor 3 is validated above and is exclusively ours.
    let listener = unsafe { UnixListener::from_raw_fd(LISTEN_FD) };
    // SAFETY: the listener owns the validated descriptor.
    if unsafe { libc::fcntl(LISTEN_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        eprintln!(
            "vpnt-tunneld: could not set close-on-exec: {}",
            io::Error::last_os_error()
        );
        return 1;
    }

    let server = Arc::new(Server::default());
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                server.dispatch(stream, peer_uid);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                eprintln!("vpnt-tunneld: could not accept connection: {error}");
                return 1;
            }
        }
    }
    0
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
