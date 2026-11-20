//! Linux socket activation, bounded admission, and the v1 dialogue.
use super::admin::PolicyStore;
use super::protocol::{
    ErrorCode, FrameError, Request, Response, ServerDecoder, decode_request, read_control, timed,
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

struct Server {
    connections: Mutex<Connections>,
    policy: PolicyStore,
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

#[cfg(test)]
impl Default for Server {
    fn default() -> Self {
        Self::new(PolicyStore::unavailable_for_test())
    }
}

impl Server {
    fn new(policy: PolicyStore) -> Self {
        Self {
            connections: Mutex::default(),
            policy,
        }
    }

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
            let _ = serve(stream, &slot.admission, &slot.server.policy, accepted);
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

fn serve(
    stream: UnixStream,
    admission: &Admission,
    policy: &PolicyStore,
    accepted: Instant,
) -> Result<(), FrameError> {
    let hello_deadline = accepted + FRAME_TIMEOUT;
    let Admission::Session(uid) = *admission else {
        let mut hello_io = timed(&stream, hello_deadline)?;
        let code = match read_control(&mut hello_io, decode_request) {
            Ok(Request::Hello { .. }) => ErrorCode::Busy,
            Err(FrameError::Protocol(ErrorCode::UnsupportedVersion)) => {
                ErrorCode::UnsupportedVersion
            }
            Ok(_) | Err(FrameError::Protocol(_)) => ErrorCode::BadRequest,
            Err(error) => return Err(error),
        };
        return write_control(&mut hello_io, &Response::Error { code });
    };

    // Keep a handle for the D1b typed errors when the v1 decoder has already
    // consumed its handle. Both handles are scoped to this connection.
    let mut decoder = ServerDecoder::new(stream.try_clone()?);
    match decoder.hello(hello_deadline) {
        Err(FrameError::Protocol(ErrorCode::BadRequest)) => {
            return reply_error(&stream, ErrorCode::BadRequest, hello_deadline);
        }
        result => result?,
    }

    let prepare_deadline = Instant::now() + FRAME_TIMEOUT;
    let offer = match decoder.prepare(prepare_deadline) {
        Ok(offer) => offer,
        Err(FrameError::Protocol(_)) => {
            return reply_error(&stream, ErrorCode::BadRequest, prepare_deadline);
        }
        Err(error) => return Err(error),
    };
    let previous = policy.open().and_then(|directory| directory.read()).ok();
    let Some((previous, grant)) = previous.as_ref().and_then(|snapshot| {
        snapshot
            .policy()
            .authorize(uid, &offer)
            .map(|grant| (snapshot, grant))
    }) else {
        return decoder.reject(ErrorCode::PermissionDenied, prepare_deadline);
    };
    decoder.prepared(prepare_deadline)?;

    let credential_deadline = Instant::now() + FRAME_TIMEOUT;
    let credentials = decoder.credentials(credential_deadline)?;
    let current = (|| -> io::Result<bool> {
        let directory = policy.open()?;
        directory.lock_shared()?;
        let current = directory.read()?;
        // An atomic replacement is a new version even when the same grant
        // was revoked and then restored before this phase.
        Ok(previous.unchanged(&current)? && current.policy().authorize(uid, &offer) == Some(grant))
    })();
    drop(credentials);
    let code = match current {
        Ok(true) => ErrorCode::MissingProgram,
        _ => ErrorCode::PermissionDenied,
    };
    decoder.reject(code, credential_deadline)
}

fn reply_error(stream: &UnixStream, code: ErrorCode, deadline: Instant) -> Result<(), FrameError> {
    write_control(&mut timed(stream, deadline)?, &Response::Error { code })
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

    let server = Arc::new(Server::new(PolicyStore::default()));
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

#[cfg(test)]
use super::protocol::VERSION;

#[cfg(test)]
mod policy_dialogue_tests {
    use super::*;
    use crate::tunneld::{admin::PolicyFixture, protocol::Credentials};
    use std::io::{Read, Write};

    fn run(
        policy: &PolicyFixture,
        port: u16,
        network: &str,
        after_prepared: impl FnOnce(),
    ) -> ErrorCode {
        let server = Arc::new(Server::new(policy.store.clone()));
        let (mut client, stream) = UnixStream::pair().unwrap();
        let worker = server.dispatch(stream, |_| Ok(1000)).unwrap();
        client
            .write_all(b"{\"op\":\"hello\",\"version\":1}\n")
            .unwrap();
        assert!(matches!(tests_receive(&client), Response::Version { .. }));
        writeln!(client, r#"{{"op":"prepare_ipsec","endpoint":{{"host":"vpn.example","port":{port}}},"username":"fixture","networks":[{{"network":"{network}","prefix":16}}]}}"#).unwrap();
        let mut response = tests_receive(&client);
        if matches!(response, Response::Prepared {}) {
            after_prepared();
            Credentials::ipsec("fixture-password", "fixture-psk")
                .unwrap()
                .write(&mut client)
                .unwrap();
            response = tests_receive(&client);
        }
        let Response::Error { code } = response else {
            panic!("unexpected {response:?}")
        };
        assert_eq!(
            timed(&client, Instant::now() + FRAME_TIMEOUT)
                .unwrap()
                .read(&mut [0])
                .unwrap(),
            0
        );
        worker.join().unwrap();
        code
    }

    fn tests_receive(stream: &UnixStream) -> Response {
        read_control(
            &mut timed(stream, Instant::now() + FRAME_TIMEOUT).unwrap(),
            super::super::protocol::decode_response,
        )
        .unwrap()
    }

    #[test]
    fn policy_before_prepared_and_after_credentials() {
        let fixture = PolicyFixture::new();
        let denied = || panic!("an unauthorized request reached Prepared");
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", denied),
            ErrorCode::PermissionDenied
        );
        fixture.install();
        std::fs::write(fixture.path(), b"invalid").unwrap();
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", denied),
            ErrorCode::PermissionDenied
        );
        std::fs::remove_file(fixture.path()).unwrap();
        fixture.install();
        assert_eq!(
            run(&fixture, 501, "10.20.0.0", denied),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            run(&fixture, 500, "10.22.0.0", denied),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || {}),
            ErrorCode::MissingProgram
        );
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || {
                fixture.revoke();
                fixture.install();
            }),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || fixture.revoke()),
            ErrorCode::PermissionDenied
        );
    }
}
