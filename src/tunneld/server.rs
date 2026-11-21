//! Linux socket activation, bounded admission, and the v1 dialogue.
use super::admin::PolicyStore;
use super::backend::{Launch, Launcher, Running};
#[cfg(test)]
use super::protocol::Prepare;
use super::protocol::{
    Command, ErrorCode, FrameError, Request, Response, ServerDecoder, decode_request, read_control,
    timed, write_control,
};
use crate::{helper::local_socket::peer_uid, netd::iproute::IpRoute};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::net::{UnixListener, UnixStream},
    },
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_IDLE_MS: libc::c_int = 24 * 60 * 60 * 1000;
const MAX_PER_UID: usize = 2;
const MAX_CONNECTIONS: usize = 8;
const LISTEN_FD: RawFd = 3;

struct Server {
    connections: Mutex<Connections>,
    policy: PolicyStore,
    launcher: Box<dyn Launch>,
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
        Self::with_launcher(
            PolicyStore::unavailable_for_test(),
            Box::new(policy_dialogue_tests::Unavailable),
        )
    }
}

impl Server {
    fn new(policy: PolicyStore) -> io::Result<Self> {
        let launcher = Launcher::system(IpRoute::system());
        launcher.recover()?;
        Ok(Self::with_launcher(policy, Box::new(launcher)))
    }

    fn with_launcher(policy: PolicyStore, launcher: Box<dyn Launch>) -> Self {
        Self {
            connections: Mutex::default(),
            policy,
            launcher,
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
            let _ = serve(
                stream,
                &slot.admission,
                &slot.server.policy,
                &*slot.server.launcher,
                accepted,
            );
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
    launcher: &dyn Launch,
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
    let read_policy = || {
        let directory = policy.open()?;
        let _lock = directory.lock_shared()?;
        directory.read()
    };
    let previous = read_policy().ok();
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
    let current = (|| -> io::Result<Option<File>> {
        let directory = policy.open()?;
        let lock = directory.lock_shared()?;
        let current = directory.read()?;
        // Lock order is policy, then network. The launcher retains the
        // policy guard through lease registration and the unit start request.
        // Administrative changes take only the policy lock.
        Ok((previous.unchanged(&current)?
            && current.policy().authorize(uid, &offer) == Some(grant))
        .then_some(lock))
    })();
    let Ok(Some(authorization)) = current else {
        return decoder.reject(ErrorCode::PermissionDenied, credential_deadline);
    };
    let session = match launcher.launch(&offer, grant, credentials, authorization) {
        Ok(session) => session,
        Err(code) => return decoder.reject(code, Instant::now() + FRAME_TIMEOUT),
    };
    dialogue(&stream, decoder, session)
}

/// Answer the client's commands for one admitted session. A stop, a closed
/// client, a malformed command or a failed reply all end in the same teardown,
/// which dropping the session runs when no stop already did.
fn dialogue(
    stream: &UnixStream,
    mut decoder: ServerDecoder,
    mut session: Box<dyn Running + '_>,
) -> Result<(), FrameError> {
    loop {
        // Wait on the authenticated supervisor pidfd as well as client
        // traffic. A silent client must not keep a dead instance's network.
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: session.peer().map_or(-1, |peer| peer.as_raw_fd()),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: poll uses these two live descriptors and initializes revents.
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, SESSION_IDLE_MS) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready == 0 {
                return Err(io::Error::from(io::ErrorKind::TimedOut).into());
            }
            if fds[1].revents != 0 {
                session.stop();
            }
            if fds[0].revents != 0 {
                break;
            }
        }
        let state = match decoder.command(Instant::now() + FRAME_TIMEOUT) {
            Ok(Command::Status) => session.state(),
            Ok(Command::Stop) => session.stop(),
            Err(error) => return Err(error),
        };
        decoder.reply_status(state, Instant::now() + FRAME_TIMEOUT)?;
    }
}

#[cfg(test)]
pub(super) fn serve_fixture(
    stream: UnixStream,
    policy: &PolicyStore,
    launcher: &dyn Launch,
) -> Result<(), FrameError> {
    serve(
        stream,
        &Admission::Session(1000),
        policy,
        launcher,
        Instant::now(),
    )
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

    let server = match Server::new(PolicyStore::default()) {
        Ok(server) => Arc::new(server),
        Err(error) => {
            eprintln!("vpnt-tunneld: startup recovery is unproven: {error}");
            return 1;
        }
    };
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
    use crate::tunneld::{
        admin::{PolicyFixture, acquire_eventually},
        handshake::Backend,
        protocol::{Credentials, State},
    };
    use std::{
        fs::{self, File, Permissions},
        io::{BufRead, BufReader, Read, Write},
        os::unix::fs::PermissionsExt,
        process::{Child, Command as Process, Stdio},
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// A launcher that refuses with `Backend`: reaching it means admission
    /// was authorized by the policy.
    pub(super) struct Unavailable;

    impl Launch for Unavailable {
        fn launch<'a>(
            &'a self,
            _: &Prepare,
            _: &super::super::policy::Entry,
            _: super::super::protocol::Credentials,
            _: File,
        ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
            Err(ErrorCode::Backend)
        }
    }

    fn run(
        policy: &PolicyFixture,
        port: u16,
        network: &str,
        after_prepared: impl FnOnce(),
    ) -> ErrorCode {
        let server = Arc::new(Server::with_launcher(
            policy.store.clone(),
            Box::new(Unavailable),
        ));
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
    fn policy_without_dedicated_lock_is_denied_before_prepared() {
        let fixture = PolicyFixture::new();
        let snapshot =
            super::super::policy::canonical_snapshot(super::super::admin::IPSEC_SNAPSHOT).unwrap();
        fs::write(fixture.path(), snapshot).unwrap();
        fs::set_permissions(fixture.path(), Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || panic!(
                "reached Prepared without a lock"
            )),
            ErrorCode::PermissionDenied
        );
        assert!(!fixture.lock_path().exists());
    }

    #[test]
    fn directory_lock_in_another_process_does_not_block_policy() {
        const FIXTURE_DIR: &str = "VPNT_TEST_POLICY_LOCK_DIRECTORY";
        if let Some(path) = std::env::var_os(FIXTURE_DIR) {
            let directory = File::open(path).unwrap();
            acquire_eventually(|| directory.try_lock().map_err(io::Error::from)).unwrap();
            println!("fixture directory locked");
            io::stdout().flush().unwrap();
            io::stdin().read_to_end(&mut Vec::new()).unwrap();
            return;
        }

        struct DirectoryLockProcess(Child);
        impl Drop for DirectoryLockProcess {
            fn drop(&mut self) {
                drop(self.0.stdin.take());
                self.0.wait().expect("reap directory lock fixture");
            }
        }

        let fixture = PolicyFixture::new();
        let path = fixture.path();
        let directory = path.parent().unwrap();
        fs::set_permissions(directory, Permissions::from_mode(0o755)).unwrap();
        let mut holder = DirectoryLockProcess(
            Process::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tunneld::server::policy_dialogue_tests::directory_lock_in_another_process_does_not_block_policy",
                    "--nocapture",
                ])
                .env_clear()
                .env(FIXTURE_DIR, directory)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = BufReader::new(holder.0.stdout.take().unwrap());
        assert!(
            (&mut stdout)
                .lines()
                .any(|line| line.unwrap().ends_with("fixture directory locked")),
            "child did not acquire the fixture directory lock"
        );

        fixture.install();
        let policy_directory = fixture.store.open().unwrap();
        drop(acquire_eventually(|| policy_directory.lock_shared()).unwrap());
        assert_eq!(run(&fixture, 500, "10.20.0.0", || {}), ErrorCode::Backend);
        drop(holder.0.stdin.take());
        assert!(holder.0.wait().unwrap().success());
    }

    #[test]
    fn unavailable_dedicated_lock_denies_policy_at_each_read() {
        let fixture = PolicyFixture::new();
        fixture.install();
        let lock = File::open(fixture.lock_path()).unwrap();
        acquire_eventually(|| lock.try_lock().map_err(io::Error::from)).unwrap();
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || panic!(
                "reached Prepared with a contended lock"
            )),
            ErrorCode::PermissionDenied
        );
        drop(lock);
        let directory = fixture.store.open().unwrap();
        drop(acquire_eventually(|| directory.lock_shared()).unwrap());
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || {
                fs::set_permissions(fixture.lock_path(), Permissions::from_mode(0o640)).unwrap();
            }),
            ErrorCode::PermissionDenied
        );
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
        let directory = fixture.store.open().unwrap();
        drop(acquire_eventually(|| directory.lock_shared()).unwrap());
        assert_eq!(
            run(&fixture, 501, "10.20.0.0", denied),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            run(&fixture, 500, "10.22.0.0", denied),
            ErrorCode::PermissionDenied
        );
        assert_eq!(run(&fixture, 500, "10.20.0.0", || {}), ErrorCode::Backend);
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || {
                fixture.revoke();
                fixture.install();
                drop(acquire_eventually(|| directory.lock_shared()).unwrap());
            }),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            run(&fixture, 500, "10.20.0.0", || {
                fixture.revoke();
                drop(acquire_eventually(|| directory.lock_shared()).unwrap());
            }),
            ErrorCode::PermissionDenied
        );
    }
    #[derive(Clone, Default)]
    struct Counters {
        launches: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        backends: Arc<Mutex<Vec<Backend>>>,
    }

    struct Fake {
        counters: Counters,
        refuse: Option<ErrorCode>,
        stop_result: State,
    }

    struct FakeSession {
        counters: Counters,
        state: State,
        stop_result: State,
    }

    impl Launch for Fake {
        fn launch<'a>(
            &'a self,
            offer: &Prepare,
            _: &super::super::policy::Entry,
            _: super::super::protocol::Credentials,
            _: File,
        ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
            let backend = offer.backend();
            self.counters.launches.fetch_add(1, Ordering::SeqCst);
            self.counters.backends.lock().unwrap().push(backend);
            match self.refuse {
                Some(code) => Err(code),
                None => Ok(Box::new(FakeSession {
                    counters: self.counters.clone(),
                    state: State::Starting,
                    stop_result: self.stop_result,
                })),
            }
        }
    }

    impl Running for FakeSession {
        fn state(&self) -> State {
            self.state
        }
        fn stop(&mut self) -> State {
            self.counters.stops.fetch_add(1, Ordering::SeqCst);
            self.state = self.stop_result;
            self.state
        }
    }

    impl Drop for FakeSession {
        fn drop(&mut self) {
            self.counters.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Run the dialogue through the credentials and return the open client.
    fn admitted_client(policy: &PolicyFixture, fake: Fake) -> (UnixStream, thread::JoinHandle<()>) {
        let server = Arc::new(Server::with_launcher(policy.store.clone(), Box::new(fake)));
        let (mut client, stream) = UnixStream::pair().unwrap();
        let worker = server.dispatch(stream, |_| Ok(1000)).unwrap();
        client
            .write_all(b"{\"op\":\"hello\",\"version\":1}\n")
            .unwrap();
        assert!(matches!(tests_receive(&client), Response::Version { .. }));
        writeln!(client, r#"{{"op":"prepare_ipsec","endpoint":{{"host":"vpn.example","port":500}},"username":"fixture","networks":[{{"network":"10.20.0.0","prefix":16}}]}}"#).unwrap();
        assert!(matches!(tests_receive(&client), Response::Prepared {}));
        Credentials::ipsec("fixture-password", "fixture-psk")
            .unwrap()
            .write(&mut client)
            .unwrap();
        (client, worker)
    }

    fn installed() -> PolicyFixture {
        let fixture = PolicyFixture::new();
        fixture.install();
        let directory = fixture.store.open().unwrap();
        drop(acquire_eventually(|| directory.lock_shared()).unwrap());
        fixture
    }

    fn command(client: &mut UnixStream, op: &str) -> Response {
        writeln!(client, r#"{{"op":"{op}"}}"#).unwrap();
        tests_receive(client)
    }

    fn fake(refuse: Option<ErrorCode>, stop_result: State) -> (Fake, Counters) {
        let counters = Counters::default();
        let fake = Fake {
            counters: counters.clone(),
            refuse,
            stop_result,
        };
        (fake, counters)
    }

    #[test]
    fn admitted_session_reports_starting_and_stops_once() {
        let fixture = installed();
        let (fake, counters) = fake(None, State::Stopped);
        let (mut client, worker) = admitted_client(&fixture, fake);
        assert!(matches!(
            command(&mut client, "status"),
            Response::Status {
                state: State::Starting
            }
        ));
        assert_eq!(counters.stops.load(Ordering::SeqCst), 0);
        assert!(matches!(
            command(&mut client, "stop"),
            Response::Status {
                state: State::Stopped
            }
        ));
        assert!(matches!(
            command(&mut client, "status"),
            Response::Status {
                state: State::Stopped
            }
        ));
        drop(client);
        worker.join().unwrap();
        assert_eq!(counters.launches.load(Ordering::SeqCst), 1);
        assert_eq!(*counters.backends.lock().unwrap(), [Backend::Ipsec]);
        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stop_reports_cleanup_pending_when_removal_is_unproven() {
        let fixture = installed();
        let (fake, counters) = fake(None, State::CleanupPending);
        let (mut client, worker) = admitted_client(&fixture, fake);
        for _ in 0..2 {
            assert!(matches!(
                command(&mut client, "stop"),
                Response::Status {
                    state: State::CleanupPending
                }
            ));
        }
        drop(client);
        worker.join().unwrap();
        // Each stop is a retry of the cleanup.
        assert_eq!(counters.stops.load(Ordering::SeqCst), 2);
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_closed_client_ends_the_session() {
        let fixture = installed();
        let (fake, counters) = fake(None, State::Stopped);
        let (mut client, worker) = admitted_client(&fixture, fake);
        assert!(matches!(
            command(&mut client, "status"),
            Response::Status {
                state: State::Starting
            }
        ));
        drop(client);
        worker.join().unwrap();
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_malformed_command_ends_the_session() {
        let fixture = installed();
        let (fake, counters) = fake(None, State::Stopped);
        let (mut client, worker) = admitted_client(&fixture, fake);
        writeln!(client, r#"{{"op":"hello","version":1}}"#).unwrap();
        worker.join().unwrap();
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            timed(&client, Instant::now() + FRAME_TIMEOUT)
                .unwrap()
                .read(&mut [0])
                .unwrap(),
            0
        );
    }

    #[test]
    fn a_refused_admission_replies_with_its_code_and_closes() {
        for code in [
            ErrorCode::Busy,
            ErrorCode::Timeout,
            ErrorCode::Backend,
            ErrorCode::CleanupPending,
        ] {
            let fixture = installed();
            let (fake, counters) = fake(Some(code), State::Stopped);
            let (client, worker) = admitted_client(&fixture, fake);
            let Response::Error { code: replied } = tests_receive(&client) else {
                panic!("expected an error")
            };
            assert_eq!(replied, code);
            assert_eq!(
                timed(&client, Instant::now() + FRAME_TIMEOUT)
                    .unwrap()
                    .read(&mut [0])
                    .unwrap(),
                0
            );
            worker.join().unwrap();
            assert_eq!(counters.launches.load(Ordering::SeqCst), 1);
            assert_eq!(counters.drops.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn a_revoked_grant_never_reaches_the_launcher() {
        let fixture = installed();
        let (fake, counters) = fake(None, State::Stopped);
        let server = Arc::new(Server::with_launcher(fixture.store.clone(), Box::new(fake)));
        let (mut client, stream) = UnixStream::pair().unwrap();
        let worker = server.dispatch(stream, |_| Ok(1000)).unwrap();
        client
            .write_all(b"{\"op\":\"hello\",\"version\":1}\n")
            .unwrap();
        tests_receive(&client);
        writeln!(client, r#"{{"op":"prepare_ipsec","endpoint":{{"host":"vpn.example","port":500}},"username":"fixture","networks":[{{"network":"10.20.0.0","prefix":16}}]}}"#).unwrap();
        assert!(matches!(tests_receive(&client), Response::Prepared {}));
        fixture.revoke();
        let directory = fixture.store.open().unwrap();
        drop(acquire_eventually(|| directory.lock_shared()).unwrap());
        Credentials::ipsec("fixture-password", "fixture-psk")
            .unwrap()
            .write(&mut client)
            .unwrap();
        assert!(matches!(
            tests_receive(&client),
            Response::Error {
                code: ErrorCode::PermissionDenied
            }
        ));
        worker.join().unwrap();
        assert_eq!(counters.launches.load(Ordering::SeqCst), 0);
    }
}
