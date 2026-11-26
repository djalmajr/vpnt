//! Linux socket activation, bounded admission, and versioned dialogues.
use super::admin::PolicyStore;
use super::backend::{Launch, Launcher, RUNTIME_DIRECTORY, Running, retry_cleanup};
use super::cleanup::{Reservation, Store};
use super::network::SetupCancellation;
#[cfg(test)]
use super::protocol::Prepare;
use super::protocol::{
    CLEANUP_VERSION, CleanupState, Command, ErrorCode, FrameError, InitialRequest,
    MAX_CONFIRMATION, Request, Response, ServerDecoder, State, decode_request, monotonic_ms,
    read_control, timed, write_control,
};
use crate::{helper::local_socket::peer_uid, netd::iproute::IpRoute};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io,
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const RECOVERY_REPLY_TIMEOUT: Duration = Duration::from_millis(100);
const SESSION_IDLE_MS: libc::c_int = 24 * 60 * 60 * 1000;
const MAX_PER_UID: usize = 2;
const MAX_CONNECTIONS: usize = 8;
const LISTEN_FD: RawFd = 3;
const RECONCILE_MIN: Duration = Duration::from_secs(1);
const RECONCILE_MAX: Duration = Duration::from_secs(8);

struct Server {
    connections: Mutex<Connections>,
    policy: PolicyStore,
    launcher: Arc<dyn Launch>,
    cleanup: Option<Arc<Store>>,
    recovered: Arc<StartupRecovery>,
}

struct StartupRecovery {
    completed_at: Mutex<Option<Instant>>,
    completed: Condvar,
}

impl StartupRecovery {
    fn new(ready: bool) -> Self {
        Self {
            completed_at: Mutex::new(ready.then(Instant::now)),
            completed: Condvar::new(),
        }
    }

    fn is_ready(&self) -> bool {
        self.completed_at
            .lock()
            .expect("startup recovery")
            .is_some()
    }

    fn mark_ready(&self) {
        *self.completed_at.lock().expect("startup recovery") = Some(Instant::now());
        self.completed.notify_all();
    }

    fn wait_until_ready(&self, deadline: Instant) -> bool {
        let completed_at = self.completed_at.lock().expect("startup recovery");
        let (completed_at, _) = self
            .completed
            .wait_timeout_while(
                completed_at,
                deadline.saturating_duration_since(Instant::now()),
                |completed| completed.is_none(),
            )
            .expect("startup recovery");
        completed_at.is_some_and(|completed| completed < deadline)
    }
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
        let cleanup = Arc::new(Store::open(Path::new(RUNTIME_DIRECTORY))?);
        let launcher = Arc::new(Launcher::system(IpRoute::system(), cleanup.clone()));
        let recovered = Arc::new(StartupRecovery::new(false));
        let worker = (launcher.clone(), cleanup.clone(), recovered.clone());
        thread::Builder::new()
            .name("vpnt-tunneld-recovery".into())
            .spawn(move || {
                let (launcher, cleanup, recovered) = worker;
                reconcile(
                    &recovered,
                    || launcher.recover_with(Some(&cleanup)),
                    || cleanup.republish(),
                    |delay| {
                        thread::sleep(delay);
                        true
                    },
                );
            })?;
        Ok(Self {
            connections: Mutex::default(),
            policy,
            launcher,
            cleanup: Some(cleanup),
            recovered,
        })
    }

    #[cfg(test)]
    fn with_launcher(policy: PolicyStore, launcher: Box<dyn Launch>) -> Self {
        Self {
            connections: Mutex::default(),
            policy,
            launcher: Arc::from(launcher),
            cleanup: None,
            recovered: Arc::new(StartupRecovery::new(true)),
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
                slot.server.cleanup.as_deref(),
                &slot.server.recovered,
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

/// A single worker owns startup recovery. After admission opens it only
/// retries publication of already-proved results, never live network teardown.
fn reconcile(
    recovered: &StartupRecovery,
    mut recover: impl FnMut() -> io::Result<()>,
    mut publish: impl FnMut() -> io::Result<()>,
    mut wait: impl FnMut(Duration) -> bool,
) {
    let mut delay = RECONCILE_MIN;
    let mut reporting_failure = false;
    loop {
        let ready = recovered.is_ready();
        let result = if ready { publish() } else { recover() };
        match result {
            Ok(()) => {
                if !ready {
                    recovered.mark_ready();
                }
                reporting_failure = false;
                delay = RECONCILE_MIN;
                if !wait(delay) {
                    return;
                }
            }
            Err(error) => {
                if !reporting_failure {
                    let stage = if ready {
                        "cleanup publication"
                    } else {
                        "startup recovery"
                    };
                    eprintln!("vpnt-tunneld: {stage} will be retried: {error}");
                    reporting_failure = true;
                }
                if !wait(delay) {
                    return;
                }
                delay = delay.saturating_mul(2).min(RECONCILE_MAX);
            }
        }
    }
}

fn serve(
    stream: UnixStream,
    admission: &Admission,
    policy: &PolicyStore,
    launcher: &dyn Launch,
    cleanup: Option<&Store>,
    recovered: &StartupRecovery,
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
    let v2 = decoder.version() == CLEANUP_VERSION;
    let offer = match decoder.initial_request(prepare_deadline) {
        Ok(InitialRequest::Prepare(offer)) => offer,
        Ok(InitialRequest::CleanupStatus(generation)) => {
            let status = cleanup.map_or(CleanupState::Unknown, |store| {
                store.status(uid, &generation)
            });
            return decoder.reply_cleanup(status, prepare_deadline);
        }
        Err(FrameError::Protocol(_)) => {
            return reply_error(&stream, ErrorCode::BadRequest, prepare_deadline);
        }
        Err(error) => return Err(error),
    };
    if !recovered.wait_until_ready(prepare_deadline) {
        eprintln!("vpnt-tunneld: admission ended: startup recovery still running");
        // The prepare budget has expired. Give only the terminal reply a
        // short write budget so the peer can still receive the typed error.
        return decoder.reject(ErrorCode::Busy, Instant::now() + RECOVERY_REPLY_TIMEOUT);
    }
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
    let mut reservation = if v2 {
        match cleanup.map(|store| store.reserve(uid)) {
            Some(Ok(reservation)) => Some(reservation),
            Some(Err(error)) => {
                eprintln!("vpnt-tunneld: could not reserve cleanup receipt: {error}");
                return decoder.reject(ErrorCode::Busy, prepare_deadline);
            }
            None => return decoder.reject(ErrorCode::Backend, prepare_deadline),
        }
    } else {
        None
    };
    let generation = reservation
        .as_ref()
        .map(|record| record.generation().clone());
    decoder.acknowledge(generation.clone(), prepare_deadline)?;

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
    let (completion, done) = UnixStream::pair()?;
    let cancel = Arc::new(SetupCancellation::default());
    let (commands, result) = thread::scope(|scope| -> Result<_, FrameError> {
        let launch_cancel = &cancel;
        let worker = thread::Builder::new().spawn_scoped(scope, || {
            let _signal_on_drop = done;
            if let Some(record) = reservation.as_mut() {
                if let Err(error) = record.begin_network() {
                    eprintln!("vpnt-tunneld: could not record network preparation: {error}");
                    return Err(ErrorCode::Backend);
                }
                launcher.launch_v2(
                    &offer,
                    grant,
                    credentials,
                    authorization,
                    launch_cancel,
                    record,
                )
            } else {
                launcher.launch(&offer, grant, credentials, authorization, launch_cancel)
            }
        })?;
        let commands = watch_setup(&stream, &completion, &mut decoder, &cancel, v2);
        if !matches!(commands, Ok((_, false))) {
            cancel.cancel();
        }
        let result = worker
            .join()
            .map_err(|_| io::Error::other("setup worker panicked"))?;
        Ok((commands, result))
    })?;
    if let Some(record) = reservation {
        return match result {
            Ok(session) if matches!(commands, Ok((_, false))) => {
                dialogue_v2(&stream, decoder, session, &record)
            }
            Ok(session) => {
                let _ = stream.shutdown(Shutdown::Both);
                finish_v2(session, &record);
                commands.map(|_| ())
            }
            Err(code) => {
                if code != ErrorCode::CleanupPending {
                    record_stopped(&record);
                }
                if matches!(commands, Ok((_, false))) {
                    decoder.reject(code, Instant::now() + FRAME_TIMEOUT)
                } else {
                    commands.map(|_| ())
                }
            }
        };
    }
    let (statuses, stop) = commands?;
    let mut session = match result {
        Ok(session) => session,
        Err(code) if stop => {
            let state = if code == ErrorCode::CleanupPending {
                State::CleanupPending
            } else {
                State::Stopped
            };
            return reply_setup_statuses(&mut decoder, statuses + 1, state);
        }
        Err(code) => return decoder.reject(code, Instant::now() + FRAME_TIMEOUT),
    };
    if stop && matches!(session.state(), State::Starting | State::NetworkReady) {
        session.stop();
    }
    let mut deadline = None;
    for _ in 0..statuses + usize::from(stop) {
        let (_, ended) = poll_session(None, &*session, 0, None)?;
        if ended {
            let cleanup_started = Instant::now();
            session.stop();
            // Preserve the remaining write budget if earlier statuses were sent.
            deadline = deadline.map(|deadline| deadline + cleanup_started.elapsed());
        }
        let write_deadline = *deadline.get_or_insert_with(|| Instant::now() + FRAME_TIMEOUT);
        decoder.reply_status(session.state(), write_deadline)?;
    }
    dialogue(&stream, decoder, session)
}

// Preserve the first Status as a report of the launch result. Keep reading
// while it is pending so a queued Stop or a disconnect can overtake setup.
fn watch_setup(
    client: &UnixStream,
    completion: &UnixStream,
    decoder: &mut ServerDecoder,
    cancel: &SetupCancellation,
    v2: bool,
) -> Result<(usize, bool), FrameError> {
    let mut statuses = 0;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: client.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: completion.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: poll updates the initialized array of live descriptors.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
            continue;
        }
        if fds[0].revents != 0 {
            match decoder.command(Instant::now() + FRAME_TIMEOUT)? {
                Command::Status if v2 => {
                    decoder.reply_status(State::Starting, Instant::now() + FRAME_TIMEOUT)?;
                }
                Command::Status => statuses += 1,
                Command::Confirm(_) => return Err(ErrorCode::BadRequest.into()),
                Command::Stop => {
                    if v2 {
                        cancel.cancel();
                        let result =
                            decoder.reply_status(State::Stopping, Instant::now() + FRAME_TIMEOUT);
                        let _ = client.shutdown(Shutdown::Both);
                        result?;
                    }
                    return Ok((statuses, true));
                }
            }
            // A half-close can follow the last queued Status. Read EOF
            // before releasing the setup worker's result to the client.
            if fds[0].revents & libc::POLLRDHUP != 0 {
                continue;
            }
        }
        if fds[1].revents != 0 {
            return Ok((statuses, false));
        }
    }
}

fn reply_setup_statuses(
    decoder: &mut ServerDecoder,
    count: usize,
    state: State,
) -> Result<(), FrameError> {
    let deadline = Instant::now() + FRAME_TIMEOUT;
    for _ in 0..count {
        decoder.reply_status(state, deadline)?;
    }
    Ok(())
}

// Internal data is read only by the authenticated backend. The same
// liveness signals take precedence over queued and live client commands.
fn poll_session(
    client: Option<&UnixStream>,
    session: &dyn Running,
    timeout: libc::c_int,
    retry_until: Option<Instant>,
) -> io::Result<(bool, bool)> {
    let mut fds = [
        libc::pollfd {
            fd: client.map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: session.peer().map_or(-1, |peer| peer.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: session
                .channel_fd()
                .map_or(-1, |channel| channel.as_raw_fd()),
            events: libc::POLLRDHUP,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: poll updates the initialized array of live or ignored descriptors.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) } >= 0 {
            return Ok((
                fds[0].revents != 0,
                fds[1].revents != 0 || fds[2].revents != 0,
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        super::network::check_deadline(retry_until)?;
    }
}

pub(super) fn probe_session_ended(session: &dyn Running, deadline: Instant) -> io::Result<bool> {
    poll_session(None, session, 0, Some(deadline)).map(|(_, ended)| ended)
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
        let (client_ready, ended) = poll_session(Some(stream), &*session, SESSION_IDLE_MS, None)?;
        if ended {
            session.stop();
        }
        if !client_ready {
            if ended {
                continue;
            }
            return Err(io::Error::from(io::ErrorKind::TimedOut).into());
        }
        let state = match decoder.command(Instant::now() + FRAME_TIMEOUT) {
            Ok(Command::Status) => session.state(),
            Ok(Command::Stop) => session.stop(),
            Ok(Command::Confirm(_)) => return Err(ErrorCode::BadRequest.into()),
            Err(error) => return Err(error),
        };
        decoder.reply_status(state, Instant::now() + FRAME_TIMEOUT)?;
    }
}

fn record_stopped(record: &Reservation<'_>) {
    if let Err(error) = record.stopped() {
        eprintln!("vpnt-tunneld: could not publish completed cleanup: {error}");
    }
}

fn finish_v2(mut session: Box<dyn Running + '_>, record: &Reservation<'_>) {
    if retry_cleanup(|| session.stop() == State::Stopped) {
        record_stopped(record);
    }
}

fn dialogue_v2(
    stream: &UnixStream,
    mut decoder: ServerDecoder,
    session: Box<dyn Running + '_>,
    record: &Reservation<'_>,
) -> Result<(), FrameError> {
    let result = (|| {
        loop {
            let (client_ready, ended) =
                poll_session(Some(stream), &*session, SESSION_IDLE_MS, None)?;
            if ended || !client_ready {
                return Ok(());
            }
            let deadline = Instant::now() + FRAME_TIMEOUT;
            match decoder.command(deadline)? {
                Command::Confirm(expires_ms) => {
                    let now = Instant::now();
                    let remaining =
                        Duration::from_millis(expires_ms.saturating_sub(monotonic_ms()?));
                    let confirm_by = now + remaining.min(MAX_CONFIRMATION);
                    if probe_session_ended(&*session, deadline)?
                        || session.state() != State::NetworkReady
                    {
                        return decoder
                            .reply_status(State::Stopping, Instant::now() + FRAME_TIMEOUT);
                    }
                    let binding = if remaining.is_zero() {
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        session.probe_binding(confirm_by)
                    };
                    let write_by = Instant::now() + FRAME_TIMEOUT;
                    if probe_session_ended(&*session, write_by)? {
                        return decoder.reply_status(State::Stopping, write_by);
                    }
                    match binding {
                        Ok(binding) if binding.generation() == record.generation() => {
                            if Instant::now() < confirm_by {
                                decoder.reply_ready(binding, write_by)?;
                            } else {
                                decoder.reply_unconfirmed(write_by)?;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                            decoder.reply_unconfirmed(write_by)?;
                        }
                        _ => return decoder.reject(ErrorCode::Backend, write_by),
                    }
                }
                Command::Status if session.state() == State::NetworkReady => {
                    let binding = match session.probe_binding(deadline) {
                        Ok(binding) if binding.generation() == record.generation() => binding,
                        _ => {
                            let _ = decoder.reject(ErrorCode::Backend, deadline);
                            return Ok(());
                        }
                    };
                    if probe_session_ended(&*session, deadline)? {
                        return decoder.reply_status(State::Stopping, deadline);
                    }
                    decoder.reply_ready(binding, deadline)?;
                }
                Command::Status => decoder.reply_status(session.state(), deadline)?,
                Command::Stop => return decoder.reply_status(State::Stopping, deadline),
            }
        }
    })();
    let _ = stream.shutdown(Shutdown::Both);
    finish_v2(session, record);
    result
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
        None,
        &StartupRecovery::new(true),
        Instant::now(),
    )
}

#[cfg(test)]
pub(super) fn serve_cleanup_fixture(
    stream: UnixStream,
    uid: u32,
    policy: &PolicyStore,
    launcher: &dyn Launch,
    cleanup: &Store,
) -> Result<(), FrameError> {
    serve(
        stream,
        &Admission::Session(uid),
        policy,
        launcher,
        Some(cleanup),
        &StartupRecovery::new(true),
        Instant::now(),
    )
}

#[cfg(test)]
pub(super) fn serve_recovery_fixture<N, A>(
    stream: UnixStream,
    uid: u32,
    policy: &PolicyStore,
    launcher: &Launcher<N, A>,
    cleanup: &Store,
) -> Result<(), FrameError>
where
    N: crate::netd::iproute::Backend,
    A: super::handshake::UnitAttestor + Send + Sync,
{
    let recovered = StartupRecovery::new(false);
    reconcile(
        &recovered,
        || launcher.recover_with(Some(cleanup)),
        || cleanup.republish(),
        |_| false,
    );
    serve(
        stream,
        &Admission::Session(uid),
        policy,
        launcher,
        Some(cleanup),
        &recovered,
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
            _: &Arc<SetupCancellation>,
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
        if matches!(response, Response::Prepared { generation: None }) {
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

    fn receive_by(stream: &UnixStream, deadline: Instant) -> Result<Response, FrameError> {
        read_control(
            &mut timed(stream, deadline)?,
            super::super::protocol::decode_response,
        )
    }

    fn tests_receive(stream: &UnixStream) -> Response {
        receive_by(stream, Instant::now() + FRAME_TIMEOUT).unwrap()
    }

    fn open_dialogue(server: &Arc<Server>, version: u32) -> (UnixStream, thread::JoinHandle<()>) {
        let (mut client, stream) = UnixStream::pair().unwrap();
        let worker = server.dispatch(stream, |_| Ok(1000)).unwrap();
        writeln!(client, r#"{{"op":"hello","version":{version}}}"#).unwrap();
        assert!(
            matches!(tests_receive(&client), Response::Version { version: received } if received == version)
        );
        (client, worker)
    }

    fn send_recovery_offer(client: &mut UnixStream) {
        writeln!(client, r#"{{"op":"prepare_ipsec","endpoint":{{"host":"vpn.example","port":500}},"username":"fixture","networks":[{{"network":"10.20.0.0","prefix":16}}]}}"#).unwrap();
    }

    #[test]
    fn startup_recovery_timeout_replies_busy_and_logs() {
        const CHILD: &str = "VPNT_TEST_STARTUP_RECOVERY_TIMEOUT";
        if std::env::var_os(CHILD).is_none() {
            let output = Process::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tunneld::server::policy_dialogue_tests::startup_recovery_timeout_replies_busy_and_logs",
                    "--nocapture",
                ])
                .env_clear()
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.lines().any(|line| {
                    line == "vpnt-tunneld: admission ended: startup recovery still running"
                }),
                "{stderr}"
            );
            return;
        }

        let server = Arc::new(Server {
            recovered: Arc::new(StartupRecovery::new(false)),
            ..Server::default()
        });
        let started = Instant::now();
        let (mut client, worker) = open_dialogue(&server, VERSION);
        send_recovery_offer(&mut client);
        let response = receive_by(
            &client,
            Instant::now() + FRAME_TIMEOUT + Duration::from_secs(1),
        );
        drop(client);
        worker.join().unwrap();
        assert!(matches!(
            response.unwrap(),
            Response::Error {
                code: ErrorCode::Busy
            }
        ));
        assert!(started.elapsed() >= FRAME_TIMEOUT);
    }

    #[test]
    fn background_recovery_keeps_status_available_and_retries_until_proved() {
        let policy = PolicyFixture::new();
        policy.install();
        let mut server = Server::with_launcher(policy.store.clone(), Box::new(Unavailable));
        server.recovered = Arc::new(StartupRecovery::new(false));
        let store = Arc::new(Store::open(policy.path().parent().unwrap()).unwrap());
        let reservation = store.reserve(1000).unwrap();
        let id = reservation.generation().clone();
        drop(reservation);
        server.cleanup = Some(store);
        let server = Arc::new(server);
        let (observed, next) = std::sync::mpsc::channel();
        thread::scope(|scope| {
            let (resume, continued) = std::sync::mpsc::channel();
            let recovered = &server.recovered;
            let scheduler = scope.spawn(move || {
                let mut attempts = 0;
                reconcile(
                    recovered,
                    || {
                        attempts += 1;
                        if attempts <= 5 {
                            Err(io::ErrorKind::WouldBlock.into())
                        } else {
                            Ok(())
                        }
                    },
                    || Ok(()),
                    |delay| {
                        observed.send(delay).unwrap();
                        continued
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap_or(false)
                    },
                );
                attempts
            });
            let backoff = [1, 2, 4, 8, 8];
            for (attempt, seconds) in backoff.into_iter().enumerate() {
                assert_eq!(
                    next.recv_timeout(Duration::from_secs(5)).unwrap(),
                    Duration::from_secs(seconds)
                );
                let (mut client, worker) = open_dialogue(&server, CLEANUP_VERSION);
                write_control(
                    &mut client,
                    &Request::CleanupStatus {
                        generation: id.clone(),
                    },
                )
                .unwrap();
                assert!(matches!(
                    tests_receive(&client),
                    Response::CleanupStatus {
                        state: CleanupState::Stopped
                    }
                ));
                worker.join().unwrap();

                if attempt + 1 < backoff.len() {
                    resume.send(true).unwrap();
                }
            }
            let mut sessions = Vec::new();
            for version in [VERSION, CLEANUP_VERSION] {
                let (mut client, worker) = open_dialogue(&server, version);
                send_recovery_offer(&mut client);
                sessions.push((version, client, worker));
            }
            let pending = sessions
                .iter()
                .map(|(_, client, _)| {
                    receive_by(client, Instant::now() + Duration::from_millis(100))
                })
                .collect::<Vec<_>>();
            resume.send(true).unwrap();
            assert_eq!(
                next.recv_timeout(Duration::from_secs(5)).unwrap(),
                RECONCILE_MIN
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            let admitted = sessions
                .into_iter()
                .map(|(version, client, worker)| {
                    let response = receive_by(&client, deadline);
                    drop(client);
                    worker.join().unwrap();
                    (version, response)
                })
                .collect::<Vec<_>>();
            resume.send(false).unwrap();
            assert_eq!(scheduler.join().unwrap(), 6);
            for response in pending {
                assert!(
                    matches!(response, Err(FrameError::Io(io::ErrorKind::TimedOut))),
                    "unexpected admission reply before recovery: {response:?}"
                );
            }
            for (version, response) in admitted {
                assert!(
                    matches!(&response, Ok(Response::Prepared { generation }) if generation.is_some() == (version == CLEANUP_VERSION)),
                    "unexpected admission reply after recovery for v{version}: {response:?}"
                );
            }
        });
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
        stop_delay: Duration,
        ended: Option<(UnixStream, bool)>,
    }

    struct FakeSession {
        counters: Counters,
        state: State,
        stop_result: State,
        stop_delay: Duration,
        ended: Option<(UnixStream, bool)>,
    }

    impl Launch for Fake {
        fn launch<'a>(
            &'a self,
            offer: &Prepare,
            _: &super::super::policy::Entry,
            _: super::super::protocol::Credentials,
            _: File,
            _: &Arc<SetupCancellation>,
        ) -> Result<Box<dyn Running + 'a>, ErrorCode> {
            let backend = offer.backend();
            self.counters.launches.fetch_add(1, Ordering::SeqCst);
            self.counters.backends.lock().unwrap().push(backend);
            match self.refuse {
                Some(code) => Err(code),
                None => Ok(Box::new(FakeSession {
                    counters: self.counters.clone(),
                    state: if self.ended.is_some() {
                        State::NetworkReady
                    } else {
                        State::Starting
                    },
                    stop_result: self.stop_result,
                    stop_delay: self.stop_delay,
                    ended: self
                        .ended
                        .as_ref()
                        .map(|(fd, peer)| (fd.try_clone().unwrap(), *peer)),
                })),
            }
        }
    }

    impl Running for FakeSession {
        fn state(&self) -> State {
            self.state
        }
        fn peer(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
            use std::os::fd::AsFd;
            self.ended
                .as_ref()
                .filter(|(_, peer)| *peer)
                .map(|(fd, _)| fd.as_fd())
        }
        fn channel_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
            use std::os::fd::AsFd;
            self.ended
                .as_ref()
                .filter(|(_, peer)| !*peer)
                .map(|(fd, _)| fd.as_fd())
        }
        fn stop(&mut self) -> State {
            self.ended.take();
            self.counters.stops.fetch_add(1, Ordering::SeqCst);
            thread::sleep(self.stop_delay);
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
        admitted_client_with_queued_status(policy, fake, false)
    }

    fn admitted_client_with_queued_status(
        policy: &PolicyFixture,
        fake: Fake,
        queue_status: bool,
    ) -> (UnixStream, thread::JoinHandle<()>) {
        let server = Arc::new(Server::with_launcher(policy.store.clone(), Box::new(fake)));
        let (mut client, stream) = UnixStream::pair().unwrap();
        let worker = server.dispatch(stream, |_| Ok(1000)).unwrap();
        client
            .write_all(b"{\"op\":\"hello\",\"version\":1}\n")
            .unwrap();
        assert!(matches!(tests_receive(&client), Response::Version { .. }));
        writeln!(client, r#"{{"op":"prepare_ipsec","endpoint":{{"host":"vpn.example","port":500}},"username":"fixture","networks":[{{"network":"10.20.0.0","prefix":16}}]}}"#).unwrap();
        assert!(matches!(
            tests_receive(&client),
            Response::Prepared { generation: None }
        ));
        let mut credentials = Vec::new();
        Credentials::ipsec("fixture-password", "fixture-psk")
            .unwrap()
            .write(&mut credentials)
            .unwrap();
        if queue_status {
            credentials.extend_from_slice(b"{\"op\":\"status\"}\n");
        }
        client.write_all(&credentials).unwrap();
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
            stop_delay: Duration::ZERO,
            ended: None,
        };
        (fake, counters)
    }

    #[test]
    fn queued_status_checks_peer_and_channel_before_publication() {
        let fixture = installed();
        for (peer, stop_result) in [(true, State::Stopped), (false, State::CleanupPending)] {
            let (mut fake, counters) = fake(None, stop_result);
            let (fd, other) = UnixStream::pair().unwrap();
            let _live_peer = if peer {
                (&other).write_all(b"ready").unwrap();
                Some(other)
            } else {
                drop(other);
                None
            };
            fake.ended = Some((fd, peer));
            let (client, worker) = admitted_client_with_queued_status(&fixture, fake, true);
            let response = tests_receive(&client);
            drop(client);
            worker.join().unwrap();
            assert!(
                matches!(response, Response::Status { state } if state == stop_result),
                "peer={peer}: unexpected queued status {response:?}"
            );
            assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn queued_status_survives_cleanup_longer_than_the_write_timeout() {
        let fixture = installed();
        let (mut fake, counters) = fake(None, State::Stopped);
        let (channel, peer) = UnixStream::pair().unwrap();
        drop(peer);
        fake.ended = Some((channel, false));
        fake.stop_delay = FRAME_TIMEOUT + Duration::from_millis(100);

        let (client, worker) = admitted_client_with_queued_status(&fixture, fake, true);
        let response = timed(&client, Instant::now() + FRAME_TIMEOUT * 3).and_then(|mut stream| {
            read_control(&mut stream, super::super::protocol::decode_response)
        });
        drop(client);
        worker.join().unwrap();

        assert_eq!(counters.stops.load(Ordering::SeqCst), 1);
        assert!(
            matches!(
                response,
                Ok(Response::Status {
                    state: State::Stopped
                })
            ),
            "expected Stopped after slow cleanup, got {response:?}"
        );
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
        assert!(matches!(
            tests_receive(&client),
            Response::Prepared { generation: None }
        ));
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
