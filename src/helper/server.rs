//! Root entrypoint with closed modes and a private inherited Unix channel.
//! The socket's kernel peer UID, not IPC or sudo environment, selects storage.
pub(crate) mod caller;
mod io;
#[cfg(target_os = "macos")]
use super::controller_lock::ControllerLock;
use super::{
    ppp_supervisor::signals,
    protocol::{self, AdminCommand, ErrorCode, Message, Request},
};
use crate::storage::{ProfileStore, StoreError};
use caller::Caller;
use std::{
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

// Reserve 30 seconds for the planned cleanup budget plus scheduling margin.
// The existing controller is still unbounded; this wait never signals it or
// implies that cleanup succeeded.
const PREVIOUS_SESSION_WAIT: Duration = Duration::from_secs(35);
const LOCK_POLL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Runtime,
    Admin,
}
impl Mode {
    pub fn parse(arguments: &[std::ffi::OsString]) -> Option<Self> {
        match arguments {
            [arg] if arg == "runtime" => Some(Self::Runtime),
            [arg] if arg == "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}
fn interrupted() -> bool {
    signals::INTERRUPTED.load(Ordering::Acquire)
}
fn mode_lock<L>(
    mode: Mode,
    acquire: impl FnOnce() -> Result<L, super::controller_lock::LockError>,
) -> Result<Option<L>, ErrorCode> {
    if mode == Mode::Admin {
        return Ok(None);
    }
    acquire().map(Some).map_err(|error| match error {
        super::controller_lock::LockError::Busy => ErrorCode::ProfileBusy,
        _ => ErrorCode::UntrustedConfiguration,
    })
}

// Inspect only the first complete request without consuming it: a legacy v3
// helper accepts and echoes this opaque ID, while an old client never sends it.
// This is capability negotiation, not authentication or authority.
fn supports_wait_notice(stream: &UnixStream, deadline: Instant) -> bool {
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; protocol::MAX_REQUEST_BYTES + 1]);
    loop {
        if interrupted() || Instant::now() >= deadline {
            return false;
        }
        // SAFETY: bytes is writable for its length and the borrowed socket is live.
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if count == 0 {
            return false;
        }
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return false;
            }
        } else {
            let seen = &bytes[..count as usize];
            if let Some(end) = seen.iter().position(|byte| *byte == b'\n') {
                return protocol::parse_request(&seen[..=end]).is_ok_and(|request| {
                    request.id == protocol::WAIT_CAPABILITY_SNAPSHOT_ID
                        && matches!(request.command, protocol::Command::Snapshot {})
                });
            }
            if seen.len() == bytes.len() {
                return false;
            }
        }
        thread::sleep(LOCK_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn wait_for_mode_lock<L>(
    mode: Mode,
    stream: &mut UnixStream,
    budget: Duration,
    announced: &mut bool,
    mut acquire: impl FnMut() -> Result<L, super::controller_lock::LockError>,
) -> Result<Option<L>, ErrorCode> {
    let deadline = Instant::now() + budget;
    loop {
        if interrupted() {
            return Err(ErrorCode::Unavailable);
        }
        match mode_lock(mode, &mut acquire) {
            Ok(lock) => return Ok(lock),
            Err(ErrorCode::ProfileBusy) if mode == Mode::Runtime => {
                if !*announced {
                    if !supports_wait_notice(stream, deadline.min(Instant::now() + io::DEADLINE)) {
                        return Err(ErrorCode::ProfileBusy);
                    }
                    send(
                        stream,
                        &Message::PreviousSessionFinishing {
                            protocol_version: protocol::VERSION,
                            version: env!("CARGO_PKG_VERSION").into(),
                        },
                    )?;
                    *announced = true;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(ErrorCode::ProfileBusy);
                }
                thread::sleep(LOCK_POLL.min(remaining));
            }
            Err(error) => return Err(error),
        }
    }
}

fn send_admission_error(stream: &mut UnixStream, announced: bool, error: ErrorCode) {
    if !(announced && error == ErrorCode::ProfileBusy) {
        let _ = send(stream, &Message::Fatal { error });
    }
}

/// Only for the standalone helper process, before it starts any threads.
/// No path, target UID or ownership override is accepted.
///
/// # Safety
/// FD 0 must not have a Rust owner or aliases. This consumes FD 0 as the only
/// duplex protocol channel; stdout/stderr are never used for protocol data.
#[cfg(target_os = "macos")]
pub unsafe fn inherited_run(mode: Mode) -> Result<(), ErrorCode> {
    // SAFETY: UID queries have no memory preconditions; deny before inspecting
    // descriptors, installed storage, lock or any privileged program.
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        return Err(ErrorCode::PermissionDenied);
    }
    if unsafe { libc::fcntl(0, libc::F_GETFD) } < 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    let mut caller = Caller::from_fd(unsafe { OwnedFd::from_raw_fd(0) })
        .map_err(|_| ErrorCode::PermissionDenied)?;
    let _signals = signals::Guard::install().map_err(|_| ErrorCode::Unavailable)?;
    let mut announced = false;
    let admitted = (|| {
        let store = ProfileStore::for_user(caller.uid).map_err(store_error)?;
        store.load().map_err(store_error)?;
        let lock = wait_for_mode_lock(
            mode,
            &mut caller.stream,
            PREVIOUS_SESSION_WAIT,
            &mut announced,
            ControllerLock::acquire,
        )?;
        let (build, _) = crate::install::engine::admit_uid(caller.uid)
            .map_err(|_| ErrorCode::UntrustedConfiguration)?;
        Ok((store, lock, build))
    })();
    let (store, lock, build) = match admitted {
        Ok(value) => value,
        Err(error) => {
            send_admission_error(&mut caller.stream, announced, error);
            return Err(error);
        }
    };
    if mode == Mode::Runtime
        && let Some(controller) = lock.as_ref()
    {
        crate::connection::ipsec::NativeContext::recover_orphans(controller, caller.uid);
    }
    match mode {
        Mode::Runtime => runtime_with_build(caller, Some(build), |uid, requests, output| {
            crate::connection::controller::run_ssl(
                lock.as_ref().ok_or(ErrorCode::Unavailable)?,
                uid,
                requests,
                output,
            )
        }),
        Mode::Admin => admin(caller, |_, request| apply_admin(&store, request)),
    }
}

/// Runs the Linux helper using its inherited protocol socket.
///
/// # Safety
/// FD 0 must not have a Rust owner or aliases; this consumes it as the sole
/// duplex protocol channel and never uses stdout/stderr for protocol data.
#[cfg(target_os = "linux")]
pub unsafe fn linux_run(mode: Mode) -> Result<(), ErrorCode> {
    let uid = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };
    check_process_uid(uid, effective)?;
    if unsafe { libc::fcntl(0, libc::F_GETFD) } < 0 {
        return Err(ErrorCode::PermissionDenied);
    }
    let mut caller = Caller::from_fd(unsafe { OwnedFd::from_raw_fd(0) })
        .map_err(|_| ErrorCode::PermissionDenied)?;
    check_peer_uid(caller.uid, effective)?;
    let _signals = signals::Guard::install().map_err(|_| ErrorCode::Unavailable)?;
    let mut announced = false;
    let admitted = (|| {
        let store = ProfileStore::for_current_user().map_err(store_error)?;
        store.load().map_err(store_error)?;
        let lock = wait_for_mode_lock(
            mode,
            &mut caller.stream,
            PREVIOUS_SESSION_WAIT,
            &mut announced,
            || super::user_lock::UserLock::acquire(&store, effective),
        )?;
        let build = build_identity()?;
        Ok((store, lock, build))
    })();
    let (store, _lock, build) = match admitted {
        Ok(value) => value,
        Err(error) => {
            send_admission_error(&mut caller.stream, announced, error);
            return Err(error);
        }
    };
    match mode {
        Mode::Runtime => runtime_with_diagnostics(
            caller,
            Some(build),
            Arc::new(|_| (protocol::DiagnosticsStatus::Unavailable, vec![])),
            crate::connection::controller::run_linux,
        ),
        Mode::Admin => admin(caller, |_, request| apply_admin(&store, request)),
    }
}

#[cfg(target_os = "linux")]
fn check_process_uid(uid: u32, effective: u32) -> Result<(), ErrorCode> {
    if uid == 0 || effective == 0 {
        Err(ErrorCode::PermissionDenied)
    } else {
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn check_peer_uid(peer: u32, effective: u32) -> Result<(), ErrorCode> {
    if peer != effective {
        Err(ErrorCode::PermissionDenied)
    } else {
        Ok(())
    }
}
#[cfg(all(test, target_os = "linux"))]
mod linux_uid_tests {
    use super::*;
    #[test]
    fn rejects_root_and_foreign_peer() {
        assert_eq!(check_process_uid(0, 1000), Err(ErrorCode::PermissionDenied));
        assert_eq!(check_process_uid(1000, 0), Err(ErrorCode::PermissionDenied));
        assert_eq!(check_process_uid(1000, 1000), Ok(()));
        assert_eq!(check_peer_uid(1001, 1000), Err(ErrorCode::PermissionDenied));
        assert_eq!(check_peer_uid(1000, 1000), Ok(()));
    }
}

#[cfg(target_os = "linux")]
fn build_identity() -> Result<String, ErrorCode> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    const LIMIT: u64 = 256 * 1024 * 1024;
    let file = std::fs::File::open("/proc/self/exe").map_err(|_| ErrorCode::Unavailable)?;
    let mut reader = file.take(LIMIT + 1);
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 16384];
    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|_| ErrorCode::Unavailable)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > LIMIT {
            return Err(ErrorCode::Unavailable);
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn store_error(error: StoreError) -> ErrorCode {
    match error {
        StoreError::NotFound => ErrorCode::ProfileNotFound,
        StoreError::Io => ErrorCode::Unavailable,
        StoreError::Busy => ErrorCode::ProfileBusy,
        _ => ErrorCode::UntrustedConfiguration,
    }
}
fn apply_admin(store: &ProfileStore, request: protocol::AdminRequest) -> Message {
    let result = (|| {
        if interrupted() {
            return Err(ErrorCode::Unavailable);
        }
        match request.command {
            AdminCommand::SaveProfile {
                profile,
                ovpn_config,
            } => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let normalized = if let Some(text) = ovpn_config {
                        if profile.kind != crate::model::VpnKind::Ovpn {
                            return Err(ErrorCode::InvalidRequest);
                        }
                        Some(
                            crate::connection::ovpn::profile::inspect(text.as_bytes())
                                .map_err(|_| ErrorCode::InvalidRequest)?
                                .normalized,
                        )
                    } else {
                        None
                    };
                    store
                        .save_admin_profile(profile, normalized.as_deref())
                        .map_err(|error| {
                            if error == StoreError::InvalidData {
                                ErrorCode::InvalidRequest
                            } else {
                                store_error(error)
                            }
                        })
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    if ovpn_config.is_some() {
                        return Err(ErrorCode::InvalidRequest);
                    }
                    store.save(profile).map_err(store_error)
                }
            }
            AdminCommand::RemoveProfile { id } => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let result = store.remove_admin_profile(&id);
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                let result = store.remove(&id);
                result.map_err(store_error)
            }
        }
    })();
    match result {
        Ok(()) => Message::Accepted { id: request.id },
        Err(error) => Message::Failed {
            id: request.id,
            error,
        },
    }
}
fn send(stream: &mut UnixStream, message: &Message) -> Result<(), ErrorCode> {
    let mut output = io::Output::new(stream).map_err(|_| ErrorCode::Unavailable)?;
    protocol::write_message(&mut output, message).map_err(|_| ErrorCode::Unavailable)
}
fn admin(
    caller: Caller,
    apply: impl FnOnce(u32, protocol::AdminRequest) -> Message,
) -> Result<(), ErrorCode> {
    let uid = caller.uid;
    let mut stream = caller.stream;
    send(
        &mut stream,
        &Message::AdminReady {
            protocol_version: protocol::VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
        },
    )?;
    let input = stream.try_clone().map_err(|_| ErrorCode::Unavailable)?;
    let mut input = io::Input::new(input, Arc::new(AtomicBool::new(false)))
        .map_err(|_| ErrorCode::Unavailable)?;
    input.begin(true); // Administration includes the one document AND EOF in the deadline.
    let request = protocol::read_admin_request(&mut input);
    match request {
        Ok(request) => send(&mut stream, &apply(uid, request)),
        Err(_) => {
            let _ = send(
                &mut stream,
                &Message::Fatal {
                    error: ErrorCode::InvalidRequest,
                },
            );
            Err(ErrorCode::InvalidRequest)
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
fn runtime(
    caller: Caller,
    run: impl FnOnce(u32, Receiver<Request>, SyncSender<Message>) -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    runtime_with_build(caller, None, run)
}

#[cfg(target_os = "macos")]
fn runtime_with_build(
    caller: Caller,
    build: Option<String>,
    run: impl FnOnce(u32, Receiver<Request>, SyncSender<Message>) -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    runtime_with_diagnostics(caller, build, Arc::new(system_diagnostics), run)
}

type Diagnostics =
    Arc<dyn Fn(u32) -> (protocol::DiagnosticsStatus, Vec<super::diagnostics::Log>) + Send + Sync>;
#[cfg(target_os = "macos")]
fn system_diagnostics(uid: u32) -> (protocol::DiagnosticsStatus, Vec<super::diagnostics::Log>) {
    gated_diagnostics(
        || crate::install::engine::admit_uid(uid).map(|(_, sole)| sole),
        || super::diagnostics::collect(std::path::Path::new(super::paths::STATE), 0, || true),
    )
}
#[cfg(target_os = "macos")]
pub(crate) fn gated_diagnostics(
    admit: impl FnOnce() -> Result<bool, crate::install::Error>,
    read: impl FnOnce() -> Option<Vec<super::diagnostics::Log>>,
) -> (protocol::DiagnosticsStatus, Vec<super::diagnostics::Log>) {
    use protocol::DiagnosticsStatus as Status;
    match admit() {
        Ok(false) => (Status::Shared, vec![]),
        Ok(true) => match read() {
            Some(logs) => (Status::Ready, logs),
            None => (Status::Unavailable, vec![]),
        },
        Err(_) => (Status::Unavailable, vec![]),
    }
}
fn runtime_with_diagnostics(
    caller: Caller,
    build: Option<String>,
    diagnostics: Diagnostics,
    run: impl FnOnce(u32, Receiver<Request>, SyncSender<Message>) -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    let stop = Arc::new(AtomicBool::new(false));
    let input = caller
        .stream
        .try_clone()
        .and_then(|s| io::Input::new(s, stop.clone()))
        .map_err(|_| ErrorCode::Unavailable)?;
    let (requests, receive) = mpsc::sync_channel(32);
    let (output, outgoing) = mpsc::sync_channel(32);
    thread::scope(|scope| {
        struct Stop(Arc<AtomicBool>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let guard = Stop(stop.clone());
        let reader_output = output.clone();
        let reader_stop = stop.clone();
        let uid = caller.uid;
        let reader = thread::Builder::new()
            .name("vpnt-input".into())
            .spawn_scoped(scope, move || {
                read_requests(
                    input,
                    requests,
                    reader_output,
                    &reader_stop,
                    uid,
                    diagnostics,
                );
            })
            .map_err(|_| ErrorCode::Unavailable)?;
        let mut stream = caller.stream;
        let writer_stop = stop.clone();
        let writer = thread::Builder::new()
            .name("vpnt-output".into())
            .spawn_scoped(scope, move || {
                for mut message in outgoing {
                    if let Message::Snapshot { build: field, .. } = &mut message {
                        *field = build.clone();
                    }
                    if send(&mut stream, &message).is_err() {
                        writer_stop.store(true, Ordering::Release);
                        return Err(ErrorCode::Unavailable);
                    }
                }
                Ok(())
            })
            .map_err(|_| ErrorCode::Unavailable)?;
        let result = run(caller.uid, receive, output.clone());
        if let Err(error) = result {
            let _ = output.try_send(Message::Fatal { error });
        }
        drop(guard); // unblocks a partial/idle read before joining; no child timeout.
        drop(output);
        reader.join().map_err(|_| ErrorCode::Unavailable)?;
        let written = writer.join().map_err(|_| ErrorCode::Unavailable)?;
        result.and(written)
    })
}
fn read_requests(
    input: io::Input,
    requests: SyncSender<Request>,
    output: SyncSender<Message>,
    stop: &AtomicBool,
    uid: u32,
    diagnostics: Diagnostics,
) {
    let mut reader = input;
    loop {
        reader.begin(false);
        let request = match protocol::read_request(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(_) => {
                if !stop.load(Ordering::Acquire) && !interrupted() {
                    let _ = output.try_send(Message::Fatal {
                        error: ErrorCode::InvalidRequest,
                    });
                }
                return;
            }
        };
        if matches!(request.command, protocol::Command::Diagnostics {}) {
            let (status, logs) = diagnostics(uid);
            let mut message = Message::Diagnostics {
                id: request.id,
                status,
                logs,
            };
            loop {
                if stop.load(Ordering::Acquire) || interrupted() {
                    return;
                }
                match output.try_send(message) {
                    Ok(()) => break,
                    Err(TrySendError::Full(value)) => message = value,
                    Err(TrySendError::Disconnected(_)) => return,
                }
                thread::sleep(Duration::from_millis(20));
            }
            continue;
        }
        let mut pending = request;
        loop {
            if stop.load(Ordering::Acquire) || interrupted() {
                return;
            }
            match requests.try_send(pending) {
                Ok(()) => break,
                Err(TrySendError::Full(request)) => pending = request,
                Err(TrySendError::Disconnected(_)) => return,
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn runtime_fixture(
    stream: UnixStream,
    run: impl FnOnce(u32, Receiver<Request>, SyncSender<Message>) -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    let caller = Caller::from_fd(stream.into()).map_err(|_| ErrorCode::PermissionDenied)?;
    runtime(caller, run)
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod tests;
