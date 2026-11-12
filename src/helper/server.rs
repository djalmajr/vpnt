//! Root entrypoint with closed modes and a private inherited Unix channel.
//! The socket's kernel peer UID, not IPC or sudo environment, selects storage.
mod caller;
mod io;
use super::{
    controller_lock::ControllerLock,
    ppp_supervisor::signals,
    protocol::{self, AdminCommand, ErrorCode, Message, Request},
};
use crate::storage::{ProfileStore, StoreError};
use caller::Caller;
use std::{
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

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
    let caller = Caller::from_fd(unsafe { OwnedFd::from_raw_fd(0) })
        .map_err(|_| ErrorCode::PermissionDenied)?;
    let _signals = signals::Guard::install().map_err(|_| ErrorCode::Unavailable)?;
    let admitted = (|| {
        let store = ProfileStore::for_user(caller.uid).map_err(store_error)?;
        store.load().map_err(store_error)?;
        let lock = ControllerLock::acquire().map_err(|error| match error {
            super::controller_lock::LockError::Busy => ErrorCode::ProfileBusy,
            _ => ErrorCode::UntrustedConfiguration,
        })?;
        Ok((store, lock))
    })();
    let (store, lock) = match admitted {
        Ok(value) => value,
        Err(error) => {
            let mut stream = caller.stream;
            let _ = send(&mut stream, &Message::Fatal { error });
            return Err(error);
        }
    };
    match mode {
        Mode::Runtime => runtime(caller, |uid, requests, output| {
            crate::connection::controller::run_ssl(&lock, uid, requests, output)
        }),
        Mode::Admin => admin(caller, |_, request| apply_admin(&lock, &store, request)),
    }
}

fn store_error(error: StoreError) -> ErrorCode {
    match error {
        StoreError::NotFound => ErrorCode::ProfileNotFound,
        StoreError::Io => ErrorCode::Unavailable,
        _ => ErrorCode::UntrustedConfiguration,
    }
}
fn apply_admin(
    lock: &ControllerLock,
    store: &ProfileStore,
    request: protocol::AdminRequest,
) -> Message {
    let result = lock
        .validate()
        .map_err(|_| ErrorCode::UntrustedConfiguration)
        .and_then(|()| {
            if interrupted() {
                return Err(ErrorCode::Unavailable);
            }
            match request.command {
                AdminCommand::SaveProfile { profile } => store.save(profile),
                AdminCommand::RemoveProfile { id } => store.remove(&id),
            }
            .map_err(store_error)
        });
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

fn runtime(
    caller: Caller,
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
        let reader = thread::Builder::new()
            .name("vpnt-input".into())
            .spawn_scoped(scope, move || {
                read_requests(input, requests, reader_output, &reader_stop);
            })
            .map_err(|_| ErrorCode::Unavailable)?;
        let mut stream = caller.stream;
        let writer_stop = stop.clone();
        let writer = thread::Builder::new()
            .name("vpnt-output".into())
            .spawn_scoped(scope, move || {
                for message in outgoing {
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

#[cfg(test)]
pub(crate) fn runtime_fixture(
    stream: UnixStream,
    run: impl FnOnce(u32, Receiver<Request>, SyncSender<Message>) -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    let caller = Caller::from_fd(stream.into()).map_err(|_| ErrorCode::PermissionDenied)?;
    runtime(caller, run)
}

#[cfg(test)]
mod tests;
