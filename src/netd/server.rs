//! Linux netd socket admission, interface reservations, and session cleanup.
use super::{
    iproute::{Backend, Existing, IpRoute, PartialCreate},
    protocol::{
        ErrorCode, Request, Response, TunName, VERSION, encode_response, parse_request, read_line,
    },
};
use crate::helper::local_socket::peer_uid;
use std::{
    collections::{HashMap, HashSet},
    ffi::{CString, OsString},
    fs::{self, DirBuilder},
    io::{self, BufReader, Read, Write},
    num::NonZeroU32,
    os::{
        fd::FromRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn admit(uid: u32) -> Result<(), ErrorCode> {
    if uid == 0 {
        Err(ErrorCode::NotOwned)
    } else {
        Ok(())
    }
}

/// Clean up previously marked links. Return links whose deletion failed so the
/// server can keep their names reserved and retry after startup.
#[doc(hidden)]
pub fn cleanup_startup(backend: &impl Backend) -> io::Result<Vec<TunName>> {
    let mut pending = Vec::new();
    for entry in backend.existing()? {
        if !entry.owned {
            log_tun("startup_name_conflict", 0, &entry.name);
        } else if backend.delete_tun(&entry.name).is_err() {
            log_tun("startup_delete_failed", 0, &entry.name);
            pending.push(entry.name);
        }
    }
    Ok(pending)
}

#[derive(Default)]
struct RetryPass {
    done: Mutex<bool>,
    finished: Condvar,
}

#[derive(Clone, Copy)]
enum CleanupProof {
    Marked,
    // Process-local evidence. After restart an unmarked link is reported
    // as a name conflict and will not be deleted.
    Created { ifindex: NonZeroU32 },
}
impl CleanupProof {
    fn matches(self, entry: &Existing) -> bool {
        match self {
            Self::Marked => entry.owned,
            Self::Created { ifindex } => entry.is_tun && entry.ifindex == ifindex,
        }
    }
}

pub(super) struct Server<B> {
    backend: B,
    reserved: Mutex<HashSet<TunName>>,
    active: Mutex<HashMap<u32, usize>>,
    pending: Mutex<HashMap<TunName, CleanupProof>>,
    retry: Mutex<Option<Arc<RetryPass>>>,
    hello_timeout: Duration,
    idle_timeout: Duration,
    frame_timeout: Duration,
}
impl<B: Backend + 'static> Server<B> {
    pub(super) fn new(backend: B, hello_timeout: Duration) -> Self {
        Self {
            backend,
            reserved: Mutex::new(HashSet::new()),
            active: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            retry: Mutex::new(None),
            hello_timeout,
            idle_timeout: IDLE_TIMEOUT,
            frame_timeout: FRAME_TIMEOUT,
        }
    }
    fn startup(&self) -> io::Result<()> {
        let pending = cleanup_startup(&self.backend)?;
        self.reserved
            .lock()
            .expect("reservation mutex")
            .extend(pending.iter().cloned());
        self.pending
            .lock()
            .expect("pending mutex")
            .extend(pending.into_iter().map(|name| (name, CleanupProof::Marked)));
        Ok(())
    }
    fn retry_pending(self: &Arc<Self>, wait: bool) {
        let pass = {
            let mut running = self.retry.lock().expect("retry mutex");
            if let Some(pass) = running.as_ref() {
                Arc::clone(pass)
            } else {
                if self.pending.lock().expect("pending mutex").is_empty() {
                    return;
                }
                let pass = Arc::new(RetryPass::default());
                *running = Some(Arc::clone(&pass));
                let server = Arc::clone(self);
                let worker_pass = Arc::clone(&pass);
                if thread::Builder::new()
                    .spawn(move || {
                        server.retry_pass();
                        let mut running = server.retry.lock().expect("retry mutex");
                        *running = None;
                        *worker_pass.done.lock().expect("retry pass mutex") = true;
                        worker_pass.finished.notify_all();
                    })
                    .is_err()
                {
                    *running = None;
                    return;
                }
                pass
            }
        };
        if wait {
            let done = pass.done.lock().expect("retry pass mutex");
            let _result =
                pass.finished
                    .wait_timeout_while(done, self.backend.retry_wait(), |done| !*done);
        }
    }
    fn retry_pass(&self) {
        let names = self.pending.lock().expect("pending mutex").clone();
        for (name, proof) in names {
            // Refresh for each deletion. A pass can outlast one backend deadline.
            let Ok(existing) = self.backend.existing() else {
                log_tun("cleanup_inventory_failed", 0, &name);
                continue;
            };
            match existing.iter().find(|entry| entry.name == name) {
                Some(entry) if !proof.matches(entry) => {
                    log_tun("cleanup_name_conflict", 0, &name);
                    continue;
                }
                Some(_) if self.backend.delete_tun(&name).is_err() => {
                    log_tun("cleanup_retry_failed", 0, &name);
                    continue;
                }
                _ => {}
            }
            self.pending.lock().expect("pending mutex").remove(&name);
            self.release(&name);
            log_tun("cleanup_released", 0, &name);
        }
    }
    pub(super) fn dispatch(
        self: &Arc<Self>,
        stream: UnixStream,
        identify: impl FnOnce(&UnixStream) -> io::Result<u32> + Send + 'static,
    ) -> Option<thread::JoinHandle<()>> {
        let accepted = Instant::now();
        let uid = identify(&stream).ok()?;
        {
            let mut active = self.active.lock().expect("connection count mutex");
            if active.values().sum::<usize>() >= 8 || active.get(&uid).copied().unwrap_or(0) >= 2 {
                return None;
            }
            *active.entry(uid).or_default() += 1;
        }
        let slot = OwnedSlot {
            server: Arc::clone(self),
            uid,
        };
        thread::Builder::new()
            .spawn(move || {
                if admit(uid).is_ok() {
                    slot.server.retry_pending(false);
                }
                let _ = slot.server.session(&stream, uid, accepted);
            })
            .ok()
    }
    fn session(
        self: &Arc<Self>,
        mut stream: &UnixStream,
        uid: u32,
        accepted: Instant,
    ) -> io::Result<()> {
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        if let Err(error) = admit(uid) {
            return reply(stream, Response::Error(error));
        }
        let mut reader = BufReader::new(SessionReader {
            stream,
            deadline: None,
            frame_start: None,
            last_read: None,
            frame_timeout: self.frame_timeout,
        });
        let hello = read_frame(&mut reader, Some(accepted + self.hello_timeout))?;
        if hello.is_empty() {
            return Ok(());
        }
        let mut last_request = Instant::now();
        match parse_request(&hello) {
            Ok(Request::Hello { .. }) => reply(stream, Response::Version(VERSION))?,
            Err(ErrorCode::UnsupportedVersion) => {
                return reply(stream, Response::Error(ErrorCode::UnsupportedVersion));
            }
            _ => return reply(stream, Response::Error(ErrorCode::BadRequest)),
        }
        let mut lease = Session {
            server: self,
            uid,
            owned: Vec::new(),
            close_failed: Vec::new(),
        };
        loop {
            let idle = lease
                .owned
                .is_empty()
                .then(|| last_request + self.idle_timeout);
            let line = read_frame(&mut reader, idle)?;
            last_request = Instant::now();
            if line.is_empty() {
                return Ok(());
            }
            let request = match parse_request(&line) {
                Ok(request) => request,
                Err(error) => return reply(stream, Response::Error(error)),
            };
            stream.write_all(&encode_response(&lease.handle(request)))?;
        }
    }
    fn create(&self, uid: u32) -> Result<TunName, ErrorCode> {
        let mut reserved = self.reserved.lock().expect("reservation mutex");
        let existing = self.backend.existing().map_err(|_| ErrorCode::Backend)?;
        let name = (0..100)
            .map(|index| TunName::parse(&format!("vpnt{index}")).expect("generated name"))
            .find(|name| {
                !reserved.contains(name) && !existing.iter().any(|entry| &entry.name == name)
            })
            .ok_or(ErrorCode::Limit)?;
        reserved.insert(name.clone());
        drop(reserved);
        if let Err(error) = self.backend.create_tun(&name, uid) {
            if let Some(partial) = error
                .get_ref()
                .and_then(|source| source.downcast_ref::<PartialCreate>())
            {
                self.defer(
                    &name,
                    CleanupProof::Created {
                        ifindex: partial.ifindex,
                    },
                );
                log_tun("create_cleanup_pending", uid, &name);
            } else {
                self.release(&name);
                log_tun("create_failed", uid, &name);
            }
            return Err(ErrorCode::Backend);
        }
        log_tun("created", uid, &name);
        Ok(name)
    }
    fn defer(&self, name: &TunName, proof: CleanupProof) {
        self.pending
            .lock()
            .expect("pending mutex")
            .insert(name.clone(), proof);
    }
    fn release(&self, name: &TunName) {
        self.reserved
            .lock()
            .expect("reservation mutex")
            .remove(name);
    }
}
struct OwnedSlot<B> {
    server: Arc<Server<B>>,
    uid: u32,
}
impl<B> Drop for OwnedSlot<B> {
    fn drop(&mut self) {
        let mut active = self.server.active.lock().expect("connection count mutex");
        let count = active.get_mut(&self.uid).expect("allocated slot");
        *count -= 1;
        if *count == 0 {
            active.remove(&self.uid);
        }
    }
}

struct SessionReader<'a> {
    stream: &'a UnixStream,
    deadline: Option<Instant>,
    frame_start: Option<Instant>,
    last_read: Option<Instant>,
    frame_timeout: Duration,
}
impl SessionReader<'_> {
    fn remaining(&self) -> io::Result<Option<Duration>> {
        let frame_limit = self.frame_start.map(|start| start + self.frame_timeout);
        let deadline = self.deadline.into_iter().chain(frame_limit).min();
        deadline
            .map(|deadline| {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                Ok(remaining)
            })
            .transpose()
    }
}
impl Read for SessionReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(self.remaining()?)?;
        let count = self.stream.read(buffer)?;
        self.remaining()?;
        if count != 0 {
            let now = Instant::now();
            self.last_read = Some(now);
            self.frame_start.get_or_insert(now);
        }
        Ok(count)
    }
}
fn read_frame(
    reader: &mut BufReader<SessionReader<'_>>,
    deadline: Option<Instant>,
) -> io::Result<Vec<u8>> {
    // Bytes already buffered with their terminator completed on the last read.
    // Time spent processing the preceding request does not make that line partial.
    if reader.buffer().contains(&b'\n') {
        return read_line(reader);
    }
    let buffered = !reader.buffer().is_empty();
    let state = reader.get_mut();
    state.deadline = deadline;
    state.frame_start = if buffered { state.last_read } else { None };
    state.remaining()?;
    read_line(reader)
}
fn reply(mut stream: &UnixStream, response: Response) -> io::Result<()> {
    stream.write_all(&encode_response(&response))
}
fn log_tun(event: &str, uid: u32, name: &TunName) {
    // A closed journal stream must not interrupt resource cleanup.
    let _ = writeln!(io::stderr().lock(), "{event} uid={uid} tun={name}");
}

struct Session<'a, B: Backend + 'static> {
    server: &'a Arc<Server<B>>,
    uid: u32,
    owned: Vec<TunName>,
    /// Owned names whose close_tun failed. Another actor may have replaced the
    /// device since, so any later delete, retry or disconnect, checks the mark.
    close_failed: Vec<TunName>,
}
impl<B: Backend + 'static> Session<'_, B> {
    fn handle(&mut self, request: Request) -> Response {
        match self.apply(request) {
            Ok(response) => response,
            Err(error) => Response::Error(error),
        }
    }
    fn apply(&mut self, request: Request) -> Result<Response, ErrorCode> {
        match request {
            Request::Hello { .. } => Err(ErrorCode::BadRequest),
            Request::OpenTun => {
                if self.owned.len() >= 2 {
                    return Err(ErrorCode::Limit);
                }
                self.server.retry_pending(true);
                let name = self.server.create(self.uid)?;
                self.owned.push(name.clone());
                Ok(Response::Opened(name))
            }
            Request::Configure(request) => {
                let name = TunName::parse(&request.ifname)?;
                if !self.owned.contains(&name) {
                    return Err(ErrorCode::NotOwned);
                }
                let config = request.validate()?;
                self.server.backend.configure(&config).map_err(|error| {
                    log_tun("configure_failed", self.uid, &name);
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        ErrorCode::RouteConflict
                    } else {
                        ErrorCode::Backend
                    }
                })?;
                log_tun("configured", self.uid, &name);
                Ok(Response::Ok)
            }
            Request::CloseTun { ifname } => {
                let name = TunName::parse(&ifname)?;
                if !self.owned.contains(&name) {
                    return Err(ErrorCode::NotOwned);
                }
                if let Err(error) = self.delete_marked(&name) {
                    if !self.close_failed.contains(&name) {
                        self.close_failed.push(name);
                    }
                    return Err(error);
                }
                self.server.release(&name);
                self.owned.retain(|owned| *owned != name);
                self.close_failed.retain(|failed| *failed != name);
                Ok(Response::Ok)
            }
        }
    }
    /// Deletes the device only while it is still a marked helper tun: a
    /// missing device needs nothing, and an unmarked one is not ours anymore.
    fn delete_marked(&self, name: &TunName) -> Result<(), ErrorCode> {
        let existing = self
            .server
            .backend
            .existing()
            .map_err(|_| ErrorCode::Backend)?;
        match existing.iter().find(|entry| entry.name == *name) {
            None => {}
            Some(entry) if !CleanupProof::Marked.matches(entry) => {
                log_tun("close_name_conflict", self.uid, name);
            }
            Some(_) => {
                // The helper trusts other CAP_NET_ADMIN actors: they could
                // replace a link between this inventory and deletion by name.
                self.server.backend.delete_tun(name).map_err(|_| {
                    log_tun("delete_failed", self.uid, name);
                    ErrorCode::Backend
                })?;
            }
        }
        Ok(())
    }
    fn delete(&self, name: &TunName) -> Result<(), ErrorCode> {
        self.server.backend.delete_tun(name).map_err(|_| {
            self.server.defer(name, CleanupProof::Marked);
            log_tun("delete_failed", self.uid, name);
            ErrorCode::Backend
        })?;
        self.server.release(name);
        log_tun("deleted", self.uid, name);
        Ok(())
    }
}
impl<B: Backend + 'static> Drop for Session<'_, B> {
    fn drop(&mut self) {
        for name in &self.owned {
            if !self.close_failed.contains(name) {
                let _ = self.delete(name);
            } else if self.delete_marked(name).is_ok() {
                self.server.release(name);
                log_tun("deleted", self.uid, name);
            } else {
                self.server.defer(name, CleanupProof::Marked);
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Activated,
    Development { path: PathBuf, owner: u32 },
}
fn mode(args: &[OsString], activated: bool) -> Option<Mode> {
    match args {
        [] if activated => Some(Mode::Activated),
        [flag, path, owner_flag, owner]
            if flag == "--socket"
                && owner_flag == "--socket-owner"
                && !path.is_empty()
                && !activated =>
        {
            let owner = owner.to_str()?;
            if owner.is_empty() || !owner.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let owner = owner.parse().ok()?;
            if owner == u32::MAX {
                return None;
            }
            Some(Mode::Development {
                path: PathBuf::from(path),
                owner,
            })
        }
        _ => None,
    }
}

fn check_listener(fd: std::os::fd::RawFd) -> io::Result<()> {
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_STREAM),
        (libc::SO_ACCEPTCONN, 1),
    ] {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: the output buffer has the expected size for the integer option.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if value != expected || len as usize != std::mem::size_of_val(&value) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(())
}

fn development_listener(path: &Path, owner: u32) -> io::Result<UnixListener> {
    let path = std::path::absolute(path)?;
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let mut directory = PathBuf::new();
    for component in parent.components() {
        directory.push(component);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new().mode(0o755).create(&directory)?;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
                fs::symlink_metadata(&directory)?
            }
            Err(error) => return Err(error),
        };
        // Protect unlink, bind, chown and chmod from pathname replacement.
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&path)?,
        Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: called only at standalone startup before worker threads exist.
    let previous = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(&path);
    // SAFETY: restore the process umask immediately after bind.
    unsafe { libc::umask(previous) };
    let listener = listener?;
    // SAFETY: cpath is NUL terminated and its ancestors cannot be replaced by the client.
    let ownership = if unsafe { libc::chown(cpath.as_ptr(), owner, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    if let Err(error) =
        ownership.and_then(|()| fs::set_permissions(&path, fs::Permissions::from_mode(0o600)))
    {
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(listener)
}

/// Run the standalone Linux helper.
///
/// # Safety
/// Call only from the standalone main thread before worker threads start.
/// With activation, descriptor 3 must belong exclusively to this process entry point.
pub unsafe fn run_linux(args: &[OsString]) -> i32 {
    let activated = activation_requested();
    // SAFETY: standalone single-threaded startup, as required by the caller contract.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    let Some(mode) = mode(args, activated) else {
        return 64;
    };
    // SAFETY: no arguments or memory requirements.
    if unsafe { libc::geteuid() } != 0 {
        return 77;
    }
    let listener = match mode {
        Mode::Activated => {
            if check_listener(3).is_err() {
                return 1;
            }
            // SAFETY: activation supplied fd 3, validated above, and transfers ownership.
            let listener = unsafe { UnixListener::from_raw_fd(3) };
            // SAFETY: fd 3 is owned by listener. Keep it out of backend subprocesses.
            if unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return 1;
            }
            Ok(listener)
        }
        Mode::Development { path, owner } => development_listener(&path, owner),
    };
    let Ok(listener) = listener else {
        return 1;
    };
    let server = Arc::new(Server::new(IpRoute::system(), HELLO_TIMEOUT));
    if server.startup().is_err() {
        return 1;
    }
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                server.dispatch(stream, peer_uid);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return 1,
        }
    }
    0
}
fn activation_requested() -> bool {
    std::env::var("LISTEN_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok())
        == Some(std::process::id())
        && std::env::var("LISTEN_FDS").as_deref() == Ok("1")
}

#[cfg(test)]
#[path = "server_tests.rs"]
pub(super) mod tests;
