//! Linux netd socket admission, interface reservations, and session cleanup.
use super::{
    iproute::{Backend, IpRoute},
    protocol::{
        ErrorCode, Request, Response, TunName, VERSION, encode_response, parse_request, read_line,
    },
};
use crate::helper::local_socket::peer_uid;
use std::{
    collections::HashSet,
    ffi::{CString, OsString},
    fs::{self, DirBuilder},
    io::{self, BufReader, Read, Write},
    os::{
        fd::FromRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn admit(uid: u32) -> Result<(), ErrorCode> {
    if uid == 0 {
        Err(ErrorCode::NotOwned)
    } else {
        Ok(())
    }
}

pub(super) struct Server<B> {
    backend: B,
    reserved: Mutex<HashSet<TunName>>,
    active: Mutex<usize>,
    hello_timeout: Duration,
}
impl<B: Backend + 'static> Server<B> {
    pub(super) fn new(backend: B, hello_timeout: Duration) -> Self {
        Self {
            backend,
            reserved: Mutex::new(HashSet::new()),
            active: Mutex::new(0),
            hello_timeout,
        }
    }
    fn startup(&self) -> io::Result<()> {
        for name in self.backend.existing()? {
            if self.backend.delete_tun(&name).is_err() {
                log_tun("startup_delete_failed", 0, &name);
            }
        }
        Ok(())
    }
    pub(super) fn dispatch(
        self: &Arc<Self>,
        stream: UnixStream,
        identify: impl FnOnce(&UnixStream) -> io::Result<u32> + Send + 'static,
    ) -> Option<thread::JoinHandle<()>> {
        {
            let mut active = self.active.lock().expect("connection count mutex");
            if *active >= 8 {
                return None;
            }
            *active += 1;
        }
        // If spawning fails, dropping the closure releases the slot.
        let slot = OwnedSlot(Arc::clone(self));
        thread::Builder::new()
            .spawn(move || {
                if let Ok(uid) = identify(&stream) {
                    let _ = slot.0.session(&stream, uid);
                }
            })
            .ok()
    }
    fn session(&self, mut stream: &UnixStream, uid: u32) -> io::Result<()> {
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        if let Err(error) = admit(uid) {
            return reply(stream, Response::Error(error));
        }
        let mut reader = BufReader::new(SessionReader {
            stream,
            deadline: Some(Instant::now() + self.hello_timeout),
        });
        let hello = read_line(&mut reader)?;
        if hello.is_empty() {
            return Ok(());
        }
        match parse_request(&hello) {
            Ok(Request::Hello { .. }) => reply(stream, Response::Version(VERSION))?,
            Err(ErrorCode::UnsupportedVersion) => {
                return reply(stream, Response::Error(ErrorCode::UnsupportedVersion));
            }
            _ => return reply(stream, Response::Error(ErrorCode::BadRequest)),
        }
        stream.set_read_timeout(None)?;
        reader.get_mut().deadline = None;
        let mut lease = Session {
            server: self,
            uid,
            owned: Vec::new(),
        };
        loop {
            let line = read_line(&mut reader)?;
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
            .find(|name| !reserved.contains(name) && !existing.contains(name))
            .ok_or(ErrorCode::Limit)?;
        reserved.insert(name.clone());
        drop(reserved);
        if self.backend.create_tun(&name, uid).is_err() {
            self.release(&name);
            log_tun("create_failed", uid, &name);
            return Err(ErrorCode::Backend);
        }
        log_tun("created", uid, &name);
        Ok(name)
    }
    fn release(&self, name: &TunName) {
        self.reserved
            .lock()
            .expect("reservation mutex")
            .remove(name);
    }
}
struct OwnedSlot<B>(Arc<Server<B>>);
impl<B> Drop for OwnedSlot<B> {
    fn drop(&mut self) {
        *self.0.active.lock().expect("connection count mutex") -= 1;
    }
}

struct SessionReader<'a> {
    stream: &'a UnixStream,
    deadline: Option<Instant>,
}
impl Read for SessionReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.stream.set_read_timeout(Some(left))?;
        }
        self.stream.read(buffer)
    }
}
fn reply(mut stream: &UnixStream, response: Response) -> io::Result<()> {
    stream.write_all(&encode_response(&response))
}
fn log_tun(event: &str, uid: u32, name: &TunName) {
    // A closed journal stream must not interrupt resource cleanup.
    let _ = writeln!(io::stderr().lock(), "{event} uid={uid} tun={name}");
}

struct Session<'a, B: Backend + 'static> {
    server: &'a Server<B>,
    uid: u32,
    owned: Vec<TunName>,
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
                self.server.backend.configure(&config).map_err(|_| {
                    log_tun("configure_failed", self.uid, &name);
                    ErrorCode::Backend
                })?;
                log_tun("configured", self.uid, &name);
                Ok(Response::Ok)
            }
            Request::CloseTun { ifname } => {
                let name = TunName::parse(&ifname)?;
                if !self.owned.contains(&name) {
                    return Err(ErrorCode::NotOwned);
                }
                self.delete(&name)?;
                self.owned.retain(|owned| *owned != name);
                Ok(Response::Ok)
            }
        }
    }
    fn delete(&self, name: &TunName) -> Result<(), ErrorCode> {
        self.server.backend.delete_tun(name).map_err(|_| {
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
            if self.delete(name).is_err() {
                // The next allocation rechecks the kernel inventory before reusing the name.
                self.server.release(name);
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
