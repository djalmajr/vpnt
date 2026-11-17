//! Private user-side persistence for already-redacted helper diagnostics.
use super::{Broker, State};
use crate::helper::{
    diagnostics::{Log, Status},
    protocol::DiagnosticsStatus,
};
use crate::{
    helper::protocol::{Command, Request},
    secrets::SecretStore,
};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub(super) fn ended(previous: State, was_cleaning: bool, next: State, cleaning: bool) -> bool {
    let terminal = matches!(
        next,
        State::Off
            | State::Dropped
            | State::CredentialsRejected
            | State::GatewayTimeout
            | State::MissingProgram
    );
    terminal
        && (previous.active() || previous == State::Disconnecting || (was_cleaning && !cleaning))
}
impl<S: SecretStore> Broker<S> {
    pub(super) fn request_diagnostics(&mut self) {
        // An older or different build may not understand this request, and
        // rejecting it can terminate its runtime channel.
        if !self.ready || self.helper != "installed" || self.component.busy() {
            return;
        }
        if self.diagnostics.pending.is_some() {
            self.diagnostics.dirty = true;
            return;
        }
        let Some(next) = self.next.checked_add(1) else {
            return;
        };
        let id = format!("diagnostics-{next}");
        if self.client.as_ref().is_some_and(|client| {
            client
                .send(Request {
                    id: id.clone(),
                    command: Command::Diagnostics {},
                })
                .is_ok()
        }) {
            self.next = next;
            self.diagnostics.pending = Some(id);
        }
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
type Sink = std::sync::Arc<dyn Fn(String) + Send + Sync>;
pub(super) struct Flow {
    pub pending: Option<String>,
    pub dirty: bool,
    writer: Option<std::thread::JoinHandle<()>>,
    queued: Option<String>,
    sink: Sink,
}
impl Flow {
    pub fn new() -> Self {
        #[cfg(not(test))]
        let sink: Sink = std::sync::Arc::new(|text| {
            let _ = save(&text);
        });
        #[cfg(test)]
        let sink: Sink = std::sync::Arc::new(|_| {});
        Self {
            pending: None,
            dirty: false,
            writer: None,
            queued: None,
            sink,
        }
    }
    pub fn enqueue(&mut self, text: String) {
        self.queued = Some(text);
        self.tick();
    }
    pub fn tick(&mut self) {
        if self
            .writer
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
            && let Some(writer) = self.writer.take()
        {
            let _ = writer.join();
        }
        if self.writer.is_none()
            && let Some(text) = self.queued.take()
        {
            let sink = self.sink.clone();
            self.writer = std::thread::Builder::new()
                .name("vpnt-diagnostics-file".into())
                .spawn(move || sink(text))
                .ok();
        }
    }
    #[cfg(test)]
    pub fn with_sink(&mut self, sink: impl Fn(String) + Send + Sync + 'static) {
        self.sink = std::sync::Arc::new(sink);
    }
}
#[cfg(test)]
impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

pub(super) fn render(status: DiagnosticsStatus, logs: &[Log]) -> String {
    match status {
        DiagnosticsStatus::Shared => return "indisponível: instalação compartilhada\n".into(),
        DiagnosticsStatus::Unavailable => return "indisponível\n".into(),
        DiagnosticsStatus::Ready => {}
    }
    let mut result = String::new();
    for log in logs {
        let modified = log
            .modified
            .map_or_else(|| "desconhecida".to_owned(), |n| n.to_string());
        result.push_str(&format!(
            "== {} ({} linhas, hora de modificação: {})\n",
            log.name, log.lines, modified
        ));
        match log.status {
            Status::Present => result.push_str(&log.text),
            Status::Missing => result.push_str("ausente\n"),
            Status::Unavailable => result.push_str("indisponível\n"),
        }
    }
    result
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "diagnostics storage")
}
fn open_at(parent: &File, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: parent and NUL-terminated name remain live for openat.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new uniquely-owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn valid_dir(file: &File, uid: u32, private: bool) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_dir()
        || m.uid() != uid
        || (private && m.mode() & 0o7777 != 0o700)
        || (!private && m.mode() & 0o7022 != 0)
        || crate::fs_permissions::check_file(file, private).is_err()
    {
        return Err(denied());
    }
    Ok(())
}
fn check_target(dir: &File, uid: u32) -> io::Result<Option<(u64, u64)>> {
    let file = match open_at(
        dir,
        c"diagnostics.txt",
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(denied()),
    };
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != uid
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || crate::fs_permissions::check_file(&file, true).is_err()
    {
        return Err(denied());
    }
    Ok(Some((m.dev(), m.ino())))
}
/// Only temporary files created by this function are removed on failure.
struct Temp<'a> {
    dir: &'a File,
    name: CString,
    stamp: (u64, u64),
    committed: bool,
}
impl Drop for Temp<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(file) = open_at(
            self.dir,
            &self.name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        ) && let Ok(m) = file.metadata()
            && (m.dev(), m.ino()) == self.stamp
        {
            // SAFETY: the name is the exact temporary file created here.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

pub(super) fn save_at(home: &Path, uid: u32, data: &str) -> io::Result<()> {
    if uid == 0 || !home.is_absolute() || data.len() > 400_000 {
        return Err(denied());
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home)?;
    valid_dir(&root, uid, false)?;
    let library = open_at(
        &root,
        c"Library",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    valid_dir(&library, uid, false)?;
    let support = open_at(
        &library,
        c"Application Support",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    valid_dir(&support, uid, false)?;
    let name = CString::new(crate::identifiers::APP).map_err(|_| denied())?;
    let dir = match open_at(
        &support,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(dir) => dir,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // SAFETY: a fixed, single component under the admitted support FD.
            if unsafe { libc::mkdirat(support.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            open_at(
                &support,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?
        }
        Err(_) => return Err(denied()),
    };
    valid_dir(&dir, uid, true)?;
    let before = check_target(&dir, uid)?;
    let name = CString::new(format!(
        ".diagnostics-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| denied())?;
    let mut file = open_at(
        &dir,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    let initial = file.metadata()?;
    let mut temp = Temp {
        dir: &dir,
        name,
        stamp: (initial.dev(), initial.ino()),
        committed: false,
    };
    if !initial.is_file() || initial.uid() != uid || initial.nlink() != 1 {
        return Err(denied());
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if crate::fs_permissions::check_file(&file, true).is_err() {
        return Err(denied());
    }
    file.write_all(data.as_bytes())?;
    file.sync_all()?;
    valid_dir(&dir, uid, true)?;
    if check_target(&dir, uid)? != before {
        return Err(denied());
    }
    // SAFETY: both names are fixed single components under the same owned FD.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            temp.name.as_ptr(),
            dir.as_raw_fd(),
            c"diagnostics.txt".as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    temp.committed = true;
    dir.sync_all()?;
    Ok(())
}
fn home(uid: u32) -> io::Result<PathBuf> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buf = [0u8; 16_384];
    // SAFETY: stack output pointers and buffer are valid for getpwuid_r.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_uid != uid || entry.pw_dir.is_null() {
        return Err(denied());
    }
    // SAFETY: successful getpwuid_r returns a NUL-terminated string in buf.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
    if dir.is_empty() || dir.contains(&0) {
        return Err(denied());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(dir.to_vec())))
}
pub(super) fn save(data: &str) -> io::Result<()> {
    // SAFETY: UID queries have no memory preconditions.
    let uid = unsafe { libc::getuid() };
    if unsafe { libc::geteuid() } != uid {
        return Err(denied());
    }
    save_at(&home(uid)?, uid, data)
}

#[cfg(test)]
mod tests;
