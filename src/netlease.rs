//! Linux coordination between the writers of VPN network state.
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    thread,
    time::{Duration, Instant},
};

const DIRECTORY: &str = "/run/vpnt";
const LOCK: &CStr = c"network-write.lock";
const REGISTRY: &CStr = c"tunnel-leases";
const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub struct NetworkLock;

impl NetworkLock {
    /// Acquire the shared network writer lock before the absolute deadline.
    pub fn acquire(deadline: Instant) -> io::Result<NetworkGuard> {
        Self::acquire_at(Path::new(DIRECTORY), 0, 0, deadline)
    }

    #[cfg(test)]
    pub(crate) fn acquire_test(path: &Path, deadline: Instant) -> io::Result<NetworkGuard> {
        // SAFETY: geteuid has no preconditions.
        unsafe { Self::acquire_at(path, libc::geteuid(), libc::getegid(), deadline) }
    }

    fn acquire_at(
        path: &Path,
        owner: u32,
        group: u32,
        deadline: Instant,
    ) -> io::Result<NetworkGuard> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        let meta = directory.metadata()?;
        require(meta.is_dir() && meta.uid() == owner && meta.mode() & 0o022 == 0)?;

        // Inspect an existing entry without opening a device or following links.
        // The validated parent excludes replacement by unprivileged callers.
        match open_at(&directory, LOCK, libc::O_PATH, 0) {
            Ok(existing) => validate_file(&existing, owner, false)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let lock = open_at(&directory, LOCK, libc::O_CREAT | libc::O_NONBLOCK, 0o600)?;
        validate_file(&lock, owner, false)?;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            // SAFETY: lock is a live descriptor; this call never blocks.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                return Ok(NetworkGuard {
                    directory,
                    owner,
                    group,
                    _lock: lock,
                });
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => thread::sleep(remaining.min(POLL_INTERVAL)),
                io::ErrorKind::Interrupted => {}
                _ => return Err(error),
            }
        }
    }
}

/// Closing the private flock descriptor releases the lock, including on unwind.
pub struct NetworkGuard {
    directory: File,
    owner: u32,
    group: u32,
    _lock: File,
}

impl NetworkGuard {
    /// Any entry blocks admission. Invalid entries fail closed even if a
    /// different valid entry also exists.
    pub fn tunnels_present(&self) -> io::Result<bool> {
        let Some(dir) = self.registry(false)? else {
            return Ok(false);
        };
        let mut entries = DirectoryEntries::new(&dir)?;
        let mut present = false;
        while let Some(name) = entries.next()? {
            if name == c"." || name == c".." {
                continue;
            }
            require(valid_name(name))?;
            self.validate_entry(&dir, name)?;
            present = true;
        }
        Ok(present)
    }

    /// Publish an empty lease atomically. A sync error after creation leaves
    /// the marker in place so readers continue to block admission.
    pub fn register(&self, name: &str) -> io::Result<()> {
        let name = lease_name(name)?;
        let dir = self.registry(true)?.ok_or(io::ErrorKind::NotFound)?;
        let file = open_at(
            &dir,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        validate_file(&file, self.owner, true)?;
        file.sync_all()?;
        dir.sync_all()?;
        self.directory.sync_all()
    }

    /// Withdraw only a validated entry. Repeating a completed withdrawal is safe.
    pub fn withdraw(&self, name: &str) -> io::Result<()> {
        let name = lease_name(name)?;
        let Some(dir) = self.registry(false)? else {
            return Ok(());
        };
        match self.validate_entry(&dir, &name) {
            Ok(()) => {
                // SAFETY: dir is live and name is a validated single component.
                if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        dir.sync_all()
    }

    fn registry(&self, create: bool) -> io::Result<Option<File>> {
        if create {
            // SAFETY: directory is live and REGISTRY is a single component.
            if unsafe { libc::mkdirat(self.directory.as_raw_fd(), REGISTRY.as_ptr(), 0o700) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
        }
        let dir = match open_at(&self.directory, REGISTRY, libc::O_DIRECTORY, 0) {
            Ok(dir) => dir,
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let meta = dir.metadata()?;
        require(
            meta.is_dir()
                && meta.uid() == self.owner
                && meta.gid() == self.group
                && meta.mode() & 0o7777 == 0o700,
        )?;
        Ok(Some(dir))
    }

    fn validate_entry(&self, dir: &File, name: &CStr) -> io::Result<()> {
        let entry = open_at(dir, name, libc::O_PATH, 0)?;
        validate_file(&entry, self.owner, true)
    }
}

fn require(valid: bool) -> io::Result<()> {
    if valid {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn validate_file(file: &File, owner: u32, lease: bool) -> io::Result<()> {
    let meta = file.metadata()?;
    let mode = meta.mode() & 0o7777;
    let permissions = if lease {
        mode == 0o600
    } else {
        mode & 0o7077 == 0
    };
    require(meta.is_file() && meta.uid() == owner && meta.nlink() == 1 && permissions)
}

fn valid_name(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn lease_name(name: &str) -> io::Result<CString> {
    CString::new(name)
        .ok()
        .filter(|name| valid_name(name))
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

fn open_at(parent: &File, name: &CStr, flags: libc::c_int, mode: libc::c_uint) -> io::Result<File> {
    // SAFETY: parent is live and name is a NUL-terminated single component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor and File takes ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

struct DirectoryEntries(*mut libc::DIR);

impl DirectoryEntries {
    fn new(dir: &File) -> io::Result<Self> {
        let scan = open_at(dir, c".", libc::O_DIRECTORY, 0)?;
        // SAFETY: scan is live and ownership transfers to the stream on success.
        let stream = unsafe { libc::fdopendir(scan.as_raw_fd()) };
        if stream.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _ = scan.into_raw_fd();
        Ok(Self(stream))
    }

    fn next(&mut self) -> io::Result<Option<&CStr>> {
        // SAFETY: errno is thread-local and self owns a valid directory stream.
        unsafe {
            *libc::__errno_location() = 0;
            let entry = libc::readdir(self.0);
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            Ok(Some(CStr::from_ptr((*entry).d_name.as_ptr())))
        }
    }
}

impl Drop for DirectoryEntries {
    fn drop(&mut self) {
        // SAFETY: this stream is owned exclusively by self.
        unsafe { libc::closedir(self.0) };
    }
}

#[cfg(test)]
#[path = "netlease_tests.rs"]
mod tests;
