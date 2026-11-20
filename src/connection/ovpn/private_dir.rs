//! A 0700 directory removed on drop, for the management socket.
use std::{
    fs, io,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(not(target_os = "linux"))]
use std::{os::unix::ffi::OsStrExt, os::unix::fs::MetadataExt};

/// `sockaddr_un.sun_path` on macOS; the terminating NUL also has to fit.
#[cfg(not(target_os = "linux"))]
const SOCKET_PATH_LIMIT: usize = 104;
/// Longest name `create` can produce: prefix, pid (u32), salt (u32 hex) and a
/// two-digit attempt (the loop covers 0..16).
#[cfg(not(target_os = "linux"))]
const MAX_DIR_NAME_LEN: usize = "vpnt-ovpn-".len() + 10 + 1 + 8 + 1 + 2;
#[cfg(not(target_os = "linux"))]
const SOCKET_NAME: &str = "management";

/// Rejects a base whose canonical chain to `/` has a foreign or group/world
/// writable directory, and returns that canonical path. Callers must create
/// the session directory from it so an input alias cannot leave the chain
/// that was checked. Linux keeps using `/tmp` (1777) and skips this check.
#[cfg(not(target_os = "linux"))]
pub(super) fn validate_base(base: &Path) -> io::Result<PathBuf> {
    let canonical = base.canonicalize()?;
    if !canonical.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "session base is not a directory",
        ));
    }
    let euid = unsafe { libc::geteuid() };
    for ancestor in canonical.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != euid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsafe session base directory: {}", ancestor.display()),
            ));
        }
    }
    Ok(canonical)
}

/// Checks the longest socket path this module can create under `base`, before
/// any directory is made, so the macOS 104-byte limit fails early and clearly.
#[cfg(not(target_os = "linux"))]
pub(super) fn check_socket_limit(base: &Path) -> io::Result<()> {
    let worst_case = base.join("x".repeat(MAX_DIR_NAME_LEN)).join(SOCKET_NAME);
    if worst_case.as_os_str().as_bytes().len() >= SOCKET_PATH_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "management socket path under {} exceeds the {}-byte macOS limit",
                base.display(),
                SOCKET_PATH_LIMIT - 1
            ),
        ));
    }
    Ok(())
}

pub(super) struct PrivateDir {
    pub(super) path: PathBuf,
}

impl PrivateDir {
    /// `mkdir` never follows an existing entry, so a shared parent such as
    /// /tmp is safe; the session uses it because a Unix socket path is limited
    /// to 104 bytes on macOS and the per-user temp directory is long.
    pub(super) fn create(base: &Path) -> io::Result<Self> {
        let salt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        for attempt in 0..16 {
            let path = base.join(format!(
                "vpnt-ovpn-{}-{salt:x}-{attempt}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no free private directory",
        ))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
