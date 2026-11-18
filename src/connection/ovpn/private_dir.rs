//! A 0700 directory removed on drop, for the management socket.
use std::{
    fs, io,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
