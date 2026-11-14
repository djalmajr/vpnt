//! One cooperating controller owns all live VPN generations on the machine.
//! The installer prepares the persistent root-owned inode; it must never be
//! unlinked/replaced during updates. This advisory lock is not a route receipt
//! or protection against another root process mutating kernel resources.
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

const NAME: &str = ".controller.lock";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockError {
    PermissionDenied,
    UntrustedPath,
    Busy,
    Io,
    Changed,
}

/// Kept alive for the entire controller, through child exit and pending
/// cleanup. There is no public descriptor, clone, unlink or early-unlock API.
pub struct ControllerLock {
    file: File,
    directory: PathBuf,
    owner: u32,
}

impl ControllerLock {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    /// Fixed production location; no owner/path comes from IPC. This does not
    /// create directories or a lock file, and never changes their permissions.
    pub fn acquire() -> Result<Self, LockError> {
        // SAFETY: UID queries have no memory preconditions.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(LockError::PermissionDenied);
        }
        Self::at(Path::new(super::paths::STATE), 0)
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn fixture(directory: &Path, owner: u32) -> Result<Self, LockError> {
        Self::at(directory, owner)
    }

    fn at(directory: &Path, owner: u32) -> Result<Self, LockError> {
        check_directory(directory, owner)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(directory.join(NAME))
            .map_err(|_| LockError::UntrustedPath)?;
        let guard = Self {
            file,
            directory: directory.into(),
            owner,
        };
        guard.validate()?;
        // SAFETY: guard owns this live descriptor. Nonblocking flock cannot
        // leave another helper waiting while its caller assumes it is active.
        if unsafe { libc::flock(guard.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::WouldBlock {
                LockError::Busy
            } else {
                LockError::Io
            });
        }
        guard.validate()?;
        Ok(guard)
    }

    /// Detects path/permission replacement before the next operation. As with
    /// any advisory lock, this is not an atomic fence against arbitrary root.
    pub fn validate(&self) -> Result<(), LockError> {
        check_directory(&self.directory, self.owner)?;
        let opened = self.file.metadata().map_err(|_| LockError::Io)?;
        check_lock(&opened, self.owner)?;
        crate::fs_permissions::check_file(&self.file, true)
            .map_err(|_| LockError::UntrustedPath)?;
        let named =
            fs::symlink_metadata(self.directory.join(NAME)).map_err(|_| LockError::Changed)?;
        if !named.is_file() || named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(LockError::Changed);
        }
        Ok(())
    }
}

impl Drop for ControllerLock {
    fn drop(&mut self) {
        // Release our authority even if a concurrent fork retains this open
        // file description until exec. Never unlink the persistent lock inode.
        // SAFETY: self owns this live descriptor. A failed acquisition has a
        // distinct open file description and cannot release another owner's lock.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn check_lock(metadata: &Metadata, owner: u32) -> Result<(), LockError> {
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LockError::UntrustedPath);
    }
    Ok(())
}

fn check_directory(directory: &Path, owner: u32) -> Result<(), LockError> {
    if !directory.is_absolute()
        || directory
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(LockError::UntrustedPath);
    }
    for path in directory.ancestors() {
        let metadata = fs::symlink_metadata(path).map_err(|_| LockError::UntrustedPath)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0
            || (path == directory && (metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700))
        {
            return Err(LockError::UntrustedPath);
        }
        crate::fs_permissions::check_path(path, path == directory)
            .map_err(|_| LockError::UntrustedPath)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "controller_lock_tests.rs"]
mod tests;
