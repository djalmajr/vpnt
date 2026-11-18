//! Per-user runtime lock; the inode is never removed while in use.
use super::controller_lock::LockError;
use crate::storage::ProfileStore;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(super) struct UserLock(File);
impl UserLock {
    pub(super) fn acquire(store: &ProfileStore, uid: u32) -> Result<Self, LockError> {
        // The lock sits in the validated store directory itself; it must not
        // depend on the OVPN import directory, which the runtime never needs.
        // A process of the same user can always remove this file: the lock
        // only keeps two app instances from running two runtimes by mistake.
        let path = store
            .private_file("runtime.lock")
            .map_err(|_| LockError::UntrustedPath)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| LockError::UntrustedPath)?;
        let opened = file.metadata().map_err(|_| LockError::Io)?;
        if !opened.is_file()
            || opened.uid() != uid
            || opened.nlink() != 1
            || opened.mode() & 0o7777 != 0o600
        {
            return Err(LockError::UntrustedPath);
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                    LockError::Busy
                } else {
                    LockError::Io
                },
            );
        }
        let named = fs::symlink_metadata(path).map_err(|_| LockError::Changed)?;
        if !named.is_file() || named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(LockError::Changed);
        }
        Ok(Self(file))
    }
}
impl Drop for UserLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
