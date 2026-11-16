//! Persistent diagnostics live outside the attempt directory and its cleanup.
use super::{Error, files::Directory};
use crate::helper::paths;
use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::Command,
};

const CURRENT: &str = "charon.log";
const PREVIOUS: &str = "charon.previous.log";
pub(super) const CHARON_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Bound regular-file writes in this child only. SIG_IGN survives exec, so a
/// full diagnostic file yields EFBIG instead of terminating the daemon.
pub(super) fn limit_file_size(command: &mut Command) {
    // SAFETY: the child hook only initializes stack values and calls
    // setrlimit/sigemptyset/sigaction; no allocation, locks or logging after fork.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: CHARON_LOG_MAX_BYTES as libc::rlim_t,
                rlim_max: CHARON_LOG_MAX_BYTES as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_IGN;
            if libc::sigemptyset(&mut action.sa_mask) != 0
                || libc::sigaction(libc::SIGXFSZ, &action, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

// Never read log contents into helper memory. Refuse links, foreign ownership,
// permissions and ACLs before rotating either name in the protected directory.
fn present(directory: &Directory, name: &str) -> Result<bool, Error> {
    directory.validate()?;
    let path = directory.path.join(name);
    let named = match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error::Unavailable),
        Ok(meta) => meta,
    };
    if !named.is_file()
        || named.uid() != directory.owner
        || named.mode() & 0o7777 != 0o600
        || named.nlink() != 1
    {
        return Err(Error::Changed);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::Changed)?;
    let opened = file.metadata().map_err(|_| Error::Unavailable)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(Error::Changed);
    }
    crate::fs_permissions::check_file(&file, true).map_err(|_| Error::Changed)?;
    directory.validate()?;
    Ok(true)
}

/// Called only after root/controller admission, immediately before spawn.
/// STATE comes from the controller rooted at paths::STATE; fixture controllers
/// supply their isolated root and current UID through the same private path.
pub(super) fn prepare(state: &Path, owner: u32) -> Result<(), Error> {
    let path = paths::charon_log(state);
    let directory = path.parent().ok_or(Error::Invalid)?.to_owned();
    let directory = match fs::symlink_metadata(&directory) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let directory = Directory::create(directory, owner)?;
            fs::File::open(state)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| Error::Unavailable)?;
            directory
        }
        Ok(_) => Directory::open(directory, owner)?,
        Err(_) => return Err(Error::Unavailable),
    };
    let current = present(&directory, CURRENT)?;
    present(&directory, PREVIOUS)?;
    if current {
        fs::rename(directory.path.join(CURRENT), directory.path.join(PREVIOUS))
            .map_err(|_| Error::Unavailable)?;
    }
    // write_new uses create_new (O_EXCL | O_CREAT), O_NOFOLLOW and mode 0600.
    directory.write_new(CURRENT, b"")?;
    if !present(&directory, CURRENT)? {
        return Err(Error::Changed);
    }
    directory.sync()
}
