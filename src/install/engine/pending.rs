use super::{Error, Tree, payload};
use crate::helper::controller_lock::ControllerLock;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

/// A free controller lock does not retire an orphaned VPN admission. Do not
/// interpret phases/PIDs or repair contents here; only the VPN reconciler can
/// prove producer exit and absence of all resources before removing its claim.
pub(super) fn clear(tree: &Tree, guard: &ControllerLock) -> Result<(), Error> {
    let validate = || {
        if guard.directory() != tree.state {
            return Err(Error::UntrustedPath);
        }
        guard.validate().map_err(|_| Error::UntrustedPath)
    };
    validate()?;
    let path = tree.state.join("ipsec");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return validate(),
        Err(_) => return Err(Error::UntrustedPath),
        Ok(_) => {}
    }
    payload::files::directory(&path, tree.owner, true)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| Error::UntrustedPath)?;
    let opened = directory.metadata().map_err(|_| Error::Io)?;
    let unchanged = || {
        payload::files::directory(&path, tree.owner, true)?;
        let named = fs::symlink_metadata(&path).map_err(|_| Error::UntrustedPath)?;
        if !named.is_dir() || named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(Error::UntrustedPath);
        }
        validate()
    };
    unchanged()?;
    if let Some(entry) = fs::read_dir(&path).map_err(|_| Error::Io)?.next() {
        entry.map_err(|_| Error::Io)?;
        return Err(Error::Busy);
    }
    unchanged()
}
