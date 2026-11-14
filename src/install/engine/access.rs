use super::*;
use crate::helper::{paths, server::caller::Caller};
use std::{
    ffi::CStr,
    os::fd::{FromRawFd, OwnedFd},
};
pub(super) mod channel;
/// Activation derives its payload from the root-owned staging executable, never
/// a caller-supplied path, uid, environment variable or working directory.
pub fn activate_staged() -> Result<Outcome, Error> {
    root()?;
    let executable = std::env::current_exe().map_err(|_| Error::UntrustedPath)?;
    let directory = executable
        .parent()
        .and_then(Path::parent)
        .ok_or(Error::UntrustedPath)?;
    let staging = Path::new(crate::helper::paths::STAGING);
    if directory.parent() != Some(staging) || executable != directory.join("adapters/installer") {
        return Err(Error::UntrustedPath);
    }
    let payload = Payload::inspect(directory, 0)?;
    if directory.file_name().and_then(|n| n.to_str()) != Some(&payload.summary().id) {
        return Err(Error::Integrity);
    }
    account(payload.summary().uid)?;
    minimum(&payload.summary().minimum_macos)?;
    system().activate(&payload)
}

/// The standalone installer has not created or aliased stdin yet.
///
/// # Safety
/// FD 0 must be unowned; this consumes its anonymous Unix capability once.
pub unsafe fn remove_inherited() -> Result<(), Error> {
    root()?;
    if std::env::current_exe().map_err(|_| Error::UntrustedPath)? != Path::new(paths::INSTALLER) {
        return Err(Error::UntrustedPath);
    }
    if unsafe { libc::fcntl(0, libc::F_GETFD) } < 0 {
        return Err(Error::PermissionDenied);
    }
    let caller =
        Caller::from_fd(unsafe { OwnedFd::from_raw_fd(0) }).map_err(|_| Error::PermissionDenied)?;
    channel::serve(caller, &mut system())
}
pub(crate) fn admit_uid(uid: u32) -> Result<(), Error> {
    root()?;
    admit(&Tree::system(), uid)
}
pub(super) fn admit(tree: &Tree, uid: u32) -> Result<(), Error> {
    payload::files::directory(&tree.state, tree.owner, true)?;
    if Journal::pending(tree)? {
        return Err(Error::RecoveryRequired);
    }
    let receipt = Receipt::load(tree)?.ok_or(Error::Conflict)?;
    if receipt.app_version != env!("CARGO_PKG_VERSION") || !receipt.users.contains_key(&uid) {
        return Err(Error::PermissionDenied);
    }
    receipt.verify(tree)
}
fn account(uid: u32) -> Result<(), Error> {
    policy::account(uid)?;
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut pointer = std::ptr::null_mut();
    let mut buffer = [0; 16384];
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut pointer,
        )
    } != 0
        || pointer.is_null()
        || record.pw_uid != uid
    {
        return Err(Error::InvalidManifest);
    }
    Ok(())
}
fn minimum(required: &str) -> Result<(), Error> {
    let mut bytes = [0u8; 64];
    let mut len = bytes.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || len > bytes.len()
    {
        return Err(Error::Incompatible);
    }
    let actual = CStr::from_bytes_until_nul(&bytes[..len])
        .map_err(|_| Error::Incompatible)?
        .to_str()
        .map_err(|_| Error::Incompatible)?;
    fn parts(s: &str) -> Result<[u32; 3], Error> {
        if !tree::version_ok(s) {
            return Err(Error::Incompatible);
        }
        let mut parts = [0; 3];
        for (i, p) in s.split('.').enumerate() {
            parts[i] = p.parse().map_err(|_| Error::Incompatible)?;
        }
        Ok(parts)
    }
    if parts(actual)? < parts(required)? {
        return Err(Error::Incompatible);
    }
    Ok(())
}
