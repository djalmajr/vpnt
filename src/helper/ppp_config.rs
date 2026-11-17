//! Refuse ambient PPP policy instead of editing or inheriting another VPN's
//! configuration. The fixed production entrypoint never accepts audit paths.
use std::{
    ffi::{CStr, OsStr},
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

// Apple ppp-884 Helpers/pppd/{main,options,pathnames,auth,ipcp,ipv6cp}.c.
// Refuse presence, even an empty/non-executable file or dangling symlink. Never
// read secrets or execute a parser/plugin merely to inspect effective policy.
const AMBIENT: &[&[u8]] = &[
    b"options",
    b"postoptions",
    b".ppprc",
    b".ppp_pseudonym",
    b"pap-secrets",
    b"chap-secrets",
    b"srp-secrets",
    b"ip-up",
    b"ip-down",
    b"auth-up",
    b"auth-down",
    b"ipv6-up",
    b"ipv6-down",
    b"ipx-up",
    b"ipx-down",
];

/// Root-only caller, read-only admission immediately before supervisor use.
/// Root administrators remain trusted: this is not an atomic lock against
/// another root process changing global policy during a connection.
pub fn verify() -> io::Result<()> {
    if fs::canonicalize("/etc")? != Path::new("/private/etc") {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let home = root_home()?;
    verify_at(Path::new("/private/etc"), &home, 0)?;
    let program = Path::new(super::ppp_supervisor::SYSTEM_PPP);
    trusted_directory(program.parent().ok_or(io::ErrorKind::InvalidInput)?, 0)?;
    let metadata = fs::symlink_metadata(program)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.nlink() != 1
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    crate::fs_permissions::check_path(program, false)
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))
}

fn root_home() -> io::Result<PathBuf> {
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut storage = [0u8; 16_384];
    let mut result = std::ptr::null_mut();
    // SAFETY: reentrant query writes only to the supplied initialized buffer
    // and passwd output. Copy the borrowed directory before storage is dropped.
    let error = unsafe {
        libc::getpwuid_r(
            0,
            entry.as_mut_ptr(),
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut result,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    if result.is_null() {
        return Err(io::ErrorKind::NotFound.into());
    }
    let entry = unsafe { entry.assume_init() };
    if entry.pw_uid != 0 || entry.pw_dir.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let bytes = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
    let path = Path::new(OsStr::from_bytes(bytes));
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Only the known system /var alias is allowed. A generic canonicalize
    // could hide an untrusted directory containing a replaceable home symlink.
    // Every remaining component is checked without following symlinks below.
    // HOME from the environment is deliberately ignored (pppd uses getpwuid).
    if let Ok(rest) = path.strip_prefix("/var") {
        if fs::canonicalize("/var")? != Path::new("/private/var") {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        return Ok(Path::new("/private/var").join(rest));
    }
    Ok(path.to_owned())
}

fn verify_at(etc: &Path, home: &Path, owner: u32) -> io::Result<()> {
    trusted_directory(etc, owner)?;
    trusted_directory(home, owner)?;
    absent(&home.join(".ppprc"))?;
    absent(&home.join(".ppp_pseudonym"))?;
    let ppp = etc.join("ppp");
    match fs::symlink_metadata(&ppp) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => trusted_directory(&ppp, owner)?,
    }
    for (count, entry) in fs::read_dir(ppp)?.enumerate() {
        if count >= 1_024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let name = entry?.file_name();
        if ambient(name.as_bytes()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(())
}
fn ambient(name: &[u8]) -> bool {
    AMBIENT.contains(&name) || name.starts_with(b"options.")
}
fn absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
    }
}
fn trusted_directory(directory: &Path, owner: u32) -> io::Result<()> {
    if !directory.is_absolute()
        || directory
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for path in directory.ancestors() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || (path == directory && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        crate::fs_permissions::check_path(path, false)
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "ppp_config_tests.rs"]
mod tests;
