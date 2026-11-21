//! A 0700 directory removed on drop, for the management socket.
#[cfg(not(target_os = "linux"))]
use std::os::unix::ffi::OsStrExt;
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
                Ok(()) => {
                    // The guard exists before the check: a rejection removes
                    // what mkdir just made, on both platforms.
                    let directory = Self { path };
                    verify(&directory.path)?;
                    return Ok(directory);
                }
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

/// Confirms what `mkdir` made without following a planted symlink. The access
/// bits must be exactly 0700: a restrictive umask or an injected chmod is
/// refused. Linux copies a setgid parent's bit onto new directories; with no
/// group access it only names the group of later entries, so it is accepted.
/// Setuid and sticky are never inherited and are refused.
fn verify(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || (mode != 0o700 && mode != 0o2700)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private session directory failed the type, owner or mode check: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Pure ownership decision for the entry we may remove: a real directory owned
/// by the expected effective user. The caller supplies the EUID so this stays
/// free of syscalls and can be tested with a foreign identity.
fn owned_directory(metadata: &fs::Metadata, euid: u32) -> bool {
    metadata.is_dir() && metadata.uid() == euid
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        // Only a directory of this effective user is ours to remove; an entry
        // swapped in by someone else is left alone.
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if owned_directory(&metadata, unsafe { libc::geteuid() }) => {}
            _ => return,
        }
        // A restrictive umask can leave the rejected directory unreadable.
        // Restore owner rwx on the entry we created so remove_dir_all can
        // clean it up. AT_SYMLINK_NOFOLLOW keeps the change on the entry
        // itself even if it was replaced by a link after the check; a 0000
        // directory cannot be opened for fchmod.
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && owned_directory(&metadata, unsafe { libc::geteuid() })
            && metadata.mode() & 0o700 != 0o700
            && let Ok(path) = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                self.path.as_os_str(),
            ))
        {
            // SAFETY: `path` is a valid NUL-terminated string for this call;
            // failure only leaves the entry for remove_dir_all to report.
            unsafe {
                libc::fchmodat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0o700,
                    libc::AT_SYMLINK_NOFOLLOW,
                );
            }
        }
        let _ = fs::remove_dir_all(&self.path);
        // If the chmod was unsupported, an empty unreadable directory is still
        // removable: rmdir needs write access to the parent, not the entry.
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{PrivateDir, owned_directory, verify};
    use std::{
        fs, io,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct RestoreUmask(libc::mode_t);

    impl RestoreUmask {
        fn set(mask: libc::mode_t) -> Self {
            Self(unsafe { libc::umask(mask) })
        }
    }

    impl Drop for RestoreUmask {
        fn drop(&mut self) {
            unsafe { libc::umask(self.0) };
        }
    }

    struct RemoveTree(PathBuf);

    impl Drop for RemoveTree {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
                }
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn unique_base() -> PathBuf {
        // Parallel tests in one process can read the same clock value.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let salt = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "vpnt-pdir-{}-{salt:x}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        base
    }

    #[test]
    fn private_directory_is_checked_after_mkdir() {
        // The umask is process-wide: run the hostile case in a child so no
        // other test can inherit it.
        const CHILD: &str = "VPNT_PRIVATE_DIR_UMASK_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let base = unique_base();
            let _cleanup = RemoveTree(base.clone());
            let _umask = RestoreUmask::set(0o777);
            match PrivateDir::create(&base) {
                Ok(directory) => panic!(
                    "accepted a directory outside 0700: {}",
                    directory.path.display()
                ),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}"),
            }
            assert_eq!(
                fs::read_dir(&base).unwrap().count(),
                0,
                "rejected directory was not removed"
            );
            return;
        }

        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "{}::private_directory_is_checked_after_mkdir",
                module_path!()
                    .strip_prefix("vpnt::")
                    .unwrap_or(module_path!())
            ))
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child rejected the bad mode: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn directory_check_refuses_a_symlink_and_a_wrong_mode() {
        let base = unique_base();
        let _cleanup = RemoveTree(base.clone());

        let good = base.join("good");
        fs::create_dir(&good).unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(verify(&good).is_ok());

        let link = base.join("link");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(verify(&link).is_err(), "symlink followed");

        fs::set_permissions(&good, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify(&good).is_err(), "wrong mode accepted");

        // A setgid parent hands its bit to new directories on Linux; with no
        // group access it is accepted. Setuid and sticky are not inherited.
        for (mode, accepted) in [(0o2700, true), (0o4700, false), (0o1700, false)] {
            fs::set_permissions(&good, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                fs::symlink_metadata(&good).unwrap().permissions().mode() & 0o7777,
                mode,
                "the fixture could not set {mode:o}"
            );
            assert_eq!(verify(&good).is_ok(), accepted, "mode {mode:o}");
        }
    }

    #[test]
    fn owned_directory_accepts_an_own_directory() {
        let base = unique_base();
        let _cleanup = RemoveTree(base.clone());
        let euid = unsafe { libc::geteuid() };
        assert!(owned_directory(&fs::symlink_metadata(&base).unwrap(), euid));
    }

    #[test]
    fn owned_directory_refuses_a_foreign_uid() {
        let base = unique_base();
        let _cleanup = RemoveTree(base.clone());
        let euid = unsafe { libc::geteuid() };
        assert!(!owned_directory(
            &fs::symlink_metadata(&base).unwrap(),
            euid.wrapping_add(1)
        ));
    }

    #[test]
    fn owned_directory_refuses_a_file_and_a_symlink() {
        let base = unique_base();
        let _cleanup = RemoveTree(base.clone());
        let file = base.join("file");
        fs::write(&file, b"").unwrap();
        // The link points at a directory of this user, so only metadata that
        // does not follow it is refused.
        let target = base.join("target");
        fs::create_dir(&target).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let euid = unsafe { libc::geteuid() };
        assert!(owned_directory(&fs::metadata(&link).unwrap(), euid));
        assert!(
            !owned_directory(&fs::symlink_metadata(&file).unwrap(), euid),
            "a regular file was accepted"
        );
        assert!(
            !owned_directory(&fs::symlink_metadata(&link).unwrap(), euid),
            "a symlink was accepted"
        );
    }

    #[test]
    fn drop_leaves_an_entry_it_does_not_own_as_a_directory() {
        let base = unique_base();
        let _cleanup = RemoveTree(base.clone());
        let target = base.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"").unwrap();
        let swapped = base.join("swapped");
        std::os::unix::fs::symlink(&target, &swapped).unwrap();

        drop(PrivateDir {
            path: swapped.clone(),
        });

        assert!(
            fs::symlink_metadata(&swapped).is_ok(),
            "the swapped-in link was removed"
        );
        assert!(target.join("keep").exists(), "the link target was touched");
    }
}
