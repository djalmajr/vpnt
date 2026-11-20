//! Root-side guard for the private base of live OVPN sessions (macOS only).
//! An existing entry is judged as it is: nothing is chmod'ed, chowned or
//! removed here. A wrong base is reported to the caller, never repaired.

use std::{
    fs::{self, Metadata},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe ovpn session base")
}

/// Pure decision over the metadata of an existing entry. `symlink_metadata`
/// reports the link itself, so a link is never mistaken for a directory.
pub(crate) fn acceptable(metadata: &Metadata, expected_uid: u32) -> bool {
    metadata.is_dir() && metadata.uid() == expected_uid && metadata.mode() & 0o077 == 0
}

/// A directory made here must be exactly 0700: a restrictive umask or an
/// injected chmod must not change what this function guarantees.
fn acceptable_new(metadata: &Metadata, expected_uid: u32) -> bool {
    acceptable(metadata, expected_uid) && metadata.mode() & 0o7777 == 0o700
}

fn check_existing(path: &Path, expected_uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if acceptable(&metadata, expected_uid) {
        Ok(())
    } else {
        Err(denied())
    }
}

/// Ensures `path` is a private directory owned by `expected_uid`, creating it
/// with `mkdir` at 0700 only when it is absent.
pub(crate) fn ensure_base(path: &Path, expected_uid: u32) -> io::Result<()> {
    ensure_base_with(path, expected_uid, |path| {
        fs::DirBuilder::new().mode(0o700).create(path)
    })
}

fn ensure_base_with(
    path: &Path,
    expected_uid: u32,
    create: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_existing(path, expected_uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => match create(path) {
            Ok(()) => {
                let metadata = fs::symlink_metadata(path)?;
                if !acceptable_new(&metadata, expected_uid) {
                    return Err(denied());
                }
                Ok(())
            }
            // Another creator won the race. Judge the entry now present,
            // never the result of our own mkdir.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                check_existing(path, expected_uid)
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT: AtomicU32 = AtomicU32::new(0);

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let salt = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.subsec_nanos());
            let path = std::env::temp_dir().join(format!(
                "vpnt-ovpn-base-{}-{salt:x}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn base(&self) -> PathBuf {
            self.0.join("ovpn")
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700));
                }
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// No-follow identity: type, mode, owner and inode, so a repair or a
    /// replacement of the entry is visible even when its mode is unchanged.
    fn snapshot(path: &Path) -> (u32, u32, u64, u64, bool) {
        let metadata = fs::symlink_metadata(path).unwrap();
        (
            metadata.mode(),
            metadata.uid(),
            metadata.ino(),
            metadata.dev(),
            metadata.is_dir(),
        )
    }

    #[test]
    fn creates_a_missing_base_with_mode_0700() {
        let root = Root::new();
        let base = root.base();
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        ensure_base(&base, uid).unwrap();
        let metadata = fs::symlink_metadata(&base).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        ensure_base(&base, uid).unwrap();
    }

    #[test]
    fn accepts_an_existing_private_base_without_touching_it() {
        let root = Root::new();
        let base = root.base();
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let before = snapshot(&base);
        ensure_base(&base, uid).unwrap();
        assert_eq!(snapshot(&base), before);
    }

    #[test]
    fn refuses_wide_mode_symlink_file_and_foreign_owner_without_repair() {
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        for case in ["wide", "symlink", "file", "foreign"] {
            let root = Root::new();
            let base = root.base();
            let target = root.0.join("target");
            let expected_uid = if case == "foreign" {
                uid.wrapping_add(1)
            } else {
                uid
            };
            match case {
                "wide" => {
                    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
                    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
                }
                "symlink" => {
                    fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
                    symlink(&target, &base).unwrap();
                }
                "file" => fs::write(&base, b"not a directory").unwrap(),
                "foreign" => {
                    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
                }
                _ => unreachable!(),
            }
            let before = snapshot(&base);
            let target_before = target.exists().then(|| snapshot(&target));
            assert!(ensure_base(&base, expected_uid).is_err(), "{case}");
            assert_eq!(snapshot(&base), before, "{case}");
            assert_eq!(
                target.exists().then(|| snapshot(&target)),
                target_before,
                "{case}"
            );
        }
    }

    #[test]
    fn a_link_seen_after_a_successful_mkdir_is_refused() {
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let root = Root::new();
        let base = root.base();
        let target = root.0.join("target");
        fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        let target_before = snapshot(&target);
        // mkdir reports success, but the entry now at the path is a link to a
        // directory that would itself pass the check if it were followed.
        let swapped = |path: &Path| -> io::Result<()> { symlink(&target, path) };
        assert!(ensure_base_with(&base, uid, swapped).is_err());
        assert!(
            fs::symlink_metadata(&base)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&base).unwrap(), target);
        assert_eq!(snapshot(&target), target_before);
    }

    #[test]
    fn mkdir_racing_an_existing_base_rechecks_the_winner() {
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let losing_mkdir = |mode: u32| {
            move |path: &Path| -> io::Result<()> {
                fs::DirBuilder::new().mode(mode).create(path)?;
                Err(io::Error::from(io::ErrorKind::AlreadyExists))
            }
        };
        let good = Root::new();
        ensure_base_with(&good.base(), uid, losing_mkdir(0o700)).unwrap();
        assert_eq!(
            fs::symlink_metadata(good.base()).unwrap().mode() & 0o7777,
            0o700
        );

        let bad = Root::new();
        assert!(ensure_base_with(&bad.base(), uid, losing_mkdir(0o755)).is_err());
        assert_eq!(
            fs::symlink_metadata(bad.base()).unwrap().mode() & 0o7777,
            0o755
        );
    }
}
