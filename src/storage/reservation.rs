use super::*;

/// A persistent per-profile inode shared by administration and connection
/// admission. Dropping this handle releases only its own flock, never its path.
pub struct ProfileReservation {
    store: ProfileStore,
    path: PathBuf,
    file: File,
}
impl ProfileStore {
    pub fn reserve(&self, id: &str) -> Result<ProfileReservation, StoreError> {
        if !valid_profile_id(id) {
            return Err(StoreError::InvalidData);
        }
        self.check_directory()?;
        // Hex preserves byte identity on case-insensitive macOS filesystems.
        let name: String = id.bytes().map(|byte| format!("{byte:02x}")).collect();
        let path = self.directory.join(format!(".profile-{name}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| StoreError::UntrustedPath)?;
        let guard = ProfileReservation {
            store: ProfileStore {
                directory: self.directory.clone(),
                owner: self.owner,
            },
            path,
            file,
        };
        guard.validate()?;
        // SAFETY: this owned descriptor is live for the lifetime of guard.
        if unsafe { libc::flock(guard.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                if std::io::Error::last_os_error().kind() == ErrorKind::WouldBlock {
                    StoreError::Busy
                } else {
                    StoreError::Io
                },
            );
        }
        guard.validate()?;
        Ok(guard)
    }
}
impl ProfileReservation {
    pub fn validate(&self) -> Result<(), StoreError> {
        self.store.check_directory()?;
        let opened = self.file.metadata().map_err(|_| StoreError::Io)?;
        self.store.check_file(&opened)?;
        if opened.mode() & 0o7777 != 0o600 {
            return Err(StoreError::UntrustedPath);
        }
        crate::fs_permissions::check_file(&self.file, true)
            .map_err(|_| StoreError::UntrustedPath)?;
        let named = fs::symlink_metadata(&self.path).map_err(|_| StoreError::UntrustedPath)?;
        if !named.is_file() || named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(StoreError::UntrustedPath);
        }
        Ok(())
    }
}

impl Drop for ProfileReservation {
    fn drop(&mut self) {
        // Explicitly release our reservation even if a concurrent fork still
        // holds this open file description briefly before its CLOEXEC boundary.
        // The persistent inode remains in place for future owners.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn release_does_not_wait_for_a_transient_duplicate_of_the_owned_descriptor() {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!("reservation-duplicate-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = ProfileStore::open(&root, fs::metadata(&root).unwrap().uid()).unwrap();
        let guard = store.reserve("one").unwrap();
        // fork shares this open file description until CLOEXEC takes effect.
        // A duplicate deterministically retains that same kernel reference.
        let transient = guard.file.try_clone().unwrap();
        assert!(matches!(store.reserve("one"), Err(StoreError::Busy)));
        drop(guard);
        let result = store.reserve("one");
        drop(transient);
        assert!(
            result.is_ok(),
            "only the owned reservation controls its lifetime"
        );
        drop(result);
        fs::remove_dir_all(root).unwrap();
    }
}
