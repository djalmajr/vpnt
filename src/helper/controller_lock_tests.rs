use super::*;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    owner: u32,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "controller-lock-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = directory.join(NAME);
        fs::write(&lock, b"persistent inode").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = fs::metadata(&directory).unwrap().uid();
        Self { directory, owner }
    }
    fn acquire(&self) -> Result<ControllerLock, LockError> {
        ControllerLock::at(&self.directory, self.owner)
    }
    fn contender(&self) -> String {
        // An independent process/implementation exercises the kernel lock,
        // rather than trusting the Rust wrapper to report its own bookkeeping.
        let output = Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import fcntl,sys\nf=open(sys.argv[1],'r+b')\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n print('acquired')\nexcept BlockingIOError:\n print('busy')",
            ])
            .arg(self.directory.join(NAME))
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn independent_process_cannot_enter_until_the_owned_guard_is_closed() {
    let fixture = Fixture::new();
    let before = fs::metadata(fixture.directory.join(NAME)).unwrap();
    let guard = fixture.acquire().unwrap();
    guard.validate().unwrap();
    assert_eq!(fixture.contender(), "busy");
    assert!(matches!(fixture.acquire(), Err(LockError::Busy)));
    // SAFETY: the guard retains the live descriptor for this query.
    assert_ne!(
        unsafe { libc::fcntl(guard.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    drop(guard);
    assert_eq!(fixture.contender(), "acquired");
    let guard = fixture.acquire().unwrap();
    guard.validate().unwrap();
    let after = fs::metadata(fixture.directory.join(NAME)).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(
        fs::read(fixture.directory.join(NAME)).unwrap(),
        b"persistent inode"
    );
}

#[test]
fn replaced_inode_and_changed_permissions_invalidate_a_live_guard() {
    let fixture = Fixture::new();
    let guard = fixture.acquire().unwrap();
    let lock = fixture.directory.join(NAME);
    fs::rename(&lock, fixture.directory.join("old-lock")).unwrap();
    fs::write(&lock, b"replacement").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(guard.validate(), Err(LockError::Changed));
    drop(guard);
    assert_eq!(fs::read(&lock).unwrap(), b"replacement");
    let guard = fixture.acquire().unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(guard.validate(), Err(LockError::UntrustedPath));
}

#[test]
fn absent_special_linked_or_exposed_lock_paths_cannot_authorize_a_controller() {
    let fixture = Fixture::new();
    let lock = fixture.directory.join(NAME);
    assert!(matches!(
        ControllerLock::at(&fixture.directory, fixture.owner.wrapping_add(1)),
        Err(LockError::UntrustedPath)
    ));
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(fixture.acquire(), Err(LockError::UntrustedPath)));
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
    let original = fixture.directory.join("original");
    fs::hard_link(&lock, &original).unwrap();
    assert!(matches!(fixture.acquire(), Err(LockError::UntrustedPath)));
    fs::remove_file(&lock).unwrap();
    symlink(&original, &lock).unwrap();
    assert!(matches!(fixture.acquire(), Err(LockError::UntrustedPath)));
    fs::remove_file(&lock).unwrap();
    assert!(matches!(fixture.acquire(), Err(LockError::UntrustedPath)));
    assert!(
        !lock.exists(),
        "acquire must not create or replace an inode"
    );
    let c_path = std::ffi::CString::new(lock.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the fixture path is live/NUL-terminated; no real path is changed.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    assert!(matches!(fixture.acquire(), Err(LockError::UntrustedPath)));
}

#[test]
fn production_factory_rejects_an_ordinary_user_without_opening_installed_state() {
    // SAFETY: UID queries have no memory preconditions. Fail before invoking
    // the factory if someone mistakenly runs these fixtures as root.
    assert!(unsafe { libc::getuid() != 0 && libc::geteuid() != 0 });
    assert!(matches!(
        ControllerLock::acquire(),
        Err(LockError::PermissionDenied)
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn an_extended_acl_cannot_expose_the_lock_despite_private_mode_bits() {
    let fixture = Fixture::new();
    let lock = fixture.directory.join(NAME);
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&lock)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(fixture.acquire(), Err(LockError::UntrustedPath)));
    assert!(
        Command::new("/bin/chmod")
            .arg("-N")
            .arg(&lock)
            .status()
            .unwrap()
            .success()
    );
    fixture.acquire().unwrap().validate().unwrap();
}
