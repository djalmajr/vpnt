use super::*;
use std::{
    fs::{self, DirBuilder, Permissions},
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vpnt-netlease-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn acquire(&self, wait: Duration) -> io::Result<NetworkGuard> {
        NetworkLock::acquire_test(&self.0, Instant::now() + wait)
    }

    fn lock(&self) -> NetworkGuard {
        self.acquire(Duration::from_secs(1)).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn creates_private_stable_lock_and_releases_on_drop_and_unwind() {
    let f = Fixture::new();
    let path = f.0.join("network-write.lock");
    let lock = f.lock();
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o600);
    assert_eq!(meta.nlink(), 1);
    // Independent open file descriptions contend even within one process.
    let start = Instant::now();
    let wait = Duration::from_millis(30);
    assert!(matches!(f.acquire(wait), Err(e) if e.kind() == io::ErrorKind::TimedOut));
    assert!(start.elapsed() >= wait);
    drop(lock);
    assert!(
        std::panic::catch_unwind(|| {
            let _lock = f.lock();
            panic!("unwind while holding lock");
        })
        .is_err()
    );
    let _lock = f.lock();
    assert_eq!(fs::metadata(path).unwrap().ino(), meta.ino());
}

#[test]
fn rejects_insecure_lock_or_parent() {
    let f = Fixture::new();
    let path = f.0.join("network-write.lock");
    let target = f.0.join("target");
    fs::write(&target, []).unwrap();
    fs::set_permissions(&target, Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &path).unwrap();
    let wait = Duration::from_millis(100);
    assert!(f.acquire(wait).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(f.acquire(wait).is_err());
    fs::remove_file(&target).unwrap();
    for mode in [0o640, 0o602] {
        fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
        assert!(f.acquire(wait).is_err());
    }
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let meta = fs::metadata(&path).unwrap();
    assert!(
        validate_file(
            &File::open(&path).unwrap(),
            meta.uid().wrapping_add(1),
            false
        )
        .is_err()
    );
    assert!(
        NetworkLock::acquire_at(
            &f.0,
            meta.uid().wrapping_add(1),
            meta.gid(),
            Instant::now() + wait
        )
        .is_err()
    );
    for mode in [0o720, 0o702] {
        fs::set_permissions(&f.0, Permissions::from_mode(mode)).unwrap();
        assert!(f.acquire(wait).is_err());
    }
    fs::set_permissions(&f.0, Permissions::from_mode(0o700)).unwrap();
    symlink(&f.0, &target).unwrap();
    assert!(NetworkLock::acquire_test(&target, Instant::now() + wait).is_err());
    drop(f.lock());
}

#[test]
fn publish_and_withdraw_use_canonical_private_entries() {
    let f = Fixture::new();
    let registry = f.0.join("tunnel-leases");
    let guard = f.lock();
    assert!(!guard.tunnels_present().unwrap());
    assert!(!registry.exists());
    for name in [
        "",
        ".",
        "Uppercase",
        "other/file",
        "é",
        "bad\0id",
        &"a".repeat(65),
    ] {
        assert_eq!(
            guard.register(name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            guard.withdraw(name).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(!registry.exists());
    let name = "a".repeat(64);
    guard.register(&name).unwrap();
    assert!(guard.tunnels_present().unwrap());
    assert_eq!(fs::metadata(&registry).unwrap().mode() & 0o7777, 0o700);
    let meta = fs::metadata(registry.join(&name)).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o600);
    assert_eq!(meta.nlink(), 1);
    assert_eq!(
        guard.register(&name).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs::metadata(registry.join(&name)).unwrap().ino(),
        meta.ino()
    );
    guard.withdraw(&name).unwrap();
    guard.withdraw(&name).unwrap();
    assert!(!guard.tunnels_present().unwrap());
    assert!(registry.is_dir());
}

#[test]
fn registry_rejects_unsafe_directory_and_any_unsafe_entry() {
    let f = Fixture::new();
    let guard = f.lock();
    let registry = f.0.join("tunnel-leases");
    symlink(&f.0, &registry).unwrap();
    assert!(guard.tunnels_present().is_err());
    fs::remove_file(&registry).unwrap();
    DirBuilder::new().mode(0o700).create(&registry).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(guard.tunnels_present().is_err());
    fs::set_permissions(&registry, Permissions::from_mode(0o700)).unwrap();
    guard.register("valid").unwrap();
    let invalid = registry.join("invalid");
    symlink("valid", &invalid).unwrap();
    assert!(guard.tunnels_present().is_err());
    assert!(guard.withdraw("invalid").is_err());
    assert!(fs::symlink_metadata(&invalid).unwrap().is_symlink());
    fs::remove_file(&invalid).unwrap();
    fs::create_dir(&invalid).unwrap();
    assert!(guard.tunnels_present().is_err());
    fs::remove_dir(&invalid).unwrap();
    fs::hard_link(registry.join("valid"), &invalid).unwrap();
    assert!(guard.tunnels_present().is_err());
    fs::remove_file(&invalid).unwrap();
    fs::write(&invalid, []).unwrap();
    fs::set_permissions(&invalid, Permissions::from_mode(0o640)).unwrap();
    assert!(guard.tunnels_present().is_err());
    fs::remove_file(&invalid).unwrap();
    fs::rename(registry.join("valid"), registry.join("Invalid")).unwrap();
    assert!(guard.tunnels_present().is_err());
}
