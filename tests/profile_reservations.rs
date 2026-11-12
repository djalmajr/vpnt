#![cfg(unix)]
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
use vpnt::{
    model::Profile,
    storage::{ProfileStore, StoreError},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "profile-reservations-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn store(&self) -> ProfileStore {
        ProfileStore::open(&self.0, fs::metadata(&self.0).unwrap().uid()).unwrap()
    }
    fn path(&self, id: &str) -> PathBuf {
        assert_eq!(id, "one");
        self.0.join(".profile-6f6e65.lock")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn profile(id: &str) -> Profile {
    serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
}
#[test]
fn a_reserved_profile_cannot_be_edited_or_removed_but_another_profile_can() {
    let f = Fixture::new();
    let s = f.store();
    s.save(profile("one")).unwrap();
    s.save(profile("two")).unwrap();
    let guard = s.reserve("one").unwrap();
    let before = fs::read(f.0.join("profiles.json")).unwrap();
    let mut edited = profile("one");
    edited.gateway = "changed.example.test".into();
    assert_eq!(s.save(edited), Err(StoreError::Busy));
    assert_eq!(s.remove("one"), Err(StoreError::Busy));
    assert_eq!(fs::read(f.0.join("profiles.json")).unwrap(), before);
    let mut other = profile("two");
    other.name = "Edited inactive profile".into();
    s.save(other).unwrap();
    s.remove("two").unwrap();
    assert_eq!(s.load().unwrap()[0].gateway, "vpn.example.test");
    guard.validate().unwrap();
    drop(guard);
    s.remove("one").unwrap();
    assert!(s.load().unwrap().is_empty());
}

#[test]
fn profile_identity_does_not_fold_case_on_case_insensitive_filesystems() {
    let f = Fixture::new();
    let s = f.store();
    let uppercase = s.reserve("Case").unwrap();
    let lowercase = s
        .reserve("case")
        .expect("different IDs cannot share a reservation inode");
    assert!(f.0.join(".profile-43617365.lock").is_file());
    assert!(f.0.join(".profile-63617365.lock").is_file());
    uppercase.validate().unwrap();
    lowercase.validate().unwrap();
}
#[test]
fn a_different_process_observes_flock_and_release_preserves_the_inode() {
    let f = Fixture::new();
    let s = f.store();
    let guard = s.reserve("one").unwrap();
    let inode = fs::metadata(f.path("one")).unwrap().ino();
    let no_inherited = Command::new("/usr/bin/python3").arg("-c").arg("import os,sys\ntarget=os.stat(sys.argv[1])\nfor name in os.listdir('/dev/fd'):\n try: entry=os.fstat(int(name))\n except OSError: continue\n assert (entry.st_dev,entry.st_ino)!=(target.st_dev,target.st_ino), 'reservation leaked through exec'").arg(f.path("one")).output().unwrap();
    assert!(
        no_inherited.status.success(),
        "{}",
        String::from_utf8_lossy(&no_inherited.stderr)
    );
    let check = |busy: bool| {
        let result=Command::new("/usr/bin/python3").arg("-c").arg("import fcntl,sys\nf=open(sys.argv[1],'r+')\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n busy=False\nexcept BlockingIOError:\n busy=True\nassert busy==(sys.argv[2]=='busy')").arg(f.path("one")).arg(if busy{"busy"}else{"free"}).output().unwrap();
        assert!(
            result.status.success(),
            "independent flock result: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    check(true);
    drop(guard);
    check(false);
    assert_eq!(fs::metadata(f.path("one")).unwrap().ino(), inode);
    assert!(s.reserve("../escape").is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn profile_reservations_reject_acl_read_grants_even_with_private_mode() {
    let f = Fixture::new();
    let s = f.store();
    let guard = s.reserve("one").unwrap();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(f.path("one"))
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::metadata(f.path("one")).unwrap().mode() & 0o777, 0o600);
    assert_eq!(guard.validate(), Err(StoreError::UntrustedPath));
    assert!(s.reserve("one").is_err());
}
#[test]
fn exposed_replaced_or_linked_reservation_inodes_are_not_trusted() {
    let f = Fixture::new();
    let s = f.store();
    let guard = s.reserve("one").unwrap();
    fs::set_permissions(f.path("one"), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(guard.validate(), Err(StoreError::UntrustedPath));
    drop(guard);
    assert!(s.reserve("one").is_err());
    fs::set_permissions(f.path("one"), fs::Permissions::from_mode(0o600)).unwrap();
    let guard = s.reserve("one").unwrap();
    fs::rename(f.path("one"), f.0.join("original.lock")).unwrap();
    let replacement = s.reserve("one").unwrap();
    assert_eq!(guard.validate(), Err(StoreError::UntrustedPath));
    drop(replacement);
    drop(guard);
    fs::remove_file(f.path("one")).unwrap();
    symlink(f.0.join("original.lock"), f.path("one")).unwrap();
    assert!(s.reserve("one").is_err());
    fs::remove_file(f.path("one")).unwrap();
    fs::hard_link(f.0.join("original.lock"), f.path("one")).unwrap();
    assert!(s.reserve("one").is_err());
}
