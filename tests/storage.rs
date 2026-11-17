#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use vpnt::{
    model::Profile,
    storage::{ProfileStore, StoreError},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    path: PathBuf,
    uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let path = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "storage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            uid: fs::metadata(&path).unwrap().uid(),
            path,
        }
    }

    fn store(&self) -> ProfileStore {
        ProfileStore::open(&self.path, self.uid).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn profile(id: &str) -> Profile {
    serde_json::from_value(serde_json::json!({
        "id":id,"name":format!("Profile {id}"),"kind":"ipsec","gateway":"vpn.example.com",
        "username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"",
        "probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"
    }))
    .unwrap()
}

#[test]
fn profiles_survive_a_new_store_and_removal_preserves_other_profiles() {
    let fixture = Fixture::new();
    let store = fixture.store();
    assert!(store.load().unwrap().is_empty());
    store.save(profile("a")).unwrap();
    store.save(profile("b")).unwrap();
    let mut edited = profile("a");
    edited.name = "Edited".into();
    store.save(edited).unwrap();
    let reloaded = fixture.store().load().unwrap();
    assert_eq!(reloaded.len(), 2);
    assert_eq!(reloaded[0].name, "Edited");
    fixture.store().remove("a").unwrap();
    let remaining = fixture.store().load().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, "b");
    assert_eq!(
        fs::metadata(fixture.path.join("profiles.json"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn invalid_updates_leave_the_last_valid_file_unchanged() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(profile("a")).unwrap();
    let before = fs::read(fixture.path.join("profiles.json")).unwrap();
    let mut invalid = profile("a");
    invalid.probe_port = 22;
    assert!(matches!(store.save(invalid), Err(StoreError::InvalidData)));
    assert!(matches!(store.remove("../a"), Err(StoreError::InvalidData)));
    assert!(matches!(store.remove("missing"), Err(StoreError::NotFound)));
    assert_eq!(
        fs::read(fixture.path.join("profiles.json")).unwrap(),
        before
    );
}

#[test]
fn symlinks_and_readable_or_writable_private_files_are_rejected() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(profile("a")).unwrap();
    let database = fixture.path.join("profiles.json");
    let original = fixture.path.join("outside.json");
    fs::rename(&database, &original).unwrap();
    symlink(&original, &database).unwrap();
    assert!(store.load().is_err());
    assert!(store.save(profile("b")).is_err());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&original).unwrap()).unwrap()["profiles"]
            [0]["id"],
        "a"
    );
    fs::remove_file(&database).unwrap();
    fs::rename(&original, &database).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load().is_err());
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&database, &original).unwrap();
    assert!(store.load().is_err());
}

#[test]
fn wrong_owner_and_swapped_or_exposed_directories_are_rejected() {
    let fixture = Fixture::new();
    assert!(ProfileStore::open(&fixture.path, fixture.uid.wrapping_add(1)).is_err());
    let store = fixture.store();
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(store.load().is_err());
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o700)).unwrap();
    let child = fixture.path.join("linked");
    symlink(&fixture.path, &child).unwrap();
    assert!(ProfileStore::open(&child, fixture.uid).is_err());
}

#[test]
fn secrets_duplicate_ids_and_unknown_versions_cannot_enter_the_profile_database() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(profile("a")).unwrap();
    let database = fixture.path.join("profiles.json");
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&database).unwrap()).unwrap();
    let mut secret = original.clone();
    secret["profiles"][0]["password"] = "fictional-secret".into();
    let mut duplicate = original.clone();
    duplicate["profiles"]
        .as_array_mut()
        .unwrap()
        .push(original["profiles"][0].clone());
    let mut version = original.clone();
    version["version"] = 999.into();
    for invalid in [secret, duplicate, version] {
        fs::write(&database, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(matches!(store.load(), Err(StoreError::InvalidData)));
    }
}

#[test]
fn concurrent_saves_do_not_lose_another_profile() {
    let fixture = Fixture::new();
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let store = fixture.store();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                store.save(profile(&format!("p-{index}"))).unwrap();
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(fixture.store().load().unwrap().len(), 8);
}

#[test]
fn capacity_and_read_limits_reject_excess_without_disabling_valid_edits() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let database = fixture.path.join("profiles.json");
    let full = serde_json::json!({"version":1,"profiles":(0..64).map(|i| profile(&format!("p-{i}"))).collect::<Vec<_>>()});
    fs::write(&database, serde_json::to_vec(&full).unwrap()).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store.load().unwrap().len(), 64);
    store.save(profile("p-0")).unwrap();
    let before = fs::read(&database).unwrap();
    assert_eq!(store.save(profile("overflow")), Err(StoreError::Limit));
    assert_eq!(fs::read(&database).unwrap(), before);
    let mut padded = br#"{"version":1,"profiles":[]}"#.to_vec();
    padded.resize(1_048_576, b' ');
    fs::write(&database, &padded).unwrap();
    assert!(store.load().unwrap().is_empty());
    padded.push(b' ');
    fs::write(&database, &padded).unwrap();
    assert!(matches!(store.load(), Err(StoreError::InvalidData)));
}

#[test]
fn a_symlink_in_place_of_the_lock_does_not_authorize_a_write() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(profile("a")).unwrap();
    let database = fixture.path.join("profiles.json");
    let before = fs::read(&database).unwrap();
    let lock = fixture.path.join(".profiles.lock");
    fs::remove_file(&lock).unwrap();
    symlink(&database, &lock).unwrap();
    assert!(store.save(profile("b")).is_err());
    assert_eq!(fs::read(&database).unwrap(), before);
}

#[test]
fn root_factory_and_path_policy_reject_root_uid_parent_traversal_and_writable_ancestors() {
    assert!(matches!(
        ProfileStore::for_user(0),
        Err(StoreError::InvalidData)
    ));
    let fixture = Fixture::new();
    let child = fixture.path.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ProfileStore::open(child.join(".."), fixture.uid).is_err());
    let descendant = child.join("private");
    fs::create_dir(&descendant).unwrap();
    fs::set_permissions(&descendant, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ProfileStore::open(&descendant, fixture.uid).is_ok());
    fs::set_permissions(&child, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(ProfileStore::open(&descendant, fixture.uid).is_err());
}

#[test]
fn a_named_pipe_cannot_block_profile_loading() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        sync::mpsc,
    };
    let fixture = Fixture::new();
    let store = fixture.store();
    let path = fixture.path.join("profiles.json");
    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated owned path stays valid; mkfifo retains no pointer.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || sender.send(store.load()).unwrap());
    let result = receiver.recv_timeout(Duration::from_secs(2));
    if result.is_err() {
        // Wake a regressed blocking open before joining the owned test thread.
        let _ = fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path);
    }
    reader.join().unwrap();
    assert!(
        matches!(result, Ok(Err(StoreError::UntrustedPath))),
        "profile loading must reject special files without waiting for a writer"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn private_profile_data_rejects_acl_read_grants_even_with_mode_0600() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store.save(profile("a")).unwrap();
    let database = fixture.path.join("profiles.json");
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&database)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::metadata(&database).unwrap().mode() & 0o777, 0o600);
    assert!(matches!(store.load(), Err(StoreError::UntrustedPath)));
    assert!(store.save(profile("b")).is_err());
}
