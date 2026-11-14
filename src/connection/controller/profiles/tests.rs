use super::*;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "controller-profiles-{}-{}",
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
fn controller_retains_a_reservation_after_worker_unwind_until_explicit_cleanup_proof() {
    let f = Fixture::new();
    let store = f.store();
    let p = profile("one");
    store.save(p.clone()).unwrap();
    store.save(profile("two")).unwrap();
    let profiles = Profiles::new(f.store());
    let use_profile = profiles.begin(&p, 1).unwrap();
    use_profile.validate().unwrap();
    assert!(!profiles.idle());
    assert_eq!(store.remove("one"), Err(StoreError::Busy));
    store.remove("two").unwrap();
    use_profile.complete().unwrap();
    drop(use_profile);
    assert!(profiles.idle());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _attempt = profiles.begin(&p, 2).unwrap();
        panic!("fictional worker unwind");
    }));
    assert!(unwind.is_err());
    assert!(!profiles.idle());
    assert_eq!(store.save(p.clone()), Err(StoreError::Busy));
    drop(profiles);
    store.remove("one").unwrap();
}
#[test]
fn changed_or_removed_metadata_cannot_start_the_cached_profile() {
    let f = Fixture::new();
    let store = f.store();
    let original = profile("one");
    store.save(original.clone()).unwrap();
    let profiles = Profiles::new(f.store());
    let mut changed = original.clone();
    changed.gateway = "changed.example.test".into();
    store.save(changed.clone()).unwrap();
    assert!(matches!(
        profiles.begin(&original, 1),
        Err(StoreError::InvalidData)
    ));
    assert!(profiles.idle());
    let live = profiles.begin(&changed, 1).unwrap();
    fs::set_permissions(
        f.0.join(".profile-6f6e65.lock"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(live.validate(), Err(StoreError::UntrustedPath));
    assert_eq!(live.complete(), Err(StoreError::UntrustedPath));
    assert!(!profiles.idle());
    fs::set_permissions(
        f.0.join(".profile-6f6e65.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    live.complete().unwrap();
    store.remove("one").unwrap();
    assert!(matches!(
        profiles.begin(&changed, 2),
        Err(StoreError::NotFound)
    ));
    assert!(profiles.idle());
    assert!(profiles.load().unwrap().is_empty());
}
