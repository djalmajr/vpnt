use super::*;
use crate::install::payload::tests::Fixture as Source;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
struct Fixture {
    source: Source,
    root: PathBuf,
    executor: Executor,
}
impl Fixture {
    fn new() -> Self {
        let source = Source::new();
        let root = source.root.with_extension("engine");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let tree = Tree::fixture(&root);
        drop(tree.bootstrap().unwrap());
        tree.directory(&tree.policies, 0o755).unwrap();
        tree.user(601).unwrap();
        let global = root.join("sudoers");
        fs::write(
            &global,
            format!("@includedir {}\n", tree.policies.display()),
        )
        .unwrap();
        let executor = Executor {
            tree,
            checks: Checks { global },
            fault: None,
        };
        Self {
            source,
            root,
            executor,
        }
    }
    fn activate(&mut self) -> Result<Outcome, Error> {
        self.executor.activate(&self.source.inspect().unwrap())
    }
    fn policy(&self, uid: u32) -> PathBuf {
        self.executor
            .tree
            .resolve(&format!("policy/{uid}"))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
pub(super) struct Fault {
    remaining: usize,
    crash: bool,
}
impl Fault {
    pub(super) fn step(&mut self, tree: &Tree) -> Result<(), Error> {
        assert!(
            matches!(tree.bootstrap(), Err(Error::Busy)),
            "transaction must retain the controller lock during writes"
        );
        if self.remaining == 0 {
            if self.crash {
                unsafe {
                    libc::_exit(81);
                }
            }
            self.remaining = usize::MAX;
            Err(Error::Io)
        } else {
            self.remaining -= 1;
            Ok(())
        }
    }
}

mod channel;
mod crash;
mod invariants;
mod journal;
mod pending;
mod recovery;

#[test]
fn install_repeat_and_remove_preserve_profiles_and_the_controller_lock_inode() {
    let mut f = Fixture::new();
    let lock = f.executor.tree.state.join(".controller.lock");
    let inode = fs::metadata(&lock).unwrap().ino();
    let directory = f.executor.tree.state.join("users/601");
    let store = crate::storage::ProfileStore::open(&directory, f.executor.tree.owner).unwrap();
    let record:crate::model::Profile=serde_json::from_value(serde_json::json!({"id":"existing","name":"Existing fixture","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
    store.save(record.clone()).unwrap();
    let profile = directory.join("profiles.json");
    let before = fs::read(&profile).unwrap();
    let profile_inode = fs::metadata(&profile).unwrap().ino();
    let reservation = directory.join(".profile-6578697374696e67.lock");
    let reservation_inode = fs::metadata(&reservation).unwrap().ino();
    let result = f
        .activate()
        .expect("a verified payload must be applied by the executor");
    assert_eq!(result.users, vec![601]);
    assert_eq!(result.files, 9);
    assert!(!result.cleanup_pending);
    let helper = f.executor.tree.resolve("adapters/helper").unwrap();
    let helper_inode = fs::metadata(&helper).unwrap().ino();
    let policy_inode = fs::metadata(f.policy(601)).unwrap().ino();
    assert_eq!(f.activate().unwrap().files, 9);
    assert_eq!(fs::metadata(&helper).unwrap().ino(), helper_inode);
    assert_eq!(fs::metadata(f.policy(601)).unwrap().ino(), policy_inode);
    let removed = f.executor.remove(601).unwrap();
    assert!(removed.users.is_empty());
    assert_eq!(removed.files, 0);
    assert!(!helper.exists());
    assert!(!f.policy(601).exists());
    assert_eq!(fs::read(&profile).unwrap(), before);
    assert_eq!(store.load().unwrap(), vec![record]);
    assert_eq!(fs::metadata(&profile).unwrap().ino(), profile_inode);
    assert_eq!(fs::metadata(&reservation).unwrap().ino(), reservation_inode);
    assert_eq!(fs::metadata(&lock).unwrap().ino(), inode);
    assert!(!Journal::pending(&f.executor.tree).unwrap());
}
