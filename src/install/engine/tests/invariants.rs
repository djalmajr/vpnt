use super::*;
use std::collections::BTreeMap;
pub(super) fn files(root: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, result: &mut BTreeMap<String, (u32, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                walk(root, &path, result)
            } else {
                let bytes = if meta.is_symlink() {
                    fs::read_link(&path)
                        .unwrap()
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec()
                } else {
                    fs::read(&path).unwrap()
                };
                result.insert(
                    path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    (meta.mode() & 0o7777, bytes),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}
impl Fixture {
    pub(super) fn recipient(&self, uid: u32) {
        let helper = hash(&fs::read(self.source.root.join("adapters/helper")).unwrap());
        let installer = hash(&fs::read(self.source.root.join("adapters/installer")).unwrap());
        fs::write(
            self.source.root.join("policy/sudoers"),
            policy::sudoers(uid, &helper, &installer).unwrap(),
        )
        .unwrap();
        self.source.manifest(uid);
    }
    pub(super) fn revise(&self) {
        let path = self.source.root.join("adapters/helper");
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"revision");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(path, bytes).unwrap();
        self.recipient(601);
    }
}
#[test]
fn update_refreshes_digests_for_registered_users_and_removing_one_preserves_the_other() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    f.recipient(602);
    assert_eq!(f.activate().unwrap().users, vec![601, 602]);
    let original = fs::read(f.policy(601)).unwrap();
    f.revise();
    assert_eq!(f.activate().unwrap().users, vec![601, 602]);
    assert_ne!(fs::read(f.policy(601)).unwrap(), original);
    let receipt = Receipt::load(&f.executor.tree).unwrap().unwrap();
    receipt.verify(&f.executor.tree).unwrap();
    access::admit(&f.executor.tree, 601).unwrap();
    access::admit(&f.executor.tree, 602).unwrap();
    assert_eq!(f.executor.remove(601).unwrap().users, vec![602]);
    assert!(!f.policy(601).exists());
    assert!(f.policy(602).exists());
    assert!(f.executor.tree.resolve("adapters/helper").unwrap().exists());
    assert_eq!(
        access::admit(&f.executor.tree, 601),
        Err(Error::PermissionDenied)
    );
    assert!(f.executor.remove(602).unwrap().users.is_empty());
}
#[test]
fn active_controller_unknown_files_and_corrupted_receipts_refuse_mutation() {
    let mut f = Fixture::new();
    let lock = f.executor.tree.bootstrap().unwrap();
    let before = files(&f.root);
    assert!(matches!(f.activate(), Err(Error::Busy)));
    assert_eq!(files(&f.root), before);
    drop(lock);
    f.executor
        .tree
        .directory(&f.executor.tree.tools, 0o755)
        .unwrap();
    let helper = f.executor.tree.resolve("adapters/helper").unwrap();
    fs::write(&helper, b"foreign fixture").unwrap();
    let before = files(&f.root);
    assert!(matches!(f.activate(), Err(Error::Conflict)));
    assert_eq!(files(&f.root), before);
    fs::remove_file(helper).unwrap();
    f.activate().unwrap();
    let receipt = f.executor.tree.resolve("receipt").unwrap();
    fs::write(&receipt, b"unknown receipt").unwrap();
    let before = files(&f.root);
    assert!(f.executor.remove(601).is_err());
    assert_eq!(files(&f.root), before);
}
#[test]
fn observed_foreign_changes_and_a_policy_that_is_not_included_are_never_silently_adopted() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let helper = f.executor.tree.resolve("adapters/helper").unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&helper, b"foreign after installation").unwrap();
    let before = files(&f.root);
    assert_eq!(access::admit(&f.executor.tree, 601), Err(Error::Conflict));
    assert!(matches!(f.activate(), Err(Error::Conflict)));
    assert_eq!(files(&f.root), before);
    let mut f = Fixture::new();
    fs::write(&f.executor.checks.global, b"# valid syntax, no include\n").unwrap();
    let before = files(&f.root);
    assert!(matches!(f.activate(), Err(Error::PolicyRejected)));
    assert_eq!(files(&f.root), before);
    assert!(!Journal::pending(&f.executor.tree).unwrap());
}
#[test]
fn no_key_in_a_payload_receipt_or_journal_can_address_a_profile_lock_or_arbitrary_path() {
    let f = Fixture::new();
    for key in [
        "../state/users/601/profiles.json",
        "receipt/../users",
        "runtime/../.controller.lock",
        "runtime/0.1.0/../../state/profiles.json",
        "runtime/0.1.0/run/charon.pid",
        "adapters/shell",
        "policy/0",
        "policy/+601",
        "/etc/sudoers",
        "users/601/profiles.json",
    ] {
        assert!(f.executor.tree.resolve(key).is_err(), "{key}");
    }
    let path = f.executor.tree.state.join(".installation-transaction");
    f.executor.tree.directory(&path, 0o700).unwrap();
    let bad = serde_json::json!({"format":1,"entries":[{"key":"users/601/profiles.json","before":null,"after":null}]});
    fs::write(
        path.join("manifest.json"),
        serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    assert_eq!(
        Journal::recover(&f.executor.tree),
        Err(Error::RecoveryRequired)
    );
    assert!(path.exists());
}

#[test]
fn installed_receipts_require_a_complete_canonical_inventory_and_matching_modes() {
    let mut f = Fixture::new();
    f.activate().unwrap();
    let path = f.executor.tree.resolve("receipt").unwrap();
    let original = fs::read(&path).unwrap();
    for case in [
        "missing",
        "mode",
        "duplicate",
        "unknown",
        "profile",
        "whitespace",
    ] {
        let mut receipt = Receipt::load(&f.executor.tree).unwrap().unwrap();
        match case {
            "missing" => {
                receipt.files.remove("adapters/helper");
            }
            "mode" => {
                receipt.files.get_mut("adapters/helper").unwrap().mode = 0o755;
            }
            "profile" => {
                receipt.files.insert(
                    "users/601/profiles.json".into(),
                    receipt.files["adapters/helper"].clone(),
                );
            }
            _ => {}
        }
        let mut bytes = serde_json::to_vec(&receipt).unwrap();
        if case == "duplicate" {
            bytes.splice(1..1, b"\"format\":1,".iter().copied());
        } else if case == "unknown" {
            bytes.splice(1..1, b"\"extra\":true,".iter().copied());
        } else if case == "whitespace" {
            bytes.push(b' ');
        }
        fs::write(&path, bytes).unwrap();
        let before = files(&f.root);
        assert!(
            Receipt::load(&f.executor.tree).is_err(),
            "receipt admission/{case}"
        );
        assert!(f.executor.remove(601).is_err(), "{case}");
        assert_eq!(files(&f.root), before, "{case}");
        fs::write(&path, &original).unwrap();
    }
    assert_eq!(
        access::admit(&f.executor.tree, 602),
        Err(Error::PermissionDenied)
    );
}

#[test]
fn destination_links_and_unsafe_permissions_are_rejected_before_mutation() {
    for case in ["hardlink", "symlink", "permissions"] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let helper = f.executor.tree.resolve("adapters/helper").unwrap();
        match case {
            "hardlink" => fs::hard_link(&helper, f.root.join("linked-helper")).unwrap(),
            "symlink" => {
                let target = f.root.join("linked-helper");
                fs::rename(&helper, &target).unwrap();
                std::os::unix::fs::symlink(target, &helper).unwrap();
            }
            _ => fs::set_permissions(&helper, fs::Permissions::from_mode(0o577)).unwrap(),
        }
        let before = files(&f.root);
        assert_eq!(
            f.executor.remove(601).unwrap_err(),
            Error::UntrustedPath,
            "{case}"
        );
        assert_eq!(files(&f.root), before, "{case}");
    }
}
