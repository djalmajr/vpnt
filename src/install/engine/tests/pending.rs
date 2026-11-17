use super::*;
use std::{os::unix::fs::symlink, process::Command};

fn installed(f: &Fixture) -> BTreeMap<String, (u64, u32, Vec<u8>)> {
    let receipt = Receipt::load(&f.executor.tree).unwrap().unwrap();
    receipt
        .files
        .keys()
        .map(String::as_str)
        .chain(["receipt"])
        .map(|key| {
            let path = f.executor.tree.resolve(key).unwrap();
            let meta = fs::symlink_metadata(&path).unwrap();
            (
                key.to_owned(),
                (meta.ino(), meta.mode(), fs::read(path).unwrap()),
            )
        })
        .collect()
}

fn claim(f: &Fixture, phase: &str) -> PathBuf {
    let tree = &f.executor.tree;
    let directory = tree.state.join("ipsec").join("a".repeat(32));
    tree.directory(directory.parent().unwrap(), 0o700).unwrap();
    tree.directory(&directory, 0o700).unwrap();
    let configuration = b"# fictional configuration without credentials\n";
    fs::write(directory.join("strongswan.conf"), configuration).unwrap();
    let birth = serde_json::json!({"pid":std::process::id(),"start":[1,0]});
    let record = serde_json::json!({
        "version":1,"session":"a".repeat(32),"uid":601,"profile":"example","generation":7,
        "reqid":16383,"connection":"vpnt-601-6578616d706c65-7",
        "local":"192.0.2.2","remote":"198.51.100.3","networks":["10.20.0.0/24"],
        "controller":birth,"runtime_hash":"a".repeat(64),"configuration_hash":hash(configuration),
        "stage":phase,"child":if phase=="running" || phase=="stopped" {Some(birth)} else {None}
    });
    fs::write(
        directory.join("claim.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    for name in ["strongswan.conf", "claim.json"] {
        fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    directory
}

// Mutations: omit either gate, ignore Stopped/unknown admissions, or recover
// the installation journal before refusing an uncertain VPN generation.
#[test]
fn claims_without_a_controller_block_activation_removal_and_journal_recovery_in_every_phase() {
    for phase in ["prepared", "starting", "running", "stopped", "unknown"] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let directory = claim(&f, phase);
        // A pending terminal journal must remain untouched while any admission
        // is unresolved, even if the controller's flock is now available.
        let completed = f.executor.tree.state.join(".installation-completed");
        f.executor.tree.directory(&completed, 0o700).unwrap();
        fs::write(completed.join("settled"), b"after\n").unwrap();
        fs::set_permissions(completed.join("settled"), fs::Permissions::from_mode(0o600)).unwrap();
        drop(f.executor.tree.bootstrap().unwrap());
        let before = invariants::files(&f.root);
        let components = installed(&f);
        assert!(
            matches!(f.activate(), Err(Error::Busy)),
            "activation: {phase}"
        );
        assert_eq!(
            invariants::files(&f.root),
            before,
            "activation recovery: {phase}"
        );
        assert!(
            matches!(f.executor.remove(601), Err(Error::Busy)),
            "removal: {phase}"
        );
        assert_eq!(
            invariants::files(&f.root),
            before,
            "removal recovery: {phase}"
        );
        assert_eq!(installed(&f), components);
        assert!(completed.exists());
        drop(f.executor.tree.bootstrap().unwrap());
        // Test-owned fixture cleanup stands for a future verified completion;
        // production never deletes a claim merely because it is Stopped.
        fs::remove_dir_all(directory).unwrap();
        f.activate().unwrap();
        assert!(!completed.exists());
        assert_eq!(installed(&f), components);
        f.executor.remove(601).unwrap();
    }
}

// Mutations: follow an alias to an empty tree, accept exposed state, or read a
// special node to decide whether an admission exists. No traversal is needed.
#[test]
fn untrusted_ipsec_roots_are_refused_and_opaque_entries_cannot_be_interpreted_as_empty() {
    for change in ["file", "link", "mode", "acl", "fifo"] {
        let mut f = Fixture::new();
        f.activate().unwrap();
        let path = f.executor.tree.state.join("ipsec");
        let before = installed(&f);
        match change {
            "file" => fs::write(&path, b"").unwrap(),
            "link" => {
                let target = f.root.join("empty");
                f.executor.tree.directory(&target, 0o700).unwrap();
                symlink(target, &path).unwrap();
            }
            _ => {
                f.executor.tree.directory(&path, 0o700).unwrap();
                match change {
                    "mode" => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap()
                    }
                    "acl" => assert!(
                        Command::new("/bin/chmod")
                            .args(["+a", "everyone allow list"])
                            .arg(&path)
                            .status()
                            .unwrap()
                            .success()
                    ),
                    _ => {
                        let name = std::ffi::CString::new(
                            path.join("unknown").as_os_str().as_encoded_bytes(),
                        )
                        .unwrap();
                        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                    }
                }
            }
        }
        let expected = if change == "fifo" {
            Error::Busy
        } else {
            Error::UntrustedPath
        };
        assert!(
            matches!(f.activate(), Err(e) if e==expected),
            "activation: {change}"
        );
        assert!(
            matches!(f.executor.remove(601), Err(e) if e==expected),
            "removal: {change}"
        );
        assert_eq!(installed(&f), before);
        assert!(fs::symlink_metadata(&path).is_ok());
        drop(f.executor.tree.bootstrap().unwrap());
    }
}
