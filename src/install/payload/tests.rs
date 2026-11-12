use super::*;
use crate::install::{policy, valid_hash};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
mod runtime;
use runtime::{RuntimeFixture, macho};

struct Fixture {
    root: PathBuf,
    runtime: RuntimeFixture,
}
impl Fixture {
    fn new() -> Self {
        let mut runtime = RuntimeFixture::new();
        let root = runtime.directory.with_file_name(format!(
            "payload-{}",
            runtime.directory.file_name().unwrap().to_str().unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&runtime.directory, root.join("runtime")).unwrap();
        runtime.directory = root.join("runtime");
        fs::create_dir(root.join("adapters")).unwrap();
        fs::create_dir(root.join("policy")).unwrap();
        for name in ["helper", "installer", "pinentry", "pppd", "askpass"] {
            let p = root.join("adapters").join(name);
            fs::write(&p, macho("/usr/lib/libSystem.B.dylib")).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o555)).unwrap();
        }
        let hash = hash(&fs::read(root.join("adapters/helper")).unwrap());
        fs::write(
            root.join("policy/sudoers"),
            policy::sudoers(601, &hash, &hash).unwrap(),
        )
        .unwrap();
        let result = Self { root, runtime };
        result.manifest(601);
        result
    }
    fn manifest(&self, uid: u32) {
        let mut files = BTreeMap::new();
        fn inventory(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    inventory(root, &path, files)
                } else if path.file_name().unwrap() != "payload.json" {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                        hash(&fs::read(&path).unwrap()),
                    );
                }
            }
        }
        inventory(&self.root, &self.root, &mut files);
        fs::write(self.root.join("payload.json"), serde_json::to_vec(&serde_json::json!({"format":1,"appVersion":env!("CARGO_PKG_VERSION"),"uid":uid,"files":files})).unwrap()).unwrap();
    }
    fn inspect(&self) -> Result<Payload, Error> {
        Payload::inspect(&self.root, self.runtime.uid)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn admitted_payload_identifies_the_recipient_and_the_entire_verified_build() {
    let f = Fixture::new();
    let payload = f
        .inspect()
        .expect("a complete private payload must be inspectable without writing to the machine");
    let summary = payload.summary();
    assert_eq!(summary.uid, 601);
    assert_eq!(summary.app_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(summary.minimum_macos, "13.0");
    assert_eq!(summary.files, 10);
    assert!(valid_hash(&summary.id));
    assert_eq!(
        summary.id,
        hash(&fs::read(f.root.join("payload.json")).unwrap())
    );
}

#[test]
fn recipient_schema_and_file_set_cannot_be_broadened_by_a_new_manifest() {
    for field in [
        "uid",
        "appVersion",
        "format",
        "unknown",
        "extra-file",
        "missing-file",
        "escape",
        "duplicate",
        "oversized",
    ] {
        let f = Fixture::new();
        let path = f.root.join("payload.json");
        let bytes = fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match field {
            "uid" => value["uid"] = 0.into(),
            "appVersion" => value["appVersion"] = "other".into(),
            "format" => value["format"] = 2.into(),
            "unknown" => value["path"] = "/etc/sudoers".into(),
            "extra-file" => {
                value["files"]["adapters/shell"] = "a".repeat(64).into();
            }
            "missing-file" => {
                value["files"]
                    .as_object_mut()
                    .unwrap()
                    .remove("adapters/pppd");
            }
            "escape" => {
                value["files"]["../escape"] = "a".repeat(64).into();
            }
            "duplicate" | "oversized" => {}
            _ => unreachable!(),
        }
        let mut new = serde_json::to_string(&value).unwrap();
        if field == "duplicate" {
            new = new.replace(
                "\"files\":{",
                &format!(
                    "\"files\":{{\"adapters/helper\":\"{}\",",
                    value["files"]["adapters/helper"].as_str().unwrap()
                ),
            );
        }
        if field == "oversized" {
            new = " ".repeat(65_537) + &new;
        }
        fs::write(&path, new).unwrap();
        assert!(
            f.inspect().is_err(),
            "{field} cannot expand an installation"
        );
    }
}

#[test]
fn unexpected_or_missing_content_and_changed_build_identity_cannot_be_admitted() {
    for case in ["hash", "missing", "extra", "empty-directory", "revalidate"] {
        let f = Fixture::new();
        let admitted = f.inspect().unwrap();
        match case {
            "hash" => {
                fs::set_permissions(
                    f.root.join("adapters/askpass"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                fs::write(
                    f.root.join("adapters/askpass"),
                    macho("/usr/lib/changed.dylib"),
                )
                .unwrap();
            }
            "missing" => fs::remove_file(f.root.join("adapters/pppd")).unwrap(),
            "extra" => fs::write(f.root.join("adapters/unlisted"), b"unlisted").unwrap(),
            "empty-directory" => fs::create_dir(f.root.join("unlisted")).unwrap(),
            "revalidate" => {
                let value: serde_json::Value =
                    serde_json::from_slice(&fs::read(f.root.join("payload.json")).unwrap())
                        .unwrap();
                // Equivalent metadata still has a different serialized build identity.
                fs::write(
                    f.root.join("payload.json"),
                    serde_json::to_vec_pretty(&value).unwrap(),
                )
                .unwrap();
                assert!(f.inspect().is_ok());
            }
            _ => unreachable!(),
        }
        assert!(
            admitted.revalidate().is_err(),
            "{case} cannot preserve admission"
        );
    }
}

#[test]
fn linking_exposure_special_files_and_untrusted_dependencies_cannot_be_packaged() {
    use std::os::unix::fs::symlink;
    for case in [
        "symlink",
        "hardlink",
        "mode",
        "directory-mode",
        "special",
        "dependency",
    ] {
        let f = Fixture::new();
        let path = f.root.join(if matches!(case, "hardlink" | "mode") {
            "policy/sudoers"
        } else {
            "adapters/askpass"
        });
        match case {
            "symlink" => {
                fs::rename(&path, f.root.join("original")).unwrap();
                symlink(f.root.join("original"), &path).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&path, f.root.join("original")).unwrap();
                fs::remove_file(&path).unwrap();
                fs::rename(f.root.join("original"), &path).unwrap();
                fs::hard_link(&path, f.root.with_extension("linked")).unwrap();
            }
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap(),
            "directory-mode" => {
                fs::set_permissions(f.root.join("policy"), fs::Permissions::from_mode(0o777))
                    .unwrap()
            }
            "special" => {
                use std::os::unix::ffi::OsStrExt;
                let fifo = f.root.join("policy/fifo");
                let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "dependency" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                fs::write(&path, macho("/tmp/untrusted.dylib")).unwrap();
                f.manifest(601);
            }
            _ => unreachable!(),
        }
        let result = f.inspect();
        if case == "hardlink" {
            fs::remove_file(f.root.with_extension("linked")).unwrap();
        }
        assert!(result.is_err(), "{case} must be rejected before activation");
    }
}

#[test]
fn changing_the_policy_or_a_declared_runtime_patch_is_not_authorized_by_rehashing() {
    for case in ["recipient", "authentication", "runtime", "runtime-content"] {
        let f = Fixture::new();
        if case == "runtime-content" {
            let path = f.root.join("runtime/bin/charon");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(path, macho("/usr/lib/different.dylib")).unwrap();
        } else if case == "runtime" {
            let path = f.root.join("runtime/manifest.json");
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["openfortivpn"]["patches"]["openfortivpn-bound-transport.patch"] =
                "0".repeat(64).into();
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        } else {
            let path = f.root.join("policy/sudoers");
            let original = fs::read_to_string(&path).unwrap();
            fs::write(
                path,
                if case == "recipient" {
                    original.replace("#601 ALL", "#602 ALL")
                } else {
                    original.replace(" PASSWD:", " NOPASSWD:")
                },
            )
            .unwrap();
        }
        f.manifest(601);
        assert!(
            f.inspect().is_err(),
            "{case} cannot be authorized by a new checksum"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_write_grants_are_rejected_before_any_payload_is_trusted() {
    for suffix in ["policy", "policy/sudoers"] {
        let f = Fixture::new();
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(f.root.join(suffix))
                .status()
                .unwrap()
                .success()
        );
        assert!(f.inspect().is_err());
    }
}
