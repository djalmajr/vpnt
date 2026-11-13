#![cfg(unix)]

use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vpnt::helper::{
    paths,
    runtime::{Program, Runtime},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    uid: u32,
}

fn macho(dependency: &str) -> Vec<u8> {
    let mut command = vec![];
    let size = (24 + dependency.len() + 1 + 7) & !7;
    for word in [0xcu32, size as u32, 24, 0, 0, 0] {
        command.extend_from_slice(&word.to_le_bytes());
    }
    command.extend_from_slice(dependency.as_bytes());
    command.push(0);
    command.resize(size, 0);
    let mut bytes = vec![];
    let cpu = if cfg!(target_arch = "aarch64") {
        0x0100_000c
    } else {
        0x0100_0007
    };
    for word in [0xfeed_facfu32, cpu, 0, 2, 1, size as u32, 0, 0] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend(command);
    bytes
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(directory.join("bin")).unwrap();
        let uid = fs::metadata(&directory).unwrap().uid();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["charon", "openfortivpn"] {
            fs::write(
                directory.join("bin").join(name),
                macho("/usr/lib/libSystem.B.dylib"),
            )
            .unwrap();
            fs::set_permissions(
                directory.join("bin").join(name),
                fs::Permissions::from_mode(0o555),
            )
            .unwrap();
        }
        fs::create_dir(directory.join("certs")).unwrap();
        fs::write(directory.join("certs/ca-bundle.pem"), b"fixture public CA").unwrap();
        let fixture = Self { directory, uid };
        fixture.manifest();
        fixture
    }
    fn manifest(&self) {
        let mut files = serde_json::Map::new();
        for name in ["bin/charon", "bin/openfortivpn", "certs/ca-bundle.pem"] {
            files.insert(
                name.into(),
                format!(
                    "{:x}",
                    Sha256::digest(fs::read(self.directory.join(name)).unwrap())
                )
                .into(),
            );
        }
        let data = serde_json::json!({"format":1,"appVersion":env!("CARGO_PKG_VERSION"),"prefix":paths::runtime_directory(),"minimumMacOS":"13.0",
            "strongswan":{"version":"6.1.0","source":"https://download.strongswan.org/strongswan-6.1.0.tar.bz2","sha256":"fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4","backend":"kernel-libipsec","pidDirectory":paths::runtime_directory().join("run"),"patches":{"charon-private-pid.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/charon-private-pid.patch"))),"strongswan-utun-framing.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/strongswan-utun-framing.patch"))),"strongswan-libipsec-no-routes.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/strongswan-libipsec-no-routes.patch"))),"charon-parent-eof.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/charon-parent-eof.patch")))}},
            "openfortivpn":{"version":"1.24.1","source":"https://github.com/adrienverge/openfortivpn/archive/refs/tags/v1.24.1.tar.gz","sha256":"c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465","patches":{"openfortivpn-no-routes.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/openfortivpn-no-routes.patch"))),"openfortivpn-bound-transport.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/openfortivpn-bound-transport.patch"))),"openfortivpn-ppp-supervisor.patch":format!("{:x}",Sha256::digest(include_bytes!("../scripts/macos/patches/openfortivpn-ppp-supervisor.patch")))}},"files":files});
        fs::write(
            self.directory.join("manifest.json"),
            serde_json::to_vec(&data).unwrap(),
        )
        .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn admitted_runtime_only_exposes_the_two_fixed_programs() {
    let fixture = Fixture::new();
    let runtime = Runtime::inspect(&fixture.directory, fixture.uid).unwrap();
    assert_eq!(
        runtime.program(Program::Charon),
        fixture.directory.join("bin/charon")
    );
    assert_eq!(
        runtime.program(Program::Fortinet),
        fixture.directory.join("bin/openfortivpn")
    );
}

#[test]
fn replacement_permissions_links_and_wrong_owners_are_rejected() {
    let fixture = Fixture::new();
    let program = fixture.directory.join("bin/charon");
    assert!(Runtime::inspect(&fixture.directory, fixture.uid.wrapping_add(1)).is_err());
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&program, macho("/usr/lib/different.dylib")).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o555)).unwrap();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
    fixture.manifest();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_ok());
    fs::set_permissions(&program, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
    fs::set_permissions(&program, fs::Permissions::from_mode(0o555)).unwrap();
    let original = fixture.directory.join("original");
    fs::rename(&program, &original).unwrap();
    symlink(&original, &program).unwrap();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
}

#[test]
fn valid_hash_does_not_admit_mutable_library_paths_or_broken_macho_commands() {
    let fixture = Fixture::new();
    let program = fixture.directory.join("bin/charon");
    for bytes in [
        macho("/opt/homebrew/opt/openssl@4/lib/libcrypto.4.dylib"),
        macho("/usr/lib/../../tmp/injected.dylib"),
        vec![0xcf, 0xfa, 0xed, 0xfe],
    ] {
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&program, bytes).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o555)).unwrap();
        fixture.manifest();
        assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
    }
}

#[test]
fn manifest_paths_and_extra_files_cannot_expand_the_runtime() {
    let fixture = Fixture::new();
    let path = fixture.directory.join("manifest.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    document["files"]["../outside"] = "a".repeat(64).into();
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
    fixture.manifest();
    fs::write(fixture.directory.join("bin/extra"), b"unexpected").unwrap();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
}

#[test]
#[ignore = "requires scripts/macos/build-runtime.py; inspects the actual prepared native runtime"]
fn prepared_native_runtime_passes_the_same_admission_code() {
    let directory = std::env::current_dir().unwrap().join("target/vpnt-runtime");
    let owner = fs::metadata(&directory).unwrap().uid();
    Runtime::inspect(directory, owner).unwrap();
}

#[test]
fn missing_or_changed_runtime_backend_patch_and_ca_inventory_are_rejected() {
    let fixture = Fixture::new();
    let path = fixture.directory.join("manifest.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for change in 0..16 {
        let mut document = original.clone();
        match change {
            0 => {
                document["strongswan"]
                    .as_object_mut()
                    .unwrap()
                    .remove("patches");
            }
            1 => {
                document["strongswan"]["patches"]["charon-private-pid.patch"] =
                    "0".repeat(64).into()
            }
            2 => {
                document["files"]
                    .as_object_mut()
                    .unwrap()
                    .remove("certs/ca-bundle.pem");
                fs::remove_file(fixture.directory.join("certs/ca-bundle.pem")).unwrap();
            }
            3 => {
                document["openfortivpn"]["patches"]["openfortivpn-no-routes.patch"] =
                    "0".repeat(64).into()
            }
            4 => document["openfortivpn"]["sha256"] = "0".repeat(64).into(),
            5 => {
                document["openfortivpn"]["patches"]
                    .as_object_mut()
                    .unwrap()
                    .remove("openfortivpn-bound-transport.patch");
            }
            6 => {
                document["openfortivpn"]["patches"]["openfortivpn-bound-transport.patch"] =
                    "0".repeat(64).into()
            }
            7 => {
                document["openfortivpn"]["patches"]
                    .as_object_mut()
                    .unwrap()
                    .remove("openfortivpn-ppp-supervisor.patch");
            }
            8 => {
                document["openfortivpn"]["patches"]["openfortivpn-ppp-supervisor.patch"] =
                    "0".repeat(64).into();
            }
            9 => {
                document["strongswan"]
                    .as_object_mut()
                    .unwrap()
                    .remove("backend");
            }
            10 => document["strongswan"]["backend"] = "kernel-pfkey".into(),
            11 => {
                document["strongswan"]["patches"]
                    .as_object_mut()
                    .unwrap()
                    .remove("strongswan-utun-framing.patch");
            }
            12 => {
                document["strongswan"]["patches"]["strongswan-libipsec-no-routes.patch"] =
                    "0".repeat(64).into()
            }
            13 => {
                document["strongswan"]["patches"]
                    .as_object_mut()
                    .unwrap()
                    .remove("charon-parent-eof.patch");
            }
            14 => {
                document["strongswan"]["patches"]["charon-parent-eof.patch"] = "0".repeat(64).into()
            }
            _ => {
                document["strongswan"]["patches"]["charon-extra.patch"] = "0".repeat(64).into();
            }
        }
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(
            Runtime::inspect(&fixture.directory, fixture.uid).is_err(),
            "{change}"
        );
        if change == 2 {
            fs::write(
                fixture.directory.join("certs/ca-bundle.pem"),
                b"fixture public CA",
            )
            .unwrap();
        }
    }
}

// Mutation: compare only the patch count, accept another backend name, or drop
// one required patch from the expected map.
#[test]
fn runtime_compiled_for_another_backend_or_patch_set_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.directory.join("manifest.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for (label, mutate) in [("backend", 0), ("missing-patch", 1), ("altered-hash", 2)] {
        let mut document = original.clone();
        match mutate {
            0 => document["strongswan"]["backend"] = "kernel-pfkey".into(),
            1 => {
                document["strongswan"]["patches"]
                    .as_object_mut()
                    .unwrap()
                    .remove("strongswan-utun-framing.patch");
            }
            _ => {
                document["strongswan"]["patches"]["strongswan-libipsec-no-routes.patch"] =
                    "0".repeat(64).into();
            }
        }
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(
            Runtime::inspect(&fixture.directory, fixture.uid).is_err(),
            "{label}"
        );
    }
    fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn an_acl_write_grant_cannot_bypass_read_only_posix_modes() {
    let fixture = Fixture::new();
    let program = fixture.directory.join("bin/charon");
    let result = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow write"])
        .arg(&program)
        .status()
        .unwrap();
    assert!(result.success());
    assert_eq!(fs::metadata(&program).unwrap().mode() & 0o777, 0o555);
    assert!(Runtime::inspect(&fixture.directory, fixture.uid).is_err());
}
