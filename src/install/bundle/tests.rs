use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
struct Fixture {
    root: PathBuf,
    executable: PathBuf,
    component: PathBuf,
    metadata: Metadata,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "vpnt-app-bundle-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let executable = root.join("vpnt.app/Contents/MacOS/vpnt");
        let component = root.join("vpnt.app/Contents/Resources/Component");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::create_dir_all(&component).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&executable, b"fictional host bytes").unwrap();
        // This layer checks binding of bytes, not package format. Real native
        // archive admission belongs to the package/app integration tests.
        fs::write(component.join("component.pkg"), b"fictional package bytes").unwrap();
        let metadata = Metadata {
            format: 1,
            app_version: env!("CARGO_PKG_VERSION").into(),
            uid: unsafe { libc::getuid() },
            build: "a".repeat(64),
            minimum_macos: "26.0".into(),
            host_sha256: digest(b"fictional host bytes"),
            package_sha256: digest(b"fictional package bytes"),
            helper_sha256: "b".repeat(64),
            installer_sha256: "c".repeat(64),
            askpass_sha256: "d".repeat(64),
        };
        let result = Self {
            root,
            executable,
            component,
            metadata,
        };
        result.write();
        result
    }
    fn write(&self) {
        fs::write(
            self.component.join("component.json"),
            serde_json::to_vec(&self.metadata).unwrap(),
        )
        .unwrap();
    }
    fn admit(&self) -> Result<Component, Error> {
        Component::at_executable(&self.executable, unsafe { libc::getuid() })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn packaged_component_is_bound_to_the_running_host_recipient_and_unchanged_bytes() {
    let f = Fixture::new();
    let component = f
        .admit()
        .expect("the packaged host must admit its fixed component");
    assert_eq!(component.metadata(), &f.metadata);
    assert_eq!(component.package(), f.component.join("component.pkg"));
    component.revalidate().unwrap();
    fs::write(
        f.component.join("component.pkg"),
        b"modified package bytes!",
    )
    .unwrap();
    assert_eq!(component.revalidate(), Err(Error::Integrity));
    assert!(matches!(f.admit(), Err(Error::Integrity)));
}

#[test]
fn recipient_version_schema_and_digest_fields_cannot_select_another_component() {
    for case in [
        "uid",
        "version",
        "format",
        "digest",
        "minimum",
        "unknown",
        "duplicate",
    ] {
        let mut f = Fixture::new();
        match case {
            "uid" => f.metadata.uid += 1,
            "version" => f.metadata.app_version = "0.0.0".into(),
            "format" => f.metadata.format = 2,
            "digest" => f.metadata.installer_sha256 = "f".repeat(63),
            "minimum" => f.metadata.minimum_macos = "26..0".into(),
            _ => {}
        }
        f.write();
        let path = f.component.join("component.json");
        let mut bytes = fs::read(&path).unwrap();
        if case == "unknown" {
            bytes.splice(1..1, b"\"package\":\"/tmp/other.pkg\",".iter().copied());
        } else if case == "duplicate" {
            bytes.splice(1..1, b"\"format\":1,".iter().copied());
        }
        fs::write(&path, &bytes).unwrap();
        assert!(f.admit().is_err(), "{case}");
        assert_eq!(
            fs::read(path).unwrap(),
            bytes,
            "admission is read-only/{case}"
        );
    }
}

#[test]
fn changing_host_or_rewriting_metadata_after_admission_invalidates_the_original_seal() {
    for case in ["host", "metadata", "coordinated"] {
        let mut f = Fixture::new();
        let component = f.admit().unwrap();
        if case == "host" {
            fs::write(&f.executable, b"a different host").unwrap();
        } else if case == "metadata" {
            f.metadata.build = "e".repeat(64);
            f.write();
        } else {
            let bytes = b"changed package and matching new metadata";
            fs::write(f.component.join("component.pkg"), bytes).unwrap();
            f.metadata.package_sha256 = digest(bytes);
            f.write();
        }
        assert_eq!(component.revalidate(), Err(Error::Integrity));
        if case == "host" {
            assert!(matches!(f.admit(), Err(Error::Integrity)));
        }
    }
}

#[test]
fn linked_special_writable_or_oversized_bundle_inputs_are_rejected_without_reading_forever() {
    for case in [
        "link",
        "hardlink",
        "fifo",
        "mode",
        "parent",
        "group-parent",
        "size",
    ] {
        let f = Fixture::new();
        let path = f.component.join("component.pkg");
        match case {
            "link" => {
                let bytes = f.root.join("other.pkg");
                fs::rename(&path, &bytes).unwrap();
                std::os::unix::fs::symlink(bytes, &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, f.root.join("other.pkg")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            }
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap(),
            "parent" => {
                fs::set_permissions(&f.component, fs::Permissions::from_mode(0o777)).unwrap()
            }
            "group-parent" => {
                fs::set_permissions(&f.component, fs::Permissions::from_mode(0o775)).unwrap()
            }
            "size" => fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(300 * 1024 * 1024 + 1)
                .unwrap(),
            _ => unreachable!(),
        }
        assert!(matches!(f.admit(), Err(Error::UntrustedPath)), "{case}");
    }
}

#[test]
fn executable_layout_cannot_redirect_to_a_debug_binary_or_linked_bundle() {
    let f = Fixture::new();
    fs::copy(&f.executable, f.executable.with_file_name("another-app")).unwrap();
    for path in [
        f.root.join("target/debug/vpnt"),
        f.executable.with_file_name("another-app"),
        f.root.join("vpnt.app/Contents/MacOS/../MacOS/vpnt"),
    ] {
        assert!(
            Component::at_executable(&path, f.metadata.uid).is_err(),
            "{}",
            path.display()
        );
    }
    let linked = f.root.join("linked.app");
    std::os::unix::fs::symlink(f.root.join("vpnt.app"), &linked).unwrap();
    assert!(matches!(
        Component::at_executable(&linked.join("Contents/MacOS/vpnt"), f.metadata.uid),
        Err(Error::UntrustedPath)
    ));
}

#[test]
fn bundle_admission_rejects_extended_write_grants_on_the_package_or_its_directory() {
    for directory in [true, false] {
        let f = Fixture::new();
        let path = if directory {
            f.component.clone()
        } else {
            f.component.join("component.pkg")
        };
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(["+a", "everyone allow write"])
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(f.admit(), Err(Error::UntrustedPath)));
    }
}

#[test]
fn native_applications_parent_is_admitted_without_weakening_bundle_directory_permissions() {
    // Native read-only evidence for the normal root:admin 0775 parent. No app
    // or setting is created in Applications by this test.
    directory(Path::new("/Applications"), unsafe { libc::getuid() }).unwrap();
    let f = Fixture::new();
    fs::set_permissions(&f.component, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        directory(&f.component, f.metadata.uid),
        Err(Error::UntrustedPath)
    );
}
