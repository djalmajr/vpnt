#![cfg(target_os = "macos")]
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
// Share the synthetic runtime format with payload admission tests.
mod helper {
    pub use vpnt::helper::paths;
}
#[path = "../src/install/payload/tests/runtime.rs"]
mod runtime;

struct Repository {
    root: PathBuf,
    _runtime: runtime::RuntimeFixture,
}
impl Repository {
    fn new() -> Self {
        let mut runtime = runtime::RuntimeFixture::new();
        let root = runtime.directory.with_file_name(format!(
            "install-preparer-{}",
            runtime.directory.file_name().unwrap().to_str().unwrap()
        ));
        fs::create_dir_all(root.join("scripts/macos")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&runtime.directory, root.join("target/vpnt-runtime")).unwrap();
        runtime.directory = root.join("target/vpnt-runtime");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fs::copy(source.join("Cargo.toml"), root.join("Cargo.toml")).unwrap();
        fs::copy(
            source.join("scripts/macos/prepare-installation.py"),
            root.join("scripts/macos/prepare-installation.py"),
        )
        .unwrap();
        // Role executables are fictional in this fixture. Each has a real native
        // Mach-O header; only the read-only inspector itself is ever executed.
        for name in [
            "vpnt-install",
            "vpnt-helper",
            "vpnt-pinentry",
            "vpnt-pppd",
            "vpnt-askpass",
        ] {
            fs::copy(
                env!("CARGO_BIN_EXE_vpnt-install"),
                root.join("target/debug").join(name),
            )
            .unwrap();
        }
        Self {
            root,
            _runtime: runtime,
        }
    }
    fn run(&self) -> std::process::Output {
        Command::new("python3")
            .arg(self.root.join("scripts/macos/prepare-installation.py"))
            .output()
            .unwrap()
    }
}
impl Drop for Repository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn preparation_is_repeatable_parses_its_own_policy_and_refuses_to_replace_a_corrupted_build() {
    let repository = Repository::new();
    let first = repository.run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(result["installationPerformed"], false);
    assert_eq!(result["uid"], repository._runtime.uid);
    assert_eq!(result["activationAvailable"], true);
    assert_eq!(result["visudoParsed"], true);
    assert_eq!(result["files"], 10);
    let second = repository.run();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&second.stdout).unwrap(),
        result
    );
    let payload = PathBuf::from(result["payload"].as_str().unwrap());
    assert!(payload.starts_with(&repository.root));
    assert_eq!(
        fs::read_dir(repository.root.join("target/vpnt-installation"))
            .unwrap()
            .count(),
        1,
        "temporary copies must be removed"
    );
    let path = payload.join("adapters/askpass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&path, b"corrupted fixture").unwrap();
    let failed = repository.run();
    assert!(
        !failed.status.success(),
        "a corrupted build must not be silently reused"
    );
    assert_eq!(
        fs::read(&path).unwrap(),
        b"corrupted fixture",
        "do not repair unknown output silently"
    );
    assert_eq!(
        fs::read_dir(repository.root.join("target/vpnt-installation"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn read_only_preparation_has_no_environment_or_argument_switch_to_activation() {
    let repository = Repository::new();
    for args in [
        vec!["activate"],
        vec!["remove"],
        vec!["inspect", "missing", "--uid", "0"],
        vec!["policy", "0", "a", "b"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vpnt-install"))
            .args(&args)
            .env("SUDO_UID", "0")
            .env("VPNT_INSTALL_ROOT", &repository.root)
            .current_dir(&repository.root)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{args:?} cannot activate a payload"
        );
        assert!(output.stdout.is_empty());
        if matches!(args.as_slice(), ["activate"] | ["remove"]) {
            assert_eq!(output.status.code(), Some(77), "root admission/{args:?}");
            assert_eq!(output.stderr, b"\"permission_denied\"\n");
        }
    }
    assert_eq!(
        fs::read_dir(&repository.root).unwrap().count(),
        3,
        "read-only commands cannot create an installation tree"
    );
    let nested = repository.root.join("target/debug/payload-output");
    let overlap = Command::new("python3")
        .arg(
            repository
                .root
                .join("scripts/macos/prepare-installation.py"),
        )
        .arg("--output")
        .arg(&nested)
        .output()
        .unwrap();
    assert!(
        !overlap.status.success(),
        "output cannot overlap the build inputs"
    );
    assert!(!nested.exists(), "overlap must be rejected before writing");
}
