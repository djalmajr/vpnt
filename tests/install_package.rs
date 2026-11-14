#![cfg(target_os = "macos")]
use std::{
    fs,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};
mod helper {
    pub use vpnt::helper::paths;
}
#[path = "installation/fixture.rs"]
mod fixture;
use fixture::Repository;

struct Package {
    repository: Repository,
    payload: PathBuf,
}
impl Package {
    fn new() -> Self {
        let repository = Repository::new();
        for name in ["package-installation.py", "installation_package.py"] {
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts/macos")
                    .join(name),
                repository.root.join("scripts/macos").join(name),
            )
            .unwrap();
        }
        let result = json(repository.run());
        assert_eq!(result["uid"], repository.uid());
        Self {
            repository,
            payload: PathBuf::from(result["payload"].as_str().unwrap()),
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new("python3");
        command
            .arg(
                self.repository
                    .root
                    .join("scripts/macos/package-installation.py"),
            )
            .arg("--payload")
            .arg(&self.payload);
        command
    }
    fn build(&self) -> serde_json::Value {
        json(self.command().output().unwrap())
    }
    fn verify(&self, path: &Path) -> Output {
        self.command().arg("--verify").arg(path).output().unwrap()
    }
}
fn json(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn native(program: &str, arguments: &[&Path]) {
    let result = Command::new(program).args(arguments).output().unwrap();
    assert!(
        result.status.success(),
        "{}: {}",
        program,
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn native_package_is_repeatable_audited_and_scripts_refuse_volume_or_unprivileged_execution() {
    let f = Package::new();
    let mut command = f.command();
    // Only the new child changes its mask; the parallel test process does not.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    let result = json(command.output().unwrap());
    assert_eq!(result["installationPerformed"], false);
    assert_eq!(result["signed"], false);
    assert_eq!(result["uid"], f.repository.uid());
    assert_eq!(result["payloadFiles"], 11);
    let package = PathBuf::from(result["package"].as_str().unwrap());
    let inode = fs::metadata(&package).unwrap().ino();
    assert_eq!(f.build(), result);
    assert_eq!(fs::metadata(&package).unwrap().ino(), inode);
    assert_eq!(json(f.verify(&package)), result);
    let expanded = f.repository.root.join("expanded");
    native(
        "/usr/sbin/pkgutil",
        &[Path::new("--expand-full"), &package, &expanded],
    );
    for script in ["preinstall", "postinstall"] {
        let path = expanded.join("Component.pkg/Scripts").join(script);
        let syntax = Command::new("/bin/sh")
            .arg("-n")
            .arg(&path)
            .status()
            .unwrap();
        assert!(syntax.success());
        if script == "postinstall" {
            assert_eq!(
                fs::read_to_string(&path).unwrap().lines().last().unwrap(),
                format!(
                    "exec /Library/PrivilegedHelperTools/dev.vpnt.staging/{}/adapters/installer activate",
                    result["id"].as_str().unwrap()
                )
            );
        }
        for (volume, expected) in [("/Volumes/Fictional", 64), ("/", 77)] {
            let output = Command::new("/bin/sh")
                .arg(&path)
                .arg(&package)
                .arg("/ignored-location")
                .arg(volume)
                .env("SUDO_UID", "0")
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(expected), "{script}/{volume}");
            assert!(output.stdout.is_empty() && output.stderr.is_empty());
        }
    }
    fs::write(&package, b"corrupted own fixture package").unwrap();
    let failed = f.command().output().unwrap();
    assert!(
        !failed.status.success(),
        "do not replace a corrupted package"
    );
    assert_eq!(
        fs::read(&package).unwrap(),
        b"corrupted own fixture package"
    );
    assert_eq!(
        fs::read_dir(package.parent().unwrap().parent().unwrap())
            .unwrap()
            .count(),
        1,
        "temporary build/audit trees must be removed"
    );
}

#[test]
fn native_archive_audit_rejects_changed_authority_destination_actions_and_ownership() {
    let f = Package::new();
    let result = f.build();
    let package = PathBuf::from(result["package"].as_str().unwrap());
    for (case, file, before, after, reason) in [
        (
            "root-tag",
            "Component.pkg/PackageInfo",
            "pkg-info",
            "not-pkg-info",
            "Unknown component metadata",
        ),
        (
            "volume",
            "Distribution",
            "rootVolumeOnly=\"true\"",
            "rootVolumeOnly=\"false\"",
            "Distribution changed",
        ),
        (
            "domain",
            "Distribution",
            "enable_currentUserHome=\"false\"",
            "enable_currentUserHome=\"true\"",
            "Distribution changed",
        ),
        (
            "destination",
            "Component.pkg/PackageInfo",
            "/Library/PrivilegedHelperTools/dev.vpnt.staging/",
            "/tmp/",
            "Component destination",
        ),
        (
            "authority",
            "Component.pkg/PackageInfo",
            "auth=\"root\"",
            "auth=\"none\"",
            "Component destination",
        ),
        (
            "relocation",
            "Component.pkg/PackageInfo",
            "relocatable=\"false\"",
            "relocatable=\"true\"",
            "Component destination",
        ),
        (
            "action",
            "Component.pkg/PackageInfo",
            "<bundle-version/>",
            "<bundle-version><bundle path=\"/tmp/unexpected\"/></bundle-version>",
            "bundle actions",
        ),
        (
            "script",
            "Component.pkg/PackageInfo",
            "file=\"./postinstall\"",
            "file=\"./preinstall\"",
            "Unexpected script action",
        ),
        (
            "owner",
            "Component.pkg/Bom",
            "",
            "",
            "BOM path, mode or ownership",
        ),
    ] {
        let expanded = f.repository.root.join(case);
        native(
            "/usr/sbin/pkgutil",
            &[Path::new("--expand"), &package, &expanded],
        );
        let path = expanded.join(file);
        if case == "owner" {
            fs::remove_file(&path).unwrap();
            native("/usr/bin/mkbom", &[&f.payload, &path]);
        } else {
            let source = fs::read_to_string(&path).unwrap();
            assert_eq!(
                source.matches(before).count(),
                if case == "root-tag" { 2 } else { 1 },
                "mutation anchor/{case}"
            );
            fs::write(&path, source.replace(before, after)).unwrap();
        }
        let forged = f.repository.root.join(format!("{case}.pkg"));
        native(
            "/usr/sbin/pkgutil",
            &[Path::new("--flatten"), &expanded, &forged],
        );
        let rejected = f.verify(&forged);
        assert!(!rejected.status.success(), "admitted forged {case}");
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains(reason),
            "{case}: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
    }
}

#[test]
fn packaging_cannot_write_into_inputs_or_enable_installation_by_argument() {
    let f = Package::new();
    let output = f.payload.join("nested-output");
    let rejected = f.command().arg("--output").arg(&output).output().unwrap();
    assert!(!rejected.status.success());
    assert!(!output.exists(), "reject overlap before writing");
    let rejected = f.command().arg("--install").output().unwrap();
    assert!(!rejected.status.success());
    assert!(!f.repository.root.join("target/vpnt-packages").exists());
}

#[path = "installation/content.rs"]
mod content;
