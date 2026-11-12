#![cfg(target_os = "macos")]
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
mod helper {
    pub use vpnt::helper::paths;
}
#[path = "installation/fixture.rs"]
mod fixture;
use fixture::Repository;

struct App {
    repository: Repository,
    payload: PathBuf,
    bundle: PathBuf,
}
impl App {
    fn new() -> Self {
        let repository = Repository::new();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"));
        for name in [
            "package-installation.py",
            "installation_package.py",
            "package-app.py",
            "app_component.py",
        ] {
            fs::copy(
                source.join("scripts/macos").join(name),
                repository.root.join("scripts/macos").join(name),
            )
            .unwrap();
        }
        fs::copy(source.join("LICENSE"), repository.root.join("LICENSE")).unwrap();
        fs::copy(
            env!("CARGO_BIN_EXE_vpnt"),
            repository.root.join("target/debug/vpnt"),
        )
        .unwrap();
        let prepared = repository.run();
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&prepared.stdout).unwrap();
        assert_eq!(result["uid"], repository.uid());
        let bundle = repository.root.join("packaged/vpnt.app");
        Self {
            repository,
            payload: PathBuf::from(result["payload"].as_str().unwrap()),
            bundle,
        }
    }
    fn package(&self, component: bool) -> Output {
        let mut command = Command::new("python3");
        command
            .arg(self.repository.root.join("scripts/macos/package-app.py"))
            .arg("--binary")
            .arg(self.repository.root.join("target/debug/vpnt"))
            .arg("--output")
            .arg(&self.bundle)
            .arg("--replace");
        if component {
            command.arg("--component-payload").arg(&self.payload);
        }
        command.output().unwrap()
    }
    fn inspect(&self) -> Output {
        Command::new(self.bundle.join("Contents/MacOS/vpnt"))
            .arg("--inspect-component")
            .env("SUDO_UID", "0")
            .env("VPNT_COMPONENT_PACKAGE", "/tmp/unrelated.pkg")
            .output()
            .unwrap()
    }
}
fn accepted(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn native_packaged_host_admits_only_its_audited_component_and_preserves_the_app_on_failed_replacement()
 {
    let f = App::new();
    let built = f.package(true);
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let metadata = accepted(f.inspect());
    let resources = f.bundle.join("Contents/Resources/Component");
    let meta_path = resources.join("component.json");
    let meta_bytes = fs::read(&meta_path).unwrap();
    assert_eq!(
        metadata,
        serde_json::from_slice::<serde_json::Value>(&meta_bytes).unwrap()
    );
    assert_eq!(metadata["uid"], f.repository.uid());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(f.payload.join("payload.json")).unwrap()).unwrap();
    assert_eq!(
        metadata["helperSha256"],
        manifest["files"]["adapters/helper"]
    );
    assert_eq!(
        metadata["installerSha256"],
        manifest["files"]["adapters/installer"]
    );
    assert_eq!(
        metadata["askpassSha256"],
        manifest["files"]["adapters/askpass"]
    );
    let plist = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :LSMinimumSystemVersion"])
        .arg(f.bundle.join("Contents/Info.plist"))
        .output()
        .unwrap();
    assert!(plist.status.success());
    assert_eq!(
        String::from_utf8(plist.stdout).unwrap().trim(),
        metadata["minimumMacOS"].as_str().unwrap()
    );
    let package = resources.join("component.pkg");
    let original = fs::read(&package).unwrap();
    fs::set_permissions(&package, fs::Permissions::from_mode(0o644)).unwrap();
    fs::write(&package, b"changed bundle package").unwrap();
    let rejected = f.inspect();
    assert!(!rejected.status.success() && rejected.stdout.is_empty());
    assert_eq!(rejected.stderr, b"\"integrity\"\n");
    fs::write(&package, &original).unwrap();
    fs::set_permissions(&package, fs::Permissions::from_mode(0o444)).unwrap();
    assert_eq!(accepted(f.inspect()), metadata);
    let source = f
        .repository
        .root
        .join("target/vpnt-packages")
        .join(metadata["build"].as_str().unwrap())
        .join(format!(
            "vpnt-component-{}-{}.pkg",
            env!("CARGO_PKG_VERSION"),
            f.repository.uid()
        ));
    fs::write(source, b"corrupted source package").unwrap();
    let replacement = f.package(true);
    assert!(
        !replacement.status.success(),
        "unadmitted input cannot replace an existing app"
    );
    assert_eq!(fs::read(meta_path).unwrap(), meta_bytes);
    assert_eq!(fs::read(package).unwrap(), original);
    assert_eq!(accepted(f.inspect()), metadata);
}

#[test]
fn headless_inspection_cannot_pick_a_component_from_arguments_environment_or_the_working_directory()
{
    let f = App::new();
    let built = f.package(false);
    assert!(built.status.success());
    let missing = f.inspect();
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty());
    let extra = Command::new(f.bundle.join("Contents/MacOS/vpnt"))
        .args(["--inspect-component", "/tmp/component.pkg"])
        .output()
        .unwrap();
    assert_eq!(extra.status.code(), Some(2));
    let bare = Command::new(f.repository.root.join("target/debug/vpnt"))
        .arg("--inspect-component")
        .current_dir(&f.payload)
        .env("VPNT_COMPONENT_PACKAGE", &f.payload)
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(1));
    assert!(bare.stdout.is_empty());
}
