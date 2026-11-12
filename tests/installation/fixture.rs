use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
#[path = "../../src/install/payload/tests/runtime.rs"]
mod runtime;

pub(crate) struct Repository {
    pub root: PathBuf,
    runtime: runtime::RuntimeFixture,
}
impl Repository {
    pub fn new() -> Self {
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
        // Fictional roles contain real native Mach-O headers. Only inspect/policy
        // on the copied inspector and package tools are executed, never VPNs.
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
        Self { root, runtime }
    }
    pub fn uid(&self) -> u32 {
        self.runtime.uid
    }
    pub fn run(&self) -> std::process::Output {
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
