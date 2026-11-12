use super::*;
use crate::helper::{paths, runtime::Runtime};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Fixture {
    pub directory: PathBuf,
    pub controller: ControllerLock,
    root: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // Copies used by mutation runners stay below the original project.
        // Keep the fixture's protected UDS path below Darwin's 104-byte limit.
        let root = manifest
            .ancestors()
            .find(|p| p.join(".git").exists())
            .unwrap_or(&manifest)
            .to_owned();
        let directory = root.join(format!(
            ".vpnt-{:x} {:x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::write(directory.join(".controller.lock"), b"").unwrap();
        fs::set_permissions(
            directory.join(".controller.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let controller = ControllerLock::fixture(&directory, uid).unwrap();
        let fixture = Self {
            directory,
            controller,
            root: manifest,
        };
        fixture.runtime();
        fixture
    }
    fn runtime(&self) {
        let path = self.directory.join("r");
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("bin")).unwrap();
        fs::create_dir(path.join("certs")).unwrap();
        let result = Command::new("/usr/bin/cc")
            .arg("-mmacosx-version-min=13.0")
            .arg(format!(
                "-DRUNTIME_PREFIX=\"{}\"",
                paths::runtime_directory().display()
            ))
            .arg(self.root.join("tests/fixtures/ipsec_producer.c"))
            .arg("-o")
            .arg(path.join("bin/charon"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "fixture compile: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::copy(path.join("bin/charon"), path.join("bin/openfortivpn")).unwrap();
        fs::write(path.join("certs/ca-bundle.pem"), b"fictional public CA").unwrap();
        let mut files = serde_json::Map::new();
        for name in ["bin/charon", "bin/openfortivpn", "certs/ca-bundle.pem"] {
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o555)).unwrap();
            files.insert(
                name.into(),
                format!("{:x}", Sha256::digest(fs::read(path.join(name)).unwrap())).into(),
            );
        }
        let hashes = |names: &[&str]| {
            names
                .iter()
                .map(|name| {
                    (
                        (*name).to_string(),
                        format!(
                            "{:x}",
                            Sha256::digest(
                                fs::read(self.root.join("scripts/macos/patches").join(name))
                                    .unwrap()
                            )
                        ),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let data = serde_json::json!({"format":1,"appVersion":env!("CARGO_PKG_VERSION"),"prefix":paths::runtime_directory(),"minimumMacOS":"13.0",
            "strongswan":{"version":"6.1.0","source":"fixture","sha256":"fixture","pidDirectory":paths::runtime_directory().join("run"),"patches":hashes(&["charon-private-pid.patch"])},
            "openfortivpn":{"version":"1.24.1","source":"fixture","sha256":"c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465","patches":hashes(&["openfortivpn-no-routes.patch","openfortivpn-bound-transport.patch","openfortivpn-ppp-supervisor.patch"])},"files":files});
        fs::write(
            path.join("manifest.json"),
            serde_json::to_vec(&data).unwrap(),
        )
        .unwrap();
    }
    pub fn context(&self) -> Arc<NativeContext<'_>> {
        // SAFETY: UID query has no memory preconditions.
        NativeContext::using(
            &self.controller,
            Runtime::inspect(self.directory.join("r"), unsafe { libc::geteuid() }).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
