use crate::helper::paths;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct RuntimeFixture {
    pub directory: PathBuf,
    pub uid: u32,
}
pub(super) fn macho(dependency: &str) -> Vec<u8> {
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

impl RuntimeFixture {
    pub(super) fn new() -> Self {
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
            "strongswan":{"version":"6.1.0","source":"https://download.strongswan.org/strongswan-6.1.0.tar.bz2","sha256":"fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4","backend":"kernel-libipsec","pidDirectory":paths::runtime_directory().join("run"),"patches":{"charon-private-pid.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/charon-private-pid.patch"))),"strongswan-utun-framing.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/strongswan-utun-framing.patch"))),"strongswan-libipsec-no-routes.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/strongswan-libipsec-no-routes.patch"))),"charon-parent-eof.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/charon-parent-eof.patch"))),"strongswan-retain-utun.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/strongswan-retain-utun.patch"))),"strongswan-protected-udp.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/strongswan-protected-udp.patch")))}},
            "openfortivpn":{"version":"1.24.1","source":"https://github.com/adrienverge/openfortivpn/archive/refs/tags/v1.24.1.tar.gz","sha256":"c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465","patches":{"openfortivpn-no-routes.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/openfortivpn-no-routes.patch"))),"openfortivpn-bound-transport.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/openfortivpn-bound-transport.patch"))),"openfortivpn-ppp-supervisor.patch":format!("{:x}",Sha256::digest(include_bytes!("../../../../scripts/macos/patches/openfortivpn-ppp-supervisor.patch")))}},"files":files});
        fs::write(
            self.directory.join("manifest.json"),
            serde_json::to_vec(&data).unwrap(),
        )
        .unwrap();
    }
}
impl Drop for RuntimeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
