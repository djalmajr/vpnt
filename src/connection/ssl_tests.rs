use super::*;
use crate::secrets::Secret;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Instant,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    runtime: Runtime,
}
impl Fixture {
    fn binding() -> Binding {
        let name = std::ffi::CString::new("lo0").unwrap();
        // SAFETY: name is a live native NUL-terminated interface name.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        Binding {
            interface: "lo0".into(),
            index,
            gateway: Ipv4Addr::LOCALHOST,
        }
    }
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let directory = root.join("output/fixtures").join(format!(
            "ssl-driver-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(directory.join("bin")).unwrap();
        fs::create_dir(directory.join("certs")).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let program = directory.join("bin/openfortivpn");
        let result = Command::new("/usr/bin/cc")
            .args([
                "-mmacosx-version-min=13.0",
                &format!(
                    "-DRUNTIME_PREFIX=\"{}\"",
                    paths::runtime_directory().display()
                ),
            ])
            .arg(root.join("tests/fixtures/ssl_client.c"))
            .arg("-o")
            .arg(&program)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "native process fixture must compile"
        );
        fs::copy(&program, directory.join("bin/charon")).unwrap();
        fs::write(directory.join("certs/ca-bundle.pem"), b"fixture public CA").unwrap();
        let mut files = serde_json::Map::new();
        for name in ["bin/charon", "bin/openfortivpn", "certs/ca-bundle.pem"] {
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o555)).unwrap();
            files.insert(
                name.into(),
                format!(
                    "{:x}",
                    Sha256::digest(fs::read(directory.join(name)).unwrap())
                )
                .into(),
            );
        }
        let manifest = serde_json::json!({"format":1,"appVersion":env!("CARGO_PKG_VERSION"),"prefix":paths::runtime_directory(),"minimumMacOS":"13.0",
            "strongswan":{"version":"6.1.0","source":"fixture","sha256":"fixture","backend":"kernel-libipsec","pidDirectory":paths::runtime_directory().join("run"),"patches":{"charon-private-pid.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/charon-private-pid.patch"))),"strongswan-utun-framing.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/strongswan-utun-framing.patch"))),"strongswan-libipsec-no-routes.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/strongswan-libipsec-no-routes.patch"))),"charon-parent-eof.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/charon-parent-eof.patch"))),"strongswan-retain-utun.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/strongswan-retain-utun.patch"))),"strongswan-protected-udp.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/strongswan-protected-udp.patch")))}},
            "openfortivpn":{"version":"1.24.1","source":"fixture","sha256":"c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465","patches":{"openfortivpn-no-routes.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/openfortivpn-no-routes.patch"))),"openfortivpn-bound-transport.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/openfortivpn-bound-transport.patch"))),"openfortivpn-ppp-supervisor.patch":format!("{:x}",Sha256::digest(include_bytes!("../../scripts/macos/patches/openfortivpn-ppp-supervisor.patch")))}},"files":files});
        fs::write(
            directory.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let owner = fs::metadata(&directory).unwrap().uid();
        let runtime = Runtime::inspect(&directory, owner).unwrap();
        Self { directory, runtime }
    }
    fn profile(gateway: &str) -> Profile {
        serde_json::from_value(serde_json::json!({"id":"fixture","name":"Fixture","kind":"ssl","gateway":gateway,"username":"fixture-user","port":443,"networks":[],"certificate":"","probeHost":"127.0.0.1","probePort":8443,"probeMethod":"tcp"})).unwrap()
    }
    fn start(&self, gateway: &str) -> SslDriver {
        SslDriver::start_using(
            &self.runtime,
            &Self::profile(gateway),
            Credentials {
                password: Secret::from("fixture-driver-password"),
                psk: Secret::from(""),
            },
            &Self::binding(),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn real_process_consumes_only_fixed_arguments_and_private_secret_channel() {
    let fixture = Fixture::new();
    let mut driver = fixture.start("ready.fixture.invalid");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let update = driver.poll().unwrap();
        assert!(!format!("{update:?}").contains("fixture-driver-password"));
        if let Some(candidate) = update.candidate {
            assert_eq!(candidate.as_str(), "ppp123");
            assert!(!update.exited);
            break;
        }
        assert!(
            !update.exited,
            "fixture must accept the driver's argv/environment/channel"
        );
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    let stopped = driver.stop().unwrap();
    assert!(!stopped.escalated);
    assert!(driver.poll().unwrap().exited);
}

#[test]
fn authentication_and_timeout_messages_survive_process_exit_without_raw_output() {
    let fixture = Fixture::new();
    for (gateway, reason) in [
        ("auth.fixture.invalid", SslFailure::CredentialsRejected),
        ("timeout.fixture.invalid", SslFailure::GatewayTimeout),
    ] {
        let mut driver = fixture.start(gateway);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let update = driver.poll().unwrap();
            assert!(update.candidate.is_none());
            assert!(!format!("{update:?}").contains("fixture-driver-password"));
            if update.exited {
                assert_eq!(update.failure, Some(reason));
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn profile_options_and_fingerprints_cannot_add_commands_or_paths() {
    let fixture = Fixture::new();
    let mut profile = Fixture::profile("ready.fixture.invalid");
    profile.certificate = "A1".repeat(32);
    let configured = command(&fixture.runtime, &profile, &Fixture::binding()).unwrap();
    assert!(
        configured
            .get_args()
            .any(|argument| argument == format!("--trusted-cert={}", "a1".repeat(32)).as_str())
    );
    for username in [
        "".into(),
        "a".repeat(65),
        "user\n--pppd-plugin=/tmp/file".into(),
    ] {
        profile.username = username;
        assert!(command(&fixture.runtime, &profile, &Fixture::binding()).is_err());
    }
    profile.username = "fixture-user".into();
    profile.gateway = "::1".into();
    assert!(command(&fixture.runtime, &profile, &Fixture::binding()).is_err());
}
