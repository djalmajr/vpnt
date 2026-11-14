use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let directory = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "ppp-config-{}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        fs::create_dir_all(directory.parent().unwrap()).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::create_dir_all(directory.join("etc/ppp")).unwrap();
        fs::create_dir_all(directory.join("home")).unwrap();
        Self(fs::canonicalize(directory).unwrap())
    }
    fn check(&self) -> io::Result<()> {
        verify_at(&self.0.join("etc"), &self.0.join("home"), unsafe {
            libc::geteuid()
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn ambient_options_scripts_and_secrets_prevent_admission_without_reading_or_mutating_them() {
    let f = Fixture::new();
    assert!(f.check().is_ok());
    // Peers are only read by a call option, which the supervisor rejects.
    fs::create_dir(f.0.join("etc/ppp/peers")).unwrap();
    fs::write(
        f.0.join("etc/ppp/peers/foreign"),
        b"foreign profile preserved",
    )
    .unwrap();
    assert!(f.check().is_ok());
    // Independent filenames: deriving input from AMBIENT would let a missing
    // production entry silently remove that case from the fixture as well.
    for name in [
        "options",
        "postoptions",
        ".ppprc",
        ".ppp_pseudonym",
        "pap-secrets",
        "chap-secrets",
        "srp-secrets",
        "ip-up",
        "ip-down",
        "auth-up",
        "auth-down",
        "ipv6-up",
        "ipv6-down",
        "ipx-up",
        "ipx-down",
        "options.ttys999",
        "options.pts.9",
    ] {
        let path = f.0.join("etc/ppp").join(name);
        let content = b"plugin foreign\nconnect 'must never run'\n";
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
        assert_eq!(
            f.check().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&path).unwrap(), content);
        fs::remove_file(path).unwrap();
        assert!(f.check().is_ok());
    }
    for name in [".ppprc", ".ppp_pseudonym"] {
        let path = f.0.join("home").join(name);
        symlink("nonexistent", &path).unwrap();
        assert!(f.check().is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(f.check().is_err());
        fs::remove_dir(path).unwrap();
    }
    assert_eq!(
        fs::read(f.0.join("etc/ppp/peers/foreign")).unwrap(),
        b"foreign profile preserved"
    );
}
#[test]
fn untrusted_or_inaccessible_configuration_directories_fail_closed() {
    let f = Fixture::new();
    fs::set_permissions(f.0.join("etc/ppp"), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(f.check().is_err());
    fs::remove_dir(f.0.join("etc/ppp")).unwrap();
    symlink(f.0.join("home"), f.0.join("etc/ppp")).unwrap();
    assert!(f.check().is_err());
    fs::remove_file(f.0.join("etc/ppp")).unwrap();
    assert!(f.check().is_ok());
    fs::set_permissions(f.0.join("home"), fs::Permissions::from_mode(0o0)).unwrap();
    assert!(f.check().is_err());
    fs::set_permissions(f.0.join("home"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(f.check().is_ok());
    fs::rename(f.0.join("home"), f.0.join("real-home")).unwrap();
    symlink(f.0.join("real-home"), f.0.join("home")).unwrap();
    assert!(f.check().is_err());
    fs::remove_file(f.0.join("home")).unwrap();
    fs::rename(f.0.join("real-home"), f.0.join("home")).unwrap();
}
