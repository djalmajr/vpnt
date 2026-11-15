//! Ordinary private files only; no installed runtime, process or VPN effects.
use super::*;
use std::{
    fs::{DirBuilder, FileTimes},
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(Runtime);
impl Fixture {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            ".vpnt-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        fs::create_dir(directory.join("bin")).unwrap();
        fs::create_dir(directory.join("certs")).unwrap();
        // Minimal native Mach-O headers, never executed.
        let mut binary = vec![0; 32];
        binary[0..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        let cpu: u32 = if cfg!(target_arch = "aarch64") {
            0x0100_000c
        } else {
            0x0100_0007
        };
        binary[4..8].copy_from_slice(&cpu.to_le_bytes());
        binary[12..16].copy_from_slice(&2_u32.to_le_bytes());
        let mut files = BTreeMap::new();
        for (name, bytes, mode) in [
            ("bin/charon", binary.as_slice(), 0o500),
            ("bin/openfortivpn", binary.as_slice(), 0o500),
            (
                "certs/ca-bundle.pem",
                b"fixture certificate".as_slice(),
                0o400,
            ),
        ] {
            fs::write(directory.join(name), bytes).unwrap();
            fs::set_permissions(directory.join(name), fs::Permissions::from_mode(mode)).unwrap();
            files.insert(name.to_owned(), format!("{:x}", Sha256::digest(bytes)));
        }
        // Only content verification is under test here; manifest admission is
        // exercised by the existing producer fixtures using Runtime::inspect.
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            "format":1,"appVersion":env!("CARGO_PKG_VERSION"),"prefix":"fixture",
            "minimumMacOS":"13.0",
            "strongswan":{"version":"6.1.0","source":"fixture","sha256":"fixture",
                "backend":"kernel-libipsec","pidDirectory":"fixture","patches":{}},
            "openfortivpn":{"version":"1.24.1","source":"fixture","sha256":"fixture","patches":{}},
            "files":files
        }))
        .unwrap();
        fs::write(directory.join("manifest.json"), b"fixture").unwrap();
        fs::set_permissions(
            directory.join("manifest.json"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        // SAFETY: UID query has no memory preconditions.
        let owner = unsafe { libc::geteuid() };
        Self(Runtime {
            directory,
            owner,
            manifest,
            verified: Mutex::new(None),
            hash_passes: AtomicUsize::new(0),
        })
    }
    fn passes(&self) -> usize {
        self.0.hash_passes.load(Ordering::Relaxed)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0.directory).unwrap();
    }
}

#[test]
fn unchanged_runtime_reuses_hashes_but_explicit_verify_still_hashes() {
    let fixture = Fixture::new();
    for _ in 0..10 {
        fixture.0.verify_unchanged().unwrap();
    }
    assert_eq!(fixture.passes(), 1);
    fixture.0.verify().unwrap();
    assert_eq!(fixture.passes(), 2);
    let path = fixture.0.directory.join("certs/ca-bundle.pem");
    let bytes = fs::read(&path).unwrap();
    let replacement = fixture.0.directory.join("replacement");
    fs::write(&replacement, bytes).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
    fs::rename(&replacement, &path).unwrap();
    fixture.0.verify_unchanged().unwrap();
    assert_eq!(
        fixture.passes(),
        3,
        "replacement requires fresh content verification"
    );
}

#[test]
fn same_length_tampering_with_restored_mtime_is_not_cached() {
    let fixture = Fixture::new();
    fixture.0.verify_unchanged().unwrap();
    let path = fixture.0.directory.join("certs/ca-bundle.pem");
    let original = fs::metadata(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    fs::write(&path, vec![b'X'; original.len() as usize]).unwrap();
    file.set_times(FileTimes::new().set_modified(original.modified().unwrap()))
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    for _ in 0..2 {
        assert_eq!(fixture.0.verify_unchanged(), Err(RuntimeError::Integrity));
    }
    assert_eq!(
        fixture.passes(),
        3,
        "failed verification must not warm the cache"
    );
}

#[test]
fn cached_runtime_still_rejects_permissions_inventory_symlinks_and_missing_files() {
    for change in ["permissions", "inventory", "symlink", "missing"] {
        let fixture = Fixture::new();
        fixture.0.verify_unchanged().unwrap();
        let path = fixture.0.directory.join("certs/ca-bundle.pem");
        match change {
            "permissions" => fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap(),
            "inventory" => fs::write(fixture.0.directory.join("extra"), b"unknown").unwrap(),
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink("../bin/charon", &path).unwrap();
            }
            "missing" => fs::remove_file(&path).unwrap(),
            _ => unreachable!(),
        }
        assert!(fixture.0.verify_unchanged().is_err(), "{change}");
    }
}
