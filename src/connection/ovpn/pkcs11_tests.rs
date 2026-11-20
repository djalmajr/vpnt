use super::*;
use crate::connection::ovpn::{session::SignError, sign_error};
use cryptoki::context::Function;

#[test]
fn pss_uses_the_digest_hash_for_mgf1_and_a_digest_sized_salt() {
    // Mutation captured: a fixed MGF1-SHA256 or a zero salt produces a
    // signature the server rejects for SHA-384 handshakes.
    let Mechanism::RsaPkcsPss(params) = mechanism(Padding::Pss(Hash::Sha384)) else {
        panic!("expected RSA-PSS");
    };
    assert_eq!(params.hash_alg, MechanismType::SHA384);
    assert_eq!(params.mgf, PkcsMgfType::MGF1_SHA384);
    assert_eq!(params.s_len, Ulong::from(48));
}

#[test]
fn pkcs1_signs_the_digest_info_with_raw_pkcs1_padding() {
    // Mutation captured: a hashing mechanism (SHA256_RSA_PKCS) would hash the
    // DigestInfo openvpn already built.
    assert!(matches!(mechanism(Padding::Pkcs1), Mechanism::RsaPkcs));
}

#[test]
fn a_canceled_approval_is_reported_as_canceled_to_the_session() {
    // Mutation captured: folding CKR_FUNCTION_CANCELED into a generic
    // failure hides from the user that the approval expired.
    let error = TokenError::from(Error::Pkcs11(RvError::FunctionCanceled, Function::Sign));
    assert_eq!(error, TokenError::Canceled);
    assert_eq!(sign_error(error), SignError::Canceled);
}

#[test]
fn a_token_that_needs_a_pin_is_reported_as_such() {
    assert_eq!(sign_error(TokenError::PinRequired), SignError::PinRequired);
    assert_eq!(
        sign_error(TokenError::Failed(RvError::DeviceError)),
        SignError::Unavailable
    );
}

#[test]
fn a_missing_module_is_a_module_error() {
    assert_eq!(
        TokenKey::open(Path::new("/nonexistent/vpnt-pkcs11.so"), &[1]).err(),
        Some(TokenError::Module)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn signing_rejects_a_permit_from_another_module_gate() {
    let fixture = super::super::private_dir::PrivateDir::create(&std::env::temp_dir()).unwrap();
    let source = fixture.path.join("fixture.c");
    let module = fixture.path.join("fixture.so");
    // Minimal PKCS#11 2.40 function list. The 12 entries before OpenSession
    // and the 55 after it are unused. Each call returns a distinct error so
    // the test can detect any call that preceded the matching-permit control.
    std::fs::write(
        &source,
        r#"
typedef unsigned long CK_ULONG;
typedef CK_ULONG (*Unused)(void);
static CK_ULONG open_session(CK_ULONG slot, CK_ULONG flags, void *context,
                             CK_ULONG (*notify)(CK_ULONG, CK_ULONG, void *),
                             CK_ULONG *session) {
    static int calls;
    return calls++ == 0 ? 0x30 : 5; /* CKR_DEVICE_ERROR, CKR_GENERAL_ERROR */
}
struct FunctionList {
    unsigned char major, minor;
    Unused before_open_session[12];
    CK_ULONG (*open_session)(CK_ULONG, CK_ULONG, void *,
                            CK_ULONG (*)(CK_ULONG, CK_ULONG, void *), CK_ULONG *);
    Unused after_open_session[55];
};
static struct FunctionList functions = { .major = 2, .minor = 40, .open_session = open_session };
CK_ULONG C_GetFunctionList(struct FunctionList **list) {
    *list = &functions;
    return 0;
}
"#,
    )
    .unwrap();
    let output = std::process::Command::new("/usr/bin/cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&module)
        .arg(source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let foreign_gate = Arc::new(RwLock::new(()));
    let key_gate = Arc::new(RwLock::new(()));
    let mut key = TokenKey {
        pkcs11: Arc::new(Pkcs11::new(&module).unwrap()),
        slot: Slot::try_from(1_u32).unwrap(),
        id: vec![1],
        session: None,
        gate: Arc::clone(&key_gate),
    };
    assert_eq!(
        key.sign_with_session(Padding::Pkcs1, &[], TokenKey::signing_guard(&foreign_gate)),
        Err(TokenError::Module)
    );
    assert_eq!(
        key.sign_with_session(Padding::Pkcs1, &[], TokenKey::signing_guard(&key_gate)),
        Err(TokenError::Failed(RvError::DeviceError))
    );
    assert_eq!(
        key.sign(Padding::Pkcs1, &[]),
        Err(TokenError::Failed(RvError::GeneralError))
    );
}

#[test]
fn listing_a_missing_module_is_a_module_error() {
    assert_eq!(
        list_certificates(Path::new("/nonexistent/vpnt-pkcs11.so")),
        Err(TokenError::Module)
    );
}

#[test]
fn certificate_debug_renders_id_as_lowercase_hex() {
    let info = CertificateInfo {
        id: vec![0, 0xa7, 0xff],
        subject: Some("Synthetic".into()),
        issuer: None,
        not_before: None,
        not_after: None,
    };
    assert!(format!("{info:?}").contains("id: \"00a7ff\""));
}

#[test]
fn admission_rejects_untrusted_file_and_ancestors_and_resolves_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = super::super::private_dir::PrivateDir::create(&std::env::temp_dir()).unwrap();
    let nested = dir.path.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
    let module = nested.join("fixture.so");
    std::fs::write(&module, b"not a library").unwrap();
    std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = unsafe { libc::geteuid() };
    let trusted = [0, uid];
    for invalid in ["relative.so", "/tmp/../module.so", "/tmp/module.dll"] {
        assert_eq!(
            admit_module_with(invalid, &trusted, &dir.path, None),
            Err(TokenError::UntrustedModule)
        );
    }
    let check = |path: &Path, owners: &[u32]| {
        admit_module_with(path.to_str().unwrap(), owners, &dir.path, None)
    };
    assert_eq!(
        check(&module, &trusted).unwrap(),
        std::fs::canonicalize(&module).unwrap()
    );
    assert_eq!(check(&module, &[]), Err(TokenError::UntrustedModule));
    std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(check(&module, &trusted), Err(TokenError::UntrustedModule));
    let alias = dir.path.join("alias.so");
    symlink(&module, &alias).unwrap();
    assert_eq!(check(&alias, &trusted), Err(TokenError::UntrustedModule));
    std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        check(&alias, &trusted).unwrap(),
        std::fs::canonicalize(&module).unwrap()
    );
    let loaded = with_admitted_module(
        &alias,
        |path| admit_module_with(path, &trusted, &dir.path, None),
        |path| Ok(path.to_path_buf()),
    )
    .unwrap();
    assert_eq!(loaded, std::fs::canonicalize(&module).unwrap());
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(check(&module, &trusted), Err(TokenError::UntrustedModule));
    assert_eq!(check(&alias, &trusted), Err(TokenError::UntrustedModule));
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o1777)).unwrap();
    assert_eq!(check(&alias, &trusted), Err(TokenError::UntrustedModule));
}

#[cfg(target_os = "macos")]
struct ApplicationBundle {
    applications: PathBuf,
    bundle: PathBuf,
    module: PathBuf,
    gid: u32,
    uid: u32,
}

#[cfg(target_os = "macos")]
impl ApplicationBundle {
    /// The tolerated directory as the production rule names it in the fixture:
    /// canonical path, the gid it must carry and the uid it must carry.
    fn tolerated(&self) -> Option<(&Path, u32, u32)> {
        Some((self.applications.as_path(), self.gid, self.uid))
    }
}

/// An app bundle shaped like an installed one: the tolerated directory carries
/// `0775` with the inspecting user's group, as `/Applications` carries
/// `root:admin 0775`, and everything below it is `0755` with a `0644` module.
#[cfg(target_os = "macos")]
fn application_bundle(root: &Path, directory: &str) -> ApplicationBundle {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let applications = root.join(directory);
    let bundle = applications.join("Example.app");
    let contents = bundle.join("Contents");
    let binaries = contents.join("MacOS");
    std::fs::create_dir_all(&binaries).unwrap();
    for path in [&applications, &bundle, &contents, &binaries] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::set_permissions(&applications, std::fs::Permissions::from_mode(0o775)).unwrap();
    let module = binaries.join("libexample.so");
    std::fs::write(&module, b"not a library").unwrap();
    std::fs::set_permissions(&module, std::fs::Permissions::from_mode(0o644)).unwrap();
    let gid = std::fs::metadata(&applications).unwrap().gid();
    let uid = std::fs::metadata(&applications).unwrap().uid();
    ApplicationBundle {
        applications,
        bundle,
        module,
        gid,
        uid,
    }
}

#[cfg(target_os = "macos")]
fn temporary_root() -> super::super::private_dir::PrivateDir {
    super::super::private_dir::PrivateDir::create(&std::env::temp_dir()).unwrap()
}

#[cfg(target_os = "macos")]
fn admission(
    path: &Path,
    owners: &[u32],
    tolerated: Option<(&Path, u32, u32)>,
    stop: &Path,
) -> Result<PathBuf, TokenError> {
    admit_module_with(
        path.to_str().unwrap(),
        owners,
        stop,
        tolerated.map(|(tolerated, gid, uid)| (tolerated.to_str().unwrap(), gid, uid)),
    )
}

#[cfg(target_os = "macos")]
fn trusted_owners() -> [u32; 2] {
    [0, unsafe { libc::geteuid() }]
}

#[cfg(target_os = "macos")]
#[test]
fn an_app_bundle_inside_the_tolerated_directory_is_admitted() {
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let owners = trusted_owners();
    let tolerated = app.tolerated();
    assert_eq!(
        admission(&app.module, &owners, tolerated, &root.path).unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    // The same chain, with the same group write, is refused without the exception.
    assert_eq!(
        admission(&app.module, &owners, None, &root.path),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_tolerated_directory_writable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let owners = trusted_owners();
    let tolerated = app.tolerated();
    std::fs::set_permissions(&app.applications, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        admission(&app.module, &owners, tolerated, &root.path),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_tolerated_directory_with_another_group_is_refused() {
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let owners = trusted_owners();
    let other_gid = app.gid.wrapping_add(1);
    assert_eq!(
        admission(
            &app.module,
            &owners,
            Some((app.applications.as_path(), other_gid, app.uid)),
            &root.path
        ),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_tolerated_directory_owned_by_another_uid_is_refused() {
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let owners = trusted_owners();
    assert_eq!(
        admission(&app.module, &owners, app.tolerated(), &root.path).unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    // The fixture's owner stays in `owners` and the group is right, so only the
    // uid the exception expects changes: the refusal comes from that comparison.
    let other_uid = app.uid.wrapping_add(1);
    assert_eq!(
        admission(
            &app.module,
            &owners,
            Some((app.applications.as_path(), app.gid, other_uid)),
            &root.path
        ),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_group_writable_directory_that_is_not_the_tolerated_one_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let elsewhere = application_bundle(&root.path, "Elsewhere");
    let owners = trusted_owners();
    let tolerated = app.tolerated();
    // The bundle below the tolerated directory is not tolerated itself.
    std::fs::set_permissions(&app.bundle, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        admission(&app.module, &owners, tolerated, &root.path),
        Err(TokenError::UntrustedModule)
    );
    std::fs::set_permissions(&app.bundle, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        admission(&app.module, &owners, tolerated, &root.path).unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    // Neither is a directory that only looks like the tolerated one.
    assert_eq!(
        admission(&elsewhere.module, &owners, tolerated, &root.path),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_group_writable_module_inside_the_tolerated_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let owners = trusted_owners();
    let tolerated = app.tolerated();
    assert_eq!(
        admission(&app.module, &owners, tolerated, &root.path).unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    std::fs::set_permissions(&app.module, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(
        admission(&app.module, &owners, tolerated, &root.path),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_tolerated_directory_owned_outside_the_allowed_users_is_refused() {
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let stranger = unsafe { libc::geteuid() }.wrapping_add(1);
    assert_eq!(
        admission(&app.module, &[stranger], app.tolerated(), &root.path),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_link_inside_the_bundle_that_leaves_the_root_is_refused() {
    use std::os::unix::fs::symlink;
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let owners = trusted_owners();
    let tolerated = app.tolerated();
    let outside = temporary_root();
    let target = outside.path.join("liboutside.so");
    std::fs::write(&target, b"not a library").unwrap();
    let escaping = app.module.parent().unwrap().join("libescaping.so");
    symlink(&target, &escaping).unwrap();
    assert_eq!(
        admission(&escaping, &owners, tolerated, &root.path),
        Err(TokenError::UntrustedModule)
    );
    let inside = app.module.parent().unwrap().join("libinside.so");
    symlink(&app.module, &inside).unwrap();
    assert_eq!(
        admission(&inside, &owners, tolerated, &root.path).unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_tolerated_directory_matches_its_canonical_path_exactly() {
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let dotted = application_bundle(&root.path, "Applications.x");
    let owners = trusted_owners();
    // A trailing slash canonicalizes away, so it names the same directory.
    let slash = PathBuf::from(format!("{}/", app.applications.display()));
    assert_eq!(
        admission(
            &app.module,
            &owners,
            Some((slash.as_path(), app.gid, app.uid)),
            &root.path
        )
        .unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    // `Applications.x` is another directory and keeps the strict rule.
    assert_eq!(
        admission(&dotted.module, &owners, app.tolerated(), &root.path),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_tolerated_directory_is_compared_after_resolving_an_alias() {
    use std::os::unix::fs::symlink;
    let root = temporary_root();
    let app = application_bundle(&root.path, "Applications");
    let elsewhere = application_bundle(&root.path, "Elsewhere");
    let owners = trusted_owners();
    // The tolerated path may be an alias: canonicalizing it resolves the link
    // to the directory the chain actually reaches.
    let alias = root.path.join("applications-alias");
    symlink(&app.applications, &alias).unwrap();
    assert_eq!(
        admission(
            &app.module,
            &owners,
            Some((alias.as_path(), app.gid, app.uid)),
            &root.path
        )
        .unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    // The comparison uses the resolved target, not the alias name: an alias
    // that resolves to another directory does not tolerate this one.
    let other = root.path.join("elsewhere-alias");
    symlink(&elsewhere.applications, &other).unwrap();
    assert_eq!(
        admission(
            &app.module,
            &owners,
            Some((other.as_path(), elsewhere.gid, elsewhere.uid)),
            &root.path
        ),
        Err(TokenError::UntrustedModule)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_installed_applications_directory_is_accepted_with_the_production_defaults() {
    use std::os::unix::fs::MetadataExt;
    // The production values are pinned here, independently of the rule that
    // reads them, so a constant moved to another directory cannot pass.
    assert_eq!(GROUP_WRITABLE, Some(("/Applications", 80, 0)));
    let Some((path, gid, uid)) = GROUP_WRITABLE else {
        panic!("macOS must tolerate `/Applications` as the one directory");
    };
    let applications = std::fs::canonicalize(path)
        .unwrap_or_else(|error| panic!("{path} must exist on macOS: {error}"));
    assert_eq!(
        applications,
        Path::new(path),
        "{path} must be its own canonical path"
    );
    // The metadata is asserted first so a host that deviates says which field
    // it deviates in, instead of only reporting the rule's `false`.
    let metadata =
        std::fs::metadata(&applications).unwrap_or_else(|error| panic!("{path} metadata: {error}"));
    assert!(metadata.is_dir(), "{path} must be a directory");
    assert_eq!(
        metadata.uid(),
        uid,
        "{path} must be owned by uid {uid}, got uid {}",
        metadata.uid()
    );
    assert_eq!(
        metadata.gid(),
        gid,
        "{path} must carry gid {gid}, got gid {}",
        metadata.gid()
    );
    assert_eq!(
        metadata.mode() & 0o022,
        0o020,
        "{path} must be writable by its group alone, mode {:o}",
        metadata.mode() & 0o7777
    );
    // The same predicate the ancestor walk applies, with the production
    // defaults, must accept the real directory on every host.
    assert!(
        tolerates_group_write(
            &applications,
            &metadata,
            Some((applications.as_path(), gid, uid))
        ),
        "{path} must be tolerated with the production defaults: uid {uid}, gid {gid}, no write for others"
    );
}

#[test]
fn root_owned_system_module_path_is_admitted_when_available() {
    use std::os::unix::fs::MetadataExt;
    let candidate = std::fs::read_dir("/usr/lib").ok().and_then(|entries| {
        entries.flatten().map(|e| e.path()).find(|p| {
            p.extension().is_some_and(|e| e == "so")
                && std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
        })
    });
    let Some(candidate) = candidate else {
        eprintln!("no root-owned .so found directly in /usr/lib; skipped");
        return;
    };
    let path = candidate.to_str().unwrap();
    assert_eq!(
        admit_module_with(path, &[0, unsafe { libc::geteuid() }], Path::new("/"), None).unwrap(),
        std::fs::canonicalize(path).unwrap()
    );
}
