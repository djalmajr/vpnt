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
    ApplicationBundle {
        applications,
        bundle,
        module,
        gid,
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
    tolerated: Option<(&Path, u32)>,
    stop: &Path,
) -> Result<PathBuf, TokenError> {
    admit_module_with(
        path.to_str().unwrap(),
        owners,
        stop,
        tolerated.map(|(tolerated, gid)| (tolerated.to_str().unwrap(), gid)),
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
    let tolerated = Some((app.applications.as_path(), app.gid));
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
    let tolerated = Some((app.applications.as_path(), app.gid));
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
            Some((app.applications.as_path(), other_gid)),
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
    let tolerated = Some((app.applications.as_path(), app.gid));
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
    let tolerated = Some((app.applications.as_path(), app.gid));
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
        admission(
            &app.module,
            &[stranger],
            Some((app.applications.as_path(), app.gid)),
            &root.path
        ),
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
    let tolerated = Some((app.applications.as_path(), app.gid));
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
            Some((slash.as_path(), app.gid)),
            &root.path
        )
        .unwrap(),
        std::fs::canonicalize(&app.module).unwrap()
    );
    // `Applications.x` is another directory and keeps the strict rule.
    assert_eq!(
        admission(
            &dotted.module,
            &owners,
            Some((app.applications.as_path(), app.gid)),
            &root.path
        ),
        Err(TokenError::UntrustedModule)
    );
}

/// A real module installed in an app bundle, when this machine has one: the
/// chain below `/Applications` already meets the strict rule, so admission can
/// only succeed through the `/Applications` exception.
#[cfg(target_os = "macos")]
fn an_installed_module(owners: &[u32]) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let strict = |path: &Path| {
        std::fs::metadata(path).is_ok_and(|metadata| {
            metadata.is_dir() && owners.contains(&metadata.uid()) && metadata.mode() & 0o022 == 0
        })
    };
    std::fs::read_dir("/Applications")
        .ok()?
        .flatten()
        .find_map(|app| {
            let contents = app.path().join("Contents");
            if !strict(&app.path()) || !strict(&contents) {
                return None;
            }
            ["MacOS", "Frameworks"].iter().find_map(|name| {
                let directory = contents.join(name);
                if !strict(&directory) {
                    return None;
                }
                std::fs::read_dir(directory)
                    .ok()?
                    .flatten()
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.extension().is_some_and(|extension| extension == "so")
                            && std::fs::metadata(path).is_ok_and(|metadata| {
                                metadata.is_file()
                                    && owners.contains(&metadata.uid())
                                    && metadata.mode() & 0o022 == 0
                            })
                    })
            })
        })
}

#[cfg(target_os = "macos")]
#[test]
fn the_installed_applications_directory_is_accepted_with_the_production_defaults() {
    use std::os::unix::fs::MetadataExt;
    assert_eq!(GROUP_WRITABLE, Some(("/Applications", 80)));
    let applications =
        std::fs::metadata("/Applications").expect("/Applications must exist on macOS");
    assert!(applications.is_dir(), "/Applications must be a directory");
    assert_eq!(
        applications.uid(),
        0,
        "/Applications must be owned by root (uid 0), got uid {}",
        applications.uid()
    );
    assert_eq!(
        applications.gid(),
        80,
        "/Applications must carry the admin group (gid 80), got gid {}",
        applications.gid()
    );
    assert_eq!(
        applications.mode() & 0o022,
        0o020,
        "/Applications must be writable by its group alone, mode {:o}",
        applications.mode() & 0o7777
    );
    assert_eq!(
        std::fs::canonicalize("/Applications").unwrap(),
        Path::new("/Applications")
    );
    if let Some(module) = an_installed_module(&trusted_owners()) {
        assert_eq!(
            admit_module(module.to_str().unwrap()).unwrap(),
            std::fs::canonicalize(&module).unwrap(),
            "a module installed in an app bundle must be admitted"
        );
    }
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
