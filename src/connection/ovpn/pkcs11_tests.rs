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
            admit_module_with(invalid, &trusted, &dir.path),
            Err(TokenError::UntrustedModule)
        );
    }
    let check =
        |path: &Path, owners: &[u32]| admit_module_with(path.to_str().unwrap(), owners, &dir.path);
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
        |path| admit_module_with(path, &trusted, &dir.path),
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
        admit_module_with(path, &[0, unsafe { libc::geteuid() }], Path::new("/")).unwrap(),
        std::fs::canonicalize(path).unwrap()
    );
}
