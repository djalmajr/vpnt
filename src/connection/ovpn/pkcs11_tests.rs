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
