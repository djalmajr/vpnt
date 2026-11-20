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

#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn sign_until_leaves_the_provider_untouched_when_canceled_behind_the_gate() {
    use std::sync::mpsc;

    let gate = Arc::new(RwLock::new(()));
    let canceled = AtomicBool::new(false);
    let (waiting, wait) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let (finished, finish) = mpsc::channel();
    let budget = Duration::from_secs(5);
    let held = gate.write().unwrap();
    thread::scope(|scope| {
        let gate = &gate;
        let canceled = &canceled;
        scope.spawn(move || {
            let mut signs = 0;
            let mut observed_writer = false;
            let result = signing_gate::sign_until(
                canceled,
                Instant::now() + budget,
                || {
                    if observed_writer {
                        waiting.send(()).unwrap();
                        resumed.recv_timeout(budget).unwrap();
                        Some(signing_gate::try_acquire(gate).expect("the writer released the gate"))
                    } else {
                        assert!(signing_gate::try_acquire(gate).is_none());
                        observed_writer = true;
                        None
                    }
                },
                |_| {
                    signs += 1;
                    Ok(vec![1])
                },
            );
            finished.send((result, signs)).unwrap();
        });
        wait.recv_timeout(budget).unwrap();
        canceled.store(true, Ordering::Release);
        drop(held);
        resume.send(()).unwrap();
        assert_eq!(finish.recv_timeout(budget).unwrap(), (Ok(None), 0));
        assert!(
            gate.try_write().is_ok(),
            "the canceled wait must release its permit"
        );
    });
}

#[cfg(unix)]
#[test]
fn sign_until_leaves_the_provider_untouched_when_the_gate_wait_expires() {
    let gate = Arc::new(RwLock::new(()));
    let held = gate.write().unwrap();
    let canceled = AtomicBool::new(false);
    let mut blocked = false;
    let mut signs = 0;
    let expires = Instant::now() + Duration::from_millis(200);
    let result = signing_gate::sign_until(
        &canceled,
        expires,
        || {
            let permit = signing_gate::try_acquire(&gate);
            blocked |= permit.is_none();
            permit
        },
        |_| {
            signs += 1;
            Ok(vec![1])
        },
    );
    assert!(blocked);
    assert!(Instant::now() >= expires);
    assert_eq!((result, signs), (Ok(None), 0));
    drop(held);
}

#[cfg(unix)]
#[test]
fn sign_until_returns_without_waiting_for_the_writer_to_release() {
    use std::sync::mpsc;

    let fixture = super::super::private_dir::PrivateDir::create(&std::env::temp_dir()).unwrap();
    let source = fixture.path.join("fixture.c");
    let module = fixture.path.join("fixture.so");
    // Loading only needs a function list. This fixture has no provider
    // operations, so an unexpected attempt to open a session is an error.
    std::fs::write(
        &source,
        r#"
struct FunctionList {
    unsigned char major, minor;
    void (*functions[68])(void);
};
static struct FunctionList functions = { .major = 2, .minor = 40 };
unsigned long C_GetFunctionList(struct FunctionList **list) {
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

    let gate = Arc::new(RwLock::new(()));
    let mut key = TokenKey {
        pkcs11: Arc::new(Pkcs11::new(&module).unwrap()),
        slot: Slot::try_from(1_u32).unwrap(),
        id: vec![1],
        session: None,
        gate: Arc::clone(&gate),
    };
    let canceled = AtomicBool::new(false);
    let budget = Duration::from_secs(5);
    let (started, start) = mpsc::channel();
    let (finished, finish) = mpsc::channel();
    let held = gate.write().unwrap();
    thread::scope(|scope| {
        scope.spawn(|| {
            let expires = Instant::now() + budget.saturating_mul(2);
            started.send(()).unwrap();
            let result = key.sign_until(Padding::Pkcs1, &[], &canceled, expires);
            finished.send(result).unwrap();
        });
        start.recv_timeout(budget).unwrap();
        canceled.store(true, Ordering::Release);
        let result = finish.recv_timeout(budget);
        drop(held);
        assert_eq!(
            result,
            Ok(Ok(None)),
            "cancel must return with the gate held"
        );
    });
}

#[cfg(unix)]
#[test]
fn try_acquire_recovers_a_poisoned_gate_like_acquire() {
    let gate = Arc::new(RwLock::new(()));
    assert!(
        thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _held = gate.write().unwrap();
                    panic!("poison the fixture gate");
                })
                .join()
        })
        .is_err()
    );
    assert!(gate.is_poisoned());
    assert!(signing_gate::acquire(&gate).belongs_to(&gate));
    assert!(signing_gate::try_acquire(&gate).unwrap().belongs_to(&gate));
}

#[cfg(unix)]
fn with_login_fixture<T>(
    step: u8,
    run: impl FnOnce(&Path, &AtomicBool, Instant) -> T + Send,
) -> (T, Vec<u8>)
where
    T: Send,
{
    use std::{
        io::{Read, Write},
        os::{fd::AsRawFd, unix::net::UnixStream},
    };

    let fixture = super::super::private_dir::PrivateDir::create(&std::env::temp_dir()).unwrap();
    let source = fixture.path.join("login.c");
    let module = fixture.path.join("login.so");
    let hold_enumeration = step == b'E';
    let (mut operator, provider) = UnixStream::pair().unwrap();
    let budget = Duration::from_secs(5);
    operator.set_read_timeout(Some(budget)).unwrap();
    provider.set_read_timeout(Some(budget)).unwrap();
    std::fs::write(
        &source,
        r#"
#include <stddef.h>
#include <string.h>
#include <unistd.h>
typedef unsigned long Ulong;
typedef Ulong (*Function)(void);
struct TokenInfo {
    unsigned char label[32], manufacturer[32], model[16], serial[16];
    Ulong flags, sessions[4], pin_lengths[2], memory[4];
    unsigned char versions[4], utc_time[16];
};
static int logged_in, key_available, sessions;

static Ulong wait_for_revocation(char step) {
    char resume;
    if (write(PROVIDER_FD, &step, 1) != 1 ||
        read(PROVIDER_FD, &resume, 1) != 1 || resume != 'R') {
        return 5; /* CKR_GENERAL_ERROR */
    }
    return 0;
}
static Ulong initialize(void *args) { return 0; }
static Ulong get_slots(unsigned char present, Ulong *slots, Ulong *count) {
    if (!slots && HOLD_ENUMERATION && wait_for_revocation('E') != 0) { return 5; }
    if (slots) { *slots = 1; }
    *count = 1;
    return 0;
}

static Ulong token_info(Ulong slot, struct TokenInfo *info) {
    if (HOLD_TOKEN_INFO && wait_for_revocation('T') != 0) { return 5; }
    memset(info, 0, sizeof(*info));
    info->flags = 0x100; /* CKF_PROTECTED_AUTHENTICATION_PATH */
    return 0;
}
static Ulong open_session(Ulong slot, Ulong flags, void *app, Function notify, Ulong *session) {
    if (HOLD_ENUMERATION && write(PROVIDER_FD, "O", 1) != 1) { return 5; }
    if (HOLD_REOPEN && sessions++ == 1 && wait_for_revocation('R') != 0) { return 5; }
    *session = 1;
    return 0;
}
static Ulong close_session(Ulong session) {
    return HOLD_ENUMERATION && write(PROVIDER_FD, "X", 1) != 1 ? 5 : 0;
}
static Ulong login(Ulong session, Ulong user, unsigned char *pin, Ulong length) {
    if (HOLD_ENUMERATION || HOLD_TOKEN_INFO || HOLD_REOPEN
            ? write(PROVIDER_FD, "L", 1) != 1 : wait_for_revocation('L') != 0) {
        return 5;
    }
    if (HOLD_REOPEN && sessions == 1) { return 0xb3; /* CKR_SESSION_HANDLE_INVALID */ }
    logged_in = 1;
    return 0;
}
struct Attribute { Ulong type; void *value; Ulong length; };
static Ulong find_init(Ulong session, struct Attribute *filter, Ulong count) {
    /* CKA_CLASS is first in the template. CKO_CERTIFICATE is public. */
    key_available = *(Ulong *)filter[0].value == 1 || logged_in;
    return 0;
}
static Ulong find(Ulong session, Ulong *keys, Ulong max, Ulong *count) {
    *count = key_available;
    if (key_available) {
        *keys = 2;
        key_available = 0;
    }
    return 0;
}
static Ulong find_final(Ulong session) { return 0; }
static Ulong sign_init(Ulong session, void *mechanism, Ulong key) { return 0; }
static Ulong sign(Ulong session, unsigned char *data, Ulong len, unsigned char *out, Ulong *size) {
    if (write(PROVIDER_FD, "S", 1) != 1) { return 5; }
    if (out) { *out = 42; }
    *size = 1;
    return 0;
}
struct FunctionList {
    unsigned char major, minor;
    Function functions[68];
};
static struct FunctionList functions = { .major = 2, .minor = 40, .functions = {
    [0] = (Function)initialize, [4] = (Function)get_slots, [6] = (Function)token_info, [12] = (Function)open_session, [13] = (Function)close_session,
    [18] = (Function)login, [26] = (Function)find_init, [27] = (Function)find,
    [28] = (Function)find_final, [42] = (Function)sign_init, [43] = (Function)sign,
}};
Ulong C_GetFunctionList(struct FunctionList **list) { *list = &functions; return 0; }
"#,
    )
    .unwrap();
    let output = std::process::Command::new("/usr/bin/cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&module)
        .arg(format!("-DPROVIDER_FD={}", provider.as_raw_fd()))
        .arg(format!(
            "-DHOLD_ENUMERATION={}",
            i32::from(hold_enumeration)
        ))
        .arg(format!("-DHOLD_TOKEN_INFO={}", i32::from(step == b'T')))
        .arg(format!("-DHOLD_REOPEN={}", i32::from(step == b'R')))
        .arg(source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let canceled = AtomicBool::new(false);
    thread::scope(|scope| {
        let canceled = &canceled;
        let worker = scope.spawn(move || {
            let _provider = provider;
            run(&module, canceled, Instant::now() + budget * 2)
        });
        let mut reached = [0];
        let mut events = Vec::new();
        if step == b'R' {
            operator.read_exact(&mut reached).unwrap();
            assert_eq!(reached, [b'L'], "the first C_Login must force a retry");
            events.push(reached[0]);
        }
        operator.read_exact(&mut reached).unwrap();
        assert_eq!(
            reached,
            [step],
            "the fixture must reach the blocked provider call"
        );
        canceled.store(true, Ordering::Release);
        operator.write_all(b"R").unwrap();
        let result = worker.join().unwrap();
        operator.read_to_end(&mut events).unwrap();
        (result, events)
    })
}

#[cfg(unix)]
#[test]
fn sign_until_skips_c_sign_when_revoked_during_provider_login() {
    let (result, events) = with_login_fixture(b'L', |module, canceled, expires| {
        let mut key = TokenKey {
            pkcs11: Arc::new(Pkcs11::new(module).unwrap()),
            slot: Slot::try_from(1_u32).unwrap(),
            id: vec![1],
            session: None,
            gate: Arc::new(RwLock::new(())),
        };
        key.sign_until(Padding::Pkcs1, &[], canceled, expires)
    });
    assert_eq!(
        (result, events.len()),
        (Ok(None), 0),
        "revocation during C_Login must prevent C_Sign"
    );
}

#[cfg(unix)]
#[test]
fn sign_until_skips_c_login_when_revoked_during_token_info() {
    for (step, logins_before_revocation, operation) in [
        (b'T', 0, "C_GetTokenInfo"),
        (b'R', 1, "reopening the session"),
    ] {
        let (result, events) = with_login_fixture(step, |module, canceled, expires| {
            let mut key = TokenKey {
                pkcs11: Arc::new(Pkcs11::new(module).unwrap()),
                slot: Slot::try_from(1_u32).unwrap(),
                id: vec![1],
                session: None,
                gate: Arc::new(RwLock::new(())),
            };
            key.sign_until(Padding::Pkcs1, &[], canceled, expires)
        });
        let logins = events.iter().filter(|event| **event == b'L').count();
        assert_eq!(
            (result, logins),
            (Ok(None), logins_before_revocation),
            "revocation during {operation} must prevent another C_Login"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn open_until_skips_session_and_login_when_revoked_during_slot_enumeration() {
    let (result, events) = with_login_fixture(b'E', |module, canceled, expires| {
        TokenKey::open_until(module, &[1], canceled, expires).map(|key| {
            // The consumer's blocking signer can log in if it receives a key.
            key.map(|mut key| key.sign(Padding::Pkcs1, &[]))
        })
    });
    let opened = events.iter().filter(|event| **event == b'O').count();
    let closed = events.iter().filter(|event| **event == b'X').count();
    let logins = events.iter().filter(|event| **event == b'L').count();
    assert_eq!(
        (result, opened, closed, logins),
        (Ok(None), 0, 0, 0),
        "revocation during C_GetSlotList must stop the open before a session can log in"
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
