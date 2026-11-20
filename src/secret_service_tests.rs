use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const PROFILE: &str = "profile-7";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vpnt-secret-fixture-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn store(&self, script: &str) -> LinuxSecretService {
        let program = self.0.join("secret-tool");
        // Each fixture writes only under the directory that owns the executable.
        crate::test_support::write_script(
            &program,
            &format!("#!/bin/sh\ncd -- \"${{0%/*}}\" || exit 2\n{script}\n"),
        );
        LinuxSecretService::with_program(program)
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(name)).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn credentials(password: &str, psk: &str) -> Credentials {
    Credentials {
        password: password.into(),
        psk: psk.into(),
    }
}

#[test]
fn secret_tool_receives_exact_arguments_and_secret_only_on_stdin() {
    let fixture = Fixture::new();
    let store = fixture.store(
        r#"
printf 'call' >> argv
printf ' <%s>' "$@" >> argv
printf '\n' >> argv
case "$1" in
    store) /usr/bin/cat > stdin ;;
    lookup) printf '%s\n' 'fixture-password';;
esac
"#,
    );
    store
        .save(PROFILE, VpnKind::Ssl, &credentials("fixture-password", ""))
        .unwrap();
    assert!(store.contains(PROFILE, VpnKind::Ssl).unwrap());
    store.remove(PROFILE, VpnKind::Ssl).unwrap();
    let argv = fixture.read("argv");
    assert!(!argv.contains("fixture-password"));
    assert_eq!(
        argv,
        concat!(
            "call <store> <--label=VPN Tray: profile-7 (password)> <application> <vpnt> <profile> <profile-7> <kind> <ssl> <field> <password>\n",
            "call <clear> <application> <vpnt> <profile> <profile-7> <kind> <ssl> <field> <psk>\n",
            "call <lookup> <application> <vpnt> <profile> <profile-7> <kind> <ssl> <field> <password>\n",
            "call <clear> <application> <vpnt> <profile> <profile-7> <kind> <ssl>\n",
        )
    );
    assert!(fixture.read("stdin") == "fixture-password");
}

#[test]
fn profile_id_beginning_with_hyphen_is_passed_as_an_attribute() {
    let fixture = Fixture::new();
    let store = fixture.store(
        r#"
printf '<%s>' "$@" > argv
exit 1
"#,
    );
    assert_eq!(store.contains("--help", VpnKind::Ssl), Ok(false));
    assert_eq!(
        fixture.read("argv"),
        "<lookup><--><application><vpnt><profile><--help><kind><ssl><field><password>"
    );
}

#[test]
fn lookup_distinguishes_single_missing_invalid_and_unavailable_values() {
    let fixture = Fixture::new();
    let store = fixture.store(
        r#"
case "$5:$7:$9" in
    profile-7:ssl:password) printf '%s\n' 'present' ;;
    invalid:ssl:password) printf 'one\ntwo\n' ;;
    incomplete:ipsec:psk) printf 'present' ;;
    unavailable:*) printf 'service unavailable\n' >&2; exit 1 ;;
    error:*) printf 'unexpected' ; exit 1 ;;
    *) exit 1 ;;
esac
"#,
    );
    let loaded = store.load(PROFILE, VpnKind::Ssl).unwrap();
    assert!(loaded.password.expose() == "present");
    assert!(loaded.psk.expose().is_empty());
    assert_eq!(
        store.load("missing", VpnKind::Ssl).unwrap_err(),
        SecretError::Missing
    );
    assert!(!store.contains("missing", VpnKind::Ssl).unwrap());
    assert_eq!(
        store.load("invalid", VpnKind::Ssl).unwrap_err(),
        SecretError::InvalidData
    );
    assert!(store.contains("incomplete", VpnKind::Ipsec).unwrap());
    assert_eq!(
        store.load("incomplete", VpnKind::Ipsec).unwrap_err(),
        SecretError::InvalidData
    );
    assert_eq!(
        store.contains("unavailable", VpnKind::Ssl),
        Err(SecretError::Unavailable)
    );
    assert_eq!(
        store.contains("error", VpnKind::Ssl),
        Err(SecretError::Unavailable)
    );
    assert_eq!(
        LinuxSecretService::with_program(fixture.0.join("missing-tool"))
            .contains(PROFILE, VpnKind::Ssl),
        Err(SecretError::Unavailable)
    );
}

#[test]
fn timeout_terminates_and_reaps_the_secret_tool() {
    let fixture = Fixture::new();
    let mut store = fixture.store("printf '%s' \"$$\" > pid\nexec /usr/bin/sleep 1");
    store.timeout = Duration::from_millis(200);
    assert_eq!(
        store.contains(PROFILE, VpnKind::Ssl),
        Err(SecretError::Unavailable)
    );
    let pid = fixture.read("pid");
    assert!(pid.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!Path::new("/proc").join(pid).exists());
}

#[test]
fn invalid_profile_ids_and_invalid_credentials_never_call_secret_tool() {
    let fixture = Fixture::new();
    let store = fixture.store("printf invoked >> calls\nexit 1");
    for invalid in ["", "../escape", "--help with spaces", "zero\0byte"] {
        assert_eq!(
            store.load(invalid, VpnKind::Ssl).unwrap_err(),
            SecretError::InvalidData
        );
        assert_eq!(
            store.contains(invalid, VpnKind::Ssl),
            Err(SecretError::InvalidData)
        );
        assert_eq!(
            store.save(invalid, VpnKind::Ssl, &credentials("valid", "")),
            Err(SecretError::InvalidData)
        );
        assert_eq!(
            store.remove(invalid, VpnKind::Ssl),
            Err(SecretError::InvalidData)
        );
    }
    assert_eq!(
        store.save(PROFILE, VpnKind::Ipsec, &credentials("valid", "")),
        Err(SecretError::InvalidData)
    );
    assert!(!fixture.0.join("calls").exists());
}

#[test]
fn ovpn_does_not_call_secret_tool() {
    let kind = VpnKind::Ovpn;
    let fixture = Fixture::new();
    let store = fixture.store("printf invoked >> calls\nexit 1");
    assert_eq!(store.contains(PROFILE, kind), Ok(false));
    assert_eq!(store.load(PROFILE, kind).unwrap_err(), SecretError::Missing);
    assert_eq!(store.save(PROFILE, kind, &credentials("", "")), Ok(()));
    assert_eq!(store.remove(PROFILE, kind), Ok(()));
    assert_eq!(
        store.save(PROFILE, kind, &credentials("unexpected", "")),
        Err(SecretError::InvalidData)
    );
    assert!(!fixture.0.join("calls").exists());
}
