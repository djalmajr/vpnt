#![cfg(target_os = "macos")]

use core_foundation::base::TCFType;
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
use vpnt::{
    keychain::MacKeychain,
    model::VpnKind,
    secrets::{Credentials, Secret, SecretError, SecretStore},
};

// The sys crate omits this macOS cleanup API. Signature from SecKeychain.h.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainDelete(keychain: security_framework_sys::base::SecKeychainRef) -> i32;
    fn SecKeychainLock(keychain: security_framework_sys::base::SecKeychainRef) -> i32;
}

struct Fixture {
    keychain: Option<SecKeychain>,
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!("keychain-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let mut fixture = Self {
            keychain: None,
            directory,
        };
        let keychain = CreateOptions::new()
            .password("fictional-test-keychain-password")
            .prompt_user(false)
            .create(fixture.directory.join("isolated.keychain"))
            .expect("create isolated fixture keychain");
        fixture.keychain = Some(keychain);
        fixture
    }

    fn cleanup(&mut self) -> i32 {
        self.keychain.take().map_or(0, |keychain| {
            // SAFETY: this retained reference is exclusively the keychain created
            // by this fixture. No default keychain or search list is replaced.
            unsafe { SecKeychainDelete(keychain.as_concrete_TypeRef()) }
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cleanup();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn search_list() -> Vec<u8> {
    let output = Command::new("/usr/bin/security")
        .args(["list-keychains", "-d", "user"])
        .output()
        .unwrap();
    assert!(output.status.success());
    output.stdout
}

// Real Security.framework consumer, explicit disposable keychain and fake data.
// The user's default keychain and final search list must stay unchanged.
#[test]
fn native_keychain_isolates_profiles_updates_pairs_and_reports_removal() {
    let before = search_list();
    let default = SecKeychain::default().unwrap();
    let _interaction = SecKeychain::disable_user_interaction().unwrap();
    let mut fixture = Fixture::new();
    let store = MacKeychain::from_keychain(fixture.keychain.as_ref().unwrap().clone());
    assert!(!store.contains("a", VpnKind::Ipsec).unwrap());
    store
        .save(
            "a",
            VpnKind::Ipsec,
            &Credentials {
                password: "first-password".into(),
                psk: "first-psk".into(),
            },
        )
        .unwrap();
    store
        .save(
            "b",
            VpnKind::Ssl,
            &Credentials {
                password: "other-password".into(),
                psk: "".into(),
            },
        )
        .unwrap();
    assert!(store.contains("a", VpnKind::Ipsec).unwrap());
    assert!(!store.contains("a", VpnKind::Ssl).unwrap());
    store
        .save(
            "a",
            VpnKind::Ipsec,
            &Credentials {
                password: "updated-password".into(),
                psk: "updated-psk".into(),
            },
        )
        .unwrap();
    let updated = store.load("a", VpnKind::Ipsec).unwrap();
    assert!(updated.password.expose() == "updated-password");
    assert!(updated.psk.expose() == "updated-psk");
    assert!(store.load("b", VpnKind::Ssl).unwrap().password.expose() == "other-password");
    assert!(
        store
            .save(
                "a",
                VpnKind::Ipsec,
                &Credentials {
                    password: "invalid\npassword".into(),
                    psk: Secret::from("psk")
                }
            )
            .is_err()
    );
    assert!(store.load("a", VpnKind::Ipsec).unwrap().password.expose() == "updated-password");
    store.remove("a", VpnKind::Ipsec).unwrap();
    assert!(!store.contains("a", VpnKind::Ipsec).unwrap());
    assert!(matches!(
        store.load("a", VpnKind::Ipsec),
        Err(SecretError::Missing)
    ));
    assert!(store.contains("b", VpnKind::Ssl).unwrap());
    store.remove("a", VpnKind::Ipsec).unwrap();
    // SAFETY: only this fixture's retained keychain is locked; never LockAll.
    assert_eq!(
        unsafe { SecKeychainLock(fixture.keychain.as_ref().unwrap().as_concrete_TypeRef()) },
        0
    );
    assert!(matches!(
        store.load("b", VpnKind::Ssl),
        Err(SecretError::Denied)
    ));
    fixture
        .keychain
        .as_mut()
        .unwrap()
        .unlock(Some("fictional-test-keychain-password"))
        .unwrap();
    assert!(store.load("b", VpnKind::Ssl).unwrap().password.expose() == "other-password");
    drop(store);
    assert_eq!(fixture.cleanup(), 0, "fixture cleanup failed");
    assert!(
        default == SecKeychain::default().unwrap(),
        "default keychain changed"
    );
    assert!(before == search_list(), "keychain search list changed");
}
