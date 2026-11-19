use super::*;
use std::{fs, os::unix::fs::OpenOptionsExt, sync::atomic::AtomicU64};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "admin-profile-isolation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join(".controller.lock"))
            .unwrap();
        Self(root)
    }
    fn store(&self) -> ProfileStore {
        ProfileStore::open(&self.0, unsafe { libc::geteuid() }).unwrap()
    }
    fn request(&self, command: AdminCommand) -> Message {
        let (a, b) = UnixStream::pair().unwrap();
        let root = self.0.clone();
        let task = thread::spawn(move || {
            admin(caller(a), |uid, request| {
                let _lock = mode_lock(Mode::Admin, || ControllerLock::fixture(&root, uid)).unwrap();
                apply_admin(&ProfileStore::open(root, uid).unwrap(), request)
            })
        });
        let mut c = admin_client(b);
        protocol::write_admin_request(
            c.get_mut(),
            &protocol::AdminRequest {
                id: "edit".into(),
                command,
            },
        )
        .unwrap();
        c.get_mut().shutdown(Shutdown::Write).unwrap();
        let response = protocol::read_message(&mut c).unwrap().unwrap();
        assert!(task.join().unwrap().is_ok());
        response
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn profile(id: &str) -> crate::model::Profile {
    serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
}
#[test]
fn administrative_wire_can_edit_another_profile_while_runtime_and_target_reservations_remain_held()
{
    let f = Fixture::new();
    let store = f.store();
    let network = ControllerLock::fixture(&f.0, unsafe { libc::geteuid() }).unwrap();
    store.save(profile("one")).unwrap();
    let active = store.reserve("one").unwrap();
    assert!(matches!(
        f.request(AdminCommand::SaveProfile {
            profile: profile("two"),
            ovpn_config: None,
        }),
        Message::Accepted { .. }
    ));
    let mut changed = profile("one");
    changed.gateway = "changed.example.test".into();
    for command in [
        AdminCommand::SaveProfile {
            profile: changed,
            ovpn_config: None,
        },
        AdminCommand::RemoveProfile { id: "one".into() },
    ] {
        assert!(matches!(
            f.request(command),
            Message::Failed {
                error: ErrorCode::ProfileBusy,
                ..
            }
        ));
    }
    assert!(matches!(
        f.request(AdminCommand::RemoveProfile { id: "two".into() }),
        Message::Accepted { .. }
    ));
    assert_eq!(store.load().unwrap(), vec![profile("one")]);
    network.validate().unwrap();
    active.validate().unwrap();
    assert!(matches!(
        ControllerLock::fixture(&f.0, unsafe { libc::geteuid() }),
        Err(super::super::super::controller_lock::LockError::Busy)
    ));
    drop(active);
    assert!(matches!(
        f.request(AdminCommand::RemoveProfile { id: "one".into() }),
        Message::Accepted { .. }
    ));
    drop(network);
}

#[test]
fn ovpn_admin_wire_normalizes_rejects_and_removes_private_config() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    let profile: crate::model::Profile = serde_json::from_value(serde_json::json!({
        "id":"one","name":"Fixture","kind":"ovpn","gateway":"vpn.example.test",
        "username":"","networks":[],"port":1194,"certificate":"",
        "probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp",
        "ovpn":{"module":"/fixture/token.dylib","certificateId":"01","tls":"pkcs1_only"}
    }))
    .unwrap();
    let input = "client\r\nremote vpn.example.test 1194\r\n<ca>\r\nfixture\r\n</ca>\r\n";
    let save = |text: &str| AdminCommand::SaveProfile {
        profile: profile.clone(),
        ovpn_config: Some(text.into()),
    };
    assert!(matches!(f.request(save(input)), Message::Accepted { .. }));
    let file = f.0.join("ovpn/one.ovpn");
    let expected = crate::connection::ovpn::profile::inspect(input.as_bytes())
        .unwrap()
        .normalized;
    assert_eq!(fs::read_to_string(&file).unwrap(), expected);
    assert_ne!(expected, input);
    let metadata = fs::metadata(&file).unwrap();
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.mode() & 0o777, 0o600);
    let directory = fs::metadata(f.0.join("ovpn")).unwrap();
    assert_eq!(directory.uid(), unsafe { libc::geteuid() });
    assert_eq!(directory.mode() & 0o777, 0o700);
    for forbidden in ["up /fixture", "script-security 2"] {
        let malicious = format!("{input}{forbidden}\n");
        assert!(matches!(
            f.request(save(&malicious)),
            Message::Failed {
                error: ErrorCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(fs::read_to_string(&file).unwrap(), expected);
    }
    assert!(matches!(
        f.request(AdminCommand::RemoveProfile { id: "one".into() }),
        Message::Accepted { .. }
    ));
    assert!(!file.exists());
}

#[test]
fn ovpn_admin_identity_keeps_each_config_through_rename_and_removal() {
    let f = Fixture::new();
    let make_profile = |id: &str| -> crate::model::Profile {
        serde_json::from_value(serde_json::json!({
            "id":id,"name":id,"kind":"ovpn","gateway":"vpn.example.test",
            "username":"","networks":[],"port":1194,"certificate":"",
            "probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp",
            "ovpn":{"module":"/fixture/token.so","certificateId":"01","tls":"pkcs1_only"}
        }))
        .unwrap()
    };
    let one = make_profile("one");
    let two = make_profile("two");
    let config_one = "remote vpn.example.test 1194\n<ca>\none\n</ca>\n<tls-crypt>\nfixture-secret-one\n</tls-crypt>\n";
    let config_two = "remote vpn.example.test 1194\n<ca>\ntwo\n</ca>\n";
    for (profile, content) in [(one.clone(), config_one), (two.clone(), config_two)] {
        assert!(matches!(
            f.request(AdminCommand::SaveProfile {
                profile,
                ovpn_config: Some(content.into())
            }),
            Message::Accepted { .. }
        ));
    }
    let first = f.0.join("ovpn/one.ovpn");
    let second = f.0.join("ovpn/two.ovpn");
    let first_data = fs::read(&first).unwrap();
    let second_data = fs::read(&second).unwrap();
    assert_ne!(first_data, second_data);
    let mut renamed = one.clone();
    renamed.name = "Renamed fixture".into();
    assert!(matches!(
        f.request(AdminCommand::SaveProfile {
            profile: renamed,
            ovpn_config: None
        }),
        Message::Accepted { .. }
    ));
    assert_eq!(fs::read(&first).unwrap(), first_data);
    assert_eq!(fs::read(&second).unwrap(), second_data);
    assert!(matches!(
        f.request(AdminCommand::RemoveProfile { id: "one".into() }),
        Message::Accepted { .. }
    ));
    assert!(!first.exists());
    assert_eq!(fs::read(&second).unwrap(), second_data);
    assert_eq!(f.store().load().unwrap(), vec![two]);
}

#[test]
fn ovpn_admin_rejects_forbidden_directives_before_writing() {
    let f = Fixture::new();
    let profile: crate::model::Profile = serde_json::from_value(serde_json::json!({
        "id":"one","name":"Fixture","kind":"ovpn","gateway":"vpn.example.test",
        "username":"","networks":[],"port":1194,"certificate":"",
        "probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp",
        "ovpn":{"module":"/fixture/token.so","certificateId":"01","tls":"pkcs1_only"}
    }))
    .unwrap();
    let valid = "remote vpn.example.test 1194\n<ca>\nfixture\n</ca>\n";
    let forbidden = format!("{valid}up /fixture\n");
    assert!(matches!(
        f.request(AdminCommand::SaveProfile {
            profile: profile.clone(),
            ovpn_config: Some(forbidden)
        }),
        Message::Failed {
            error: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert!(!f.0.join("ovpn/one.ovpn").exists());
    assert!(f.store().load().unwrap().is_empty());
    assert!(matches!(
        f.request(AdminCommand::SaveProfile {
            profile,
            ovpn_config: Some(valid.into())
        }),
        Message::Accepted { .. }
    ));
}

fn ovpn_profile(id: &str) -> crate::model::Profile {
    serde_json::from_value(serde_json::json!({
        "id":id,"name":id,"kind":"ovpn","gateway":"vpn.example.test",
        "username":"","networks":[],"port":1194,"certificate":"",
        "probeHost":"192.0.2.1","probePort":8443,"probeMethod":"tcp",
        "ovpn":{"module":"/fixture/token.dylib","certificateId":"01","tls":"pkcs1_only"}
    }))
    .unwrap()
}

fn normalized(text: &str) -> String {
    crate::connection::ovpn::profile::inspect(text.as_bytes())
        .unwrap()
        .normalized
}

#[cfg(target_os = "macos")]
struct Deny(std::ffi::CString);
#[cfg(target_os = "macos")]
impl Drop for Deny {
    fn drop(&mut self) {
        // SAFETY: the NUL-terminated owned path stays valid for this call.
        assert_eq!(unsafe { libc::chflags(self.0.as_ptr(), 0) }, 0);
    }
}
#[cfg(not(target_os = "macos"))]
struct Deny(std::path::PathBuf);
#[cfg(not(target_os = "macos"))]
impl Drop for Deny {
    fn drop(&mut self) {
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
/// Induces the failure the removal must report: an unremovable config file on
/// macOS, an unwritable config directory elsewhere. The guard restores it.
#[cfg(target_os = "macos")]
fn deny_config_removal(_: &std::path::Path, config: &std::path::Path) -> Deny {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(config.as_os_str().as_bytes()).unwrap();
    // SAFETY: the NUL-terminated owned path stays valid for this call.
    assert_eq!(
        unsafe { libc::chflags(path.as_ptr(), libc::UF_IMMUTABLE) },
        0
    );
    Deny(path)
}
#[cfg(not(target_os = "macos"))]
fn deny_config_removal(directory: &std::path::Path, _: &std::path::Path) -> Deny {
    fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).unwrap();
    Deny(directory.to_owned())
}

#[test]
fn administrative_wire_refuses_an_id_that_differs_only_in_case() {
    let f = Fixture::new();
    let first = "remote vpn.example.test 1194\n<ca>\nfirst\n</ca>\n";
    let second = "remote vpn.example.test 1194\n<ca>\nsecond\n</ca>\n";
    let save = |id: &str, text: &str| AdminCommand::SaveProfile {
        profile: ovpn_profile(id),
        ovpn_config: Some(text.into()),
    };
    assert!(matches!(
        f.request(save("one", first)),
        Message::Accepted { .. }
    ));
    let config = f.0.join("ovpn/one.ovpn");
    assert_eq!(fs::read_to_string(&config).unwrap(), normalized(first));
    assert!(matches!(
        f.request(save("One", second)),
        Message::Failed {
            error: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert_eq!(fs::read_to_string(&config).unwrap(), normalized(first));
    assert_eq!(
        f.store()
            .load()
            .unwrap()
            .iter()
            .map(|profile| profile.id.clone())
            .collect::<Vec<_>>(),
        ["one"]
    );
    let mut edited = ovpn_profile("one");
    edited.name = "Edited fixture".into();
    assert!(matches!(
        f.request(AdminCommand::SaveProfile {
            profile: edited.clone(),
            ovpn_config: None
        }),
        Message::Accepted { .. }
    ));
    assert_eq!(f.store().load().unwrap(), vec![edited]);
    assert_eq!(fs::read_to_string(&config).unwrap(), normalized(first));
    // The alias was never stored: removing it must not touch the stored config.
    assert!(matches!(
        f.request(AdminCommand::RemoveProfile { id: "One".into() }),
        Message::Failed {
            error: ErrorCode::ProfileNotFound,
            ..
        }
    ));
    assert_eq!(fs::read_to_string(&config).unwrap(), normalized(first));
    assert_eq!(f.store().load().unwrap().len(), 1);
}

#[test]
fn administrative_wire_reports_a_config_cleanup_failure_and_retries() {
    let f = Fixture::new();
    let input = "remote vpn.example.test 1194\n<ca>\nfixture\n</ca>\n";
    assert!(matches!(
        f.request(AdminCommand::SaveProfile {
            profile: ovpn_profile("one"),
            ovpn_config: Some(input.into())
        }),
        Message::Accepted { .. }
    ));
    let config = f.0.join("ovpn/one.ovpn");
    let before = fs::read(&config).unwrap();
    assert_eq!(before, normalized(input).as_bytes());
    let deny = deny_config_removal(&f.0.join("ovpn"), &config);
    let reply = f.request(AdminCommand::RemoveProfile { id: "one".into() });
    assert!(matches!(reply, Message::Failed { .. }), "{reply:?}");
    assert_eq!(fs::read(&config).unwrap(), before);
    assert_eq!(f.store().load().unwrap().len(), 1);
    drop(deny);
    assert!(matches!(
        f.request(AdminCommand::RemoveProfile { id: "one".into() }),
        Message::Accepted { .. }
    ));
    assert!(!config.exists());
    assert!(f.store().load().unwrap().is_empty());
}
