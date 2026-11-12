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
        let mut c = client(b);
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
            profile: profile("two")
        }),
        Message::Accepted { .. }
    ));
    let mut changed = profile("one");
    changed.gateway = "changed.example.test".into();
    for command in [
        AdminCommand::SaveProfile { profile: changed },
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
