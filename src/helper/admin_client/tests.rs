use super::*;
use crate::{
    helper::protocol::{AdminCommand, AdminRequest},
    model::Profile,
};
use std::{fs, path::PathBuf, sync::atomic::AtomicU64, time::Duration};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Peer {
    root: PathBuf,
    state: Arc<State>,
}
impl Peer {
    fn new(mode: &str, deadline: Duration) -> (Self, Admin) {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "admin-client-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg(
                std::env::current_dir()
                    .unwrap()
                    .join("tests/fixtures/helper-admin/peer.py"),
            )
            .arg(mode)
            .arg(root.join("peer"))
            .env("VPNT_MUST_NOT_REACH_HELPER", "fictional");
        let admin =
            Admin::fixture(command, request(), Locale::PtBr, Instant::now() + deadline).unwrap();
        (
            Self {
                root,
                state: admin.state.clone(),
            },
            admin,
        )
    }
    fn marker(&self, name: &str) -> PathBuf {
        self.root.join(format!("peer.{name}"))
    }
    fn has(&self, name: &str) -> bool {
        self.marker(name).exists()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = fs::write(self.marker("allow_exit"), b"");
        let _ = fs::write(self.marker("allow_ready"), b"");
        self.state.stop.store(true, Ordering::Release);
        let until = Instant::now() + Duration::from_secs(3);
        while !self.state.finished.load(Ordering::Acquire) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        if self.state.finished.load(Ordering::Acquire) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
fn request() -> AdminRequest {
    let profile:Profile=serde_json::from_value(serde_json::json!({"id":"one","name":"Fictional","kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap();
    AdminRequest {
        id: "admin-one".into(),
        command: AdminCommand::SaveProfile { profile },
    }
}
fn wait(mut predicate: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(4);
    while !predicate() {
        assert!(Instant::now() < until, "admin condition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn document_waits_for_ready_and_eof_then_success_waits_for_the_owned_child() {
    let (peer, mut admin) = Peer::new("hold", Duration::from_secs(3));
    wait(|| peer.has("ready"));
    assert!(
        !peer.has("early"),
        "no document before authenticated readiness"
    );
    wait(|| peer.has("retiring"));
    assert!(peer.has("received"));
    assert!(!peer.has("early"));
    assert!(!admin.finished());
    assert!(admin.poll().is_none(), "acceptance is not an exit receipt");
    fs::write(peer.marker("allow_exit"), b"").unwrap();
    wait(|| admin.finished());
    assert_eq!(admin.poll(), Some(Ok(())));
    assert!(admin.poll().is_none());
    assert!(peer.has("cleaned"));
}
#[test]
fn incompatible_or_late_authorization_never_receives_the_document() {
    for (mode, expected, deadline) in [
        ("version", Error::Incompatible, Duration::from_secs(2)),
        ("protocol", Error::Incompatible, Duration::from_secs(2)),
        ("late", Error::Expired, Duration::from_millis(250)),
    ] {
        let (peer, mut admin) = Peer::new(mode, deadline);
        wait(|| matches!(admin.poll(),Some(Err(e))if e==expected));
        fs::write(peer.marker("allow_ready"), b"").unwrap();
        wait(|| admin.finished());
        assert!(!peer.has("received"));
        assert!(!peer.has("early"));
    }
}
#[test]
fn mismatched_duplicate_failed_and_unsuccessful_exit_are_not_success() {
    for (mode, expected) in [
        ("wrong", Error::InvalidReply),
        ("duplicate", Error::InvalidReply),
        ("busy", Error::Rejected(ErrorCode::ProfileBusy)),
        ("exit", Error::Unavailable),
    ] {
        let (_peer, mut admin) = Peer::new(mode, Duration::from_secs(2));
        let mut outcome = None;
        wait(|| {
            outcome = admin.poll();
            outcome.is_some()
        });
        assert_eq!(outcome, Some(Err(expected)));
        wait(|| admin.finished());
    }
}
#[test]
fn elevation_command_is_closed_and_never_uses_shell_or_cached_authentication() {
    let command = command();
    assert_eq!(command.get_program(), "/usr/bin/sudo");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            "-A",
            "-k",
            "--",
            "/Library/PrivilegedHelperTools/dev.vpnt.helper",
            "admin"
        ]
    );
}
