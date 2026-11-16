use super::*;
use std::{
    os::unix::fs::symlink,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    home: PathBuf,
    uid: u32,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!(
            "vpnt-user-diagnostics-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(home.join("Library")).unwrap();
        fs::create_dir(home.join("Library/Application Support")).unwrap();
        Self {
            home,
            uid: unsafe { libc::geteuid() },
        }
    }
    fn directory(&self) -> PathBuf {
        self.home
            .join("Library/Application Support")
            .join(crate::identifiers::APP)
    }
    fn file(&self) -> PathBuf {
        self.directory().join("diagnostics.txt")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}
#[test]
fn terminal_detection_covers_failed_attempts_and_cleanup_without_spurious_requests() {
    for state in [
        State::Off,
        State::Dropped,
        State::CredentialsRejected,
        State::GatewayTimeout,
        State::MissingProgram,
    ] {
        assert!(ended(State::Connecting, false, state, false), "{state:?}");
        assert!(
            ended(State::Disconnecting, false, state, false),
            "{state:?}"
        );
        assert!(ended(state, true, state, false), "cleanup {state:?}");
        assert!(!ended(state, false, state, false), "unchanged {state:?}");
    }
    for active in [
        State::Connecting,
        State::Connected,
        State::Unresponsive,
        State::Reconnecting,
    ] {
        assert!(!ended(active, false, active, false), "active {active:?}");
    }
}

#[test]
fn private_file_is_atomically_replaced_and_contains_the_rendered_logs() {
    let _: fn(&str) -> io::Result<()> = save;
    let f = Fixture::new();
    let log = Log {
        name: "charon.log".into(),
        status: Status::Present,
        modified: Some(123),
        lines: 1,
        text: "redacted\n".into(),
    };
    let data = render(DiagnosticsStatus::Ready, &[log]);
    assert!(data.contains("== charon.log (1 linhas, hora de modificação: 123)"));
    assert!(data.contains("redacted\n"));
    save_at(&f.home, f.uid, &data).unwrap();
    let first = fs::metadata(f.file()).unwrap();
    assert_eq!(first.mode() & 0o7777, 0o600);
    assert_eq!(first.uid(), f.uid);
    assert_eq!(fs::metadata(f.directory()).unwrap().mode() & 0o7777, 0o700);
    save_at(&f.home, f.uid, "second\n").unwrap();
    assert_ne!(first.ino(), fs::metadata(f.file()).unwrap().ino());
    assert_eq!(fs::read_to_string(f.file()).unwrap(), "second\n");
    assert_eq!(fs::read_dir(f.directory()).unwrap().count(), 1);
}
#[test]
fn check_target_rejects_foreign_file_owner_after_directory_admission() {
    let f = Fixture::new();
    save_at(&f.home, f.uid, "fixture diagnostic\n").unwrap();
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(f.directory())
        .unwrap();
    valid_dir(&dir, f.uid, true).expect("fixture bundle directory must be admitted");
    let actual = fs::metadata(f.file()).unwrap();
    assert_eq!(actual.uid(), f.uid);
    assert_eq!(actual.mode() & 0o7777, 0o600);
    assert_eq!(actual.nlink(), 1);
    let expected = Some((actual.dev(), actual.ino()));
    assert_eq!(check_target(&dir, f.uid).unwrap(), expected);
    let other_uid = f
        .uid
        .checked_add(1)
        .expect("fixture UID must have a different value");
    let refused = check_target(&dir, other_uid);
    assert!(
        refused.is_err(),
        "file owned by another UID must be refused"
    );
    assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(check_target(&dir, f.uid).unwrap(), expected);
    assert_eq!(fs::read(f.file()).unwrap(), b"fixture diagnostic\n");
}

#[test]
fn storage_refuses_symlinks_modes_hardlinks_and_wrong_owner() {
    for case in [
        "library-link",
        "support-link",
        "bundle-link",
        "file-link",
        "directory-mode",
        "file-mode",
        "file-hardlink",
        "owner",
    ] {
        let f = Fixture::new();
        let sentinel = f.home.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();
        match case {
            "library-link" => {
                fs::remove_dir(f.home.join("Library/Application Support")).unwrap();
                fs::remove_dir(f.home.join("Library")).unwrap();
                symlink(&sentinel, f.home.join("Library")).unwrap();
            }
            "support-link" => {
                fs::remove_dir(f.home.join("Library/Application Support")).unwrap();
                symlink(&sentinel, f.home.join("Library/Application Support")).unwrap();
            }
            "bundle-link" => symlink(&sentinel, f.directory()).unwrap(),
            _ => {
                save_at(&f.home, f.uid, "before\n").unwrap();
                match case {
                    "file-link" => {
                        fs::remove_file(f.file()).unwrap();
                        symlink(&sentinel, f.file()).unwrap();
                    }
                    "directory-mode" => {
                        fs::set_permissions(f.directory(), fs::Permissions::from_mode(0o755))
                            .unwrap()
                    }
                    "file-mode" => {
                        fs::set_permissions(f.file(), fs::Permissions::from_mode(0o644)).unwrap()
                    }
                    "file-hardlink" => fs::hard_link(f.file(), f.home.join("alias")).unwrap(),
                    _ => {}
                }
            }
        }
        let uid = if case == "owner" {
            f.uid.wrapping_add(1)
        } else {
            f.uid
        };
        assert!(save_at(&f.home, uid, "should not write").is_err(), "{case}");
        assert_eq!(fs::read(sentinel).unwrap(), b"unchanged");
    }
}
#[test]
fn replacing_during_read_never_exposes_partial_content() {
    let f = Fixture::new();
    let old = "a".repeat(32_768);
    let new = "b".repeat(32_768);
    save_at(&f.home, f.uid, &old).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let path = f.file();
    std::thread::scope(|scope| {
        struct Stop(Arc<AtomicBool>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let finish = Stop(stop.clone());
        let done = stop.clone();
        let old_reader = old.clone();
        let new_reader = new.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let reader = scope.spawn(move || {
            assert_eq!(fs::read(&path).unwrap(), old_reader.as_bytes());
            ready_tx.send(()).unwrap();
            let mut samples = 1;
            while !done.load(Ordering::Acquire) {
                let bytes = fs::read(&path).unwrap();
                assert!(bytes == old_reader.as_bytes() || bytes == new_reader.as_bytes());
                samples += 1;
            }
            samples
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        for i in 0..20 {
            save_at(&f.home, f.uid, if i % 2 == 0 { &new } else { &old }).unwrap();
        }
        drop(finish);
        assert!(reader.join().unwrap() > 0);
    });
}
