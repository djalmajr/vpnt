use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: std::path::PathBuf,
    uid: u32,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "vpnt-diagnostics-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("logs")).unwrap();
        fs::set_permissions(root.join("logs"), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            root,
            uid: unsafe { libc::geteuid() },
        }
    }
    fn put(&self, name: &str, bytes: &[u8]) {
        let path = self.root.join("logs").join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn read(&self) -> Vec<Log> {
        collect(&self.root, self.uid, || true).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn admission_precedes_all_log_access_and_missing_are_not_fatal() {
    let f = Fixture::new();
    let bad_path = f.root.join("not-a-directory");
    fs::write(&bad_path, b"sentinel").unwrap();
    assert!(collect(&bad_path, f.uid, || false).is_none());
    let missing = f.read();
    assert_eq!(missing.len(), 4);
    assert!(
        missing
            .iter()
            .all(|item| item.status == Status::Missing && item.text.is_empty())
    );
    fs::remove_dir(f.root.join("logs")).unwrap();
    assert!(f.read().iter().all(|item| item.status == Status::Missing));
    symlink(&bad_path, f.root.join("logs")).unwrap();
    assert!(
        f.read()
            .iter()
            .all(|item| item.status == Status::Unavailable)
    );
    assert_eq!(fs::read(bad_path).unwrap(), b"sentinel");
}

#[test]
fn four_fixed_files_are_bounded_and_use_shared_keyword_redaction() {
    let f = Fixture::new();
    for name in [
        "openfortivpn.log",
        "openfortivpn.previous.log",
        "charon.log",
        "charon.previous.log",
    ] {
        let mut text = String::new();
        for i in 0..230 {
            text.push_str(&format!("line-{i}\n"));
        }
        text.push_str("ToKeN fictional-value\nlast visible\n");
        f.put(name, text.as_bytes());
    }
    let logs = f.read();
    for log in logs {
        assert_eq!(log.status, Status::Present, "{}", log.name);
        assert_eq!(log.lines, 200);
        assert!(log.text.len() <= 65_536);
        assert!(log.text.contains(REDACTED_LINE));
        assert!(!log.text.contains("fictional-value"));
        assert!(log.text.contains("last visible"));
        assert!(!log.text.contains("line-0\n"));
    }
}

#[test]
fn partial_first_line_is_discarded_before_redaction() {
    let f = Fixture::new();
    let mut line = b"password ".to_vec();
    line.extend(std::iter::repeat_n(b'x', 70_000));
    line.extend_from_slice(b"\nvisible\n");
    f.put("charon.log", &line);
    let logs = f.read();
    let log = &logs[2];
    assert_eq!(log.text, "visible\n");
    assert_eq!(log.lines, 1);
}

#[test]
fn incomplete_last_line_is_never_published() {
    let f = Fixture::new();
    f.put("charon.log", b"complete\npartial-value");
    let logs = f.read();
    assert_eq!(logs[2].text, "complete\n");
    assert_eq!(logs[2].lines, 1);
}

#[test]
fn read_log_rejects_foreign_file_owner_after_directory_admission() {
    let f = Fixture::new();
    f.put("charon.log", b"fixture log\n");
    let state = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&f.root)
        .unwrap();
    assert!(directory(&state, f.uid), "fixture state must be admitted");
    let logs = open_at(
        &state,
        c"logs",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
    .unwrap();
    assert!(
        directory(&logs, f.uid),
        "fixture logs directory must be admitted"
    );
    let actual = fs::metadata(f.root.join("logs/charon.log")).unwrap();
    assert_eq!(actual.uid(), f.uid);
    assert_eq!(actual.mode() & 0o7777, 0o600);
    assert_eq!(actual.nlink(), 1);
    let positive = read_log(&logs, f.uid, "charon.log");
    assert_eq!(positive.status, Status::Present);
    assert_eq!(positive.text, "fixture log\n");
    assert_eq!(positive.lines, 1);
    let other_uid = f
        .uid
        .checked_add(1)
        .expect("fixture UID must have a different value");
    let refused = read_log(&logs, other_uid, "charon.log");
    assert_eq!(refused.status, Status::Unavailable);
    assert!(refused.text.is_empty());
    assert_eq!(refused.lines, 0);
    assert_eq!(refused.modified, None);
    let control = read_log(&logs, f.uid, "charon.log");
    assert_eq!(control.status, Status::Present);
    assert_eq!(control.text, positive.text);
    assert_eq!(
        fs::metadata(f.root.join("logs/charon.log")).unwrap().ino(),
        actual.ino()
    );
}

#[test]
fn links_modes_hardlinks_and_wrong_owner_do_not_read_target() {
    for case in ["link", "mode", "hardlink", "owner"] {
        let f = Fixture::new();
        let target = f.root.join("sentinel");
        fs::write(&target, b"sensitive sentinel").unwrap();
        let path = f.root.join("logs/charon.log");
        match case {
            "link" => symlink(&target, &path).unwrap(),
            "mode" => {
                f.put("charon.log", b"sensitive sentinel");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "hardlink" => {
                f.put("charon.log", b"sensitive sentinel");
                fs::hard_link(&path, f.root.join("alias")).unwrap();
            }
            _ => f.put("charon.log", b"sensitive sentinel"),
        }
        let owner = if case == "owner" {
            f.uid.wrapping_add(1)
        } else {
            f.uid
        };
        let logs = collect(&f.root, owner, || true).unwrap();
        assert_eq!(logs[2].status, Status::Unavailable, "{case}");
        assert!(logs[2].text.is_empty(), "{case}");
        assert_eq!(fs::read(target).unwrap(), b"sensitive sentinel");
    }
}
