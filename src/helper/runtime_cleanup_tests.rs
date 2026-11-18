use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vpnt-cleanup-log-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("logs"))
            .unwrap();
        Self(root)
    }
    fn owner(&self) -> Owner {
        Owner {
            uid: uid(),
            profile: "fixture-id".into(),
            generation: 7,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
#[test]
fn cleanup_log_is_private_appends_bounded_lines_and_rate_limits_reasons() {
    let f = Fixture::new();
    let now = Instant::now();
    assert!(due(None, Reason::FenceIncomplete, now));
    assert!(!due(
        Some((Reason::FenceIncomplete, now)),
        Reason::FenceIncomplete,
        now + Duration::from_secs(29)
    ));
    assert!(due(
        Some((Reason::FenceIncomplete, now)),
        Reason::FenceIncomplete,
        now + REPEAT_AFTER
    ));
    assert!(due(
        Some((Reason::FenceIncomplete, now)),
        Reason::ProducerNotStopped,
        now
    ));
    for n in 1..=2 {
        append(&f.0, uid(), &f.owner(), n, Reason::FenceIncomplete).unwrap();
    }
    let path = paths::cleanup_log(&f.0);
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("profile=fixture-id attempt=2 reason=fence_incomplete\n"));
    assert_eq!(&text[2..3], ":");
    assert_eq!(&text[5..6], ":");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(CLEANUP_LOG_MAX_BYTES - 1).unwrap();
    append(&f.0, uid(), &f.owner(), 3, Reason::FenceIncomplete).unwrap();
    assert_eq!(file.metadata().unwrap().len(), CLEANUP_LOG_MAX_BYTES - 1);
    assert_eq!(CLEANUP_LOG_MAX_BYTES, 8 * 1024 * 1024);
}
#[test]
fn cleanup_log_creates_a_missing_private_logs_directory() {
    let f = Fixture::new();
    fs::remove_dir(f.0.join("logs")).unwrap();
    finish_at(&f.0, uid(), &f.owner(), false, Instant::now());
    let logs = fs::symlink_metadata(f.0.join("logs")).unwrap();
    assert!(logs.is_dir());
    assert_eq!(logs.mode() & 0o7777, 0o700);
    let text = fs::read_to_string(paths::cleanup_log(&f.0)).unwrap();
    assert!(text.ends_with("profile=fixture-id attempt=1 reason=observation_failed\n"));
}
#[test]
#[ignore = "child harness executed by cleanup_log_directory_survives_a_restrictive_umask"]
fn cleanup_log_umask_child() {
    let root = std::path::PathBuf::from(std::env::var_os("VPNT_CLEANUP_LOG_ROOT").unwrap());
    assert!(root.starts_with(std::env::temp_dir()));
    // umask is process-wide: only this dedicated child process changes it.
    unsafe { libc::umask(0o100) };
    let owner = Owner {
        uid: uid(),
        profile: "fixture-id".into(),
        generation: 7,
    };
    append(&root, uid(), &owner, 1, Reason::FenceIncomplete).unwrap();
    append(&root, uid(), &owner, 2, Reason::FenceIncomplete).unwrap();
}
#[test]
fn cleanup_log_directory_survives_a_restrictive_umask() {
    let f = Fixture::new();
    fs::remove_dir(f.0.join("logs")).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "helper::runtime::cleanup::tests::cleanup_log_umask_child",
        ])
        .env("VPNT_CLEANUP_LOG_ROOT", &f.0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let logs = fs::symlink_metadata(f.0.join("logs")).unwrap();
    assert_eq!(logs.mode() & 0o7777, 0o700);
    let text = fs::read_to_string(paths::cleanup_log(&f.0)).unwrap();
    assert_eq!(text.lines().count(), 2);
}
#[test]
fn cleanup_log_refuses_symlinks_hardlinks_modes_and_foreign_owner() {
    for change in [
        "symlink",
        "directory-link",
        "directory-mode",
        "mode",
        "hardlink",
        "owner",
    ] {
        let f = Fixture::new();
        let path = paths::cleanup_log(&f.0);
        let sentinel = f.0.join("sentinel");
        fs::write(&sentinel, "unchanged").unwrap();
        if change == "symlink" {
            symlink(&sentinel, &path).unwrap();
        } else if change == "directory-link" {
            fs::remove_dir(f.0.join("logs")).unwrap();
            symlink(&f.0, f.0.join("logs")).unwrap();
        } else {
            append(&f.0, uid(), &f.owner(), 1, Reason::FenceIncomplete).unwrap();
            match change {
                "directory-mode" => {
                    fs::set_permissions(f.0.join("logs"), fs::Permissions::from_mode(0o755))
                        .unwrap()
                }
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "hardlink" => fs::hard_link(&path, f.0.join("alias")).unwrap(),
                _ => {}
            }
        }
        let owner = if change == "owner" {
            uid().wrapping_add(1)
        } else {
            uid()
        };
        assert!(
            append(&f.0, owner, &f.owner(), 2, Reason::ProducerNotStopped).is_err(),
            "{change}"
        );
        assert_eq!(fs::read_to_string(sentinel).unwrap(), "unchanged");
    }
}

#[test]
fn cleanup_log_actual_recorder_emits_changes_and_thirty_second_heartbeats_only() {
    let f = Fixture::new();
    let now = Instant::now();
    DIAGNOSTIC.with(|d| *d.borrow_mut() = Diagnostic::default());
    for (seconds, reason, complete) in [
        (0, Reason::FenceIncomplete, false),
        (1, Reason::FenceIncomplete, false),
        (29, Reason::FenceIncomplete, false),
        (30, Reason::FenceIncomplete, false),
        (31, Reason::ProducerNotStopped, false),
        (32, Reason::ProducerNotStopped, true),
    ] {
        begin();
        mark(reason);
        finish_at(
            &f.0,
            uid(),
            &f.owner(),
            complete,
            now + Duration::from_secs(seconds),
        );
    }
    let text = fs::read_to_string(paths::cleanup_log(&f.0)).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    for (line, n) in lines.iter().zip([1, 4, 5]) {
        assert!(line.contains(&format!("attempt={n} ")));
    }
    assert!(lines[2].ends_with("reason=producer_not_stopped"));
}
#[test]
fn journal_failure_gets_its_own_line_and_never_replaces_the_refusal() {
    let f = Fixture::new();
    let now = Instant::now();
    DIAGNOSTIC.with(|d| *d.borrow_mut() = Diagnostic::default());
    for (seconds, failed, refusal) in [
        (0, true, Some(Reason::RouteLock)),
        (1, true, None),
        (2, false, None),
        (31, true, None),
    ] {
        begin();
        assert!(!journal_failure());
        if failed {
            journal_failed();
        }
        if let Some(reason) = refusal {
            mark(reason);
        }
        assert_eq!(current_reason(), refusal);
        finish_at(
            &f.0,
            uid(),
            &f.owner(),
            refusal.is_none(),
            now + Duration::from_secs(seconds),
        );
    }
    let text = fs::read_to_string(paths::cleanup_log(&f.0)).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[0].ends_with("profile=fixture-id attempt=1 reason=route_lock_failed"));
    assert!(lines[1].ends_with("profile=fixture-id attempt=1 journal=failed"));
    assert!(lines[2].ends_with("profile=fixture-id attempt=4 journal=failed"));
}
#[test]
fn deadline_line_says_whether_a_live_attempt_had_no_journal() {
    let f = Fixture::new();
    deadline_at(&f.0, uid(), true).unwrap();
    deadline_at(&f.0, uid(), false).unwrap();
    let text = fs::read_to_string(paths::cleanup_log(&f.0)).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].ends_with(" exit=deadline unjournaled=yes"));
    assert!(lines[1].ends_with(" exit=deadline unjournaled=no"));
    // The same private-file checks as every append: a foreign owner is refused.
    assert!(deadline_at(&f.0, uid().wrapping_add(1), true).is_err());
}
