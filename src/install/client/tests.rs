use super::*;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::current_dir()
            .unwrap()
            .join("output/fixtures")
            .join(format!(
                "vpnt-component-client-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }
    fn command(&self, source: &str) -> Command {
        let path = self.root.join("child.py");
        fs::write(&path, source).unwrap();
        let mut c = Command::new("/usr/bin/python3");
        c.arg(path).arg(&self.root);
        c
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn until(mut check: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(3);
    while !check() {
        assert!(Instant::now() < end, "condition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn admitted_component_process_cannot_start_before_the_controller_releases_its_gate() {
    let f = Fixture::new();
    let mut unreleased = Operation::fixture(
        Kind::Install,
        f.command("import pathlib,sys\npathlib.Path(sys.argv[1], 'started').touch()\n"),
        "unreleased-1".into(),
        Locale::EnUs,
        Instant::now() + Duration::from_millis(200),
    )
    .unwrap();
    until(|| unreleased.finished());
    assert_eq!(unreleased.poll(), Some(Err(Error::Expired)));
    assert!(
        !f.root.join("started").exists(),
        "an unreleased gate must never spawn"
    );
    let command =
        f.command("import pathlib,sys\npathlib.Path(sys.argv[1], 'started').write_text('yes')\n");
    let mut op = Operation::fixture(
        Kind::Install,
        command,
        "install-1".into(),
        Locale::EnUs,
        Instant::now() + Duration::from_secs(2),
    )
    .expect("the operation must prepare asynchronously");
    until(|| op.prepared());
    assert!(!f.root.join("started").exists());
    assert!(op.poll().is_none() && !op.finished());
    op.proceed();
    until(|| op.finished());
    assert!(f.root.join("started").exists());
    assert_eq!(
        op.poll(),
        Some(Ok(Receipt::Installed {
            helper_sha256: "a".repeat(64)
        }))
    );
}

#[test]
fn deadline_or_cancel_before_handoff_never_launches_a_component_process() {
    for cancel in [true, false] {
        let f = Fixture::new();
        let mut op = Operation::fixture(
            Kind::Install,
            f.command("import pathlib,sys\npathlib.Path(sys.argv[1], 'started').touch()\n"),
            "pending-1".into(),
            Locale::EnUs,
            Instant::now() + Duration::from_millis(300),
        )
        .unwrap();
        until(|| op.prepared());
        if cancel {
            op.close();
        }
        until(|| op.finished());
        assert_eq!(
            op.poll(),
            Some(Err(if cancel {
                Error::Canceled
            } else {
                Error::Expired
            }))
        );
        op.proceed();
        assert!(!f.root.join("started").exists());
    }
}

#[test]
fn expired_operation_is_reported_but_its_live_child_is_never_killed_or_treated_as_finished() {
    let f = Fixture::new();
    let source = "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\n(p/'started').touch()\ndeadline=time.monotonic()+5\nwhile not (p/'release').exists() and time.monotonic()<deadline:time.sleep(0.005)\nassert (p/'release').exists()\n(p/'finished').touch()\n";
    let mut op = Operation::fixture(
        Kind::Install,
        f.command(source),
        "held-1".into(),
        Locale::EnUs,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    until(|| op.prepared());
    op.proceed();
    until(|| f.root.join("started").exists());
    let mut reported = None;
    until(|| {
        reported = op.poll();
        reported.is_some()
    });
    assert_eq!(reported, Some(Err(Error::Expired)));
    assert!(!op.finished() && !f.root.join("finished").exists());
    fs::write(f.root.join("release"), b"").unwrap();
    until(|| op.finished());
    assert!(f.root.join("finished").exists());
    assert!(
        op.poll().is_none(),
        "late exit cannot publish a second receipt"
    );
}

fn removal(f: &Fixture, case: &str) -> Operation {
    let mut command = f.command(include_str!(
        "../../../tests/fixtures/component-client/peer.py"
    ));
    command
        .arg(env!("CARGO_PKG_VERSION"))
        .arg(case)
        .env("VPNT_TEST_UNTRUSTED", "not inherited");
    let op = Operation::fixture(
        Kind::Remove,
        command,
        "remove-1".into(),
        Locale::PtBr,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    until(|| op.prepared());
    op.proceed();
    op
}

#[test]
fn removal_receipt_and_eof_do_not_report_success_before_the_owned_child_has_exited() {
    let held = Fixture::new();
    let mut held_op = removal(&held, "held");
    let mut premature = None;
    until(|| {
        premature = held_op.poll();
        premature.is_some()
    });
    assert_eq!(
        premature,
        Some(Err(Error::Expired)),
        "a receipt cannot complete while its child remains alive"
    );
    assert!(!held_op.finished());
    fs::write(held.root.join("release"), b"").unwrap();
    until(|| held_op.finished());
    assert!(
        held_op.poll().is_none(),
        "exit after expiry cannot publish again"
    );
    let f = Fixture::new();
    let mut op = removal(&f, "held");
    until(|| f.root.join("receipt").exists());
    assert!(!op.finished() && op.poll().is_none());
    let request: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root.join("request")).unwrap()).unwrap();
    assert_eq!(request, serde_json::json!({"id":"remove-1"}));
    fs::write(f.root.join("release"), b"").unwrap();
    until(|| op.finished());
    assert_eq!(
        op.poll(),
        Some(Ok(Receipt::Removed {
            component_present: true
        }))
    );
}

#[test]
fn incompatible_wrong_extra_or_excessive_removal_replies_never_commit_and_exit_must_succeed() {
    for case in [
        "format",
        "version",
        "id",
        "unknown",
        "extra",
        "oversized",
        "exit",
    ] {
        let f = Fixture::new();
        let mut op = removal(&f, case);
        until(|| op.finished());
        let expected = match case {
            "format" | "version" => Error::Incompatible,
            "exit" => Error::Unavailable,
            _ => Error::InvalidReply,
        };
        assert_eq!(op.poll(), Some(Err(expected)), "{case}");
    }
}

#[test]
fn component_launches_have_fixed_programs_arguments_and_no_shell_or_saved_state_reset() {
    let package = std::path::Path::new("/private/fixture/package $(not-a-command).pkg");
    let install = plan::install_command(package);
    assert_eq!(install.get_program(), "/usr/bin/open");
    assert_eq!(
        install.get_args().collect::<Vec<_>>(),
        [
            "-W",
            "-n",
            "-b",
            "com.apple.installer",
            package.to_str().unwrap()
        ]
    );
    let remove = plan::remove_command();
    assert_eq!(remove.get_program(), "/usr/bin/sudo");
    assert_eq!(
        remove.get_args().collect::<Vec<_>>(),
        ["-A", "-k", "--", crate::helper::paths::INSTALLER, "remove"]
    );
}
