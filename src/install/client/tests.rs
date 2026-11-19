use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
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
    let end = Instant::now() + Duration::from_secs(15);
    while !check() {
        assert!(Instant::now() < end, "condition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}
// Fixture-only guard: slow runners must not turn a setup wait into an
// unbounded hang, and a failure must name the step that stalled.
fn until_step(case: &str, label: &str, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    let end = started + Duration::from_secs(15);
    while !check() {
        assert!(
            Instant::now() < end,
            "condition timed out: {case}/{label} after {:?}",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
// After the child is reaped, publication has no fixture startup to wait for:
// keep the 15 s limit of the base test so a hidden completion is still caught.
fn until_finished(case: &str, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    let end = started + Duration::from_secs(15);
    while !check() {
        assert!(
            Instant::now() < end,
            "condition timed out: {case}/finished after {:?}",
            started.elapsed()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
// The setup guard must explain itself: a stalled fixture is not evidence
// about the product, so include everything the test can still observe.
fn wait_for_marker(case: &str, path: &Path, op: &mut Operation, root: &Path) {
    let started = Instant::now();
    while !path.exists() {
        if started.elapsed() >= Duration::from_secs(15) {
            let result = op.poll();
            let mut files = fs::read_dir(root)
                .map(|entries| {
                    entries
                        .filter_map(Result::ok)
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            files.sort();
            let stderr = fs::read_to_string(root.join("child.stderr")).unwrap_or_default();
            panic!(
                "condition timed out: {case}/waiting after {:?}: result={result:?} finished={} prepared={} files={files:?} stderr={stderr:?}",
                started.elapsed(),
                op.finished(),
                op.prepared()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn component_admission_accepts_599_seconds_and_rejects_expired_or_over_600() {
    for kind in [Kind::Install, Kind::Remove] {
        let command = || Command::new("/usr/bin/true");
        let mut admitted = Operation::fixture(
            kind,
            command(),
            "accepted-599".into(),
            Locale::EnUs,
            Instant::now() + Duration::from_secs(599),
        )
        .expect("599 seconds must be admitted");
        until(|| admitted.prepared());
        admitted.close();
        until(|| admitted.finished());
        assert_eq!(admitted.poll(), Some(Err(Error::Canceled)));
        for duration in [Duration::ZERO, Duration::from_secs(601)] {
            let expires = Instant::now() + duration;
            let rejected =
                Operation::fixture(kind, command(), "refused".into(), Locale::EnUs, expires);
            assert!(
                matches!(rejected, Err(Error::Expired)),
                "zero or >600 seconds must be refused"
            );
        }
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
        Instant::now() + Duration::from_secs(30),
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

fn removal(f: &Fixture, case: &str, expires: Duration) -> Operation {
    let mut command = f.command(include_str!(
        "../../../tests/fixtures/component-client/peer.py"
    ));
    command
        .arg(env!("CARGO_PKG_VERSION"))
        .arg(case)
        .arg(crate::helper::paths::ASKPASS)
        .env("VPNT_TEST_UNTRUSTED", "not inherited");
    let op = Operation::fixture(
        Kind::Remove,
        command,
        "remove-1".into(),
        Locale::PtBr,
        Instant::now() + expires,
    )
    .unwrap();
    until(|| op.prepared());
    op.proceed();
    op
}

#[test]
fn removal_receipt_and_eof_do_not_report_success_before_the_owned_child_has_exited() {
    let held = Fixture::new();
    // Short on purpose: this case must expire while the child is held.
    let mut held_op = removal(&held, "held", Duration::from_secs(2));
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
    let mut op = removal(&f, "held", Duration::from_secs(30));
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
        let mut op = removal(&f, case, Duration::from_secs(30));
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

#[test]
fn removal_reply_wait_keeps_the_absolute_deadline_and_cancellation() {
    for cancel in [false, true] {
        let case = if cancel { "cancel" } else { "deadline" };
        let f = Fixture::new();
        let mut command = f.command(
            r#"import json,pathlib,socket,sys,time
p=pathlib.Path(sys.argv[1]);s=socket.socket(fileno=0)
sys.stderr=open(p/'child.stderr','w')
s.sendall((json.dumps(dict(type='ready',format=1,version=sys.argv[2]))+'\n').encode())
r=json.loads(s.makefile('rb').read())
(p/'waiting').touch()
# The reply is owned by the fixture, not by the test's result: it is sent
# as soon as the test writes 'done' after observing the result. A worker
# that extends or ignores the deadline therefore still receives it and is
# refused by the assertions below. The cap is only a fixture guard.
deadline=time.monotonic()+60
while not (p/'done').exists() and time.monotonic()<deadline:time.sleep(0.005)
if not (p/'done').exists(): raise SystemExit(0)
try:
 s.sendall((json.dumps(dict(type='removed',id=r['id'],component_present=False))+'\n').encode())
except BrokenPipeError:
 pass
s.close()
"#,
        );
        command.arg(env!("CARGO_PKG_VERSION"));
        // Property: Expired must be published at 24 s, before the reply that
        // is released just after the result is observed. 18 s lost a run here
        // (child still starting when the worker closed its socket), so 24 s
        // adds 6 s of setup margin. The 3.5 s ceiling is the shared readiness
        // limit: correct with a supported 3 s pause publishes by 27 s, leaving
        // 0.5 s; a 3 s drift is accepted, while 4 s or more is refused. A
        // worker extended by 10 s or 600 s has no result inside the window;
        // one that reads late publishes a Removed receipt, refused below.
        // The 60 s cap is only a fixture guard.
        let expires = Instant::now() + Duration::from_secs(24);
        let mut op = Operation::fixture(
            Kind::Remove,
            command,
            "bounded-removal".into(),
            Locale::EnUs,
            expires,
        )
        .unwrap();
        until_step(case, "prepared", || op.prepared());
        op.proceed();
        wait_for_marker(case, &f.root.join("waiting"), &mut op, &f.root);
        if cancel {
            op.close();
        }
        let floor = if cancel { Instant::now() } else { expires };
        let ceiling = floor + Duration::from_millis(3500);
        let mut result = None;
        while result.is_none() {
            if let Some(observed) = op.poll() {
                assert!(
                    Instant::now() >= floor,
                    "{case}: deadline violated: {observed:?} published before the floor at {:?} (now {:?})",
                    floor,
                    Instant::now()
                );
                result = Some(observed);
                break;
            }
            assert!(
                Instant::now() < ceiling,
                "{case}: deadline ignored: no result by {:?} (floor {:?})",
                ceiling,
                floor
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            result,
            Some(Err(if cancel {
                Error::Canceled
            } else {
                Error::Expired
            }))
        );
        assert!(
            !op.finished(),
            "a live child must retain exclusion after an error"
        );
        // The child is no longer needed: release its reply and let it exit.
        fs::write(f.root.join("done"), b"").unwrap();
        until_finished(case, || op.finished());
        assert!(op.poll().is_none(), "a late reply cannot publish success");
    }
}

#[test]
fn removal_terminal_eof_can_arrive_after_the_request_write_budget() {
    let f = Fixture::new();
    let mut command = f.command(
        r#"import json,socket,sys,time
s=socket.socket(fileno=0)
s.sendall((json.dumps(dict(type='ready',format=1,version=sys.argv[2]))+'\n').encode())
r=json.loads(s.makefile('rb').read())
s.sendall((json.dumps(dict(type='removed',id=r['id'],component_present=False))+'\n').encode())
time.sleep(5.3)
s.shutdown(socket.SHUT_WR);s.close()
"#,
    );
    command.arg(env!("CARGO_PKG_VERSION"));
    let mut op = Operation::fixture(
        Kind::Remove,
        command,
        "delayed-eof".into(),
        Locale::EnUs,
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    until(|| op.prepared());
    op.proceed();
    let deadline = Instant::now() + Duration::from_secs(8);
    while !op.finished() {
        assert!(Instant::now() < deadline, "remover did not exit");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        op.poll(),
        Some(Ok(Receipt::Removed {
            component_present: false
        }))
    );
}

#[test]
fn removal_client_preserves_previous_session_finishing_from_installer() {
    let fixture = Fixture::new();
    let source = r#"import json,socket
s=socket.socket(fileno=0)
s.sendall((json.dumps({'type':'ready','format':1,'version':'VERSION'})+'\n').encode())
data=b''
while not data.endswith(b'\n'):
    part=s.recv(4096)
    if not part: break
    data+=part
request=json.loads(data)
s.sendall((json.dumps({'type':'failed','id':request['id'],'error':'previous_session_finishing'})+'\n').encode())
s.shutdown(socket.SHUT_WR)
s.close()
"#.replace("VERSION", env!("CARGO_PKG_VERSION"));
    let mut operation = Operation::fixture(
        Kind::Remove,
        fixture.command(&source),
        "remove-finishing".into(),
        Locale::EnUs,
        Instant::now() + Duration::from_secs(4),
    )
    .unwrap();
    until(|| operation.prepared());
    operation.proceed();
    until(|| operation.finished());
    assert_eq!(
        operation.poll(),
        Some(Err(Error::Rejected(
            crate::install::Error::PreviousSessionFinishing
        )))
    );
}
