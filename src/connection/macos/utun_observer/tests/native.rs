use super::super::{Error, Expected, observe};
use super::{deadline, open};
use crate::connection::macos::process::{ExitWatch, Process};
use crate::helper::{controller_lock::ControllerLock, process::ManagedChild};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::{ChildStdin, Command},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vpnt-utun-observer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let fixture = Self(directory);
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ipsec/utun_socket.c");
        let program = fixture.program();
        let result = Command::new("/usr/bin/xcrun")
            .args(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "fixture compile: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }

    fn program(&self) -> PathBuf {
        self.0.join("fixture")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn controller() -> (Root, ControllerLock) {
    let uid = unsafe { libc::getuid() };
    let directory = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            ".vpnt-utun-observer-gate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let root = Root(directory);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.0.join(".controller.lock"))
        .unwrap();
    let controller = ControllerLock::fixture(&root.0, uid).unwrap();
    (root, controller)
}

struct ChildGuard {
    child: Option<ManagedChild>,
    stdin: Option<ChildStdin>,
}

impl ChildGuard {
    fn spawn(fixture: &Fixture) -> Self {
        let mut command = Command::new(fixture.program());
        command.arg("child");
        let mut child = ManagedChild::spawn(&mut command).unwrap();
        let stdin = child.take_stdin();
        let stdout = child.take_stdout().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let _fd = line.trim().parse::<i32>().unwrap();
        Self {
            child: Some(child),
            stdin,
        }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn managed(&mut self) -> &mut ManagedChild {
        self.child.as_mut().unwrap()
    }

    fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    fn stop(mut self) {
        self.close_stdin();
        if let Some(mut child) = self.child.take() {
            let _ = child.stop(Duration::from_secs(1));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.close_stdin();
        if let Some(mut child) = self.child.take() {
            let _ = child.stop(Duration::from_secs(1));
        }
    }
}

fn expected(process: &Process) -> Expected<'_> {
    Expected {
        identity: process.identity.clone(),
        parent: process.parent,
        uid: process.uid,
        executable: &process.executable,
    }
}

// Mutation: map a known non-utun socket to `Unavailable`, so the live child is
// no longer reported as having no utun.
#[test]
fn own_udp_child_has_no_utun_interface() {
    let fixture = Fixture::new();
    let (_root, controller) = controller();
    let mut child = ChildGuard::spawn(&fixture);
    let process = Process::read(child.id()).unwrap();
    let cancel = open();
    assert_eq!(
        observe(
            &controller,
            child.managed(),
            &expected(&process),
            deadline(),
            &cancel
        ),
        Err(Error::NotFound)
    );
    child.stop();
}

// Mutation: drop the stored birth-identity comparison, so a wrong identity is
// accepted and the child is reported as having no utun instead of changed.
#[test]
fn wrong_expected_identity_is_changed() {
    let fixture = Fixture::new();
    let (_root, controller) = controller();
    let mut child = ChildGuard::spawn(&fixture);
    let process = Process::read(child.id()).unwrap();
    let mut expected = expected(&process);
    expected.identity.start.0 = expected.identity.start.0.wrapping_add(1);
    let cancel = open();
    assert_eq!(
        observe(&controller, child.managed(), &expected, deadline(), &cancel),
        Err(Error::Changed)
    );
    child.stop();
}

// Mutation: skip controller validation, so a replaced lock file is ignored and
// the observation proceeds instead of failing closed.
#[test]
fn tampered_controller_is_changed() {
    let fixture = Fixture::new();
    let (root, controller) = controller();
    let mut child = ChildGuard::spawn(&fixture);
    let process = Process::read(child.id()).unwrap();
    fs::remove_file(root.0.join(".controller.lock")).unwrap();
    let cancel = open();
    assert_eq!(
        observe(
            &controller,
            child.managed(),
            &expected(&process),
            deadline(),
            &cancel
        ),
        Err(Error::Changed)
    );
    child.stop();
}

// Mutation: admit an exited child (ignore the exit poll and the running bit),
// so the zombie is probed instead of rejected as changed.
#[test]
fn exited_own_child_is_changed() {
    let fixture = Fixture::new();
    let (_root, controller) = controller();
    let mut child = ChildGuard::spawn(&fixture);
    let process = Process::read(child.id()).unwrap();
    let identity = process.identity.clone();
    let mut watch = ExitWatch::attach(&identity).unwrap();
    child.close_stdin();
    let end = Instant::now() + Duration::from_secs(5);
    while !watch.exited().unwrap() {
        assert!(Instant::now() < end, "fixture child did not exit");
        thread::sleep(Duration::from_millis(5));
    }
    let mut expected = expected(&process);
    expected.identity = identity;
    let cancel = open();
    // The child is an unreaped zombie here; the observer must not query it.
    assert_eq!(
        observe(&controller, child.managed(), &expected, deadline(), &cancel),
        Err(Error::Changed)
    );
    child.stop();
}
