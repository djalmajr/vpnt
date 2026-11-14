use super::*;
use std::{
    fs,
    os::unix::{fs::DirBuilderExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Own ordinary child and private directory; removed by `Drop` on every path.
struct Fixture {
    directory: PathBuf,
    audit: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vpnt-parent-pipe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        // The cleanup guard exists before the compiler runs, so a compile panic
        // also removes this private directory.
        let fixture = Self {
            audit: directory.join("audit"),
            executable: directory.join("parent_pipe"),
            directory,
        };
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ipsec/parent_pipe.c");
        let result = Command::new("/usr/bin/cc")
            .arg("-mmacosx-version-min=13.0")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg(&source)
            .arg("-o")
            .arg(&fixture.executable)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "parent-pipe fixture compile: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fixture
    }

    /// The real charon spawn path: this is the code under test, not a copy.
    fn spawn(&self) -> ManagedChild {
        let mut command = Command::new(&self.executable);
        command.arg(&self.audit);
        ManagedChild::spawn_charon(&mut command, &self.directory.join("strongswan.conf")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn audit(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Bounded wait for an audit token; never a sleep used as proof of exit.
fn wait_for(path: &Path, token: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if audit(path).contains(token) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}

// Mutations: null charon stdin, a copied/moved parent writer, or an exit path
// that only a signal can produce. The child asserts FIFO/stdout-null itself.
#[test]
fn charon_stdin_is_the_private_parent_pipe_and_eof_stops_the_child() {
    let fixture = Fixture::new();
    let mut child = fixture.spawn();
    let writer = child.take_stdin().expect("charon stdin is a pipe");
    // SAFETY: the descriptor belongs to this live ChildStdin.
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0, "the parent write end must have readable flags");
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "the parent write end must stay CLOEXEC"
    );
    assert!(
        wait_for(&fixture.audit, "ready", Duration::from_secs(5)),
        "child did not pass its stdio assertions and record readiness"
    );
    assert!(
        child.poll().unwrap().is_none(),
        "child exited while the only writer was retained"
    );
    assert!(
        !audit(&fixture.audit).contains("eof"),
        "child observed EOF before the writer was dropped"
    );
    drop(writer);
    assert!(
        wait_for(&fixture.audit, "eof", Duration::from_secs(5)),
        "child did not observe EOF after the writer was dropped"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.poll().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "child did not exit after EOF");
        thread::sleep(Duration::from_millis(5));
    };
    assert!(
        status.success(),
        "EOF must stop the child by a normal exit, got {status:?}"
    );
    assert!(
        audit(&fixture.audit).contains("eof"),
        "the exit was not caused by the observed EOF"
    );
}
