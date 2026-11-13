use super::*;
use crate::helper::{charon_channel, local_socket::Budget, process::ManagedChild};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Own directory and C fixture. The cleanup guard exists before `cc` runs, so a
/// compile panic also removes the directory.
pub(super) struct Fixture {
    directory: PathBuf,
    executable: PathBuf,
    audit: PathBuf,
}

/// Bounded readiness wait for the inherited FD; never receives or peeks.
pub(super) fn wait_readable(fd: libc::c_int, seconds: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live descriptor and an initialized pollfd.
        let result = unsafe { libc::poll(&mut ready, 1, 50) };
        if result > 0 {
            return true;
        }
        if result == 0 {
            if Instant::now() >= deadline {
                return false;
            }
            continue;
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return false;
        }
    }
}

pub(super) fn await_inherited() -> bool {
    wait_readable(3, 5)
}

/// Reads a pipe to end; shared with the importer parent.
pub(super) fn read_all(pipe: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).unwrap();
    bytes
}

/// Writes one short report line; the child is a dedicated process.
pub(super) fn write_out(bytes: &[u8]) {
    // SAFETY: writes a live byte slice to a live descriptor.
    unsafe { libc::write(1, bytes.as_ptr().cast(), bytes.len()) };
}

/// Reads lines until one contains `needle`; bounded, EINTR-safe, skips the
/// test harness's leading output.
pub(super) fn await_line(pipe: &mut std::process::ChildStdout, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return line;
        }
        let mut ready = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live descriptor and an initialized pollfd.
        let result = unsafe { libc::poll(&mut ready, 1, 50) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return line;
        }
        if result == 0 {
            continue;
        }
        match pipe.read(&mut byte) {
            Ok(0) => return line,
            Ok(_) if byte[0] == b'\n' => {
                if line.contains(needle) {
                    line.push('\n');
                    return line;
                }
                line.clear();
            }
            Ok(_) => line.push(byte[0] as char),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return line,
        }
    }
}

pub(super) fn await_outcome(pipe: &mut std::process::ChildStdout) -> String {
    await_line(pipe, "outcome=")
}

/// Bounded wait with no signal: the predicate decides when the wait is over.
fn poll_until<F: FnMut() -> bool>(seconds: u64, mut done: F) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

impl Fixture {
    pub(super) fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vpnt-charon-channel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            executable: directory.join("channel"),
            audit: directory.join("audit"),
            directory,
        };
        let source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/charon_channel.c");
        let result = Command::new("/usr/bin/cc")
            .arg("-mmacosx-version-min=13.0")
            .args(["-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&fixture.executable)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "charon-channel fixture compile: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700)).unwrap();
        fixture
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(&self.executable);
        command.arg(mode).arg(&self.audit);
        command
    }

    pub(super) fn spawn(&self, mode: &str) -> (ManagedChild, Receiver) {
        charon_channel::spawn(self.command(mode), &self.directory.join("strongswan.conf")).unwrap()
    }

    pub(super) fn spawn_plain(&self, mode: &str) -> ManagedChild {
        let mut command = self.command(mode);
        ManagedChild::spawn(&mut command).unwrap()
    }

    pub(super) fn audit(&self) -> String {
        fs::read_to_string(&self.audit).unwrap_or_default()
    }

    pub(super) fn wait_for(&self, token: &str) -> bool {
        poll_until(5, || self.audit().contains(token))
    }

    pub(super) fn budget(&self) -> Budget {
        Budget::new(Duration::from_secs(2)).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Reaps the original child on every path; never searches for a PID.
pub(super) fn reap(child: &mut ManagedChild) {
    if !poll_until(5, || child.poll().unwrap().is_some()) {
        let _ = child.stop(Duration::from_secs(2));
        assert!(
            child.poll().unwrap().is_some(),
            "fixture child was not reaped"
        );
    }
}

pub(super) fn exit_status(child: &mut ManagedChild) -> std::process::ExitStatus {
    reap(child);
    child.poll().unwrap().unwrap()
}

mod importer;
