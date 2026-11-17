use super::*;
use crate::connection::macos::process::{ExitWatch, Process};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vpnt-utun-socket-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        // Own the guard before compiling so a failed compile still removes it.
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

/// Owned fixture child. Every path closes stdin and reaps; no `Child` leaks
/// when an assertion (or a mutation) fails in the middle of a test.
struct ChildGuard {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    fd: i32,
}

impl ChildGuard {
    fn spawn(fixture: &Fixture) -> Self {
        let mut child = Command::new(fixture.program())
            .arg("child")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let fd = line.trim().parse().unwrap();
        Self {
            child: Some(child),
            stdin,
            fd,
        }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    fn fd(&self) -> i32 {
        self.fd
    }

    fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    fn finish(mut self) -> ExitStatus {
        self.close_stdin();
        self.child.take().unwrap().wait().unwrap()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.close_stdin();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

// Mutation: accept a non-control `soi_kind` and the synthetic wrong-kind case
// decodes as a match, so the shared fixture reports the failing assertion.
#[test]
fn synthetic_sdk_structs_decode_the_utun_shape_and_reject_variants() {
    let fixture = Fixture::new();
    let result = Command::new(fixture.program()).output().unwrap();
    assert!(
        result.status.success(),
        "synthetic fixture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("synthetic ok"));
}

// Mutation: report a known non-utun socket as `Changed`, so the live UDP
// descriptor is no longer distinguished from a changed one.
#[test]
fn own_child_udp_socket_is_not_a_utun_control_socket() {
    let fixture = Fixture::new();
    let child = ChildGuard::spawn(&fixture);
    assert_eq!(observe(child.id(), child.fd()), Err(Error::NotUtun));
    assert_eq!(observe(child.id(), 2048), Err(Error::Changed));
    assert!(child.finish().success());
}

// Mutation: map a gone PID to `Unavailable` instead of `Changed`, so an exited
// own child is no longer reported as changed/gone.
#[test]
fn exited_own_child_descriptor_is_reported_as_changed() {
    let fixture = Fixture::new();
    let mut child = ChildGuard::spawn(&fixture);
    let pid = child.id();
    let identity = Process::read(pid).unwrap().identity;
    // Watch the exit before the pipe closes; the child stays unreaped while
    // `observe` runs (a zombie's PID cannot be reused).
    let mut watch = ExitWatch::attach(&identity).unwrap();
    child.close_stdin();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !watch.exited().unwrap() {
        assert!(Instant::now() < deadline, "fixture child did not exit");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(observe(pid, child.fd()), Err(Error::Changed));
    assert!(child.finish().success());
}

// Mutation: drop the private-ABI size check, so a short/short-declared record
// is accepted and the stamps leak through an `Ok` observation.
#[test]
fn wrapper_rejects_abi_drift_and_redacts_stamps() {
    let size = ABI_SIZE;
    let good = Raw {
        version: ABI_VERSION,
        size,
        status: STATUS_MATCH,
        unit: 4,
        reserved: 0,
        socket: 0x1111_2222_3333_4444,
        pcb: 0x5555_6666_7777_8888,
    };
    let observed = validate(&good, size, STATUS_MATCH).unwrap();
    assert_eq!(observed.unit, 4);
    assert_eq!(observed.socket, 0x1111_2222_3333_4444);
    assert_eq!(observed.pcb, 0x5555_6666_7777_8888);
    let debug = format!("{observed:?}");
    assert!(!debug.contains("1111"), "{debug}");
    assert!(!debug.contains("5555"), "{debug}");

    for drifted in [
        Raw {
            size: size - 1,
            ..good
        },
        Raw {
            version: ABI_VERSION + 1,
            ..good
        },
        Raw {
            reserved: 1,
            ..good
        },
        Raw { unit: 0, ..good },
    ] {
        assert_eq!(validate(&drifted, size, STATUS_MATCH), Err(Error::Abi));
    }
    assert_eq!(
        validate(
            &Raw {
                status: STATUS_ABI,
                ..good
            },
            size,
            STATUS_ABI
        ),
        Err(Error::Abi)
    );
}
