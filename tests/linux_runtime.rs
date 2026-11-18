#![cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[test]
fn non_socket_stdin_is_refused() {
    let status = Command::new(env!("CARGO_BIN_EXE_vpnt"))
        .args(["helper", "runtime"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
}

use sha2::{Digest, Sha256};
use std::{
    fs,
    io::BufReader,
    net::Shutdown,
    os::{
        fd::OwnedFd,
        unix::{fs::DirBuilderExt, net::UnixStream},
    },
    path::PathBuf,
    process::Child,
    thread,
    time::{Duration, Instant},
};
use vpnt::{
    helper::protocol::{
        self, AdminCommand, AdminRequest, Command as RequestCommand, Message, Request,
    },
    model::Profile,
};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache")
            .join(format!(
                "vpnt-runtime-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn start(&self, mode: &str) -> (Process, UnixStream) {
        let (host, child) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_vpnt"))
            .args(["helper", mode])
            .env("XDG_DATA_HOME", &self.0)
            .stdin(Stdio::from(OwnedFd::from(child)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        (Process(child), host)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Process(Child);
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "helper did not exit");
            thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn snapshot(stream: &mut UnixStream, id: &str) -> Message {
    protocol::write_request(
        stream,
        &Request {
            id: id.into(),
            command: RequestCommand::Snapshot {},
        },
    )
    .unwrap();
    protocol::read_message(&mut BufReader::new(stream.try_clone().unwrap()))
        .unwrap()
        .unwrap()
}
fn profile() -> Profile {
    serde_json::from_value(serde_json::json!({"id":"first","name":"First","kind":"ssl","gateway":"vpn.example.test","username":"fixture","networks":[],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
}
#[test]
fn runtime_protocol_lock_and_admin_round_trip() {
    let f = Fixture::new();
    let (mut first, mut stream) = f.start("runtime");
    let hash = format!(
        "{:x}",
        Sha256::digest(fs::read(env!("CARGO_BIN_EXE_vpnt")).unwrap())
    );
    match snapshot(&mut stream, "initial") {
        Message::Snapshot {
            id,
            protocol_version,
            build,
            profiles,
            connections,
            ..
        } => {
            assert_eq!(id, "initial");
            assert_eq!(protocol_version, protocol::VERSION);
            assert_eq!(build, Some(hash.clone()));
            assert!(profiles.is_empty());
            assert!(connections.is_empty());
        }
        other => panic!("unexpected: {other:?}"),
    }
    let (mut second, mut waiting) = f.start("runtime");
    assert!(matches!(
        snapshot(&mut waiting, protocol::WAIT_CAPABILITY_SNAPSHOT_ID),
        Message::PreviousSessionFinishing {
            protocol_version: protocol::VERSION,
            ..
        }
    ));
    second.0.kill().unwrap();
    second.0.wait().unwrap();
    drop(waiting);
    let (mut admin, mut admin_stream) = f.start("admin");
    assert!(matches!(
        protocol::read_message(&mut BufReader::new(admin_stream.try_clone().unwrap())).unwrap(),
        Some(Message::AdminReady {
            protocol_version: protocol::VERSION,
            ..
        })
    ));
    protocol::write_admin_request(
        &mut admin_stream,
        &AdminRequest {
            id: "save".into(),
            command: AdminCommand::SaveProfile { profile: profile() },
        },
    )
    .unwrap();
    admin_stream.shutdown(Shutdown::Write).unwrap();
    assert!(
        matches!(protocol::read_message(&mut BufReader::new(admin_stream.try_clone().unwrap())).unwrap(),Some(Message::Accepted { id }) if id == "save")
    );
    assert!(admin.wait().success());
    drop(admin_stream);
    drop(stream);
    assert!(first.wait().success());
    let (mut next, mut next_stream) = f.start("runtime");
    assert!(
        matches!(snapshot(&mut next_stream,"again"),Message::Snapshot { profiles,build,.. } if profiles == [profile()] && build == Some(hash))
    );
    drop(next_stream);
    assert!(next.wait().success());
}

#[test]
fn runtime_refuses_symlinked_lock_without_touching_target() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let app = f.0.join("vpnt");
    fs::DirBuilder::new().mode(0o700).create(&app).unwrap();
    let profiles = app.join("profiles");
    fs::DirBuilder::new().mode(0o700).create(&profiles).unwrap();
    let target = f.0.join("target");
    fs::write(&target, b"fixture").unwrap();
    symlink(&target, profiles.join("runtime.lock")).unwrap();
    let (mut process, stream) = f.start("runtime");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(matches!(
        protocol::read_message(&mut reader).unwrap(),
        Some(Message::Fatal {
            error: protocol::ErrorCode::UntrustedConfiguration
        })
    ));
    assert_eq!(fs::read(&target).unwrap(), b"fixture");
    drop(reader);
    drop(stream);
    assert_eq!(process.wait().code(), Some(1));
}
