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

#[test]
fn linux_client_rejects_relative_executable() {
    use vpnt::helper::client::{Client, Error};
    assert!(matches!(
        Client::linux_for_executable(std::path::Path::new("relative-vpnt")),
        Err(Error::Untrusted)
    ));
    assert!(matches!(
        Client::linux_for_executable(std::path::Path::new("/definitely-not-a-vpnt-binary")),
        Err(Error::Untrusted)
    ));
    let mut existing_relative = PathBuf::new();
    for part in std::env::current_dir().unwrap().components() {
        if matches!(part, std::path::Component::Normal(_)) {
            existing_relative.push("..");
        }
    }
    existing_relative.push("usr/bin/true");
    assert!(existing_relative.is_file());
    assert!(matches!(
        Client::linux_for_executable(&existing_relative),
        Err(Error::Untrusted)
    ));
    let request = AdminRequest {
        id: "relative".into(),
        command: AdminCommand::SaveProfile { profile: profile() },
    };
    assert!(matches!(
        vpnt::helper::admin_client::Admin::linux_for_executable(
            &existing_relative,
            request,
            vpnt::localization::Locale::EnUs,
            Instant::now() + Duration::from_secs(5)
        ),
        Err(vpnt::helper::admin_client::Error::Untrusted)
    ));
}

#[test]
fn linux_client_integration_child() {
    use vpnt::{
        helper::{
            admin_client::Admin,
            client::{Client, linux_build_identity},
        },
        localization::Locale,
    };
    if std::env::var_os("VPNT_CLIENT_TEST_CHILD").is_none() {
        return;
    }
    let expected = format!(
        "{:x}",
        Sha256::digest(fs::read(env!("CARGO_BIN_EXE_vpnt")).unwrap())
    );
    let own_hash = format!(
        "{:x}",
        Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())
    );
    assert_eq!(linux_build_identity(), Some(own_hash));
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_vpnt"));
    fn wait_for(mut f: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(12);
        while !f() {
            assert!(Instant::now() < end, "client condition timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn get_snapshot(client: &mut Client, id: &str) -> Message {
        client
            .send(Request {
                id: id.into(),
                command: RequestCommand::Snapshot {},
            })
            .unwrap();
        let mut found = None;
        wait_for(|| {
            for message in client.poll().unwrap() {
                if matches!(message, Message::Snapshot { .. }) {
                    found = Some(message);
                    return true;
                }
            }
            false
        });
        found.unwrap()
    }
    let mut client = Client::linux_for_executable(executable).unwrap();
    assert!(
        matches!(get_snapshot(&mut client,"first"), Message::Snapshot { profiles,build,.. } if profiles.is_empty() && build == Some(expected.clone()))
    );
    client.close();
    wait_for(|| client.finished());
    let mut admin = Admin::linux_for_executable(
        executable,
        AdminRequest {
            id: "save-client".into(),
            command: AdminCommand::SaveProfile { profile: profile() },
        },
        Locale::EnUs,
        Instant::now() + Duration::from_secs(12),
    )
    .unwrap();
    let mut result = None;
    wait_for(|| {
        result = admin.poll();
        result.is_some()
    });
    assert_eq!(result, Some(Ok(())));
    wait_for(|| admin.finished());
    let mut client = Client::linux_for_executable(executable).unwrap();
    assert!(
        matches!(get_snapshot(&mut client,"second"), Message::Snapshot { profiles,build,.. } if profiles == [profile()] && build == Some(expected))
    );
    client.close();
    wait_for(|| client.finished());

    let root = PathBuf::from(std::env::var_os("XDG_DATA_HOME").unwrap());
    let fake = root.join("fake-vpnt");
    fs::write(&fake, r##"#!/usr/bin/python3
import os,sys
from pathlib import Path
allowed={'PATH','LANG','LC_ALL','HOME','USER','LOGNAME','XDG_DATA_HOME','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS'}
expected={'USER':'fixture-user','LOGNAME':'fixture-log','XDG_CONFIG_HOME':'/fixture/config','XDG_CACHE_HOME':'/fixture/cache','XDG_RUNTIME_DIR':'/fixture/runtime','DBUS_SESSION_BUS_ADDRESS':'unix:path=/fixture/bus'}
ok=set(os.environ).issubset(allowed) and all(os.environ.get(k)==v for k,v in expected.items()) and os.environ.get('VPNT_MUST_NOT_REACH_HELPER') is None and os.environ.get('LANG')=='C' and os.environ.get('LC_ALL')=='C' and os.environ.get('PATH')=='/usr/bin:/bin:/usr/sbin:/sbin' and os.environ.get('HOME')==os.environ.get('XDG_DATA_HOME') and sys.argv[1] == 'helper' and sys.argv[2] in ('runtime','admin')
Path(os.environ['XDG_DATA_HOME'], 'fake-'+sys.argv[2]).write_text('ok' if ok else 'bad')
while os.read(0,1024): pass
"##).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let mut fake_client = Client::linux_for_executable(&fake).unwrap();
    wait_for(|| root.join("fake-runtime").exists());
    assert_eq!(fs::read_to_string(root.join("fake-runtime")).unwrap(), "ok");
    fake_client.close();
    wait_for(|| fake_client.finished());
    let mut fake_admin = Admin::linux_for_executable(
        &fake,
        AdminRequest {
            id: "fake".into(),
            command: AdminCommand::SaveProfile { profile: profile() },
        },
        Locale::EnUs,
        Instant::now() + Duration::from_secs(12),
    )
    .unwrap();
    wait_for(|| root.join("fake-admin").exists());
    assert_eq!(fs::read_to_string(root.join("fake-admin")).unwrap(), "ok");
    fake_admin.close();
    wait_for(|| fake_admin.finished());
}

#[test]
fn linux_clients_use_real_runtime_and_filter_child_environment() {
    let f = Fixture::new();
    let mut p = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "linux_client_integration_child", "--nocapture"])
            .env("VPNT_CLIENT_TEST_CHILD", "1")
            .env("XDG_DATA_HOME", &f.0)
            .env("HOME", &f.0)
            .env("VPNT_MUST_NOT_REACH_HELPER", "fictional")
            .env("USER", "fixture-user")
            .env("LOGNAME", "fixture-log")
            .env("XDG_CONFIG_HOME", "/fixture/config")
            .env("XDG_CACHE_HOME", "/fixture/cache")
            .env("XDG_RUNTIME_DIR", "/fixture/runtime")
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/fixture/bus")
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = p.0.try_wait().unwrap() {
            assert!(status.success(), "client child: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "client child timed out");
        thread::sleep(Duration::from_millis(20));
    }
}
