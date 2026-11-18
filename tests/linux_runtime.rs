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
            command: AdminCommand::SaveProfile {
                profile: profile(),
                ovpn_config: None,
            },
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
        command: AdminCommand::SaveProfile {
            profile: profile(),
            ovpn_config: None,
        },
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
            command: AdminCommand::SaveProfile {
                profile: profile(),
                ovpn_config: None,
            },
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
            command: AdminCommand::SaveProfile {
                profile: profile(),
                ovpn_config: None,
            },
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

const IMPORTED_OVPN: &str =
    "# Name: Fixture  \r\nremote vpn.example.test 1194\t\r\n<ca>\r\nSYNTHETIC-CA\r\n</ca>\r\n";
const NORMALIZED_OVPN: &str =
    "# Name: Fixture\nremote vpn.example.test 1194\n<ca>\nSYNTHETIC-CA\n</ca>\n";

fn ovpn_profile() -> Profile {
    let mut value = serde_json::to_value(profile()).unwrap();
    value["kind"] = "ovpn".into();
    value["username"] = "".into();
    value["port"] = 1194.into();
    value["ovpn"] = serde_json::json!({"certificateId":"01ab","module":"/opt/fixture/token.so"});
    let profile: Profile = serde_json::from_value(value).unwrap();
    assert_eq!(profile.validate(), Ok(()));
    profile
}

fn run_admin(fixture: &Fixture, command: serde_json::Value) -> Message {
    use std::io::Write;
    let (mut process, mut stream) = fixture.start("admin");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert!(matches!(
        protocol::read_message(&mut reader).unwrap(),
        Some(Message::AdminReady { .. })
    ));
    let request = serde_json::json!({"id":"fixture-admin","command":command});
    serde_json::to_writer(&mut stream, &request).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let result = protocol::read_message(&mut reader).unwrap().unwrap();
    assert!(
        process.wait().success(),
        "admin rejected this frame: {result:?}"
    );
    result
}

#[test]
fn admin_persists_normalized_ovpn_before_profile_and_cleans_up() {
    use std::os::unix::fs::{MetadataExt, symlink};
    use vpnt::{helper::protocol::ErrorCode, storage::ProfileStore};

    let fixture = Fixture::new();
    let mut profile_ovpn = ovpn_profile();
    let save = |profile: &Profile, config: Option<&str>| {
        let mut value = serde_json::json!({"type":"save_profile","profile":profile});
        if let Some(config) = config {
            value["ovpn_config"] = config.into();
        }
        run_admin(&fixture, value)
    };
    let root = fixture.0.join("vpnt/profiles");
    let config = root.join("ovpn/first.ovpn");
    use std::os::unix::fs::PermissionsExt;
    let ovpn_dir = root.join("ovpn");
    fs::create_dir_all(&ovpn_dir).unwrap();
    for dir in [root.as_path(), ovpn_dir.as_path()] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let store = ProfileStore::open(&root, fs::metadata(&root).unwrap().uid()).unwrap();
    let target = fixture.0.join("untouched");
    fs::write(&target, "untouched").unwrap();
    symlink(&target, &config).unwrap();
    assert!(matches!(
        save(&profile_ovpn, Some(IMPORTED_OVPN)),
        Message::Failed {
            error: ErrorCode::Unavailable,
            ..
        }
    ));
    assert!(store.load().unwrap().is_empty());
    assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    assert!(fs::symlink_metadata(&config).unwrap().is_symlink());
    fs::remove_file(&config).unwrap();

    assert!(matches!(
        save(&profile_ovpn, None),
        Message::Failed {
            error: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert!(matches!(
        save(&profile_ovpn, Some("up SYNTHETIC-DO-NOT-PRINT")),
        Message::Failed {
            error: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert!(!config.exists());

    assert!(store.load().unwrap().is_empty());

    assert!(matches!(
        save(&profile_ovpn, Some(IMPORTED_OVPN)),
        Message::Accepted { .. }
    ));
    assert_eq!(fs::read_to_string(&config).unwrap(), NORMALIZED_OVPN);
    assert_eq!(fs::metadata(&config).unwrap().mode() & 0o777, 0o600);
    assert_eq!(store.load().unwrap(), [profile_ovpn.clone()]);

    profile_ovpn.name = "Edited fixture".into();
    let guard = store.reserve(&profile_ovpn.id).unwrap();
    assert!(matches!(
        save(
            &profile_ovpn,
            Some(&IMPORTED_OVPN.replace("Fixture", "New"))
        ),
        Message::Failed {
            error: ErrorCode::ProfileBusy,
            ..
        }
    ));
    assert_eq!(fs::read_to_string(&config).unwrap(), NORMALIZED_OVPN);
    drop(guard);
    assert!(matches!(
        save(&profile_ovpn, None),
        Message::Accepted { .. }
    ));
    assert_eq!(store.load().unwrap(), [profile_ovpn.clone()]);
    assert_eq!(fs::read_to_string(&config).unwrap(), NORMALIZED_OVPN);

    let ssl = profile();
    assert!(matches!(
        save(&ssl, Some(IMPORTED_OVPN)),
        Message::Failed {
            error: ErrorCode::InvalidRequest,
            ..
        }
    ));
    assert!(matches!(save(&ssl, None), Message::Accepted { .. }));
    assert!(!config.exists());
    assert_eq!(store.load().unwrap(), [ssl]);
    assert!(matches!(
        save(&profile_ovpn, Some(IMPORTED_OVPN)),
        Message::Accepted { .. }
    ));
    assert!(matches!(
        run_admin(
            &fixture,
            serde_json::json!({"type":"remove_profile","id":"first"})
        ),
        Message::Accepted { .. }
    ));
    assert!(!config.exists());
    assert!(store.load().unwrap().is_empty());
}

#[test]
fn admin_save_protocol_remains_compatible_and_prepares_only_normalized_ovpn() {
    let legacy = profile();
    let expected = format!(
        "{{\"id\":\"legacy\",\"command\":{{\"type\":\"save_profile\",\"profile\":{}}}}}\n",
        serde_json::to_string(&legacy).unwrap()
    );
    let request = protocol::read_admin_request(&mut expected.as_bytes()).unwrap();
    assert!(
        matches!(&request.command, AdminCommand::SaveProfile { profile, ovpn_config: None } if profile == &legacy)
    );
    let mut wire = Vec::new();
    protocol::write_admin_request(&mut wire, &request).unwrap();
    assert_eq!(wire, expected.as_bytes());

    assert!(matches!(
        AdminCommand::for_save(legacy, Some(IMPORTED_OVPN.into())),
        Err("invalid_profile")
    ));
    assert!(matches!(
        AdminCommand::for_save(ovpn_profile(), Some("up SYNTHETIC-DO-NOT-PRINT".into())),
        Err("invalid_ovpn")
    ));
    let request = AdminRequest {
        id: "normalized".into(),
        command: AdminCommand::for_save(ovpn_profile(), Some(IMPORTED_OVPN.into())).unwrap(),
    };
    let mut wire = Vec::new();
    protocol::write_admin_request(&mut wire, &request).unwrap();
    let parsed = protocol::read_admin_request(&mut wire.as_slice()).unwrap();
    assert!(matches!(parsed.command,
        AdminCommand::SaveProfile { profile, ovpn_config: Some(config) }
            if profile == ovpn_profile() && config == NORMALIZED_OVPN
    ));
}

#[test]
fn ovpn_size_boundary_survives_bridge_and_admin() {
    use vpnt::bridge::{self, Command};
    let mut content = "remote vpn.example.test 1194\n<ca>\nx\n</ca>\n".to_string();
    let line = format!("#{}\n", "\"\\".repeat(125));
    while content.len() + line.len() <= 32 * 1024 {
        content.push_str(&line);
    }
    let remaining = 32 * 1024 - content.len();
    if remaining >= 2 {
        content.push('#');
        content.push_str(&"\"".repeat(remaining - 2));
        content.push('\n');
    } else if remaining == 1 {
        content.push('\n');
    }
    assert_eq!(content.len(), 32 * 1024);
    let profile = ovpn_profile();
    let body = serde_json::json!({"id":"size", "command":{"type":"save_profile", "profile":profile, "ovpn_config":content}}).to_string();
    assert!(body.len() > 65_536);
    let request = bridge::parse_request(&body).expect("32 KiB profile must cross bridge");
    let Command::SaveProfile {
        profile,
        ovpn_config,
    } = request.command
    else {
        panic!("wrong command")
    };
    let command = AdminCommand::for_save(profile, ovpn_config).unwrap();
    let fixture = Fixture::new();
    assert!(matches!(
        run_admin(&fixture, serde_json::to_value(command).unwrap()),
        Message::Accepted { .. }
    ));
    let file = fixture.0.join("vpnt/profiles/ovpn/first.ovpn");
    assert_eq!(fs::read_to_string(file).unwrap(), content);
    let mut too_large = content;
    too_large.push('\n');
    let oversized_body = serde_json::json!({"id":"size-over", "command":{"type":"save_profile", "profile":ovpn_profile(), "ovpn_config":too_large}}).to_string();
    let oversized =
        bridge::parse_request(&oversized_body).expect("oversized profile must reach validation");
    let Command::SaveProfile {
        profile,
        ovpn_config,
    } = oversized.command
    else {
        panic!("wrong command")
    };
    assert!(matches!(
        AdminCommand::for_save(profile, ovpn_config),
        Err("invalid_ovpn")
    ));
}

#[cfg(debug_assertions)]
#[test]
fn debug_override_starts_runtime_and_admin_with_matching_build() {
    use vpnt::{
        helper::client::{Client, linux_build_identity},
        localization::Locale,
    };
    if std::env::var_os("VPNT_OVERRIDE_TEST_CHILD").is_some() {
        let executable = std::env::var_os("VPNT_TEST_EXECUTABLE").unwrap();
        let expected = format!("{:x}", Sha256::digest(fs::read(executable).unwrap()));
        assert_eq!(linux_build_identity(), Some(expected));
        let mut client = Client::runtime().unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut ready = false;
        while Instant::now() < deadline && !ready {
            client
                .send(Request {
                    id: "snapshot".into(),
                    command: RequestCommand::Snapshot {},
                })
                .ok();
            thread::sleep(Duration::from_millis(30));
            ready = client
                .poll()
                .unwrap()
                .iter()
                .any(|message| matches!(message, Message::Snapshot { .. }));
        }
        assert!(ready, "runtime did not respond");
        client.close();
        while !client.finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(client.finished());
        let mut admin = vpnt::helper::admin_client::Admin::start(
            AdminRequest {
                id: "save".into(),
                command: AdminCommand::SaveProfile {
                    profile: profile(),
                    ovpn_config: None,
                },
            },
            Locale::EnUs,
            Instant::now() + Duration::from_secs(8),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut result = None;
        while result.is_none() && Instant::now() < deadline {
            result = admin.poll();
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(result, Some(Ok(())));
        return;
    }
    let f = Fixture::new();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "debug_override_starts_runtime_and_admin_with_matching_build",
            "--nocapture",
        ])
        .env("VPNT_OVERRIDE_TEST_CHILD", "1")
        .env("VPNT_TEST_EXECUTABLE", env!("CARGO_BIN_EXE_vpnt"))
        .env("XDG_DATA_HOME", &f.0)
        .env("XDG_CONFIG_HOME", &f.0)
        .env("HOME", &f.0)
        .status()
        .unwrap();
    assert!(status.success(), "debug override child failed: {status}");
}

#[cfg(all(debug_assertions, feature = "desktop"))]
#[test]
fn real_backend_saves_profile_through_bridge() {
    use std::sync::mpsc;
    use vpnt::bridge::parse_request;
    if std::env::var_os("VPNT_BACKEND_TEST_CHILD").is_some() {
        // The helper uses socketpair; prohibit all connect syscalls in this
        // child and its descendants so the production netd path is never reached.
        let filter = [
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_connect as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: 0x00050000 | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut _,
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0,
            "no_new_privs: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
            0,
            "seccomp: {}",
            std::io::Error::last_os_error()
        );
        let (send, recv) = mpsc::channel();
        let backend = vpnt::desktop::TestBackend::new(false, move |reply| {
            let _ = send.send(reply);
        })
        .unwrap();
        let send_request = |id: &str, command: serde_json::Value| {
            let body = serde_json::json!({"id": id, "command":command}).to_string();
            backend
                .send(parse_request(&body).unwrap(), Instant::now())
                .unwrap();
            recv.recv_timeout(Duration::from_secs(15)).unwrap()
        };
        let initial = send_request("initial", serde_json::json!({"type":"get_snapshot"}));
        assert!(
            initial.snapshot.is_some(),
            "initial snapshot: {:?}",
            initial.error
        );
        let saved = send_request(
            "save",
            serde_json::json!({"type":"save_profile", "profile":profile()}),
        );
        assert!(saved.error.is_none(), "save: {:?}", saved.error);
        let after = send_request("after", serde_json::json!({"type":"get_snapshot"}));
        assert!(
            after
                .snapshot
                .unwrap()
                .vpns
                .iter()
                .any(|entry| entry.profile.id == "first")
        );
        drop(backend);
        assert!(
            matches!(
                recv.recv_timeout(Duration::from_secs(5)),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            "actor did not stop"
        );
        let mut check = vpnt::helper::client::Client::runtime().unwrap();
        check
            .send(Request {
                id: protocol::WAIT_CAPABILITY_SNAPSHOT_ID.into(),
                command: RequestCommand::Snapshot {},
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut seen = false;
        while !seen && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
            seen = check
                .poll()
                .unwrap()
                .iter()
                .any(|message| matches!(message, Message::Snapshot { .. }));
        }
        assert!(seen, "runtime lock was not released after backend drop");
        check.close();
        while !check.finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(check.finished(), "verification runtime did not exit");
        return;
    }
    let f = Fixture::new();
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_backend_saves_profile_through_bridge",
            "--nocapture",
        ])
        .env("VPNT_BACKEND_TEST_CHILD", "1")
        .env("VPNT_TEST_EXECUTABLE", env!("CARGO_BIN_EXE_vpnt"))
        .env("XDG_DATA_HOME", &f.0)
        .env("XDG_CONFIG_HOME", &f.0)
        .env("HOME", &f.0)
        .status()
        .unwrap();
    assert!(status.success(), "backend child: {status}");
}

#[test]
fn concurrent_admin_ovpn_saves_leave_matching_profile_and_config() {
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Arc, Barrier};
    let fixture = Fixture::new();
    let barrier = Arc::new(Barrier::new(3));
    let outcomes = thread::scope(|scope| {
        let workers: Vec<_> = ["alpha", "bravo"].into_iter().map(|name| {
            let barrier = barrier.clone(); let fixture = &fixture;
            scope.spawn(move || {
                let mut profile = ovpn_profile(); profile.name = name.into();
                let config = format!("# Name: {name}\nremote vpn.example.test 1194\n<ca>\n{name}\n</ca>\n");
                barrier.wait();
                run_admin(fixture, serde_json::json!({"type":"save_profile", "profile":profile, "ovpn_config":config}))
            })
        }).collect();
        barrier.wait();
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(
        outcomes
            .iter()
            .any(|result| matches!(result, Message::Accepted { .. }))
    );
    assert!(outcomes.iter().all(|result| matches!(
        result,
        Message::Accepted { .. }
            | Message::Failed {
                error: vpnt::helper::protocol::ErrorCode::ProfileBusy,
                ..
            }
    )));
    let root = fixture.0.join("vpnt/profiles");
    let store =
        vpnt::storage::ProfileStore::open(&root, fs::metadata(&root).unwrap().uid()).unwrap();
    let profiles = store.load().unwrap();
    assert_eq!(profiles.len(), 1);
    let config = fs::read_to_string(root.join("ovpn/first.ovpn")).unwrap();
    assert!(config.starts_with(&format!("# Name: {}\n", profiles[0].name)));
    assert!(config.contains(&format!("\n{}\n</ca>", profiles[0].name)));
}

#[test]
fn ovpn_limit_counts_the_added_final_newline() {
    // 32 KiB without a final newline normalizes to 32 KiB + 1: refused by the
    // first inspection, so the admin process never sees a text it would refuse.
    let mut content = "remote vpn.example.test 1194\n<ca>\nx\n</ca>\n".to_owned();
    while content.len() + 200 <= 32 * 1024 {
        content.push_str(&format!("#{}\n", "x".repeat(198)));
    }
    let remaining = 32 * 1024 - content.len();
    if remaining > 0 {
        content.push('#');
        content.push_str(&"x".repeat(remaining - 1));
    }
    assert_eq!(content.len(), 32 * 1024);
    assert!(!content.ends_with('\n'));
    assert!(AdminCommand::for_save(ovpn_profile(), Some(content.clone())).is_err());
    // One byte less, the normalized text fits exactly and reaches the admin.
    content.pop();
    let command = AdminCommand::for_save(ovpn_profile(), Some(content)).unwrap();
    let fixture = Fixture::new();
    assert!(matches!(
        run_admin(&fixture, serde_json::to_value(command).unwrap()),
        Message::Accepted { .. }
    ));
}
