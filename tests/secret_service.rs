#![cfg(target_os = "linux")]

use std::{
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use vpnt::{
    model::VpnKind,
    secret_service::LinuxSecretService,
    secrets::{Credentials, SecretError, SecretStore},
};

const OPT_IN: &str = "VPNT_TEST_SECRET_SERVICE";
const PRIVATE_ROOT: &str = "VPNT_TEST_SECRET_SERVICE_PRIVATE_ROOT";
const BUS: &str = "DBUS_SESSION_BUS_ADDRESS";
const SESSION: &str = "/usr/bin/dbus-run-session";
const DAEMON: &str = "/usr/bin/gnome-keyring-daemon";
const DBUS_SEND: &str = "/usr/bin/dbus-send";

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            self.0.kill().ok();
            self.0.wait().ok();
        }
    }
}

#[test]
fn isolated_secret_service_round_trip() {
    if std::env::var_os(OPT_IN).as_deref() != Some(OsStr::new("1")) {
        eprintln!("skipped: set {OPT_IN}=1 to run on a private D-Bus session");
        return;
    }
    if let Some(path) = [SESSION, DAEMON, DBUS_SEND, "/usr/bin/secret-tool"]
        .into_iter()
        .find(|path| !Path::new(path).is_file())
    {
        eprintln!("skipped: required executable missing at {path}");
        return;
    }
    if let Some(root) = std::env::var_os(PRIVATE_ROOT) {
        run_on_private_bus(Path::new(&root));
        return;
    }

    let root = Path::new("/tmp").join(format!("vpnt-secret-service-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let fixture = Fixture(root);
    for subdir in [
        "home", "data", "runtime", "config", "cache", "tmp", "control",
    ] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(fixture.0.join(subdir))
            .unwrap();
    }
    let config = fixture.0.join("dbus.conf");
    fs::write(
        &config,
        format!(
            "<busconfig><type>session</type><listen>unix:path={}/bus</listen>\
         <auth>EXTERNAL</auth><policy context='default'><allow send_destination='*'/>\
         <allow receive_sender='*'/><allow own='*'/></policy></busconfig>",
            fixture.0.display(),
        ),
    )
    .unwrap();

    let output = Command::new(SESSION)
        .env_clear()
        .env(OPT_IN, "1")
        .env(PRIVATE_ROOT, &fixture.0)
        .env("HOME", fixture.0.join("home"))
        .env("USERPROFILE", fixture.0.join("home"))
        .env("XDG_DATA_HOME", fixture.0.join("data"))
        .env("XDG_RUNTIME_DIR", fixture.0.join("runtime"))
        .env("XDG_CONFIG_HOME", fixture.0.join("config"))
        .env("XDG_CACHE_HOME", fixture.0.join("cache"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .arg(format!("--config-file={}", config.display()))
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "isolated_secret_service_round_trip",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "private Secret Service test failed ({})\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("private D-Bus and temporary GNOME keyring round-trip passed");
}

fn run_on_private_bus(root: &Path) {
    let bus = std::env::var(BUS).unwrap();
    let expected = format!("unix:path={}/bus,guid=", root.display());
    assert!(
        root.parent() == Some(Path::new("/tmp"))
            && root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("vpnt-secret-service-")
            && bus.strip_prefix(&expected).is_some_and(
                |guid| guid.len() == 32 && guid.bytes().all(|byte| byte.is_ascii_hexdigit())
            )
            && std::env::var_os("HOME").as_deref() == Some(root.join("home").as_os_str())
            && std::env::var_os("XDG_DATA_HOME").as_deref() == Some(root.join("data").as_os_str())
            && std::env::var_os("XDG_RUNTIME_DIR").as_deref()
                == Some(root.join("runtime").as_os_str()),
        "refusing to access a Secret Service outside the fixture"
    );

    let mut daemon = Daemon(
        Command::new(DAEMON)
            .args(["--foreground", "--unlock", "--components=secrets"])
            .arg(format!(
                "--control-directory={}",
                root.join("control").display()
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    daemon
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"fixture-unlock")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let output = Command::new(DBUS_SEND)
            .args([
                "--session",
                "--print-reply",
                "--reply-timeout=1000",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                "string:org.freedesktop.secrets",
            ])
            .output()
            .unwrap();
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("boolean true")
        {
            break;
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "fixture keyring daemon exited"
        );
        assert!(
            Instant::now() < deadline,
            "fixture keyring never owned the Secret Service name"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let store = LinuxSecretService::new();
    let id = "--help";
    let kind = VpnKind::Ssl;
    assert!(!store.contains(id, kind).unwrap());
    store
        .save(
            id,
            kind,
            &Credentials {
                password: "fixture-private-service".into(),
                psk: "".into(),
            },
        )
        .unwrap();
    assert!(store.contains(id, kind).unwrap());
    let loaded = store.load(id, kind).unwrap();
    assert!(loaded.password.expose() == "fixture-private-service");
    assert!(loaded.psk.expose().is_empty());
    store.remove(id, kind).unwrap();
    store.remove(id, kind).unwrap();
    assert!(!store.contains(id, kind).unwrap());
    assert_eq!(store.load(id, kind).unwrap_err(), SecretError::Missing);
}
