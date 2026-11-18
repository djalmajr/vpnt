use super::*;
use crate::preferences::ProbeInterval;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let home = std::env::var_os("HOME").expect("HOME for fixtures");
        let path = PathBuf::from(home).join(format!(
            ".vpnt-preferences-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn backend(&self, exec: &str) -> LinuxBackend {
        LinuxBackend {
            base: self.0.join(".config"),
            exec: executable(Path::new(exec)),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn config_base_prefers_absolute_xdg_and_falls_back_to_absolute_home() {
    let home = Some(OsStr::new("/home/example"));
    assert_eq!(
        config_base(Some(OsStr::new("/settings")), home).unwrap(),
        Path::new("/settings")
    );
    for xdg in [None, Some(OsStr::new("")), Some(OsStr::new("relative"))] {
        assert_eq!(
            config_base(xdg, home).unwrap(),
            Path::new("/home/example/.config")
        );
    }
    assert_eq!(config_base(None, None), Err(Error::Storage));
    assert_eq!(
        config_base(None, Some(OsStr::new("relative"))),
        Err(Error::Storage)
    );
}

#[test]
fn restores_without_writes_and_persists_closed_preferences_with_private_modes() {
    let fixture = Fixture::new();
    let mut backend = fixture.backend("/usr/bin/vpnt");
    assert_eq!(backend.load(), Ok(None));
    let host = Coordinator::restore(fixture.backend("/usr/bin/vpnt")).unwrap();
    assert_eq!(host.current(), Preferences::default());
    assert!(!backend.base.exists());

    let preferences = Preferences {
        interval: ProbeInterval::THIRTY,
        notify: false,
        reconnect: true,
        startup: false,
    };
    backend.save(preferences).unwrap();
    assert_eq!(backend.load(), Ok(Some(preferences)));
    let directory = backend.base.join("vpnt");
    let path = directory.join("preferences.json");
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    let json = serde_json::to_vec(&preferences).unwrap();
    assert_eq!(fs::read(&path).unwrap(), json);
    for malformed in [
        vec![b' '; 1025],
        b"[30,false,true,false]".to_vec(),
        b"{}".to_vec(),
    ] {
        fs::write(&path, malformed).unwrap();
        assert_eq!(backend.load(), Err(Error::Storage));
    }
}

#[test]
fn symlinked_file_or_directory_is_refused_without_touching_target() {
    let fixture = Fixture::new();
    let mut backend = fixture.backend("/usr/bin/vpnt");
    fs::create_dir_all(backend.base.join("vpnt")).unwrap();
    let path = backend.base.join("vpnt/preferences.json");
    let other = fixture.0.join("foreign.json");
    let original = serde_json::to_vec(&Preferences::default()).unwrap();
    fs::write(&other, &original).unwrap();
    symlink(&other, &path).unwrap();
    assert_eq!(backend.load(), Err(Error::Storage));
    assert_eq!(backend.save(Preferences::default()), Err(Error::Storage));
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    assert_eq!(fs::read(&other).unwrap(), original);
    fs::remove_file(&path).unwrap();
    fs::hard_link(&other, &path).unwrap();
    assert_eq!(backend.load(), Err(Error::Storage));
    assert_eq!(backend.save(Preferences::default()), Err(Error::Storage));
    assert_eq!(fs::read(&other).unwrap(), original);

    let relative_target = fixture.0.join("foreign_directory");
    fs::create_dir(&relative_target).unwrap();
    fs::write(relative_target.join("preferences.json"), &original).unwrap();
    fs::remove_file(&path).unwrap();
    fs::remove_dir(backend.base.join("vpnt")).unwrap();
    symlink(&relative_target, backend.base.join("vpnt")).unwrap();
    assert_eq!(backend.load(), Err(Error::Storage));
    assert_eq!(backend.save(Preferences::default()), Err(Error::Storage));
    assert_eq!(
        fs::read(relative_target.join("preferences.json")).unwrap(),
        original
    );
}

#[test]
fn replacing_preferences_leaves_the_old_open_file_intact_and_no_temporary() {
    let fixture = Fixture::new();
    let mut backend = fixture.backend("/usr/bin/vpnt");
    let before = Preferences::default();
    backend.save(before).unwrap();
    let directory = backend.base.join("vpnt");
    let path = directory.join("preferences.json");
    let mut old = File::open(&path).unwrap();
    let after = Preferences {
        reconnect: true,
        ..before
    };
    backend.save(after).unwrap();

    let mut data = Vec::new();
    old.read_to_end(&mut data).unwrap();
    assert_eq!(data, serde_json::to_vec(&before).unwrap());
    assert_ne!(
        old.metadata().unwrap().ino(),
        fs::metadata(&path).unwrap().ino()
    );
    assert_eq!(backend.load(), Ok(Some(after)));
    assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
}

#[test]
fn manages_only_owned_startup_entries_and_respects_hidden() {
    let fixture = Fixture::new();
    let mut backend = fixture.backend("/usr/bin/vpnt");
    assert_eq!(backend.startup_status(), StartupStatus::Disabled);
    assert_eq!(backend.set_startup(true), Ok(StartupStatus::Enabled));
    assert_eq!(backend.startup_status(), StartupStatus::Enabled);
    let directory = backend.base.join("autostart");
    let path = directory.join("vpnt.desktop");
    let expected = concat!(
        "[Desktop Entry]\nType=Application\nName=VPN Tray\nExec=/usr/bin/vpnt\n",
        "Icon=vpnt\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n",
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o755);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    fs::write(&path, format!("{expected}Hidden=true\n")).unwrap();
    assert_eq!(backend.startup_status(), StartupStatus::Disabled);
    assert_eq!(backend.set_startup(false), Ok(StartupStatus::Disabled));
    assert!(!path.exists());
    assert_eq!(backend.set_startup(false), Ok(StartupStatus::Disabled));

    for foreign in [
        expected.replace("Name=VPN Tray", "Name=Foreign App"),
        expected.replace("Exec=/usr/bin/vpnt", "Exec=/usr/bin/different"),
        expected.replace("Exec=/usr/bin/vpnt", "Exec=vpnt --unexpected"),
        expected.replace("Name=VPN Tray", "Name=VPN Tray\nName=Foreign App"),
        expected.replace("Name=VPN Tray", "Name=VPN Tray\nName = Foreign App"),
        expected.replace("[Desktop Entry]", "[Desktop Action Other]"),
        format!("{expected}[Desktop Action Other]\n[Desktop Entry]\nExec=other\n"),
    ] {
        fs::write(&path, &foreign).unwrap();
        assert_eq!(backend.startup_status(), StartupStatus::Disabled);
        assert!(backend.set_startup(false).is_err());
        assert!(backend.set_startup(true).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), foreign);
    }

    fs::remove_file(&path).unwrap();
    let target = fixture.0.join("other.desktop");
    fs::write(&target, expected).unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(backend.startup_status(), StartupStatus::Unavailable);
    assert!(backend.set_startup(false).is_err());
    assert!(backend.set_startup(true).is_err());
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    assert_eq!(fs::read_to_string(&target).unwrap(), expected);
}

#[test]
fn generated_entry_uses_package_command_for_paths_outside_safe_system_paths() {
    let fixture = Fixture::new();
    for path in [
        "/home/example/bin/vpnt",
        "/usr/bin-other/vpnt",
        "/usr/bin/my vpnt",
        "/usr/bin/vpnt%f",
        "/usr/bin/vpnt\"quoted",
        "/usr/bin/vpnt\\esc",
    ] {
        let mut backend = fixture.backend(path);
        assert_eq!(backend.set_startup(true), Ok(StartupStatus::Enabled));
        let entry = fs::read_to_string(backend.base.join("autostart/vpnt.desktop")).unwrap();
        assert!(entry.lines().any(|line| line == "Exec=vpnt"), "{path:?}");
    }
}
