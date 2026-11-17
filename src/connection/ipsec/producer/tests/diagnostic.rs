use super::super::diagnostic::{CHARON_LOG_MAX_BYTES, limit_file_size, prepare};
use super::*;
use crate::helper::paths;
use std::os::unix::fs::{MetadataExt, symlink};

// Mutation: omit the child file limit.
#[test]
fn diagnostic_child_stays_alive_after_file_limit_and_rotation_keeps_both_logs_bounded() {
    let fixture = Fixture::new();
    let executable = fixture.directory.join("diagnostic-limit");
    let compiled = std::process::Command::new("/usr/bin/cc")
        .arg("-mmacosx-version-min=13.0")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/connection/ipsec/producer/tests/diagnostic_limit.c"
        ))
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "fixture compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    // SAFETY: UID query has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let path = paths::charon_log(&fixture.directory);
    for attempt in 0..2 {
        prepare(&fixture.directory, uid).unwrap();
        let mut command = std::process::Command::new(&executable);
        command.arg(&path);
        limit_file_size(&mut command);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "fixture: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"alive after repeated EFBIG\n");
        assert_eq!(fs::metadata(&path).unwrap().len(), CHARON_LOG_MAX_BYTES);
        if attempt == 1 {
            assert_eq!(
                fs::metadata(path.with_file_name("charon.previous.log"))
                    .unwrap()
                    .len(),
                CHARON_LOG_MAX_BYTES
            );
        }
    }
}

#[test]
fn diagnostic_preparation_failure_prevents_spawn_without_touching_link_target() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("normal", 1)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    // SAFETY: UID query has no memory preconditions.
    prepare(&fixture.directory, unsafe { libc::geteuid() }).unwrap();
    let path = paths::charon_log(&fixture.directory);
    fs::remove_file(&path).unwrap();
    let target = fixture.directory.join("sentinel");
    fs::write(&target, "unchanged").unwrap();
    symlink(&target, &path).unwrap();
    assert!(matches!(
        peer.open(reservation.owner(), until(), token()),
        Err(Error::Changed)
    ));
    let producer = peer.producer.lock().unwrap();
    assert!(producer.lease.record.child.is_none());
    assert!(!producer.lease.directory.path.join("pid").exists());
    assert_eq!(fs::read_to_string(target).unwrap(), "unchanged");
    assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    drop(producer);
    peer.retire(reservation.owner()).unwrap();
    registry.release(&reservation).unwrap();
}

#[test]
fn diagnostic_log_is_prepared_before_spawn_and_survives_attempt_cleanup() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("normal", 1)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    let path = paths::charon_log(&fixture.directory);
    assert!(!path.exists());
    let conf = fs::read_to_string(
        peer.producer
            .lock()
            .unwrap()
            .lease
            .directory
            .path
            .join(state::CONFIG),
    )
    .unwrap();
    assert!(conf.contains(&format!("path = \"{}\"", path.display())));
    peer.open(reservation.owner(), until(), token()).unwrap();
    assert!(path.is_file());
    fs::write(&path, "fixture diagnostic").unwrap();
    peer.retire(reservation.owner()).unwrap();
    registry.release(&reservation).unwrap();
    assert!(context.store.records().unwrap().is_empty());
    assert_eq!(fs::read_to_string(path).unwrap(), "fixture diagnostic");
}

#[test]
fn diagnostic_configuration_has_exact_options_and_bounded_levels() {
    let fixture = Fixture::new();
    let log = paths::charon_log(&fixture.directory);
    for bound in [None, std::num::NonZeroU16::new(7)] {
        let rendered = match bound {
            Some(index) => config::render_bound(&fixture.directory, &log, index),
            None => config::render(&fixture.directory, &log),
        }
        .unwrap();
        let start = rendered.find(" filelog {").unwrap();
        let end = rendered.find(" syslog {").unwrap();
        let expected = format!(
            " filelog {{\n  diagnostic {{\n   path = \"{}\"\n   append = yes\n   flush_line = yes\n   time_format = %H:%M:%S\n   ike_name = yes\n   default = 0\n   ike = 2\n   cfg = 2\n   chd = 1\n   dmn = 1\n   net = 1\n   knl = 1\n   enc = 0\n   mgr = 0\n   lib = 1\n   asn = 0\n   job = 0\n   esp = 0\n   tls = 0\n   tnc = -1\n   imc = -1\n   imv = -1\n   pts = -1\n  }}\n  stderr {{ default = -1 }}\n }}\n",
            log.display()
        );
        assert_eq!(&rendered[start..end], expected);
        for line in expected.lines() {
            if let Some(level) = line
                .split_once(" = ")
                .and_then(|(_, value)| value.parse::<i32>().ok())
            {
                assert!((-1..=2).contains(&level));
            }
        }
        assert!(rendered.contains(" syslog { daemon { default = -1 } auth { default = -1 } }"));
    }
    assert_eq!(
        paths::charon_log(std::path::Path::new(paths::STATE)),
        std::path::Path::new(paths::STATE).join("logs/charon.log")
    );
}

#[test]
fn diagnostic_rotation_preserves_only_the_previous_attempt_with_private_modes() {
    let fixture = Fixture::new();
    // SAFETY: UID query has no memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let path = paths::charon_log(&fixture.directory);
    let previous = path.with_file_name("charon.previous.log");
    for content in ["first attempt", "second attempt", "third attempt"] {
        prepare(&fixture.directory, uid).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.len(), 0);
        assert_eq!(metadata.nlink(), 1);
        let directory = fs::symlink_metadata(path.parent().unwrap()).unwrap();
        assert_eq!(directory.uid(), uid);
        assert_eq!(directory.mode() & 0o7777, 0o700);
        let expected = match content {
            "first attempt" => None,
            "second attempt" => Some("first attempt"),
            _ => Some("second attempt"),
        };
        assert_eq!(fs::read_to_string(&previous).ok().as_deref(), expected);
        if previous.exists() {
            let meta = fs::symlink_metadata(&previous).unwrap();
            assert_eq!(meta.uid(), uid);
            assert_eq!(meta.mode() & 0o7777, 0o600);
        }
        fs::write(&path, content).unwrap();
    }
}

#[test]
fn diagnostic_refuses_symlinks_wrong_owners_modes_and_hardlinks() {
    for change in [
        "directory-link",
        "directory-mode",
        "owner",
        "current-link",
        "previous-link",
        "file-mode",
        "hardlink",
    ] {
        let fixture = Fixture::new();
        // SAFETY: UID query has no memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let path = paths::charon_log(&fixture.directory);
        let directory = path.parent().unwrap();
        let target = fixture.directory.join("sentinel");
        fs::write(&target, "unchanged").unwrap();
        if change == "directory-link" {
            symlink(&fixture.directory, directory).unwrap();
        } else {
            prepare(&fixture.directory, uid).unwrap();
            match change {
                "directory-mode" => {
                    fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap()
                }
                "current-link" => {
                    fs::remove_file(&path).unwrap();
                    symlink(&target, &path).unwrap();
                }
                "previous-link" => {
                    symlink(&target, path.with_file_name("charon.previous.log")).unwrap()
                }
                "file-mode" => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap()
                }
                "hardlink" => fs::hard_link(&path, fixture.directory.join("alias")).unwrap(),
                _ => {}
            }
        }
        let owner = if change == "owner" {
            uid.wrapping_add(1)
        } else {
            uid
        };
        assert!(prepare(&fixture.directory, owner).is_err(), "{change}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
        assert!(!path.with_file_name("charon.previous.log").exists() || change == "previous-link");
    }
}
