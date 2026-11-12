#![cfg(unix)]
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    process::Command,
};
use vpnt::{helper::pinentry_channel::PinentryChild, secrets::Secret};

#[test]
fn invalid_credentials_cannot_start_the_requested_child() {
    let directory = std::env::current_dir().unwrap().join("output/fixtures");
    fs::create_dir_all(&directory).unwrap();
    let marker = directory.join(format!("invalid-pinentry-{}", std::process::id()));
    assert!(!marker.exists());
    for value in ["".into(), "x".repeat(257), "bad\nvalue".into()] {
        let mut command = Command::new("/bin/sh");
        // The path is positional data, never interpolated into shell source.
        command
            .args(["-c", "printf unexpected > \"$1\"", "fixture"])
            .arg(&marker);
        assert!(PinentryChild::spawn(command, Secret::from(value)).is_err());
        assert!(!marker.exists());
    }
}

#[test]
fn dropping_the_owner_revokes_a_pending_password_and_reaps_its_child() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'ready\\n'; read -r ignored <&3; exit 0"]);
    let mut child = PinentryChild::spawn(command, Secret::from("fictional-pending")).unwrap();
    let id = child.id();
    let mut stdout = BufReader::new(child.take_stdout().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    drop(child);
    let mut remaining = Vec::new();
    stdout.read_to_end(&mut remaining).unwrap();
    assert!(remaining.is_empty());
    let mut status = 0;
    // SAFETY: id belonged to our child; WNOHANG cannot block, status is valid.
    assert_eq!(
        unsafe { libc::waitpid(id as i32, &mut status, libc::WNOHANG) },
        -1
    );
}
