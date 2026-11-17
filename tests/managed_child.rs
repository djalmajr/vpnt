#![cfg(unix)]

use std::{
    io::{BufRead, BufReader, Read},
    process::Command,
    time::Duration,
};
use vpnt::helper::process::ManagedChild;

#[test]
fn inherited_environment_and_relative_programs_do_not_reach_the_child() {
    let mut relative = Command::new("sh");
    assert!(ManagedChild::spawn(&mut relative).is_err());
    let mut command = Command::new("/bin/sh");
    command
        .env("VPNT_TEST_INHERITED", "must-not-reach-child")
        .args(["-c", "printf '%s' \"${VPNT_TEST_INHERITED-unset}\""]);
    let mut child = ManagedChild::spawn(&mut command).unwrap();
    let mut output = String::new();
    child
        .take_stdout()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(output, "unset");
    assert!(child.stop(Duration::from_secs(1)).unwrap().status.success());
}

/// Deterministic peer: the SIGTERM handler is registered before `ready`, runs
/// the cleanup callback (marker on stdout) and exits 0, and the wait is
/// `signal.pause()` (no blocking read, no external process to fork or sleep).
const CLEANUP_PEER: &str = "\
import os, signal, sys
def cleanup(signum, frame):
    os.write(1, b'cleanup\\n')
    os._exit(0)
signal.signal(signal.SIGTERM, cleanup)
sys.stdout.write('ready\\n')
sys.stdout.flush()
while True:
    signal.pause()
";

#[test]
fn graceful_stop_allows_the_owned_child_to_run_its_cleanup_handler() {
    let mut command = Command::new("/usr/bin/python3");
    command.args(["-I", "-S", "-c", CLEANUP_PEER]);
    let mut child = ManagedChild::spawn(&mut command).unwrap();
    let mut reader = BufReader::new(child.take_stdout().unwrap());
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready, "ready\n");
    let stopped = child.stop(Duration::from_secs(5)).unwrap();
    assert!(!stopped.escalated);
    assert!(stopped.status.success());
    // Only the handler can emit this marker; spontaneous exit or EOF cannot.
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "cleanup\n");
}

#[test]
fn stop_waits_for_its_owned_child_and_reports_escalation() {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "trap '' TERM; printf 'ready\\n'; while read line; do :; done",
    ]);
    let mut child = ManagedChild::spawn(&mut command).unwrap();
    let mut reader = BufReader::new(child.take_stdout().unwrap());
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready, "ready\n");
    let stopped = child.stop(Duration::from_millis(30)).unwrap();
    assert!(stopped.escalated);
    assert!(!stopped.status.success());
    assert!(child.poll().unwrap().is_some());
    assert!(!child.stop(Duration::ZERO).unwrap().escalated);
}

#[test]
fn dropping_the_process_owner_closes_the_child_without_signalling_by_name() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'ready\\n'; while read line; do :; done"]);
    let mut child = ManagedChild::spawn(&mut command).unwrap();
    let pid = child.id();
    let mut reader = BufReader::new(child.take_stdout().unwrap());
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready, "ready\n");
    drop(child);
    let mut byte = [0];
    assert_eq!(reader.read(&mut byte).unwrap(), 0);
    // The owner already reaped its child; waitpid must not find a remaining child.
    let mut status = 0;
    // SAFETY: status is a valid output pointer and WNOHANG cannot block.
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
}
