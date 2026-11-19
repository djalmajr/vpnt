use std::{
    io::{BufRead, BufReader, Read},
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use vpnt::{helper::pinentry_channel::PinentryChild, secrets::Secret};
fn finish(child: &mut PinentryChild, label: &str) {
    // Guard against a hung consumer only: the base 8 s is enough for every
    // case except case 9, whose natural EOF happens at the production 5 s
    // timeout and gets its own natural-time + 3.5 s window.
    finish_until(child, label, Instant::now() + Duration::from_secs(8));
}
fn finish_until(child: &mut PinentryChild, label: &str, deadline: Instant) {
    let started = Instant::now();
    loop {
        if let Some(status) = child.poll().unwrap() {
            if !status.success() {
                let mut errors = String::new();
                if let Some(mut stderr) = child.take_stderr() {
                    let _ = stderr.read_to_string(&mut errors);
                }
                panic!(
                    "consumer rejected exchange: {label} exit={:?} stderr={errors:?}",
                    status.code()
                );
            }
            break;
        }
        assert!(
            Instant::now() < deadline,
            "consumer deadline after {:?}",
            started.elapsed()
        );
        thread::sleep(Duration::from_millis(2));
    }
}
fn start(consumer: &str, adapter: &str, case: u8) -> PinentryChild {
    let mut command = Command::new(consumer);
    command.args([adapter, &case.to_string()]);
    let value = match case {
        0 => " %fixture+é ".into(),
        1 => "x".repeat(256),
        2 => "é".repeat(128),
        _ => "fixture-must-not-be-delivered".into(),
    };
    PinentryChild::spawn(command, Secret::from(value)).unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let (consumer, adapter, wrong, production) = (&args[1], &args[2], &args[3], &args[4]);
    for case in [0, 1, 2, 3, 4, 6] {
        eprintln!("case {case}");
        finish(&mut start(consumer, adapter, case), &format!("case {case}"));
    }
    eprintln!("case 5");
    let mut revoked = start(consumer, adapter, 5);
    let mut ready = String::new();
    BufReader::new(revoked.take_stdout().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    // Time the server-side revocation from the moment the consumer is about
    // to read, not from when the owner got 'ready': a 3 s consumer pause must
    // not be charged to the product, but a missing close_control still leaves
    // the consumer waiting for the production 5 s timeout.
    let (sender, receiver) = mpsc::channel();
    let stderr = revoked.take_stderr().unwrap();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if let Ok(line) = line {
                let _ = sender.send(line);
            }
        }
    });
    // Well below the checker's 30 s watchdog and shared by both markers: a
    // missing marker must be reported by this fixture, with the consumer's own
    // diagnostic, even while the consumer keeps writing other lines.
    let deadline = Instant::now() + Duration::from_secs(20);
    let wait_marker = |marker: &str| loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "case 5 marker {marker} never arrived within 20 s"
        );
        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(line) if line == marker => return Instant::now(),
            Ok(line) if line.starts_with("REVOKE-FAILED") => {
                panic!("case 5 consumer reported {line}")
            }
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("case 5 marker {marker}: consumer channel disconnected")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    wait_marker("READING");
    let started = Instant::now();
    revoked.revoke_password();
    revoked.revoke_password();
    wait_marker("REVOKED");
    // Measure through the terminal status, not just the consumer's EOF:
    // a late status publication is part of the revocation latency.
    finish(&mut revoked, "case 5");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(3500),
        "case 5 revocation took {elapsed:?} (expected < 3.5 s)"
    );
    reader.join().unwrap();
    eprintln!("case 7");
    finish(&mut start(consumer, wrong, 7), "case 7");
    // This executable is intentionally denied outside its privileged context.
    eprintln!("case 8");
    finish(&mut start(consumer, production, 8), "case 8");
    eprintln!("case 1+2");
    let mut one = start(consumer, adapter, 1);
    let mut two = start(consumer, adapter, 2);
    finish(&mut one, "case 1");
    finish(&mut two, "case 2");
    eprintln!("case 9");
    // An abandoned capability expires, even if its child remains alive.
    let started = Instant::now();
    // Natural EOF is the production 5 s timeout; 3.5 s of supported drift
    // ends the window at 8.5 s. A 4 s pause after EOF (9 s) must fail.
    finish_until(
        &mut start(consumer, adapter, 9),
        "case 9",
        started + Duration::from_millis(8500),
    );
    assert!(started.elapsed() >= Duration::from_secs(4));
}
