use std::{
    io::{BufRead, BufReader, Read},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use vpnt::{helper::pinentry_channel::PinentryChild, secrets::Secret};
fn finish(child: &mut PinentryChild) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = child.poll().unwrap() {
            if !status.success() {
                let mut errors = String::new();
                child
                    .take_stderr()
                    .unwrap()
                    .read_to_string(&mut errors)
                    .unwrap();
                eprintln!("fixture child errors: {errors}");
            }
            assert!(status.success(), "consumer rejected exchange");
            break;
        }
        assert!(Instant::now() < deadline, "consumer deadline");
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
        finish(&mut start(consumer, adapter, case));
    }
    let mut revoked = start(consumer, adapter, 5);
    let mut ready = String::new();
    BufReader::new(revoked.take_stdout().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    let started = Instant::now();
    revoked.revoke_password();
    revoked.revoke_password();
    finish(&mut revoked);
    assert!(started.elapsed() < Duration::from_secs(1));
    finish(&mut start(consumer, wrong, 7));
    // This executable is intentionally denied outside its privileged context.
    finish(&mut start(consumer, production, 8));
    let mut one = start(consumer, adapter, 1);
    let mut two = start(consumer, adapter, 2);
    finish(&mut one);
    finish(&mut two);
    // An abandoned capability expires, even if its child remains alive.
    let started = Instant::now();
    finish(&mut start(consumer, adapter, 9));
    assert!(started.elapsed() >= Duration::from_secs(4));
}
