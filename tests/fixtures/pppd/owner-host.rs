// Runs the actual production host receiver, with fixture-only policy paths.
use std::{
    fs,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use vpnt::{
    helper::{pinentry_channel::PinentryChild, process::ManagedChild},
    secrets::Secret,
};
#[path = "../../../src/helper/local_socket.rs"]
pub mod local_socket;
mod helper {
    pub use super::local_socket;
}
#[path = "../../../src/connection/macos/ppp_control.rs"]
mod ppp_control;
#[path = "../../../src/connection/macos/process.rs"]
mod process;
fn main() {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    assert_eq!(args.len(), 4);
    let mode = args[3].to_str().unwrap();
    let (server, channel) = UnixStream::pair().unwrap();
    let canceled = Arc::new(AtomicBool::new(false));
    let mut command = Command::new(&args[0]);
    command.arg("host");
    let mut client = PinentryChild::spawn_with_supervisor(
        command,
        Secret::from("fixture-host-password"),
        channel.into(),
    )
    .unwrap();
    let mut decoy = None;
    let (client_pid, client_program) = if mode == "foreign-parent" {
        let child = ManagedChild::spawn(Command::new("/bin/sleep").arg("30")).unwrap();
        let result = (child.id(), PathBuf::from("/bin/sleep"));
        decoy = Some(child);
        result
    } else {
        (client.id(), args[0].clone())
    };
    let policy = ppp_control::Policy {
        owner: unsafe { libc::geteuid() },
        client: client_program,
        supervisor: if mode == "wrong-program" {
            args[1].with_extension("not-admitted")
        } else {
            args[1].clone()
        },
        ppp: args[1].parent().unwrap().join("child"),
    };
    let mut host = ppp_control::Control::new(server, client_pid, policy, canceled.clone()).unwrap();
    if mode == "pre-cancel" {
        canceled.store(true, Ordering::Release);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut revoked = false;
    let mut observed_running = false;
    let mut orphan_waited = false;
    loop {
        host.poll().unwrap();
        let marker = fs::read_to_string(&args[2])
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        if let Some(pid) = marker {
            assert!(host.may_have_run(), "exec without retained grant receipt");
            let proof = host.proof().unwrap();
            assert_eq!(proof.child().pid, pid);
            if proof.current().unwrap() {
                observed_running = true;
            }
            if mode != "normal" && !revoked {
                if mode == "orphan" {
                    // The C fixture owns/reaps its supervisor and kills that
                    // Child after the payload marker. The payload self-exits.
                } else if mode == "parent-exit" {
                    client.stop(Duration::from_millis(20)).unwrap();
                }
                canceled.store(true, Ordering::Release);
                host.cancel();
                revoked = true;
            }
        }
        let exited = client.poll().unwrap().is_some();
        let complete = host.complete(exited).unwrap();
        if mode == "orphan" && exited && !complete {
            orphan_waited = true;
        }
        if complete {
            break;
        }
        assert!(Instant::now() < deadline, "host cleanup failed to settle");
        thread::sleep(Duration::from_millis(1));
    }
    if matches!(mode, "foreign-parent" | "wrong-program" | "pre-cancel") {
        if mode != "pre-cancel" {
            assert!(host.failed());
        }
        assert!(!host.may_have_run());
        assert!(!args[2].exists());
    } else {
        assert!(host.may_have_run());
        if !matches!(mode, "normal" | "exec-failure" | "orphan") {
            assert!(observed_running);
        }
    }
    if mode == "orphan" {
        assert!(
            orphan_waited,
            "EOF/client exit must not hide a still-running PPP child"
        );
    }
    if let Some(mut child) = decoy {
        child.stop(Duration::from_millis(20)).unwrap();
    }
    // Owned process cleanup remains available even if the host rejected it.
    client.stop(Duration::from_millis(20)).unwrap();
}
