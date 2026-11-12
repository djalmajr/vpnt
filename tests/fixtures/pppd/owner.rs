use std::{
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use vpnt::helper::process::ManagedChild;
// This is the same read-only native observer used in production. It never
// signals the PIDs reported by the inherited channel.
#[path = "../../../src/connection/macos/process.rs"]
mod observe;
fn frame(tag: &[u8; 4], pid: u32) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(tag);
    bytes[4..].copy_from_slice(&pid.to_be_bytes());
    bytes
}
fn receive(stream: &mut UnixStream, tag: &[u8; 4]) -> u32 {
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes[..4], tag);
    u32::from_be_bytes(bytes[4..].try_into().unwrap())
}
fn high(fd: i32) -> OwnedFd {
    // SAFETY: duplicate the live borrowed FD to avoid target 3/4 aliasing.
    let value = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    assert!(value >= 10);
    unsafe { OwnedFd::from_raw_fd(value) }
}
struct Owner {
    child: ManagedChild,
    channel: UnixStream,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.channel.shutdown(Shutdown::Write);
        let _ = self.child.stop(Duration::from_millis(20));
        let _ = self.channel.set_read_timeout(Some(Duration::from_secs(3)));
        let mut tail = vec![];
        let _ = self.channel.read_to_end(&mut tail);
    }
}
fn wait_exit(watch: &mut observe::ExitWatch) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !watch.exited().unwrap() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
}
fn wait_marker(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(value) = fs::read_to_string(path)
            && let Ok(pid) = value.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
}
fn main() {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    assert_eq!(args.len(), 4);
    let mode = args[3].to_str().unwrap();
    let (server, capability) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(7)))
        .unwrap();
    let (mut secret, sentinel) = UnixStream::pair().unwrap();
    secret
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let cap = high(capability.as_raw_fd());
    let pass = high(sentinel.as_raw_fd());
    let descriptor = cap.as_raw_fd();
    let password = pass.as_raw_fd();
    let mut command = Command::new(&args[0]);
    command.arg(mode);
    // SAFETY: only async-signal-safe descriptor operations run after fork.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(password, 3) < 0
                || libc::dup2(descriptor, 4) < 0
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
                || libc::fcntl(4, libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = ManagedChild::spawn(&mut command).unwrap();
    drop(cap);
    drop(pass);
    drop(capability);
    drop(sentinel);
    let client_info = observe::Process::read(child.id()).unwrap();
    let mut client_exit = observe::ExitWatch::attach(&client_info.identity).unwrap();
    let mut owner = Owner {
        child,
        channel: server,
    };
    if matches!(
        mode,
        "wrong-peer" | "bad-argv" | "extra-argv" | "production-gate"
    ) {
        assert_eq!(owner.channel.read(&mut [0]).unwrap(), 0);
        assert!(!args[2].exists());
        let status = owner.child.stop(Duration::from_secs(1)).unwrap().status;
        if mode == "production-gate" {
            assert_eq!(status.code(), Some(77));
        }
        wait_exit(&mut client_exit);
        return;
    }
    let supervisor = receive(&mut owner.channel, b"VPS1");
    let supervisor_info = observe::Process::read(supervisor).unwrap();
    assert_eq!(supervisor_info.parent, owner.child.id());
    assert_eq!(supervisor_info.executable, args[1]);
    assert_eq!(supervisor_info.real_uid, client_info.real_uid);
    assert_eq!(supervisor_info.uid, client_info.uid);
    let mut supervisor_exit = observe::ExitWatch::attach(&supervisor_info.identity).unwrap();
    assert!(
        !args[2].exists(),
        "no PPP exec before supervisor permission"
    );
    if mode == "deny-supervisor" {
        owner
            .channel
            .write_all(&frame(b"VPA1", supervisor + 1))
            .unwrap();
        assert_eq!(owner.channel.read(&mut [0]).unwrap(), 0);
        assert!(!args[2].exists());
        wait_exit(&mut supervisor_exit);
        return;
    }
    owner
        .channel
        .write_all(&frame(b"VPA1", supervisor))
        .unwrap();
    let ppp = receive(&mut owner.channel, b"VPB1");
    let preexec = observe::Process::read(ppp).unwrap();
    assert_eq!(preexec.parent, supervisor);
    assert_eq!(preexec.executable, args[1], "child is held before exec");
    let mut ppp_exit = observe::ExitWatch::attach(&preexec.identity).unwrap();
    assert!(!args[2].exists(), "no PPP exec before child permission");
    if mode == "deny-child" {
        owner.channel.write_all(&frame(b"VPC1", ppp + 1)).unwrap();
    } else if mode == "revoke-child" {
        owner.channel.shutdown(Shutdown::Write).unwrap();
    } else {
        owner.channel.write_all(&frame(b"VPC1", ppp)).unwrap();
        if mode != "exec-failure" {
            let actual = wait_marker(&args[2]);
            assert_eq!(actual, ppp);
            if mode != "normal" {
                if mode == "parent-exit" {
                    owner.child.stop(Duration::from_millis(20)).unwrap();
                } else if mode == "extra-control" {
                    owner.channel.write_all(b"unexpected").unwrap();
                } else if mode == "hup" {
                    // The C client closes its own PTY master, as upstream does
                    // on teardown. Its session leader receives the native HUP.
                    owner.child.take_stdin().unwrap().write_all(b"h").unwrap();
                } else {
                    owner.channel.shutdown(Shutdown::Write).unwrap();
                }
            }
        }
    }
    assert_eq!(receive(&mut owner.channel, b"VPF1"), ppp);
    assert!(
        !observe::Process::read(ppp)
            .is_ok_and(|process| process.identity == preexec.identity && process.running),
        "final receipt arrived while the original child was running"
    );
    wait_exit(&mut ppp_exit);
    wait_exit(&mut supervisor_exit);
    if matches!(mode, "deny-child" | "revoke-child" | "exec-failure") {
        assert!(!args[2].exists());
    }
    owner.child.stop(Duration::from_secs(1)).unwrap();
    wait_exit(&mut client_exit);
    // Drain through EOF, including buffered control bytes that the supervisor
    // deliberately treated as revocation. No password capability reached PPP.
    let mut tail = vec![];
    owner.channel.read_to_end(&mut tail).unwrap();
    assert!(tail.is_empty());
    assert_eq!(secret.read(&mut [0]).unwrap(), 0);
}
