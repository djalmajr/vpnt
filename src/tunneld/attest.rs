//! Resolve the backend supervisor through the system manager.

use super::handshake::{PHASE_TIMEOUT, UnitAttestor, UnitIdentity};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    fmt::Write as _,
    io::{self, Read},
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const BUSCTL: &str = "/usr/bin/busctl";
const SERVICE: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const UNIT_PATH_PREFIX: &str = "/org/freedesktop/systemd1/unit/";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const PIDFD_SLOT: libc::c_int = 3;
// Matches the handshake frame bound and fits even an escaped systemd unit ID.
const MAX_REPLY: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Attest over the local system bus using the packaged host's busctl.
#[derive(Default)]
pub struct SystemdAttestor;

impl UnitAttestor for SystemdAttestor {
    fn attest(&self, pidfd: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
        self.attest_until(pidfd, Instant::now() + PHASE_TIMEOUT)
    }

    fn attest_until(&self, pidfd: BorrowedFd<'_>, deadline: Instant) -> io::Result<UnitIdentity> {
        attest_with_busctl(Path::new(BUSCTL), pidfd, deadline)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply<T> {
    #[serde(rename = "type")]
    signature: String,
    data: T,
}

fn attest_with_busctl(
    busctl: &Path,
    pidfd: BorrowedFd<'_>,
    deadline: Instant,
) -> io::Result<UnitIdentity> {
    let (object, name, lookup_invocation): (String, String, [u8; 16]) = request(
        busctl,
        &[
            "call",
            SERVICE,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "GetUnitByPIDFD",
            "h",
            "3",
        ],
        Some(pidfd),
        "osay",
        deadline,
    )?;
    if name.is_empty() || object != unit_object_path(&name) {
        return Err(invalid("systemd unit name does not match its object path"));
    }

    let invocation: [u8; 16] = request(
        busctl,
        &[
            "get-property",
            SERVICE,
            &object,
            UNIT_INTERFACE,
            "InvocationID",
        ],
        None,
        "ay",
        deadline,
    )?;
    if invocation == [0; 16] || invocation != lookup_invocation {
        return Err(invalid("systemd invocation is absent or changed"));
    }
    let main_pid: u32 = request(
        busctl,
        &[
            "get-property",
            SERVICE,
            &object,
            SERVICE_INTERFACE,
            "MainPID",
        ],
        None,
        "u",
        deadline,
    )?;
    let main_pid = libc::pid_t::try_from(main_pid)
        .ok()
        .filter(|&pid| pid > 0)
        .ok_or_else(|| invalid("systemd unit has no valid MainPID"))?;

    let mut invocation_hex = String::with_capacity(32);
    for byte in invocation {
        write!(invocation_hex, "{byte:02x}").expect("writing to a String");
    }
    remaining(deadline)?;
    Ok(UnitIdentity {
        name,
        invocation: invocation_hex,
        main_pid,
    })
}

fn unit_object_path(name: &str) -> String {
    let mut path = UNIT_PATH_PREFIX.to_owned();
    for (index, byte) in name.bytes().enumerate() {
        if byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit()) {
            path.push(char::from(byte));
        } else {
            write!(path, "_{byte:02x}").expect("writing to a String");
        }
    }
    path
}

fn request<T: DeserializeOwned>(
    busctl: &Path,
    args: &[&str],
    pidfd: Option<BorrowedFd<'_>>,
    signature: &str,
    deadline: Instant,
) -> io::Result<T> {
    let operation = if pidfd.is_some() {
        "GetUnitByPIDFD"
    } else {
        args.last().expect("busctl property name")
    };
    let timeout = remaining(deadline)?.as_nanos().div_ceil(1_000);
    let mut command = Command::new(busctl);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args(["--system", "--json=short"])
        .arg(format!("--timeout={timeout}us"))
        .arg("--")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let raw = pidfd.map(|fd| fd.as_raw_fd());
    // SAFETY: the closure uses async-signal-safe syscalls only, and the
    // borrowed descriptor stays open in the parent through spawn.
    unsafe { command.pre_exec(move || prepare_descriptors(raw)) };
    let mut child = command
        .spawn()
        .map_err(|error| operation_error(operation, error))?;
    let output = match collect(&mut child, deadline) {
        Ok(output) => output,
        Err(error) => {
            // A child still owned by this handle has not had its PID recycled.
            // Always attempt to reap, including if kill reports an error.
            let kill = child.kill();
            let reap = child.wait();
            if let Err(cleanup) = kill.and(reap) {
                return Err(io::Error::new(
                    error.kind(),
                    format!("busctl {operation}: {error}; child cleanup: {cleanup}"),
                ));
            }
            return Err(operation_error(operation, error));
        }
    };
    let reply: Reply<T> = serde_json::from_slice(&output).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("busctl {operation}: {error}"),
        )
    })?;
    if reply.signature != signature {
        return Err(invalid("unexpected busctl reply signature"));
    }
    Ok(reply.data)
}

fn prepare_descriptors(pidfd: Option<libc::c_int>) -> io::Result<()> {
    // Mark inherited FDs CLOEXEC instead of closing them, preserving Rust's
    // exec-error pipe until exec. Only the pidfd slot is then reopened.
    // SAFETY: all syscalls below take scalar arguments.
    unsafe {
        if libc::syscall(
            libc::SYS_close_range,
            PIDFD_SLOT as libc::c_uint,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(fd) = pidfd {
            let result = if fd == PIDFD_SLOT {
                libc::fcntl(fd, libc::F_SETFD, 0)
            } else {
                libc::dup3(fd, PIDFD_SLOT, 0)
            };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn collect(child: &mut Child, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut stdout = child.stdout.take().expect("busctl stdout is a pipe");
    // SAFETY: stdout remains an owned descriptor, and the pipe's read end
    // belongs to this invocation. Blocking reads would bypass the deadline.
    if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut output = Vec::new();
    let mut buffer = [0; MAX_REPLY];
    let mut eof = false;
    loop {
        remaining(deadline)?;
        if !eof {
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) if output.len() + count <= MAX_REPLY => {
                    output.extend_from_slice(&buffer[..count]);
                    continue;
                }
                Ok(_) => return Err(invalid("oversized busctl reply")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(io::Error::other(format!("busctl exited with {status}")));
            }
            if eof {
                return Ok(output);
            }
        }
        thread::sleep(remaining(deadline)?.min(POLL_INTERVAL));
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "systemd attestation deadline expired",
            )
        })
}

fn operation_error(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("busctl {operation}: {error}"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::write_script;
    use std::{
        fs::{self, DirBuilder, File},
        os::{
            fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
            unix::fs::DirBuilderExt,
        },
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    const NAME: &str = "vpnt-tunneld-ipsec@0123456789abcdef0123456789abcdef.service";
    const OBJECT: &str = "/org/freedesktop/systemd1/unit/vpnt_2dtunneld_2dipsec_400123456789abcdef0123456789abcdef_2eservice";
    const INVOCATION: &str = "0102030405060708090a0b0c0d0e0f10";
    const BYTES: &str = "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]";
    const SWITCH: &str = "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17]";

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vpnt-attest-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn script(&self, body: &str) -> PathBuf {
            let path = self.0.join("busctl");
            write_script(&path, &format!("#!/bin/sh\n{body}\n"));
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove this attestation fixture");
        }
    }

    fn pidfd() -> OwnedFd {
        // SAFETY: pidfd_open takes scalar arguments and returns a new FD.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
        // SAFETY: the successful syscall transfers ownership.
        unsafe { OwnedFd::from_raw_fd(fd as i32) }
    }

    fn manager(name: &str, invocation: &str, main_pid: &str, descriptor_check: &str) -> String {
        format!(
            r#"
[ "${{LC_ALL-}}" = C ] || exit 20
[ -z "${{HOME-}}${{DBUS_SYSTEM_BUS_ADDRESS-}}${{XDG_CONFIG_HOME-}}" ] || exit 21
[ "$1" = --system ] && [ "$2" = --json=short ] || exit 22
case "$3" in --timeout=*us) ;; *) exit 23;; esac
[ "$4" = -- ] && [ "$6" = org.freedesktop.systemd1 ] || exit 24
case "$5" in
  call)
    [ "$7" = /org/freedesktop/systemd1 ] &&
    [ "$8" = org.freedesktop.systemd1.Manager ] &&
    [ "$9" = GetUnitByPIDFD ] &&
    [ "${{10}}" = h ] && [ "${{11}}" = 3 ] && [ "$#" = 11 ] || exit 25
    [ -e /proc/self/fdinfo/3 ] || exit 26
    {descriptor_check}
    printf '%s\n' '{{"type":"osay","data":["{OBJECT}","{name}",{BYTES}]}}'
    ;;
  get-property)
    [ ! -e /proc/self/fd/3 ] || exit 29
    [ "$7" = '{OBJECT}' ] && [ "$#" = 9 ] || exit 30
    case "$8/$9" in
      org.freedesktop.systemd1.Unit/InvocationID)
        printf '%s\n' '{{"type":"ay","data":{invocation}}}';;
      org.freedesktop.systemd1.Service/MainPID)
        printf '%s\n' '{{"type":"u","data":{main_pid}}}';;
      *) exit 31;;
    esac
    ;;
  *) exit 32;;
esac
"#
        )
    }

    fn run(body: &str) -> io::Result<UnitIdentity> {
        let fixture = Fixture::new();
        let path = fixture.script(body);
        attest_with_busctl(&path, pidfd().as_fd(), Instant::now() + PHASE_TIMEOUT)
    }

    #[test]
    fn returns_exact_manager_identity_and_only_passes_the_pidfd() {
        let file = File::open("/dev/null").unwrap();
        // SAFETY: F_DUPFD returns an independent, deliberately non-CLOEXEC descriptor.
        let leaked = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(leaked >= 64);
        // SAFETY: F_DUPFD returned a new descriptor.
        let leaked = unsafe { OwnedFd::from_raw_fd(leaked) };
        let check = format!(
            r#"[ ! -e /proc/self/fd/{leaked} ] || exit 33
found=
while IFS= read -r line; do
    case "$line" in Pid:*{pid}) found=yes;; esac
done </proc/self/fdinfo/3
[ "$found" = yes ] || exit 34"#,
            leaked = leaked.as_raw_fd(),
            pid = std::process::id(),
        );
        let identity = run(&manager(NAME, BYTES, "4242", &check)).unwrap();
        assert_eq!(identity.name, NAME);
        assert_eq!(identity.invocation, INVOCATION);
        assert_eq!(identity.main_pid, 4242);
        // SAFETY: the parent still owns the descriptor.
        assert_eq!(unsafe { libc::fcntl(leaked.as_raw_fd(), libc::F_GETFD) }, 0);
    }

    #[test]
    fn refuses_a_unit_name_different_from_the_object_identity() {
        let result = run(&manager(
            "vpnt-tunneld-fortinet@0123456789abcdef0123456789abcdef.service",
            BYTES,
            "4242",
            "",
        ));
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[test]
    fn refuses_stale_invocation_and_invalid_main_pid() {
        for (invocation, pid) in [(SWITCH, "4242"), (BYTES, "0"), (BYTES, "2147483648")] {
            assert!(
                matches!(run(&manager(NAME, invocation, pid, "")), Err(error) if error.kind() == io::ErrorKind::InvalidData)
            );
        }
    }

    #[test]
    fn refuses_malformed_ambiguous_or_failed_replies() {
        for reply in [
            "not json".to_owned(),
            format!(r#"{{"type":"osay","type":"osay","data":["{OBJECT}","{NAME}",{BYTES}]}}"#),
            format!(r#"{{"type":"osay","data":["{OBJECT}","{NAME}",{BYTES},1]}}"#),
            format!(r#"{{"type":"o","data":["{OBJECT}"]}}"#),
        ] {
            assert!(
                matches!(run(&format!("printf '%s\\n' '{reply}'")), Err(error) if error.kind() == io::ErrorKind::InvalidData)
            );
        }
        assert!(matches!(run("exit 37"), Err(error) if error.to_string().contains("37")));
    }

    #[test]
    fn kills_and_reaps_a_child_that_exceeds_the_phase_deadline() {
        let fixture = Fixture::new();
        let path = fixture.script(
            r#"printf '%s\n' "$$" > "$0.pid"
exec /usr/bin/sleep 3"#,
        );
        let start = Instant::now();
        let result = attest_with_busctl(&path, pidfd().as_fd(), start + Duration::from_millis(500));
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert!(start.elapsed() < Duration::from_secs(2));
        let pid: libc::pid_t = fs::read_to_string(path.with_extension("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut status = 0;
        // SAFETY: status is writable and pid identifies the instrumented child.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    }
}
