//! The openfortivpn and the pinentry are Python fixtures: they record what the
//! supervisor gave them (argv, environment, descriptors) in the scratch
//! directory, and the tests read it from outside.
use super::*;
use crate::test_support::write_script;
use crate::tunneld::handshake::{AuthenticatedChannel, Backend, authenticated_pair_for_tests};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    os::{
        fd::AsFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
};

const PIN: [u8; 32] = [0xab; 32];
const GENERATION: &str = "0123456789abcdef0123456789abcdef";
const INVOCATION: &str = "fedcba9876543210fedcba9876543210";
const PASSWORD: &str = "pw-SENTINEL-4f9c";
const HELPER_ENV: &str = "VPNT_FORTINET_INSTANCE_HELPER";
const WAIT: Duration = Duration::from_secs(10);

fn credential_frame(password: &str) -> Vec<u8> {
    let mut frame = vec![MESSAGE_CREDENTIAL];
    frame.extend_from_slice(&(password.len() as u16).to_be_bytes());
    frame.extend_from_slice(password.as_bytes());
    frame
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vpnt-fortinet-instance-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn json(&self, name: &str) -> Value {
        wait_for(&self.path(name));
        serde_json::from_slice(&fs::read(self.path(name)).unwrap()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + WAIT;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Dead or a zombie that nobody has reaped yet.
fn gone(pid: i64) -> bool {
    let deadline = Instant::now() + WAIT;
    loop {
        let state = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit(')').next().map(str::to_owned));
        if state.is_none_or(|rest| rest.trim_start().starts_with('Z')) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// One end of a `SOCK_SEQPACKET` pair, like the authenticated channel.
struct Seq(OwnedFd);

impl Seq {
    fn pair() -> (Self, Self) {
        let mut fds = [-1; 2];
        // SAFETY: socketpair fills the two descriptors.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0);
        // SAFETY: both descriptors are fresh and owned here.
        unsafe {
            (
                Self(OwnedFd::from_raw_fd(fds[0])),
                Self(OwnedFd::from_raw_fd(fds[1])),
            )
        }
    }

    fn put(&self, bytes: &[u8]) {
        // SAFETY: bytes is readable for its length.
        let count = unsafe {
            libc::send(
                self.0.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(
            count,
            bytes.len() as isize,
            "{}",
            io::Error::last_os_error()
        );
    }

    /// `Ok(None)` on timeout, `Err` on EOF.
    fn take(&self, limit: Duration) -> io::Result<Option<Vec<u8>>> {
        let mut fds = [poll_entry(self.0.as_raw_fd())];
        poll_fds(&mut fds, limit)?;
        if fds[0].revents == 0 {
            return Ok(None);
        }
        let mut bytes = vec![0; MAX_DATAGRAM];
        // SAFETY: bytes is writable for its length.
        let count = unsafe {
            libc::recv(
                self.0.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        match count {
            0 => Err(io::ErrorKind::UnexpectedEof.into()),
            ..0 => Err(io::Error::last_os_error()),
            count => {
                bytes.truncate(count as usize);
                Ok(Some(bytes))
            }
        }
    }

    fn credential(&self, password: &str) {
        self.put(&credential_frame(password));
    }

    fn stop(&self) {
        self.put(&[MESSAGE_STOP]);
    }

    /// Events up to and including `exited`; fewer when the peer goes away.
    fn events(&self) -> Vec<Value> {
        let mut events = Vec::new();
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            let Ok(Some(bytes)) = self.take(Duration::from_millis(100)) else {
                continue;
            };
            let event: Value = serde_json::from_slice(&bytes).unwrap();
            let done = event["event"] == "exited";
            events.push(event);
            if done {
                break;
            }
        }
        events
    }
}

impl Channel for Seq {
    fn fd(&self) -> io::Result<BorrowedFd<'_>> {
        Ok(self.0.as_fd())
    }

    fn receive(&mut self) -> io::Result<Datagram> {
        self.take(Duration::ZERO)?
            .map(Datagram::from_vec)
            .ok_or_else(|| io::ErrorKind::WouldBlock.into())
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.put(bytes);
        Ok(())
    }
}

/// Stands in for the shared parser: it understands only the few lines these
/// tests print. The real parser is `connection::ssl_output`, see the report.
#[derive(Default)]
struct LineObserver {
    seen: Arc<Mutex<Observation>>,
    readers: Vec<JoinHandle<()>>,
    expected: Option<String>,
}

impl Observer for LineObserver {
    fn expect_interface(&mut self, name: &str) -> io::Result<()> {
        self.expected = Some(name.to_owned());
        Ok(())
    }

    fn attach(&mut self, pipe: File) -> io::Result<()> {
        use std::io::{BufRead, BufReader};
        let seen = Arc::clone(&self.seen);
        let expected = self.expected.clone();
        self.readers.push(thread::spawn(move || {
            for line in BufReader::new(pipe).split(b'\n').map_while(Result::ok) {
                let line = String::from_utf8_lossy(&line).into_owned();
                let mut seen = seen.lock().unwrap();
                if let Some(name) = line
                    .strip_prefix("INFO:   Interface ")
                    .and_then(|rest| rest.strip_suffix(" is UP."))
                {
                    if expected.as_deref().is_none_or(|expected| expected == name) {
                        seen.candidate = Some(name.to_owned());
                    } else {
                        seen.interface_mismatch = true;
                    }
                } else if let Some(address) = line.strip_prefix("INFO:   vpnt: dns-server ") {
                    seen.dns_servers.push(address.parse().unwrap());
                } else if let Some(name) = line.strip_prefix("INFO:   vpnt: dns-domain ") {
                    seen.dns_domains.push(name.to_owned());
                } else if let Some(route) = line.strip_prefix("INFO:   vpnt: split-route ") {
                    seen.split
                        .push((route.split('/').next().unwrap().parse().unwrap(), 8));
                } else if line.starts_with("ERROR:  Could not authenticate") {
                    seen.failure = Some(Failure::CredentialsRejected);
                }
            }
        }));
        Ok(())
    }

    fn snapshot(&self) -> Observation {
        self.seen.lock().unwrap().clone()
    }

    /// Bounded, like the real parser: a descendant that kept the pipe open must
    /// not hold the supervisor (or hide that it was left alive).
    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_millis(500);
        for reader in self.readers.drain(..) {
            while !reader.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            if reader.is_finished() {
                reader.join().unwrap();
            }
        }
    }
}

fn params(pin: Option<[u8; 32]>) -> Params {
    Params::new(
        Endpoint::new("vpn.example.test".into(), 10443).unwrap(),
        "alice".into(),
        pin,
        Binding {
            interface: "eth0".into(),
            index: 7,
            gateway: Ipv4Addr::new(192, 0, 2, 10),
        },
        Params::default_pppd_ifname(1),
        "10.99.0.0/24".parse().unwrap(),
    )
    .unwrap()
}

const PREAMBLE: &str = r#"#!/usr/bin/python3
import json, os, signal, socket, subprocess, sys, time
D = "@DIR@"
def fds():
    out = {}
    for n in os.listdir("/proc/self/fd"):
        try:
            t = os.readlink("/proc/self/fd/" + n)
        except OSError:
            continue
        if not t.endswith("/fd"):
            out[n] = t
    return out
def put(name, value):
    with open(D + "/" + name + ".tmp", "w") as f:
        json.dump(value, f)
    os.rename(D + "/" + name + ".tmp", D + "/" + name)
def raw(path):
    with open(path, "rb") as f:
        return f.read().decode("latin1")
"#;

const CLIENT: &str = r#"
put("client", {"argv": sys.argv[1:], "fds": fds(), "pid": os.getpid(),
    "pgid": os.getpgrp(), "cmdline": raw("/proc/self/cmdline"),
    "environ": raw("/proc/self/environ"), "stdin": os.readlink("/proc/self/fd/0")})
def pin(tag):
    program = [a for a in sys.argv if a.startswith("--pinentry=")][0][len("--pinentry="):]
    return subprocess.run([program, tag], pass_fds=(3,), stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL).returncode
def idle():
    while True:
        time.sleep(0.05)
"#;

const PINENTRY_FIXTURE: &str = r#"
tag = sys.argv[1]
result = {"fds": fds(), "password": None, "error": None}
try:
    s = socket.socket(fileno=3)
    s.sendall(b"VPT1" + os.getppid().to_bytes(4, "big"))
    s.shutdown(socket.SHUT_WR)
    def take(n):
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                raise EOFError("short")
            b += c
        return b
    result["password"] = take(int.from_bytes(take(2), "big")).decode()
    if s.recv(1):
        raise ValueError("trailing")
except Exception as e:
    result["error"] = type(e).__name__
put("pinentry." + tag, result)
"#;

/// Writes the fixtures and returns `(client, pinentry)` paths.
fn fixtures(scratch: &Scratch, body: &str) -> (PathBuf, PathBuf) {
    let preamble = PREAMBLE.replace("@DIR@", scratch.0.to_str().unwrap());
    let client = scratch.path("openfortivpn");
    let pinentry = scratch.path("vpnt-pinentry");
    write_script(&client, &format!("{preamble}{CLIENT}{body}"));
    write_script(&pinentry, &format!("{preamble}{PINENTRY_FIXTURE}"));
    (client, pinentry)
}

fn limits(grace: Duration) -> Limits {
    Limits {
        credential_wait: Duration::from_secs(5),
        grace,
        kill_wait: Duration::from_secs(5),
    }
}

struct Instance {
    writer: Seq,
    thread: JoinHandle<io::Result<Exit>>,
}

impl Instance {
    fn start(scratch: &Scratch, body: &str, params: Params, grace: Duration) -> Self {
        Self::start_with(scratch, body, params, grace, LineObserver::default())
    }

    fn start_with(
        scratch: &Scratch,
        body: &str,
        params: Params,
        grace: Duration,
        mut observer: impl Observer + Send + 'static,
    ) -> Self {
        let (client, pinentry) = fixtures(scratch, body);
        let (instance, writer) = Seq::pair();
        let thread = thread::spawn(move || {
            let mut instance = instance;
            run_with(
                &mut instance,
                params,
                &mut observer,
                Config {
                    client: client.to_str().unwrap(),
                    pinentry: pinentry.to_str().unwrap(),
                    limits: limits(grace),
                    own_process: false,
                },
            )
        });
        Self { writer, thread }
    }

    /// A run that does not end is told to stop, then reported, never waited for.
    fn join(self) -> io::Result<Exit> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.thread.is_finished() {
            if Instant::now() >= deadline {
                self.writer.stop();
                panic!("run did not return");
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.thread.join().unwrap()
    }
}

/// Python for a child that ignores TERM and says so once it is ignoring it.
fn stubborn(scratch: &Scratch) -> String {
    format!(
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); \
         open(\"{}/ready\", \"w\").close(); time.sleep(60)",
        scratch.0.display()
    )
}

fn pids(scratch: &Scratch) -> i64 {
    scratch.json("client")["pid"].as_i64().unwrap()
}

fn expected_argv(pinentry: &Path) -> Vec<String> {
    let mut argv: Vec<String> = [
        "--config=/dev/null",
        "--no-routes",
        "--no-dns",
        "--pppd-no-peerdns",
        "--pppd-accept-remote=0",
        "--pppd-ifname=vpntp1",
        "--fortinet-local-cidr=10.99.0.0/24",
        "--persistent=0",
        "--username=alice",
    ]
    .map(String::from)
    .into();
    argv.push(format!("--pinentry={}", pinentry.display()));
    argv.extend(
        [
            "--ifname=eth0",
            "--vpnt-ifindex=7",
            "--vpnt-gateway-ip=192.0.2.10",
            &format!("--trusted-cert={}", "ab".repeat(32)),
            "--",
            "vpn.example.test:10443",
        ]
        .map(String::from),
    );
    argv
}

#[test]
fn argv_is_exact_pins_the_certificate_and_has_no_ca_file() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "put('done', {})\nidle()\n",
        params(Some(PIN)),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    let argv: Vec<String> = serde_json::from_value(scratch.json("client")["argv"].clone()).unwrap();
    assert_eq!(argv, expected_argv(&scratch.path("vpnt-pinentry")));
    let pins: Vec<_> = argv
        .iter()
        .filter(|arg| arg.starts_with("--trusted-cert="))
        .collect();
    let delimiter = argv.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(pins.len(), 1);
    assert!(
        argv.iter()
            .position(|arg| arg.starts_with("--trusted-cert="))
            .unwrap()
            < delimiter
    );
    assert_eq!(argv.len(), delimiter + 2, "one operand after the delimiter");
    assert!(
        argv.iter().all(|arg| !arg.contains("ca-file")),
        "the pin is the anchor on Linux"
    );
    instance.writer.stop();
    assert_eq!(instance.join().unwrap().reason, Reason::Stop);
}

#[test]
fn password_remains_available_when_tls_takes_more_than_five_seconds() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "time.sleep(5.5)\npin('after-tls')\n",
        params(Some(PIN)),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    instance.join().unwrap();
    let result = scratch.json("pinentry.after-tls");
    assert_eq!(result["error"], Value::Null);
    assert_eq!(result["password"], PASSWORD);
}

#[test]
fn password_reaches_the_pinentry_once_and_nothing_else() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "pin('first')\npin('second')\nput('done', {})\nidle()\n",
        params(Some(PIN)),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let client = scratch.json("client");
    let pid = client["pid"].as_i64().unwrap();

    // Seen by the child itself and by an observer outside, while it runs.
    let outside = [
        fs::read(format!("/proc/{pid}/cmdline")).unwrap(),
        fs::read(format!("/proc/{pid}/environ")).unwrap(),
    ];
    for bytes in outside {
        assert!(!String::from_utf8_lossy(&bytes).contains(PASSWORD));
    }
    for field in ["cmdline", "environ"] {
        assert!(
            !client[field].as_str().unwrap().contains(PASSWORD),
            "{field}"
        );
    }
    let names: BTreeSet<_> = client["environ"]
        .as_str()
        .unwrap()
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.split('=').next().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["LANG", "LC_ALL", "PATH"].map(String::from).into());

    // Exactly once: the second ask finds the channel revoked.
    let first = scratch.json("pinentry.first");
    let second = scratch.json("pinentry.second");
    assert_eq!(first["password"], PASSWORD);
    assert_eq!(first["error"], Value::Null);
    assert_eq!(second["password"], Value::Null);
    assert_ne!(second["error"], Value::Null);

    instance.writer.stop();
    let events = instance.writer.events();
    instance.join().unwrap();
    assert!(!serde_json::to_string(&events).unwrap().contains(PASSWORD));
}

#[test]
fn only_stdio_and_the_two_owned_descriptors_reach_the_client() {
    // A descriptor the supervisor process happens to hold, not close-on-exec.
    // SAFETY: duplicates stdin above 20, without close-on-exec.
    let leaked = unsafe { libc::fcntl(0, libc::F_DUPFD, 20) };
    assert!(leaked >= 20);
    // SAFETY: the duplicate is owned here; flags are integers.
    let leaked = unsafe {
        assert_eq!(libc::fcntl(leaked, libc::F_SETFD, 0), 0);
        OwnedFd::from_raw_fd(leaked)
    };

    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "pin('only')\nput('done', {})\nidle()\n",
        params(Some(PIN)),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let client = scratch.json("client");
    let numbers: BTreeSet<_> = client["fds"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        numbers,
        ["0", "1", "2", "3", "4"].map(String::from).into(),
        "{client}"
    );
    assert_eq!(client["stdin"], "/dev/null");
    assert!(client["fds"]["1"].as_str().unwrap().starts_with("pipe:"));
    assert!(client["fds"]["2"].as_str().unwrap().starts_with("pipe:"));
    assert!(client["fds"]["3"].as_str().unwrap().starts_with("socket:"));
    assert_eq!(client["fds"]["4"], "anon_inode:[timerfd]");
    assert_eq!(
        client["pgid"], client["pid"],
        "the client leads its own group"
    );

    // The adapter gets the channel on 3 and nothing above it.
    let pinentry = scratch.json("pinentry.only");
    let numbers: BTreeSet<_> = pinentry["fds"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        numbers,
        ["0", "1", "2", "3"].map(String::from).into(),
        "{pinentry}"
    );
    assert_eq!(pinentry["password"], PASSWORD);

    instance.writer.stop();
    instance.join().unwrap();
    drop(leaked);
}

#[test]
fn a_missing_pin_is_refused_before_the_credential_is_read_or_anything_starts() {
    for pin in [None, Some([0; 32])] {
        let scratch = Scratch::new();
        let (client, pinentry) = fixtures(&scratch, "idle()\n");
        let (mut instance, writer) = Seq::pair();
        writer.credential(PASSWORD);
        // A build that started the client anyway ends here instead of hanging.
        writer.stop();
        let error = run_with(
            &mut instance,
            params(pin),
            &mut LineObserver::default(),
            Config {
                client: client.to_str().unwrap(),
                pinentry: pinentry.to_str().unwrap(),
                limits: limits(Duration::from_secs(1)),
                own_process: false,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            !scratch.path("client").exists(),
            "the client must not start"
        );
        // The credential is still queued: it was never read.
        assert!(instance.receive().is_ok(), "credential was consumed");
    }
    // Control: the same setup with a pin starts the client.
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "idle()\n",
        params(Some(PIN)),
        Duration::from_secs(1),
    );
    instance.writer.credential(PASSWORD);
    pids(&scratch);
    instance.writer.stop();
    instance.join().unwrap();
}

#[test]
fn observations_become_typed_events_and_no_raw_line_returns() {
    let scratch = Scratch::new();
    let body = r#"
print("INFO:   Interface vpntp1 is UP.", flush=True)
print("INFO:   vpnt: split-route 10.0.0.0/255.0.0.0", file=sys.stderr, flush=True)
print("INFO:   vpnt: dns-server 10.1.1.1", flush=True)
print("INFO:   vpnt: dns-domain corp.example.test", flush=True)
print("INFO:   token=RAWLINE-SECRET gateway said so", file=sys.stderr, flush=True)
put("done", {})
idle()
"#;
    let instance = Instance::start(&scratch, body, params(Some(PIN)), Duration::from_secs(2));
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    instance.writer.stop();
    let events = instance.writer.events();
    assert_eq!(instance.join().unwrap().reason, Reason::Stop);

    let mut seen: Vec<String> = events.iter().map(Value::to_string).collect();
    seen.sort();
    let mut expected: Vec<String> = [
        json!({"event": "started"}),
        json!({"event": "interface", "name": "vpntp1"}),
        json!({"event": "split_route", "network": "10.0.0.0", "prefix": 8}),
        json!({"event": "dns_server", "address": "10.1.1.1"}),
        json!({"event": "dns_domain", "name": "corp.example.test"}),
        json!({"event": "exited", "code": null, "signal": 15}),
    ]
    .iter()
    .map(Value::to_string)
    .collect();
    expected.sort();
    assert_eq!(seen, expected);
    assert_eq!(events.first().unwrap()["event"], "started");
    assert_eq!(events.last().unwrap()["event"], "exited");
    let wire = serde_json::to_string(&events).unwrap();
    for raw in ["RAWLINE", "token", "INFO:", "gateway said"] {
        assert!(!wire.contains(raw), "{raw} came back");
    }
}

#[test]
fn channel_eof_stops_the_client_with_term_and_reaps_it_once() {
    let scratch = Scratch::new();
    let body = format!(
        "def term(*_):\n    open('{}/term', 'w').write('1')\n    os._exit(0)\n\
         signal.signal(signal.SIGTERM, term)\nput('done', {{}})\nidle()\n",
        scratch.0.display()
    );
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), Duration::from_secs(2));
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let pid = pids(&scratch);
    drop(instance.writer);
    let exit = instance.thread.join().unwrap().unwrap();
    assert_eq!(exit.reason, Reason::ChannelClosed);
    // The writer dropped with events unread: reset, or plain EOF.
    assert!(matches!(
        exit.channel_error.unwrap().kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
    ));
    assert!(scratch.path("term").exists(), "SIGTERM came first");
    assert!(!exit.escalated);
    assert_eq!(exit.status.unwrap().code(), Some(0));
    assert!(exit.descendants_gone);
    assert!(gone(pid));
}

#[test]
fn stop_command_sends_term_then_kill_to_everything_that_ignores_it() {
    let scratch = Scratch::new();
    let body = format!(
        "signal.signal(signal.SIGTERM, lambda *_: open('{dir}/term', 'w').write('1'))\n\
         child = subprocess.Popen(['/usr/bin/python3', '-c', \
         '{grandchild}'])\n\
         while not os.path.exists('{dir}/ready'):\n    time.sleep(0.01)\n\
         put('grandchild', {{'pid': child.pid, 'pgid': os.getpgid(child.pid)}})\n\
         put('done', {{}})\nidle()\n",
        dir = scratch.0.display(),
        grandchild = stubborn(&scratch)
    );
    let grace = Duration::from_millis(300);
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), grace);
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let grandchild = scratch.json("grandchild");
    assert_eq!(
        grandchild["pgid"],
        scratch.json("client")["pid"],
        "same group"
    );
    let started = Instant::now();
    instance.writer.stop();
    let events = instance.writer.events();
    let exit = instance.join().unwrap();

    assert_eq!(exit.reason, Reason::Stop);
    assert!(exit.escalated);
    assert!(
        started.elapsed() >= grace,
        "KILL came before the grace ended"
    );
    assert!(
        scratch.path("term").exists(),
        "TERM was delivered before KILL"
    );
    assert_eq!(exit.status.unwrap().signal(), Some(libc::SIGKILL));
    assert!(exit.descendants_gone);
    assert!(
        gone(grandchild["pid"].as_i64().unwrap()),
        "descendant outlived the stop"
    );
    assert!(gone(pids(&scratch)));
    assert_eq!(
        events.last().unwrap(),
        &json!({"event": "exited", "code": null, "signal": 9})
    );
}

#[test]
fn descendants_that_outlive_the_leader_are_swept_before_it_is_reaped() {
    let scratch = Scratch::new();
    // The leader exits on TERM; its child ignores TERM and would live on.
    let body = format!(
        "signal.signal(signal.SIGTERM, lambda *_: os._exit(0))\n\
         child = subprocess.Popen(['/usr/bin/python3', '-c', '{grandchild}'])\n\
         while not os.path.exists('{dir}/ready'):\n    time.sleep(0.01)\n\
         put('grandchild', {{'pid': child.pid}})\nput('done', {{}})\nidle()\n",
        dir = scratch.0.display(),
        grandchild = stubborn(&scratch)
    );
    let grace = Duration::from_millis(400);
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), grace);
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let grandchild = scratch.json("grandchild")["pid"].as_i64().unwrap();
    assert!(
        fs::metadata(format!("/proc/{grandchild}")).is_ok(),
        "control: alive"
    );
    let started = Instant::now();
    instance.writer.stop();
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::Stop);
    // The leader left on TERM, but its child ignored it: the grace belongs to
    // the whole set, and the KILL that ended it is recorded.
    assert!(exit.escalated, "a descendant needed SIGKILL");
    assert!(
        started.elapsed() >= grace,
        "KILL came before the grace ended"
    );
    assert_eq!(exit.status.unwrap().code(), Some(0));
    assert!(exit.descendants_gone);
    assert!(gone(grandchild), "the descendant outlived the leader");
}

#[test]
fn client_scope_denial_is_reported_before_its_exit_status() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "put('done', {})\ntime.sleep(0.2)\nsys.exit(3)\n",
        params(Some(PIN)),
        Duration::from_secs(1),
    );
    instance.writer.credential(PASSWORD);
    let events = instance.writer.events();
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::ClientExited);
    assert_eq!(exit.status.unwrap().code(), Some(3));
    assert!(!exit.escalated);
    assert_eq!(
        &events[events.len() - 2],
        &json!({"event": "failure", "kind": "local_address_denied"})
    );
    assert_eq!(
        events.last().unwrap(),
        &json!({"event": "exited", "code": 3, "signal": null})
    );
}

#[test]
fn a_repeated_credential_is_a_violation_that_stops_the_client() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "put('done', {})\nidle()\n",
        params(Some(PIN)),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let pid = pids(&scratch);
    instance.writer.credential("another");
    let error = instance.join().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(gone(pid), "the client must not outlive the violation");
}

#[test]
fn an_unknown_message_is_a_violation_that_stops_the_client() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "put('done', {})\nidle()\n",
        params(Some(PIN)),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let pid = pids(&scratch);
    instance.writer.put(&[9, 9]);
    assert_eq!(
        instance.join().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(gone(pid));
}

#[test]
fn nothing_starts_without_a_credential() {
    for case in ["stop", "eof", "timeout"] {
        let scratch = Scratch::new();
        let (client, pinentry) = fixtures(&scratch, "idle()\n");
        let (mut instance, writer) = Seq::pair();
        let config = Config {
            client: client.to_str().unwrap(),
            pinentry: pinentry.to_str().unwrap(),
            limits: Limits {
                credential_wait: Duration::from_millis(150),
                ..limits(Duration::from_secs(1))
            },
            own_process: false,
        };
        match case {
            "stop" => writer.stop(),
            "eof" => drop(writer),
            _ => {}
        }
        let result = run_with(
            &mut instance,
            params(Some(PIN)),
            &mut LineObserver::default(),
            config,
        );
        match case {
            "stop" => {
                let exit = result.unwrap();
                assert_eq!((exit.reason, exit.status.is_none()), (Reason::Stop, true));
            }
            "eof" => {
                let exit = result.unwrap();
                assert_eq!(
                    (exit.reason, exit.status.is_none()),
                    (Reason::ChannelClosed, true)
                );
                assert_eq!(
                    exit.channel_error.unwrap().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
            _ => assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut),
        }
        assert!(
            !scratch.path("client").exists(),
            "{case}: the client must not start"
        );
    }
}

/// Entry of the re-executed test binary. Runs only when the parent test asks.
#[test]
fn helper_supervisor() {
    let Ok(spec) = std::env::var(HELPER_ENV) else {
        return;
    };
    let mut fields = spec.split('|');
    let mode = fields.next().unwrap();
    let fd: RawFd = fields.next().unwrap().parse().unwrap();
    let dir = PathBuf::from(fields.next().unwrap());
    // SAFETY: the parent passed this descriptor to this process alone.
    let mut channel = Seq(unsafe { OwnedFd::from_raw_fd(fd) });
    // SAFETY: fcntl takes integers; the descriptor is live.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if mode == "dumpable" {
        // SAFETY: prctl query takes integers only.
        let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        let error = serve(&mut channel, &mut LineObserver::default()).unwrap_err();
        // SAFETY: as above.
        let after = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        let mut subreaper: libc::c_int = -1;
        // SAFETY: the query writes one integer through the given pointer.
        unsafe {
            libc::prctl(
                libc::PR_GET_CHILD_SUBREAPER,
                &mut subreaper as *mut libc::c_int,
            )
        };
        fs::write(
            dir.join("dumpable"),
            format!("{before} {after} {:?} {subreaper}", error.kind()),
        )
        .unwrap();
        return;
    }
    let client = fields.next().unwrap();
    let pinentry = fields.next().unwrap();
    let own_process = mode == "reap";
    if own_process {
        harden().unwrap();
    }
    let result = run_with(
        &mut channel,
        params(Some(PIN)),
        &mut LineObserver::default(),
        Config {
            client,
            pinentry,
            limits: limits(Duration::from_secs(2)),
            own_process,
        },
    );
    if own_process {
        let orphan: Value = serde_json::from_slice(&fs::read(dir.join("pppd")).unwrap()).unwrap();
        let pid = orphan["pid"].as_i64().unwrap();
        let exit = result.unwrap();
        let report = json!({
            "reason": format!("{:?}", exit.reason),
            "descendants_gone": exit.descendants_gone,
            "escalated": exit.escalated,
            "orphan_listed": fs::metadata(format!("/proc/{pid}")).is_ok(),
            "children": children_of(process::id() as libc::pid_t).unwrap(),
        });
        fs::write(dir.join("reap"), report.to_string()).unwrap();
    }
}

/// Starts the test binary as a separate process running `helper_supervisor`.
fn spawn_helper(mode: &str, scratch: &Scratch, extra: &str, channel: &Seq) -> process::Child {
    let fd = channel.0.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "tunneld::fortinet_instance::tests::helper_supervisor",
            "--nocapture",
        ])
        .env(
            HELPER_ENV,
            format!("{mode}|{fd}|{}{extra}", scratch.0.display()),
        )
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null());
    // SAFETY: only fcntl on an integer runs in the child before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

#[test]
fn the_client_dies_with_its_supervisor() {
    let scratch = Scratch::new();
    let (client, pinentry) = fixtures(&scratch, "put('done', {})\nidle()\n");
    let (instance, writer) = Seq::pair();
    let extra = format!("|{}|{}", client.display(), pinentry.display());
    let mut helper = spawn_helper("run", &scratch, &extra, &instance);
    writer.credential(PASSWORD);
    scratch.json("done");
    let pid = pids(&scratch);
    assert!(
        fs::metadata(format!("/proc/{pid}")).is_ok(),
        "control: client alive"
    );
    assert!(
        helper.try_wait().unwrap().is_none(),
        "control: supervisor alive"
    );

    helper.kill().unwrap();
    helper.wait().unwrap();
    assert!(gone(pid), "the client survived its supervisor");
}

#[test]
fn serve_makes_the_supervisor_non_dumpable_before_anything_else() {
    let scratch = Scratch::new();
    let (instance, writer) = Seq::pair();
    let mut start = start_order();
    start.certificate_sha256 = "00".repeat(32);
    writer.put(&serde_json::to_vec(&start).unwrap());
    let mut helper = spawn_helper("dumpable", &scratch, "", &instance);
    assert!(helper.wait().unwrap().success());
    assert_eq!(
        fs::read_to_string(scratch.path("dumpable")).unwrap(),
        "1 0 InvalidInput 1"
    );
}

/// Python for a stand-in of the PPP daemon: its own session, as `forkpty`
/// gives the real one, so it is not in the client's process group.
fn pppd_fixture(scratch: &Scratch, ignore_term: bool) -> String {
    // One line of simple statements: it is embedded in a quoted `-c` argument.
    format!(
        "import json,os,signal,time; {ignore}\
         json.dump({{\"pid\": os.getpid(), \"sid\": os.getsid(0), \"pgid\": os.getpgrp()}}, \
         open(\"{dir}/pppd.tmp\", \"w\")); \
         os.rename(\"{dir}/pppd.tmp\", \"{dir}/pppd\"); time.sleep(60)",
        ignore = if ignore_term {
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        } else {
            ""
        },
        dir = scratch.0.display()
    )
}

/// Client body that starts the stand-in daemon in a new session and waits for it.
fn with_pppd(scratch: &Scratch, ignore_term: bool, leader: &str) -> String {
    with_pppd_code(scratch, &pppd_fixture(scratch, ignore_term), leader)
}

fn with_pppd_code(scratch: &Scratch, code: &str, leader: &str) -> String {
    format!(
        "{leader}\
         subprocess.Popen(['/usr/bin/python3', '-c', '{code}'], start_new_session=True)\n\
         while not os.path.exists('{dir}/pppd'):\n    time.sleep(0.01)\n\
         put('done', {{}})\nidle()\n",
        code = code.replace('\'', ""),
        dir = scratch.0.display()
    )
}

/// A stand-in daemon that takes `delay` to finish handling TERM and then says so.
fn slow_term_pppd(scratch: &Scratch, delay: &str) -> String {
    pppd_fixture(scratch, false).replacen(
        "import json,os,signal,time; ",
        &format!(
            "import json,os,signal,time; signal.signal(signal.SIGTERM, lambda *_: \
             (time.sleep({delay}), open(\"{dir}/termdone\", \"w\").write(\"1\"), os._exit(0))); ",
            dir = scratch.0.display()
        ),
        1,
    )
}

fn pppd_pid(scratch: &Scratch) -> i64 {
    scratch.json("pppd")["pid"].as_i64().unwrap()
}

#[test]
fn a_pppd_in_its_own_session_is_stopped_with_the_client() {
    let scratch = Scratch::new();
    let body = with_pppd(&scratch, false, "");
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), Duration::from_secs(5));
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let pppd = scratch.json("pppd");
    let client = pids(&scratch);
    assert_eq!(
        pppd["sid"], pppd["pid"],
        "control: it leads its own session"
    );
    assert_ne!(
        pppd["pgid"].as_i64().unwrap(),
        client,
        "control: outside the client's group"
    );
    instance.writer.stop();
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::Stop);
    assert!(!exit.escalated);
    assert!(exit.descendants_gone);
    assert!(gone(pppd_pid(&scratch)), "the pppd outlived the stop");
    assert!(gone(client));
}

#[test]
fn a_pppd_that_ignores_term_is_killed_after_the_grace() {
    let scratch = Scratch::new();
    let body = with_pppd(
        &scratch,
        true,
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n",
    );
    let instance = Instance::start(
        &scratch,
        &body,
        params(Some(PIN)),
        Duration::from_millis(300),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    instance.writer.stop();
    let exit = instance.join().unwrap();
    assert!(exit.escalated);
    assert_eq!(exit.status.unwrap().signal(), Some(libc::SIGKILL));
    assert!(exit.descendants_gone);
    assert!(gone(pppd_pid(&scratch)), "the pppd outlived the kill");
}

#[test]
fn a_pppd_left_behind_by_a_client_that_leaves_on_term_is_still_stopped() {
    let scratch = Scratch::new();
    // The leader exits on TERM; the daemon, in another session, ignores it.
    let body = with_pppd(
        &scratch,
        true,
        "signal.signal(signal.SIGTERM, lambda *_: os._exit(0))\n",
    );
    let grace = Duration::from_millis(400);
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), grace);
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let pppd = pppd_pid(&scratch);
    assert!(
        fs::metadata(format!("/proc/{pppd}")).is_ok(),
        "control: alive"
    );
    let started = Instant::now();
    instance.writer.stop();
    let exit = instance.join().unwrap();
    assert!(exit.escalated, "the daemon ignored TERM and needed SIGKILL");
    assert!(
        started.elapsed() >= grace,
        "KILL came before the grace ended"
    );
    assert!(exit.descendants_gone);
    assert!(gone(pppd), "the pppd was left behind");
}

#[test]
fn a_client_that_exits_by_itself_leaves_no_pppd() {
    let scratch = Scratch::new();
    let body = with_pppd(&scratch, true, "").replace(
        "put('done', {})\nidle()\n",
        "put('done', {})\ntime.sleep(0.3)\nsys.exit(3)\n",
    );
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), Duration::from_secs(5));
    instance.writer.credential(PASSWORD);
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::ClientExited);
    assert_eq!(exit.status.unwrap().code(), Some(3));
    assert!(exit.descendants_gone);
    assert!(gone(pppd_pid(&scratch)), "the pppd outlived its client");
}

#[test]
fn an_orphaned_pppd_is_adopted_stopped_and_reaped_by_a_dedicated_supervisor() {
    let scratch = Scratch::new();
    // Double fork: the daemon is orphaned at once, so it is never the client's
    // child when the supervisor looks, only its (adopted) own.
    let body = format!(
        "if os.fork() == 0:\n\
         \x20   if os.fork() == 0:\n\
         \x20       os.setsid()\n\
         \x20       signal.signal(signal.SIGTERM, signal.SIG_IGN)\n\
         \x20       json.dump({{'pid': os.getpid()}}, open('{dir}/pppd.tmp', 'w'))\n\
         \x20       os.rename('{dir}/pppd.tmp', '{dir}/pppd')\n\
         \x20       time.sleep(60)\n\
         \x20   os._exit(0)\n\
         while not os.path.exists('{dir}/pppd'):\n    time.sleep(0.01)\n\
         time.sleep(0.2)\nput('done', {{}})\nidle()\n",
        dir = scratch.0.display()
    );
    let (client, pinentry) = fixtures(&scratch, &body);
    let (instance, writer) = Seq::pair();
    let extra = format!("|{}|{}", client.display(), pinentry.display());
    let mut helper = spawn_helper("reap", &scratch, &extra, &instance);
    writer.credential(PASSWORD);
    scratch.json("done");
    let pppd = pppd_pid(&scratch);
    assert!(
        fs::metadata(format!("/proc/{pppd}")).is_ok(),
        "control: alive"
    );
    writer.stop();
    writer.events();
    assert!(helper.wait().unwrap().success());
    let report = scratch.json("reap");
    assert_eq!(report["reason"], "Stop", "{report}");
    assert_eq!(report["descendants_gone"], true, "{report}");
    assert_eq!(
        report["orphan_listed"], false,
        "gone, not even a zombie: {report}"
    );
    assert_eq!(report["children"], json!([]), "{report}");
    assert!(gone(pppd));
}

#[test]
fn credential_datagram_is_zeroed_on_every_path() {
    let good = {
        let mut frame = vec![MESSAGE_CREDENTIAL, 0, PASSWORD.len() as u8];
        frame.extend_from_slice(PASSWORD.as_bytes());
        frame
    };
    let cases = [
        good,
        vec![MESSAGE_CREDENTIAL, 0, 9, b'x'],
        vec![MESSAGE_STOP],
        vec![7; 40],
    ];
    for case in cases {
        // The datagram arrives in the wiping buffer of the channel: `decode`
        // wipes the whole message, and the buffer wipes its capacity on release.
        let mut bytes = Datagram::from_vec(case.clone());
        let message = decode(&mut bytes);
        assert_eq!(bytes.len(), case.len());
        assert!(
            bytes.iter().all(|&byte| byte == 0),
            "{case:?} left bytes behind"
        );
        if case[0] == MESSAGE_CREDENTIAL && case.len() == 3 + PASSWORD.len() {
            let Ok(Message::Credential(secret)) = message else {
                panic!("good frame refused")
            };
            assert_eq!(secret.expose(), PASSWORD);
        }
    }
}

#[test]
fn only_well_formed_messages_are_accepted() {
    let frame = |length: u16, body: &[u8]| {
        let mut frame = vec![MESSAGE_CREDENTIAL];
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(body);
        frame
    };
    let long = "p".repeat(256);
    let too_long = "p".repeat(257);
    assert!(matches!(parse(&[MESSAGE_STOP]), Ok(Message::Stop)));
    for good in [frame(1, b"p"), frame(256, long.as_bytes())] {
        assert!(
            matches!(parse(&good), Ok(Message::Credential(_))),
            "{}",
            good.len()
        );
    }
    let bad: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![3],
        vec![MESSAGE_STOP, 0],
        vec![MESSAGE_CREDENTIAL],
        vec![MESSAGE_CREDENTIAL, 0],
        frame(0, b""),
        frame(2, b"p"),
        frame(1, b"pp"),
        frame(257, too_long.as_bytes()),
        frame(3, b"a\0b"),
        frame(3, b"a\nb"),
        frame(3, b"a\rb"),
        frame(2, &[0xff, 0xfe]),
    ];
    for message in bad {
        assert_eq!(
            parse(&message).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData),
            "{message:?}"
        );
    }
}

#[test]
fn observations_turn_into_each_event_once() {
    let mut sent = Observation::default();
    let mut now = Observation::default();
    assert!(changes(&sent, &now).is_empty());
    now.candidate = Some("vpntp1".into());
    now.failure = Some(Failure::GatewayTimeout);
    now.split = vec![(Ipv4Addr::new(10, 0, 0, 0), 8)];
    now.split_count = Some(1);
    now.interface_mismatch = true;
    now.split_invalid = true;
    now.dns_servers = vec![Ipv4Addr::new(10, 1, 1, 1)];
    now.dns_domains = vec!["corp.example.test".into()];
    now.dns_count = Some((1, 1));
    now.dns_invalid = true;
    let first = changes(&sent, &now);
    assert_eq!(
        first,
        vec![
            Event::Interface {
                name: "vpntp1".into()
            },
            Event::Failure {
                kind: Failure::GatewayTimeout
            },
            Event::SplitRoute {
                network: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8
            },
            Event::SplitRoutes { count: 1 },
            Event::InterfaceMismatch,
            Event::SplitInvalid,
            Event::DnsServer {
                address: Ipv4Addr::new(10, 1, 1, 1)
            },
            Event::DnsDomain {
                name: "corp.example.test".into()
            },
            Event::DnsCount {
                servers: 1,
                domains: 1
            },
            Event::DnsInvalid,
        ]
    );
    sent = now.clone();
    assert!(changes(&sent, &now).is_empty(), "nothing is repeated");
    now.split.push((Ipv4Addr::new(172, 16, 0, 0), 12));
    assert_eq!(
        changes(&sent, &now),
        vec![Event::SplitRoute {
            network: Ipv4Addr::new(172, 16, 0, 0),
            prefix: 12
        }]
    );
}

#[test]
fn events_have_a_closed_wire_shape() {
    for (event, wire) in [
        (Event::Started, r#"{"event":"started"}"#),
        (
            Event::InterfaceMismatch,
            r#"{"event":"interface_mismatch"}"#,
        ),
        (
            Event::Failure {
                kind: Failure::CredentialsRejected,
            },
            r#"{"event":"failure","kind":"credentials_rejected"}"#,
        ),
        (
            Event::Exited {
                code: Some(1),
                signal: None,
            },
            r#"{"event":"exited","code":1,"signal":null}"#,
        ),
    ] {
        assert_eq!(serde_json::to_string(&event).unwrap(), wire);
    }
    let longest = Event::DnsDomain {
        name: "a".repeat(253),
    };
    assert!(serde_json::to_vec(&longest).unwrap().len() <= MAX_DATAGRAM);
}

#[test]
fn parameters_refuse_hostile_values() {
    let binding = |interface: &str, index: u32, gateway: Ipv4Addr| Binding {
        interface: interface.into(),
        index,
        gateway,
    };
    let endpoint = || Endpoint::new("vpn.example.test".into(), 443).unwrap();
    let ok = Ipv4Addr::new(192, 0, 2, 1);
    let ppp = || "vpntp1".to_owned();
    let hostile = [
        ("", binding("eth0", 1, ok), ppp()),
        ("a\nb", binding("eth0", 1, ok), ppp()),
        (&*"u".repeat(65), binding("eth0", 1, ok), ppp()),
        ("alice", binding("", 1, ok), ppp()),
        ("alice", binding("eth0 --x", 1, ok), ppp()),
        ("alice", binding("a-very-long-name-x", 1, ok), ppp()),
        ("alice", binding("eth0", 0, ok), ppp()),
        ("alice", binding("eth0", 1, Ipv4Addr::UNSPECIFIED), ppp()),
        ("alice", binding("eth0", 1, Ipv4Addr::BROADCAST), ppp()),
        (
            "alice",
            binding("eth0", 1, Ipv4Addr::new(224, 0, 0, 1)),
            ppp(),
        ),
        ("alice", binding("eth0", 1, ok), String::new()),
        ("alice", binding("eth0", 1, ok), "a".repeat(16)),
        ("alice", binding("eth0", 1, ok), "Vpntp1".into()),
        ("alice", binding("eth0", 1, ok), "vpn_p1".into()),
        ("alice", binding("eth0", 1, ok), "vpn-p1".into()),
        ("alice", binding("eth0", 1, ok), "vpn.p1".into()),
        ("alice", binding("eth0", 1, ok), "vpn p1".into()),
        ("alice", binding("eth0", 1, ok), "vpntp1\n".into()),
        ("alice", binding("eth0", 1, ok), "vpntp\u{e9}".into()),
    ];
    for (username, binding, interface) in hostile {
        let result = Params::new(
            endpoint(),
            username.into(),
            Some(PIN),
            binding.clone(),
            interface.clone(),
            "10.99.0.0/24".parse().unwrap(),
        );
        assert!(result.is_err(), "{username:?} {binding:?} {interface:?}");
    }
    // Controls: the longest accepted name, and the default for any ordinal.
    for interface in [
        "a".repeat(15),
        "vpntp0".into(),
        Params::default_pppd_ifname(4_000_000_000),
    ] {
        assert!(
            Params::new(
                endpoint(),
                "alice".into(),
                Some(PIN),
                binding("eth0", 1, ok),
                interface.clone(),
                "10.99.0.0/24".parse().unwrap(),
            )
            .is_ok(),
            "{interface}"
        );
    }
}

#[test]
fn the_shared_parser_drives_the_same_typed_events() {
    let scratch = Scratch::new();
    let body = r#"
print("INFO:   Interface vpntp1 is UP.", flush=True)
# One pipe for the counted lines: two pipes would race the count against the route.
print("INFO:   vpnt: split-route 10.0.0.0/255.0.0.0", flush=True)
print("INFO:   vpnt: split-routes 1", flush=True)
print("INFO:   vpnt: dns-server 10.1.1.1", flush=True)
print("INFO:   vpnt: dns-server 0.0.0.0", flush=True)
print("INFO:   vpnt: dns-domain corp.example.test", flush=True)
print("INFO:   vpnt: dns 1 1", flush=True)
print("ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.", flush=True)
print("INFO:   token=RAWLINE-SECRET gateway said so", file=sys.stderr, flush=True)
put("done", {})
idle()
"#;
    let (client, pinentry) = fixtures(&scratch, body);
    let (instance, writer) = Seq::pair();
    let thread = thread::spawn(move || {
        let mut instance = instance;
        run_with(
            &mut instance,
            params(Some(PIN)),
            &mut crate::connection::ssl_output::Output::default(),
            Config {
                client: client.to_str().unwrap(),
                pinentry: pinentry.to_str().unwrap(),
                limits: limits(Duration::from_secs(2)),
                own_process: false,
            },
        )
    });
    writer.credential(PASSWORD);
    scratch.json("done");
    // The rejected-password line is a fatal event: the supervisor ends the run
    // by itself, so no Stop is sent (one would race the fatal exit).
    let events = writer.events();
    assert_eq!(thread.join().unwrap().unwrap().reason, Reason::Fatal);
    let mut seen: Vec<String> = events.iter().map(Value::to_string).collect();
    seen.sort();
    let mut expected: Vec<String> = [
        json!({"event": "started"}),
        json!({"event": "interface", "name": "vpntp1"}),
        json!({"event": "failure", "kind": "credentials_rejected"}),
        json!({"event": "split_route", "network": "10.0.0.0", "prefix": 8}),
        json!({"event": "split_routes", "count": 1}),
        json!({"event": "dns_server", "address": "10.1.1.1"}),
        json!({"event": "dns_domain", "name": "corp.example.test"}),
        json!({"event": "dns_count", "servers": 1, "domains": 1}),
        json!({"event": "dns_invalid"}),
        json!({"event": "exited", "code": null, "signal": 15}),
    ]
    .iter()
    .map(Value::to_string)
    .collect();
    expected.sort();
    assert_eq!(seen, expected);
    let wire = serde_json::to_string(&events).unwrap();
    for raw in ["RAWLINE", "token", "INFO:", "gateway said", "authenticate"] {
        assert!(!wire.contains(raw), "{raw} came back");
    }
}

fn real_pair(scratch: &Scratch) -> (AuthenticatedChannel, AuthenticatedChannel) {
    authenticated_pair_for_tests(&scratch.0, GENERATION, Backend::Fortinet, INVOCATION).unwrap()
}

/// Events from the writer end of a real channel, up to `exited`.
fn real_events(writer: &mut AuthenticatedChannel) -> Vec<Value> {
    let mut events = Vec::new();
    while let Ok(bytes) = writer.receive() {
        let event: Value = serde_json::from_slice(&bytes).unwrap();
        let done = event["event"] == "exited";
        events.push(event);
        if done {
            break;
        }
    }
    events
}

#[test]
fn the_real_authenticated_channel_and_parser_drive_a_run() {
    let scratch = Scratch::new();
    let body = r#"
print("INFO:   Interface vpntp1 is UP.", flush=True)
print("INFO:   vpnt: split-route 10.0.0.0/255.0.0.0", file=sys.stderr, flush=True)
print("INFO:   vpnt: dns-server 10.1.1.1", flush=True)
pin('only')
put("done", {})
idle()
"#;
    let (client, pinentry) = fixtures(&scratch, body);
    let (mut writer, instance) = real_pair(&scratch);
    assert_eq!(instance.invocation(), INVOCATION);
    let thread = thread::spawn(move || {
        let mut instance = instance;
        run_with(
            &mut instance,
            params(Some(PIN)),
            &mut crate::connection::ssl_output::Output::default(),
            Config {
                client: client.to_str().unwrap(),
                pinentry: pinentry.to_str().unwrap(),
                limits: limits(Duration::from_secs(2)),
                own_process: false,
            },
        )
    });
    writer.send(&credential_frame(PASSWORD)).unwrap();
    scratch.json("done");
    assert_eq!(scratch.json("pinentry.only")["password"], PASSWORD);
    writer.send(&[MESSAGE_STOP]).unwrap();
    let events = real_events(&mut writer);
    assert_eq!(thread.join().unwrap().unwrap().reason, Reason::Stop);
    let mut seen: Vec<String> = events.iter().map(Value::to_string).collect();
    seen.sort();
    let mut expected: Vec<String> = [
        json!({"event": "started"}),
        json!({"event": "interface", "name": "vpntp1"}),
        json!({"event": "split_route", "network": "10.0.0.0", "prefix": 8}),
        json!({"event": "dns_server", "address": "10.1.1.1"}),
        json!({"event": "exited", "code": null, "signal": 15}),
    ]
    .iter()
    .map(Value::to_string)
    .collect();
    expected.sort();
    assert_eq!(seen, expected);
}

#[test]
fn the_end_of_the_real_channel_stops_the_client() {
    let scratch = Scratch::new();
    let (client, pinentry) = fixtures(&scratch, "put('done', {})\nidle()\n");
    let (mut writer, instance) = real_pair(&scratch);
    let thread = thread::spawn(move || {
        let mut instance = instance;
        run_with(
            &mut instance,
            params(Some(PIN)),
            &mut LineObserver::default(),
            Config {
                client: client.to_str().unwrap(),
                pinentry: pinentry.to_str().unwrap(),
                limits: limits(Duration::from_secs(2)),
                own_process: false,
            },
        )
    });
    writer.send(&credential_frame(PASSWORD)).unwrap();
    scratch.json("done");
    let pid = pids(&scratch);
    drop(writer);
    let exit = thread.join().unwrap().unwrap();
    assert_eq!(exit.reason, Reason::ChannelClosed);
    assert!(exit.channel_error.is_some(), "the cause is kept");
    assert!(exit.descendants_gone);
    assert!(gone(pid));
}

#[test]
fn a_descendant_gets_its_whole_grace_after_the_leader_left() {
    let scratch = Scratch::new();
    // The leader leaves on TERM at once; the daemon, in another session, needs
    // 0.6 s to finish handling TERM, well inside the grace.
    let body = with_pppd_code(
        &scratch,
        &slow_term_pppd(&scratch, "0.6"),
        "signal.signal(signal.SIGTERM, lambda *_: os._exit(0))\n",
    );
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), Duration::from_secs(5));
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let pppd = pppd_pid(&scratch);
    instance.writer.stop();
    let exit = instance.join().unwrap();
    assert!(
        scratch.path("termdone").exists(),
        "the daemon was killed before it finished handling TERM"
    );
    assert!(!exit.escalated, "no SIGKILL was needed");
    assert!(exit.descendants_gone);
    assert!(gone(pppd));
}

#[test]
fn a_client_that_exited_by_itself_still_gives_its_pppd_the_grace() {
    let scratch = Scratch::new();
    let body = with_pppd_code(&scratch, &slow_term_pppd(&scratch, "0.6"), "").replace(
        "put('done', {})\nidle()\n",
        "put('done', {})\ntime.sleep(0.2)\nsys.exit(3)\n",
    );
    let instance = Instance::start(&scratch, &body, params(Some(PIN)), Duration::from_secs(5));
    instance.writer.credential(PASSWORD);
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::ClientExited);
    assert!(
        scratch.path("termdone").exists(),
        "the daemon was killed before it finished handling TERM"
    );
    assert!(!exit.escalated);
    assert!(exit.descendants_gone);
}

/// Descriptors of a stand-in PPP daemon started the way the C client does it:
/// `execv` after `forkpty`, so everything not close-on-exec is inherited.
fn fake_pppd_fds(scratch: &Scratch, close_capability: bool) -> BTreeSet<String> {
    let preamble = PREAMBLE.replace("@DIR@", scratch.0.to_str().unwrap());
    write_script(
        &scratch.path("fake-pppd"),
        &format!("{preamble}\nput('pppd-fds', sorted(fds()))\n"),
    );
    // A descriptor the supervisor process holds, not close-on-exec: the
    // supervisor must keep it from the client (and so from the daemon).
    // SAFETY: duplicates stdin above 20, without close-on-exec.
    let leaked = unsafe { libc::fcntl(0, libc::F_DUPFD, 20) };
    assert!(leaked >= 20);
    let body = format!(
        "pin('only')\n{close}os.close(4)  # the login timer is consumed before PPP starts\n\
         subprocess.Popen([D + '/fake-pppd'], close_fds=False).wait()\nput('done', {{}})\nidle()\n",
        close = if close_capability {
            "os.close(3)  # what the patched client does after the read\n"
        } else {
            ""
        }
    );
    let instance = Instance::start(scratch, &body, params(Some(PIN)), Duration::from_secs(2));
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let fds: Vec<String> = serde_json::from_value(scratch.json("pppd-fds")).unwrap();
    assert_eq!(scratch.json("pinentry.only")["password"], PASSWORD);
    instance.writer.stop();
    instance.join().unwrap();
    // SAFETY: closes the duplicate made above, owned here.
    unsafe { libc::close(leaked) };
    fds.into_iter().collect()
}

#[test]
fn the_pppd_inherits_only_stdio_once_the_client_closed_the_pinentry_descriptor() {
    // The fixture models both closes in the patched client. The daemon then
    // checks what it actually inherited from the supervisor and the client.
    let closed = fake_pppd_fds(&Scratch::new(), true);
    assert_eq!(closed, ["0", "1", "2"].map(String::from).into());
    // Control: a client that keeps 3 hands it to the daemon, and the probe sees it.
    let kept = fake_pppd_fds(&Scratch::new(), false);
    assert_eq!(kept, ["0", "1", "2", "3"].map(String::from).into());
}

#[test]
fn a_listed_pid_that_is_not_the_leaders_child_is_never_held_or_signalled() {
    struct Alien(process::Child);
    impl Drop for Alien {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let alive = |pid: libc::pid_t| {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| stat.rsplit(')').next().map(str::to_owned))
            .is_some_and(|rest| !rest.trim_start().starts_with('Z'))
    };
    let scratch = Scratch::new();
    let body = "child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(60)'])\n\
                put('child', {'pid': child.pid})\nput('done', {})\nidle()\n";
    let (client_path, pinentry) = fixtures(&scratch, body);
    let config = Config {
        client: client_path.to_str().unwrap(),
        pinentry: pinentry.to_str().unwrap(),
        limits: limits(Duration::from_secs(1)),
        own_process: false,
    };
    let (spawn, null) = command(&config, &params(Some(PIN)), &PIN).unwrap();
    let mut client = Client::spawn(
        spawn,
        Secret::from(PASSWORD),
        false,
        FortinetDeadline::new().unwrap(),
    )
    .unwrap();
    drop(null);
    scratch.json("done");
    let real = scratch.json("child")["pid"].as_i64().unwrap() as libc::pid_t;
    // A process of the test, never a descendant of the client: what a pid
    // recycled between the listing and the open looks like.
    let alien = Alien(
        process::Command::new("/usr/bin/python3")
            .args(["-c", "import time; time.sleep(60)"])
            .spawn()
            .unwrap(),
    );
    let alien_pid = alien.0.id() as libc::pid_t;
    let group = client.group;
    // The stale listing names the alien as a child of the leader.
    client
        .track_in(|parent| {
            let mut pids = children_of(parent)?;
            if parent == group {
                pids.push(alien_pid);
            }
            Ok(pids)
        })
        .unwrap();
    let held: Vec<_> = client.members.iter().map(|member| member.pid).collect();
    assert!(held.contains(&real), "control: the real child is held");
    assert!(!held.contains(&alien_pid), "the alien was held: {held:?}");
    client.signal_members(libc::SIGKILL, 0).unwrap();
    assert!(
        gone(i64::from(real)),
        "control: the real child was signalled"
    );
    assert!(alive(alien_pid), "the alien was signalled");
}

/// Events of a run with the real parser. `ends_alone`: the supervisor is
/// expected to end the run by itself (a fatal event), so no Stop is sent.
fn real_parser_events(body: &str, ends_alone: bool) -> (Vec<Value>, Exit) {
    let scratch = Scratch::new();
    let instance = Instance::start_with(
        &scratch,
        body,
        params(Some(PIN)),
        Duration::from_secs(2),
        crate::connection::ssl_output::Output::default(),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    if !ends_alone {
        instance.writer.stop();
    }
    let events = instance.writer.events();
    let exit = instance.join().unwrap();
    (events, exit)
}

fn has(events: &[Value], wanted: Value) -> bool {
    events.contains(&wanted)
}

#[test]
fn the_real_parser_reports_the_interface_the_supervisor_configured() {
    let (events, exit) = real_parser_events(
        "print('INFO:   Interface vpntp1 is UP.', flush=True)\n\
         print('INFO:   vpnt: split-route 10.0.0.0/255.0.0.0', flush=True)\n\
         put('done', {})\nidle()\n",
        false,
    );
    assert_eq!(exit.reason, Reason::Stop, "a good interface is not fatal");
    assert!(has(
        &events,
        json!({"event": "interface", "name": "vpntp1"})
    ));
    assert!(has(
        &events,
        json!({"event": "split_route", "network": "10.0.0.0", "prefix": 8})
    ));
    assert!(!has(&events, json!({"event": "interface_mismatch"})));
}

#[test]
fn the_real_parser_types_any_other_interface_as_a_mismatch() {
    for other in ["ppp0", "vpntp2", "vpntp10", "eth0"] {
        let (events, exit) = real_parser_events(
            &format!(
                "print('INFO:   Interface {other} is UP.', flush=True)\n\
                 print('INFO:   vpnt: split-route 10.0.0.0/255.0.0.0', flush=True)\n\
                 print('INFO:   vpnt: dns-server 10.1.1.1', flush=True)\n\
                 put('done', {{}})\nidle()\n"
            ),
            true,
        );
        // The mismatch ends the instance by itself: the client was stopped.
        assert_eq!(exit.reason, Reason::Fatal, "{other}");
        assert!(exit.status.is_some(), "{other}: the client was reaped");
        assert!(
            has(&events, json!({"event": "interface_mismatch"})),
            "{other}: {events:?}"
        );
        assert!(
            events.iter().all(|event| event["event"] != "interface"),
            "{other} was reported as the interface"
        );
        // The `vpnt:` lines after it do not refer to the expected interface.
        assert!(has(&events, json!({"event": "split_invalid"})), "{other}");
        assert!(has(&events, json!({"event": "dns_invalid"})), "{other}");
        assert!(
            events.iter().all(|event| event["event"] != "split_route"),
            "{other}"
        );
    }
}

/// What the instance writes to its journal, kept in memory.
#[derive(Clone, Default)]
struct Journal(Arc<Mutex<Vec<u8>>>);

impl io::Write for Journal {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_instance_journals_only_fixed_client_states_once() {
    let scratch = Scratch::new();
    // The same recognized pppd line on both pipes and twice on one of them, and
    // an unknown line carrying an address on each.
    let body = r#"
print("Peer refused to agree to his IP address", file=sys.stderr, flush=True)
print("Peer refused to agree to his IP address", file=sys.stderr, flush=True)
print("Peer refused to agree to his IP address", flush=True)
print("rcvd address 10.20.30.40 for alice", file=sys.stderr, flush=True)
print("INFO:   Got addresses: [10.20.30.41]", flush=True)
put("done", {})
idle()
"#;
    let journal = Journal::default();
    let instance = Instance::start_with(
        &scratch,
        body,
        params(Some(PIN)),
        Duration::from_secs(2),
        journaling_observer(journal.clone()),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    instance.writer.stop();
    let events = instance.writer.events();
    assert_eq!(instance.join().unwrap().reason, Reason::Stop);
    assert_eq!(
        String::from_utf8(journal.0.lock().unwrap().clone()).unwrap(),
        "vpnt-tunneld: fortinet client: Peer refused to agree to his IP address\n"
    );
    // The journal is the only new destination: nothing of it reaches the writer.
    let wire = serde_json::to_string(&events).unwrap();
    for raw in ["Peer refused", "10.20.30.4", "alice"] {
        assert!(!wire.contains(raw), "{raw} reached the writer");
    }
}

#[test]
fn the_sweep_reports_a_kill_of_a_live_process_and_only_then() {
    let scratch = Scratch::new();
    let (client_path, pinentry) = fixtures(&scratch, "put('done', {})\nidle()\n");
    let config = Config {
        client: client_path.to_str().unwrap(),
        pinentry: pinentry.to_str().unwrap(),
        limits: limits(Duration::from_secs(1)),
        own_process: false,
    };
    let (spawn, null) = command(&config, &params(Some(PIN)), &PIN).unwrap();
    let mut client = Client::spawn(
        spawn,
        Secret::from(PASSWORD),
        false,
        FortinetDeadline::new().unwrap(),
    )
    .unwrap();
    drop(null);
    scratch.json("done");
    assert!(client.alive(), "control: the leader is running");
    assert!(client.sweep().unwrap(), "a live leader was killed");
    assert!(client.wait_exit(Duration::from_secs(5)).unwrap());
    assert!(
        !client.sweep().unwrap(),
        "nothing was alive the second time"
    );
    // Reaped here, as `terminate` does after its sweep.
    assert!(client.child.poll().unwrap().is_some());
    client.reaped = true;
}

fn start_order() -> Start {
    Start {
        host: "vpn.example.test".into(),
        port: 10443,
        username: "alice".into(),
        certificate_sha256: "ab".repeat(32),
        fortinet_local_cidr: "10.99.0.0/24".parse().unwrap(),
        interface: "eth0".into(),
        index: 7,
        gateway: Ipv4Addr::new(192, 0, 2, 10),
        ppp_ifname: "vpntp1".into(),
        establishment_deadline_ms: FortinetDeadline::new().unwrap().monotonic_ms,
    }
}

/// `serve` against fixtures; returns the supervisor's result and the events.
fn serve_fixture(
    scratch: &Scratch,
    first: &[u8],
    then_credential: bool,
) -> (io::Result<Exit>, Seq) {
    let (client, pinentry) = fixtures(scratch, "put('done', {})\nidle()\n");
    let (mut instance, writer) = Seq::pair();
    writer.put(first);
    if then_credential {
        writer.credential(PASSWORD);
        // A build that runs the client ends here instead of hanging.
        writer.stop();
    }
    let result = serve_with(
        &mut instance,
        &mut LineObserver::default(),
        Config {
            client: client.to_str().unwrap(),
            pinentry: pinentry.to_str().unwrap(),
            limits: Limits {
                credential_wait: Duration::from_millis(300),
                ..limits(Duration::from_secs(1))
            },
            own_process: false,
        },
    );
    (result, writer)
}

#[test]
fn the_start_order_becomes_exactly_the_parameters_the_supervisor_runs_with() {
    let params = start_order().params().unwrap();
    assert_eq!(params.endpoint.host(), "vpn.example.test");
    assert_eq!(params.endpoint.port(), 10443);
    assert_eq!(params.username, "alice");
    assert_eq!(params.certificate_sha256, Some([0xab; 32]));
    assert_eq!(
        params.binding,
        Binding {
            interface: "eth0".into(),
            index: 7,
            gateway: Ipv4Addr::new(192, 0, 2, 10),
        }
    );
    assert_eq!(params.pppd_ifname, "vpntp1");
    assert_eq!(params.fortinet_local_cidr, "10.99.0.0/24".parse().unwrap());
    let wire = serde_json::to_string(&start_order()).unwrap();
    assert!(!wire.contains(PASSWORD));
}

#[test]
fn hostile_start_orders_are_refused_before_anything_starts() {
    type Change = fn(&mut Start);
    let hostile: [(&str, Change); 14] = [
        ("short pin", |s| s.certificate_sha256 = "ab".repeat(31)),
        ("long pin", |s| s.certificate_sha256 = "ab".repeat(33)),
        ("upper-case pin", |s| s.certificate_sha256 = "AB".repeat(32)),
        ("non-hex pin", |s| s.certificate_sha256 = "zz".repeat(32)),
        ("zero pin", |s| s.certificate_sha256 = "00".repeat(32)),
        ("empty pin", |s| s.certificate_sha256 = String::new()),
        ("flag as host", |s| s.host = "--ca-file=/x".into()),
        ("host with a slash", |s| s.host = "a/b".into()),
        ("empty user", |s| s.username = String::new()),
        ("control in user", |s| s.username = "a\nb".into()),
        ("path as interface", |s| s.interface = "../eth0".into()),
        ("zero index", |s| s.index = 0),
        ("multicast gateway", |s| {
            s.gateway = Ipv4Addr::new(224, 0, 0, 1)
        }),
        ("foreign ppp name", |s| s.ppp_ifname = "ppp0;x".into()),
    ];
    for (label, change) in hostile {
        let mut start = start_order();
        change(&mut start);
        let scratch = Scratch::new();
        let (result, _) = serve_fixture(&scratch, &serde_json::to_vec(&start).unwrap(), true);
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{label}"
        );
        assert!(
            !scratch.path("client").exists(),
            "{label}: the client must not start"
        );
    }
    // Control: the same path with the good order does start the client.
    let scratch = Scratch::new();
    let (result, writer) =
        serve_fixture(&scratch, &serde_json::to_vec(&start_order()).unwrap(), true);
    let exit = result.unwrap();
    assert_eq!(exit.reason, Reason::Stop);
    // `started` is sent only after the client was spawned.
    let events = writer.events();
    assert_eq!(events.first().unwrap(), &json!({"event": "started"}));
    assert_eq!(events.last().unwrap()["event"], "exited");
}

#[test]
fn only_a_well_formed_start_object_is_accepted_as_the_first_datagram() {
    let scratch = Scratch::new();
    let good = serde_json::to_value(start_order()).unwrap();
    let mut extra = good.clone();
    extra["extra"] = json!(1);
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("gateway");
    for (label, bytes) in [
        ("unknown field", serde_json::to_vec(&extra).unwrap()),
        ("missing field", serde_json::to_vec(&missing).unwrap()),
        ("a credential frame first", credential_frame_of(PASSWORD)),
        ("garbage", b"{not json".to_vec()),
        ("not an object", b"[1]".to_vec()),
    ] {
        let (result, _) = serve_fixture(&scratch, &bytes, false);
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "{label}"
        );
    }
    assert!(!scratch.path("client").exists());
}

#[test]
fn start_requires_the_authenticated_establishment_deadline() {
    let scratch = Scratch::new();
    let mut order = serde_json::to_value(start_order()).unwrap();
    order
        .as_object_mut()
        .unwrap()
        .remove("establishment_deadline_ms");
    let (result, _) = serve_fixture(&scratch, &serde_json::to_vec(&order).unwrap(), true);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(!scratch.path("client").exists());
}

#[test]
fn start_rejects_an_expired_establishment_deadline() {
    let scratch = Scratch::new();
    let mut order = serde_json::to_value(start_order()).unwrap();
    order["establishment_deadline_ms"] = json!(crate::tunneld::protocol::monotonic_ms().unwrap());
    let (result, _) = serve_fixture(&scratch, &serde_json::to_vec(&order).unwrap(), true);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(!scratch.path("client").exists());
}

#[test]
fn establishment_deadline_ceiling_is_inclusive_and_expiry_is_exclusive() {
    let now = Duration::from_millis(100_000);
    let instant = Instant::now();
    let ceiling = FortinetDeadline::from_sample(135_000, now, instant).unwrap();
    assert_eq!(ceiling.instant, instant + Duration::from_secs(35));
    assert_eq!(
        FortinetDeadline::from_sample(135_001, now, instant)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        FortinetDeadline::from_sample(100_000, now, instant)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::TimedOut
    );

    let scratch = Scratch::new();
    let mut order = start_order();
    order.establishment_deadline_ms = u64::MAX;
    let (result, _) = serve_fixture(&scratch, &serde_json::to_vec(&order).unwrap(), true);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(!scratch.path("client").exists());
}

#[test]
fn instance_uses_the_writers_establishment_deadline_after_tls() {
    let scratch = Scratch::new();
    let (client, pinentry) = fixtures(&scratch, "time.sleep(1.5)\npin('after-cutoff')\n");
    let (mut writer, mut instance) = real_pair(&scratch);
    let mut order = serde_json::to_value(start_order()).unwrap();
    order["establishment_deadline_ms"] =
        json!(crate::tunneld::protocol::monotonic_ms().unwrap() + 1_000);
    writer.send(&serde_json::to_vec(&order).unwrap()).unwrap();
    writer.send(&credential_frame(PASSWORD)).unwrap();
    let exit = serve_with(
        &mut instance,
        &mut LineObserver::default(),
        Config {
            client: client.to_str().unwrap(),
            pinentry: pinentry.to_str().unwrap(),
            limits: limits(Duration::from_secs(1)),
            own_process: false,
        },
    )
    .unwrap();
    assert_eq!(exit.reason, Reason::ClientExited);
    let result = scratch.json("pinentry.after-cutoff");
    assert_eq!(result["password"], Value::Null, "{result}");
    assert!(result["error"].is_string(), "{result}");
}

fn credential_frame_of(password: &str) -> Vec<u8> {
    super::credential_frame(password).unwrap().to_vec()
}

#[test]
fn stop_or_eof_before_the_start_order_ends_without_a_client() {
    let scratch = Scratch::new();
    let (result, _) = serve_fixture(&scratch, &[MESSAGE_STOP], false);
    let exit = result.unwrap();
    assert_eq!((exit.reason, exit.status.is_none()), (Reason::Stop, true));
    // EOF: the writer goes away before sending anything.
    let (client, pinentry) = fixtures(&scratch, "idle()\n");
    let (mut instance, writer) = Seq::pair();
    drop(writer);
    let exit = serve_with(
        &mut instance,
        &mut LineObserver::default(),
        Config {
            client: client.to_str().unwrap(),
            pinentry: pinentry.to_str().unwrap(),
            limits: limits(Duration::from_secs(1)),
            own_process: false,
        },
    )
    .unwrap();
    assert_eq!(exit.reason, Reason::ChannelClosed);
    // Silence ends in a timeout, not a hang.
    let (_instance_end, writer) = Seq::pair();
    let mut silent = _instance_end;
    let error = serve_with(
        &mut silent,
        &mut LineObserver::default(),
        Config {
            client: client.to_str().unwrap(),
            pinentry: pinentry.to_str().unwrap(),
            limits: Limits {
                credential_wait: Duration::from_millis(150),
                ..limits(Duration::from_secs(1))
            },
            own_process: false,
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    drop(writer);
    assert!(!scratch.path("client").exists());
}

#[test]
fn the_writers_credential_frame_is_what_the_supervisor_decodes() {
    let mut frame = Datagram::from_vec(credential_frame_of(PASSWORD));
    let Ok(Message::Credential(secret)) = decode(&mut frame) else {
        panic!("the writer's frame was refused");
    };
    assert_eq!(secret.expose(), PASSWORD);
    for bad in ["", &"p".repeat(257)] {
        assert!(super::credential_frame(bad).is_err(), "{} bytes", bad.len());
    }
    assert!(super::credential_frame(&"p".repeat(256)).is_ok());
}

#[test]
fn events_round_trip_and_unknown_ones_are_refused() {
    for event in [
        Event::Started,
        Event::Interface {
            name: "vpntp1".into(),
        },
        Event::Failure {
            kind: Failure::GatewayTimeout,
        },
        Event::SplitRoute {
            network: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8,
        },
        Event::SplitRoutes { count: 1 },
        Event::SplitInvalid,
        Event::InterfaceMismatch,
        Event::DnsServer {
            address: Ipv4Addr::new(10, 1, 1, 1),
        },
        Event::DnsDomain {
            name: "corp.example.test".into(),
        },
        Event::DnsCount {
            servers: 1,
            domains: 1,
        },
        Event::DnsInvalid,
        Event::Exited {
            code: Some(1),
            signal: None,
        },
    ] {
        let wire = serde_json::to_vec(&event).unwrap();
        assert_eq!(serde_json::from_slice::<Event>(&wire).unwrap(), event);
    }
    for bad in [
        r#"{"event":"interface","name":"vpntp1","extra":1}"#,
        r#"{"event":"unknown"}"#,
        r#"{"event":"failure","kind":"nope"}"#,
        r#"{"name":"vpntp1"}"#,
    ] {
        assert!(serde_json::from_str::<Event>(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_fatal_event_makes_the_supervisor_stop_the_client_and_exit_by_itself() {
    // The writer sends nothing: the instance ends on its own, after reporting.
    let cases: [(&str, &str, &str); 2] = [
        (
            "interface_mismatch",
            "print('INFO:   Interface ppp0 is UP.', flush=True)\n",
            "interface_mismatch",
        ),
        (
            "credentials_rejected",
            "print('ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.', flush=True)\n",
            "failure",
        ),
    ];
    for (label, line, event) in cases {
        let scratch = Scratch::new();
        let body = format!("{line}put('done', {{}})\nidle()\n");
        let instance = Instance::start(&scratch, &body, params(Some(PIN)), Duration::from_secs(2));
        instance.writer.credential(PASSWORD);
        scratch.json("done");
        let pid = pids(&scratch);
        let events = instance.writer.events();
        let exit = instance.join().unwrap();
        assert_eq!(exit.reason, Reason::Fatal, "{label}");
        assert!(
            events.iter().any(|e| e["event"] == event),
            "{label}: {events:?}"
        );
        assert_eq!(events.last().unwrap()["event"], "exited", "{label}");
        assert!(exit.descendants_gone, "{label}");
        assert!(gone(pid), "{label}: the client outlived the fatal event");
    }
    // Control: observations that are not fatal keep the run going until Stop.
    let scratch = Scratch::new();
    let body = "print('INFO:   Interface vpntp1 is UP.', flush=True)\nput('done', {})\nidle()\n";
    let instance = Instance::start(&scratch, body, params(Some(PIN)), Duration::from_secs(2));
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    thread::sleep(Duration::from_millis(300));
    assert!(!instance.thread.is_finished(), "a good run ended by itself");
    instance.writer.stop();
    assert_eq!(instance.join().unwrap().reason, Reason::Stop);
}
