//! The openfortivpn and the pinentry are Python fixtures: they record what the
//! supervisor gave them (argv, environment, descriptors) in the scratch
//! directory, and the tests read it from outside.
use super::*;
use crate::test_support::write_script;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    os::{
        fd::AsFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::Path,
    process,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
};

const PIN: [u8; 32] = [0xab; 32];
const PASSWORD: &str = "pw-SENTINEL-4f9c";
const HELPER_ENV: &str = "VPNT_FORTINET_INSTANCE_HELPER";
const WAIT: Duration = Duration::from_secs(10);

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
        let mut frame = vec![MESSAGE_CREDENTIAL];
        frame.extend_from_slice(&(password.len() as u16).to_be_bytes());
        frame.extend_from_slice(password.as_bytes());
        self.put(&frame);
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

    fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.take(Duration::ZERO)?
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
}

impl Observer for LineObserver {
    fn attach(&mut self, pipe: File) -> io::Result<()> {
        use std::io::{BufRead, BufReader};
        let seen = Arc::clone(&self.seen);
        self.readers.push(thread::spawn(move || {
            for line in BufReader::new(pipe).split(b'\n').map_while(Result::ok) {
                let line = String::from_utf8_lossy(&line).into_owned();
                let mut seen = seen.lock().unwrap();
                if let Some(name) = line
                    .strip_prefix("INFO:   Interface ")
                    .and_then(|rest| rest.strip_suffix(" is UP."))
                {
                    seen.candidate = Some(name.to_owned());
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

    fn finish(&mut self) {
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
    }
}

fn params(pin: Option<[u8; 32]>, ca_file: Option<&str>) -> Params {
    Params::new(
        Endpoint::new("vpn.example.test".into(), 10443).unwrap(),
        "alice".into(),
        pin,
        Binding {
            interface: "eth0".into(),
            index: 7,
            gateway: Ipv4Addr::new(192, 0, 2, 10),
        },
        ca_file.map(PathBuf::from),
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
        let (client, pinentry) = fixtures(scratch, body);
        let (instance, writer) = Seq::pair();
        let thread = thread::spawn(move || {
            let mut instance = instance;
            run_with(
                &mut instance,
                params,
                &mut LineObserver::default(),
                Config {
                    client: client.to_str().unwrap(),
                    pinentry: pinentry.to_str().unwrap(),
                    limits: limits(grace),
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

fn expected_argv(pinentry: &Path, ca_file: Option<&str>) -> Vec<String> {
    let mut argv: Vec<String> = [
        "--config=/dev/null",
        "--no-routes",
        "--no-dns",
        "--pppd-no-peerdns",
        "--pppd-accept-remote=0",
        "--persistent=0",
        "--username=alice",
    ]
    .map(String::from)
    .into();
    argv.push(format!("--pinentry={}", pinentry.display()));
    argv.extend(ca_file.map(|path| format!("--ca-file={path}")));
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
fn argv_is_exact_and_always_pins_the_certificate() {
    for ca_file in [None, Some("/etc/vpnt/ca.pem")] {
        let scratch = Scratch::new();
        let instance = Instance::start(
            &scratch,
            "put('done', {})\nidle()\n",
            params(Some(PIN), ca_file),
            Duration::from_secs(2),
        );
        instance.writer.credential(PASSWORD);
        let argv: Vec<String> =
            serde_json::from_value(scratch.json("client")["argv"].clone()).unwrap();
        assert_eq!(argv, expected_argv(&scratch.path("vpnt-pinentry"), ca_file));
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
        instance.writer.stop();
        assert_eq!(instance.join().unwrap().reason, Reason::Stop);
    }
}

#[test]
fn password_reaches_the_pinentry_once_and_nothing_else() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "pin('first')\npin('second')\nput('done', {})\nidle()\n",
        params(Some(PIN), None),
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
fn only_stdio_and_the_pinentry_descriptor_reach_the_client() {
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
        params(Some(PIN), None),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let client = scratch.json("client");
    let numbers: BTreeSet<_> = client["fds"].as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        numbers,
        ["0", "1", "2", "3"].map(String::from).into(),
        "{client}"
    );
    assert_eq!(client["stdin"], "/dev/null");
    assert!(client["fds"]["1"].as_str().unwrap().starts_with("pipe:"));
    assert!(client["fds"]["2"].as_str().unwrap().starts_with("pipe:"));
    assert!(client["fds"]["3"].as_str().unwrap().starts_with("socket:"));
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
            params(pin, None),
            &mut LineObserver::default(),
            Config {
                client: client.to_str().unwrap(),
                pinentry: pinentry.to_str().unwrap(),
                limits: limits(Duration::from_secs(1)),
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
        params(Some(PIN), None),
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
print("INFO:   Interface ppp0 is UP.", flush=True)
print("INFO:   vpnt: split-route 10.0.0.0/255.0.0.0", file=sys.stderr, flush=True)
print("INFO:   vpnt: dns-server 10.1.1.1", flush=True)
print("INFO:   vpnt: dns-domain corp.example.test", flush=True)
print("INFO:   token=RAWLINE-SECRET gateway said so", file=sys.stderr, flush=True)
put("done", {})
idle()
"#;
    let instance = Instance::start(
        &scratch,
        body,
        params(Some(PIN), None),
        Duration::from_secs(2),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    instance.writer.stop();
    let events = instance.writer.events();
    assert_eq!(instance.join().unwrap().reason, Reason::Stop);

    let mut seen: Vec<String> = events.iter().map(Value::to_string).collect();
    seen.sort();
    let mut expected: Vec<String> = [
        json!({"event": "started"}),
        json!({"event": "interface", "name": "ppp0"}),
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
    let instance = Instance::start(
        &scratch,
        &body,
        params(Some(PIN), None),
        Duration::from_secs(2),
    );
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
    let instance = Instance::start(&scratch, &body, params(Some(PIN), None), grace);
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
    let instance = Instance::start(
        &scratch,
        &body,
        params(Some(PIN), None),
        Duration::from_secs(5),
    );
    instance.writer.credential(PASSWORD);
    scratch.json("done");
    let grandchild = scratch.json("grandchild")["pid"].as_i64().unwrap();
    assert!(
        fs::metadata(format!("/proc/{grandchild}")).is_ok(),
        "control: alive"
    );
    instance.writer.stop();
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::Stop);
    assert!(!exit.escalated, "the leader left on TERM, within the grace");
    assert_eq!(exit.status.unwrap().code(), Some(0));
    assert!(exit.descendants_gone);
    assert!(gone(grandchild), "the descendant outlived the leader");
}

#[test]
fn client_exit_is_reported_with_its_status() {
    let scratch = Scratch::new();
    let instance = Instance::start(
        &scratch,
        "put('done', {})\ntime.sleep(0.2)\nsys.exit(3)\n",
        params(Some(PIN), None),
        Duration::from_secs(1),
    );
    instance.writer.credential(PASSWORD);
    let events = instance.writer.events();
    let exit = instance.join().unwrap();
    assert_eq!(exit.reason, Reason::ClientExited);
    assert_eq!(exit.status.unwrap().code(), Some(3));
    assert!(!exit.escalated);
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
        params(Some(PIN), None),
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
        params(Some(PIN), None),
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
        };
        match case {
            "stop" => writer.stop(),
            "eof" => drop(writer),
            _ => {}
        }
        let result = run_with(
            &mut instance,
            params(Some(PIN), None),
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
        let error = run(
            &mut channel,
            params(None, None),
            &mut LineObserver::default(),
        )
        .unwrap_err();
        // SAFETY: as above.
        let after = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        fs::write(
            dir.join("dumpable"),
            format!("{before} {after} {:?}", error.kind()),
        )
        .unwrap();
        return;
    }
    let client = fields.next().unwrap();
    let pinentry = fields.next().unwrap();
    let _ = run_with(
        &mut channel,
        params(Some(PIN), None),
        &mut LineObserver::default(),
        Config {
            client,
            pinentry,
            limits: limits(Duration::from_secs(2)),
        },
    );
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
fn run_makes_the_supervisor_non_dumpable_before_anything_else() {
    let scratch = Scratch::new();
    let (instance, _writer) = Seq::pair();
    let mut helper = spawn_helper("dumpable", &scratch, "", &instance);
    assert!(helper.wait().unwrap().success());
    assert_eq!(
        fs::read_to_string(scratch.path("dumpable")).unwrap(),
        "1 0 InvalidInput"
    );
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
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(&case);
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();
        let message = decode(&mut bytes);
        // SAFETY: `bytes` is alive; zeroize wrote zeros over its whole capacity.
        let memory = unsafe { std::slice::from_raw_parts(pointer, capacity) };
        assert!(
            memory.iter().all(|&byte| byte == 0),
            "{case:?} left bytes behind"
        );
        assert!(bytes.is_empty());
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
    now.candidate = Some("ppp0".into());
    now.failure = Some(Failure::GatewayTimeout);
    now.split = vec![(Ipv4Addr::new(10, 0, 0, 0), 8)];
    now.split_count = Some(1);
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
                name: "ppp0".into()
            },
            Event::Failure {
                kind: Failure::GatewayTimeout
            },
            Event::SplitRoute {
                network: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8
            },
            Event::SplitRoutes { count: 1 },
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
    let hostile = [
        ("", binding("eth0", 1, ok), None),
        ("a\nb", binding("eth0", 1, ok), None),
        (&*"u".repeat(65), binding("eth0", 1, ok), None),
        ("alice", binding("", 1, ok), None),
        ("alice", binding("eth0 --x", 1, ok), None),
        ("alice", binding("a-very-long-name-x", 1, ok), None),
        ("alice", binding("eth0", 0, ok), None),
        ("alice", binding("eth0", 1, Ipv4Addr::UNSPECIFIED), None),
        ("alice", binding("eth0", 1, Ipv4Addr::BROADCAST), None),
        (
            "alice",
            binding("eth0", 1, Ipv4Addr::new(224, 0, 0, 1)),
            None,
        ),
        ("alice", binding("eth0", 1, ok), Some("relative/ca.pem")),
    ];
    for (username, binding, ca_file) in hostile {
        let result = Params::new(
            endpoint(),
            username.into(),
            Some(PIN),
            binding.clone(),
            ca_file.map(PathBuf::from),
        );
        assert!(result.is_err(), "{username:?} {binding:?} {ca_file:?}");
    }
    assert!(
        Params::new(
            endpoint(),
            "alice".into(),
            Some(PIN),
            binding("eth0", 1, ok),
            None
        )
        .is_ok()
    );
}
