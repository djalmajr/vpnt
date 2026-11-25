use super::*;
use crate::{
    test_support::write_script,
    tunneld::{instance_protocol::encode_credentials, protocol},
};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

const REEXEC: &str = "tunneld::ipsec_instance::tests::supervisor_process";
const FIXTURE: &str = "VPNT_IPSEC_INSTANCE_FIXTURE";
const SENTINEL: &str = "vpnt synthetic supervisor memory marker";

const FAKE: &str = r#"#!/usr/bin/python3
import json, os, pathlib, re, signal, socket, struct
import sys, threading, time

conf = pathlib.Path(os.environ['STRONGSWAN_CONF'])
instance = conf.parent
root = instance.parent
text = conf.read_text()
fds = {}
for fd in os.listdir('/proc/self/fd'):
    try:
        fds[fd] = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError:
        pass
try:
    fd = os.open('/proc/%d/mem' % os.getppid(), os.O_RDONLY)
except OSError as error:
    mem = error.errno
else:
    os.close(fd)
    mem = 0

path = re.search(r'socket = "unix://([^"]+)"', text)[1]
vici = socket.socket(socket.AF_UNIX)
old_umask = os.umask(0o117)
try:
    vici.bind(path)
finally:
    os.umask(old_umask)
vici.listen()
def term(*_):
    (root / 'term').touch()
    if not (root / 'ignore-term').exists():
        sys.exit(0)
signal.signal(signal.SIGTERM, term)
tmp = root / 'starting'
tmp.write_text(json.dumps(dict(pid=os.getpid(), pgid=os.getpgrp(),
    argc=len(sys.argv), program=sys.argv[0], conf=str(conf),
    env_keys=sorted(entry.split(b'=', 1)[0].decode()
        for entry in pathlib.Path('/proc/self/environ').read_bytes().split(b'\0') if entry),
    fds=fds, mem=mem, cwd=os.getcwd())))
tmp.rename(root / 'ready')
def read_exact(conn, size):
    result = bytearray()
    while len(result) < size:
        part = conn.recv(size - len(result))
        if not part:
            raise EOFError
        result.extend(part)
    return result

def short(value):
    return bytes([len(value)]) + value

def blob(value):
    return struct.pack('!H', len(value)) + value

def encode(message):
    result = bytearray()
    for key, value in message.items():
        name = short(key.encode())
        if isinstance(value, dict):
            result += b'\x01' + name + encode(value) + b'\x02'
        elif isinstance(value, list):
            result += b'\x04' + name
            for item in value:
                result += b'\x05' + blob(item.encode())
            result += b'\x06'
        else:
            result += b'\x03' + name + blob(value.encode())
    return result

def decode(data):
    index = 0
    def number(size):
        nonlocal index
        value = int.from_bytes(data[index:index + size], 'big')
        index += size
        return value
    def text(size):
        nonlocal index
        length = number(size)
        value = data[index:index + length].decode()
        index += length
        return value
    def message():
        fields = {}
        while index < len(data):
            tag = number(1)
            if tag == 2:
                break
            key = text(1)
            if tag == 1:
                fields[key] = message()
            elif tag == 3:
                fields[key] = text(2)
            elif tag == 4:
                items = []
                while number(1) == 5:
                    items.append(text(2))
                fields[key] = items
            else:
                raise ValueError('unexpected VICI field')
        return fields
    return message()

def reply(conn, kind, message=None, event=None):
    frame = bytes([kind])
    if event:
        frame += short(event.encode())
    if message:
        frame += encode(message)
    conn.sendall(struct.pack('!I', len(frame)) + frame)

def serve(conn):
    with conn:
        try:
            packet = read_exact(conn, int.from_bytes(read_exact(conn, 4), 'big'))
            if packet[0] == 3:
                reply(conn, 5)
                packet = read_exact(conn, int.from_bytes(read_exact(conn, 4), 'big'))
            assert packet[0] == 0
            end = packet[1] + 2
            command = packet[2:end].decode()
            request = decode(packet[end:])
            if command == 'load-shared':
                request['credential_matches'] = request.pop('data') == {
                    'EAP': 'synthetic-password', 'IKE': 'synthetic-psk'
                }.get(request['type'])
            with (root / 'vici-commands').open('a') as log:
                log.write(json.dumps([command, request]) + '\n')
            if command == 'version':
                reply(conn, 1, {'daemon': 'charon', 'version': '6.1.0'})
            elif command == 'stats':
                plugins = ['kernel-netlink', 'socket-default', 'vici']
                if (root / 'foreign-backend').exists():
                    plugins.append('kernel-libipsec')
                reply(conn, 1, {'plugins': plugins})
            elif command == 'list-sas':
                if (root / 'slow-list-sas').exists():
                    (root / 'negotiating').touch()
                    patience = time.time() + 6
                    while not (root / 'release').exists() and time.time() < patience:
                        time.sleep(0.05)
                reply(conn, 7, {request['ike']: {
                    'state': 'ESTABLISHED', 'version': '2', 'initiator': 'yes',
                    'remote-host': '192.0.2.10', 'remote-port': '4500',
                    'local-vips': ['198.51.100.17'],
                    'child-sas': {request['ike'] + '-child-1': {
                        'name': request['ike'] + '-child', 'uniqueid': '1',
                        'state': 'INSTALLED', 'mode': 'TUNNEL', 'protocol': 'ESP',
                        'reqid': '567', 'if-id-in': '00001234',
                        'if-id-out': '00005678' if (root / 'wrong-if-id').exists() else '00001234',
                        'local-ts': ['198.51.100.17/32'], 'remote-ts': ['198.51.100.128/25'],
                    }},
                }}, 'list-sa')
                reply(conn, 1)
            elif command == 'initiate' and (root / 'fail-initiate').exists():
                reply(conn, 1, {'success': 'no', 'errmsg': 'synthetic-psk'})
            else:
                reply(conn, 1, {'success': 'yes'})
        except (EOFError, OSError):
            pass

while True:
    conn, _ = vici.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
"#;

fn fixture_start(identity: &str) -> Start {
    Start {
        remote_ipv4: "192.0.2.10".parse().unwrap(),
        port: 500,
        peer_identity: identity.into(),
        username: "fixture-user".into(),
        if_id: 0x1234,
        reqid: 567,
        local_ts: vec!["dynamic".into()],
        remote_ts: vec![CidrV4::new("198.51.100.0".parse().unwrap(), 24).unwrap()],
    }
}

fn fixture_credentials() -> Zeroizing<Vec<u8>> {
    encode_credentials(
        &protocol::Credentials::ipsec("synthetic-password", "synthetic-psk").unwrap(),
    )
    .unwrap()
}

fn send_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

struct FixtureChannel(UnixStream);

impl InstanceChannel for FixtureChannel {
    fn receive(&mut self, child: Option<BorrowedFd<'_>>) -> io::Result<Datagram> {
        // Like the real channel, a backend exit is reported first and leaves
        // the channel usable for one terminal reply.
        if let Some(child) = child {
            let mut entries = [
                libc::pollfd {
                    fd: child.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.0.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: poll updates just the two supplied entries.
            checked(unsafe { libc::poll(entries.as_mut_ptr(), 2, -1) })?;
            if entries[0].revents != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "backend process exited",
                ));
            }
        }
        let mut size = [0; 4];
        self.0.read_exact(&mut size)?;
        let mut bytes = vec![0; u32::from_be_bytes(size) as usize];
        self.0.read_exact(&mut bytes)?;
        Ok(Datagram::from_vec(bytes))
    }

    fn wait_control(&mut self, timeout: Duration) -> io::Result<bool> {
        let mut entry = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = timeout.as_millis() as libc::c_int;
        // SAFETY: poll updates just the supplied entry.
        let ready = unsafe { libc::poll(&mut entry, 1, millis) };
        checked(ready)?;
        Ok(ready > 0)
    }

    fn send(&mut self, reply: &Reply) -> io::Result<()> {
        serde_json::to_writer(&mut self.0, reply)?;
        self.0.write_all(b"\n")
    }
}

struct Fixture {
    root: PathBuf,
    writer: UnixStream,
    supervisor: Child,
    backend_pidfd: Option<OwnedFd>,
    replies: Vec<Reply>,
    /// Output already read from the supervisor while waiting for `Established`.
    early: Vec<u8>,
}

impl Fixture {
    fn launch(ignore_term: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "vpnt-i2c-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("instance"))
            .unwrap();
        write_script(&root.join("charon"), FAKE);
        if ignore_term {
            fs::write(root.join("ignore-term"), []).unwrap();
        }
        let (writer, reader) = UnixStream::pair().unwrap();
        let reader: OwnedFd = reader.into();
        let supervisor = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", REEXEC, "--nocapture"])
            .env_clear()
            .env(FIXTURE, &root)
            .env("RUNTIME_DIRECTORY", root.join("instance"))
            .stdin(Stdio::from(reader))
            .stdout(fs::File::create(root.join("supervisor.stdout")).unwrap())
            .stderr(fs::File::create(root.join("supervisor.stderr")).unwrap())
            .spawn()
            .unwrap();
        writer
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        Self {
            root,
            writer,
            supervisor,
            backend_pidfd: None,
            replies: Vec::new(),
            early: Vec::new(),
        }
    }

    /// Start and wait until the supervisor has published `Established`, so
    /// that a later order cannot overtake the negotiation.
    fn start(&mut self) -> serde_json::Value {
        self.start_with(fixture_start("fqdn:fixture.example"))
    }

    fn start_with(&mut self, start: Start) -> serde_json::Value {
        let ready = self.begin(start);
        let mut byte = [0];
        while self.early.last() != Some(&b'\n') {
            self.writer.read_exact(&mut byte).unwrap();
            self.early.push(byte[0]);
        }
        ready
    }

    /// Start without waiting: the negotiation may still be in progress.
    fn begin(&mut self, start: Start) -> serde_json::Value {
        self.send_bytes(&serde_json::to_vec(&Order::Start(start)).unwrap());
        self.send_bytes(&fixture_credentials());
        let deadline = Instant::now() + Duration::from_secs(5);
        let ready = loop {
            match fs::read(self.root.join("ready")) {
                Ok(contents) => break contents,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    assert!(self.supervisor.try_wait().unwrap().is_none());
                    assert!(
                        Instant::now() < deadline,
                        "fake did not publish VICI readiness"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("fake readiness: {error}"),
            }
        };
        let ready: serde_json::Value = serde_json::from_slice(&ready).unwrap();
        self.backend_pidfd = Some(pidfd_open(ready["pid"].as_u64().unwrap() as u32).unwrap());
        ready
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        send_frame(&mut self.writer, bytes).unwrap();
    }

    fn wait_for(&mut self, marker: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.root.join(marker).exists() {
            assert!(self.supervisor.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline, "fake never reached {marker}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(&mut self, action: Option<&[u8]>) -> String {
        match action {
            Some(b"T") => self.send_bytes(br#"{"op":"stop"}"#),
            Some(bytes) => self.send_bytes(bytes),
            None => self.writer.shutdown(std::net::Shutdown::Write).unwrap(),
        }
        self.collect()
    }

    /// Read what the supervisor says until it exits, without sending anything.
    fn collect(&mut self) -> String {
        let mut answer = String::from_utf8(std::mem::take(&mut self.early)).unwrap();
        self.writer.read_to_string(&mut answer).unwrap();
        assert!(self.supervisor.wait().unwrap().success());
        assert!(
            fs::read_dir(self.root.join("instance"))
                .unwrap()
                .next()
                .is_none()
        );
        if let Some(fd) = &self.backend_pidfd {
            assert!(poll_until(fd, Instant::now()).unwrap());
        }
        let mut output = answer.lines();
        let status = output.next_back().expect("supervisor outcome").to_owned();
        self.replies = output
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for log in ["supervisor.stdout", "supervisor.stderr"] {
            let content = fs::read_to_string(self.root.join(log)).unwrap();
            for secret in ["synthetic-password", "synthetic-psk"] {
                assert!(!content.contains(secret), "credential in {log}");
            }
        }
        status
    }

    fn commands(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.root.join("vici-commands"))
            .expect("expected private VICI exchanges before shutdown")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(fd) = &self.backend_pidfd {
            let _ = pidfd_signal(fd, libc::SIGKILL);
        }
        if matches!(self.supervisor.try_wait(), Ok(None)) {
            let _ = self.supervisor.kill();
            let _ = self.supervisor.wait();
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn supervisor_process() {
    let Some(root) = std::env::var_os(FIXTURE).map(PathBuf::from) else {
        return;
    };
    // Duplicate the fixture channel on an intentionally inheritable descriptor.
    // This makes the exec-wide FD invariant independent of Rust's socket defaults.
    // SAFETY: FD 0 is the fixture socket supplied by Command::stdin.
    let raw = unsafe { libc::fcntl(0, libc::F_DUPFD, 3) };
    assert!(raw >= 3);
    // SAFETY: fcntl returned a new owned FD.
    let mut channel = FixtureChannel(UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) }));
    let result = run_with(
        &mut channel,
        &Params {
            directory: std::env::var_os("RUNTIME_DIRECTORY").unwrap().into(),
        },
        &root.join("charon"),
        unsafe { (libc::geteuid(), libc::getegid()) },
    );
    std::hint::black_box(SENTINEL);
    let answer = match result {
        Ok(exit) => format!("{exit:?}"),
        Err(error) => format!("error: {:?}", error.kind()),
    };
    channel.0.write_all(answer.as_bytes()).unwrap();
}

#[test]
fn vici_socket_admission_checks_mode_type_and_owner() {
    struct SocketDirectory(PathBuf);

    impl Drop for SocketDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    let pid = std::process::id();
    let directory = std::env::temp_dir().join(format!("vpnt-vici-mode-{pid}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let directory = SocketDirectory(directory);
    let path = directory.0.join(VICI_SOCKET_NAME);
    let listener = UnixListener::bind(&path).unwrap();
    let child = pidfd_open(pid).unwrap();
    // SAFETY: these calls take no arguments or pointers.
    let owner = unsafe { (libc::geteuid(), libc::getegid()) };
    let mut vici = PrivateVici {
        path: &path,
        child: &child,
        pid,
        owner,
        loaded: false,
        cancel: Arc::default(),
    };
    let deadline = || Instant::now() + Duration::from_secs(1);
    let assert_rejected = |vici: &PrivateVici<'_>, case| {
        let error = vici.open(deadline()).err().expect(case);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{case}");
        assert_eq!(error.to_string(), "unsafe IPsec VICI socket", "{case}");
    };

    for mode in [0o600, 0o660] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        if let Err(error) = vici.open(deadline()) {
            panic!("VICI socket mode {mode:#o} rejected: {error}");
        }
        listener.accept().unwrap();
    }

    for (mode, case) in [
        (0o606, "other read/write"),
        (0o604, "other read"),
        (0o700, "owner execute"),
        (0o770, "owner and group execute"),
        (0o4600, "setuid"),
        (0o2600, "setgid"),
        (0o1600, "sticky"),
    ] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, mode);
        assert_rejected(&vici, case);
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    vici.owner = (owner.0 ^ 1, owner.1);
    assert_rejected(&vici, "wrong uid");
    vici.owner = (owner.0, owner.1 ^ 1);
    assert_rejected(&vici, "wrong gid");

    vici.owner = owner;
    drop(listener);
    fs::remove_file(&path).unwrap();
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert_rejected(&vici, "regular file");
}

#[test]
fn exec_is_private_and_stop_cleans_up() {
    let mut fixture = Fixture::launch(false);
    let ready = fixture.start();
    let dir = fixture.root.join("instance");
    let conf = dir.join("strongswan.conf");
    let socket = dir.join("vici.sock");
    assert_eq!(ready["argc"], 1);
    assert_eq!(
        ready["program"],
        fixture.root.join("charon").to_str().unwrap()
    );
    assert_eq!(ready["conf"], conf.to_str().unwrap());
    assert_eq!(ready["cwd"], dir.to_str().unwrap());
    assert_eq!(ready["env_keys"], serde_json::json!(["STRONGSWAN_CONF"]));
    assert_eq!(
        ready["fds"],
        serde_json::json!({"0":"/dev/null","1":"/dev/null","2":"/dev/null"})
    );
    assert!(
        matches!(ready["mem"].as_i64(), Some(errno) if errno == i64::from(libc::EACCES) || errno == i64::from(libc::EPERM))
    );
    assert_eq!(ready["pid"], ready["pgid"]);
    assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&conf).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o660);
    assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());
    let mut contents: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    contents.sort();
    assert_eq!(contents, ["strongswan.conf", "vici.sock"]);
    assert!(!fixture.root.join("vici.sock").exists());
    let config = fs::read_to_string(conf).unwrap();
    assert!(config.contains("load = aes sha1 sha2 md4 hmac kdf random nonce openssl eap-identity eap-mschapv2 kernel-netlink socket-default vici"));
    for setting in [
        "load_modular = no",
        "install_routes = no",
        "install_virtual_ip = no",
        "routing_table = 0",
        "install_routes_xfrmi = no",
        "port_bypass = no",
        "follow_redirects = no",
    ] {
        assert!(config.contains(setting), "missing {setting}");
    }
    assert!(config.contains(&format!("socket = \"unix://{}\"", socket.display())));
    assert!(!config.contains("include"));
    assert!(!config.contains("/etc/"));
    assert_eq!(fixture.finish(Some(b"T")), "Stopped");
    assert!(fixture.root.join("term").exists());
}

#[test]
fn loads_frozen_ipv4_and_credentials_before_starting_ipsec() {
    let mut fixture = Fixture::launch(false);
    fixture.start();
    assert_eq!(fixture.finish(Some(b"T")), "Stopped");
    let commands = fixture.commands();
    assert_eq!(
        fixture.replies,
        [
            Reply::Established {
                if_id: 0x1234,
                reqid: 567,
                virtual_ipv4: "198.51.100.17".parse().unwrap(),
                remote_ts: vec![CidrV4::new("198.51.100.128".parse().unwrap(), 25).unwrap()],
            },
            Reply::Stopped {},
        ]
    );
    assert_eq!(
        commands
            .iter()
            .map(|entry| entry[0].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "version",
            "stats",
            "load-conn",
            "load-shared",
            "load-shared",
            "initiate",
            "list-sas",
            "terminate",
            "unload-conn",
            "unload-shared",
            "unload-shared"
        ]
    );
    let connection = commands[2][1].as_object().unwrap().values().next().unwrap();
    assert_eq!(
        connection["remote_addrs"],
        serde_json::json!(["192.0.2.10"])
    );
    assert_eq!(connection["version"], "2");
    assert_eq!(connection["mobike"], "no");
    assert_eq!(connection["remote"]["id"], "fqdn:fixture.example");
    let child = connection["children"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(child["reqid"], "567");
    assert_eq!(child["if_id_in"], "4660");
    assert_eq!(child["if_id_out"], "4660");
    assert_eq!(commands[3][1]["credential_matches"], true);
    assert_eq!(commands[4][1]["credential_matches"], true);
    assert_eq!(connection["vips"], serde_json::json!(["0.0.0.0"]));
    assert_eq!(connection["local"]["auth"], "eap-mschapv2");
    assert_eq!(connection["remote"]["auth"], "psk");
    assert_eq!(child["local_ts"], serde_json::json!(["dynamic"]));
    assert_eq!(child["remote_ts"], serde_json::json!(["198.51.100.0/24"]));
    assert_eq!(
        commands[3][1]["owners"],
        serde_json::json!(["fqdn:fixture-user"])
    );
    assert_eq!(
        commands[4][1]["owners"],
        serde_json::json!(["fqdn:fixture.example"])
    );
    assert!(!commands[3][1].as_object().unwrap().contains_key("data"));
    assert!(!commands[4][1].as_object().unwrap().contains_key("data"));
    assert!(
        commands[5][1]["timeout"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .is_ok_and(|ms| (1..=30_000).contains(&ms))
    );
}

#[test]
fn sends_typed_ipv4_identity_without_using_it_as_the_transport_address() {
    let mut fixture = Fixture::launch(false);
    fixture.start_with(fixture_start("ipv4:192.0.2.99"));
    assert_eq!(fixture.finish(Some(b"T")), "Stopped");
    let commands = fixture.commands();
    let connection = commands[2][1].as_object().unwrap().values().next().unwrap();
    assert_eq!(connection["remote"]["id"], "ipv4:192.0.2.99");
    assert_eq!(
        connection["remote_addrs"],
        serde_json::json!(["192.0.2.10"])
    );
    assert_eq!(
        commands[4][1]["owners"],
        serde_json::json!(["ipv4:192.0.2.99"])
    );
}

#[test]
fn failure_and_mismatched_sa_clean_up_before_the_terminal_reply() {
    for failure in ["fail-initiate", "wrong-if-id"] {
        let mut fixture = Fixture::launch(false);
        fs::write(fixture.root.join(failure), []).unwrap();
        fixture.begin(fixture_start("fqdn:fixture.example"));
        assert_eq!(fixture.collect(), "error: Other");
        assert_eq!(
            fixture.replies,
            [Reply::Failed {
                code: ErrorCode::Backend
            }]
        );
        let commands = fixture.commands();
        let names: Vec<_> = commands
            .iter()
            .map(|entry| entry[0].as_str().unwrap())
            .collect();
        assert_eq!(names.contains(&"list-sas"), failure == "wrong-if-id");
        assert!(names.ends_with(&["terminate", "unload-conn", "unload-shared", "unload-shared"]));
        assert!(fixture.root.join("term").exists());
    }
}

fn names(commands: &[serde_json::Value]) -> Vec<&str> {
    commands
        .iter()
        .map(|entry| entry[0].as_str().unwrap())
        .collect()
}

#[test]
fn stop_during_negotiation_cancels_cleans_up_and_never_reports_established() {
    let mut fixture = Fixture::launch(false);
    fs::write(fixture.root.join("slow-list-sas"), []).unwrap();
    fixture.begin(fixture_start("fqdn:fixture.example"));
    fixture.wait_for("negotiating");
    let started = Instant::now();
    assert_eq!(fixture.finish(Some(b"T")), "Stopped");
    // The slow fake would have answered after 6 s: the stop did not wait.
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(fixture.replies, [Reply::Stopped {}]);
    let commands = fixture.commands();
    let names = names(&commands);
    assert!(names.contains(&"initiate") && names.contains(&"list-sas"));
    assert!(names.ends_with(&["terminate", "unload-conn", "unload-shared", "unload-shared"]));
    assert!(fixture.root.join("term").exists());
}

#[test]
fn eof_during_negotiation_cancels_cleans_up_and_sends_nothing() {
    let mut fixture = Fixture::launch(false);
    fs::write(fixture.root.join("slow-list-sas"), []).unwrap();
    fixture.begin(fixture_start("fqdn:fixture.example"));
    fixture.wait_for("negotiating");
    let started = Instant::now();
    assert_eq!(fixture.finish(None), "Eof");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(fixture.replies.is_empty());
    let commands = fixture.commands();
    assert!(names(&commands).ends_with(&[
        "terminate",
        "unload-conn",
        "unload-shared",
        "unload-shared"
    ]));
    assert!(fixture.root.join("term").exists());
}

#[test]
fn an_order_that_overtook_the_negotiation_is_never_followed_by_its_result() {
    let established = || {
        Ok(Reply::Established {
            if_id: 1,
            reqid: 1,
            virtual_ipv4: "198.51.100.17".parse().unwrap(),
            remote_ts: Vec::new(),
        })
    };
    let canceled = || Err(io::Error::from(io::ErrorKind::Interrupted));
    let stop = || Some(Ok(Order::Stop {}));
    let eof = || Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));

    // Control: with no order pending the result is published.
    assert!(matches!(
        settle(established(), None).unwrap(),
        Settled::Publish(Reply::Established { .. })
    ));
    // The negotiation finished first, but the order is already pending.
    assert!(matches!(
        settle(established(), stop()).unwrap(),
        Settled::Done(Exit::Stopped)
    ));
    assert!(matches!(
        settle(established(), eof()).unwrap(),
        Settled::Done(Exit::Eof)
    ));
    // The cancellation the order caused is not reported as a failure.
    assert!(matches!(
        settle(canceled(), stop()).unwrap(),
        Settled::Done(Exit::Stopped)
    ));
    assert!(matches!(
        settle(canceled(), eof()).unwrap(),
        Settled::Done(Exit::Eof)
    ));
    // A real failure still surfaces, and so does a bad order.
    let failed = settle(Err(io::Error::other("charon refused")), stop());
    assert!(matches!(failed, Err(error) if error.kind() == io::ErrorKind::Other));
    let second_start = Some(Ok(Order::Start(fixture_start("fqdn:fixture.example"))));
    assert!(matches!(
        settle(established(), second_start),
        Err(error) if error.kind() == io::ErrorKind::InvalidData
    ));
    let garbled = Some(Err(invalid("invalid IPsec instance order")));
    assert!(matches!(
        settle(canceled(), garbled),
        Err(error) if error.kind() == io::ErrorKind::InvalidData
    ));
}

#[test]
fn backend_death_after_established_is_reported_before_the_channel_ends() {
    let mut fixture = Fixture::launch(false);
    fixture.start();
    let fd = fixture.backend_pidfd.as_ref().unwrap();
    pidfd_signal(fd, libc::SIGKILL).unwrap();
    assert!(poll_until(fd, Instant::now() + TERM_GRACE).unwrap());
    assert_eq!(fixture.collect(), "error: BrokenPipe");
    assert_eq!(
        fixture.replies.last(),
        Some(&Reply::Failed {
            code: ErrorCode::Backend
        })
    );
    assert!(matches!(
        fixture.replies.as_slice(),
        [Reply::Established { .. }, Reply::Failed { .. }]
    ));
}

#[test]
fn largest_public_credentials_and_start_fit_the_instance_frame() {
    use crate::tunneld::handshake::MAX_FRAME;

    let secret = "p".repeat(4096);
    let psk = "k".repeat(4096);
    let frame = encode_credentials(&protocol::Credentials::ipsec(&secret, &psk).unwrap()).unwrap();
    assert_eq!(frame.len(), 4 + 4096 + 4096);
    assert!(frame.len() <= MAX_FRAME);
    let mut frame = frame;
    let credentials = decode_credentials(&mut frame).unwrap();
    assert_eq!(credentials.password.expose(), secret);
    assert_eq!(credentials.psk.expose(), psk);

    // The first byte past the limit is refused, and still wiped.
    let mut oversized = Zeroizing::new(vec![b'x'; MAX_FRAME + 1]);
    assert_eq!(
        decode_credentials(&mut oversized).unwrap_err(),
        ErrorCode::BadRequest
    );
    assert!(oversized.iter().all(|byte| *byte == 0));

    let start = largest_start();
    let bytes = serde_json::to_vec(&Order::Start(start)).unwrap();
    assert!(bytes.len() > 4096, "{}", bytes.len());
    assert!(bytes.len() <= MAX_FRAME, "{}", bytes.len());
    let Order::Start(start) = serde_json::from_slice(&bytes).unwrap() else {
        panic!("expected a start order");
    };
    Attempt::new(start).unwrap();
}

fn largest_start() -> Start {
    // The most the instance admits: 64 selectors each way, a long identity
    // and a long username.
    let mut start = fixture_start(&format!("fqdn:{}", "a".repeat(200)));
    start.username = "u".repeat(200);
    start.local_ts = (0..64)
        .map(|index| match index {
            0 => "198.51.100.0/24".to_owned(),
            _ => format!("100.{}.100.200/32", 64 + index),
        })
        .collect();
    start.remote_ts = (0..64)
        .map(|index| match index {
            0 => CidrV4::new("198.51.100.0".parse().unwrap(), 24).unwrap(),
            _ => CidrV4::new(format!("203.{}.200.100", 100 + index).parse().unwrap(), 32).unwrap(),
        })
        .collect();
    start
}

#[test]
fn peer_identity_rule_is_the_one_policy_applies() {
    for accepted in [
        "fqdn:vpn.example",
        "email:user@example.test",
        "ipv4:192.0.2.99",
        &format!("fqdn:{}", "a".repeat(253 - 5)),
    ] {
        assert!(Config::literal_peer_identity(accepted), "{accepted}");
        Attempt::new(fixture_start(accepted)).unwrap();
    }
    for refused in [
        "fqdn:vpn.example\n",
        "fqdn:vpn.exämple",
        "email:usér@example.test",
        "fqdn:*.example",
        "fqdn:#0102",
        "fqdn:^vpn$",
        "fqdn:",
        "ipv4:0.0.0.0",
        "ipv4:224.0.0.1",
        "ipv6:2001:db8::1",
        "vpn.example",
        &format!("fqdn:{}", "a".repeat(253 - 4)),
    ] {
        assert!(!Config::literal_peer_identity(refused), "{refused}");
        assert!(Attempt::new(fixture_start(refused)).is_err(), "{refused}");
    }
}

#[test]
fn foreign_backend_is_refused_before_load_and_receives_no_credentials() {
    let mut fixture = Fixture::launch(false);
    fs::write(fixture.root.join("foreign-backend"), []).unwrap();
    fixture.begin(fixture_start("fqdn:fixture.example"));
    assert_eq!(fixture.collect(), "error: Other");
    assert_eq!(
        fixture.replies,
        [Reply::Failed {
            code: ErrorCode::Backend
        }]
    );
    let commands = fixture.commands();
    assert_eq!(
        commands
            .iter()
            .map(|entry| entry[0].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["version", "stats"]
    );
}

#[test]
fn bad_start_and_bad_credential_frames_do_not_spawn_charon() {
    let mut bad_starts = Vec::new();
    for edit in [
        ("if_id", serde_json::json!(0)),
        ("reqid", serde_json::json!(0)),
        ("reqid", serde_json::json!(0x4000)),
        ("port", serde_json::json!(4501)),
        ("peer_identity", serde_json::json!("fqdn:*")),
        ("peer_identity", serde_json::json!("fqdn:#0102")),
        ("peer_identity", serde_json::json!("fqdn:^fixture$")),
        ("peer_identity", serde_json::json!("fixture.example")),
        ("remote_ipv4", serde_json::json!("fixture.example")),
        ("local_ts", serde_json::json!(["::/0"])),
        (
            "local_ts",
            serde_json::json!(["dynamic", "198.51.100.0/24"]),
        ),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut start =
            serde_json::to_value(Order::Start(fixture_start("fqdn:fixture.example"))).unwrap();
        start[edit.0] = edit.1;
        bad_starts.push(start);
    }
    for start in bad_starts {
        let mut fixture = Fixture::launch(false);
        fixture.send_bytes(&serde_json::to_vec(&start).unwrap());
        assert_eq!(fixture.finish(None), "error: InvalidData", "{start}");
        assert_eq!(
            fixture.replies,
            [Reply::Failed {
                code: ErrorCode::BadRequest
            }]
        );
        assert!(!fixture.root.join("ready").exists());
    }
    let mut fixture = Fixture::launch(false);
    fixture.send_bytes(
        &serde_json::to_vec(&Order::Start(fixture_start("fqdn:fixture.example"))).unwrap(),
    );
    fixture.send_bytes(br#"{"op":"stop"}"#);
    assert_eq!(fixture.finish(None), "error: InvalidData");
    assert_eq!(
        fixture.replies,
        [Reply::Failed {
            code: ErrorCode::BadRequest
        }]
    );
    assert!(!fixture.root.join("ready").exists());
}

#[test]
fn credential_datagram_is_wiped_after_success_and_rejection() {
    let mut valid = fixture_credentials();
    let credentials = decode_credentials(&mut valid).unwrap();
    assert_eq!(credentials.password.expose(), "synthetic-password");
    assert_eq!(credentials.psk.expose(), "synthetic-psk");
    assert!(valid.iter().all(|byte| *byte == 0));

    for mut invalid in [
        Zeroizing::new(vec![0, 8, b'x']),
        Zeroizing::new(vec![0, 1, b'x', 0, 1, b'y', b'z']),
        Zeroizing::new(vec![0, 1, 0xff, 0, 1, b'y']),
        Zeroizing::new(vec![0, 1, b'x', 0, 1, b'\n']),
    ] {
        assert_eq!(
            decode_credentials(&mut invalid).unwrap_err(),
            ErrorCode::BadRequest
        );
        assert!(invalid.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn eof_escalates_after_grace_and_reaps_ignoring_child() {
    let mut fixture = Fixture::launch(true);
    fixture.start();
    let start = Instant::now();
    assert_eq!(fixture.finish(None), "Eof");
    assert!(fixture.root.join("term").exists());
    assert!(start.elapsed() >= TERM_GRACE);
}

#[test]
fn channel_error_stops_and_cleans_up() {
    let mut fixture = Fixture::launch(false);
    fixture.start();
    assert_eq!(fixture.finish(Some(b"X")), "error: InvalidData");
    assert!(fixture.root.join("term").exists());
}

#[test]
fn stop_before_start_has_no_side_effects() {
    let mut fixture = Fixture::launch(false);
    assert_eq!(fixture.finish(Some(b"T")), "error: InvalidData");
    assert!(!fixture.root.join("ready").exists());
}

#[test]
fn parent_death_kills_the_child() {
    let mut fixture = Fixture::launch(false);
    fixture.start();
    fixture.supervisor.kill().unwrap();
    assert_eq!(
        fixture.supervisor.wait().unwrap().signal(),
        Some(libc::SIGKILL)
    );
    assert!(
        poll_until(
            fixture.backend_pidfd.as_ref().unwrap(),
            Instant::now() + TERM_GRACE
        )
        .unwrap(),
        "child remained alive after supervisor death"
    );
}

#[test]
#[ignore = "run under unshare -Ur to exercise the production root-only handshake"]
fn authenticated_supervisor_survives_idle_and_observes_charon_exit() {
    use crate::tunneld::handshake::{
        self, Backend, CONTROL_SOCKET_NAME, PHASE_TIMEOUT, UnitAttestor, UnitIdentity, Writer,
    };
    use std::ffi::OsStr;

    const GENERATION: &str = "0123456789abcdef0123456789abcdef";
    const INVOCATION: &str = "abcdef0123456789abcdef0123456789";

    struct Workspace(PathBuf);

    impl Drop for Workspace {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    struct Attestor;

    impl UnitAttestor for Attestor {
        fn attest(&self, _: BorrowedFd<'_>) -> io::Result<UnitIdentity> {
            Ok(UnitIdentity {
                name: format!("vpnt-tunneld-ipsec@{GENERATION}.service"),
                invocation: INVOCATION.to_owned(),
                main_pid: std::process::id() as libc::pid_t,
            })
        }
    }

    let root = std::env::temp_dir().join(format!("vpnt-i2c-auth-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let workspace = Workspace(root);
    let root = &workspace.0;
    let runtime = root.join("instance");
    let artifacts = root.join("handshake");
    for path in [&runtime, &artifacts] {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    let program = root.join("charon");
    write_script(&program, FAKE);
    let writer = Writer::publish(
        &artifacts,
        OsStr::new(CONTROL_SOCKET_NAME),
        GENERATION,
        Backend::Ipsec,
        0,
    )
    .unwrap();

    std::thread::scope(|scope| {
        let supervisor = scope.spawn(|| {
            let channel = handshake::connect_instance(
                &artifacts.join(CONTROL_SOCKET_NAME),
                &artifacts.join(GENERATION),
                GENERATION,
                Backend::Ipsec,
                INVOCATION,
                0,
            )
            .unwrap();
            run_authenticated(
                channel,
                &Params {
                    directory: runtime.clone(),
                },
                &program,
                (0, 0),
            )
        });
        let mut client = writer.authenticate(&Attestor).unwrap();
        // The largest Start the instance admits and the largest public
        // credentials both cross the real authenticated channel.
        client
            .send(&serde_json::to_vec(&Order::Start(largest_start())).unwrap())
            .unwrap();
        client
            .send(
                &encode_credentials(
                    &protocol::Credentials::ipsec(&"p".repeat(4096), &"k".repeat(4096)).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            serde_json::from_slice::<Reply>(&client.receive().unwrap()).unwrap(),
            Reply::Established { .. }
        ));
        let deadline = Instant::now() + PHASE_TIMEOUT;
        let ready = loop {
            match fs::read(root.join("ready")) {
                Ok(bytes) => break serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    assert!(
                        !supervisor.is_finished(),
                        "supervisor exited before readiness"
                    );
                    assert!(Instant::now() < deadline, "fake charon never became ready");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("fake charon readiness: {error}"),
            }
        };
        let child = pidfd_open(ready["pid"].as_u64().unwrap() as u32).unwrap();
        std::thread::sleep(PHASE_TIMEOUT + Duration::from_millis(250));
        assert!(
            !supervisor.is_finished(),
            "supervisor exited during an idle authenticated session"
        );
        assert!(!poll_until(&child, Instant::now()).unwrap());
        let exit = Instant::now();
        pidfd_signal(&child, libc::SIGKILL).unwrap();
        // The authenticated peer is told why the instance ends.
        assert_eq!(
            serde_json::from_slice::<Reply>(&client.receive().unwrap()).unwrap(),
            Reply::Failed {
                code: ErrorCode::Backend
            }
        );
        assert_eq!(
            supervisor.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(exit.elapsed() < TERM_GRACE, "child exit was not prompt");
        assert!(poll_until(&child, Instant::now()).unwrap());
        assert!(fs::read_dir(&runtime).unwrap().next().is_none());
    });
}
