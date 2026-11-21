use super::*;
use crate::test_support::write_script;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicUsize, Ordering};

const REEXEC: &str = "tunneld::ipsec_instance::tests::supervisor_process";
const FIXTURE: &str = "VPNT_IPSEC_INSTANCE_FIXTURE";
const SENTINEL: &str = "vpnt synthetic supervisor memory marker";

const FAKE: &str = r#"#!/usr/bin/python3
import json, os, pathlib, re, signal, socket
import sys

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
vici.bind(path)
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
while True:
    signal.pause()
"#;

struct Fixture {
    root: PathBuf,
    writer: UnixStream,
    supervisor: Child,
    backend_pidfd: Option<OwnedFd>,
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
            .stdin(Stdio::from(reader))
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
        }
    }

    fn start(&mut self) -> serde_json::Value {
        self.writer.write_all(b"S").unwrap();
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

    fn finish(&mut self, action: Option<&[u8]>) -> String {
        match action {
            Some(bytes) => self.writer.write_all(bytes).unwrap(),
            None => self.writer.shutdown(std::net::Shutdown::Write).unwrap(),
        }
        let mut answer = String::new();
        self.writer.read_to_string(&mut answer).unwrap();
        assert!(self.supervisor.wait().unwrap().success());
        assert!(!self.root.join("instance").exists());
        if let Some(fd) = &self.backend_pidfd {
            assert!(poll_until(fd, Instant::now()).unwrap());
        }
        answer
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
    let mut channel = UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let result = run_with(
        || {
            let mut byte = [0];
            channel.read_exact(&mut byte)?;
            match byte {
                [b'S'] => decode_order(br#""start""#),
                [b'T'] => decode_order(br#""stop""#),
                _ => decode_order(br#""invalid""#),
            }
        },
        &Params {
            directory: root.join("instance"),
        },
        &root.join("charon"),
        unsafe { (libc::geteuid(), libc::getegid()) },
    );
    std::hint::black_box(SENTINEL);
    let answer = match result {
        Ok(exit) => format!("{exit:?}"),
        Err(error) => format!("error: {:?}", error.kind()),
    };
    channel.write_all(answer.as_bytes()).unwrap();
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
    assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
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
