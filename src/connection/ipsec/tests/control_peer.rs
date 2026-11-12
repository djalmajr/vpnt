use super::*;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
pub(super) struct Process {
    child: Child,
    signaled: bool,
}
impl Process {
    fn signal(&mut self) {
        if !self.signaled {
            self.signaled = true;
            let _ = self.child.stdin.as_mut().unwrap().write_all(b"R");
        }
    }
    pub fn exited(&mut self) -> bool {
        self.child.try_wait().unwrap().is_some_and(|status| {
            assert!(status.success());
            true
        })
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.signal();
        let _ = self.child.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) struct Harness {
    _directory: Directory,
    pub process: Arc<Mutex<Process>>,
    pub retire: Arc<AtomicBool>,
    audit: PathBuf,
}
impl Harness {
    pub fn audit(&self) -> Vec<String> {
        fs::read_to_string(&self.audit)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
    pub fn wait_for(&self, command: &str) {
        let until = Instant::now() + Duration::from_secs(2);
        while !self.audit().iter().any(|s| s == command) {
            assert!(
                Instant::now() < until,
                "command did not reach independent peer"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn stop(&self) {
        self.retire.store(true, Ordering::Release);
        self.process.lock().unwrap().signal();
        self.wait_exit();
    }
    pub fn wait_exit(&self) {
        let until = Instant::now() + Duration::from_secs(2);
        while !self.process.lock().unwrap().exited() {
            assert!(Instant::now() < until, "owned peer did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
pub(super) struct TestPeer {
    process: Arc<Mutex<Process>>,
    retire: Arc<AtomicBool>,
    path: PathBuf,
    registry: Arc<Mutex<Registry<Observation>>>,
    observation: Observation,
    collide: bool,
    opens: usize,
}
impl TestPeer {
    pub fn new(
        mode: &str,
        registry: Arc<Mutex<Registry<Observation>>>,
        observation: Observation,
        collide: bool,
    ) -> (Self, Harness) {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "vpnt-ipsec-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let directory = Directory(path.clone());
        let audit = path.join("audit");
        let socket = path.join("vici.sock");
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-u",
                "-c",
                include_str!("../../../../tests/fixtures/vici/control.py"),
            ])
            .arg(&socket)
            .arg(&audit)
            .arg(mode)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let process = Arc::new(Mutex::new(Process {
            child,
            signaled: false,
        }));
        let mut ready = String::new();
        output.read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(), "ready");
        let retire = Arc::new(AtomicBool::new(false));
        let peer = Self {
            process: process.clone(),
            retire: retire.clone(),
            path: socket,
            registry,
            observation,
            collide,
            opens: 0,
        };
        (
            peer,
            Harness {
                _directory: directory,
                process,
                retire,
                audit,
            },
        )
    }
}
impl Peer for TestPeer {
    fn open(
        &mut self,
        current: &Owner,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<crate::helper::vici::Client, Error> {
        assert!(
            self.registry.try_lock().is_ok(),
            "registry held across VICI IO"
        );
        assert_eq!(current, &owner("Case", 7));
        self.opens += 1;
        if self.collide && self.opens == 4 {
            self.observation.0.lock().unwrap().occupied.insert(16383);
        }
        // SAFETY: geteuid has no memory preconditions.
        crate::helper::vici::Client::connect_until(
            &self.path,
            unsafe { libc::geteuid() },
            expires,
            cancel,
        )
        .map_err(|e| match e {
            crate::helper::vici::Error::Canceled => Error::Canceled,
            crate::helper::vici::Error::Timeout => Error::Timeout,
            _ => Error::Unavailable,
        })
    }
    fn retire(&mut self, current: &Owner) -> Result<bool, Error> {
        assert_eq!(current, &owner("Case", 7));
        if !self.retire.load(Ordering::Acquire) {
            return Ok(false);
        }
        let mut process = self.process.lock().unwrap();
        process.signal();
        Ok(process.exited())
    }
}
