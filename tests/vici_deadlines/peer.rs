use std::{
    io::{BufRead, BufReader, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    process::{Child, ChildStdout, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::Duration,
};
use vpnt::helper::vici::{CommandResult, Error};

pub struct Peer {
    child: Option<Child>,
    control: UnixStream,
    output: BufReader<ChildStdout>,
}

impl Peer {
    pub fn new(mode: &str) -> (Self, UnixStream) {
        let (client, wire) = UnixStream::pair().unwrap();
        let (control, barrier) = UnixStream::pair().unwrap();
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-u",
                "-c",
                include_str!("../fixtures/vici/deadline.py"),
                mode,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(wire)))
            .stdout(Stdio::piped())
            .stderr(Stdio::from(OwnedFd::from(barrier)))
            .spawn()
            .unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut peer = Self {
            child: Some(child),
            control,
            output,
        };
        assert_eq!(peer.line(), "ready");
        (peer, client)
    }

    pub fn line(&mut self) -> String {
        let mut value = String::new();
        self.output.read_line(&mut value).unwrap();
        value.trim().to_owned()
    }

    pub fn alive(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }

    pub fn finish(&mut self) {
        let _ = self.control.write_all(b"R");
        if let Some(mut child) = self.child.take() {
            assert!(child.wait().unwrap().success(), "independent peer failed");
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.control.write_all(b"R");
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

pub struct Operation {
    worker: Option<JoinHandle<()>>,
    result: Receiver<Result<CommandResult, Error>>,
}

impl Operation {
    pub fn new(work: impl FnOnce() -> Result<CommandResult, Error> + Send + 'static) -> Self {
        let (send, result) = mpsc::channel();
        let worker = Some(thread::spawn(move || {
            let _ = send.send(work());
        }));
        Self { worker, result }
    }

    pub fn receive(&self) -> Result<Result<CommandResult, Error>, RecvTimeoutError> {
        self.result.recv_timeout(Duration::from_millis(800))
    }

    pub fn join(&mut self) {
        self.worker.take().unwrap().join().unwrap();
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub struct SocketDirectory(pub PathBuf);
impl SocketDirectory {
    pub fn new() -> Self {
        let path = PathBuf::from("/tmp").join(format!("vpnt-vici-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
