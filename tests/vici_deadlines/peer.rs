#[cfg(target_os = "macos")]
use std::ffi::CStr;
use std::{
    io::{BufRead, BufReader, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    process::{Child, ChildStdout, Command, Stdio},
    sync::{
        Arc, OnceLock,
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use vpnt::helper::vici::{CommandResult, Error};

const BLOCK_BARRIER: Duration = Duration::from_secs(15);
/// Synchronization guard for an operation result; longer than the 15 s test
/// deadlines so a late result is judged by the readiness assertion.
const RESULT_GUARD: Duration = Duration::from_secs(20);

struct ThreadState {
    waiting: bool,
    label: String,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // These Mach calls are absent from libc 0.2.191; no dependency may be added.
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
    fn thread_suspend(thread: libc::mach_port_t) -> libc::kern_return_t;
    fn thread_resume(thread: libc::mach_port_t) -> libc::kern_return_t;
    fn thread_get_state(
        thread: libc::mach_port_t,
        flavor: libc::c_int,
        state: *mut libc::c_int,
        count: *mut libc::mach_msg_type_number_t,
    ) -> libc::kern_return_t;
}

/// Owns the Mach send right from `mach_thread_self`, including when the
/// identity is never consumed or when sending it fails.
#[cfg(target_os = "macos")]
struct ThreadIdentity {
    port: libc::mach_port_t,
}

#[cfg(target_os = "macos")]
impl ThreadIdentity {
    #[allow(deprecated)] // mach2 is not a project dependency; this is test-only.
    fn current() -> Self {
        // SAFETY: mach_thread_self has no memory preconditions and returns an
        // owned send right; Drop releases it on every path.
        Self {
            port: unsafe { libc::mach_thread_self() },
        }
    }
    fn port(&self) -> libc::mach_port_t {
        self.port
    }
}

#[cfg(target_os = "macos")]
impl Drop for ThreadIdentity {
    #[allow(deprecated)] // mach2 is not a project dependency; this is test-only.
    fn drop(&mut self) {
        // SAFETY: `port` is the owned send right acquired in `current`, still
        // valid here, and this Drop runs exactly once for that right.
        unsafe {
            mach_port_deallocate(libc::mach_task_self(), self.port);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ThreadIdentity(libc::pid_t);

#[cfg(target_os = "linux")]
impl ThreadIdentity {
    fn current() -> Self {
        // SAFETY: gettid has no memory preconditions.
        Self(unsafe { libc::gettid() })
    }
    fn tid(&self) -> libc::pid_t {
        self.0
    }
}

#[cfg(target_os = "macos")]
struct ResumeOnDrop(libc::mach_port_t);

#[cfg(target_os = "macos")]
impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        // SAFETY: the port is the live thread suspended just before this guard
        // was built; resuming is required on success, error and panic alike.
        unsafe {
            thread_resume(self.0);
        }
    }
}

#[cfg(target_os = "macos")]
#[repr(C, align(16))]
struct MachThreadState([u8; 1024]);

// XNU thread state layouts: PC follows x[29], fp, lr, sp on arm64, and the
// 16 integer registers on x86_64. The buffer is larger than either state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PC_OFFSET: usize = 29 * 8 + 3 * 8;
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const PC_OFFSET: usize = 16 * 8;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const THREAD_STATE_FLAVOR: libc::c_int = 6; // ARM_THREAD_STATE64
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const THREAD_STATE_FLAVOR: libc::c_int = 4; // x86_THREAD_STATE64 (5 is x86_FLOAT_STATE64)

#[cfg(target_os = "macos")]
fn program_counter(identity: &ThreadIdentity) -> Result<usize, String> {
    // SAFETY: the port is a live send right for the operation thread, never
    // this thread; suspending it cannot suspend the observer.
    let result = unsafe { thread_suspend(identity.port()) };
    if result != libc::KERN_SUCCESS {
        return Err(format!("thread_suspend={result}"));
    }
    // Nothing in this block may allocate or lock: the suspended thread could
    // hold the allocator lock. Errors are formatted after the resume.
    let read = {
        let _resume = ResumeOnDrop(identity.port());
        let mut state = MachThreadState([0; 1024]);
        let mut count = (std::mem::size_of_val(&state) / std::mem::size_of::<libc::c_int>())
            as libc::mach_msg_type_number_t;
        // SAFETY: `state` is writable and aligned, `count` matches its byte size,
        // and the port names the suspended live thread.
        let result = unsafe {
            thread_get_state(
                identity.port(),
                THREAD_STATE_FLAVOR,
                state.0.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if result == libc::KERN_SUCCESS {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&state.0[PC_OFFSET..PC_OFFSET + 8]);
            Ok(usize::from_ne_bytes(bytes))
        } else {
            Err(result)
        }
    };
    read.map_err(|result| format!("thread_get_state={result}"))
}

#[cfg(target_os = "macos")]
fn symbol_at(pc: usize) -> Result<(bool, String), String> {
    static POLL_START: OnceLock<Result<usize, String>> = OnceLock::new();
    let start = POLL_START
        .get_or_init(|| {
            let symbol = b"poll\0";
            // SAFETY: `symbol` is NUL-terminated and RTLD_DEFAULT is the
            // process-wide lookup scope used by dlsym.
            let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr().cast()) };
            if address.is_null() {
                return Err("dlsym(poll) returned null".to_owned());
            }
            // SAFETY: Dl_info is a plain output struct whose zero bits are valid.
            let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
            // SAFETY: `address` came from dlsym and `info` is a valid out pointer.
            if unsafe { libc::dladdr(address, &mut info) } == 0 {
                return Err("dladdr(poll) failed".to_owned());
            }
            Ok(info.dli_saddr as usize)
        })
        .clone()?;
    // SAFETY: Dl_info is a plain output struct whose zero bits are valid.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: `pc` is a code address read from the thread state and `info` is valid.
    if unsafe { libc::dladdr(pc as *const libc::c_void, &mut info) } == 0 {
        return Err(format!("dladdr(pc=0x{pc:x}) failed"));
    }
    let name = if info.dli_sname.is_null() {
        "?".to_owned()
    } else {
        // SAFETY: dladdr filled dli_sname with a NUL-terminated C string.
        unsafe { CStr::from_ptr(info.dli_sname) }
            .to_string_lossy()
            .into_owned()
    };
    let start_of_symbol = info.dli_saddr as usize;
    Ok((
        start_of_symbol == start,
        format!("pc=0x{pc:x} symbol={name} saddr=0x{start_of_symbol:x} poll=0x{start:x}"),
    ))
}

#[cfg(target_os = "macos")]
fn blocked_state(identity: &ThreadIdentity) -> Result<ThreadState, String> {
    let (waiting, label) = symbol_at(program_counter(identity)?)?;
    Ok(ThreadState { waiting, label })
}

#[cfg(target_os = "linux")]
fn blocked_state(identity: &ThreadIdentity) -> Result<ThreadState, String> {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{}/syscall", identity.tid()))
        .map_err(|error| format!("syscall={error}"))?;
    let first = stat
        .split_whitespace()
        .next()
        .ok_or_else(|| "syscall file is empty".to_owned())?;
    let waiting = if first == "running" {
        false
    } else {
        let number: i64 = first
            .parse()
            .map_err(|error| format!("syscall number {first}: {error}"))?;
        #[cfg(target_arch = "x86_64")]
        {
            number == libc::SYS_poll as i64 || number == libc::SYS_ppoll as i64
        }
        #[cfg(target_arch = "aarch64")]
        {
            number == libc::SYS_ppoll as i64
        }
    };
    Ok(ThreadState {
        waiting,
        label: format!("syscall={first}"),
    })
}

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

    pub fn try_finish(&mut self) -> Result<(), String> {
        self.control
            .write_all(b"R")
            .map_err(|error| format!("peer signal: {error}"))?;
        if let Some(mut child) = self.child.take() {
            let status = child
                .wait()
                .map_err(|error| format!("peer wait: {error}"))?;
            if !status.success() {
                return Err(format!("independent peer failed: {status}"));
            }
        }
        Ok(())
    }

    pub fn finish(&mut self) {
        if let Err(error) = self.try_finish() {
            panic!("{error}");
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
    identity: Receiver<ThreadIdentity>,
    finished: Arc<OnceLock<Instant>>,
}

impl Operation {
    pub fn new(work: impl FnOnce() -> Result<CommandResult, Error> + Send + 'static) -> Self {
        let (send, result) = mpsc::channel();
        let (identity_send, identity) = mpsc::channel();
        let finished = Arc::new(OnceLock::new());
        let worker_finished = Arc::clone(&finished);
        let worker = Some(thread::spawn(move || {
            // The owner is dropped by `send` on failure, so the Mach right is
            // released even when nobody receives the identity.
            let _ = identity_send.send(ThreadIdentity::current());
            let work_result = work();
            // Source timestamp: recorded by this worker as it returns, before
            // publishing the result to the receiver.
            let _ = worker_finished.set(Instant::now());
            let _ = send.send(work_result);
        }));
        Self {
            worker,
            result,
            identity,
            finished,
        }
    }

    pub fn finished_at(&self) -> Option<Instant> {
        self.finished.get().copied()
    }

    /// Synchronization guard only: publish cancellation after the operation's
    /// own thread has entered the nonblocking socket's poll.
    pub fn wait_until_blocked(&self, mode: &str) -> Result<(), String> {
        let identity = self
            .identity
            .recv_timeout(BLOCK_BARRIER)
            .map_err(|error| format!("{mode}: no operation thread identity: {error}"))?;
        let limit = Instant::now() + BLOCK_BARRIER;
        let mut last: String;
        loop {
            match blocked_state(&identity) {
                Ok(state) => {
                    if state.waiting {
                        return Ok(());
                    }
                    last = state.label;
                }
                Err(error) => last = error,
            }
            if Instant::now() >= limit {
                return Err(format!(
                    "{mode}: client thread never blocked within 15 s (last {last})"
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Synchronization guard only: readiness limits are asserted from
    /// `finished_at`, never from how long this guard waited.
    pub fn receive(&self, label: &str) -> Result<Result<CommandResult, Error>, String> {
        self.result
            .recv_timeout(RESULT_GUARD)
            .map_err(|error| format!("{label}: operation did not return within 20 s ({error})"))
    }

    pub fn try_join(&mut self) -> Result<(), String> {
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| "operation worker panicked".to_owned())
        } else {
            Ok(())
        }
    }

    pub fn join(&mut self) {
        if let Err(error) = self.try_join() {
            panic!("{error}");
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let _ = self.try_join();
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
