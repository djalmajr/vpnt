//! Unprivileged owner of one helper invocation. Closing the channel requests
//! cleanup; this layer never signals or kills the helper while it cleans up.
mod worker;
use super::protocol::{Message, Request};
#[cfg(target_os = "macos")]
use super::{
    paths,
    runtime::{Runtime, RuntimeError},
};
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Missing,
    Untrusted,
    Unavailable,
    Incompatible,
    Busy,
    PreviousSessionFinishing,
}
struct State {
    fault: Mutex<Option<Error>>,
    finished: AtomicBool,
}
pub struct Client {
    requests: Option<SyncSender<Request>>,
    output: Receiver<Message>,
    stop: Arc<AtomicBool>,
    state: Arc<State>,
    failed: bool,
    #[cfg(all(test, target_os = "macos"))]
    fixture_build: Option<String>,
}
impl Client {
    #[cfg(target_os = "macos")]
    pub fn runtime() -> Result<Self, Error> {
        Runtime::verify_helper().map_err(|e| {
            if e == RuntimeError::Missing {
                Error::Missing
            } else {
                Error::Untrusted
            }
        })?;
        let mut command = Command::new("/usr/bin/sudo");
        command.args(["-n", "--", paths::HELPER, "runtime"]);
        Self::spawn(command)
    }
    #[cfg(target_os = "linux")]
    pub fn runtime() -> Result<Self, Error> {
        let path = linux_executable().map_err(|_| Error::Untrusted)?;
        Self::linux_for_executable(&path)
    }
    /// Starts a Linux runtime using the supplied absolute executable.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn linux_for_executable(path: &std::path::Path) -> Result<Self, Error> {
        Self::spawn(linux_command(path, "runtime")?)
    }
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn fixture(command: Command) -> Result<Self, Error> {
        let mut client = Self::spawn(command)?;
        client.fixture_build = Some("a".repeat(64));
        Ok(client)
    }
    #[cfg(test)]
    pub(crate) fn fixture_channels(
        requests: SyncSender<Request>,
        output: Receiver<Message>,
    ) -> Self {
        Self {
            requests: Some(requests),
            output,
            stop: Arc::new(AtomicBool::new(false)),
            state: Arc::new(State {
                fault: Mutex::new(None),
                finished: AtomicBool::new(false),
            }),
            failed: false,
            #[cfg(target_os = "macos")]
            fixture_build: None,
        }
    }
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn fixture_build(&self) -> Option<&str> {
        self.fixture_build.as_deref()
    }
    fn spawn(command: Command) -> Result<Self, Error> {
        if !std::path::Path::new(command.get_program()).is_absolute() {
            return Err(Error::Untrusted);
        }
        let (requests, input) = mpsc::sync_channel(32);
        let (output, receive) = mpsc::sync_channel(64);
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(State {
            fault: Mutex::new(None),
            finished: AtomicBool::new(false),
        });
        let worker_stop = stop.clone();
        let worker_state = state.clone();
        std::thread::Builder::new()
            .name("vpnt-helper-client".into())
            .spawn(move || {
                worker::run(command, input, output, worker_stop, worker_state);
            })
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            requests: Some(requests),
            output: receive,
            stop,
            state,
            failed: false,
            #[cfg(all(test, target_os = "macos"))]
            fixture_build: None,
        })
    }
    pub fn send(&self, request: Request) -> Result<(), Error> {
        if self.failed || self.stop.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        self.requests
            .as_ref()
            .ok_or(Error::Unavailable)?
            .try_send(request)
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => Error::Busy,
                _ => Error::Unavailable,
            })
    }
    pub fn poll(&mut self) -> Result<Vec<Message>, Error> {
        if self.failed {
            return Ok(vec![]);
        }
        if let Some(error) = self
            .state
            .fault
            .lock()
            .map_err(|_| Error::Unavailable)?
            .take()
        {
            self.failed = true;
            while self.output.try_recv().is_ok() {}
            return Err(error);
        }
        Ok(self.output.try_iter().take(64).collect())
    }
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn fixture_finished(&self) -> impl Fn() -> bool + Send + Clone + 'static {
        let state = self.state.clone();
        move || state.finished.load(Ordering::Acquire)
    }
    pub fn finished(&self) -> bool {
        self.state.finished.load(Ordering::Acquire)
    }
    pub fn close(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.requests = None;
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(target_os = "linux")]
pub(super) fn linux_executable() -> std::io::Result<std::path::PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("VPNT_TEST_EXECUTABLE") {
        return Ok(path.into());
    }
    std::env::current_exe()
}

#[cfg(target_os = "linux")]
pub(super) fn linux_command(path: &std::path::Path, mode: &str) -> Result<Command, Error> {
    if !path.is_absolute() {
        return Err(Error::Untrusted);
    }
    let path = std::fs::canonicalize(path).map_err(|_| Error::Untrusted)?;
    if !path.is_absolute() || !path.is_file() {
        return Err(Error::Untrusted);
    }
    let mut command = Command::new(path);
    command.args(["helper", mode]);
    Ok(command)
}

/// Prepares a Linux runtime or admin child: passes the user's session
/// variables, and lets only stdin (the channel), stdout and stderr cross exec.
#[cfg(target_os = "linux")]
pub(super) fn linux_inherit_session(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Descriptors the app inherited without CLOEXEC would otherwise stay open in
    // the child for its whole session. Marking them close-on-exec (instead of
    // closing) keeps std's own exec-error pipe working. Kernels before 5.11
    // lack CLOSE_RANGE_CLOEXEC: there the spawn fails rather than leak.
    // SAFETY: the closure runs between fork and exec and only makes one raw
    // syscall, which is async-signal-safe and allocates nothing.
    unsafe {
        command.pre_exec(|| {
            let first: libc::c_uint = 3;
            if libc::syscall(
                libc::SYS_close_range,
                first,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) == 0
            {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    for key in [
        "HOME",
        "USER",
        "LOGNAME",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn linux_build_identity() -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    const LIMIT: u64 = 256 * 1024 * 1024;
    #[cfg(debug_assertions)]
    let path = if std::env::var_os("VPNT_TEST_EXECUTABLE").is_some() {
        let selected = linux_executable().ok()?;
        if !selected.is_absolute() {
            return None;
        }
        std::fs::canonicalize(selected).ok()?
    } else {
        std::path::PathBuf::from("/proc/self/exe")
    };
    #[cfg(not(debug_assertions))]
    let path = std::path::PathBuf::from("/proc/self/exe");
    let mut input = std::fs::File::open(path).ok()?.take(LIMIT + 1);
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0u8; 16384];
    loop {
        let n = input.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > LIMIT {
            return None;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests;
#[cfg(all(test, target_os = "macos"))]
pub(crate) mod tests;
