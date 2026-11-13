//! Ownership and cleanup of direct child processes. This proves process exit,
//! not VPN route/SA cleanup; each driver must verify its own tunnel resources.
use super::fd_guard;
#[cfg(target_os = "macos")]
use std::sync::Arc;
use std::{
    io,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct StopOutcome {
    pub status: ExitStatus,
    pub escalated: bool,
}

pub struct ManagedChild {
    child: Child,
    pid: u32,
    #[cfg(target_os = "macos")]
    authority: Authority,
    status: Option<ExitStatus>,
}

/// Per-spawn authority: two handles match only when they share this allocation.
/// A recycled PID keeps a different allocation, so identity survives `reap`.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(crate) struct Authority(Arc<()>);

#[cfg(target_os = "macos")]
impl Authority {
    pub(crate) fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

pub(crate) enum Environment {
    System,
    PrivateVpn,
    Charon(PathBuf),
}

impl ManagedChild {
    /// The driver must admit a fixed trusted executable before calling this.
    /// This layer additionally blocks relative paths and inherited environment.
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        Self::spawn_with_environment(command, Environment::System)
    }

    pub(crate) fn spawn_with_environment(
        command: &mut Command,
        environment: Environment,
    ) -> io::Result<Self> {
        Self::spawn_configured(command, environment, false)
    }
    #[cfg(test)]
    pub(crate) fn spawn_charon(command: &mut Command, configuration: &Path) -> io::Result<Self> {
        Self::spawn_configured(
            command,
            Environment::Charon(configuration.to_owned()),
            false,
        )
    }

    /// PPP already owns a PTY supplied by its admitted parent. Preserve only
    /// stdin/stdout/stderr; callers keep their private capabilities CLOEXEC.
    pub(crate) fn spawn_terminal(command: &mut Command) -> io::Result<Self> {
        Self::spawn_configured(command, Environment::System, true)
    }

    fn spawn_configured(
        command: &mut Command,
        environment: Environment,
        terminal: bool,
    ) -> io::Result<Self> {
        if !Path::new(command.get_program()).is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute executable required",
            ));
        }
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir("/");
        if matches!(
            environment,
            Environment::PrivateVpn | Environment::Charon(_)
        ) {
            let runtime = super::paths::runtime_directory();
            command
                .env("OPENSSL_CONF", "/dev/null")
                .env("OPENSSL_MODULES", runtime.join("lib/ossl-modules"))
                .env("OPENSSL_ENGINES", runtime.join("lib/engines"))
                .env("SSL_CERT_FILE", runtime.join("certs/ca-bundle.pem"));
        }
        if let Environment::Charon(configuration) = environment {
            // The inherited read end is the private parent-liveness capability:
            // charon's opt-in watcher exits when this process drops its only
            // write end. Nothing is written; stdout/stderr stay discarded.
            command
                .env("STRONGSWAN_CONF", configuration)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        } else if terminal {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        } else {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        // Descriptor reception installs fds before it can mark them CLOEXEC;
        // every spawn shares this one guard so no child can inherit one.
        let child = {
            let _guard = fd_guard::spawn();
            command.spawn()?
        };
        Ok(Self {
            pid: child.id(),
            child,
            #[cfg(target_os = "macos")]
            authority: Authority(Arc::new(())),
            status: None,
        })
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Opaque spawn authority for the charon capability binding. The handle
    /// keeps the allocation alive while any receiver still refers to it.
    #[cfg(target_os = "macos")]
    pub(crate) fn authority(&self) -> Authority {
        self.authority.clone()
    }

    /// Test seam for PID reuse: only the recorded PID changes, the authority
    /// allocation stays the one this handle was spawned with.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn retarget_pid_for_test(&mut self, pid: u32) {
        self.pid = pid;
    }
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    pub fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }

    pub fn stop(&mut self, grace: Duration) -> io::Result<StopOutcome> {
        if let Some(status) = self.poll()? {
            return Ok(StopOutcome {
                status,
                escalated: false,
            });
        }
        let deadline = Instant::now()
            .checked_add(grace)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid stop deadline"))?;
        // SAFETY: this Child has not been reaped. Even if it exits between poll
        // and kill, its PID cannot be reused before our wait. Never signal after
        // observing/reaping an exit, and never signal a searched PID or group.
        let result = unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        while Instant::now() < deadline {
            if let Some(status) = self.poll()? {
                return Ok(StopOutcome {
                    status,
                    escalated: false,
                });
            }
            thread::sleep(
                Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        if let Some(status) = self.poll()? {
            return Ok(StopOutcome {
                status,
                escalated: false,
            });
        }
        self.child.kill()?;
        let status = self.child.wait()?;
        self.status = Some(status);
        Ok(StopOutcome {
            status,
            escalated: true,
        })
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.status.is_none() {
            // No poll/reap occurred before this signal. The same ownership
            // argument applies, including when spawn succeeded but setup failed.
            let _ = self.child.kill();
            if let Ok(status) = self.child.wait() {
                self.status = Some(status);
            }
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests;
