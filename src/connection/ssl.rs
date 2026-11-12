//! Process layer of the Fortinet driver. An interface named by client output
//! is only a candidate; the controller must prove ownership, install its leased
//! routes and run a tunnel-bound probe before reporting Connected.
use super::ssl_output::Output;
use crate::{
    helper::{
        paths,
        pinentry_channel::PinentryChild,
        process::StopOutcome,
        runtime::{Program, Runtime, RuntimeError},
    },
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use std::{io, net::IpAddr, process::Command, time::Duration};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceName(String);
impl InterfaceName {
    pub(super) fn parse(name: &str) -> Option<Self> {
        let unit = name.strip_prefix("ppp")?;
        if unit.is_empty() || name.len() > 15 || !unit.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(Self(name.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SslFailure {
    CredentialsRejected,
    GatewayTimeout,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartError {
    InvalidProfile,
    InvalidSecret,
    PermissionDenied,
    MissingProgram,
    UntrustedRuntime,
    Unavailable,
}

#[derive(Debug)]
pub struct Update {
    pub candidate: Option<InterfaceName>,
    pub failure: Option<SslFailure>,
    pub exited: bool,
}

pub struct SslDriver {
    child: PinentryChild,
    output: Output,
}

impl SslDriver {
    #[cfg(target_os = "macos")]
    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }
    /// Called by the privileged helper with its own stored profile. No paths or
    /// executable names are accepted from the IPC request.
    pub fn start(profile: &Profile, credentials: Credentials) -> Result<Self, StartError> {
        // SAFETY: UID queries have no memory preconditions.
        if !cfg!(target_os = "macos") || unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(StartError::PermissionDenied);
        }
        let runtime = Runtime::installed().map_err(map_runtime)?;
        Runtime::verify_pinentry().map_err(map_runtime)?;
        Self::start_using(&runtime, profile, credentials)
    }
    fn start_using(
        runtime: &Runtime,
        profile: &Profile,
        credentials: Credentials,
    ) -> Result<Self, StartError> {
        let command = command(runtime, profile)?;
        credentials
            .validate(VpnKind::Ssl)
            .map_err(|_| StartError::InvalidSecret)?;
        runtime.verify().map_err(map_runtime)?;
        let child = PinentryChild::spawn_private_runtime(command, credentials.password)
            .map_err(|_| StartError::Unavailable)?;
        let mut driver = Self {
            child,
            output: Output::default(),
        };
        let stdout = driver.child.take_stdout().ok_or(StartError::Unavailable)?;
        driver
            .output
            .attach(stdout)
            .map_err(|_| StartError::Unavailable)?;
        let stderr = driver.child.take_stderr().ok_or(StartError::Unavailable)?;
        driver
            .output
            .attach(stderr)
            .map_err(|_| StartError::Unavailable)?;
        Ok(driver)
    }
    pub fn poll(&mut self) -> io::Result<Update> {
        let exited = self.child.poll()?.is_some();
        if exited {
            self.output.finish();
        }
        let observed = self.output.snapshot();
        Ok(Update {
            candidate: observed.candidate,
            failure: observed.failure,
            exited,
        })
    }
    /// This confirms exit of the direct client only. The controller must also
    /// verify PPP and its leased routes are gone, including after escalation.
    pub fn stop(&mut self) -> io::Result<StopOutcome> {
        let result = self.child.stop(Duration::from_secs(3));
        self.output.finish();
        result
    }
}
impl Drop for SslDriver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn command(runtime: &Runtime, profile: &Profile) -> Result<Command, StartError> {
    profile.validate().map_err(|_| StartError::InvalidProfile)?;
    if profile.kind != VpnKind::Ssl
        || profile.username.is_empty()
        || matches!(profile.gateway.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
    {
        return Err(StartError::InvalidProfile);
    }
    let mut command = Command::new(runtime.program(Program::Fortinet));
    command
        .args([
            "--config=/dev/null",
            "--no-routes",
            "--no-dns",
            "--pppd-no-peerdns",
            "--pppd-accept-remote=0",
            "--persistent=0",
        ])
        .arg(format!("--username={}", profile.username))
        .arg(format!("--pinentry={}", paths::PINENTRY))
        .arg(format!("--ca-file={}", runtime.ca_bundle().display()));
    if !profile.certificate.is_empty() {
        command.arg(format!(
            "--trusted-cert={}",
            profile.certificate.to_ascii_lowercase()
        ));
    }
    command
        .arg("--")
        .arg(format!("{}:{}", profile.gateway, profile.port));
    Ok(command)
}

fn map_runtime(error: RuntimeError) -> StartError {
    match error {
        RuntimeError::Missing => StartError::MissingProgram,
        RuntimeError::Io => StartError::Unavailable,
        _ => StartError::UntrustedRuntime,
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "ssl_tests.rs"]
mod tests;
