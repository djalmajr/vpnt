//! Process layer of the Fortinet driver. An interface named by client output
//! is only a candidate; the controller must prove ownership, install its leased
//! routes and run a tunnel-bound probe before reporting Connected.
use super::ssl_output::Output;
use crate::helper::{pinentry_channel::PinentryChild, process::StopOutcome};
#[cfg(target_os = "macos")]
use crate::{
    connection::macos::{
        egress::Egress,
        ppp_control::{Control, Policy, Proof},
    },
    helper::{
        paths,
        runtime::{Program, Runtime, RuntimeError},
    },
    model::{Profile, VpnKind},
    secrets::Credentials,
};
use std::{io, time::Duration};
#[cfg(target_os = "macos")]
use std::{
    net::{IpAddr, Ipv4Addr},
    os::unix::net::UnixStream,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
};

#[cfg(target_os = "macos")]
pub(crate) struct Binding {
    pub(crate) interface: String,
    pub(crate) index: u32,
    pub(crate) gateway: Ipv4Addr,
}

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
    pub start_error: Option<StartError>,
}

pub struct SslDriver {
    child: PinentryChild,
    output: Output,
    #[cfg(target_os = "macos")]
    supervision: Control,
    start_error: Option<StartError>,
}

impl SslDriver {
    /// Called by the privileged helper with its own stored profile. No paths or
    /// executable names are accepted from the IPC request.
    #[cfg(target_os = "macos")]
    pub fn start(
        profile: &Profile,
        credentials: Credentials,
        egress: &Egress,
        canceled: &Arc<AtomicBool>,
    ) -> Result<Self, StartError> {
        // SAFETY: UID queries have no memory preconditions.
        if !cfg!(target_os = "macos") || unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(StartError::PermissionDenied);
        }
        crate::helper::ppp_config::verify().map_err(|_| StartError::Unavailable)?;
        let runtime = Runtime::installed().map_err(map_runtime)?;
        Runtime::verify_pinentry().map_err(map_runtime)?;
        Runtime::verify_ppp_supervisor().map_err(map_runtime)?;
        let binding = egress
            .binding(profile)
            .map_err(|_| StartError::Unavailable)?;
        let mut driver =
            Self::start_using(&runtime, profile, credentials, &binding, canceled.clone())?;
        if !egress.is_current(profile).unwrap_or(false) {
            driver.start_error = Some(StartError::Unavailable);
        }
        Ok(driver)
    }
    #[cfg(target_os = "macos")]
    fn start_using(
        runtime: &Runtime,
        profile: &Profile,
        credentials: Credentials,
        binding: &Binding,
        canceled: Arc<AtomicBool>,
    ) -> Result<Self, StartError> {
        let command = command(runtime, profile, binding)?;
        credentials
            .validate(VpnKind::Ssl)
            .map_err(|_| StartError::InvalidSecret)?;
        runtime.verify().map_err(map_runtime)?;
        let (server, supervisor) = UnixStream::pair().map_err(|_| StartError::Unavailable)?;
        let child =
            PinentryChild::spawn_private_runtime(command, credentials.password, supervisor.into())
                .map_err(|_| StartError::Unavailable)?;
        // No permission has been issued before this control object exists.
        // Construction failure closes the capability and the owned client;
        // admitted runtime code cannot bypass the supervisor gate.
        let supervision = Control::new(
            server,
            child.id(),
            Policy {
                owner: runtime.owner(),
                client: runtime.program(Program::Fortinet),
                supervisor: paths::PPP_SUPERVISOR.into(),
                ppp: crate::helper::ppp_supervisor::SYSTEM_PPP.into(),
            },
            canceled,
        )
        .map_err(|_| StartError::Unavailable)?;
        let mut driver = Self {
            child,
            output: Output::default(),
            supervision,
            start_error: None,
        };
        let setup = (|| {
            let stdout = driver.child.take_stdout().ok_or(StartError::Unavailable)?;
            driver
                .output
                .attach(stdout)
                .map_err(|_| StartError::Unavailable)?;
            let stderr = driver.child.take_stderr().ok_or(StartError::Unavailable)?;
            driver
                .output
                .attach(stderr)
                .map_err(|_| StartError::Unavailable)
        })();
        // After spawn, retain the driver/receipts even when setup fails.
        driver.start_error = setup.err();
        Ok(driver)
    }
    pub fn poll(&mut self) -> io::Result<Update> {
        #[cfg(target_os = "macos")]
        {
            if self.start_error.is_some() {
                self.supervision.cancel();
            }
            self.supervision.poll()?;
            if self.supervision.failed() {
                self.start_error = Some(StartError::Unavailable);
            }
        }
        let exited = self.child.poll()?.is_some();
        if exited {
            self.output.finish();
        }
        let observed = self.output.snapshot();
        Ok(Update {
            candidate: observed.candidate,
            failure: observed.failure,
            exited,
            start_error: self.start_error,
        })
    }
    /// This confirms exit of the direct client only. The controller must also
    /// verify PPP and its leased routes are gone, including after escalation.
    pub fn stop(&mut self) -> io::Result<StopOutcome> {
        #[cfg(target_os = "macos")]
        self.supervision.cancel();
        let result = self.child.stop(Duration::from_secs(3));
        self.output.finish();
        result
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn supervised_ppp(&self) -> Option<Arc<Proof>> {
        self.supervision.proof()
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn ppp_may_have_run(&self) -> bool {
        self.supervision.may_have_run()
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn children_complete(&mut self) -> io::Result<bool> {
        let exited = self.child.poll()?.is_some();
        self.supervision.complete(exited)
    }
}
impl Drop for SslDriver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(target_os = "macos")]
fn command(runtime: &Runtime, profile: &Profile, binding: &Binding) -> Result<Command, StartError> {
    profile.validate().map_err(|_| StartError::InvalidProfile)?;
    if profile.kind != VpnKind::Ssl
        || profile.username.is_empty()
        || matches!(profile.gateway.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
        || binding.index == 0
        || binding.interface.is_empty()
        || binding.interface.len() >= libc::IFNAMSIZ
        || !binding
            .interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || binding.gateway.is_unspecified()
        || binding.gateway.is_multicast()
        || binding.gateway == Ipv4Addr::BROADCAST
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
        .arg(format!("--ca-file={}", runtime.ca_bundle().display()))
        .arg(format!("--ifname={}", binding.interface))
        .arg(format!("--vpnt-ifindex={}", binding.index))
        .arg(format!("--vpnt-gateway-ip={}", binding.gateway));
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

#[cfg(target_os = "macos")]
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
