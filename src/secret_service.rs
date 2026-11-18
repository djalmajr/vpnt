//! Session Secret Service access through the system libsecret executable.
use crate::{
    model::{VpnKind, valid_profile_id},
    secrets::{Credentials, Secret, SecretError, SecretStore},
};
use std::{
    io::{self, Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PROGRAM: &str = "/usr/bin/secret-tool";
const BUS: &str = "DBUS_SESSION_BUS_ADDRESS";
const TIMEOUT: Duration = Duration::from_secs(30);
// Credentials accept up to 4096 bytes. Allow a lookup terminator and detect overflow.
const OUTPUT_LIMIT: usize = 4098;

pub struct LinuxSecretService {
    #[cfg(test)]
    program: std::path::PathBuf,
    timeout: Duration,
}

impl Default for LinuxSecretService {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxSecretService {
    pub fn new() -> Self {
        Self {
            #[cfg(test)]
            program: PROGRAM.into(),
            timeout: TIMEOUT,
        }
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub fn with_program(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            program: path.into(),
            timeout: TIMEOUT,
        }
    }

    fn command(&self) -> Result<Command, SecretError> {
        #[cfg(test)]
        if self.program != std::path::Path::new(PROGRAM) {
            let directory = self.program.parent().ok_or(SecretError::Unavailable)?;
            let mut command = Command::new(&self.program);
            command
                .env_clear()
                .env("HOME", directory)
                .env("USERPROFILE", directory)
                .env("TMPDIR", directory)
                .env("XDG_CONFIG_HOME", directory)
                .env("PATH", "/usr/bin:/bin");
            return Ok(command);
        }

        if !std::env::var_os(BUS).is_some_and(|address| !address.is_empty()) {
            return Err(SecretError::Unavailable);
        }
        Ok(Command::new(PROGRAM))
    }

    fn run(
        &self,
        account: &Account<'_>,
        operation: Operation<'_>,
        field: Option<&str>,
    ) -> Result<Option<Secret>, SecretError> {
        let mut command = self.command()?;
        command.arg(operation.command());
        if let Operation::Store(_) = operation {
            let field = field.expect("store requires a field");
            command.arg(format!("--label=VPN Tray: {} ({field})", account.id));
        }
        // Valid profile IDs can begin with a hyphen, which libsecret parses as an option.
        if account.id.starts_with('-') {
            command.arg("--");
        }
        command.args([
            "application",
            "vpnt",
            "profile",
            account.id,
            "kind",
            account.kind,
        ]);
        if let Some(field) = field {
            command.args(["field", field]);
        }

        let mut input = match operation {
            Operation::Store(value) => {
                let (parent, child) = pipe()?;
                command.stdin(child);
                Some((parent, value.as_bytes()))
            }
            _ => {
                command.stdin(Stdio::null());
                None
            }
        };
        let mut output = if matches!(operation, Operation::Lookup) {
            let (parent, child) = pipe()?;
            command.stdout(child);
            Some(parent)
        } else {
            command.stdout(Stdio::null());
            None
        };
        let (errors, child_errors) = pipe()?;
        let mut errors = Some(errors);
        command.stderr(child_errors);
        let deadline = Instant::now() + self.timeout;
        let mut child = OwnedChild(command.spawn().map_err(unavailable)?);
        drop(command);

        let mut stdout = Zeroizing::new([0; OUTPUT_LIMIT]);
        let mut size = 0;
        let mut stderr = Zeroizing::new([0; 256]);
        let mut has_stderr = false;
        let status = loop {
            if Instant::now() >= deadline {
                return Err(SecretError::Unavailable);
            }
            write_input(&mut input)?;
            size += read_pipe(&mut output, &mut stdout[size..])?;
            if size == stdout.len() {
                return Err(SecretError::InvalidData);
            }
            has_stderr |= read_pipe(&mut errors, &mut stderr[..])? > 0;
            if let Some(status) = child.0.try_wait().map_err(unavailable)? {
                if input.is_some() {
                    return Err(SecretError::Unavailable);
                }
                if output.is_none() && errors.is_none() {
                    break status;
                }
            }
            thread::sleep(Duration::from_millis(5));
        };

        if status.success() {
            if matches!(operation, Operation::Lookup) {
                let bytes = &stdout[..size];
                let value = std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap_or(bytes))
                    .map_err(|_| SecretError::InvalidData)?;
                return Ok(Some(value.into()));
            }
            return Ok(None);
        }
        if status.code() == Some(1)
            && size == 0
            && !has_stderr
            && !matches!(operation, Operation::Store(_))
        {
            return Ok(None);
        }
        Err(SecretError::Unavailable)
    }
}

struct Account<'a> {
    id: &'a str,
    kind: &'static str,
    required: &'static str,
}

impl<'a> Account<'a> {
    fn new(id: &'a str, kind: VpnKind) -> Result<Option<Self>, SecretError> {
        if !valid_profile_id(id) {
            return Err(SecretError::InvalidData);
        }
        // Types without reusable credentials (including OVPN when enabled) never call libsecret.
        let (kind, required) = if kind == VpnKind::Ssl {
            ("ssl", "password")
        } else if kind == VpnKind::Ipsec {
            ("ipsec", "psk")
        } else {
            return Ok(None);
        };
        Ok(Some(Self { id, kind, required }))
    }
}

impl SecretStore for LinuxSecretService {
    fn contains(&self, id: &str, kind: VpnKind) -> Result<bool, SecretError> {
        let Some(account) = Account::new(id, kind)? else {
            return Ok(false);
        };
        Ok(self
            .run(&account, Operation::Lookup, Some(account.required))?
            .is_some())
    }

    fn load(&self, id: &str, kind: VpnKind) -> Result<Credentials, SecretError> {
        let account = Account::new(id, kind)?.ok_or(SecretError::Missing)?;
        let password = self.run(&account, Operation::Lookup, Some("password"))?;
        let psk = self.run(&account, Operation::Lookup, Some("psk"))?;
        if password.is_none() && psk.is_none() {
            return Err(SecretError::Missing);
        }
        let credentials = Credentials {
            password: password.unwrap_or_else(|| "".into()),
            psk: psk.unwrap_or_else(|| "".into()),
        };
        credentials.validate(kind)?;
        Ok(credentials)
    }

    fn save(&self, id: &str, kind: VpnKind, credentials: &Credentials) -> Result<(), SecretError> {
        let Some(account) = Account::new(id, kind)? else {
            return if credentials.password.expose().is_empty()
                && credentials.psk.expose().is_empty()
            {
                Ok(())
            } else {
                Err(SecretError::InvalidData)
            };
        };
        credentials.validate(kind)?;
        for (field, value) in [
            ("password", credentials.password.expose()),
            ("psk", credentials.psk.expose()),
        ] {
            let operation = if value.is_empty() {
                Operation::Clear
            } else {
                Operation::Store(value)
            };
            self.run(&account, operation, Some(field))?;
        }
        Ok(())
    }

    fn remove(&self, id: &str, kind: VpnKind) -> Result<(), SecretError> {
        if let Some(account) = Account::new(id, kind)? {
            self.run(&account, Operation::Clear, None)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Operation<'a> {
    Lookup,
    Store(&'a str),
    Clear,
}

impl Operation<'_> {
    fn command(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Store(_) => "store",
            Self::Clear => "clear",
        }
    }
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn pipe() -> Result<(UnixStream, Stdio), SecretError> {
    let (parent, child) = UnixStream::pair().map_err(unavailable)?;
    parent.set_nonblocking(true).map_err(unavailable)?;
    Ok((parent, Stdio::from(OwnedFd::from(child))))
}

fn write_input(input: &mut Option<(UnixStream, &[u8])>) -> Result<(), SecretError> {
    if let Some((stream, bytes)) = input {
        match stream.write(bytes) {
            Ok(0) => return Err(SecretError::Unavailable),
            Ok(size) => {
                *bytes = &bytes[size..];
                if bytes.is_empty() {
                    *input = None;
                }
            }
            Err(error) if retry_io(&error) => {}
            Err(error) => return Err(unavailable(error)),
        }
    }
    Ok(())
}

fn read_pipe(pipe: &mut Option<UnixStream>, buffer: &mut [u8]) -> Result<usize, SecretError> {
    let Some(stream) = pipe else {
        return Ok(0);
    };
    match stream.read(buffer) {
        Ok(0) => {
            *pipe = None;
            Ok(0)
        }
        Ok(size) => Ok(size),
        Err(error) if retry_io(&error) => Ok(0),
        Err(error) => Err(unavailable(error)),
    }
}

fn retry_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn unavailable(_: io::Error) -> SecretError {
    SecretError::Unavailable
}

#[cfg(test)]
#[path = "secret_service_tests.rs"]
mod tests;
