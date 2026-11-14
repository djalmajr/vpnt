use super::*;
use crate::{
    helper::{paths, runtime::Runtime},
    install::{bundle::Component, payload},
};
use std::{path::Path, process::Command};
pub(super) struct Plan {
    pub command: Command,
    component: Option<Component>,
    #[cfg(test)]
    fixture: bool,
}
impl Plan {
    pub fn admit(kind: Kind) -> Result<Self, Error> {
        let component = if kind == Kind::Install {
            Some(Component::current().map_err(|_| Error::Untrusted)?)
        } else {
            None
        };
        let command = if let Some(component) = &component {
            install_command(component.package())
        } else {
            removal_admission()?;
            remove_command()
        };
        Ok(Self {
            command,
            component,
            #[cfg(test)]
            fixture: false,
        })
    }
    pub fn revalidate(&self) -> Result<(), Error> {
        #[cfg(test)]
        if self.fixture {
            return Ok(());
        }
        if let Some(c) = &self.component {
            c.revalidate().map_err(|_| Error::Untrusted)
        } else {
            removal_admission()
        }
    }
    pub fn installed(&self) -> Result<Receipt, Error> {
        #[cfg(test)]
        if self.fixture {
            return Ok(Receipt::Installed {
                helper_sha256: "a".repeat(64),
            });
        }
        let component = self.component.as_ref().ok_or(Error::Untrusted)?;
        Runtime::verify_helper().map_err(|_| Error::Untrusted)?;
        let bytes = payload::files::read(Path::new(paths::HELPER), 0, 64 * 1024 * 1024)
            .map_err(|_| Error::Untrusted)?;
        use sha2::{Digest, Sha256};
        if format!("{:x}", Sha256::digest(bytes)) != component.metadata().helper_sha256 {
            return Err(Error::Incompatible);
        }
        Ok(Receipt::Installed {
            helper_sha256: component.metadata().helper_sha256.clone(),
        })
    }
    #[cfg(test)]
    pub fn fixture(command: Command) -> Self {
        Self {
            command,
            component: None,
            fixture: true,
        }
    }
}
fn removal_admission() -> Result<(), Error> {
    Runtime::verify_installer()
        .and_then(|_| Runtime::verify_askpass())
        .map_err(|_| Error::Untrusted)
}
pub(super) fn install_command(package: &Path) -> Command {
    let mut c = Command::new("/usr/bin/open");
    c.args(["-W", "-n", "-b", "com.apple.installer"])
        .arg(package);
    c
}
pub(super) fn remove_command() -> Command {
    let mut c = Command::new("/usr/bin/sudo");
    c.args(["-A", "-k", "--", paths::INSTALLER, "remove"]);
    c
}
