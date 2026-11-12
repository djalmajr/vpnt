use super::*;
use crate::helper::{
    controller_lock::{ControllerLock, LockError},
    paths, runtime,
};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) struct Tree {
    pub tools: PathBuf,
    pub state: PathBuf,
    pub policies: PathBuf,
    pub owner: u32,
    pub group: u32,
}
impl Tree {
    pub fn system() -> Self {
        Self {
            tools: Path::new(paths::HELPER).parent().unwrap().into(),
            state: paths::STATE.into(),
            policies: "/private/etc/sudoers.d".into(),
            owner: 0,
            group: 0,
        }
    }
    #[cfg(test)]
    pub fn fixture(root: &Path) -> Self {
        Self {
            tools: root.join("tools"),
            state: root.join("state"),
            policies: root.join("sudoers.d"),
            owner: unsafe { libc::getuid() },
            group: unsafe { libc::getgid() },
        }
    }
    pub fn bootstrap(&self) -> Result<ControllerLock, Error> {
        self.directory(&self.state, 0o700)?;
        let path = self.state.join(".controller.lock");
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                file.sync_all().map_err(|_| Error::Io)?;
                self.sync(&self.state)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::UntrustedPath),
        }
        #[cfg(test)]
        let lock = ControllerLock::fixture(&self.state, self.owner);
        #[cfg(not(test))]
        let lock = ControllerLock::acquire();
        lock.map_err(|e| {
            if e == LockError::Busy {
                Error::Busy
            } else {
                Error::UntrustedPath
            }
        })
    }
    pub fn directory(&self, path: &Path, mode: u32) -> Result<(), Error> {
        match fs::symlink_metadata(path) {
            Ok(m) => {
                if !m.is_dir() || m.mode() & 0o7777 != mode {
                    return Err(Error::UntrustedPath);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(Error::UntrustedPath)?;
                self.existing_parent(path)?;
                if !parent.exists() {
                    self.directory(parent, 0o755)?;
                }
                DirBuilder::new()
                    .mode(mode)
                    .create(path)
                    .map_err(|_| Error::Io)?;
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .map_err(|_| Error::Io)?;
                self.sync(parent)?;
            }
            Err(_) => return Err(Error::UntrustedPath),
        }
        payload::files::directory(path, self.owner, mode == 0o700)
    }
    pub fn existing_parent(&self, path: &Path) -> Result<(), Error> {
        let mut parent = path.parent().ok_or(Error::UntrustedPath)?;
        loop {
            match fs::symlink_metadata(parent) {
                Ok(_) => return payload::files::directory(parent, self.owner, false),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    parent = parent.parent().ok_or(Error::UntrustedPath)?
                }
                Err(_) => return Err(Error::UntrustedPath),
            }
        }
    }
    pub fn sync(&self, path: &Path) -> Result<(), Error> {
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Io)
    }
    pub fn resolve(&self, key: &str) -> Result<PathBuf, Error> {
        if let Some(name) = key.strip_prefix("adapters/") {
            let target = match name {
                "helper" => paths::HELPER,
                "installer" => paths::INSTALLER,
                "askpass" => paths::ASKPASS,
                "pinentry" => paths::PINENTRY,
                "pppd" => paths::PPP_SUPERVISOR,
                _ => return Err(Error::InvalidManifest),
            };
            return Ok(self.tools.join(Path::new(target).file_name().unwrap()));
        }
        if let Some(value) = key.strip_prefix("runtime/") {
            let (version, name) = value.split_once('/').ok_or(Error::InvalidManifest)?;
            if !version_ok(version) || (name != "manifest.json" && !runtime::valid_name(name)) {
                return Err(Error::InvalidManifest);
            }
            return Ok(self.tools.join("dev.vpnt.runtime").join(version).join(name));
        }
        if let Some(value) = key.strip_prefix("policy/") {
            let uid = value.parse::<u32>().map_err(|_| Error::InvalidManifest)?;
            if uid.to_string() != value {
                return Err(Error::InvalidManifest);
            }
            policy::account(uid)?;
            return Ok(self.policies.join(format!("dev_vpnt_{uid}")));
        }
        if key == "receipt" {
            return Ok(self.state.join(".installation.json"));
        }
        Err(Error::InvalidManifest)
    }
    pub fn parent(&self, key: &str) -> Result<(), Error> {
        let path = self.resolve(key)?;
        self.directory(
            path.parent().ok_or(Error::UntrustedPath)?,
            if key == "receipt" { 0o700 } else { 0o755 },
        )
    }
    pub fn user(&self, uid: u32) -> Result<(), Error> {
        policy::account(uid)?;
        self.directory(&self.state.join("users"), 0o700)?;
        self.directory(&self.state.join("users").join(uid.to_string()), 0o700)
    }
}
pub(super) fn version_ok(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}
pub(super) fn mode(key: &str) -> u32 {
    if key == "receipt" {
        0o600
    } else if key.starts_with("policy/") {
        0o440
    } else if key.starts_with("adapters/") || key.contains("/bin/") || key.ends_with(".dylib") {
        0o555
    } else {
        0o444
    }
}
