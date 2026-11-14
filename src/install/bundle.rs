//! Read-only binding between a packaged host, its component and recipient.
use super::{Error, valid_hash};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component as Part, Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub format: u32,
    pub app_version: String,
    pub uid: u32,
    pub build: String,
    #[serde(rename = "minimumMacOS")]
    pub minimum_macos: String,
    pub host_sha256: String,
    pub package_sha256: String,
    pub helper_sha256: String,
    pub installer_sha256: String,
    pub askpass_sha256: String,
}
pub struct Component {
    package: PathBuf,
    executable: PathBuf,
    principal: u32,
    metadata: Metadata,
    seal: String,
}
impl Component {
    pub fn current() -> Result<Self, Error> {
        let uid = unsafe { libc::getuid() };
        if uid == 0 || unsafe { libc::geteuid() } != uid {
            return Err(Error::PermissionDenied);
        }
        Self::at_executable(&std::env::current_exe().map_err(|_| Error::Io)?, uid)
    }
    fn at_executable(executable: &Path, uid: u32) -> Result<Self, Error> {
        super::policy::account(uid)?;
        let macos = executable.parent().ok_or(Error::UntrustedPath)?;
        let contents = macos.parent().ok_or(Error::UntrustedPath)?;
        let bundle = contents.parent().ok_or(Error::UntrustedPath)?;
        if executable.file_name().is_none_or(|n| n != "vpnt")
            || macos.file_name().is_none_or(|n| n != "MacOS")
            || contents.file_name().is_none_or(|n| n != "Contents")
            || bundle.extension().is_none_or(|n| n != "app")
        {
            return Err(Error::UntrustedPath);
        }
        let directory = contents.join("Resources/Component");
        let bytes = read(&directory.join("component.json"), uid, 8192)?;
        let metadata: Metadata =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidManifest)?;
        if metadata.format != 1
            || metadata.app_version != env!("CARGO_PKG_VERSION")
            || metadata.uid != uid
        {
            return Err(Error::Incompatible);
        }
        let parts = metadata.minimum_macos.split('.').collect::<Vec<_>>();
        if !(2..=3).contains(&parts.len())
            || parts
                .iter()
                .any(|p| p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()))
            || [
                &metadata.build,
                &metadata.host_sha256,
                &metadata.package_sha256,
                &metadata.helper_sha256,
                &metadata.installer_sha256,
                &metadata.askpass_sha256,
            ]
            .into_iter()
            .any(|h| !valid_hash(h))
        {
            return Err(Error::InvalidManifest);
        }
        let result = Self {
            package: directory.join("component.pkg"),
            executable: executable.into(),
            principal: uid,
            metadata,
            seal: hash(&bytes),
        };
        result.revalidate()?;
        Ok(result)
    }
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    pub fn package(&self) -> &Path {
        &self.package
    }
    pub fn revalidate(&self) -> Result<(), Error> {
        let uid = self.principal;
        if hash(&read(
            &self.package.with_file_name("component.json"),
            uid,
            8192,
        )?) != self.seal
            || hash(&read(&self.executable, uid, 128 * 1024 * 1024)?) != self.metadata.host_sha256
            || hash(&read(&self.package, uid, 300 * 1024 * 1024)?) != self.metadata.package_sha256
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}

fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
fn read(path: &Path, uid: u32, limit: u64) -> Result<Vec<u8>, Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Part::RootDir | Part::Normal(_)))
    {
        return Err(Error::UntrustedPath);
    }
    for parent in path.parent().ok_or(Error::UntrustedPath)?.ancestors() {
        directory(parent, uid)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::UntrustedPath)?;
    let m = file.metadata().map_err(|_| Error::Io)?;
    if !m.is_file()
        || (m.uid() != uid && m.uid() != 0)
        || m.nlink() != 1
        || m.mode() & 0o7022 != 0
        || m.len() > limit
    {
        return Err(Error::UntrustedPath);
    }
    crate::fs_permissions::check_file(&file, false).map_err(|_| Error::UntrustedPath)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Integrity);
    }
    Ok(bytes)
}

fn directory(path: &Path, uid: u32) -> Result<(), Error> {
    let m = fs::symlink_metadata(path).map_err(|_| Error::UntrustedPath)?;
    // The system Applications directory is normally root:admin 0775. The app
    // and every descendant must still belong to root/current uid without ACL
    // mutation grants; this exception never applies to component/helper files.
    let applications = matches!(
        path.to_str(),
        Some("/Applications" | "/System/Volumes/Data/Applications")
    ) && m.uid() == 0
        && m.gid() == 80
        && m.mode() & 0o7777 == 0o775;
    if !m.is_dir() || (m.uid() != uid && m.uid() != 0) || (m.mode() & 0o7022 != 0 && !applications)
    {
        return Err(Error::UntrustedPath);
    }
    crate::fs_permissions::check_path(path, false).map_err(|_| Error::UntrustedPath)
}

#[cfg(test)]
mod tests;
