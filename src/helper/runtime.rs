//! Admission of the fixed private client runtime. Production always requires
//! root ownership; fixture ownership is explicit and never comes from IPC.
use super::paths;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{ErrorKind, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const MAX_FILE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Missing,
    Io,
    Untrusted,
    InvalidManifest,
    Integrity,
    UnsupportedBinary,
}

#[derive(Clone, Copy)]
pub enum Program {
    Charon,
    Fortinet,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    format: u32,
    app_version: String,
    prefix: String,
    #[serde(rename = "minimumMacOS")]
    minimum_macos: String,
    strongswan: Swan,
    openfortivpn: Forti,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Swan {
    version: String,
    #[serde(rename = "source")]
    _source: String,
    #[serde(rename = "sha256")]
    _sha256: String,
    backend: String,
    pid_directory: String,
    patches: BTreeMap<String, String>,
}

/// Exact strongSwan patch set compiled into the private runtime, in apply order.
fn swan_patches() -> BTreeMap<String, String> {
    [
        (
            "charon-private-pid.patch",
            include_bytes!("../../scripts/macos/patches/charon-private-pid.patch").as_slice(),
        ),
        (
            "strongswan-utun-framing.patch",
            include_bytes!("../../scripts/macos/patches/strongswan-utun-framing.patch").as_slice(),
        ),
        (
            "strongswan-libipsec-no-routes.patch",
            include_bytes!("../../scripts/macos/patches/strongswan-libipsec-no-routes.patch")
                .as_slice(),
        ),
        (
            "charon-parent-eof.patch",
            include_bytes!("../../scripts/macos/patches/charon-parent-eof.patch").as_slice(),
        ),
        (
            "strongswan-retain-utun.patch",
            include_bytes!("../../scripts/macos/patches/strongswan-retain-utun.patch").as_slice(),
        ),
        (
            "strongswan-protected-udp.patch",
            include_bytes!("../../scripts/macos/patches/strongswan-protected-udp.patch").as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, bytes)| (name.into(), format!("{:x}", Sha256::digest(bytes))))
    .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forti {
    version: String,
    #[serde(rename = "source")]
    _source: String,
    sha256: String,
    patches: BTreeMap<String, String>,
}

pub struct Runtime {
    directory: PathBuf,
    owner: u32,
    manifest: Manifest,
}

impl Runtime {
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
    pub fn installed() -> Result<Self, RuntimeError> {
        Self::inspect(paths::runtime_directory(), 0)
    }

    pub fn inspect(directory: impl AsRef<Path>, owner: u32) -> Result<Self, RuntimeError> {
        let directory = directory.as_ref().to_owned();
        check_directory(&directory, owner)?;
        let bytes = read_file(&directory.join("manifest.json"), owner, false, 65_536)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| RuntimeError::InvalidManifest)?;
        if manifest.format != 1
            || manifest.app_version != env!("CARGO_PKG_VERSION")
            || Path::new(&manifest.prefix) != paths::runtime_directory()
            || Path::new(&manifest.strongswan.pid_directory)
                != paths::runtime_directory().join("run")
            || manifest.strongswan.version != "6.1.0"
            || manifest.strongswan.backend != "kernel-libipsec"
            || manifest.strongswan.patches != swan_patches()
            || manifest.openfortivpn.version != "1.24.1"
            || manifest.openfortivpn.sha256
                != "c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465"
            || manifest.openfortivpn.patches
                != BTreeMap::from([
                    (
                        "openfortivpn-no-routes.patch".into(),
                        format!(
                            "{:x}",
                            Sha256::digest(include_bytes!(
                                "../../scripts/macos/patches/openfortivpn-no-routes.patch"
                            ))
                        ),
                    ),
                    (
                        "openfortivpn-bound-transport.patch".into(),
                        format!(
                            "{:x}",
                            Sha256::digest(include_bytes!(
                                "../../scripts/macos/patches/openfortivpn-bound-transport.patch"
                            ))
                        ),
                    ),
                    (
                        "openfortivpn-ppp-supervisor.patch".into(),
                        format!(
                            "{:x}",
                            Sha256::digest(include_bytes!(
                                "../../scripts/macos/patches/openfortivpn-ppp-supervisor.patch"
                            ))
                        ),
                    ),
                ])
            || manifest.files.len() > 64
            || !valid_version(&manifest.minimum_macos)
            || !manifest.files.contains_key("bin/charon")
            || !manifest.files.contains_key("bin/openfortivpn")
            || !manifest.files.contains_key("certs/ca-bundle.pem")
        {
            return Err(RuntimeError::InvalidManifest);
        }
        let runtime = Self {
            directory,
            owner,
            manifest,
        };
        runtime.verify()?;
        Ok(runtime)
    }

    pub fn program(&self, program: Program) -> PathBuf {
        self.directory.join(match program {
            Program::Charon => "bin/charon",
            Program::Fortinet => "bin/openfortivpn",
        })
    }

    pub fn ca_bundle(&self) -> PathBuf {
        self.directory.join("certs/ca-bundle.pem")
    }

    /// Only the fixed auxiliary executable is admitted in production. Root
    /// ownership and all ancestors are checked independently from the C runtime.
    pub fn verify_helper() -> Result<(), RuntimeError> {
        Self::verify_adapter(Path::new(paths::HELPER))
    }
    pub fn verify_installer() -> Result<(), RuntimeError> {
        Self::verify_adapter(Path::new(paths::INSTALLER))
    }
    pub fn verify_askpass() -> Result<(), RuntimeError> {
        Self::verify_adapter(Path::new(paths::ASKPASS))
    }
    pub fn verify_pinentry() -> Result<(), RuntimeError> {
        Self::verify_adapter(Path::new(paths::PINENTRY))
    }
    pub fn verify_ppp_supervisor() -> Result<(), RuntimeError> {
        Self::verify_adapter(Path::new(paths::PPP_SUPERVISOR))
    }
    fn verify_adapter(path: &Path) -> Result<(), RuntimeError> {
        Self::inspect_adapter(path, 0)
    }
    pub(crate) fn inspect_adapter(path: &Path, owner: u32) -> Result<(), RuntimeError> {
        check_directory(path.parent().ok_or(RuntimeError::Untrusted)?, owner)?;
        let bytes = read_file(path, owner, true, MAX_FILE)?;
        check_macho(&bytes, &BTreeMap::new(), true)
    }
    pub(crate) fn file_hashes(&self) -> &BTreeMap<String, String> {
        &self.manifest.files
    }
    pub(crate) fn minimum_macos(&self) -> &str {
        &self.manifest.minimum_macos
    }

    /// Recheck immediately before spawning. Non-root callers cannot replace
    /// admitted files or ancestors in the production tree between check and exec.
    pub fn verify(&self) -> Result<(), RuntimeError> {
        check_directory(&self.directory, self.owner)?;
        let mut actual = BTreeSet::new();
        inventory(&self.directory, &self.directory, self.owner, &mut actual)?;
        let expected = self
            .manifest
            .files
            .keys()
            .cloned()
            .chain(std::iter::once("manifest.json".into()))
            .collect();
        if actual != expected {
            return Err(RuntimeError::Integrity);
        }
        for (name, hash) in &self.manifest.files {
            if !valid_name(name)
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(RuntimeError::InvalidManifest);
            }
            let executable = matches!(name.as_str(), "bin/charon" | "bin/openfortivpn");
            let bytes = read_file(&self.directory.join(name), self.owner, executable, MAX_FILE)?;
            if format!("{:x}", Sha256::digest(&bytes)) != *hash {
                return Err(RuntimeError::Integrity);
            }
            if executable || name.starts_with("lib/") {
                check_macho(&bytes, &self.manifest.files, executable)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 240
        && name.split('/').count() <= 8
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
        && (matches!(
            name,
            "bin/charon" | "bin/openfortivpn" | "certs/ca-bundle.pem"
        ) || (name.starts_with("lib/") && name.ends_with(".dylib"))
            || (name.starts_with("licenses/") && name.ends_with(".txt")))
}

fn valid_version(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 3 && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn check_directory(directory: &Path, owner: u32) -> Result<(), RuntimeError> {
    if !directory.is_absolute()
        || directory
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(RuntimeError::Untrusted);
    }
    for path in directory.ancestors() {
        let metadata = fs::symlink_metadata(path).map_err(map_io)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0
            || (path == directory && metadata.uid() != owner)
        {
            return Err(RuntimeError::Untrusted);
        }
        crate::fs_permissions::check_path(path, false).map_err(|_| RuntimeError::Untrusted)?;
    }
    Ok(())
}

fn read_file(
    path: &Path,
    owner: u32,
    executable: bool,
    limit: u64,
) -> Result<Vec<u8>, RuntimeError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(map_io)?;
    let metadata = file.metadata().map_err(map_io)?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || (executable && metadata.mode() & 0o100 == 0)
        || metadata.len() > limit
    {
        return Err(RuntimeError::Untrusted);
    }
    crate::fs_permissions::check_file(&file, false).map_err(|_| RuntimeError::Untrusted)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() as u64 > limit {
        return Err(RuntimeError::Untrusted);
    }
    Ok(bytes)
}

fn inventory(
    root: &Path,
    directory: &Path,
    owner: u32,
    files: &mut BTreeSet<String>,
) -> Result<(), RuntimeError> {
    if directory
        .strip_prefix(root)
        .map_err(|_| RuntimeError::Untrusted)?
        .components()
        .count()
        > 8
    {
        return Err(RuntimeError::Untrusted);
    }
    for entry in fs::read_dir(directory).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(map_io)?;
        if metadata.is_dir() {
            check_directory(&path, owner)?;
            inventory(root, &path, owner, files)?;
        } else if metadata.is_file() {
            let name = path
                .strip_prefix(root)
                .map_err(|_| RuntimeError::Untrusted)?
                .to_str()
                .ok_or(RuntimeError::Untrusted)?
                .to_owned();
            if name != "manifest.json" && !valid_name(&name) {
                return Err(RuntimeError::Untrusted);
            }
            files.insert(name);
            if files.len() > 65 {
                return Err(RuntimeError::InvalidManifest);
            }
        } else {
            return Err(RuntimeError::Untrusted);
        }
    }
    Ok(())
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, RuntimeError> {
    let data = bytes
        .get(offset..offset + 4)
        .ok_or(RuntimeError::UnsupportedBinary)?;
    Ok(u32::from_le_bytes(data.try_into().unwrap()))
}

fn command_string(command: &[u8], offset_at: usize) -> Result<&str, RuntimeError> {
    let offset = word(command, offset_at)? as usize;
    if offset < 12 {
        return Err(RuntimeError::UnsupportedBinary);
    }
    let value = command
        .get(offset..)
        .ok_or(RuntimeError::UnsupportedBinary)?;
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(RuntimeError::UnsupportedBinary)?;
    std::str::from_utf8(&value[..end]).map_err(|_| RuntimeError::UnsupportedBinary)
}

fn check_dependency(value: &str, files: &BTreeMap<String, String>) -> Result<(), RuntimeError> {
    if value.split('/').any(|part| part == ".." || part == ".") {
        return Err(RuntimeError::Untrusted);
    }
    if value.starts_with("/usr/lib/") || value.starts_with("/System/Library/") {
        return Ok(());
    }
    let prefix = paths::runtime_directory();
    let name = Path::new(value)
        .strip_prefix(prefix)
        .map_err(|_| RuntimeError::Untrusted)?;
    if !files.contains_key(name.to_str().ok_or(RuntimeError::Untrusted)?) {
        return Err(RuntimeError::Integrity);
    }
    Ok(())
}

fn check_macho(
    bytes: &[u8],
    files: &BTreeMap<String, String>,
    executable: bool,
) -> Result<(), RuntimeError> {
    if bytes.len() < 32 || word(bytes, 0)? != 0xfeed_facf {
        return Err(RuntimeError::UnsupportedBinary);
    }
    let cpu = if cfg!(target_arch = "aarch64") {
        0x0100_000c
    } else {
        0x0100_0007
    };
    if word(bytes, 4)? != cpu {
        return Err(RuntimeError::UnsupportedBinary);
    }
    if (executable && word(bytes, 12)? != 2) || (!executable && !matches!(word(bytes, 12)?, 6 | 8))
    {
        return Err(RuntimeError::UnsupportedBinary);
    }
    let count = word(bytes, 16)? as usize;
    let size = word(bytes, 20)? as usize;
    if count > 4096 || size > bytes.len() - 32 {
        return Err(RuntimeError::UnsupportedBinary);
    }
    let end = 32 + size;
    let mut offset = 32;
    for _ in 0..count {
        let kind = word(bytes, offset)?;
        let length = word(bytes, offset + 4)? as usize;
        if length < 8 || !length.is_multiple_of(8) || length > end.saturating_sub(offset) {
            return Err(RuntimeError::UnsupportedBinary);
        }
        let command = &bytes[offset..offset + length];
        match kind {
            0xc | 0x8000_0018 | 0x8000_001f | 0x8000_0023 | 0x20 => {
                if length < 24 || word(command, 8)? < 24 {
                    return Err(RuntimeError::UnsupportedBinary);
                }
                check_dependency(command_string(command, 8)?, files)?
            }
            // Search paths and embedded DYLD environment are unnecessary after
            // relocation. Reject them instead of trusting a mutable fallback.
            0x8000_001c | 0x27 => return Err(RuntimeError::Untrusted),
            0xe if command_string(command, 8)? != "/usr/lib/dyld" => {
                return Err(RuntimeError::Untrusted);
            }
            _ => {}
        }
        offset += length;
    }
    if offset != end {
        return Err(RuntimeError::UnsupportedBinary);
    }
    Ok(())
}

fn map_io(error: std::io::Error) -> RuntimeError {
    if error.kind() == ErrorKind::NotFound {
        RuntimeError::Missing
    } else {
        RuntimeError::Io
    }
}
