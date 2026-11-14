use super::*;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Stamp {
    pub hash: String,
    pub mode: u32,
}
#[derive(Clone)]
pub(super) struct Image {
    pub stamp: Stamp,
    pub bytes: Vec<u8>,
}
impl Image {
    pub fn new(bytes: Vec<u8>, mode: u32) -> Self {
        Self {
            stamp: Stamp {
                hash: hash(&bytes),
                mode,
            },
            bytes,
        }
    }
}

pub(super) fn snapshot(tree: &Tree, key: &str) -> Result<Option<Image>, Error> {
    let path = tree.resolve(key)?;
    tree.existing_parent(&path)?;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::UntrustedPath),
    };
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file()
        || metadata.uid() != tree.owner
        || metadata.gid() != tree.group
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.len() > 64 * 1024 * 1024
    {
        return Err(Error::UntrustedPath);
    }
    crate::fs_permissions::check_file(&file, key == "receipt").map_err(|_| Error::UntrustedPath)?;
    let mode = metadata.mode() & 0o7777;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(Error::Integrity);
    }
    Ok(Some(Image::new(bytes, mode)))
}
pub(super) fn same(image: Option<&Image>, stamp: Option<&Stamp>) -> bool {
    image.map(|i| &i.stamp) == stamp
}

pub(super) fn set(
    tree: &Tree,
    key: &str,
    expected: Option<&Stamp>,
    next: Option<&Image>,
) -> Result<(), Error> {
    let current = snapshot(tree, key)?;
    if !same(current.as_ref(), expected) {
        return Err(Error::Conflict);
    }
    if same(current.as_ref(), next.map(|i| &i.stamp)) {
        return Ok(());
    }
    let path = tree.resolve(key)?;
    if let Some(next) = next {
        tree.parent(key)?;
        atomic(tree, &path, next)?;
    } else {
        fs::remove_file(&path).map_err(|_| Error::Io)?;
        tree.sync(path.parent().unwrap())?;
    }
    Ok(())
}

pub(super) fn atomic(tree: &Tree, path: &std::path::Path, next: &Image) -> Result<(), Error> {
    if hash(&next.bytes) != next.stamp.hash {
        return Err(Error::Integrity);
    }
    let parent = path.parent().ok_or(Error::UntrustedPath)?;
    payload::files::directory(parent, tree.owner, false)?;
    let temporary = parent.join(format!(
        ".vpnt-write-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| Error::Io)?;
    let temporary = Temp(temporary);
    file.write_all(&next.bytes).map_err(|_| Error::Io)?;
    if unsafe { libc::fchown(file.as_raw_fd(), tree.owner, tree.group) } != 0 {
        return Err(Error::Io);
    }
    file.set_permissions(fs::Permissions::from_mode(next.stamp.mode))
        .map_err(|_| Error::Io)?;
    file.sync_all().map_err(|_| Error::Io)?;
    fs::rename(&temporary.0, path).map_err(|_| Error::Io)?;
    tree.sync(parent)
}
pub(super) fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
