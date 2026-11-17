use super::super::Error;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    dev: u64,
    ino: u64,
}
impl Stamp {
    pub fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}
pub(super) struct Directory {
    pub path: PathBuf,
    file: File,
    pub owner: u32,
    stamp: Stamp,
}
impl Directory {
    pub fn open(path: PathBuf, owner: u32) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| Error::Changed)?;
        let stamp = Stamp::of(&file.metadata().map_err(|_| Error::Unavailable)?);
        let result = Self {
            path,
            file,
            owner,
            stamp,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn create(path: PathBuf, owner: u32) -> Result<Self, Error> {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Busy
                } else {
                    Error::Unavailable
                }
            })?;
        Self::open(path, owner)
    }
    pub fn validate(&self) -> Result<(), Error> {
        let named = fs::symlink_metadata(&self.path).map_err(|_| Error::Changed)?;
        let opened = self.file.metadata().map_err(|_| Error::Unavailable)?;
        if !named.is_dir()
            || named.uid() != self.owner
            || named.mode() & 0o7777 != 0o700
            || Stamp::of(&named) != self.stamp
            || Stamp::of(&opened) != self.stamp
        {
            return Err(Error::Changed);
        }
        crate::fs_permissions::check_file(&self.file, true).map_err(|_| Error::Changed)
    }
    pub fn sync(&self) -> Result<(), Error> {
        self.validate()?;
        self.file.sync_all().map_err(|_| Error::Unavailable)
    }
    pub fn read(&self, name: &str, limit: u64) -> Result<(Vec<u8>, Stamp), Error> {
        self.validate()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.path.join(name))
            .map_err(|_| Error::Changed)?;
        let meta = file.metadata().map_err(|_| Error::Unavailable)?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.nlink() != 1
            || meta.mode() & 0o7777 != 0o600
            || meta.len() > limit
        {
            return Err(Error::Changed);
        }
        crate::fs_permissions::check_file(&file, true).map_err(|_| Error::Changed)?;
        let stamp = Stamp::of(&meta);
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        if bytes.len() as u64 > limit {
            return Err(Error::Invalid);
        }
        let now = fs::symlink_metadata(self.path.join(name)).map_err(|_| Error::Changed)?;
        if Stamp::of(&now) != stamp || !now.is_file() {
            return Err(Error::Changed);
        }
        self.validate()?;
        Ok((bytes, stamp))
    }
    pub fn write_new(&self, name: &str, bytes: &[u8]) -> Result<Stamp, Error> {
        self.validate()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.join(name))
            .map_err(|_| Error::Unavailable)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Unavailable)?;
        let stamp = Stamp::of(&file.metadata().map_err(|_| Error::Unavailable)?);
        self.validate()?;
        Ok(stamp)
    }
    pub fn inventory(&self) -> Result<Vec<String>, Error> {
        self.validate()?;
        let mut result = Vec::new();
        for entry in fs::read_dir(&self.path).map_err(|_| Error::Unavailable)? {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            result.push(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Error::Changed)?,
            );
            if result.len() > 64 {
                return Err(Error::Exhausted);
            }
        }
        self.validate()?;
        Ok(result)
    }
    pub fn remove_own(&self) -> Result<(), Error> {
        self.validate()?;
        fs::remove_dir_all(&self.path).map_err(|_| Error::Unavailable)
    }
}
pub(super) struct Unstarted(pub Option<Directory>);
impl Drop for Unstarted {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            let _ = dir.remove_own();
        }
    }
}
pub(super) fn checked_path(path: &Path) -> Result<&str, Error> {
    let value = path.to_str().ok_or(Error::Invalid)?;
    if !path.is_absolute() || value.bytes().any(|b| b < 32 || b == b'"' || b == b'\\') {
        return Err(Error::Invalid);
    }
    Ok(value)
}
