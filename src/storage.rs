//! Private, atomic profile persistence. The privileged helper uses owner 0;
//! unprivileged tests exercise the same implementation in an owned fixture.

use crate::model::{Profile, valid_profile_id};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_BYTES: u64 = 1_048_576;
const MAX_PROFILES: usize = 64;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Io,
    UntrustedPath,
    InvalidData,
    NotFound,
    Limit,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    profiles: Vec<Profile>,
}

pub struct ProfileStore {
    directory: PathBuf,
    owner: u32,
}

impl ProfileStore {
    /// Fixed production location. No path or ownership policy comes from IPC.
    pub fn for_user(uid: u32) -> Result<Self, StoreError> {
        if uid == 0 {
            return Err(StoreError::InvalidData);
        }
        Self::open(
            Path::new("/Library/Application Support/vpnt/users").join(uid.to_string()),
            0,
        )
    }

    /// The caller must choose a trusted owner. This does not create directories
    /// or grant access; installation prepares the root-owned production tree.
    pub fn open(directory: impl AsRef<Path>, owner: u32) -> Result<Self, StoreError> {
        let store = Self {
            directory: directory.as_ref().to_owned(),
            owner,
        };
        store.check_directory()?;
        Ok(store)
    }

    pub fn load(&self) -> Result<Vec<Profile>, StoreError> {
        self.check_directory()?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.directory.join("profiles.json"))
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err(StoreError::Io),
        };
        self.check_file(&file.metadata().map_err(|_| StoreError::Io)?)?;
        let mut data = vec![];
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| StoreError::Io)?;
        if data.len() as u64 > MAX_BYTES {
            return Err(StoreError::InvalidData);
        }
        let document: Document =
            serde_json::from_slice(&data).map_err(|_| StoreError::InvalidData)?;
        let mut ids = HashSet::new();
        if document.version != 1
            || document.profiles.len() > MAX_PROFILES
            || document
                .profiles
                .iter()
                .any(|profile| profile.validate().is_err() || !ids.insert(&profile.id))
        {
            return Err(StoreError::InvalidData);
        }
        Ok(document.profiles)
    }

    pub fn save(&self, profile: Profile) -> Result<(), StoreError> {
        profile.validate().map_err(|_| StoreError::InvalidData)?;
        let _lock = self.lock()?;
        let mut profiles = self.load()?;
        if let Some(existing) = profiles
            .iter_mut()
            .find(|existing| existing.id == profile.id)
        {
            *existing = profile;
        } else {
            if profiles.len() >= MAX_PROFILES {
                return Err(StoreError::Limit);
            }
            profiles.push(profile);
        }
        self.write(profiles)
    }

    pub fn remove(&self, id: &str) -> Result<(), StoreError> {
        if !valid_profile_id(id) {
            return Err(StoreError::InvalidData);
        }
        let _lock = self.lock()?;
        let mut profiles = self.load()?;
        let count = profiles.len();
        profiles.retain(|profile| profile.id != id);
        if count == profiles.len() {
            return Err(StoreError::NotFound);
        }
        self.write(profiles)
    }

    fn check_directory(&self) -> Result<(), StoreError> {
        if !self.directory.is_absolute()
            || self
                .directory
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(StoreError::UntrustedPath);
        }
        for path in self.directory.ancestors() {
            let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::UntrustedPath)?;
            if !metadata.is_dir()
                || (metadata.uid() != 0 && metadata.uid() != self.owner)
                || metadata.mode() & 0o022 != 0
                || (path == self.directory
                    && (metadata.uid() != self.owner || metadata.mode() & 0o777 != 0o700))
            {
                return Err(StoreError::UntrustedPath);
            }
        }
        Ok(())
    }

    fn check_file(&self, metadata: &Metadata) -> Result<(), StoreError> {
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(StoreError::UntrustedPath);
        }
        Ok(())
    }

    fn lock(&self) -> Result<File, StoreError> {
        self.check_directory()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.directory.join(".profiles.lock"))
            .map_err(|_| StoreError::Io)?;
        self.check_file(&file.metadata().map_err(|_| StoreError::Io)?)?;
        // SAFETY: file owns a valid descriptor for the duration of the lock.
        // Closing this owned File releases flock, including on error/unwind.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(StoreError::Io);
        }
        Ok(file)
    }

    fn write(&self, profiles: Vec<Profile>) -> Result<(), StoreError> {
        let destination = self.directory.join("profiles.json");
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => self.check_file(&metadata)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
        let data = serde_json::to_vec(&Document {
            version: 1,
            profiles,
        })
        .map_err(|_| StoreError::InvalidData)?;
        if data.len() as u64 > MAX_BYTES {
            return Err(StoreError::Limit);
        }
        let mut created = None;
        for _ in 0..16 {
            let path = self.directory.join(format!(
                ".profiles-{}-{}.tmp",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(file) => {
                    created = Some((Temporary(path), file));
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(StoreError::Io),
            }
        }
        let (temporary, mut file) = created.ok_or(StoreError::Io)?;
        file.write_all(&data).map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        fs::rename(&temporary.0, destination).map_err(|_| StoreError::Io)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::Io)
    }
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
