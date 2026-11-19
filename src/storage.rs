//! Private, atomic profile persistence. The privileged helper uses owner 0;
//! unprivileged tests exercise the same implementation in an owned fixture.
mod reservation;
pub use reservation::ProfileReservation;

use crate::model::{Profile, VpnKind, valid_profile_id};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    fs::{self, File, Metadata, OpenOptions, Permissions},
    io::{self, ErrorKind, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_BYTES: u64 = 1_048_576;
const MAX_PROFILES: usize = 64;
const MAX_OVPN_BYTES: usize = 32 * 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Io,
    UntrustedPath,
    InvalidData,
    NotFound,
    Limit,
    Busy,
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

enum ConfigChange {
    None,
    // The admin path stores .ovpn files.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Remove,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Replace(Option<Vec<u8>>),
}

impl ProfileStore {
    /// Opens the Linux user's XDG profile store without accepting paths over IPC.
    #[cfg(target_os = "linux")]
    pub fn for_current_user() -> Result<Self, StoreError> {
        Self::for_user_environment(
            std::env::var_os("XDG_DATA_HOME"),
            std::env::var_os("HOME"),
            unsafe { libc::geteuid() },
        )
    }

    #[cfg(target_os = "linux")]
    fn for_user_environment(
        xdg: Option<std::ffi::OsString>,
        home: Option<std::ffi::OsString>,
        uid: u32,
    ) -> Result<Self, StoreError> {
        if uid == 0 {
            return Err(StoreError::InvalidData);
        }
        let xdg = xdg.filter(|s| !s.is_empty());
        if let Some(value) = &xdg {
            reject_dot_components(Path::new(value))?;
        }
        let base = match xdg.as_deref().map(Path::new).filter(|p| p.is_absolute()) {
            Some(path) => path.to_path_buf(),
            None => {
                let home = home
                    .as_deref()
                    .map(Path::new)
                    .filter(|p| p.is_absolute())
                    .ok_or(StoreError::UntrustedPath)?;
                reject_dot_components(home)?;
                let parent = home.join(".local");
                check_ancestors(&parent, uid)?;
                let share = parent.join("share");
                create_private_dir_if_missing(&share, uid, false)?;
                share
            }
        };
        match fs::symlink_metadata(&base) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let parent = base.parent().ok_or(StoreError::UntrustedPath)?;
                check_ancestors(parent, uid)?;
                create_private_dir_if_missing(&base, uid, true)?;
            }
            Err(_) => return Err(StoreError::UntrustedPath),
        }
        check_ancestors(&base, uid)?;
        let app_dir = base.join("vpnt");
        create_private_dir_if_missing(&app_dir, uid, false)?;
        let metadata = fs::symlink_metadata(&app_dir).map_err(|_| StoreError::UntrustedPath)?;
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(StoreError::UntrustedPath);
        }
        let dir = app_dir.join("profiles");
        create_private_dir_if_missing(&dir, uid, true)?;
        Self::open(dir, uid)
    }

    /// Path of a file directly in the validated store directory, for state
    /// such as the runtime lock. The name is fixed by the caller, never IPC.
    pub fn private_file(&self, name: &'static str) -> Result<PathBuf, StoreError> {
        self.check_directory()?;
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            return Err(StoreError::UntrustedPath);
        }
        Ok(self.directory.join(name))
    }

    /// Directory for imported OpenVPN profiles.
    pub fn ovpn_dir(&self) -> Result<PathBuf, StoreError> {
        self.check_directory()?;
        let dir = self.directory.join("ovpn");
        create_private_dir_if_missing(&dir, self.owner, true)?;
        Ok(dir)
    }

    pub fn save_ovpn_config(&self, id: &str, text: &str) -> Result<(), StoreError> {
        self.save_ovpn_bytes(id, text.as_bytes())
    }

    fn save_ovpn_bytes(&self, id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let name = ovpn_name(id)?;
        if bytes.len() > MAX_OVPN_BYTES {
            return Err(StoreError::Limit);
        }
        let dir = self.ovpn_directory(true)?.ok_or(StoreError::Io)?;
        self.ovpn_file(&dir, &name)?;
        let (mut temp, mut file) = OvpnTemporary::create(&dir)?;
        file.write_all(bytes).map_err(|_| StoreError::Io)?;
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        self.ovpn_file(&dir, &name)?;
        // SAFETY: both names are single components in the same open directory.
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp.name.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(StoreError::Io);
        }
        temp.committed = true;
        dir.sync_all().map_err(|_| StoreError::Io)
    }

    pub fn ovpn_config_exists(&self, id: &str) -> Result<bool, StoreError> {
        let name = ovpn_name(id)?;
        let Some(dir) = self.ovpn_directory(false)? else {
            return Ok(false);
        };
        self.ovpn_file(&dir, &name).map(|file| file.is_some())
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn read_ovpn_config(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let name = ovpn_name(id)?;
        let Some(dir) = self.ovpn_directory(false)? else {
            return Ok(None);
        };
        let Some(file) = self.ovpn_file(&dir, &name)? else {
            return Ok(None);
        };
        let mut data = Vec::new();
        file.take(MAX_OVPN_BYTES as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| StoreError::Io)?;
        if data.len() > MAX_OVPN_BYTES {
            return Err(StoreError::Limit);
        }
        Ok(Some(data))
    }

    fn restore_ovpn_config(&self, id: &str, old: Option<&[u8]>) {
        let restored = match old {
            Some(bytes) => self.save_ovpn_bytes(id, bytes),
            None => self.remove_ovpn_config(id),
        };
        if restored.is_err() {
            eprintln!("ovpn_rollback_failed");
        }
    }

    pub fn remove_ovpn_config(&self, id: &str) -> Result<(), StoreError> {
        let name = ovpn_name(id)?;
        let Some(dir) = self.ovpn_directory(false)? else {
            return Ok(());
        };
        if self.ovpn_file(&dir, &name)?.is_none() {
            return Ok(());
        }
        match unlink_at(&dir, &name) {
            Ok(()) => dir.sync_all().map_err(|_| StoreError::Io),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(StoreError::Io),
        }
    }

    fn ovpn_directory(&self, create: bool) -> Result<Option<File>, StoreError> {
        const FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        self.check_directory()?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(FLAGS)
            .open(&self.directory)
            .map_err(|_| StoreError::UntrustedPath)?;
        let dir = match open_at(&root, c"ovpn", FLAGS, 0) {
            Ok(dir) => dir,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if !create {
                    return Ok(None);
                }
                // SAFETY: root is live and the fixed component is NUL-terminated.
                if unsafe { libc::mkdirat(root.as_raw_fd(), c"ovpn".as_ptr(), 0o700) } == 0 {
                    root.sync_all().map_err(|_| StoreError::Io)?;
                } else if io::Error::last_os_error().kind() != ErrorKind::AlreadyExists {
                    return Err(StoreError::Io);
                }
                open_at(&root, c"ovpn", FLAGS, 0).map_err(|_| StoreError::UntrustedPath)?
            }
            Err(_) => return Err(StoreError::UntrustedPath),
        };
        let metadata = dir.metadata().map_err(|_| StoreError::Io)?;
        if metadata.uid() != self.owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(StoreError::UntrustedPath);
        }
        crate::fs_permissions::check_file(&dir, true).map_err(|_| StoreError::UntrustedPath)?;
        Ok(Some(dir))
    }

    fn ovpn_file(&self, dir: &File, name: &CStr) -> Result<Option<File>, StoreError> {
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        let file = match open_at(dir, name, flags, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::UntrustedPath),
        };
        let metadata = file.metadata().map_err(|_| StoreError::Io)?;
        self.check_file(&metadata)?;
        if metadata.mode() & 0o7777 != 0o600 {
            return Err(StoreError::UntrustedPath);
        }
        crate::fs_permissions::check_file(&file, true).map_err(|_| StoreError::UntrustedPath)?;
        Ok(Some(file))
    }

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
        crate::fs_permissions::check_file(&file, true).map_err(|_| StoreError::UntrustedPath)?;
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
        self.save_profile_with(profile, |_| Ok(ConfigChange::None), |data| self.write(data))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn save_admin_profile(
        &self,
        profile: Profile,
        config: Option<&str>,
    ) -> Result<(), StoreError> {
        self.save_admin_profile_with(profile, config, |data| self.write(data))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn save_admin_profile_with(
        &self,
        profile: Profile,
        config: Option<&str>,
        write_profile: impl FnOnce(&[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let id = profile.id.clone();
        let kind = profile.kind;
        self.save_profile_with(
            profile,
            |previous| {
                if kind != VpnKind::Ovpn {
                    // Refuse an untrusted cleanup target before replacing the profile.
                    if previous == Some(VpnKind::Ovpn) {
                        return self.ovpn_config_exists(&id).map(|exists| {
                            if exists {
                                ConfigChange::Remove
                            } else {
                                ConfigChange::None
                            }
                        });
                    }
                    return Ok(ConfigChange::None);
                }
                if let Some(config) = config {
                    let old = self.read_ovpn_config(&id).map_err(|_| StoreError::Io)?;
                    if self.save_ovpn_config(&id, config).is_err() {
                        self.restore_ovpn_config(&id, old.as_deref());
                        return Err(StoreError::Io);
                    }
                    return Ok(ConfigChange::Replace(old));
                } else if !self.ovpn_config_exists(&id)? {
                    return Err(StoreError::InvalidData);
                }
                Ok(ConfigChange::None)
            },
            write_profile,
        )
    }

    fn save_profile_with(
        &self,
        profile: Profile,
        prepare_config: impl FnOnce(Option<VpnKind>) -> Result<ConfigChange, StoreError>,
        write_profile: impl FnOnce(&[u8]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        profile.validate().map_err(|_| StoreError::InvalidData)?;
        let id = profile.id.clone();
        let reservation = self.reserve(&id)?;
        let _lock = self.lock()?;
        let mut profiles = self.load()?;
        let original = profiles.clone();
        // Two ids that differ only in case stay separate in the catalog but
        // converge on a case-insensitive volume (APFS), where one config would
        // replace the other. Refuse the new write; a catalog that already holds
        // both keeps loading until it is edited.
        if profiles
            .iter()
            .any(|existing| existing.id != id && existing.id.eq_ignore_ascii_case(&id))
        {
            return Err(StoreError::InvalidData);
        }
        let previous =
            if let Some(existing) = profiles.iter_mut().find(|existing| existing.id == id) {
                let kind = existing.kind;
                *existing = profile;
                Some(kind)
            } else {
                if profiles.len() >= MAX_PROFILES {
                    return Err(StoreError::Limit);
                }
                profiles.push(profile);
                None
            };
        let data = encode_profiles(profiles)?;
        reservation.validate()?;
        let change = prepare_config(previous)?;
        let result = reservation.validate().and_then(|()| write_profile(&data));
        if let Err(error) = result {
            match self.load() {
                Ok(current) if current != original => {
                    if encode_profiles(original)
                        .and_then(|prior| self.write(&prior))
                        .is_err()
                    {
                        eprintln!("profile_rollback_failed");
                    }
                }
                Err(_) => eprintln!("profile_rollback_unconfirmed"),
                _ => {}
            }
            if let ConfigChange::Replace(old) = change {
                self.restore_ovpn_config(&id, old.as_deref());
            }
            return Err(error);
        }
        // A crash between these writes can leave the user's new config with the old profile.
        if matches!(change, ConfigChange::Remove) && self.remove_ovpn_config(&id).is_err() {
            eprintln!("ovpn_orphan");
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), StoreError> {
        self.remove_profile(id, false)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn remove_admin_profile(&self, id: &str) -> Result<(), StoreError> {
        self.remove_profile(id, true)
    }

    fn remove_profile(&self, id: &str, remove_config: bool) -> Result<(), StoreError> {
        if !valid_profile_id(id) {
            return Err(StoreError::InvalidData);
        }
        let reservation = self.reserve(id)?;
        let _lock = self.lock()?;
        let mut profiles = self.load()?;
        let count = profiles.len();
        profiles.retain(|profile| profile.id != id);
        if count == profiles.len() {
            // Nothing in the catalog means this id was never saved here. Its
            // config path may still converge with another profile's on a
            // case-insensitive volume, so nothing is removed.
            return Err(StoreError::NotFound);
        }
        reservation.validate()?;
        // The config belongs to this entry: remove it first, so a failure
        // leaves the catalog unchanged and the profile visible for a retry.
        if remove_config {
            self.remove_ovpn_config(id)?;
        }
        self.write(&encode_profiles(profiles)?)?;
        Ok(())
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
            crate::fs_permissions::check_path(path, path == self.directory)
                .map_err(|_| StoreError::UntrustedPath)?;
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
        crate::fs_permissions::check_file(&file, true).map_err(|_| StoreError::UntrustedPath)?;
        // SAFETY: file owns a valid descriptor for the duration of the lock.
        // Closing this owned File releases flock, including on error/unwind.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(StoreError::Io);
        }
        Ok(file)
    }

    fn write(&self, data: &[u8]) -> Result<(), StoreError> {
        let destination = self.directory.join("profiles.json");
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => self.check_file(&metadata)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
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
        file.write_all(data).map_err(|_| StoreError::Io)?;
        file.sync_all().map_err(|_| StoreError::Io)?;
        fs::rename(&temporary.0, destination).map_err(|_| StoreError::Io)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::Io)
    }
}

fn encode_profiles(profiles: Vec<Profile>) -> Result<Vec<u8>, StoreError> {
    let data = serde_json::to_vec(&Document {
        version: 1,
        profiles,
    })
    .map_err(|_| StoreError::InvalidData)?;
    if data.len() as u64 > MAX_BYTES {
        return Err(StoreError::Limit);
    }
    Ok(data)
}

fn ovpn_name(id: &str) -> Result<CString, StoreError> {
    if !valid_profile_id(id) {
        return Err(StoreError::InvalidData);
    }
    CString::new(format!("{id}.ovpn")).map_err(|_| StoreError::InvalidData)
}

fn open_at(dir: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: dir owns a live descriptor and name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful openat returned a descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn unlink_at(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: the live directory and name are borrowed only for the syscall.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct OvpnTemporary<'a> {
    dir: &'a File,
    name: CString,
    committed: bool,
}
impl<'a> OvpnTemporary<'a> {
    fn create(dir: &'a File) -> Result<(Self, File), StoreError> {
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
        for _ in 0..16 {
            let name = CString::new(format!(
                ".ovpn-{}-{}.tmp",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ))
            .map_err(|_| StoreError::Io)?;
            match open_at(dir, &name, flags, 0o600) {
                Ok(file) => {
                    return Ok((
                        Self {
                            dir,
                            name,
                            committed: false,
                        },
                        file,
                    ));
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(StoreError::Io),
            }
        }
        Err(StoreError::Io)
    }
}
impl Drop for OvpnTemporary<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unlink_at(self.dir, &self.name);
        }
    }
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(target_os = "linux")]
fn reject_dot_components(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::ffi::OsStrExt;
    if path
        .as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .any(|s| s == b"." || s == b"..")
    {
        Err(StoreError::UntrustedPath)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn check_ancestors(path: &Path, owner: u32) -> Result<(), StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::UntrustedPath);
    }
    reject_dot_components(path)?;
    for part in path.ancestors() {
        let metadata = fs::symlink_metadata(part).map_err(|_| StoreError::UntrustedPath)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0
        {
            return Err(StoreError::UntrustedPath);
        }
        crate::fs_permissions::check_path(part, false).map_err(|_| StoreError::UntrustedPath)?;
    }
    Ok(())
}

// Threat model: the store belongs to the user and the runtime runs as the
// user. A process of the same user that swaps a parent for a link between the
// checks and the mkdir can make the directory appear elsewhere in its own
// files; that grants nothing it could not do directly, and open() still
// refuses the result. Other users cannot write the ancestors (checked).
fn create_private_dir_if_missing(
    path: &Path,
    owner: u32,
    private_existing: bool,
) -> Result<(), StoreError> {
    let created = match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => false,
        Err(_) => return Err(StoreError::Io),
    };
    let meta = fs::symlink_metadata(path).map_err(|_| StoreError::UntrustedPath)?;
    if !meta.is_dir()
        || (created || private_existing) && (meta.uid() != owner || meta.mode() & 0o7777 != 0o700)
    {
        return Err(StoreError::UntrustedPath);
    }
    crate::fs_permissions::check_path(path, created || private_existing)
        .map_err(|_| StoreError::UntrustedPath)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::{
        ffi::OsString,
        os::unix::fs::{PermissionsExt, symlink},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        path: PathBuf,
        uid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let uid = unsafe { libc::geteuid() };
            assert_ne!(uid, 0, "fixture requires an unprivileged user");
            let path = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
                .join(".cache")
                .join(format!(
                    "vpnt-storage-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            // A fresh CI runner may have no ~/.cache yet.
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path.parent().unwrap())
                .unwrap();
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self { path, uid }
        }
        fn home(&self) -> PathBuf {
            let home = self.path.join("home");
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(home.join(".local"))
                .unwrap();
            home
        }
        fn make(
            &self,
            xdg: Option<OsString>,
            home: Option<OsString>,
        ) -> Result<ProfileStore, StoreError> {
            ProfileStore::for_user_environment(xdg, home, self.uid)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }
    fn profile() -> Profile {
        serde_json::from_value(serde_json::json!({ "id":"a","name":"Profile a","kind":"ipsec","gateway":"vpn.example.com","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp" })).unwrap()
    }
    #[test]
    fn xdg_store_is_private_and_profiles_round_trip() {
        let f = Fixture::new();
        let base = f.path.join("xdg");
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let store = f.make(Some(base.clone().into_os_string()), None).unwrap();
        assert_eq!(store.directory, base.join("vpnt/profiles"));
        assert_eq!(mode(&store.directory), 0o700);
        let expected = profile();
        store.save(expected.clone()).unwrap();
        assert_eq!(store.load().unwrap(), vec![expected]);
    }
    #[test]
    fn missing_xdg_base_is_created_private_without_creating_its_parent() {
        let f = Fixture::new();
        let base = f.path.join("new-base");
        let store = f.make(Some(base.clone().into_os_string()), None).unwrap();
        assert_eq!(mode(&base), 0o700);
        assert_eq!(store.directory, base.join("vpnt/profiles"));
        let nested = f.path.join("missing-parent/base");
        assert!(matches!(
            f.make(Some(nested.into_os_string()), None),
            Err(StoreError::UntrustedPath)
        ));
        assert!(!f.path.join("missing-parent").exists());
    }
    #[test]
    fn relative_or_empty_xdg_uses_home_and_creates_only_share() {
        for xdg in [
            Some(OsString::from("relative")),
            Some(OsString::new()),
            None,
        ] {
            let f = Fixture::new();
            let home = f.home();
            let store = f.make(xdg, Some(home.clone().into_os_string())).unwrap();
            assert_eq!(store.directory, home.join(".local/share/vpnt/profiles"));
            assert_eq!(mode(&home.join(".local/share")), 0o700);
            assert_eq!(mode(&store.directory), 0o700);
        }
    }
    #[test]
    fn rejects_invalid_paths_and_root() {
        let f = Fixture::new();
        let home = f.home();
        assert!(matches!(
            f.make(None, Some("relative".into())),
            Err(StoreError::UntrustedPath)
        ));
        for value in [
            format!("{}/./bad", f.path.display()),
            format!("{}/../bad", f.path.display()),
        ] {
            assert!(matches!(
                f.make(Some(value.into()), Some(home.clone().into_os_string())),
                Err(StoreError::UntrustedPath)
            ));
        }
        assert!(matches!(
            ProfileStore::for_user_environment(Some(f.path.clone().into_os_string()), None, 0),
            Err(StoreError::InvalidData)
        ));
    }
    #[test]
    fn app_directory_shared_with_webkit_is_accepted_without_changing_contents() {
        let f = Fixture::new();
        let app = f.path.join("vpnt");
        fs::DirBuilder::new().mode(0o700).create(&app).unwrap();
        fs::set_permissions(&app, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(app.join("hsts-storage.sqlite"), b"fixture").unwrap();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        assert_eq!(store.directory, app.join("profiles"));
        assert_eq!(mode(&app), 0o755);
        assert_eq!(mode(&store.directory), 0o700);
        assert_eq!(
            fs::read(app.join("hsts-storage.sqlite")).unwrap(),
            b"fixture"
        );
        let expected = profile();
        store.save(expected.clone()).unwrap();
        assert_eq!(store.load().unwrap(), [expected]);
    }
    #[test]
    fn group_writable_app_directory_is_refused_before_creating_profiles() {
        let f = Fixture::new();
        let app = f.path.join("vpnt");
        fs::DirBuilder::new().mode(0o700).create(&app).unwrap();
        fs::set_permissions(&app, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(matches!(
            f.make(Some(f.path.clone().into_os_string()), None),
            Err(StoreError::UntrustedPath)
        ));
        assert_eq!(mode(&app), 0o775);
        assert!(!app.join("profiles").exists());
    }
    #[test]
    fn profiles_with_wrong_mode_are_refused_without_changes() {
        let f = Fixture::new();
        let app = f.path.join("vpnt");
        fs::DirBuilder::new().mode(0o700).create(&app).unwrap();
        let profiles = app.join("profiles");
        fs::DirBuilder::new().mode(0o700).create(&profiles).unwrap();
        fs::set_permissions(&profiles, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            f.make(Some(f.path.clone().into_os_string()), None),
            Err(StoreError::UntrustedPath)
        ));
        assert_eq!(mode(&profiles), 0o755);
        assert!(matches!(
            create_private_dir_if_missing(&profiles, f.uid, true),
            Err(StoreError::UntrustedPath)
        ));
        assert!(matches!(
            ProfileStore::open(&profiles, f.uid),
            Err(StoreError::UntrustedPath)
        ));
        assert_eq!(mode(&profiles), 0o755);
    }
    #[test]
    fn symlinks_in_app_or_profiles_are_refused() {
        for link_app in [true, false] {
            let f = Fixture::new();
            let app = f.path.join("vpnt");
            let target = f.path.join("target");
            fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
            let link = if link_app {
                app
            } else {
                fs::DirBuilder::new().mode(0o700).create(&app).unwrap();
                app.join("profiles")
            };
            symlink(&target, &link).unwrap();
            assert!(matches!(
                f.make(Some(f.path.clone().into_os_string()), None),
                Err(StoreError::UntrustedPath)
            ));
            assert!(
                fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(mode(&target), 0o700);
        }
    }
    #[test]
    fn ovpn_directory_is_private_and_never_follows_symlinks() {
        let f = Fixture::new();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        let dir = store.ovpn_dir().unwrap();
        assert_eq!(dir, f.path.join("vpnt/profiles/ovpn"));
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(store.ovpn_dir().unwrap(), dir);
        fs::remove_dir(&dir).unwrap();
        let target = f.path.join("target");
        fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
        symlink(&target, &dir).unwrap();
        assert!(matches!(store.ovpn_dir(), Err(StoreError::UntrustedPath)));
        assert!(fs::symlink_metadata(&dir).unwrap().file_type().is_symlink());
    }

    #[test]
    fn removing_profile_rejects_symlink_before_changing_document() {
        let f = Fixture::new();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        let mut value = serde_json::to_value(profile()).unwrap();
        value["kind"] = "ovpn".into();
        value["username"] = "".into();
        value["networks"] = serde_json::json!([]);
        value["ovpn"] = serde_json::json!({"certificateId":"01", "module":"/fixture.so"});
        let old: Profile = serde_json::from_value(value).unwrap();
        store.save(old.clone()).unwrap();
        let dir = store.ovpn_dir().unwrap();
        let target = f.path.join("target");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, dir.join("a.ovpn")).unwrap();
        assert!(store.remove_admin_profile("a").is_err());
        assert_eq!(store.load().unwrap(), [old]);
        assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
    }

    #[test]
    fn failed_profile_write_restores_or_removes_config() {
        for previous in [None, Some(&b"old\xffconfig"[..])] {
            let f = Fixture::new();
            let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
            let mut value = serde_json::to_value(profile()).unwrap();
            value["kind"] = "ovpn".into();
            value["username"] = "".into();
            value["networks"] = serde_json::json!([]);
            value["ovpn"] = serde_json::json!({"certificateId":"01", "module":"/fixture.so"});
            let ovpn: Profile = serde_json::from_value(value).unwrap();
            if let Some(old) = previous {
                store.save_ovpn_bytes("a", old).unwrap();
                store.save(ovpn.clone()).unwrap();
            }
            let before = store.load().unwrap();
            let error =
                store.save_admin_profile_with(ovpn, Some("new config"), |_| Err(StoreError::Io));
            assert_eq!(error, Err(StoreError::Io));
            assert_eq!(store.load().unwrap(), before);
            assert_eq!(store.read_ovpn_config("a").unwrap().as_deref(), previous);
        }
    }

    #[test]
    fn failed_profile_write_after_rename_restores_both_files() {
        let f = Fixture::new();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        let mut value = serde_json::to_value(profile()).unwrap();
        value["kind"] = "ovpn".into();
        value["username"] = "".into();
        value["networks"] = serde_json::json!([]);
        value["ovpn"] = serde_json::json!({"certificateId":"01", "module":"/fixture.so"});
        let old: Profile = serde_json::from_value(value).unwrap();
        store.save_ovpn_bytes("a", b"old").unwrap();
        store.save(old.clone()).unwrap();
        let mut new = old.clone();
        new.name = "Changed".into();
        let result = store.save_admin_profile_with(new, Some("new"), |data| {
            store.write(data)?;
            Err(StoreError::Io)
        });
        assert_eq!(result, Err(StoreError::Io));
        assert_eq!(store.load().unwrap(), [old]);
        assert_eq!(store.read_ovpn_config("a").unwrap().unwrap(), b"old");
    }

    #[test]
    fn ovpn_config_is_atomic_private_and_bounded() {
        let f = Fixture::new();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        assert_eq!(store.ovpn_config_exists("test"), Ok(false));
        assert_eq!(store.remove_ovpn_config("test"), Ok(()));
        let dir = store.directory.join("ovpn");
        assert!(!dir.exists());
        for id in ["", "../outside", "separ/ator"] {
            assert_eq!(
                store.save_ovpn_config(id, "fixture"),
                Err(StoreError::InvalidData)
            );
        }
        let data = "X".repeat(MAX_OVPN_BYTES);
        let over = format!("{data}X");
        assert_eq!(
            store.save_ovpn_config("test", &over),
            Err(StoreError::Limit)
        );
        assert!(!dir.exists());
        store.save_ovpn_config("test", &data).unwrap();
        let path = dir.join("test.ovpn");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        let old = File::open(&path).unwrap();
        store.save_ovpn_config("test", "replacement").unwrap();
        assert_eq!(store.ovpn_config_exists("test"), Ok(true));
        assert_ne!(
            old.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        let mut original = String::new();
        (&old).read_to_string(&mut original).unwrap();
        assert!(original == data);
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        store.remove_ovpn_config("test").unwrap();
        assert_eq!(store.ovpn_config_exists("test"), Ok(false));
        assert_eq!(store.remove_ovpn_config("test"), Ok(()));
    }

    #[test]
    fn ovpn_save_holds_the_profile_reservation_between_the_two_writes() {
        use std::{sync::mpsc, thread, time::Duration};

        let f = Fixture::new();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        let expected = profile();
        let (reservation, document_before) = thread::scope(|scope| {
            let (file_saved, await_file) = mpsc::channel();
            let (resume, await_resume) = mpsc::channel();
            let writer_store = &store;
            let writer = scope.spawn(move || {
                writer_store.save_profile_with(
                    expected.clone(),
                    move |_| {
                        writer_store.save_ovpn_config(&expected.id, "synthetic")?;
                        file_saved.send(()).unwrap();
                        await_resume.recv_timeout(Duration::from_secs(5)).unwrap();
                        Ok(ConfigChange::None)
                    },
                    |data| writer_store.write(data),
                )
            });
            await_file.recv_timeout(Duration::from_secs(5)).unwrap();
            let reservation = store.reserve(&profile().id);
            let document_before = store.load().unwrap();
            resume.send(()).unwrap();
            writer.join().unwrap().unwrap();
            (reservation, document_before)
        });
        assert!(matches!(reservation, Err(StoreError::Busy)));
        assert!(document_before.is_empty());
        assert_eq!(store.load().unwrap(), [profile()]);
    }

    #[test]
    fn ovpn_config_never_writes_through_untrusted_paths() {
        let f = Fixture::new();
        let store = f.make(Some(f.path.clone().into_os_string()), None).unwrap();
        let target_dir = f.path.join("target");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&target_dir)
            .unwrap();
        let target = target_dir.join("test.ovpn");
        fs::write(&target, "fixture").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let dir = store.directory.join("ovpn");
        symlink(&target_dir, &dir).unwrap();
        assert_eq!(
            store.save_ovpn_config("test", "no"),
            Err(StoreError::UntrustedPath)
        );
        assert_eq!(
            store.ovpn_config_exists("test"),
            Err(StoreError::UntrustedPath)
        );
        assert_eq!(
            store.remove_ovpn_config("test"),
            Err(StoreError::UntrustedPath)
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "fixture");
        fs::remove_file(&dir).unwrap();

        let dir = store.ovpn_dir().unwrap();
        let path = dir.join("test.ovpn");
        symlink(&target, &path).unwrap();
        assert_eq!(
            store.save_ovpn_config("test", "no"),
            Err(StoreError::UntrustedPath)
        );
        assert_eq!(
            store.ovpn_config_exists("test"),
            Err(StoreError::UntrustedPath)
        );
        assert_eq!(
            store.remove_ovpn_config("test"),
            Err(StoreError::UntrustedPath)
        );
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&path).unwrap();

        fs::hard_link(&target, &path).unwrap();
        assert_eq!(
            store.save_ovpn_config("test", "no"),
            Err(StoreError::UntrustedPath)
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "fixture");
        fs::remove_file(&path).unwrap();
        fs::write(&path, "untrusted-mode").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.ovpn_config_exists("test"),
            Err(StoreError::UntrustedPath)
        );
    }
}

// Portable administrative-store cases: identity of an id and its config.
#[cfg(test)]
mod admin_tests {
    use super::*;
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, sync::atomic::AtomicU64};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir()
                .unwrap()
                .join("output/fixtures")
                .join(format!(
                    "storage-admin-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn store(&self) -> ProfileStore {
            ProfileStore::open(&self.0, fs::metadata(&self.0).unwrap().uid()).unwrap()
        }
        fn config(&self, id: &str) -> PathBuf {
            self.0.join("ovpn").join(format!("{id}.ovpn"))
        }
        fn config_exists(&self, id: &str) -> bool {
            fs::symlink_metadata(self.config(id)).is_ok()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const CONFIG: &str = "remote vpn.example.test 1194\r\n<ca>\r\nfixture\r\n</ca>\r\n";
    const OTHER_CONFIG: &str = "remote vpn.example.test 1194\n<ca>\nother\n</ca>\n";

    fn ovpn_profile(id: &str) -> Profile {
        serde_json::from_value(serde_json::json!({
            "id": id, "name": id, "kind": "ovpn", "gateway": "vpn.example.test",
            "username": "", "networks": [], "port": 1194, "certificate": "",
            "probeHost": "192.0.2.1", "probePort": 8443, "probeMethod": "tcp",
            "ovpn": {"module": "/fixture/token.dylib", "certificateId": "01", "tls": "pkcs1_only"}
        }))
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    struct Deny(std::ffi::CString);
    #[cfg(target_os = "macos")]
    impl Drop for Deny {
        fn drop(&mut self) {
            // SAFETY: the NUL-terminated owned path stays valid for this call.
            assert_eq!(unsafe { libc::chflags(self.0.as_ptr(), 0) }, 0);
        }
    }
    #[cfg(target_os = "macos")]
    fn deny_config_removal(f: &Fixture) -> Deny {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(f.config("one").as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated owned path stays valid for this call.
        assert_eq!(
            unsafe { libc::chflags(path.as_ptr(), libc::UF_IMMUTABLE) },
            0
        );
        Deny(path)
    }
    #[cfg(not(target_os = "macos"))]
    struct Deny(PathBuf);
    #[cfg(not(target_os = "macos"))]
    impl Drop for Deny {
        fn drop(&mut self) {
            fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    #[cfg(not(target_os = "macos"))]
    fn deny_config_removal(f: &Fixture) -> Deny {
        // The unlink needs a writable directory; this fixture makes it read-only.
        let directory = f.0.join("ovpn");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        Deny(directory)
    }

    #[test]
    fn saving_an_id_that_differs_only_in_case_is_refused() {
        let f = Fixture::new();
        let store = f.store();
        store
            .save_admin_profile(ovpn_profile("one"), Some(CONFIG))
            .unwrap();
        let catalog = fs::read(f.0.join("profiles.json")).unwrap();
        let config = fs::read(f.config("one")).unwrap();
        assert_eq!(
            store.save_admin_profile(ovpn_profile("One"), Some(OTHER_CONFIG)),
            Err(StoreError::InvalidData)
        );
        assert_eq!(fs::read(f.0.join("profiles.json")).unwrap(), catalog);
        assert_eq!(fs::read(f.config("one")).unwrap(), config);
        assert_eq!(
            store
                .load()
                .unwrap()
                .iter()
                .map(|profile| profile.id.clone())
                .collect::<Vec<_>>(),
            ["one"]
        );
    }

    #[test]
    fn editing_the_stored_id_keeps_its_config() {
        let f = Fixture::new();
        let store = f.store();
        store
            .save_admin_profile(ovpn_profile("one"), Some(CONFIG))
            .unwrap();
        let mut edited = ovpn_profile("one");
        edited.name = "Edited fixture".into();
        store.save_admin_profile(edited.clone(), None).unwrap();
        assert_eq!(store.load().unwrap(), vec![edited]);
        assert_eq!(fs::read(f.config("one")).unwrap(), CONFIG.as_bytes());
    }

    #[test]
    fn removing_an_absent_case_alias_keeps_the_stored_profile_config() {
        let f = Fixture::new();
        let store = f.store();
        store
            .save_admin_profile(ovpn_profile("one"), Some(CONFIG))
            .unwrap();
        assert_eq!(store.remove_admin_profile("One"), Err(StoreError::NotFound));
        assert!(f.config_exists("one"));
        assert_eq!(fs::read(f.config("one")).unwrap(), CONFIG.as_bytes());
        assert_eq!(store.load().unwrap().len(), 1);
    }

    #[test]
    fn failed_config_removal_keeps_the_profile_and_a_retry_succeeds() {
        let f = Fixture::new();
        let store = f.store();
        store
            .save_admin_profile(ovpn_profile("one"), Some(CONFIG))
            .unwrap();
        let catalog = fs::read(f.0.join("profiles.json")).unwrap();
        let deny = deny_config_removal(&f);
        assert!(store.remove_admin_profile("one").is_err());
        assert!(f.config_exists("one"));
        assert_eq!(fs::read(f.0.join("profiles.json")).unwrap(), catalog);
        assert_eq!(store.load().unwrap().len(), 1);
        drop(deny);
        store.remove_admin_profile("one").unwrap();
        assert!(!f.config_exists("one"));
        assert!(store.load().unwrap().is_empty());
    }
}
