//! Private, atomic profile persistence. The privileged helper uses owner 0;
//! unprivileged tests exercise the same implementation in an owned fixture.
mod reservation;
pub use reservation::ProfileReservation;

use crate::model::{Profile, valid_profile_id};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
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
        profile.validate().map_err(|_| StoreError::InvalidData)?;
        let reservation = self.reserve(&profile.id)?;
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
        reservation.validate()?;
        self.write(profiles)
    }

    pub fn remove(&self, id: &str) -> Result<(), StoreError> {
        if !valid_profile_id(id) {
            return Err(StoreError::InvalidData);
        }
        let reservation = self.reserve(id)?;
        let _lock = self.lock()?;
        let mut profiles = self.load()?;
        let count = profiles.len();
        profiles.retain(|profile| profile.id != id);
        if count == profiles.len() {
            return Err(StoreError::NotFound);
        }
        reservation.validate()?;
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
}
