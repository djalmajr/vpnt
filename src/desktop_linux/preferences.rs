//! User-scoped Linux preference storage and XDG autostart.
use crate::preferences::{
    Preferences,
    host::{Backend, Coordinator, Error, Host, StartupFailure, StartupStatus},
};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::{self, File, Permissions},
    io::{self, ErrorKind, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const PREFERENCES: &CStr = c"preferences.json";
const AUTOSTART: &CStr = c"vpnt.desktop";
const DIRECTORY: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
const PREFERENCES_LIMIT: u64 = 1024;
const DESKTOP_ENTRY_LIMIT: u64 = 4096;

struct LinuxBackend {
    base: PathBuf,
    exec: String,
}

pub(super) fn current() -> Result<Box<dyn Host>, Error> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME");
    let home = std::env::var_os("HOME");
    let exec = std::env::current_exe().and_then(fs::canonicalize);
    let backend = LinuxBackend {
        base: config_base(xdg.as_deref(), home.as_deref())?,
        exec: exec.as_deref().map_or_else(|_| "vpnt".into(), executable),
    };
    Coordinator::restore(backend).map(|host| Box::new(host) as Box<dyn Host>)
}

fn config_base(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf, Error> {
    if let Some(path) = xdg.map(Path::new).filter(|path| path.is_absolute()) {
        return Ok(path.to_owned());
    }
    home.map(Path::new)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(".config"))
        .ok_or(Error::Storage)
}

fn executable(path: &Path) -> String {
    if let Some(path) = path.to_str().filter(|path| {
        path.starts_with("/usr/bin/")
            && path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'.' | b'-' | b'+')
            })
    }) {
        return path.into();
    }
    "vpnt".into()
}

impl LinuxBackend {
    fn directory(&self, name: &CStr, mode: Option<u32>) -> io::Result<Option<File>> {
        let mut directory = File::open("/")?;
        for component in self.base.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::ParentDir => c"..".to_owned(),
                Component::Normal(name) => CString::new(name.as_bytes())?,
                Component::Prefix(_) => return Err(ErrorKind::InvalidInput.into()),
            };
            let Some(child) = subdirectory(&directory, &name, mode.map(|_| 0o700))? else {
                return Ok(None);
            };
            directory = child;
        }
        subdirectory(&directory, name, mode)
    }

    fn startup_entry(&self, file: &File) -> io::Result<Option<StartupStatus>> {
        let bytes = read_bounded(file, DESKTOP_ENTRY_LIMIT)?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Ok(None);
        };
        let mut lines = text
            .lines()
            .map(str::trim)
            .skip_while(|line| line.is_empty() || line.starts_with('#'));
        if lines.next() != Some("[Desktop Entry]") {
            return Ok(None);
        }
        let (mut name, mut exec, mut hidden) = (None, None, None);
        let mut in_main_group = true;
        for line in lines {
            if line == "[Desktop Entry]" {
                return Ok(None);
            }
            if line.starts_with('[') {
                in_main_group = false;
            }
            if !in_main_group {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let slot = match key.trim_end() {
                "Name" => &mut name,
                "Exec" => &mut exec,
                "Hidden" => &mut hidden,
                _ => continue,
            };
            if slot.replace(value.trim_start()).is_some() {
                return Ok(None);
            }
        }
        if name != Some("VPN Tray")
            || !exec.is_some_and(|value| {
                value == self.exec || matches!(value, "vpnt" | "/usr/bin/vpnt")
            })
        {
            return Ok(None);
        }
        Ok(match hidden {
            Some("true") => Some(StartupStatus::Disabled),
            None | Some("false") => Some(StartupStatus::Enabled),
            Some(_) => None,
        })
    }

    fn read_startup(&self) -> io::Result<StartupStatus> {
        if let Some(dir) = self.directory(c"autostart", None)?
            && let Some(file) = regular_file(&dir, AUTOSTART)?
        {
            return Ok(self
                .startup_entry(&file)?
                .unwrap_or(StartupStatus::Disabled));
        }
        Ok(StartupStatus::Disabled)
    }

    fn change_startup(&self, enabled: bool) -> io::Result<StartupStatus> {
        let Some(dir) = self.directory(c"autostart", enabled.then_some(0o755))? else {
            return Ok(StartupStatus::Disabled);
        };
        let existing = regular_file(&dir, AUTOSTART)?;
        if let Some(file) = &existing
            && self.startup_entry(file)?.is_none()
        {
            return Err(ErrorKind::PermissionDenied.into());
        }
        if enabled {
            let entry = format!(
                "[Desktop Entry]\nType=Application\nName=VPN Tray\nExec={}\n\
                 Icon=vpnt\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n",
                self.exec,
            );
            atomic_write(&dir, AUTOSTART, 0o644, entry.as_bytes(), existing.as_ref())?;
            Ok(StartupStatus::Enabled)
        } else {
            if existing.is_some() {
                require_same_entry(&dir, AUTOSTART, existing.as_ref())?;
                unlink_at(&dir, AUTOSTART)?;
                dir.sync_all()?;
            }
            Ok(StartupStatus::Disabled)
        }
    }

    fn read_preferences(&self) -> io::Result<Option<Preferences>> {
        let Some(dir) = self.directory(c"vpnt", None)? else {
            return Ok(None);
        };
        let Some(file) = regular_file(&dir, PREFERENCES)? else {
            return Ok(None);
        };
        let bytes = read_bounded(&file, PREFERENCES_LIMIT)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if !value.is_object() {
            return Err(ErrorKind::InvalidData.into());
        }
        serde_json::from_value(value).map(Some).map_err(Into::into)
    }

    fn write_preferences(&self, preferences: Preferences) -> io::Result<()> {
        let data = serde_json::to_vec(&preferences)?;
        if data.len() as u64 > PREFERENCES_LIMIT {
            return Err(ErrorKind::InvalidData.into());
        }
        let dir = self
            .directory(c"vpnt", Some(0o700))?
            .ok_or(ErrorKind::NotFound)?;
        let existing = regular_file(&dir, PREFERENCES)?;
        atomic_write(&dir, PREFERENCES, 0o600, &data, existing.as_ref())
    }
}

impl Backend for LinuxBackend {
    fn load(&mut self) -> Result<Option<Preferences>, Error> {
        self.read_preferences().map_err(|_| Error::Storage)
    }

    fn save(&mut self, preferences: Preferences) -> Result<(), Error> {
        self.write_preferences(preferences)
            .map_err(|_| Error::Storage)
    }

    fn startup_status(&mut self) -> StartupStatus {
        self.read_startup().unwrap_or(StartupStatus::Unavailable)
    }

    fn set_startup(&mut self, enabled: bool) -> Result<StartupStatus, StartupFailure> {
        self.change_startup(enabled).map_err(|_| StartupFailure {
            observed: self.read_startup().ok(),
        })
    }
}

fn open_at(parent: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: parent owns a live descriptor and name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn subdirectory(parent: &File, name: &CStr, mode: Option<u32>) -> io::Result<Option<File>> {
    match open_at(parent, name, DIRECTORY, 0) {
        Ok(file) => return Ok(Some(file)),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let Some(mode) = mode else {
        return Ok(None);
    };
    // SAFETY: parent and name remain live during the relative syscall.
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } == 0;
    if !created {
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let file = open_at(parent, name, DIRECTORY, 0)?;
    if created {
        file.set_permissions(Permissions::from_mode(mode))?;
        parent.sync_all()?;
    }
    Ok(Some(file))
}

fn regular_file(dir: &File, name: &CStr) -> io::Result<Option<File>> {
    match open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => {
            let metadata = file.metadata()?;
            if metadata.is_file() && metadata.nlink() == 1 {
                Ok(Some(file))
            } else {
                Err(ErrorKind::InvalidData.into())
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_bounded(file: &File, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

fn require_same_entry(dir: &File, name: &CStr, previous: Option<&File>) -> io::Result<()> {
    let identity = |file: &File| {
        file.metadata()
            .map(|metadata| (metadata.dev(), metadata.ino()))
    };
    let current = regular_file(dir, name)?;
    if current.as_ref().map(identity).transpose()? != previous.map(identity).transpose()? {
        return Err(ErrorKind::AlreadyExists.into());
    }
    Ok(())
}

fn unlink_at(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: dir and name remain live. Neither argument is retained.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Temporary<'a> {
    dir: &'a File,
    name: CString,
    committed: bool,
}

impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = unlink_at(self.dir, &self.name);
        }
    }
}

fn atomic_write(
    dir: &File,
    name: &CStr,
    mode: u32,
    data: &[u8],
    previous: Option<&File>,
) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let (mut temp, mut file) = (0..16)
        .find_map(|_| {
            let temp_name = CString::new(format!(
                ".vpnt-{}-{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
            .expect("temporary name has no NUL bytes");
            match open_at(
                dir,
                &temp_name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                mode,
            ) {
                Ok(file) => Some(Ok((
                    Temporary {
                        dir,
                        name: temp_name,
                        committed: false,
                    },
                    file,
                ))),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .unwrap_or_else(|| Err(ErrorKind::AlreadyExists.into()))?;

    file.write_all(data)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    require_same_entry(dir, name, previous)?;
    // SAFETY: both single-component names are live and relative to the held directory.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            temp.name.as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    temp.committed = true;
    dir.sync_all()
}

#[cfg(test)]
#[path = "preferences_tests.rs"]
mod tests;
