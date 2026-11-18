//! Durable, observation-only records of resources whose cleanup was not proved.
//! This module never grants authority to delete a process, route or interface.
use crate::{connection::routes::AbandonedRoute, model::valid_profile_id};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_BYTES: u64 = 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fence {
    pub version: u32,
    pub uid: u32,
    pub profile: String,
    pub generation: u64,
    pub kind: Kind,
    pub reason: String,
    /// False only when the producer knows its inventory is complete.
    #[serde(default = "incomplete_by_default")]
    pub incomplete: bool,
    pub written_unix_ms: u64,
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_key: Option<String>,
    pub processes: Vec<ProcessIdentity>,
    pub interface: Option<Interface>,
    pub sink: Option<Sink>,
    #[serde(default)]
    pub retired: Vec<RetiredIdentity>,
    pub routes: Vec<AbandonedRoute>,
}
fn incomplete_by_default() -> bool {
    true
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Ssl,
    Ipsec,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_sec: i64,
    pub start_usec: i32,
    pub program: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    pub index: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sink {
    pub name: String,
    pub index: u32,
    pub source: Option<IpAddr>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredIdentity {
    pub interface: Option<Interface>,
    pub sink: Option<Sink>,
}
#[derive(Debug)]
pub enum Error {
    Untrusted,
    Invalid,
    Io(io::Error),
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "untrusted fence storage")
}
fn name(profile: &str, generation: u64) -> Result<CString, Error> {
    if !valid_profile_id(profile) || generation == 0 {
        return Err(Error::Invalid);
    }
    CString::new(format!("{profile}-{generation}.json")).map_err(|_| Error::Invalid)
}
fn parse_name(value: &CStr) -> Result<(String, u64), Error> {
    let value = value.to_str().map_err(|_| Error::Invalid)?;
    let value = value.strip_suffix(".json").ok_or(Error::Invalid)?;
    let (profile, generation) = value.rsplit_once('-').ok_or(Error::Invalid)?;
    let generation: u64 = generation.parse().map_err(|_| Error::Invalid)?;
    if name(profile, generation)?.to_bytes() != value_with_suffix(value).as_bytes() {
        return Err(Error::Invalid);
    }
    Ok((profile.to_owned(), generation))
}
fn value_with_suffix(value: &str) -> String {
    format!("{value}.json")
}
fn validate_fence(fence: &Fence, uid: u32, profile: &str, generation: u64) -> Result<(), Error> {
    if fence.version != 1
        || uid == 0
        || fence.uid != uid
        || fence.profile != profile
        || fence.generation != generation
        || name(profile, generation).is_err()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn open_at(parent: &File, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: live descriptor and NUL-terminated single-component name.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned by this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn valid_dir(dir: &File, owner: u32) -> io::Result<()> {
    let m = dir.metadata()?;
    if !m.is_dir()
        || m.uid() != owner
        || m.mode() & 0o7777 != 0o700
        || crate::fs_permissions::check_file(dir, true).is_err()
    {
        return Err(denied());
    }
    Ok(())
}
fn named_matches(dir: &File, path: &Path) -> io::Result<()> {
    let named = fs::symlink_metadata(path)?;
    let opened = dir.metadata()?;
    if !named.is_dir() || named.dev() != opened.dev() || named.ino() != opened.ino() {
        return Err(denied());
    }
    Ok(())
}
const DIR_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
fn directory(state: &Path, owner: u32, uid: u32, create: bool) -> io::Result<Option<File>> {
    if uid == 0 || !state.is_absolute() {
        return Err(denied());
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state)?;
    valid_dir(&root, owner)?;
    named_matches(&root, state)?;
    let mut parent = root;
    let mut path = state.to_path_buf();
    for component in ["fences".to_string(), uid.to_string()] {
        let component = CString::new(component).map_err(|_| denied())?;
        path.push(component.to_str().map_err(|_| denied())?);
        let mut created = false;
        let next = match open_at(&parent, &component, DIR_FLAGS, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                // The parent is private and validated; never repair an existing component.
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => created = true,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
                open_at(&parent, &component, DIR_FLAGS, 0)?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if created {
            let m = next.metadata()?;
            if !m.is_dir() || m.uid() != owner {
                return Err(denied());
            }
            next.set_permissions(fs::Permissions::from_mode(0o700))?;
            parent.sync_all()?;
        }
        valid_dir(&next, owner)?;
        named_matches(&next, &path)?;
        parent = next;
    }
    Ok(Some(parent))
}
fn valid_file(file: &File, owner: u32) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != owner
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || crate::fs_permissions::check_file(file, true).is_err()
    {
        return Err(denied());
    }
    Ok(())
}
fn existing(dir: &File, name: &CStr, owner: u32) -> io::Result<Option<(u64, u64)>> {
    match open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => {
            valid_file(&file, owner)?;
            let m = file.metadata()?;
            Ok(Some((m.dev(), m.ino())))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
struct Temp<'a> {
    dir: &'a File,
    name: CString,
    file: File,
    committed: bool,
}
impl Drop for Temp<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let identity = self.file.metadata().ok().map(|m| (m.dev(), m.ino()));
        // fstatat does not require read permission on the temporary file and
        // does not follow a substituted symlink.
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        let status = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                &mut named,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        let current = (status == 0).then_some((named.st_dev as u64, named.st_ino as u64));
        if identity.is_some() && identity == current {
            // SAFETY: unlink only the still-identical temporary file created here.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}
pub fn write(state_root: &Path, owner: u32, fence: &Fence) -> io::Result<()> {
    write_inner(state_root, owner, fence, |_, _| Ok(()))
}
fn write_inner(
    state_root: &Path,
    owner: u32,
    fence: &Fence,
    after_write: impl FnOnce(&File, &CStr) -> io::Result<()>,
) -> io::Result<()> {
    validate_fence(fence, fence.uid, &fence.profile, fence.generation)
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let data = serde_json::to_vec(fence).map_err(io::Error::other)?;
    if data.len() as u64 > MAX_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let final_name =
        name(&fence.profile, fence.generation).map_err(|_| io::ErrorKind::InvalidInput)?;
    let dir = directory(state_root, owner, fence.uid, true)?.ok_or_else(denied)?;
    let before = existing(&dir, &final_name, owner)?;
    let temporary = CString::new(format!(
        ".fence-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .map_err(|_| denied())?;
    let file = open_at(
        &dir,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    let mut temp = Temp {
        dir: &dir,
        name: temporary,
        file,
        committed: false,
    };
    let m = temp.file.metadata()?;
    if !m.is_file() || m.uid() != owner || m.nlink() != 1 {
        return Err(denied());
    }
    temp.file
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    valid_file(&temp.file, owner)?;
    temp.file.write_all(&data)?;
    after_write(&dir, &final_name)?;
    temp.file.sync_all()?;
    valid_dir(&dir, owner)?;
    let current = directory(state_root, owner, fence.uid, false)?.ok_or_else(denied)?;
    let (before_dir, after_dir) = (dir.metadata()?, current.metadata()?);
    if (before_dir.dev(), before_dir.ino()) != (after_dir.dev(), after_dir.ino()) {
        return Err(denied());
    }
    if existing(&dir, &final_name, owner)? != before {
        return Err(denied());
    }
    // SAFETY: both names are single components under this validated directory.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            temp.name.as_ptr(),
            dir.as_raw_fd(),
            final_name.as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    temp.committed = true;
    dir.sync_all()
}
fn map_storage(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => Error::Untrusted,
        _ if matches!(
            error.raw_os_error(),
            Some(libc::ELOOP) | Some(libc::ENOTDIR)
        ) =>
        {
            Error::Untrusted
        }
        _ => Error::Io(error),
    }
}
fn read_from(
    dir: &File,
    owner: u32,
    uid: u32,
    profile: &str,
    generation: u64,
) -> Result<Option<Fence>, Error> {
    let target = name(profile, generation)?;
    let file = match open_at(
        dir,
        &target,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(map_storage(e)),
    };
    valid_file(&file, owner).map_err(map_storage)?;
    if file.metadata()?.len() > MAX_BYTES {
        return Err(Error::Invalid);
    }
    let mut data = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_BYTES {
        return Err(Error::Invalid);
    }
    let fence: Fence = serde_json::from_slice(&data).map_err(|_| Error::Invalid)?;
    validate_fence(&fence, uid, profile, generation)?;
    Ok(Some(fence))
}
pub fn read(
    state_root: &Path,
    owner: u32,
    uid: u32,
    profile: &str,
    generation: u64,
) -> Result<Option<Fence>, Error> {
    name(profile, generation)?;
    let Some(dir) = directory(state_root, owner, uid, false).map_err(map_storage)? else {
        return Ok(None);
    };
    read_from(&dir, owner, uid, profile, generation)
}

fn enumeration_fd(dir: &File) -> io::Result<OwnedFd> {
    // SAFETY: duplicate the live descriptor with close-on-exec set atomically.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful duplicate transfers ownership to OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// Directory traversal is anchored to the already validated descriptor, not to a path.
fn names(dir: &File) -> io::Result<Vec<CString>> {
    let fd = enumeration_fd(dir)?;
    // SAFETY: ownership of fd transfers to DIR on success.
    let stream = unsafe { libc::fdopendir(fd.as_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _ = fd.into_raw_fd();
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Directory(stream);
    // The duplicate shares the open file description, and with it the read
    // offset, with `dir`. A previous enumeration left that offset at the end,
    // and fdopendir does not rewind on every system (btrfs then misses
    // entries created since), so start from the first entry explicitly.
    // SAFETY: the stream is valid until Directory drops it.
    unsafe { libc::rewinddir(stream.0) };
    let mut result = Vec::new();
    loop {
        // SAFETY: errno belongs to this thread; readdir's returned entry lives until the next call.
        unsafe {
            *errno_ptr() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            result.push(name.to_owned());
        }
    }
    Ok(result)
}
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
unsafe fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__error() }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

pub fn read_all(state_root: &Path, owner: u32, uid: u32) -> Result<Vec<Fence>, Error> {
    let Some(dir) = directory(state_root, owner, uid, false).map_err(map_storage)? else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for entry in names(&dir)? {
        let (profile, generation) = parse_name(&entry)?;
        let fence = read_from(&dir, owner, uid, &profile, generation)?.ok_or(Error::Untrusted)?;
        result.push(fence);
    }
    Ok(result)
}

/// Preserve the path identity even when an individual record is rejected.
/// A directory or filename that cannot be trusted fails the entire scan.
type ScannedFence = (String, u64, Result<Fence, Error>);
pub(crate) fn scan(
    state_root: &Path,
    owner: u32,
    uid: u32,
    live: &std::collections::BTreeSet<(String, u64)>,
) -> Result<Vec<ScannedFence>, Error> {
    let Some(dir) = directory(state_root, owner, uid, false).map_err(map_storage)? else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for entry in names(&dir)? {
        let (profile, generation) = match parse_name(&entry) {
            Ok(value) => value,
            Err(_) => {
                let text = entry.to_str().map_err(|_| Error::Invalid)?;
                let stem = text.strip_suffix(".json").ok_or(Error::Invalid)?;
                let candidate = match stem.rsplit_once('-') {
                    Some((profile, generation))
                        if generation.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        profile
                    }
                    None => stem,
                    _ => return Err(Error::Invalid),
                };
                if !valid_profile_id(candidate) {
                    return Err(Error::Invalid);
                }
                result.push((candidate.to_owned(), 0, Err(Error::Invalid)));
                continue;
            }
        };
        // Do not open or interpret an active generation's journal.
        if live.contains(&(profile.clone(), generation)) {
            continue;
        }
        let fence = read_from(&dir, owner, uid, &profile, generation)
            .and_then(|item| item.ok_or(Error::Untrusted));
        result.push((profile, generation, fence));
    }
    Ok(result)
}
pub fn remove(
    state_root: &Path,
    owner: u32,
    uid: u32,
    profile: &str,
    generation: u64,
) -> Result<(), Error> {
    let target = name(profile, generation)?;
    let Some(dir) = directory(state_root, owner, uid, false).map_err(map_storage)? else {
        return Ok(());
    };
    if existing(&dir, &target, owner)
        .map_err(map_storage)?
        .is_none()
    {
        return Ok(());
    }
    // SAFETY: validated directory and single-component target; no paths from the record are used.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), target.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(map_storage(error));
    }
    dir.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::routes::{Key, Network, NextHop, Route};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Fixture {
        root: PathBuf,
        owner: u32,
        uid: u32,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::current_dir().unwrap().join(format!(
                ".fence-fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let owner = unsafe { libc::geteuid() };
            Self {
                root,
                owner,
                uid: if owner == 0 { 501 } else { owner },
            }
        }
        fn dir(&self) -> PathBuf {
            self.root.join("fences").join(self.uid.to_string())
        }
        fn target(&self) -> PathBuf {
            self.dir().join("a-b-3.json")
        }
        fn fence(&self) -> Fence {
            Fence {
                version: 1,
                uid: self.uid,
                profile: "a-b".into(),
                generation: 3,
                kind: Kind::Ssl,
                reason: "route_owner_pending".into(),
                incomplete: false,
                written_unix_ms: 123456,
                service_id: Some("12345678-1234-4123-8123-123456789ABC".into()),
                dns_key: None,
                processes: vec![ProcessIdentity {
                    pid: 123,
                    start_sec: 456,
                    start_usec: 789,
                    program: "openfortivpn".into(),
                }],
                interface: Some(Interface {
                    name: "ppp0".into(),
                    index: 4,
                }),
                sink: Some(Sink {
                    name: "utun5".into(),
                    index: 5,
                    source: Some("192.0.2.1".parse().unwrap()),
                }),
                retired: vec![],
                routes: vec![AbandonedRoute {
                    route: Route {
                        key: Key {
                            network: "10.20.0.0/16".parse::<Network>().unwrap(),
                            scope: 0,
                        },
                        interface: 4,
                        next_hop: NextHop::Interface,
                    },
                    created: true,
                }],
            }
        }
        fn write(&self) {
            write(&self.root, self.owner, &self.fence()).unwrap();
        }
        fn read(&self) -> Result<Option<Fence>, Error> {
            read(&self.root, self.owner, self.uid, "a-b", 3)
        }
        fn overwrite(&self, contents: &[u8]) {
            fs::write(self.target(), contents).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn roundtrip_and_idempotent_remove() {
        let f = Fixture::new();
        assert!(f.read().unwrap().is_none());
        assert!(read_all(&f.root, f.owner, f.uid).unwrap().is_empty());
        f.write();
        assert_eq!(f.read().unwrap(), Some(f.fence()));
        assert_eq!(read_all(&f.root, f.owner, f.uid).unwrap(), vec![f.fence()]);
        remove(&f.root, f.owner, f.uid, "a-b", 3).unwrap();
        remove(&f.root, f.owner, f.uid, "a-b", 3).unwrap();
        assert!(f.read().unwrap().is_none());
    }
    #[test]
    fn enumeration_descriptor_is_close_on_exec_before_fdopendir() {
        let f = Fixture::new();
        f.write();
        let dir = directory(&f.root, f.owner, f.uid, false).unwrap().unwrap();
        let fd = enumeration_fd(&dir).unwrap();
        // SAFETY: fd is live and F_GETFD does not modify it.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "enumeration fd must be born close-on-exec"
        );
    }
    #[test]
    fn file_owner_is_checked_after_the_directory_is_trusted() {
        let f = Fixture::new();
        f.write();
        let dir = directory(&f.root, f.owner, f.uid, false).unwrap().unwrap();
        valid_dir(&dir, f.owner).unwrap();
        assert!(matches!(
            read_from(&dir, f.owner.wrapping_add(1), f.uid, "a-b", 3),
            Err(Error::Untrusted)
        ));
        assert_eq!(
            read_from(&dir, f.owner, f.uid, "a-b", 3).unwrap(),
            Some(f.fence())
        );
        assert!(f.target().exists());
    }
    #[test]
    fn failed_write_does_not_publish_and_removes_temp() {
        let f = Fixture::new();
        let result = write_inner(&f.root, f.owner, &f.fence(), |dir, final_name| {
            assert!(
                existing(dir, final_name, f.owner).unwrap().is_none(),
                "final must not exist before successful write"
            );
            let entries = names(dir).unwrap();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].to_bytes().starts_with(b".fence-"));
            Err(io::Error::other("injected write failure"))
        });
        assert!(result.is_err());
        assert!(!f.target().exists());
        assert_eq!(fs::read_dir(f.dir()).unwrap().count(), 0);
    }
    #[test]
    fn failed_replacement_preserves_original() {
        let f = Fixture::new();
        f.write();
        let mut changed = f.fence();
        changed.reason = "changed".into();
        assert!(
            write_inner(&f.root, f.owner, &changed, |_, _| Err(io::Error::other(
                "injected"
            )))
            .is_err()
        );
        assert_eq!(f.read().unwrap(), Some(f.fence()));
        assert_eq!(fs::read_dir(f.dir()).unwrap().count(), 1);
    }
    #[test]
    fn a_second_enumeration_of_the_same_directory_sees_every_entry() {
        let f = Fixture::new();
        f.write();
        let dir = directory(&f.root, f.owner, f.uid, false).unwrap().unwrap();
        assert_eq!(names(&dir).unwrap().len(), 1);
        fs::write(f.dir().join("late-entry"), b"").unwrap();
        // The first pass left the shared offset at the end of the directory.
        let again = names(&dir).unwrap();
        assert_eq!(again.len(), 2, "{again:?}");
    }
    #[test]
    fn failed_write_removes_unreadable_temp() {
        let f = Fixture::new();
        let result = write_inner(&f.root, f.owner, &f.fence(), |dir, _| {
            let entries = names(dir).unwrap();
            assert_eq!(entries.len(), 1);
            let filename = entries[0].to_str().unwrap();
            fs::set_permissions(f.dir().join(filename), fs::Permissions::from_mode(0o000))?;
            Err(io::Error::other("injected"))
        });
        assert!(result.is_err());
        assert!(!f.target().exists());
        assert_eq!(fs::read_dir(f.dir()).unwrap().count(), 0);
    }
    #[test]
    fn rejects_file_symlink_and_bad_mode() {
        let f = Fixture::new();
        f.write();
        fs::set_permissions(f.target(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(f.read(), Err(Error::Untrusted)));
        assert!(matches!(
            read_all(&f.root, f.owner, f.uid),
            Err(Error::Untrusted)
        ));
        fs::set_permissions(f.target(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(f.target()).unwrap();
        symlink("missing", f.target()).unwrap();
        assert!(matches!(f.read(), Err(Error::Untrusted)));
        assert!(matches!(
            read_all(&f.root, f.owner, f.uid),
            Err(Error::Untrusted)
        ));
    }
    #[test]
    fn rejects_directory_symlinks_and_wrong_owner() {
        let f = Fixture::new();
        symlink(&f.root, f.root.join("fences")).unwrap();
        assert!(matches!(f.read(), Err(Error::Untrusted)));
        assert!(write(&f.root, f.owner, &f.fence()).is_err());
        fs::remove_file(f.root.join("fences")).unwrap();
        f.write();
        assert!(matches!(
            read(&f.root, f.owner.wrapping_add(1), f.uid, "a-b", 3),
            Err(Error::Untrusted)
        ));
        let dir = directory(&f.root, f.owner, f.uid, false).unwrap().unwrap();
        assert!(matches!(
            read_from(&dir, f.owner.wrapping_add(1), f.uid, "a-b", 3),
            Err(Error::Untrusted)
        ));
    }
    #[test]
    fn rejects_invalid_content_identity_and_size() {
        let f = Fixture::new();
        f.write();
        let mut v = serde_json::to_value(f.fence()).unwrap();
        v["extra"] = true.into();
        f.overwrite(&serde_json::to_vec(&v).unwrap());
        assert!(matches!(f.read(), Err(Error::Invalid)));
        v = serde_json::to_value(f.fence()).unwrap();
        v["uid"] = (f.uid + 1).into();
        f.overwrite(&serde_json::to_vec(&v).unwrap());
        assert!(matches!(f.read(), Err(Error::Invalid)));
        for (key, value) in [
            ("version", serde_json::json!(2)),
            ("profile", serde_json::json!("other")),
            ("generation", serde_json::json!(4)),
        ] {
            let mut v = serde_json::to_value(f.fence()).unwrap();
            v[key] = value;
            f.overwrite(&serde_json::to_vec(&v).unwrap());
            assert!(matches!(f.read(), Err(Error::Invalid)), "{key}");
        }
        f.overwrite(b"not json");
        assert!(matches!(f.read(), Err(Error::Invalid)));
        f.overwrite(&vec![b' '; MAX_BYTES as usize + 1]);
        assert!(matches!(f.read(), Err(Error::Invalid)));
    }
    #[test]
    fn rejects_unknown_nested_fields_bad_names_and_non_regular_files() {
        let f = Fixture::new();
        f.write();
        let mut v = serde_json::to_value(f.fence()).unwrap();
        v["routes"][0]["route"]["unknown"] = true.into();
        f.overwrite(&serde_json::to_vec(&v).unwrap());
        assert!(matches!(f.read(), Err(Error::Invalid)));
        f.write();
        fs::write(f.dir().join("not-a-fence"), b"x").unwrap();
        assert!(matches!(
            read_all(&f.root, f.owner, f.uid),
            Err(Error::Invalid)
        ));
        fs::remove_file(f.dir().join("not-a-fence")).unwrap();
        fs::remove_file(f.target()).unwrap();
        fs::create_dir(f.target()).unwrap();
        assert!(matches!(f.read(), Err(Error::Untrusted)));
    }
}
