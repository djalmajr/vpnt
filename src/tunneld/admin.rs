//! Descriptor-anchored policy storage and the standalone administrative command.
use super::policy::{Entry, Key, MAX_POLICY, MAX_SNAPSHOT, Policy};
use std::{
    ffi::{CStr, CString, OsString, c_int},
    fs::{File, OpenOptions, Permissions},
    io::{self, BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const POLICY_PATH: &str = "/etc/vpnt/tunnel-policy.json";
const DIRECTORY_FLAGS: c_int = libc::O_DIRECTORY | libc::O_NOFOLLOW;
const POLICY_FLAGS: c_int = libc::O_NOFOLLOW | libc::O_NONBLOCK;

#[derive(Clone)]
pub(super) struct PolicyStore {
    root: PathBuf,
    owner: u32,
    group: u32,
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            owner: 0,
            group: 0,
        }
    }
}

pub(super) struct Directory {
    parent: File,
    owner: u32,
    group: u32,
}

pub(super) struct Snapshot {
    policy: Policy,
    source: Option<Source>,
}

struct Source {
    file: File,
    bytes: Vec<u8>,
}

impl Snapshot {
    pub(super) fn policy(&self) -> &Policy {
        &self.policy
    }

    pub(super) fn unchanged(&self, other: &Self) -> io::Result<bool> {
        match (&self.source, &other.source) {
            (None, None) => Ok(true),
            (Some(left), Some(right)) => {
                Ok(left.bytes == right.bytes && same_file(&left.file, &right.file)?)
            }
            _ => Ok(false),
        }
    }
}

fn names() -> impl DoubleEndedIterator<Item = CString> {
    POLICY_PATH
        .trim_start_matches('/')
        .split('/')
        .map(|name| CString::new(name).expect("static path component"))
}

impl PolicyStore {
    #[cfg(test)]
    pub(super) fn unavailable_for_test() -> Self {
        Self {
            root: PathBuf::from("/dev/null"),
            ..Self::default()
        }
    }

    pub(super) fn open(&self) -> io::Result<Directory> {
        let mut parent = OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY_FLAGS)
            .open(&self.root)?;
        check_parent(&parent, self.owner)?;
        let mut components = names();
        let _filename = components.next_back().expect("policy filename");
        for name in components {
            parent = open_at(&parent, &name, libc::O_RDONLY | DIRECTORY_FLAGS, 0)?;
            check_parent(&parent, self.owner)?;
        }
        Ok(Directory {
            parent,
            owner: self.owner,
            group: self.group,
        })
    }
}

fn check_parent(file: &File, owner: u32) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "insecure policy directory",
        ));
    }
    Ok(())
}

fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok((left.dev(), left.ino()) == (right.dev(), right.ino()))
}

fn open_at(parent: &File, name: &CStr, flags: c_int, mode: libc::mode_t) -> io::Result<File> {
    // SAFETY: the descriptor and the single-component C string are valid.
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
    // SAFETY: openat returned a new descriptor owned by this call.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl Directory {
    pub(super) fn lock_shared(&self) -> io::Result<()> {
        self.lock(libc::LOCK_SH | libc::LOCK_NB)
    }

    fn lock(&self, operation: c_int) -> io::Result<()> {
        // The protected parent directory is the stable lock inode. Each
        // operation opens it independently and holds it through its decision.
        // SAFETY: this File owns a valid descriptor for the lifetime of the lock.
        if unsafe { libc::flock(self.parent.as_raw_fd(), operation) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn read(&self) -> io::Result<Snapshot> {
        let name = names().last().expect("policy filename");
        let file = match open_at(&self.parent, &name, libc::O_RDONLY | POLICY_FLAGS, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Snapshot {
                    policy: Policy::default(),
                    source: None,
                });
            }
            Err(error) => return Err(error),
        };
        self.check_policy_file(&file)?;
        let bytes = read_limited(&file, MAX_POLICY)?;
        let policy = Policy::from_disk(&bytes)?;
        Ok(Snapshot {
            policy,
            source: Some(Source { file, bytes }),
        })
    }

    fn check_policy_file(&self, file: &File) -> io::Result<()> {
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.gid() != self.group
            || meta.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "insecure policy file",
            ));
        }
        Ok(())
    }

    fn replace(&self, bytes: &[u8]) -> io::Result<()> {
        let name = names().last().expect("policy filename");
        let (mut temp, mut file) = Temporary::create(&self.parent)?;
        if file.metadata()?.gid() != self.group {
            // SAFETY: the open descriptor owns the newly created regular file.
            if unsafe { libc::fchown(file.as_raw_fd(), self.owner, self.group) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        file.set_permissions(Permissions::from_mode(0o600))?;
        self.check_policy_file(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // SAFETY: both names are anchored to the same owned directory descriptor.
        if unsafe {
            libc::renameat(
                self.parent.as_raw_fd(),
                temp.name.as_ptr(),
                self.parent.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        temp.renamed = true;
        if let Err(error) = self.parent.sync_all() {
            let observation = match self.read() {
                Ok(snapshot)
                    if snapshot
                        .source
                        .as_ref()
                        .is_some_and(|source| source.bytes == bytes) =>
                {
                    "the approved bytes are visible; durability is uncertain".to_owned()
                }
                Ok(_) => "the observed policy differs; durability is uncertain".to_owned(),
                Err(read_error) => format!(
                    "cannot read the resulting policy ({read_error}); durability is uncertain"
                ),
            };
            return Err(io::Error::other(format!(
                "directory sync failed ({error}); {observation}"
            )));
        }
        Ok(())
    }
}

struct Temporary<'a> {
    parent: &'a File,
    name: CString,
    renamed: bool,
}

impl<'a> Temporary<'a> {
    fn create(parent: &'a File) -> io::Result<(Self, File)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let name = CString::new(format!(
                ".tunnel-policy.{}.{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ))
            .expect("temporary filename");
            match open_at(
                parent,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                0o600,
            ) {
                Ok(file) => {
                    return Ok((
                        Self {
                            parent,
                            name,
                            renamed: false,
                        },
                        file,
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.renamed {
            // SAFETY: the temporary name was opened exclusively in this directory.
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
                eprintln!(
                    "vpnt-tunneld: could not remove policy temporary: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
}

fn read_limited(input: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "policy exceeds byte limit",
        ));
    }
    Ok(bytes)
}

enum Change {
    Apply(Entry),
    Revoke(Key),
}

impl Change {
    fn key(&self) -> Key {
        match self {
            Self::Apply(entry) => entry.key(),
            Self::Revoke(key) => key.clone(),
        }
    }
}

fn parse_change(args: &[OsString], input: impl Read) -> io::Result<Change> {
    match args {
        [apply] if apply == "apply" => Ok(Change::Apply(Policy::snapshot(&read_limited(
            input,
            MAX_SNAPSHOT,
        )?)?)),
        [revoke, uid, backend, hostname, port] if revoke == "revoke" => {
            let arg = |value: &OsString| value.clone().into_string().map_err(|_| usage());
            Ok(Change::Revoke(Key::from_args(
                &arg(uid)?,
                &arg(backend)?,
                &arg(hostname)?,
                &arg(port)?,
            )?))
        }
        _ => Err(usage()),
    }
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: vpnt-tunneld policy apply | policy revoke <uid> <backend> <hostname> <port>",
    )
}

fn update(
    store: &PolicyStore,
    change: Change,
    confirm: impl FnOnce(&Key, bool, &[u8]) -> io::Result<bool>,
) -> io::Result<()> {
    let directory = store.open()?;
    let previous = directory.read()?;
    let mut next = previous.policy.clone();
    let key = change.key();
    let revoke = matches!(change, Change::Revoke(_));
    match change {
        Change::Apply(entry) => next.apply(entry)?,
        Change::Revoke(key) => next.revoke(&key)?,
    }
    let bytes = next.bytes()?;
    if !confirm(&key, revoke, &bytes)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "policy change not confirmed",
        ));
    }

    let current = store.open()?;
    current.lock(libc::LOCK_EX)?;
    if !same_file(&directory.parent, &current.parent)? || !previous.unchanged(&current.read()?)? {
        return Err(io::Error::other(
            "policy changed while awaiting confirmation",
        ));
    }
    current.replace(&bytes)
}

fn confirm_tty(tty: &mut File, key: &Key, revoke: bool, bytes: &[u8]) -> io::Result<bool> {
    let action = if revoke { "Revoke" } else { "Apply" };
    writeln!(tty, "{action} policy for {key}")?;
    tty.write_all(bytes)?;
    // SAFETY: tty is the open controlling terminal. Discard input queued
    // before the full policy was shown.
    if unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) } != 0 {
        return Err(io::Error::last_os_error());
    }
    write!(tty, "Type yes to confirm: ")?;
    tty.flush()?;
    let mut answer = Vec::new();
    BufReader::new(tty.take(4)).read_until(b'\n', &mut answer)?;
    Ok(answer == b"yes\n")
}

/// Run the policy subcommand with a fixed destination and a controlling TTY.
pub fn run(args: &[OsString]) -> i32 {
    let result = (|| {
        // SAFETY: geteuid has no arguments or preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "policy administration requires root",
            ));
        }
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/tty")?;
        let change = parse_change(args, io::stdin().lock())?;
        update(&PolicyStore::default(), change, |key, revoke, bytes| {
            confirm_tty(&mut tty, key, revoke, bytes)
        })
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("vpnt-tunneld: {error}");
            1
        }
    }
}

#[cfg(test)]
pub(super) const IPSEC_SNAPSHOT: &[u8] = br#"{
  "version":1,"entries":[{
    "backend":"ipsec","uid":1000,"hostname":"vpn.example",
    "peer_identity":"fqdn:vpn.example","transport_ipv4":["192.0.2.22","192.0.2.20"],
    "port":500,"route_cidrs":["10.20.0.0/15","172.16.0.0/12"],"dns_domains":[],"dns_servers":[]
  }]
}"#;

#[cfg(test)]
pub(super) struct PolicyFixture {
    pub(super) store: PolicyStore,
}

#[cfg(test)]
impl PolicyFixture {
    pub(super) fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let root = loop {
            let root = base.join(format!(
                "vpnt-tunneld-policy-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => break root,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("fixture directory: {error}"),
            }
        };
        let meta = std::fs::metadata(&root).unwrap();
        let fixture = Self {
            store: PolicyStore {
                root,
                owner: meta.uid(),
                group: meta.gid(),
            },
        };
        std::fs::create_dir_all(fixture.path().parent().unwrap()).unwrap();
        fixture
    }

    pub(super) fn path(&self) -> PathBuf {
        self.store.root.join(POLICY_PATH.trim_start_matches('/'))
    }

    pub(super) fn install(&self) {
        update(
            &self.store,
            Change::Apply(Policy::snapshot(IPSEC_SNAPSHOT).unwrap()),
            |_, _, _| Ok(true),
        )
        .unwrap();
    }

    pub(super) fn revoke(&self) {
        let key = Key::from_args("1000", "ipsec", "vpn.example", "500").unwrap();
        update(&self.store, Change::Revoke(key), |_, _, _| Ok(true)).unwrap();
    }
}

#[cfg(test)]
impl Drop for PolicyFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.store.root).expect("remove private policy fixture");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    fn apply() -> Change {
        parse_change(&["apply".into()], IPSEC_SNAPSHOT).unwrap()
    }

    #[test]
    fn apply_requires_confirmation_and_writes_exactly_the_displayed_bytes() {
        let fixture = PolicyFixture::new();
        let no_tty = update(&fixture.store, apply(), |_, _, _| {
            Err(io::Error::from_raw_os_error(libc::ENXIO))
        });
        assert_eq!(no_tty.unwrap_err().raw_os_error(), Some(libc::ENXIO));
        assert!(!fixture.path().exists());
        assert_eq!(
            update(&fixture.store, apply(), |_, _, _| Ok(false))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!fixture.path().exists());

        let mut displayed = Vec::new();
        update(&fixture.store, apply(), |key, revoke, bytes| {
            assert_eq!(key.to_string(), "1000 ipsec vpn.example 500");
            assert!(!revoke);
            assert!(!fixture.path().exists());
            displayed.extend_from_slice(bytes);
            Ok(true)
        })
        .unwrap();
        let path = fixture.path();
        assert_eq!(fs::read(&path).unwrap(), displayed);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        let before = File::open(&path).unwrap();
        let args = ["revoke", "1000", "ipsec", "vpn.example", "500"].map(OsString::from);
        let change = parse_change(&args, io::empty()).unwrap();
        update(&fixture.store, change, |key, revoke, bytes| {
            assert_eq!(key.to_string(), "1000 ipsec vpn.example 500");
            assert!(revoke);
            assert_eq!(bytes, b"{\"version\":1,\"entries\":[]}\n");
            Ok(true)
        })
        .unwrap();
        assert_eq!(read_limited(&before, MAX_POLICY).unwrap(), displayed);
        assert!(!same_file(&before, &File::open(&path).unwrap()).unwrap());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"{\"version\":1,\"entries\":[]}\n"
        );
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn terminal_confirmation_shows_policy_and_requires_the_exact_answer() {
        for (answer, expected) in [(b"no\n".as_slice(), false), (b"yes\n", true)] {
            let (mut master_fd, mut slave_fd) = (-1, -1);
            // SAFETY: both output pointers are writable; optional tty parameters are absent.
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master_fd,
                        &mut slave_fd,
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                },
                0,
                "{}",
                io::Error::last_os_error()
            );
            // SAFETY: openpty returned two new descriptors.
            let (master, mut slave) =
                unsafe { (File::from_raw_fd(master_fd), File::from_raw_fd(slave_fd)) };
            let key = Key::from_args("1000", "ipsec", "vpn.example", "500").unwrap();
            let bytes = super::super::policy::canonical_snapshot(IPSEC_SNAPSHOT).unwrap();
            std::thread::scope(|scope| {
                let mut master = master;
                let confirmation = scope.spawn(|| confirm_tty(&mut slave, &key, false, &bytes));
                let mut output = Vec::new();
                while !output.ends_with(b"Type yes to confirm: ") {
                    let mut ready = libc::pollfd {
                        fd: master.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: ready is a writable single pollfd.
                    assert_eq!(unsafe { libc::poll(&mut ready, 1, 2000) }, 1);
                    let mut chunk = [0; 512];
                    let count = master.read(&mut chunk).unwrap();
                    assert_ne!(count, 0);
                    output.extend_from_slice(&chunk[..count]);
                }
                let output = String::from_utf8(output).unwrap().replace("\r\n", "\n");
                assert_eq!(
                    output.as_bytes(),
                    [
                        b"Apply policy for 1000 ipsec vpn.example 500\n".as_slice(),
                        &bytes,
                        b"Type yes to confirm: ",
                    ]
                    .concat()
                );
                master.write_all(answer).unwrap();
                assert_eq!(confirmation.join().unwrap().unwrap(), expected);
            });
        }
    }

    #[test]
    fn concurrent_confirmed_change_is_detected_even_for_identical_bytes() {
        let fixture = PolicyFixture::new();
        fixture.install();
        let mut intervening = None;
        let result = update(&fixture.store, apply(), |_, _, _| {
            fixture.install();
            intervening = Some(File::open(fixture.path()).unwrap());
            Ok(true)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "policy changed while awaiting confirmation"
        );
        assert!(same_file(&intervening.unwrap(), &File::open(fixture.path()).unwrap()).unwrap());
    }

    #[test]
    fn readers_and_admin_lock_the_same_directory_inode() {
        let fixture = PolicyFixture::new();
        let reader = fixture.store.open().unwrap();
        let admin = fixture.store.open().unwrap();
        reader.lock_shared().unwrap();
        assert_eq!(
            admin
                .lock(libc::LOCK_EX | libc::LOCK_NB)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock,
        );
        drop(reader);
        admin.lock(libc::LOCK_EX | libc::LOCK_NB).unwrap();
        let reader = fixture.store.open().unwrap();
        assert_eq!(
            reader.lock_shared().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(admin);
        reader.lock_shared().unwrap();
    }

    #[test]
    fn rejects_unprotected_directories_and_policy_files() {
        let fixture = PolicyFixture::new();
        let path = fixture.path();
        let parent = path.parent().unwrap();
        let etc = parent.parent().unwrap();
        let original_parent = etc.join("real-vpnt");
        fs::rename(parent, &original_parent).unwrap();
        symlink(&original_parent, parent).unwrap();
        assert!(fixture.store.open().is_err());
        fs::remove_file(parent).unwrap();
        fs::rename(original_parent, parent).unwrap();

        fs::set_permissions(etc, Permissions::from_mode(0o770)).unwrap();
        assert!(fixture.store.open().is_err());
        fs::set_permissions(etc, Permissions::from_mode(0o700)).unwrap();
        let mut wrong_owner = fixture.store.clone();
        wrong_owner.owner ^= 1;
        assert!(wrong_owner.open().is_err());

        fixture.install();
        let mut wrong_group = fixture.store.clone();
        wrong_group.group ^= 1;
        assert!(wrong_group.open().unwrap().read().is_err());
        fs::set_permissions(&path, Permissions::from_mode(0o620)).unwrap();
        assert!(fixture.store.open().unwrap().read().is_err());
        let moved = parent.join("grant");
        fs::rename(&path, &moved).unwrap();
        fs::set_permissions(&moved, Permissions::from_mode(0o600)).unwrap();
        symlink(&moved, &path).unwrap();
        assert!(fixture.store.open().unwrap().read().is_err());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(fixture.store.open().unwrap().read().is_err());
    }
}
