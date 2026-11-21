//! Single-generation authentication for the Linux backend control channel.

use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::mem::{MaybeUninit, size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::ptr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, de};

pub use super::protocol::Backend;

const VERSION: u32 = 1;
pub(super) const PHASE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAME: usize = 4096;
const SCM_PIDFD: libc::c_int = 4;
const PID_FS_MAGIC: libc::c_long = 0x5049_4446;

#[derive(Clone, Copy)]
struct Credentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl Credentials {
    fn root(gid: libc::gid_t) -> Self {
        Self { uid: 0, gid }
    }

    fn check(self, actual: libc::ucred) -> io::Result<()> {
        if self.uid != actual.uid || self.gid != actual.gid {
            return Err(denied("unexpected peer credentials"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Attempt<'a> {
    generation: &'a str,
    backend: Backend,
}

impl Attempt<'_> {
    fn validate(self) -> io::Result<()> {
        check_hex(self.generation, 32)
    }

    fn unit_name(self) -> String {
        let backend = match self.backend {
            Backend::Ipsec => "ipsec",
            Backend::Fortinet => "fortinet",
        };
        format!("vpnt-tunneld-{backend}@{}.service", self.generation)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(remote = "Backend", rename_all = "snake_case")]
enum BackendWire {
    Ipsec,
    Fortinet,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Pidfs {
    dev: u64,
    ino: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    boot_id: String,
    generation: String,
    #[serde(with = "BackendWire")]
    backend: Backend,
    #[serde(deserialize_with = "named_object")]
    writer_pidfs: Pidfs,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    InstanceHello {
        version: u32,
        generation: String,
        #[serde(with = "BackendWire")]
        backend: Backend,
        challenge_i: String,
    },
    WriterChallenge {
        challenge_i: String,
        challenge_w: String,
    },
    InstanceConfirm {
        challenge_i: String,
        challenge_w: String,
        version: u32,
        generation: String,
        #[serde(with = "BackendWire")]
        backend: Backend,
        invocation: String,
    },
    WriterConfirm {},
}

// Like the public protocol, require named fields before dispatching to Serde's
// derived visitor, which rejects duplicate and unknown fields.
fn named_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct NamedObject<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for NamedObject<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object with named fields")
        }

        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(NamedObject(std::marker::PhantomData))
}

fn decode_object<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> io::Result<T> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let decoded = named_object(&mut decoder)?;
    decoder.end()?;
    Ok(decoded)
}

fn decode_frame(bytes: &[u8]) -> io::Result<Frame> {
    decode_object(bytes)
}

fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn check_hex(value: &str, len: usize) -> io::Result<()> {
    if value.len() != len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid("noncanonical handshake identifier"));
    }
    Ok(())
}

fn challenge() -> io::Result<String> {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 32];
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: the remaining slice is writable for the supplied length.
        let result = unsafe {
            libc::getrandom(
                bytes[filled..].as_mut_ptr().cast(),
                bytes.len() - filled,
                libc::GRND_NONBLOCK,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += result as usize;
    }

    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}

fn syscall_result(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Only call this with the return value of a syscall that transfers an FD
// on success.
fn new_fd(raw: RawFd) -> io::Result<OwnedFd> {
    syscall_result(raw)?;
    // SAFETY: the successful syscall just transferred ownership.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn stat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut result = MaybeUninit::uninit();
    // SAFETY: fstat initializes the pointed-to result on success.
    unsafe {
        syscall_result(libc::fstat(fd.as_raw_fd(), result.as_mut_ptr()))?;
        Ok(result.assume_init())
    }
}

fn pidfs(fd: BorrowedFd<'_>) -> io::Result<Pidfs> {
    if !cfg!(target_pointer_width = "64") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "requires 64-bit pidfs",
        ));
    }
    let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes the pointed-to result on success.
    let kind = unsafe {
        syscall_result(libc::fstatfs(fd.as_raw_fd(), filesystem.as_mut_ptr()))?;
        filesystem.assume_init().f_type
    };
    if kind != PID_FS_MAGIC {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "requires pidfs"));
    }
    let metadata = stat(fd)?;
    Ok(Pidfs {
        dev: metadata.st_dev as _,
        ino: metadata.st_ino as _,
    })
}

fn live(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut entry = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll can read and update the one supplied pollfd.
    let ready = unsafe { libc::poll(&mut entry, 1, 0) };
    syscall_result(ready)?;
    if ready != 0 {
        return Err(denied("peer pidfd is no longer live"));
    }
    Ok(())
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn wait_ready(fd: BorrowedFd<'_>, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let duration = remaining(deadline)?;
        let millis = duration.as_nanos().div_ceil(1_000_000);
        let mut entry = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: poll can read and update the one supplied pollfd.
        let result = unsafe { libc::poll(&mut entry, 1, millis.min(i32::MAX as u128) as i32) };
        if result > 0 {
            remaining(deadline)?;
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn retry_io(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn path_cstring(path: &OsStr) -> io::Result<CString> {
    CString::new(path.as_bytes()).map_err(|_| invalid("NUL in handshake path"))
}

fn basename(name: &OsStr) -> io::Result<CString> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(part)) if part == name)
        || components.next().is_some()
    {
        return Err(invalid("handshake artifact name must be a basename"));
    }
    path_cstring(name)
}

fn address(path: &Path) -> io::Result<libc::sockaddr_un> {
    let path = path_cstring(path.as_os_str())?;
    // SAFETY: zero is valid for every field of sockaddr_un.
    let mut addr: libc::sockaddr_un = unsafe { zeroed() };
    let bytes = path.as_bytes_with_nul();
    if bytes.len() <= 1 || bytes.len() > addr.sun_path.len() {
        return Err(invalid("invalid Unix socket path length"));
    }
    addr.sun_family = libc::AF_UNIX as _;
    for (dest, &source) in addr.sun_path.iter_mut().zip(bytes) {
        *dest = source as _;
    }
    Ok(addr)
}

fn socket() -> io::Result<OwnedFd> {
    // SAFETY: socket takes integer options and returns a new FD.
    let fd = new_fd(unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    })?;
    for option in [libc::SO_PASSCRED, libc::SO_PASSPIDFD] {
        let enabled: libc::c_int = 1;
        // SAFETY: setsockopt reads the supplied integer.
        unsafe {
            syscall_result(libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                ptr::from_ref(&enabled).cast(),
                size_of::<libc::c_int>() as _,
            ))?;
        }
    }
    Ok(fd)
}

fn boot_id() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim_end()
        .to_owned())
}

fn check_mode(
    fd: BorrowedFd<'_>,
    uid: libc::uid_t,
    kind: libc::mode_t,
    mode: libc::mode_t,
) -> io::Result<()> {
    let metadata = stat(fd)?;
    if metadata.st_uid != uid || metadata.st_mode & (libc::S_IFMT | 0o7777) != kind | mode {
        return Err(denied("unexpected handshake artifact owner, type or mode"));
    }
    Ok(())
}

/// `struct open_how` of openat2(2); the `libc` one is non-exhaustive.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_record(path: &Path, owner: libc::uid_t) -> io::Result<Record> {
    let path = path_cstring(path.as_os_str())?;
    // RESOLVE_NO_SYMLINKS refuses a link in any component, ancestors included;
    // O_NOFOLLOW only covers the last one. A kernel without openat2 returns
    // ENOSYS, and the read fails closed instead of falling back to open.
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: openat2 reads a NUL-terminated path and an open_how of the
    // stated size, and returns a new FD.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            ptr::from_ref(&how),
            size_of::<OpenHow>(),
        )
    };
    let fd = new_fd(RawFd::try_from(raw).map_err(|_| invalid("invalid openat2 result"))?)?;
    check_mode(fd.as_fd(), owner, libc::S_IFREG, 0o600)?;
    let mut data = Vec::new();
    File::from(fd)
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > MAX_FRAME {
        return Err(invalid("oversized writer record"));
    }
    decode_object(&data)
}

fn peer_credential(fd: BorrowedFd<'_>) -> io::Result<libc::ucred> {
    let mut value = MaybeUninit::<libc::ucred>::uninit();
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output buffer is as large as length.
    unsafe {
        syscall_result(libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            value.as_mut_ptr().cast(),
            &mut length,
        ))?;
        if length != size_of::<libc::ucred>() as libc::socklen_t {
            return Err(invalid("invalid SO_PEERCRED length"));
        }
        Ok(value.assume_init())
    }
}

struct Peer {
    fd: OwnedFd,
    identity: Pidfs,
    expected: Credentials,
}

impl Peer {
    fn new(socket: BorrowedFd<'_>, expected: Credentials) -> io::Result<Self> {
        expected.check(peer_credential(socket)?)?;
        let mut raw: RawFd = -1;
        let mut length = size_of::<RawFd>() as libc::socklen_t;
        // SAFETY: getsockopt writes a RawFd and transfers it on success.
        unsafe {
            syscall_result(libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                ptr::from_mut(&mut raw).cast(),
                &mut length,
            ))?;
        }
        let fd = new_fd(raw)?;
        if length != size_of::<RawFd>() as libc::socklen_t {
            return Err(invalid("invalid SO_PEERPIDFD length"));
        }
        let identity = pidfs(fd.as_fd())?;
        live(fd.as_fd())?;
        Ok(Self {
            fd,
            identity,
            expected,
        })
    }

    fn check_sender(&self, credentials: libc::ucred, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.expected.check(credentials)?;
        if pidfs(fd)? != self.identity {
            return Err(denied("frame pidfd differs from connected peer"));
        }
        live(fd)
    }
}

/// Manager-provided identity for the process represented by the supplied pidfd.
pub struct UnitIdentity {
    pub name: String,
    pub invocation: String,
    pub main_pid: libc::pid_t,
}

/// Resolve the exact process through the trusted host manager.
///
/// The handshake passes its absolute phase deadline and rechecks it after
/// attestation. External manager calls must finish within that budget.
pub trait UnitAttestor {
    fn attest(&self, pidfd: BorrowedFd<'_>) -> io::Result<UnitIdentity>;

    fn attest_until(&self, pidfd: BorrowedFd<'_>, _deadline: Instant) -> io::Result<UnitIdentity> {
        self.attest(pidfd)
    }
}

/// One-use listener with an already published generation record.
pub struct Writer {
    listener: OwnedFd,
    directory: OwnedFd,
    socket_name: CString,
    generation: String,
    backend: Backend,
    expected: Credentials,
    timeout: Duration,
}

impl Writer {
    /// Publish in the writer's trusted, root-owned 0700 state directory.
    /// The generation is the record basename, so changing socket names
    /// cannot reuse a generation in this directory. The caller mounts both
    /// artifacts privately into the supervisor. The record survives the listener.
    pub fn publish(
        directory: &Path,
        socket_name: &OsStr,
        generation: &str,
        backend: Backend,
        instance_gid: libc::gid_t,
    ) -> io::Result<Self> {
        Self::publish_as(
            directory,
            socket_name,
            Attempt {
                generation,
                backend,
            },
            Credentials::root(instance_gid),
            PHASE_TIMEOUT,
        )
    }

    fn publish_as(
        directory: &Path,
        socket_name: &OsStr,
        attempt: Attempt<'_>,
        expected: Credentials,
        timeout: Duration,
    ) -> io::Result<Self> {
        attempt.validate()?;
        let directory_name = path_cstring(directory.as_os_str())?;
        let socket_name = basename(socket_name)?;
        let record_name = path_cstring(OsStr::new(attempt.generation))?;
        if socket_name == record_name {
            return Err(invalid("socket and record must have distinct names"));
        }
        // SAFETY: open reads a NUL-terminated path and returns a new FD.
        let directory = new_fd(unsafe {
            libc::open(
                directory_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        check_mode(directory.as_fd(), expected.uid, libc::S_IFDIR, 0o700)?;

        // Bind relative to the verified directory descriptor. Unix sockets
        // lack bindat, so use the procfs descriptor path.
        let path = format!("/proc/self/fd/{}/", directory.as_raw_fd());
        let addr = address(&Path::new(&path).join(OsStr::from_bytes(socket_name.as_bytes())))?;
        let listener = socket()?;
        // SAFETY: pidfd_open takes a PID and flags and returns a CLOEXEC FD.
        let own_fd =
            new_fd(unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as RawFd)?;
        let record = Record {
            boot_id: boot_id()?,
            generation: attempt.generation.to_owned(),
            backend: attempt.backend,
            writer_pidfs: pidfs(own_fd.as_fd())?,
        };
        let encoded = serde_json::to_vec(&record)?;
        // SAFETY: openat uses the verified directory FD and NUL-terminated basename.
        let record_fd = new_fd(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                record_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::mode_t,
            )
        })?;
        // SAFETY: set the exact mode regardless of the process's umask.
        unsafe { syscall_result(libc::fchmod(record_fd.as_raw_fd(), 0o600))? };
        check_mode(record_fd.as_fd(), expected.uid, libc::S_IFREG, 0o600)?;
        File::from(record_fd).write_all(&encoded)?;

        // SAFETY: bind reads the initialized Unix socket address.
        unsafe {
            syscall_result(libc::bind(
                listener.as_raw_fd(),
                ptr::from_ref(&addr).cast(),
                size_of::<libc::sockaddr_un>() as _,
            ))?;
        }
        let writer = Self {
            listener,
            directory,
            socket_name,
            generation: record.generation,
            backend: attempt.backend,
            expected,
            timeout,
        };
        // SAFETY: the descriptor is a bound socket.
        unsafe { syscall_result(libc::listen(writer.listener.as_raw_fd(), 1))? };
        Ok(writer)
    }

    /// Accept one connection and consume the listener on success or failure.
    pub fn authenticate(self, attestor: &impl UnitAttestor) -> io::Result<AuthenticatedChannel> {
        let deadline = Instant::now() + self.timeout;
        let socket = loop {
            wait_ready(self.listener.as_fd(), libc::POLLIN, deadline)?;
            // SAFETY: no peer address requested and accept4 transfers a new FD.
            let accepted = new_fd(unsafe {
                libc::accept4(
                    self.listener.as_raw_fd(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            });
            match accepted {
                Err(ref error) if retry_io(error) => continue,
                result => break result?,
            }
        };
        let peer = Peer::new(socket.as_fd(), self.expected)?;
        let transport = Transport { socket, peer };
        let attempt = Attempt {
            generation: &self.generation,
            backend: self.backend,
        };
        let (frame, sender) = transport.read_frame(deadline)?;
        let Frame::InstanceHello {
            version,
            generation,
            backend,
            challenge_i,
        } = frame
        else {
            return Err(invalid("expected instance_hello"));
        };
        check_attempt(attempt, version, &generation, backend)?;
        check_hex(&challenge_i, 64)?;

        let deadline = Instant::now() + self.timeout;
        let challenge_w = challenge()?;
        transport.write_frame(
            &Frame::WriterChallenge {
                challenge_i: challenge_i.clone(),
                challenge_w: challenge_w.clone(),
            },
            deadline,
        )?;

        let deadline = Instant::now() + self.timeout;
        let (frame, confirmed_sender) = transport.read_frame(deadline)?;
        let Frame::InstanceConfirm {
            challenge_i: echoed_i,
            challenge_w: echoed_w,
            version,
            generation,
            backend,
            invocation,
        } = frame
        else {
            return Err(invalid("expected instance_confirm"));
        };
        check_attempt(attempt, version, &generation, backend)?;
        check_hex(&invocation, 32)?;
        if echoed_i != challenge_i || echoed_w != challenge_w {
            return Err(denied("instance confirmation challenge mismatch"));
        }

        remaining(deadline)?;
        live(transport.peer.fd.as_fd())?;
        let unit = attestor.attest_until(transport.peer.fd.as_fd(), deadline)?;
        remaining(deadline)?;
        live(transport.peer.fd.as_fd())?;
        if unit.name != attempt.unit_name()
            || unit.invocation != invocation
            || sender <= 0
            || sender != confirmed_sender
            || unit.main_pid != sender
        {
            return Err(denied("unit attestation does not match the instance"));
        }

        transport.write_frame(&Frame::WriterConfirm {}, Instant::now() + self.timeout)?;
        Ok(AuthenticatedChannel {
            transport: Some(transport),
            invocation,
        })
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // SAFETY: socket_name names our socket within the writer-owned directory.
        unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.socket_name.as_ptr(), 0) };
    }
}

fn check_attempt(
    attempt: Attempt<'_>,
    version: u32,
    generation: &str,
    backend: Backend,
) -> io::Result<()> {
    if version != VERSION || generation != attempt.generation || backend != attempt.backend {
        return Err(denied("handshake version, generation or backend mismatch"));
    }
    Ok(())
}

/// Connect from the supervisor using its own invocation ID and private mounts.
/// Run in the supervisor itself, before it starts any backend children.
pub fn connect_instance(
    socket_path: &Path,
    record_path: &Path,
    generation: &str,
    backend: Backend,
    invocation: &str,
    writer_gid: libc::gid_t,
) -> io::Result<AuthenticatedChannel> {
    protect_supervisor()?;
    connect_as(
        socket_path,
        record_path,
        Attempt {
            generation,
            backend,
        },
        invocation,
        Credentials::root(writer_gid),
        PHASE_TIMEOUT,
    )
}

fn protect_supervisor() -> io::Result<()> {
    // SAFETY: prctl takes integer flags. Set this before opening the channel
    // so other processes with the same UID cannot inspect the supervisor.
    unsafe { syscall_result(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0)) }
}

fn connect_as(
    socket_path: &Path,
    record_path: &Path,
    attempt: Attempt<'_>,
    invocation: &str,
    expected: Credentials,
    timeout: Duration,
) -> io::Result<AuthenticatedChannel> {
    attempt.validate()?;
    check_hex(invocation, 32)?;
    let record = open_record(record_path, expected.uid)?;
    check_attempt(attempt, VERSION, &record.generation, record.backend)?;
    if boot_id()? != record.boot_id {
        return Err(denied("writer record belongs to a different boot"));
    }

    let deadline = Instant::now() + timeout;
    let addr = address(socket_path)?;
    let socket = socket()?;
    // SAFETY: connect reads the initialized Unix socket address. A full Unix
    // listen queue is an error on this one-use channel.
    unsafe {
        syscall_result(libc::connect(
            socket.as_raw_fd(),
            ptr::from_ref(&addr).cast(),
            size_of::<libc::sockaddr_un>() as _,
        ))?;
    }
    let peer = Peer::new(socket.as_fd(), expected)?;
    if peer.identity != record.writer_pidfs {
        return Err(denied("connected writer does not match its pidfs record"));
    }
    let transport = Transport { socket, peer };
    let challenge_i = challenge()?;
    transport.write_frame(
        &Frame::InstanceHello {
            version: VERSION,
            generation: attempt.generation.to_owned(),
            backend: attempt.backend,
            challenge_i: challenge_i.clone(),
        },
        deadline,
    )?;

    let (frame, _) = transport.read_frame(Instant::now() + timeout)?;
    let Frame::WriterChallenge {
        challenge_i: echoed_i,
        challenge_w,
    } = frame
    else {
        return Err(invalid("expected writer_challenge"));
    };
    check_hex(&challenge_w, 64)?;
    if echoed_i != challenge_i {
        return Err(denied(
            "writer challenge does not echo the instance challenge",
        ));
    }

    transport.write_frame(
        &Frame::InstanceConfirm {
            challenge_i,
            challenge_w,
            version: VERSION,
            generation: attempt.generation.to_owned(),
            backend: attempt.backend,
            invocation: invocation.to_owned(),
        },
        Instant::now() + timeout,
    )?;

    let (frame, _) = transport.read_frame(Instant::now() + timeout)?;
    if !matches!(frame, Frame::WriterConfirm {}) {
        return Err(invalid("expected writer_confirm"));
    }
    Ok(AuthenticatedChannel {
        transport: Some(transport),
        invocation: invocation.to_owned(),
    })
}

/// An established channel keeps the connected socket and the peer's pidfd.
/// The socket stays private so callers cannot bypass per-datagram checks.
pub struct AuthenticatedChannel {
    transport: Option<Transport>,
    invocation: String,
}

impl AuthenticatedChannel {
    pub fn invocation(&self) -> &str {
        &self.invocation
    }

    /// Receive one application datagram from the authenticated peer. An error
    /// closes the channel. Application message schemas are checked by callers.
    pub fn receive(&mut self) -> io::Result<Vec<u8>> {
        let transport = self.transport.take().ok_or(io::ErrorKind::NotConnected)?;
        let (bytes, _) = transport.receive(Instant::now() + PHASE_TIMEOUT)?;
        self.transport = Some(transport);
        Ok(bytes)
    }

    /// Send one application datagram to the authenticated peer. An error
    /// closes the channel.
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let transport = self.transport.take().ok_or(io::ErrorKind::NotConnected)?;
        transport.send(bytes, Instant::now() + PHASE_TIMEOUT)?;
        self.transport = Some(transport);
        Ok(())
    }
}

struct Transport {
    socket: OwnedFd,
    peer: Peer,
}

impl Transport {
    fn send(&self, bytes: &[u8], deadline: Instant) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME {
            return Err(invalid("invalid handshake datagram length"));
        }
        loop {
            wait_ready(self.socket.as_fd(), libc::POLLOUT, deadline)?;
            live(self.peer.fd.as_fd())?;
            // SAFETY: bytes is readable for its reported length.
            let count = unsafe {
                libc::send(
                    self.socket.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if count >= 0 {
                if count as usize != bytes.len() {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if !retry_io(&error) {
                return Err(error);
            }
        }
    }

    fn receive(&self, deadline: Instant) -> io::Result<(Vec<u8>, libc::pid_t)> {
        let mut bytes = vec![0; MAX_FRAME];
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        loop {
            wait_ready(self.socket.as_fd(), libc::POLLIN, deadline)?;
            // Word alignment satisfies cmsghdr. Linux closes any SCM_RIGHTS
            // descriptors that do not fit in the ancillary buffer.
            let mut control = [0_usize; 16];
            // SAFETY: zero is valid for every member of msghdr.
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of::<[usize; 16]>();
            // SAFETY: the message points to writable data and control buffers.
            let count = unsafe {
                libc::recvmsg(
                    self.socket.as_raw_fd(),
                    &mut message,
                    libc::MSG_CMSG_CLOEXEC,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if retry_io(&error) {
                    continue;
                }
                return Err(error);
            }

            // Parse even on truncation so Rust owns every delivered FD.
            let ancillary = collect_ancillary(&message);
            if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                return Err(invalid("truncated handshake datagram"));
            }
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let (credentials, pidfd) = ancillary?;
            self.peer.check_sender(credentials, pidfd.as_fd())?;
            remaining(deadline)?;
            bytes.truncate(count as usize);
            return Ok((bytes, credentials.pid));
        }
    }

    fn write_frame(&self, frame: &Frame, deadline: Instant) -> io::Result<()> {
        self.send(&serde_json::to_vec(frame)?, deadline)
    }

    fn read_frame(&self, deadline: Instant) -> io::Result<(Frame, libc::pid_t)> {
        let (bytes, sender) = self.receive(deadline)?;
        let frame = decode_frame(&bytes)?;
        remaining(deadline)?;
        Ok((frame, sender))
    }
}

fn collect_ancillary(message: &libc::msghdr) -> io::Result<(libc::ucred, OwnedFd)> {
    let mut credentials = None;
    let mut pidfd = None;
    let mut invalid_control = false;
    // SAFETY: the message came from a successful recvmsg and its control
    // buffer lives for the walk. Its ancillary headers are written by Linux.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        let content_offset = libc::CMSG_LEN(0) as usize;
        while !header.is_null() {
            let data = libc::CMSG_DATA(header);
            let length = (*header).cmsg_len - content_offset;
            match ((*header).cmsg_level, (*header).cmsg_type) {
                (libc::SOL_SOCKET, libc::SCM_CREDENTIALS)
                    if length == size_of::<libc::ucred>() && credentials.is_none() =>
                {
                    credentials = Some(data.cast::<libc::ucred>().read_unaligned());
                }
                (libc::SOL_SOCKET, SCM_PIDFD | libc::SCM_RIGHTS) => {
                    let is_pidfd = (*header).cmsg_type == SCM_PIDFD;
                    for index in 0..length / size_of::<RawFd>() {
                        let raw = data.cast::<RawFd>().add(index).read_unaligned();
                        let Ok(received) = new_fd(raw) else {
                            invalid_control = true;
                            continue;
                        };
                        if is_pidfd && length == size_of::<RawFd>() && pidfd.is_none() {
                            pidfd = Some(received);
                        } else {
                            invalid_control = true;
                        }
                    }
                    invalid_control |= !is_pidfd || length != size_of::<RawFd>();
                }
                _ => invalid_control = true,
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    match (credentials, pidfd) {
        (Some(credentials), Some(pidfd)) if !invalid_control => Ok((credentials, pidfd)),
        _ => Err(invalid("expected exactly one kernel credential and pidfd")),
    }
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
