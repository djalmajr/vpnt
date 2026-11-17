use super::*;
use socket::Transport;
use std::{
    fs, mem,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            net::UnixDatagram,
        },
    },
    path::{Path, PathBuf},
};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Same predicate the controller lock applies, checked here only to explain a
/// refused temp path instead of surfacing a bare `UntrustedPath`.
fn private_directory(path: &Path, owner: u32, leaf: bool) -> Result<(), String> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| format!("{}: {error}", ancestor.display()))?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0
            || (leaf
                && ancestor == path
                && (metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700))
        {
            return Err(format!(
                "{} is mode {:o} owned by uid {}",
                ancestor.display(),
                metadata.mode() & 0o7777,
                metadata.uid()
            ));
        }
    }
    Ok(())
}

/// Resolve the user temp directory so the fixture does not depend on the
/// checkout path, and fail with the reason when that directory is not private.
fn gate_parent(owner: u32) -> PathBuf {
    let parent = fs::canonicalize(std::env::temp_dir())
        .unwrap_or_else(|error| panic!("protected temp directory must resolve: {error}"));
    private_directory(&parent, owner, false).unwrap_or_else(|reason| {
        panic!(
            "controller-lock gate needs a private temp directory, but {reason}; \
             point TMPDIR at a directory owned by this user whose ancestors are not \
             group/other writable"
        )
    });
    parent
}

// Mutations: bypass native UID admission or wrap/reuse a request nonce.
#[test]
fn ordinary_uid_cannot_admit_a_reader_and_nonces_never_wrap_or_repeat() {
    // SAFETY: UID read only, without elevation or changes to the process.
    let uid = unsafe { libc::getuid() };
    assert_ne!(uid, 0, "run as an ordinary user");
    let directory =
        gate_parent(uid).join(format!(".vpnt-pfkey-reader-gate-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let root = Root(directory);
    private_directory(&root.0, uid, true)
        .unwrap_or_else(|reason| panic!("gate fixture directory refused: {reason}"));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.0.join(".controller.lock"))
        .unwrap();
    let controller = ControllerLock::fixture(&root.0, uid).unwrap();
    assert!(matches!(
        Reader::new(&controller),
        Err(Error::PermissionDenied)
    ));
    let reader = Reader {
        controller: &controller,
        pid: std::process::id(),
    };
    assert_eq!(
        reader.collect(
            Kind::Sad,
            Instant::now() + Duration::from_secs(1),
            Arc::new(AtomicBool::new(false))
        ),
        Err(Error::PermissionDenied)
    );
    let counter = AtomicU32::new(1);
    assert_eq!(next_sequence(&counter), Ok(1));
    assert_eq!(next_sequence(&counter), Ok(2));
    let counter = AtomicU32::new(u32::MAX - 1);
    assert_eq!(next_sequence(&counter), Ok(u32::MAX - 1));
    assert_eq!(next_sequence(&counter), Err(Error::Exhausted));
    assert_eq!(next_sequence(&counter), Err(Error::Exhausted));
    assert_eq!(next_sequence(&AtomicU32::new(0)), Err(Error::Exhausted));
}

// Mutations: permit a userspace origin, overlook address lengths, admit
// truncated recvmsg payloads, or leave descriptors inheritable/blocking.
#[test]
fn native_recvmsg_rejects_truncation_and_userspace_sources_with_private_descriptor_flags() {
    let (channel, remote) = UnixDatagram::pair().unwrap();
    let fd = channel.as_raw_fd();
    socket::configure(fd).unwrap();
    // SAFETY: live owned socket; fcntl only reads flags.
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    // SAFETY: same live socket and flag query.
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
        0
    );
    remote.send(&[7u8; 64]).unwrap();
    assert!(matches!(
        socket::receive(fd, &mut [0u8; 16], &budget()),
        Err(Error::Invalid)
    ));
    remote.send(&[7u8; 16]).unwrap();
    let kernel = socket::Kernel { fd: channel.into() };
    assert_eq!(
        kernel.receive(&mut [0u8; 16], &budget()),
        Err(Error::Changed)
    );

    // SDK-independent exact AF_KEY address shape; real PF_KEY is never opened.
    // SAFETY: all-zero sockaddr_storage is a valid initialized C value.
    let source = unsafe { mem::zeroed() };
    let mut r = socket::Received {
        length: 16,
        source,
        source_length: 2,
    };
    r.source.ss_len = 2;
    r.source.ss_family = libc::PF_KEY as _;
    assert!(r.kernel_source());
    r.source_length = 3;
    assert!(!r.kernel_source());
    r.source_length = 2;
    r.source.ss_len = 3;
    assert!(!r.kernel_source());
    r.source.ss_len = 2;
    r.source.ss_family = libc::AF_UNIX as _;
    assert!(!r.kernel_source());
}
