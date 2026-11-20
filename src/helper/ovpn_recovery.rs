//! Startup cleanup under the global controller lock.
use crate::{
    connection::{
        fence::{self, Fence, Interface, Kind, ProcessIdentity},
        macos::{fence_recovery::ovpn_network_absent, process::Process},
    },
    helper::{
        controller_lock::ControllerLock,
        paths,
        runtime::{Program, Runtime},
    },
};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const DIRECTORY: i32 = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const EXIT_WAIT: Duration = Duration::from_secs(5);
const KILL_WAIT: Duration = Duration::from_secs(2);

pub(super) fn recover(controller: &ControllerLock, uid: u32) {
    if controller.validate().is_err() {
        warn(c"controller", io::ErrorKind::PermissionDenied.into());
        return;
    }
    let base = paths::ovpn_sessions_directory();
    let result = Sessions::open(controller.directory(), &base, 0);
    let sessions = match result {
        Ok(sessions) => sessions,
        Err(error) => {
            warn(c"open_base", error);
            return;
        }
    };
    sessions.recover_user(uid, process_absent, network_absent, warn);
}

type Failure = (&'static CStr, io::Error);

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn fence_error(error: fence::Error) -> io::Error {
    match error {
        fence::Error::Invalid => invalid(),
        fence::Error::Untrusted => io::ErrorKind::PermissionDenied.into(),
        fence::Error::Io(error) => error,
    }
}

fn warn(stage: &CStr, error: io::Error) {
    let kind = CString::new(format!("{:?}", error.kind())).expect("fixed error-kind names");
    // SAFETY: both arguments match the fixed format and are live NUL-terminated strings.
    unsafe {
        libc::syslog(
            libc::LOG_WARNING,
            c"vpnt: ovpn recovery %s: %s".as_ptr(),
            stage.as_ptr(),
            kind.as_ptr(),
        );
    }
}

fn wait_until(timeout: Duration, mut absent: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
    let expires = Instant::now() + timeout;
    loop {
        if absent()? {
            return Ok(());
        }
        let remaining = expires.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn read_process(pid: u32) -> io::Result<Option<Process>> {
    match Process::read(pid) {
        Ok(current) => Ok(Some(current)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // proc_pidpath can fail for a process whose PID still exists.
            // Signal zero gives an independent absence check.
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                return Err(error);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

fn stop_process(
    expected: &ProcessIdentity,
    mut read: impl FnMut(u32) -> io::Result<Option<Process>>,
    verify_runtime: impl FnOnce() -> io::Result<PathBuf>,
    mut signal: impl FnMut(u32, libc::c_int) -> io::Result<()>,
    mut wait: impl FnMut(Duration, &mut dyn FnMut() -> io::Result<bool>) -> io::Result<()>,
) -> io::Result<()> {
    let mut current = || -> io::Result<bool> {
        let Some(process) = read(expected.pid)? else {
            return Ok(false);
        };
        if !process.running
            || process.identity.pid != expected.pid
            || process.identity.start != (expected.start_sec as u64, expected.start_usec as u64)
            || process.executable != Path::new(&expected.program)
        {
            return Ok(false);
        }
        if process.uid != 0 || process.real_uid != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(true)
    };
    if !current()? {
        return Ok(());
    }
    if verify_runtime()? != Path::new(&expected.program) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    for (sig, timeout) in [(libc::SIGTERM, EXIT_WAIT), (libc::SIGKILL, KILL_WAIT)] {
        if !current()? {
            return Ok(());
        }
        if let Err(error) = signal(expected.pid, sig) {
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(error);
        }
        match wait(timeout, &mut || match current() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            outcome => outcome.map(|running| !running),
        }) {
            Err(error) if sig == libc::SIGTERM && error.kind() == io::ErrorKind::TimedOut => {}
            result => return result,
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}

fn process_absent(expected: &ProcessIdentity) -> io::Result<()> {
    stop_process(
        expected,
        read_process,
        || {
            Runtime::installed()
                .map(|runtime| runtime.program(Program::Openvpn))
                .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))
        },
        |pid, signal| {
            // Recovery relies on XNU's sequential allocation: reusing this PID
            // requires wrapping the PID space between the immediate identity
            // check and kill. The numeric-PID syscall itself is not atomic with
            // the identity check.
            // SAFETY: the journal PID is positive and matched immediately above.
            if unsafe { libc::kill(pid as i32, signal) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        },
        |timeout, absent| wait_until(timeout, absent),
    )
}

fn network_absent(interface: &Interface) -> io::Result<()> {
    wait_until(EXIT_WAIT, || ovpn_network_absent(interface))
}

fn private(file: &File, owner: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o700
        || crate::fs_permissions::check_file(file, true).is_err()
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn open_at(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: name is a single component and the descriptor is live.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transfers ownership of the new descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_base(path: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid());
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(DIRECTORY)
        .open("/")?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        directory = open_at(&directory, &name, DIRECTORY)?;
    }
    Ok(directory)
}

fn unlink(directory: &File, name: &CStr, flags: i32) -> io::Result<()> {
    // SAFETY: name is a single component below a live directory descriptor.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

struct Sessions<'a> {
    state: &'a Path,
    base: &'a Path,
    owner: u32,
    directory: File,
}

impl<'a> Sessions<'a> {
    fn open(state: &'a Path, base: &'a Path, owner: u32) -> io::Result<Self> {
        let directory = open_base(base)?;
        private(&directory, owner)?;
        Ok(Self {
            state,
            base,
            owner,
            directory,
        })
    }

    fn recover_user(
        &self,
        uid: u32,
        mut await_process: impl FnMut(&ProcessIdentity) -> io::Result<()>,
        mut await_network: impl FnMut(&Interface) -> io::Result<()>,
        mut report: impl FnMut(&CStr, io::Error),
    ) {
        // Snapshot references before any directed cleanup, so the sweep
        // also excludes directories whose recovery was attempted this time.
        let referenced = self.referenced_sessions();
        match self.user_fence_entries(uid) {
            Ok(Some(entries)) => {
                // Snapshot the names before removing any entries from this directory.
                for entry in entries.collect::<Vec<_>>() {
                    let record =
                        entry.and_then(|entry| self.read_user_fence(uid, &entry.file_name()));
                    match record {
                        Ok(record) if record.kind == Kind::Ovpn => {
                            if let Err((stage, error)) =
                                self.recover_fence(&record, &mut await_process, &mut await_network)
                            {
                                report(stage, error);
                            }
                        }
                        Ok(_) => {}
                        Err(error) => report(c"read_fence", error),
                    }
                }
            }
            Ok(None) => {}
            Err(error) => report(c"scan_fences", error),
        }
        match referenced {
            Ok(referenced) => {
                if let Err(error) = self.sweep(&referenced, &mut report) {
                    report(c"sweep", error);
                }
            }
            Err(error) => report(c"session_inventory", error),
        }
    }

    fn fence_directory(&self, path: &Path) -> io::Result<Option<File>> {
        match OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY)
            .open(path)
        {
            Ok(directory) => {
                private(&directory, self.owner)?;
                Ok(Some(directory))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn user_fence_entries(&self, uid: u32) -> io::Result<Option<fs::ReadDir>> {
        let path = self.state.join("fences");
        let Some(directory) = self.fence_directory(&path)? else {
            return Ok(None);
        };
        let name = CString::new(uid.to_string()).expect("decimal UID");
        let directory = match open_at(&directory, &name, DIRECTORY) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        private(&directory, self.owner)?;
        fs::read_dir(path.join(uid.to_string())).map(Some)
    }

    fn read_user_fence(&self, uid: u32, name: &std::ffi::OsStr) -> io::Result<Fence> {
        let name = name.to_str().ok_or_else(invalid)?;
        let (profile, generation) = name
            .strip_suffix(".json")
            .and_then(|stem| stem.rsplit_once('-'))
            .ok_or_else(invalid)?;
        let generation = generation.parse::<u64>().map_err(|_| invalid())?;
        if name != format!("{profile}-{generation}.json") {
            return Err(invalid());
        }
        fence::read(self.state, self.owner, uid, profile, generation)
            .map_err(fence_error)?
            .ok_or_else(invalid)
    }

    fn recover_fence(
        &self,
        record: &Fence,
        mut await_process: impl FnMut(&ProcessIdentity) -> io::Result<()>,
        await_network: impl FnOnce(&Interface) -> io::Result<()>,
    ) -> Result<(), Failure> {
        let name =
            Self::checked_session_name(record).map_err(|error| (c"validate_fence", error))?;
        for process in &record.processes {
            await_process(process).map_err(|error| (c"process", error))?;
        }
        if let Some(interface) = &record.interface {
            await_network(interface).map_err(|error| (c"interface", error))?;
        }
        self.remove(name).map_err(|error| (c"session_dir", error))?;
        fence::remove(
            self.state,
            self.owner,
            record.uid,
            &record.profile,
            record.generation,
        )
        .map_err(|error| (c"remove_fence", fence_error(error)))
    }

    fn checked_session_name(record: &Fence) -> io::Result<&str> {
        let name = record
            .session_dir
            .as_deref()
            .and_then(fence::ovpn_session_dir_name)
            .ok_or_else(invalid)?;
        if record.processes.is_empty()
            || record.processes.iter().any(|process| {
                process.pid == 0
                    || i32::try_from(process.pid).is_err()
                    || process.start_sec <= 0
                    || !(0..1_000_000).contains(&process.start_usec)
                    || !Path::new(&process.program).is_absolute()
            })
            || record.sink.is_some()
            || !record.retired.is_empty()
        {
            return Err(invalid());
        }
        if let Some(interface) = &record.interface {
            if !interface
                .name
                .strip_prefix("utun")
                .is_some_and(|unit| unit.parse::<u32>().is_ok())
                || interface.index == 0
                || record
                    .routes
                    .iter()
                    .any(|route| u32::from(route.route.interface) != interface.index)
            {
                return Err(invalid());
            }
        } else if !record.routes.is_empty() {
            return Err(invalid());
        }
        Ok(name)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        if !fence::is_ovpn_session_name(name) {
            return Err(invalid());
        }
        let name = CString::new(name).map_err(|_| invalid())?;
        let directory = match open_at(
            &self.directory,
            &name,
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        ) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        private(&directory, self.owner)?;
        // Session creates only these entries. An unexpected entry prevents
        // rmdir instead of giving recovery authority over another tree.
        for entry in [c"management", c"config", c"openssl.cnf"] {
            unlink(&directory, entry, 0)?;
        }
        unlink(&self.directory, &name, libc::AT_REMOVEDIR)?;
        self.directory.sync_all()
    }

    fn referenced_sessions(&self) -> io::Result<BTreeSet<String>> {
        let path = self.state.join("fences");
        let Some(_directory) = self.fence_directory(&path)? else {
            return Ok(BTreeSet::new());
        };
        let mut names = BTreeSet::new();
        // The base is shared by all UIDs. The controller lock and private
        // root prevent another controller from changing this inventory.
        for user in fs::read_dir(path)? {
            let name = user?.file_name();
            let name = name.to_str().ok_or_else(invalid)?;
            let uid = name
                .parse::<u32>()
                .ok()
                .filter(|uid| *uid != 0 && uid.to_string() == name)
                .ok_or_else(invalid)?;
            for record in fence::read_all(self.state, self.owner, uid).map_err(fence_error)? {
                if record.kind == Kind::Ovpn {
                    // A legacy or invalid record leaves the global inventory incomplete.
                    names.insert(Self::checked_session_name(&record)?.to_owned());
                }
            }
        }
        Ok(names)
    }

    fn sweep(
        &self,
        referenced: &BTreeSet<String>,
        mut report: impl FnMut(&CStr, io::Error),
    ) -> io::Result<()> {
        for entry in fs::read_dir(self.base)? {
            let name = entry?.file_name();
            match name.to_str() {
                Some(name) if referenced.contains(name) => {}
                Some(name) if fence::is_ovpn_session_name(name) => {
                    if let Err(error) = self.remove(name) {
                        report(c"orphan_session_dir", error);
                    }
                }
                _ => report(c"orphan_name", invalid()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
    };

    const PROTECTED: &str = "vpnt-ovpn-234-1a-0";
    const ORPHAN: &str = "vpnt-ovpn-234-1a-1";
    const RUNTIME: &str = "/fixture/runtime/bin/openvpn";

    fn expected_process() -> ProcessIdentity {
        ProcessIdentity {
            pid: 123,
            start_sec: 1,
            start_usec: 2,
            program: RUNTIME.into(),
        }
    }

    fn live_process(pid: u32, start: (u64, u64), program: &str) -> Option<Process> {
        Some(Process {
            identity: crate::connection::macos::process::Identity { pid, start },
            parent: 1,
            uid: 0,
            real_uid: 0,
            running: true,
            executable: program.into(),
        })
    }

    #[test]
    fn active_recovery_never_signals_reused_pid_or_changed_executable() {
        let expected = expected_process();
        for (start, program) in [((1, 3), RUNTIME), ((1, 2), "/fixture/unrelated")] {
            stop_process(
                &expected,
                |pid| Ok(live_process(pid, start, program)),
                || Ok(RUNTIME.into()),
                |_, _| panic!("signaled a different process identity"),
                |_, _| panic!("waited for a different process identity"),
            )
            .unwrap();
        }
    }

    #[test]
    fn active_recovery_requires_the_verified_runtime_executable() {
        let mut expected = expected_process();
        expected.program = "/fixture/other/bin/openvpn".into();
        let error = stop_process(
            &expected,
            |pid| Ok(live_process(pid, (1, 2), &expected.program)),
            || Ok(RUNTIME.into()),
            |_, _| panic!("signaled an executable outside the verified runtime"),
            |_, _| panic!("waited after an unauthorized signal"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn active_recovery_rereads_before_term_and_kill() {
        let expected = expected_process();
        for reused_on_read in [2, 4] {
            let mut reads = 0;
            let mut signals = Vec::new();
            stop_process(
                &expected,
                |pid| {
                    reads += 1;
                    let start = if reads < reused_on_read {
                        (1, 2)
                    } else {
                        (1, 3)
                    };
                    Ok(live_process(pid, start, RUNTIME))
                },
                || Ok(RUNTIME.into()),
                |pid, signal| {
                    signals.push((pid, signal));
                    Ok(())
                },
                |timeout, observe| {
                    assert_eq!(timeout, EXIT_WAIT);
                    assert!(!observe()?);
                    Err(io::ErrorKind::TimedOut.into())
                },
            )
            .unwrap();
            let permitted = [(expected.pid, libc::SIGTERM)];
            assert_eq!(signals, &permitted[..usize::from(reused_on_read == 4)]);
            assert_eq!(reads, reused_on_read);
        }
    }

    #[test]
    fn active_recovery_escalates_only_after_term_deadline_and_requires_exit() {
        let expected = expected_process();
        let mut signals = Vec::new();
        let mut timeouts = Vec::new();
        let result = stop_process(
            &expected,
            |pid| Ok(live_process(pid, (1, 2), RUNTIME)),
            || Ok(RUNTIME.into()),
            |pid, signal| {
                assert_eq!(pid, expected.pid);
                signals.push(signal);
                Ok(())
            },
            |timeout, observe| {
                timeouts.push(timeout);
                assert!(!observe()?);
                Err(io::ErrorKind::TimedOut.into())
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(signals, [libc::SIGTERM, libc::SIGKILL]);
        assert_eq!(timeouts, [EXIT_WAIT, KILL_WAIT]);
    }

    struct Fixture {
        root: PathBuf,
        base: PathBuf,
        owner: u32,
        uid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "vpnt-ovpn-recovery-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            let owner = unsafe { libc::geteuid() };
            let base = root.join("ovpn");
            for path in [&root, &base] {
                fs::DirBuilder::new().mode(0o700).create(path).unwrap();
            }
            Self {
                root,
                base,
                owner,
                uid: owner.max(501),
            }
        }

        fn item(&self, uid: u32) -> Fence {
            Fence {
                version: 1,
                uid,
                profile: "ovpn-fixture".into(),
                generation: 1,
                kind: Kind::Ovpn,
                reason: "fixture".into(),
                written_unix_ms: 1,
                incomplete: true,
                service_id: None,
                dns_key: None,
                session_dir: Some(
                    paths::ovpn_sessions_directory()
                        .join(PROTECTED)
                        .to_str()
                        .unwrap()
                        .into(),
                ),
                processes: vec![ProcessIdentity {
                    pid: 123,
                    start_sec: 1,
                    start_usec: 2,
                    program: "/fixture/openvpn".into(),
                }],
                interface: Some(Interface {
                    name: "utun12".into(),
                    index: 12,
                }),
                sink: None,
                retired: Vec::new(),
                routes: Vec::new(),
            }
        }

        fn save(&self, uid: u32) -> Fence {
            let item = self.item(uid);
            fence::write(&self.root, self.owner, &item).unwrap();
            item
        }

        fn fence_path(&self, uid: u32) -> PathBuf {
            self.root
                .join("fences")
                .join(uid.to_string())
                .join("ovpn-fixture-1.json")
        }

        fn directory(&self, path: &Path) {
            fs::DirBuilder::new().mode(0o700).create(path).unwrap();
            fs::write(path.join("config"), b"fixture").unwrap();
        }

        fn sessions(&self) -> Sessions<'_> {
            Sessions::open(&self.root, &self.base, self.owner).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn recovery_refuses_outside_and_parent_session_dirs_and_keeps_fence() {
        let fixture = Fixture::new();
        let outside = fixture.root.join(PROTECTED);
        fixture.directory(&outside);
        fixture.directory(&fixture.base.join(PROTECTED));
        let item = fixture.save(fixture.uid);
        let sessions = fixture.sessions();
        for path in [
            outside.clone(),
            paths::ovpn_sessions_directory().join("..").join(PROTECTED),
        ] {
            let mut bad = item.clone();
            bad.session_dir = Some(path.to_str().unwrap().to_owned());
            let fence_path = fixture.fence_path(fixture.uid);
            let contents = serde_json::to_vec(&bad).unwrap();
            fs::write(&fence_path, &contents).unwrap();
            assert!(matches!(
                fence::read(&fixture.root, fixture.owner, fixture.uid, &item.profile, 1),
                Err(fence::Error::Invalid)
            ));
            let error = sessions
                .recover_fence(
                    &bad,
                    |_| panic!("observed process"),
                    |_| panic!("observed network"),
                )
                .unwrap_err();
            assert_eq!(error.0, c"validate_fence");
            assert!(sessions.referenced_sessions().is_err());
            assert_eq!(fs::read(fence_path).unwrap(), contents);
            assert_eq!(fs::read(outside.join("config")).unwrap(), b"fixture");
            assert_eq!(
                fs::read(fixture.base.join(PROTECTED).join("config")).unwrap(),
                b"fixture"
            );
        }
    }

    #[test]
    fn recovery_refuses_session_symlink_to_outside_and_keeps_fence() {
        let fixture = Fixture::new();
        let outside = fixture.root.join(PROTECTED);
        fixture.directory(&outside);
        let link = fixture.base.join(PROTECTED);
        symlink(&outside, &link).unwrap();
        let item = fixture.save(fixture.uid);
        let sessions = fixture.sessions();
        let failure = sessions
            .recover_fence(&item, |_| Ok(()), |_| Ok(()))
            .unwrap_err();
        assert_eq!(failure.0, c"session_dir");
        sessions
            .sweep(&sessions.referenced_sessions().unwrap(), |_, _| {
                panic!("fenced name reached sweep")
            })
            .unwrap();
        assert_eq!(fs::read_link(link).unwrap(), outside);
        assert_eq!(fs::read(outside.join("config")).unwrap(), b"fixture");
        assert!(fixture.fence_path(fixture.uid).exists());
    }

    #[test]
    fn recovery_requires_process_and_network_absence_before_removal() {
        let fixture = Fixture::new();
        let directory = fixture.base.join(PROTECTED);
        fixture.directory(&directory);
        let item = fixture.save(fixture.uid);
        let sessions = fixture.sessions();
        let uncertain = || Err(io::ErrorKind::TimedOut.into());
        let failure = sessions
            .recover_fence(
                &item,
                |_| uncertain(),
                |_| panic!("observed network before process exit"),
            )
            .unwrap_err();
        assert_eq!(failure.0, c"process");
        assert!(directory.join("config").exists());
        assert!(fixture.fence_path(fixture.uid).exists());
        let failure = sessions
            .recover_fence(&item, |_| Ok(()), |_| uncertain())
            .unwrap_err();
        assert_eq!(failure.0, c"interface");
        assert!(directory.join("config").exists());
        assert!(fixture.fence_path(fixture.uid).exists());
        sessions
            .recover_fence(&item, |_| Ok(()), |_| Ok(()))
            .unwrap();
        assert!(!directory.exists());
        assert!(!fixture.fence_path(fixture.uid).exists());
    }

    #[test]
    fn sweep_preserves_other_users_fences_and_refuses_untrusted_directories() {
        let fixture = Fixture::new();
        fixture.save(fixture.uid + 1);
        let referenced = fixture.base.join(PROTECTED);
        let orphan = fixture.base.join(ORPHAN);
        let wide = fixture.base.join("vpnt-ovpn-234-1a-2");
        let unexpected = fixture.base.join("unexpected");
        for dir in [&referenced, &orphan, &wide, &unexpected] {
            fixture.directory(dir);
        }
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o755)).unwrap();
        let mut warnings = Vec::new();
        let sessions = fixture.sessions();
        sessions
            .sweep(&sessions.referenced_sessions().unwrap(), |stage, error| {
                warnings.push((stage.to_owned(), error.kind()))
            })
            .unwrap();
        assert!(!orphan.exists());
        assert!(referenced.join("config").exists());
        assert!(wide.join("config").exists());
        assert!(unexpected.join("config").exists());
        assert!(warnings.contains(&(
            c"orphan_session_dir".to_owned(),
            io::ErrorKind::PermissionDenied
        )));
        assert!(warnings.contains(&(c"orphan_name".to_owned(), io::ErrorKind::InvalidData)));
    }

    #[test]
    fn recovery_does_not_follow_symlink_in_base_ancestor() {
        let fixture = Fixture::new();
        let alias = fixture.root.join("alias");
        symlink(&fixture.root, &alias).unwrap();
        assert!(Sessions::open(&fixture.root, &alias.join("ovpn"), fixture.owner).is_err());
    }

    #[test]
    fn sweep_preserves_duplicate_references_without_suspending_other_cleanup() {
        let fixture = Fixture::new();
        fixture.save(fixture.uid);
        fixture.save(fixture.uid + 1);
        fixture.directory(&fixture.base.join(PROTECTED));
        let orphan = fixture.base.join(ORPHAN);
        fixture.directory(&orphan);
        let sessions = fixture.sessions();
        let referenced = sessions.referenced_sessions().unwrap();
        sessions
            .sweep(&referenced, |stage, error| panic!("{stage:?}: {error}"))
            .unwrap();
        assert!(fixture.base.join(PROTECTED).join("config").exists());
        assert!(!orphan.exists());
    }
    #[test]
    fn startup_recovers_valid_fence_and_suspends_sweep_on_incomplete_inventory() {
        for invalid_other in [false, true] {
            let fixture = Fixture::new();
            let valid = fixture.save(fixture.uid);
            let legacy = Fence {
                profile: "legacy".into(),
                session_dir: None,
                ..valid
            };
            fence::write(&fixture.root, fixture.owner, &legacy).unwrap();
            if invalid_other {
                let other_uid = fixture.uid + 1;
                fixture.save(other_uid);
                fs::write(fixture.fence_path(other_uid), b"{").unwrap();
            }
            let active = fixture.base.join(PROTECTED);
            let orphan = fixture.base.join(ORPHAN);
            fixture.directory(&active);
            fixture.directory(&orphan);
            let mut warnings = Vec::new();
            fixture.sessions().recover_user(
                fixture.uid,
                |_| Ok(()),
                |_| Ok(()),
                |stage, error| warnings.push((stage.to_owned(), error.kind())),
            );
            assert!(
                !fixture.fence_path(fixture.uid).exists(),
                "valid fence remains"
            );
            assert!(!active.exists());
            assert!(
                orphan.join("config").exists(),
                "incomplete sweep deleted an orphan"
            );
            assert_eq!(
                fence::read(&fixture.root, fixture.owner, fixture.uid, "legacy", 1).unwrap(),
                Some(legacy)
            );
            if invalid_other {
                assert_eq!(fs::read(fixture.fence_path(fixture.uid + 1)).unwrap(), b"{");
            }
            assert!(warnings.contains(&(c"validate_fence".to_owned(), io::ErrorKind::InvalidData)));
        }
    }

    #[test]
    fn startup_recovers_when_only_another_users_fence_is_invalid() {
        let fixture = Fixture::new();
        fixture.save(fixture.uid);
        fixture.save(fixture.uid + 1);
        fs::write(fixture.fence_path(fixture.uid + 1), b"{").unwrap();
        fixture.directory(&fixture.base.join(PROTECTED));
        fixture
            .sessions()
            .recover_user(fixture.uid, |_| Ok(()), |_| Ok(()), |_, _| {});
        assert!(!fixture.fence_path(fixture.uid).exists());
    }

    #[test]
    fn startup_recovers_past_an_unexpected_current_user_fence_filename() {
        let fixture = Fixture::new();
        fixture.save(fixture.uid);
        let unknown = fixture.fence_path(fixture.uid).with_file_name("unexpected");
        fs::write(&unknown, b"{").unwrap();
        fixture.directory(&fixture.base.join(PROTECTED));
        let orphan = fixture.base.join(ORPHAN);
        fixture.directory(&orphan);
        fixture
            .sessions()
            .recover_user(fixture.uid, |_| Ok(()), |_| Ok(()), |_, _| {});
        assert!(!fixture.fence_path(fixture.uid).exists());
        assert_eq!(fs::read(unknown).unwrap(), b"{");
        assert!(orphan.join("config").exists());
    }

    #[test]
    fn startup_recovers_reused_utun_name_only_after_recorded_index_routes_disappear() {
        use crate::connection::{
            macos::{
                fence_recovery::ovpn_network_absent_with,
                routing::{Record, Snapshot},
                vip::ovpn_link::fixture_interfaces,
            },
            routes::Key,
        };

        let fixture = Fixture::new();
        let item = fixture.save(fixture.uid);
        let directory = fixture.base.join(PROTECTED);
        fixture.directory(&directory);
        let sessions = fixture.sessions();
        let observe = |interface: &Interface, name, index, route_index| {
            let absent = ovpn_network_absent_with(
                interface,
                || Ok(fixture_interfaces(&[(name, index)])),
                || {
                    Ok(Snapshot {
                        records: vec![Record {
                            key: Key {
                                network: "192.0.2.0/24".parse().unwrap(),
                                scope: 0,
                            },
                            interface: route_index,
                            flags: 0,
                            gateway: None,
                            source: None,
                        }],
                    })
                },
            )?;
            if absent {
                Ok(())
            } else {
                Err(io::ErrorKind::WouldBlock.into())
            }
        };
        for (name, index, route_index) in
            [("utun12", 12, 44), ("utun12", 44, 12), ("utun44", 12, 12)]
        {
            let error = sessions
                .recover_fence(
                    &item,
                    |_| Ok(()),
                    |interface| observe(interface, name, index, route_index),
                )
                .unwrap_err();
            assert_eq!(error.0, c"interface");
            assert!(fixture.fence_path(fixture.uid).exists());
            assert!(directory.join("config").exists());
        }
        sessions.recover_user(
            fixture.uid,
            |_| Ok(()),
            |interface| observe(interface, "utun12", 44, 44),
            |stage, error| panic!("{stage:?}: {error}"),
        );
        assert!(!directory.exists());
        assert!(!fixture.fence_path(fixture.uid).exists());
        assert!(observe(item.interface.as_ref().unwrap(), "utun44", 12, 44).is_ok());
    }
}
