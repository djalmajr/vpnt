//! Private, generation-scoped cleanup receipts for the v2 control protocol.
use super::protocol::{CleanupState, Generation};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

const RETENTION_SECONDS: u64 = 5 * 60;
const MAX_RECORDS: usize = 256;
const MAX_BYTES: u64 = 4096;

#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Namespace {
    boot: String,
    netns: (u64, u64),
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Prepared,
    Pending,
    Stopped { at: u64 },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    generation: Generation,
    uid: u32,
    namespace: Namespace,
    phase: Phase,
}

pub(super) struct Store {
    directory: PathBuf,
    namespace: Namespace,
    owner: u32,
    access: Mutex<()>,
    clock: fn() -> io::Result<u64>,
}

pub(super) struct Reservation<'a> {
    store: &'a Store,
    generation: Generation,
    uid: u32,
    armed: bool,
}

fn now() -> io::Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the timespec is writable and CLOCK_BOOTTIME takes no other inputs.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut timestamp) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(timestamp.tv_sec).map_err(|_| io::ErrorKind::InvalidData.into())
}

fn fresh(at: u64, now: u64) -> bool {
    now.checked_sub(at)
        .is_some_and(|age| age < RETENTION_SECONDS)
}

impl Store {
    pub(super) fn open(runtime: &Path) -> io::Result<Self> {
        // SAFETY: geteuid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        let parent = fs::symlink_metadata(runtime)?;
        if !parent.is_dir() || parent.uid() != owner || parent.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let directory = runtime.join("tunneld-cleanup");
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => File::open(runtime)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let meta = fs::symlink_metadata(&directory)?;
        if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o7777 != 0o700 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let netns = fs::metadata("/proc/self/ns/net")?;
        Ok(Self {
            directory,
            namespace: Namespace {
                boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                    .trim()
                    .to_owned(),
                netns: (netns.dev(), netns.ino()),
            },
            owner,
            access: Mutex::new(()),
            clock: now,
        })
    }

    fn read(&self, generation: &Generation) -> io::Result<Receipt> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join(generation.as_str()))?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != self.owner || meta.mode() & 0o7777 != 0o600 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        if receipt.generation != *generation
            || receipt.namespace != self.namespace
            || receipt.uid == 0
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(receipt)
    }

    fn save(&self, receipt: &Receipt) -> io::Result<()> {
        let temp = self.directory.join(".tmp");
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(receipt)?)?;
        file.sync_all()?;
        fs::rename(temp, self.directory.join(receipt.generation.as_str()))?;
        File::open(&self.directory)?.sync_all()
    }

    fn entries(&self) -> io::Result<Vec<Option<Generation>>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let name = entry?.file_name();
            if name == ".tmp" {
                continue;
            }
            if entries.len() == MAX_RECORDS {
                return Err(io::ErrorKind::StorageFull.into());
            }
            entries.push(name.into_string().ok().and_then(Generation::parse));
        }
        Ok(entries)
    }

    pub(super) fn reserve(&self, uid: u32) -> io::Result<Reservation<'_>> {
        let _access = self.access.lock().expect("cleanup receipt store");
        let time = (self.clock)()?;
        let mut used = 0;
        for entry in self.entries()? {
            if let Some(generation) = entry
                && let Ok(receipt) = self.read(&generation)
                && let Phase::Stopped { at } = receipt.phase
                && time
                    .checked_sub(at)
                    .is_some_and(|age| age >= RETENTION_SECONDS)
            {
                fs::remove_file(self.directory.join(generation.as_str()))?;
                continue;
            }
            used += 1;
        }
        if used >= MAX_RECORDS {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let generation = Generation::parse(super::backend::generation()?)
            .expect("kernel-generated generation is valid");
        match fs::symlink_metadata(self.directory.join(generation.as_str())) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            Err(error) => return Err(error),
        }
        self.save(&Receipt {
            generation: generation.clone(),
            uid,
            namespace: Namespace {
                boot: self.namespace.boot.clone(),
                netns: self.namespace.netns,
            },
            phase: Phase::Prepared,
        })?;
        Ok(Reservation {
            store: self,
            generation,
            uid,
            armed: false,
        })
    }

    pub(super) fn status(&self, uid: u32, generation: &Generation) -> CleanupState {
        // Atomic replacement lets readers observe either complete receipt without
        // waiting for fsync, a network lock, or a backend teardown.
        match self.read(generation) {
            Ok(receipt) if receipt.uid == uid => match receipt.phase {
                Phase::Prepared | Phase::Pending => CleanupState::Pending,
                Phase::Stopped { at } if (self.clock)().is_ok_and(|now| fresh(at, now)) => {
                    CleanupState::Stopped
                }
                Phase::Stopped { .. } => CleanupState::Unknown,
            },
            _ => CleanupState::Unknown,
        }
    }

    fn change(&self, generation: &Generation, uid: Option<u32>, phase: Phase) -> io::Result<()> {
        let _access = self.access.lock().expect("cleanup receipt store");
        let mut receipt = self.read(generation)?;
        if uid.is_some_and(|uid| uid != receipt.uid) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if matches!(receipt.phase, Phase::Stopped { .. }) {
            // Never refresh a terminal record or reopen it for effects.
            return if matches!(phase, Phase::Stopped { .. }) {
                Ok(())
            } else {
                Err(io::ErrorKind::InvalidData.into())
            };
        }
        receipt.phase = phase;
        self.save(&receipt)
    }

    pub(super) fn recovered(&self, generation: &str) -> io::Result<()> {
        let generation =
            Generation::parse(generation.to_owned()).expect("validated receipt directory");
        match self.change(
            &generation,
            None,
            Phase::Stopped {
                at: (self.clock)()?,
            },
        ) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                Ok(())
            }
            result => result,
        }
    }

    /// Called only when startup recovery has the network lock and has proved
    /// there are no outstanding leases. A launch persists its network receipt
    /// before creating a lease or contacting an instance unit.
    pub(super) fn recovered_without_leases(&self) -> io::Result<()> {
        for generation in self.entries()?.into_iter().flatten() {
            self.recovered(generation.as_str())?;
        }
        Ok(())
    }
}

impl Reservation<'_> {
    pub(super) fn generation(&self) -> &Generation {
        &self.generation
    }

    pub(super) fn arm(&mut self) -> io::Result<()> {
        self.store
            .change(&self.generation, Some(self.uid), Phase::Pending)?;
        self.armed = true;
        Ok(())
    }

    pub(super) fn stopped(&self) -> io::Result<()> {
        self.store.change(
            &self.generation,
            Some(self.uid),
            Phase::Stopped {
                at: (self.store.clock)()?,
            },
        )
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.armed
            && let Err(error) = self.stopped()
        {
            eprintln!("vpnt-tunneld: could not record unused preparation: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "vpnt-cleanup-{}",
                super::super::backend::generation().unwrap()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> Store {
            let mut store = Store::open(&self.0).unwrap();
            store.clock = || Ok(600);
            store
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove this fixture's private root");
        }
    }

    #[test]
    fn cleanup_proof_requires_current_owner_boot_namespace_and_a_valid_record() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let record = store.reserve(1000).unwrap();
        let id = record.generation().clone();
        assert_eq!(store.status(1000, &id), CleanupState::Pending);
        assert_eq!(store.status(1001, &id), CleanupState::Unknown);
        drop(record);
        assert_eq!(store.status(1000, &id), CleanupState::Stopped);
        assert_eq!(store.status(1001, &id), CleanupState::Unknown);

        let mut wrong = fixture.store();
        wrong.namespace.boot.push_str("-other");
        assert_eq!(wrong.status(1000, &id), CleanupState::Unknown);
        wrong.namespace.boot.clone_from(&store.namespace.boot);
        wrong.namespace.netns.1 ^= 1;
        assert_eq!(wrong.status(1000, &id), CleanupState::Unknown);

        let path = store.directory.join(id.as_str());
        let valid: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut malformed = valid.clone();
        malformed["phase"]["stopped"]["extra"] = true.into();
        fs::write(&path, serde_json::to_vec(&malformed).unwrap()).unwrap();
        assert_eq!(store.status(1000, &id), CleanupState::Unknown);
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(store.status(1000, &id), CleanupState::Stopped);
        fs::remove_file(path).unwrap();
        assert_eq!(store.status(1000, &id), CleanupState::Unknown);
    }

    #[test]
    fn pressure_reclaims_only_expired_terminal_records_and_retains_pending() {
        let fixture = Fixture::new();
        let store = fixture.store();
        for index in 0..MAX_RECORDS {
            store
                .save(&Receipt {
                    generation: Generation::parse(format!("{index:032x}")).unwrap(),
                    uid: 1000,
                    namespace: Namespace {
                        boot: store.namespace.boot.clone(),
                        netns: store.namespace.netns,
                    },
                    phase: if index == 0 {
                        Phase::Pending
                    } else {
                        Phase::Stopped { at: 301 }
                    },
                })
                .unwrap();
        }
        let pending = Generation::parse(format!("{:032x}", 0)).unwrap();
        let terminal = Generation::parse(format!("{:032x}", 1)).unwrap();
        assert_eq!(store.status(1000, &terminal), CleanupState::Stopped);
        assert!(matches!(store.reserve(1000), Err(e) if e.kind() == io::ErrorKind::StorageFull));
        let mut expired = store.read(&terminal).unwrap();
        expired.phase = Phase::Stopped { at: 300 };
        store.save(&expired).unwrap();
        assert_eq!(store.status(1000, &terminal), CleanupState::Unknown);
        assert!(store.reserve(1000).is_ok());
        assert!(!store.directory.join(terminal.as_str()).exists());
        assert_eq!(store.status(1000, &pending), CleanupState::Pending);
    }
}
