use super::{
    Error,
    bound::budget::{self, Budget},
    config,
    files::{Directory, Stamp, Unstarted},
    record::{self, Birth, Record, Stage},
};
use crate::connection::ipsec::{Config, Reservation};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    fs,
    num::NonZeroU16,
    os::unix::fs::{FileTypeExt, MetadataExt},
    sync::{Arc, Mutex},
};
pub(super) const CONFIG: &str = "strongswan.conf";
const CLAIM: &str = "claim.json";
const MAX: u64 = 8192;
mod lease;

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) struct Store {
    pub root: Directory,
    io: Mutex<()>,
    /// Test-only one-shot hook: set a caller's cancel flag after the record
    /// scan and immediately before the first durable create.
    #[cfg(test)]
    pub(super) before_create: Mutex<Option<Arc<AtomicBool>>>,
}
impl Store {
    pub fn open(parent: &std::path::Path, owner: u32) -> Result<Arc<Self>, Error> {
        let path = parent.join("ipsec");
        let root = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let dir = Directory::create(path, owner)?;
                fs::File::open(parent)
                    .and_then(|d| d.sync_all())
                    .map_err(|_| Error::Unavailable)?;
                dir
            }
            Ok(_) => Directory::open(path, owner)?,
            Err(_) => return Err(Error::Unavailable),
        };
        Ok(Arc::new(Self {
            root,
            io: Mutex::new(()),
            #[cfg(test)]
            before_create: Mutex::new(None),
        }))
    }
    #[cfg(test)]
    pub(super) fn cancel_before_create(&self, cancel: Arc<AtomicBool>) {
        *self.before_create.lock().expect("before_create hook") = Some(cancel);
    }

    #[cfg(test)]
    pub(super) fn io_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.io.lock().expect("io lock")
    }

    /// Intentionally unbudgeted: Observer callers (`unrepresented`, `stopped`,
    /// `completed`) have no caller deadline in their public contract; do not
    /// invent a global deadline. Active open/observe/take paths use the
    /// bounded [`Lease`] entrypoints instead.
    pub fn records(&self) -> Result<Vec<Record>, Error> {
        let _lock = self.io.lock().map_err(|_| Error::Unavailable)?;
        self.records_unlocked()
    }
    fn records_unlocked(&self) -> Result<Vec<Record>, Error> {
        self.root
            .inventory()?
            .into_iter()
            .map(|name| {
                if !record::hex(&name, 32) {
                    return Err(Error::Changed);
                }
                let dir = Directory::open(self.root.path.join(&name), self.root.owner)?;
                let (bytes, _) = dir.read(CLAIM, MAX)?;
                let record: Record = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
                record.valid()?;
                if record.session != name {
                    return Err(Error::Changed);
                }
                let (conf, _) = dir.read(CONFIG, MAX)?;
                if digest(&conf) != record.configuration_hash {
                    return Err(Error::Changed);
                }
                inventory(&dir)?;
                Ok(record)
            })
            .collect()
    }
    pub fn prepare(
        self: &Arc<Self>,
        reservation: &Reservation,
        config: &Config,
        controller: Birth,
        runtime_hash: String,
        transport_interface: Option<NonZeroU16>,
        budget: Option<&Budget>,
    ) -> Result<Lease, Error> {
        let _lock = budget::lock(budget, &self.io)?;
        budget::check(budget)?;
        let records = self.records_unlocked()?;
        budget::check(budget)?;
        if records.iter().any(|r| {
            r.reqid == reservation.reqid()
                || (r.uid == reservation.owner().uid && r.profile == reservation.owner().profile)
        }) {
            return Err(Error::Busy);
        }
        if records.len() >= 64 {
            return Err(Error::Exhausted);
        }
        // Deterministic test seam: cancel/expire between the record scan and
        // the first durable write. Production never arms this hook.
        #[cfg(test)]
        if let Some(cancel) = self
            .before_create
            .lock()
            .map_err(|_| Error::Unavailable)?
            .take()
        {
            cancel.store(true, Ordering::Release);
        }
        let mut selected = None;
        for _ in 0..16 {
            let mut random = [0u8; 16];
            // SAFETY: getentropy receives a writable 16-byte buffer, below its 256-byte limit.
            if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
                return Err(Error::Unavailable);
            }
            let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
            // Never start the first durable write after a known cancel/expiry.
            budget::check(budget)?;
            match Directory::create(self.root.path.join(&id), self.root.owner) {
                Ok(dir) => {
                    selected = Some((id, dir));
                    break;
                }
                Err(Error::Busy) => {}
                Err(e) => return Err(e),
            }
        }
        let (session, dir) = selected.ok_or(Error::Exhausted)?;
        let mut unstarted = Unstarted(Some(dir));
        let dir = unstarted.0.as_ref().unwrap();
        budget::check(budget)?;
        let conf = match transport_interface {
            Some(index) => config::render_bound(&dir.path, index)?,
            None => config::render(&dir.path)?,
        };
        let owner = reservation.owner();
        let record = Record {
            version: 1,
            session,
            uid: owner.uid,
            profile: owner.profile.clone(),
            generation: owner.generation,
            reqid: reservation.reqid(),
            connection: config.name().into(),
            local: config.local,
            remote: config.remote,
            networks: config.networks.clone(),
            controller,
            runtime_hash,
            configuration_hash: digest(conf.as_bytes()),
            transport_interface,
            stage: Stage::Prepared,
            child: None,
        };
        record.valid()?;
        budget::check(budget)?;
        let config_stamp = dir.write_new(CONFIG, conf.as_bytes())?;
        budget::check(budget)?;
        let record_stamp = dir.write_new(
            CLAIM,
            &serde_json::to_vec(&record).map_err(|_| Error::Invalid)?,
        )?;
        budget::check(budget)?;
        dir.sync()?;
        budget::check(budget)?;
        self.root.sync()?;
        Ok(Lease {
            store: self.clone(),
            directory: unstarted.0.take().unwrap(),
            record,
            config_stamp,
            record_stamp,
            removed: false,
        })
    }
}
pub(super) struct Lease {
    pub store: Arc<Store>,
    pub directory: Directory,
    pub record: Record,
    config_stamp: Stamp,
    record_stamp: Stamp,
    removed: bool,
}
fn inventory(dir: &Directory) -> Result<(), Error> {
    for name in dir.inventory()? {
        if matches!(name.as_str(), CLAIM | CONFIG) {
            continue;
        }
        let meta = fs::symlink_metadata(dir.path.join(&name)).map_err(|_| Error::Changed)?;
        if meta.uid() != dir.owner || meta.nlink() != 1 {
            return Err(Error::Changed);
        }
        let valid = match name.as_str() {
            "v" => {
                meta.file_type().is_socket()
                    && meta.mode() & 0o7007 == 0
                    && meta.mode() & 0o600 == 0o600
            }
            "pid" => {
                meta.is_file() && matches!(meta.mode() & 0o7777, 0o600 | 0o644) && meta.len() <= 32
            }
            _ => false,
        };
        if !valid {
            return Err(Error::Changed);
        }
        crate::fs_permissions::check_path(&dir.path.join(&name), true)
            .map_err(|_| Error::Changed)?;
    }
    Ok(())
}
