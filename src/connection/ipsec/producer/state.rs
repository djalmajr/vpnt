use super::{
    Config, Error, Reservation, config,
    files::{Directory, Stamp, Unstarted},
    record::{self, Birth, Record, Stage},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    sync::{Arc, Mutex},
};
pub(super) const CONFIG: &str = "strongswan.conf";
const CLAIM: &str = "claim.json";
const MAX: u64 = 8192;
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) struct Store {
    pub root: Directory,
    io: Mutex<()>,
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
        }))
    }
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
    ) -> Result<Lease, Error> {
        let _lock = self.io.lock().map_err(|_| Error::Unavailable)?;
        let records = self.records_unlocked()?;
        if records.iter().any(|r| {
            r.reqid == reservation.reqid()
                || (r.uid == reservation.owner().uid && r.profile == reservation.owner().profile)
        }) {
            return Err(Error::Busy);
        }
        if records.len() >= 64 {
            return Err(Error::Exhausted);
        }
        let mut selected = None;
        for _ in 0..16 {
            let mut random = [0u8; 16];
            // SAFETY: getentropy receives a writable 16-byte buffer, below its 256-byte limit.
            if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
                return Err(Error::Unavailable);
            }
            let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
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
        let conf = config::render(&dir.path)?;
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
            stage: Stage::Prepared,
            child: None,
        };
        record.valid()?;
        let config_stamp = dir.write_new(CONFIG, conf.as_bytes())?;
        let record_stamp = dir.write_new(
            CLAIM,
            &serde_json::to_vec(&record).map_err(|_| Error::Invalid)?,
        )?;
        dir.sync()?;
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
impl Lease {
    fn validate_unlocked(&self) -> Result<(), Error> {
        self.store.root.validate()?;
        let (bytes, stamp) = self.directory.read(CLAIM, MAX)?;
        if stamp != self.record_stamp
            || bytes != serde_json::to_vec(&self.record).map_err(|_| Error::Invalid)?
        {
            return Err(Error::Changed);
        }
        let (conf, stamp) = self.directory.read(CONFIG, MAX)?;
        if stamp != self.config_stamp || digest(&conf) != self.record.configuration_hash {
            return Err(Error::Changed);
        }
        inventory(&self.directory)
    }
    pub fn validate(&self) -> Result<(), Error> {
        let _lock = self.store.io.lock().map_err(|_| Error::Unavailable)?;
        self.validate_unlocked()
    }
    pub fn stage(&mut self, stage: Stage, child: Option<Birth>) -> Result<(), Error> {
        let _lock = self.store.io.lock().map_err(|_| Error::Unavailable)?;
        self.validate_unlocked()?;
        if !matches!(
            (self.record.stage, stage),
            (Stage::Prepared, Stage::Starting | Stage::Stopped)
                | (Stage::Starting, Stage::Running | Stage::Stopped)
                | (Stage::Running, Stage::Stopped)
        ) {
            return Err(Error::Changed);
        }
        let mut next = self.record.clone();
        next.stage = stage;
        next.child = child;
        next.valid()?;
        let stamp = self.directory.write_new(
            ".next",
            &serde_json::to_vec(&next).map_err(|_| Error::Invalid)?,
        )?;
        fs::rename(
            self.directory.path.join(".next"),
            self.directory.path.join(CLAIM),
        )
        .map_err(|_| Error::Unavailable)?;
        self.record = next;
        self.record_stamp = stamp;
        self.directory.sync()
    }
    /// The caller is Observer.completed, after native absence and owned exit.
    pub fn complete(&mut self) -> Result<(), Error> {
        let _lock = self.store.io.lock().map_err(|_| Error::Unavailable)?;
        if self.removed {
            return self.store.root.sync();
        }
        self.validate_unlocked()?;
        if self.record.stage != Stage::Stopped {
            return Err(Error::Busy);
        }
        self.directory.remove_own()?;
        self.removed = true;
        self.store.root.sync()
    }
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
