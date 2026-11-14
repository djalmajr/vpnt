//! Lease durability. Read/write paths share the store io mutex; bounded
//! entrypoints use the caller's budget, while the wrappers without a call
//! budget (teardown/completed/metadata Observer/tests) stay exactly as before
//! and are intentionally unbudgeted.
use super::super::bound::budget;
use super::{Birth, CLAIM, CONFIG, Error, Lease, MAX, Stage, digest, fs, inventory};
use std::{sync::atomic::AtomicBool, time::Instant};

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

    /// Intentionally unbudgeted: teardown/completed/metadata Observer/tests
    /// have no caller connection budget. Active open/observe/take paths use
    /// [`Lease::validate_bounded`].
    pub fn validate(&self) -> Result<(), Error> {
        let _lock = self.store.io.lock().map_err(|_| Error::Unavailable)?;
        self.validate_unlocked()
    }

    pub(in crate::connection::ipsec::producer) fn validate_bounded(
        &self,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), Error> {
        let _lock = budget::lock_until(expires, cancel, &self.store.io)?;
        budget::check_until(expires, cancel)?;
        self.validate_unlocked()
    }

    /// Intentionally unbudgeted: teardown only. Active spawn paths use
    /// [`Lease::stage_bounded`].
    pub fn stage(&mut self, stage: Stage, child: Option<Birth>) -> Result<(), Error> {
        let store = self.store.clone();
        let _lock = store.io.lock().map_err(|_| Error::Unavailable)?;
        self.stage_with(stage, child, || Ok(()))
    }

    pub(in crate::connection::ipsec::producer) fn stage_bounded(
        &mut self,
        stage: Stage,
        child: Option<Birth>,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), Error> {
        let store = self.store.clone();
        let _lock = budget::lock_until(expires, cancel, &store.io)?;
        budget::check_until(expires, cancel)?;
        self.stage_with(stage, child, || budget::check_until(expires, cancel))
    }

    fn stage_with(
        &mut self,
        stage: Stage,
        child: Option<Birth>,
        prewrite: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
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
        prewrite()?;
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
