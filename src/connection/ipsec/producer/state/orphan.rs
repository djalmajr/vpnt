//! Startup-only retirement of the preceding controller's durable claims.
use super::{Birth, Directory, Error, Record, Stage, Store, fs, read_admission};
use crate::{
    connection::routes::Owner,
    helper::{controller_lock::ControllerLock, runtime::cleanup::Reason},
};

pub(in crate::connection::ipsec::producer) trait ObserveOrphan {
    fn birth_absent(&mut self, birth: &Birth) -> Result<bool, Error>;
    fn resources_absent(&mut self, record: &Record) -> Result<bool, Reason>;
}

impl Store {
    pub(in crate::connection::ipsec::producer) fn recover_orphans(
        controller: &ControllerLock,
        owner: u32,
        current: &Birth,
        observer: &mut impl ObserveOrphan,
        mut report: impl FnMut(Option<&Owner>, Reason),
    ) -> Result<(), Reason> {
        controller
            .validate()
            .map_err(|_| Reason::AdmissionCleanup)?;
        let parent = controller.directory();
        let path = parent.join("ipsec");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Reason::AdmissionCleanup),
            Ok(_) => {}
        }
        let store = Self::from_root(
            parent,
            Directory::open(path, owner).map_err(|_| Reason::AdmissionCleanup)?,
        );
        let _io = store.io.lock().map_err(|_| Reason::AdmissionCleanup)?;
        for name in store
            .root
            .inventory()
            .map_err(|_| Reason::AdmissionCleanup)?
        {
            let Ok((dir, admission)) = store.session(&name).and_then(|dir| {
                let admission = read_admission(&dir, &name)?;
                Ok((dir, admission))
            }) else {
                report(None, Reason::AdmissionCleanup);
                continue;
            };
            let record = &admission.0;
            if let Err(reason) = prove(current, record, observer).and_then(|()| {
                // Only the lock holder can admit a cooperating producer. Check
                // the original directory/claim/config again after observation.
                controller
                    .validate()
                    .map_err(|_| Reason::DurableCompletion)?;
                store
                    .root
                    .validate()
                    .map_err(|_| Reason::DurableCompletion)?;
                let latest = read_admission(&dir, &name).map_err(|_| Reason::DurableCompletion)?;
                if latest != admission {
                    return Err(Reason::DurableCompletion);
                }
                dir.remove_own().map_err(|_| Reason::DurableCompletion)?;
                store.root.sync().map_err(|_| Reason::DurableCompletion)
            }) {
                report(Some(&record.owner()), reason);
            }
        }
        Ok(())
    }
}

fn prove(
    current: &Birth,
    record: &Record,
    observer: &mut impl ObserveOrphan,
) -> Result<(), Reason> {
    if record.controller == *current {
        return Err(Reason::UnrepresentedProducer);
    }
    let mut absent = |birth| {
        observer
            .birth_absent(birth)
            .map_err(|_| Reason::ObservationFailed)
    };
    if !absent(&record.controller)? {
        return Err(Reason::ProducerNotStopped);
    }
    if record.stage == Stage::Starting {
        // Spawn can have succeeded before Running and its birth became durable.
        return Err(Reason::ProducerMissing);
    }
    if let Some(child) = &record.child
        && !absent(child)?
    {
        return Err(Reason::ProducerNotStopped);
    }
    if !observer.resources_absent(record)? {
        return Err(Reason::RetiredResources);
    }
    Ok(())
}
