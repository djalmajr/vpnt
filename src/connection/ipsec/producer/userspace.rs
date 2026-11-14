use super::{Error, NativeContext, Observer, record};
use crate::connection::routes::Owner;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};

/// Complete fresh pending userspace resources of the IPsec domain only:
/// FD/VIP/route admissions acquired or uncertain by an IPsec attempt. SSL owners
/// are not legitimate claims and must never be included. An unknown in-domain
/// claim is an error; there is no default or empty production implementation.
pub trait ResourceClaims {
    fn pending_owners(&mut self) -> Result<Vec<Owner>, Error>;

    /// Infallible post-durable hook. It runs only after
    /// `NativeContext::completed` succeeded and must not perform I/O.
    fn completed(&mut self, _owner: &Owner) {}
}

/// Explicit userspace admission observer. It maps every real pending owner to
/// exactly one durable producer record and unions the durable records that no
/// live producer represents; it never reads a fake kernel table.
pub struct UserspaceObserver<'a, R: ResourceClaims> {
    context: Arc<NativeContext<'a>>,
    resources: R,
}

impl<'a, R: ResourceClaims> UserspaceObserver<'a, R> {
    pub(super) fn new(context: Arc<NativeContext<'a>>, resources: R) -> Self {
        Self { context, resources }
    }
}

impl<R: ResourceClaims> Observer for UserspaceObserver<'_, R> {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        let owners = self.resources.pending_owners()?;
        let mut occupied = self.context.occupied_owners(&owners)?;
        occupied.extend(self.context.unrepresented()?);
        Ok(occupied)
    }

    /// Only the exact requested owner/reqid is skipped, and only while its
    /// same-admission producer is live, unreleased and Running. An
    /// unrepresented/dormant record stays in the union and therefore blocks.
    fn occupied_before_initiate(
        &mut self,
        owner: &Owner,
        reqid: u16,
    ) -> Result<BTreeSet<u32>, Error> {
        let owners = self.resources.pending_owners()?;
        let mut occupied = self.context.unrepresented()?;
        for (claim, record) in self.context.mapped_claims(&owners)? {
            if claim == *owner && record.reqid == reqid && self.context.active_running(&record)? {
                continue;
            }
            occupied.insert(u32::from(record.reqid));
        }
        Ok(occupied)
    }

    fn producer_stopped(&mut self, owner: &Owner) -> Result<bool, Error> {
        self.context.stopped(owner)
    }

    fn completed(&mut self, owner: &Owner, reqid: u16) -> Result<(), Error> {
        self.context.completed(owner, reqid)?;
        self.resources.completed(owner);
        Ok(())
    }
}

impl NativeContext<'_> {
    /// Every owner must map to exactly one valid durable record and reqid; a
    /// missing, duplicate or inconsistent mapping is an error, never omitted.
    fn mapped_claims(&self, owners: &[Owner]) -> Result<Vec<(Owner, record::Record)>, Error> {
        self.validate()?;
        let records = self.store.records()?;
        let mut mapped = Vec::with_capacity(owners.len());
        let mut by_reqid: BTreeMap<u16, Owner> = BTreeMap::new();
        for owner in owners {
            if mapped.iter().any(|(seen, _)| seen == owner) {
                return Err(Error::Changed);
            }
            let mut matching = records.iter().filter(|record| record.owner() == *owner);
            let record = matching.next().ok_or(Error::Changed)?.clone();
            if matching.next().is_some() {
                return Err(Error::Changed);
            }
            if let Some(previous) = by_reqid.insert(record.reqid, owner.clone())
                && previous != *owner
            {
                return Err(Error::Changed);
            }
            mapped.push((owner.clone(), record));
        }
        Ok(mapped)
    }

    fn occupied_owners(&self, owners: &[Owner]) -> Result<BTreeSet<u32>, Error> {
        Ok(self
            .mapped_claims(owners)?
            .into_iter()
            .map(|(_, record)| u32::from(record.reqid))
            .collect())
    }

    fn active_running(&self, record: &record::Record) -> Result<bool, Error> {
        if record.stage != record::Stage::Running {
            return Ok(false);
        }
        let live = self
            .active
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get(&record.session)
            .and_then(Weak::upgrade);
        let Some(producer) = live else {
            return Ok(false);
        };
        let producer = producer.lock().map_err(|_| Error::Unavailable)?;
        producer.lease.validate()?;
        Ok(!producer.released
            && producer.lease.record.same_admission(record)
            && producer.lease.record.stage == record::Stage::Running)
    }
}
