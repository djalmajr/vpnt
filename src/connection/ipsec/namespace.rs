use super::Error;
use crate::connection::routes::Owner;
use crate::model::valid_profile_id;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
// Darwin reassigns policy reqids above IPSEC_MANUAL_REQID_MAX. Keep SAD and
// SPD on the same explicit reqid by using only the manual range.
const MAX_MANUAL_REQID: u16 = 0x3fff;

/// Native implementations must read all relevant SAs and SPD policies, and
/// include durable incomplete admissions, and prove their own producer has
/// stopped. A cached/partial VICI or kernel reply is insufficient. Native use
/// also requires the controller lock; this is no fence against arbitrary root.
pub trait Observer {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error>;
    fn producer_stopped(&mut self, owner: &Owner) -> Result<bool, Error>;
    /// Pre-initiate only. A userspace observer may exclude the exact requested
    /// owner/reqid when it belongs to its own unreleased, Running producer. The
    /// default is full occupancy: the legacy kernel contract is unchanged, and
    /// finalization (`release`) must use [`Observer::occupied`], never this view.
    fn occupied_before_initiate(
        &mut self,
        _owner: &Owner,
        _reqid: u16,
    ) -> Result<BTreeSet<u32>, Error> {
        self.occupied()
    }
    /// Called only after stopped + a fresh clear observation. A native observer
    /// must durably complete its admission before the in-memory slot is freed.
    fn completed(&mut self, _owner: &Owner, _reqid: u16) -> Result<(), Error> {
        Ok(())
    }
}
/// No Clone/Deserialize/Drop release: an uncertain producer retains its slot.
#[derive(Debug)]
pub struct Reservation {
    owner: Owner,
    reqid: u16,
    serial: u64,
    authority: Arc<()>,
}
#[derive(Clone)]
pub(super) struct Binding {
    authority: Arc<()>,
    serial: u64,
}
impl Binding {
    pub(super) fn matches(&self, reservation: &Reservation) -> bool {
        Arc::ptr_eq(&self.authority, &reservation.authority) && self.serial == reservation.serial
    }
}
impl Reservation {
    pub(super) fn binding(&self) -> Binding {
        Binding {
            authority: self.authority.clone(),
            serial: self.serial,
        }
    }
    pub fn owner(&self) -> &Owner {
        &self.owner
    }
    pub fn reqid(&self) -> u16 {
        self.reqid
    }
}
pub struct Registry<N: Observer> {
    observer: N,
    authority: Arc<()>,
    next: u64,
    entries: BTreeMap<u16, (u64, Owner)>,
}
impl<N: Observer> Registry<N> {
    pub fn new(observer: N) -> Self {
        Self {
            observer,
            authority: Arc::new(()),
            next: 0,
            entries: BTreeMap::new(),
        }
    }
    pub fn reserve(&mut self, owner: Owner) -> Result<Reservation, Error> {
        if owner.uid == 0 || owner.generation == 0 || !valid_profile_id(&owner.profile) {
            return Err(Error::Invalid);
        }
        if self
            .entries
            .values()
            .any(|(_, current)| current.uid == owner.uid && current.profile == owner.profile)
        {
            return Err(Error::Busy);
        }
        if self.entries.len() >= 64 {
            return Err(Error::Exhausted);
        }
        let occupied = self.occupied()?;
        let reqid = (1..=MAX_MANUAL_REQID)
            .rev()
            .find(|id| !self.entries.contains_key(id) && !occupied.contains(&u32::from(*id)))
            .ok_or(Error::Exhausted)?;
        let serial = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        self.entries.insert(reqid, (serial, owner.clone()));
        self.next = serial;
        Ok(Reservation {
            owner,
            reqid,
            serial,
            authority: self.authority.clone(),
        })
    }
    pub fn validate(&self, reservation: &Reservation) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.authority, &reservation.authority)
            || !self
                .entries
                .get(&reservation.reqid)
                .is_some_and(|(serial, owner)| {
                    *serial == reservation.serial && owner == &reservation.owner
                })
        {
            return Err(Error::Changed);
        }
        Ok(())
    }
    /// Recheck immediately before the first kernel-changing command.
    pub fn ensure_clear(&mut self, reservation: &Reservation) -> Result<(), Error> {
        self.validate(reservation)?;
        if self.occupied()?.contains(&u32::from(reservation.reqid)) {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// Recheck before `initiate` only. This never completes or releases a
    /// reservation; `ensure_clear` and `release` remain full-absence checks.
    /// Reqid bounds are validated exactly like `occupied()`.
    pub fn ensure_initiate_clear(&mut self, reservation: &Reservation) -> Result<(), Error> {
        self.validate(reservation)?;
        let occupied = self
            .observer
            .occupied_before_initiate(&reservation.owner, reservation.reqid)?;
        if occupied.iter().any(|id| *id > u32::from(u16::MAX)) {
            return Err(Error::Invalid);
        }
        if occupied.contains(&u32::from(reservation.reqid)) {
            return Err(Error::Busy);
        }
        Ok(())
    }
    pub fn release(&mut self, reservation: &Reservation) -> Result<(), Error> {
        self.validate(reservation)?;
        if !self.observer.producer_stopped(&reservation.owner)? {
            return Err(Error::Busy);
        }
        self.ensure_clear(reservation)?;
        self.observer
            .completed(&reservation.owner, reservation.reqid)?;
        self.entries.remove(&reservation.reqid);
        Ok(())
    }
    pub fn has_reservations(&self) -> bool {
        !self.entries.is_empty()
    }
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        let occupied = self.observer.occupied()?;
        if occupied.iter().any(|id| *id > u32::from(u16::MAX)) {
            return Err(Error::Invalid);
        }
        Ok(occupied)
    }
}
