use super::*;
use crate::connection::ipsec::{Observer, ResourceClaims};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Claims(Arc<Mutex<Vec<Owner>>>);
impl Claims {
    fn set(&self, owners: &[Owner]) {
        *self.0.lock().unwrap() = owners.to_vec();
    }
    fn push(&self, owner: Owner) {
        self.0.lock().unwrap().push(owner);
    }
    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}
impl ResourceClaims for Claims {
    fn pending_owners(&mut self) -> Result<Vec<Owner>, Error> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Failing;
impl ResourceClaims for Failing {
    fn pending_owners(&mut self) -> Result<Vec<Owner>, Error> {
        Err(Error::Unavailable)
    }
}

/// Intentionally different full/pre-initiate sets: release must use full.
struct Split {
    full: Arc<Mutex<BTreeSet<u32>>>,
    pre: Arc<Mutex<BTreeSet<u32>>>,
    stopped: bool,
}
impl Observer for Split {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        Ok(self.full.lock().unwrap().clone())
    }
    fn occupied_before_initiate(
        &mut self,
        _owner: &Owner,
        _reqid: u16,
    ) -> Result<BTreeSet<u32>, Error> {
        Ok(self.pre.lock().unwrap().clone())
    }
    fn producer_stopped(&mut self, _owner: &Owner) -> Result<bool, Error> {
        Ok(self.stopped)
    }
}

fn released(registry: &mut Registry<impl Observer>, reservation: &Reservation) {
    assert_eq!(registry.release(reservation), Ok(()));
}

#[test]
fn own_active_resource_permits_preinitiate_and_blocks_release_until_cleared() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let claims = Claims::default();
    let mut registry = Registry::new(context.userspace_observer(claims.clone()));
    let reservation = registry.reserve(owner("normal", 7)).unwrap();
    let configuration = config(&registry, &reservation);
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    let _client = peer.open(reservation.owner(), until(), token()).unwrap();
    claims.push(reservation.owner().clone());

    assert_eq!(registry.ensure_initiate_clear(&reservation), Ok(()));
    assert_eq!(registry.ensure_clear(&reservation), Err(Error::Busy));
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert_eq!(registry.release(&reservation), Err(Error::Busy));

    claims.clear();
    released(&mut registry, &reservation);
    assert!(context.active.lock().unwrap().is_empty());
}

#[test]
fn foreign_pending_resource_occupies_its_durable_reqid() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let foreign_claims = Claims::default();
    let mut foreign = Registry::new(context.userspace_observer(foreign_claims.clone()));
    let foreign_reservation = foreign.reserve(owner("foreign", 9)).unwrap();
    let foreign_config = config(&foreign, &foreign_reservation);
    let _foreign_peer = context
        .prepare(&foreign, &foreign_reservation, &foreign_config)
        .unwrap();
    foreign_claims.push(foreign_reservation.owner().clone());

    let mut normal = Registry::new(context.userspace_observer(foreign_claims.clone()));
    let normal_reservation = normal.reserve(owner("normal", 7)).unwrap();
    assert_ne!(normal_reservation.reqid(), foreign_reservation.reqid());
}

#[test]
fn unknown_duplicate_and_failing_claims_fail_closed() {
    let fixture = Fixture::new();
    let context = fixture.context();

    let missing = Claims::default();
    missing.push(owner("missing", 3));
    let mut unknown = Registry::new(context.userspace_observer(missing));
    assert!(matches!(
        unknown.reserve(owner("normal", 7)),
        Err(Error::Changed)
    ));

    let duplicate = Claims::default();
    let mut setup = Registry::new(context.userspace_observer(duplicate.clone()));
    let reservation = setup.reserve(owner("duplicate", 5)).unwrap();
    let configuration = config(&setup, &reservation);
    let _peer = context
        .prepare(&setup, &reservation, &configuration)
        .unwrap();
    duplicate.set(&[reservation.owner().clone(), reservation.owner().clone()]);
    let mut repeated = Registry::new(context.userspace_observer(duplicate));
    assert!(matches!(
        repeated.reserve(owner("normal", 7)),
        Err(Error::Changed)
    ));

    let wrong_generation = Claims::default();
    wrong_generation.push(owner("duplicate", 6));
    let mut generation = Registry::new(context.userspace_observer(wrong_generation));
    assert!(matches!(
        generation.reserve(owner("normal", 7)),
        Err(Error::Changed)
    ));

    let mut failing = Registry::new(context.userspace_observer(Failing));
    assert!(matches!(
        failing.reserve(owner("normal", 7)),
        Err(Error::Unavailable)
    ));
}

#[test]
fn exact_owner_mapping_is_used_not_the_first_record() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let claims = Claims::default();
    let mut registry = Registry::new(context.userspace_observer(claims.clone()));
    let a = registry.reserve(owner("first", 11)).unwrap();
    let a_config = config(&registry, &a);
    let _a = context.prepare(&registry, &a, &a_config).unwrap();
    let b = registry.reserve(owner("second", 12)).unwrap();
    let b_config = config(&registry, &b);
    let _b = context.prepare(&registry, &b, &b_config).unwrap();

    let records = context.store.records().unwrap();
    assert_eq!(records.len(), 2);
    let claimed = records.get(1).expect("two records").owner();
    claims.set(&[claimed]);

    let mut observer = context.userspace_observer(claims);
    let occupied = Observer::occupied(&mut observer).unwrap();
    assert_eq!(
        occupied,
        BTreeSet::from([u32::from(records[1].reqid)]),
        "the claim must map to its own record, not the first one"
    );
    assert!(!occupied.contains(&u32::from(records[0].reqid)));
}

#[test]
fn dormant_unrepresented_claim_cannot_be_filtered_before_initiate() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let claims = Claims::default();
    let mut registry = Registry::new(context.userspace_observer(claims.clone()));
    let reservation = registry.reserve(owner("normal", 7)).unwrap();
    let configuration = config(&registry, &reservation);
    let peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    claims.push(reservation.owner().clone());
    drop(peer);

    assert_eq!(
        registry.ensure_initiate_clear(&reservation),
        Err(Error::Busy)
    );
}

#[test]
fn legacy_kernel_default_is_full_and_release_stays_full() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let kernel = Kernel::default();
    let mut registry = Registry::new(context.observer(kernel.clone()));
    let reservation = registry.reserve(owner("normal", 8)).unwrap();
    kernel
        .0
        .lock()
        .unwrap()
        .insert(u32::from(reservation.reqid()));

    assert_eq!(
        registry.ensure_initiate_clear(&reservation),
        Err(Error::Busy)
    );
    assert_eq!(registry.ensure_clear(&reservation), Err(Error::Busy));
    assert_eq!(registry.release(&reservation), Err(Error::Busy));

    kernel.0.lock().unwrap().clear();
    assert_eq!(registry.ensure_initiate_clear(&reservation), Ok(()));
    released(&mut registry, &reservation);
}

#[test]
fn release_never_uses_the_filtered_hook() {
    let full = Arc::new(Mutex::new(BTreeSet::new()));
    let pre = Arc::new(Mutex::new(BTreeSet::new()));
    let mut registry = Registry::new(Split {
        full: full.clone(),
        pre: pre.clone(),
        stopped: true,
    });
    let reservation = registry.reserve(owner("normal", 9)).unwrap();
    pre.lock().unwrap().insert(u32::from(reservation.reqid()));

    assert_eq!(
        registry.ensure_initiate_clear(&reservation),
        Err(Error::Busy)
    );
    assert_eq!(registry.ensure_clear(&reservation), Ok(()));
    released(&mut registry, &reservation);
    assert!(full.lock().unwrap().is_empty());
}
