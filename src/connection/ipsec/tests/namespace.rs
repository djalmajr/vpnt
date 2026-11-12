use super::*;

#[test]
fn reservations_exclude_kernel_ids_and_other_generations_until_the_producer_and_kernel_are_clear() {
    let observed = Observation::default();
    observed
        .0
        .lock()
        .unwrap()
        .occupied
        .extend([0x3fff, 0x3ffe, 0x4000, 65535]);
    let mut r = Registry::new(observed.clone());
    let a = r.reserve(owner("Case", 1)).expect("reserve a free reqid");
    let b = r.reserve(owner("case", 1)).unwrap();
    assert_eq!(a.reqid(), 0x3ffd);
    assert_eq!(b.reqid(), 0x3ffc);
    assert!(matches!(r.reserve(owner("Case", 2)), Err(Error::Busy)));
    assert_eq!(r.release(&a), Err(Error::Busy));
    observed.0.lock().unwrap().stopped = true;
    observed
        .0
        .lock()
        .unwrap()
        .occupied
        .insert(u32::from(a.reqid()));
    assert_eq!(r.ensure_clear(&a), Err(Error::Busy));
    assert_eq!(r.release(&a), Err(Error::Busy));
    observed
        .0
        .lock()
        .unwrap()
        .occupied
        .remove(&u32::from(a.reqid()));
    r.release(&a).unwrap();
    assert_eq!(r.validate(&a), Err(Error::Changed));
    let next = r.reserve(owner("Case", 2)).unwrap();
    assert_eq!(next.reqid(), a.reqid());
    assert_ne!(next.reqid(), b.reqid());
    drop(b);
    assert!(
        r.has_reservations(),
        "dropping a token does not confirm cleanup"
    );
}

#[test]
fn foreign_and_stale_tokens_cannot_release_a_new_reservation_and_failed_observation_changes_nothing()
 {
    let observed = Observation::default();
    observed.0.lock().unwrap().stopped = true;
    let mut a = Registry::new(observed.clone());
    let mut b = Registry::new(observed.clone());
    let first = a.reserve(owner("Case", 1)).unwrap();
    let _other = b.reserve(owner("Case", 1)).unwrap();
    assert_eq!(b.release(&first), Err(Error::Changed));
    a.release(&first).unwrap();
    let current = a.reserve(owner("Case", 1)).unwrap();
    assert_eq!(current.reqid(), first.reqid());
    assert_eq!(a.release(&first), Err(Error::Changed));
    observed.0.lock().unwrap().fail = true;
    assert_eq!(a.release(&current), Err(Error::Unavailable));
    assert!(matches!(
        a.reserve(owner("new", 1)),
        Err(Error::Unavailable)
    ));
    assert!(a.has_reservations());
    observed.0.lock().unwrap().fail = false;
    a.release(&current).unwrap();
    assert!(!a.has_reservations());
}

#[test]
fn exhausted_or_invalid_namespaces_never_truncate_or_admit_an_invalid_owner() {
    let observed = Observation::default();
    let mut r = Registry::new(observed.clone());
    for bad in [
        Owner {
            uid: 0,
            ..owner("Case", 1)
        },
        owner("Case", 0),
        owner("../escape", 1),
    ] {
        assert!(matches!(r.reserve(bad), Err(Error::Invalid)));
    }
    observed.0.lock().unwrap().occupied = (1..=0x3fff).collect();
    assert!(matches!(r.reserve(owner("Case", 1)), Err(Error::Exhausted)));
    assert!(!r.has_reservations());
    observed.0.lock().unwrap().occupied = BTreeSet::from([65536]);
    assert!(matches!(r.reserve(owner("Case", 1)), Err(Error::Invalid)));
    assert!(!r.has_reservations());
}

#[test]
fn the_profile_capacity_is_bounded_without_reusing_dropped_or_unconfirmed_reservations() {
    let mut r = Registry::new(Observation::default());
    for i in 0..64 {
        let token = r.reserve(owner(&format!("profile-{i}"), 1)).unwrap();
        drop(token);
    }
    assert!(r.has_reservations());
    assert!(matches!(
        r.reserve(owner("overflow", 1)),
        Err(Error::Exhausted)
    ));
}
