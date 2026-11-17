use super::*;

fn owner(uid: u32) -> Owner {
    Owner {
        uid,
        profile: "fence".into(),
        generation: 7,
    }
}

#[test]
fn begin_rejects_invalid_owner_and_mints_pending_once() {
    for invalid in [
        Owner {
            uid: 0,
            profile: "fence".into(),
            generation: 7,
        },
        Owner {
            uid: 501,
            profile: "fence".into(),
            generation: 0,
        },
        Owner {
            uid: 501,
            profile: String::new(),
            generation: 7,
        },
    ] {
        assert!(matches!(
            ResourceFence::begin(&invalid),
            Err(Error::Invalid)
        ));
    }
    let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
    assert_eq!(fence.owner(), &owner(501));
    assert!(!fence.is_complete());
    drop(work);
    assert!(fence.is_complete());
}

#[test]
fn unbound_drop_completes_but_bound_drop_never_does() {
    let (fence, work) = ResourceFence::begin(&owner(501)).unwrap();
    drop(work);
    assert!(fence.is_complete());

    let (fence, mut work) = ResourceFence::begin(&owner(501)).unwrap();
    work.bind(&owner(501)).unwrap();
    drop(work);
    assert!(!fence.is_complete());
}

#[test]
fn passive_clone_observes_but_cannot_complete() {
    let (fence, mut work) = ResourceFence::begin(&owner(501)).unwrap();
    let passive = fence.clone();
    work.bind(&owner(501)).unwrap();
    assert!(!passive.is_complete());
    assert!(!fence.is_complete());
    work.complete().unwrap();
    assert!(passive.is_complete());
    assert!(fence.is_complete());
}

#[test]
fn only_the_exact_owner_can_bind_and_complete_is_bounded_idempotent() {
    let (fence, mut work) = ResourceFence::begin(&owner(501)).unwrap();
    assert_eq!(work.bind(&owner(502)), Err(Error::Invalid));
    assert!(!fence.is_complete());
    work.bind(&owner(501)).unwrap();
    assert_eq!(work.bind(&owner(501)), Err(Error::Busy));
    assert_eq!(work.complete(), Ok(()));
    assert_eq!(work.complete(), Ok(()));
    assert!(fence.is_complete());
}

#[test]
fn pending_work_cannot_complete_and_wrong_owner_drop_still_completes() {
    let (fence, mut work) = ResourceFence::begin(&owner(501)).unwrap();
    assert_eq!(work.complete(), Err(Error::Invalid));
    assert!(!fence.is_complete());
    drop(work);
    assert!(fence.is_complete());
}
