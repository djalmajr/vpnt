use super::*;
use crate::connection::routes::{Key, Network, NextHop, Presence};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Fake {
    rows: BTreeMap<Key, Route>,
    creates: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    fail_remove: bool,
}

impl Backend for Fake {
    type Receipt = Key;
    fn authorize(&mut self, _: &Owner, _: Route) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
        Ok(self.rows.get(&key).copied())
    }
    fn create(&mut self, route: Route) -> Result<Key, Error> {
        self.creates.fetch_add(1, Ordering::AcqRel);
        self.rows.insert(route.key, route);
        Ok(route.key)
    }
    fn receipt_state(&mut self, receipt: &Key) -> Result<Presence, Error> {
        Ok(if self.rows.contains_key(receipt) {
            Presence::Owned
        } else {
            Presence::Absent
        })
    }
    fn remove(&mut self, receipt: &Key) -> Result<(), Error> {
        if self.fail_remove {
            return Err(Error::Unavailable);
        }
        self.rows.remove(receipt);
        Ok(())
    }
}

fn route(network: &str, interface: u16) -> Route {
    Route {
        key: Key {
            network: network.parse::<Network>().unwrap(),
            scope: 0,
        },
        interface,
        next_hop: NextHop::Interface,
    }
}

fn owner(id: &str, generation: u64) -> Owner {
    Owner {
        uid: 502,
        profile: id.into(),
        generation,
    }
}

fn manager() -> (Coordinator<Fake>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let fake = Fake::default();
    let creates = fake.creates.clone();
    let calls = fake.calls.clone();
    (Coordinator::new(fake).unwrap(), creates, calls)
}

#[test]
fn initial_guard_failure_creates_no_claim_or_call() {
    let (mut manager, creates, calls) = manager();
    let first = Arc::new(AtomicUsize::new(0));
    let error = manager
        .acquire_guarded(owner("guard", 1), &[route("10.20.0.0/16", 3)], {
            let first = first.clone();
            move || {
                if first.fetch_add(1, Ordering::AcqRel) == 0 {
                    Err(Error::TimedOut)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap_err();
    assert_eq!(error.reason, Error::TimedOut);
    assert_eq!(creates.load(Ordering::Acquire), 0);
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert!(!manager.has_resources());
}

#[test]
fn guard_after_first_confirmed_attach_rolls_back_without_success() {
    let (mut manager, creates, calls) = manager();
    let creates_seen = creates.clone();
    let error = manager
        .acquire_guarded(
            owner("guard", 1),
            &[route("10.20.0.0/16", 3), route("10.21.0.0/16", 3)],
            move || {
                if creates_seen.load(Ordering::Acquire) > 0 {
                    Err(Error::Canceled)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.reason, Error::Canceled);
    assert_eq!(creates.load(Ordering::Acquire), 1);
    assert_eq!(error.cleanup.pending, 0);
    assert!(!manager.has_resources());
    manager.backend_mut().rows.clear();
    assert!(calls.load(Ordering::Acquire) >= 1);
}

#[test]
fn guarded_extension_failure_preserves_old_keys() {
    let (mut manager, creates, _) = manager();
    let old = route("10.20.0.0/16", 3);
    let lease = manager.acquire(owner("guard", 1), &[old]).unwrap();
    let creates_seen = creates.clone();
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let error = manager
        .extend_guarded(
            &lease,
            &[route("10.21.0.0/16", 3), route("10.22.0.0/16", 3)],
            {
                let failed = failed.clone();
                move || {
                    if creates_seen.load(Ordering::Acquire) > 1
                        && !failed.swap(true, Ordering::AcqRel)
                    {
                        Err(Error::TimedOut)
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.reason, Error::TimedOut);
    manager.validate(&lease).unwrap();
    assert_eq!(manager.backend_mut().rows.len(), 1);
    assert!(manager.backend_mut().rows.contains_key(&old.key));
    assert_eq!(error.cleanup.pending, 0);
}

#[test]
fn guard_after_final_validation_rolls_back_extension() {
    let (mut manager, _, _) = manager();
    let old = route("10.20.0.0/16", 3);
    let lease = manager.acquire(owner("guard", 1), &[old]).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let error = manager
        .extend_guarded(&lease, &[route("10.21.0.0/16", 3)], {
            let calls = calls.clone();
            move || {
                if calls.fetch_add(1, Ordering::AcqRel) + 1 >= 6 {
                    Err(Error::TimedOut)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap_err();
    assert_eq!(error.reason, Error::TimedOut);
    manager.validate(&lease).unwrap();
    assert_eq!(manager.backend_mut().rows.len(), 1);
    assert!(manager.backend_mut().rows.contains_key(&old.key));
}

#[test]
fn pre_next_attach_guard_failure_rolls_back_tail_and_keeps_old_keys() {
    let (mut manager, creates, _) = manager();
    let old = route("10.20.0.0/16", 3);
    let lease = manager.acquire(owner("guard", 1), &[old]).unwrap();
    let creates_seen = creates.clone();
    let mut passed_post = false;
    let error = manager
        .extend_guarded(
            &lease,
            &[route("10.21.0.0/16", 3), route("10.22.0.0/16", 3)],
            move || {
                if creates_seen.load(Ordering::Acquire) > 1 {
                    if !passed_post {
                        passed_post = true;
                        Ok(())
                    } else {
                        Err(Error::Canceled)
                    }
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.reason, Error::Canceled);
    assert_eq!(creates.load(Ordering::Acquire), 2);
    assert_eq!(error.cleanup.removed, 1);
    assert_eq!(manager.backend_mut().rows.len(), 1);
    assert!(manager.backend_mut().rows.contains_key(&old.key));
    manager.validate(&lease).unwrap();
}

#[test]
fn pending_guard_rollback_keeps_uncertain_tail_and_blocks_old_lease() {
    let (mut manager, creates, _) = manager();
    let old = route("10.20.0.0/16", 3);
    let lease = manager.acquire(owner("guard", 1), &[old]).unwrap();
    manager.backend_mut().fail_remove = true;
    let creates_seen = creates.clone();
    let mut passed_post = false;
    let error = manager
        .extend_guarded(
            &lease,
            &[route("10.21.0.0/16", 3), route("10.22.0.0/16", 3)],
            move || {
                if creates_seen.load(Ordering::Acquire) > 1 {
                    if !passed_post {
                        passed_post = true;
                        Ok(())
                    } else {
                        Err(Error::TimedOut)
                    }
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.reason, Error::TimedOut);
    assert!(error.cleanup.pending > 0);
    assert_eq!(creates.load(Ordering::Acquire), 2);
    assert_eq!(manager.backend_mut().rows.len(), 2);
    assert_eq!(manager.validate(&lease), Err(Error::Changed));
    manager.backend_mut().fail_remove = false;
    let cleanup = manager.release(lease).unwrap();
    assert!(cleanup.pending == 0 && cleanup.removed == 2);
    assert!(!manager.has_resources());
}

#[test]
fn acquire_guarded_pending_failure_does_not_return_or_leak_claim() {
    let (mut manager, creates, _) = manager();
    manager.backend_mut().fail_remove = true;
    let creates_seen = creates.clone();
    let mut passed_post = false;
    let error = manager
        .acquire_guarded(
            owner("guard", 1),
            &[route("10.20.0.0/16", 3), route("10.21.0.0/16", 3)],
            move || {
                if creates_seen.load(Ordering::Acquire) > 0 {
                    if !passed_post {
                        passed_post = true;
                        Ok(())
                    } else {
                        Err(Error::Unavailable)
                    }
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
    assert_eq!(error.reason, Error::Unavailable);
    assert!(error.cleanup.pending > 0);
    assert_eq!(creates.load(Ordering::Acquire), 1);
    assert_eq!(manager.backend_mut().rows.len(), 1);
    manager.backend_mut().fail_remove = false;
    assert_eq!(manager.retry_cleanup().removed, 1);
    assert!(!manager.has_resources());
}
