use super::*;
use crate::connection::routes::{Coordinator, ppp_networks};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
struct Kernel {
    routes: BTreeMap<Key, Route>,
    live: BTreeMap<u16, bool>,
    closes: BTreeMap<u16, usize>,
    writes: usize,
    lose_ack: bool,
    ignore_add: bool,
    fail_after_add: bool,
    read_error: Option<Error>,
    auto_purge: bool,
}
type Shared = Rc<RefCell<Kernel>>;
struct FixtureTable(Shared);
impl Table for FixtureTable {
    fn exact(&mut self, key: Key) -> Result<Option<Route>, Error> {
        let kernel = self.0.borrow_mut();
        if let Some(error) = kernel.read_error {
            return Err(error);
        }
        Ok(kernel.routes.get(&key).copied())
    }
}
struct FixtureScope {
    kernel: Shared,
    primary: u16,
    targets: BTreeSet<u16>,
}
impl Scope for FixtureScope {
    fn index(&self) -> u16 {
        self.primary
    }
    fn owns(&self, index: u16) -> bool {
        self.targets.contains(&index)
    }
    fn active(&self) -> Result<(), Error> {
        if self.kernel.borrow_mut().live[&self.primary] {
            Ok(())
        } else {
            Err(Error::Changed)
        }
    }
    fn add(&mut self, route: Route) -> Result<Attempt, Error> {
        assert!(self.owns(route.interface));
        let mut kernel = self.kernel.borrow_mut();
        kernel.writes += 1;
        if kernel.routes.contains_key(&route.key) {
            return Ok(Attempt {
                confirmation: Err(Error::Conflict),
            });
        }
        if !kernel.ignore_add {
            kernel.routes.insert(route.key, route);
        }
        if kernel.fail_after_add {
            kernel.read_error = Some(Error::Changed);
        }
        Ok(Attempt {
            confirmation: if kernel.lose_ack {
                Err(Error::TimedOut)
            } else {
                Ok(())
            },
        })
    }
    fn detach_if_stopped(&mut self) -> Result<bool, Error> {
        let mut kernel = self.kernel.borrow_mut();
        if kernel.live[&self.primary] {
            return Ok(false);
        }
        for &target in &self.targets {
            *kernel.closes.entry(target).or_default() += 1;
        }
        // Fixture models eventual interface lifecycle, not per-key deletion.
        if kernel.auto_purge {
            kernel
                .routes
                .retain(|_, route| !self.targets.contains(&route.interface));
        }
        Ok(true)
    }
}
type TestRegistry = Registry<FixtureScope, FixtureTable>;
fn backend() -> (TestRegistry, Shared) {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    (Registry::new(FixtureTable(kernel.clone())).unwrap(), kernel)
}
fn owner(profile: &str, generation: u64) -> Owner {
    Owner {
        uid: 501,
        profile: profile.into(),
        generation,
    }
}
fn route(network: &str, index: u16) -> Route {
    Route {
        key: Key {
            network: network.parse().unwrap(),
            scope: 0,
        },
        interface: index,
        next_hop: NextHop::Interface,
    }
}
fn register(
    registry: &mut TestRegistry,
    kernel: &Shared,
    profile: &str,
    index: u16,
    plan: Vec<Route>,
) -> InterfaceToken {
    let targets = plan
        .iter()
        .map(|route| route.interface)
        .chain([index])
        .collect();
    kernel.borrow_mut().live.insert(index, true);
    registry
        .register(
            FixtureScope {
                kernel: kernel.clone(),
                primary: index,
                targets,
            },
            owner(profile, 1),
            plan,
        )
        .unwrap()
}

#[test]
fn confirmed_routes_stay_pending_until_both_reference_release_and_absence() {
    let (mut registry, kernel) = backend();
    let plan = vec![route("10.20.0.0/16", 3)];
    let foreign = route("198.51.100.0/24", 9);
    kernel.borrow_mut().routes.insert(foreign.key, foreign);
    let token = register(&mut registry, &kernel, "one", 3, plan.clone());
    let mut coordinator = Coordinator::new(registry).unwrap();
    let lease = coordinator.acquire(owner("one", 1), &plan).unwrap();
    coordinator.validate(&lease).unwrap();
    assert_eq!(coordinator.release(lease).unwrap().pending, 1);
    assert!(!coordinator.backend_mut().begin_cleanup(&token).unwrap());
    assert!(matches!(
        coordinator.backend_mut().create(plan[0]),
        Err(Error::Busy)
    ));
    assert!(kernel.borrow_mut().closes.is_empty());
    kernel.borrow_mut().live.insert(3, false);
    assert!(coordinator.backend_mut().begin_cleanup(&token).unwrap());
    assert!(coordinator.backend_mut().begin_cleanup(&token).unwrap());
    assert_eq!(kernel.borrow_mut().closes[&3], 1);
    assert_eq!(coordinator.retry_cleanup().pending, 1);
    assert_eq!(
        coordinator.backend_mut().finish_cleanup(&token),
        Err(Error::Busy)
    );
    kernel.borrow_mut().routes.remove(&plan[0].key);
    assert_eq!(coordinator.retry_cleanup().absent, 1);
    coordinator.backend_mut().finish_cleanup(&token).unwrap();
    assert!(coordinator.backend_mut().is_empty());
    assert_eq!(kernel.borrow_mut().routes.get(&foreign.key), Some(&foreign));
}
#[test]
fn lost_ack_or_postflight_read_failure_never_discards_a_possible_add() {
    for lost_ack in [true, false] {
        let (mut registry, kernel) = backend();
        let plan = vec![route("10.20.0.0/16", 3)];
        {
            let mut state = kernel.borrow_mut();
            state.lose_ack = lost_ack;
            state.fail_after_add = !lost_ack;
        }
        let token = register(&mut registry, &kernel, "one", 3, plan.clone());
        let mut coordinator = Coordinator::new(registry).unwrap();
        let error = coordinator.acquire(owner("one", 1), &plan).unwrap_err();
        assert_eq!(error.cleanup.pending, 1);
        assert!(kernel.borrow_mut().routes.contains_key(&plan[0].key));
        {
            let mut state = kernel.borrow_mut();
            state.read_error = None;
            state.lose_ack = false;
            state.fail_after_add = false;
        }
        // A later matching table entry cannot repair an unconfirmed attempt.
        assert_eq!(coordinator.retry_cleanup().pending, 1);
        assert_eq!(
            coordinator
                .acquire(owner("one", 2), &plan)
                .unwrap_err()
                .reason,
            Error::Busy
        );
        {
            let mut state = kernel.borrow_mut();
            state.live.insert(3, false);
            state.auto_purge = true;
        }
        coordinator.backend_mut().begin_cleanup(&token).unwrap();
        assert_eq!(coordinator.retry_cleanup().absent, 1);
        coordinator.backend_mut().finish_cleanup(&token).unwrap();
    }
}
#[test]
fn an_ack_without_an_observed_exact_route_cannot_authorize_a_lease() {
    let (mut registry, kernel) = backend();
    let plan = vec![route("10.20.0.0/16", 3)];
    let broader = route("10.0.0.0/8", 9);
    {
        let mut state = kernel.borrow_mut();
        state.ignore_add = true;
        state.routes.insert(broader.key, broader);
    }
    let token = register(&mut registry, &kernel, "one", 3, plan.clone());
    let receipt = registry.create(plan[0]).unwrap();
    assert_eq!(receipt.confirmation, Err(Error::Changed));
    assert_eq!(registry.receipt_state(&receipt).unwrap(), Presence::Absent);
    assert_eq!(registry.finish_cleanup(&token), Err(Error::Busy));
    kernel.borrow_mut().live.insert(3, false);
    registry.begin_cleanup(&token).unwrap();
    registry.finish_cleanup(&token).unwrap();
    assert_eq!(kernel.borrow_mut().routes.get(&broader.key), Some(&broader));
}
#[test]
fn borrowed_routes_are_still_checked_when_finishing_the_interface_scope() {
    let (mut registry, kernel) = backend();
    let plan = vec![route("10.20.0.0/16", 3)];
    kernel.borrow_mut().routes.insert(plan[0].key, plan[0]);
    let token = register(&mut registry, &kernel, "one", 3, plan.clone());
    let mut coordinator = Coordinator::new(registry).unwrap();
    let lease = coordinator.acquire(owner("one", 1), &plan).unwrap();
    assert_eq!(kernel.borrow_mut().writes, 0);
    assert_eq!(coordinator.release(lease).unwrap().borrowed, 1);
    kernel.borrow_mut().live.insert(3, false);
    coordinator.backend_mut().begin_cleanup(&token).unwrap();
    assert_eq!(
        coordinator.backend_mut().finish_cleanup(&token),
        Err(Error::Busy)
    );
    kernel.borrow_mut().routes.clear();
    coordinator.backend_mut().finish_cleanup(&token).unwrap();
}
#[test]
fn replacements_are_preserved_and_same_index_changes_remain_uncertain() {
    for different_index in [true, false] {
        let (mut registry, kernel) = backend();
        let plan = vec![route("10.20.0.0/16", 3)];
        let token = register(&mut registry, &kernel, "one", 3, plan.clone());
        let mut coordinator = Coordinator::new(registry).unwrap();
        let lease = coordinator.acquire(owner("one", 1), &plan).unwrap();
        let mut replacement = plan[0];
        if different_index {
            replacement.interface = 9;
        } else {
            replacement.next_hop = NextHop::Gateway(crate::connection::routes::Address::unscoped(
                "192.0.2.1".parse().unwrap(),
            ));
        }
        kernel
            .borrow_mut()
            .routes
            .insert(replacement.key, replacement);
        let cleanup = coordinator.release(lease).unwrap();
        assert_eq!(
            (cleanup.changed, cleanup.pending),
            if different_index { (1, 0) } else { (0, 1) }
        );
        kernel.borrow_mut().live.insert(3, false);
        coordinator.backend_mut().begin_cleanup(&token).unwrap();
        if different_index {
            coordinator.backend_mut().finish_cleanup(&token).unwrap();
        } else {
            assert_eq!(
                coordinator.backend_mut().finish_cleanup(&token),
                Err(Error::Busy)
            );
            kernel.borrow_mut().read_error = Some(Error::Changed);
            assert_eq!(coordinator.retry_cleanup().pending, 1);
            assert_eq!(
                coordinator.backend_mut().finish_cleanup(&token),
                Err(Error::Unavailable)
            );
            {
                let mut state = kernel.borrow_mut();
                state.read_error = None;
                state.routes.clear();
            }
            assert_eq!(coordinator.retry_cleanup().absent, 1);
            coordinator.backend_mut().finish_cleanup(&token).unwrap();
        }
        if different_index {
            assert_eq!(
                kernel.borrow_mut().routes.get(&replacement.key),
                Some(&replacement)
            );
        }
    }
}
#[test]
fn backend_and_generation_tokens_do_not_cross_even_when_an_index_is_reused() {
    let (mut a, kernel) = backend();
    let plan = vec![route("10.20.0.0/16", 3)];
    let old = register(&mut a, &kernel, "one", 3, plan.clone());
    let receipt = a.create(plan[0]).unwrap();
    let (mut b, other) = backend();
    let foreign = register(&mut b, &other, "two", 3, vec![route("10.30.0.0/16", 3)]);
    assert_eq!(b.begin_cleanup(&old), Err(Error::Invalid));
    assert_eq!(a.begin_cleanup(&foreign), Err(Error::Invalid));
    assert_eq!(b.receipt_state(&receipt), Err(Error::Invalid));
    {
        let mut state = kernel.borrow_mut();
        state.live.insert(3, false);
        state.auto_purge = true;
    }
    a.begin_cleanup(&old).unwrap();
    a.finish_cleanup(&old).unwrap();
    let _new = register(&mut a, &kernel, "one", 3, plan.clone());
    kernel.borrow_mut().routes.insert(plan[0].key, plan[0]);
    assert_eq!(a.begin_cleanup(&old), Err(Error::Invalid));
    assert_eq!(a.receipt_state(&receipt), Err(Error::Unavailable));
}
#[test]
fn mixed_owned_targets_all_have_to_disappear_before_full_tunnel_cleanup_finishes() {
    let (mut registry, kernel) = backend();
    let plan = ppp_networks(&[], 3, true, false, Some(4)).unwrap();
    let token = register(&mut registry, &kernel, "one", 3, plan.clone());
    let mut coordinator = Coordinator::new(registry).unwrap();
    let lease = coordinator.acquire(owner("one", 1), &plan).unwrap();
    coordinator.validate(&lease).unwrap();
    assert_eq!(coordinator.release(lease).unwrap().pending, 4);
    kernel.borrow_mut().live.insert(3, false);
    coordinator.backend_mut().begin_cleanup(&token).unwrap();
    kernel
        .borrow_mut()
        .routes
        .retain(|_, route| route.interface == 4);
    assert_eq!(
        coordinator.backend_mut().finish_cleanup(&token),
        Err(Error::Busy)
    );
    assert!(coordinator.retry_cleanup().pending > 0);
    kernel.borrow_mut().routes.clear();
    assert_eq!(coordinator.retry_cleanup().pending, 0);
    coordinator.backend_mut().finish_cleanup(&token).unwrap();
    assert_eq!(kernel.borrow_mut().closes, BTreeMap::from([(3, 1), (4, 1)]));
}

#[test]
fn only_registered_networks_and_owned_targets_can_reach_the_writer() {
    let (mut registry, kernel) = backend();
    let plan = vec![route("10.20.0.0/16", 3)];
    let _token = register(&mut registry, &kernel, "one", 3, plan);
    for attempted in [route("10.30.0.0/16", 3), route("10.20.0.0/16", 9)] {
        assert!(matches!(registry.create(attempted), Err(Error::Invalid)));
    }
    assert_eq!(kernel.borrow().writes, 0);
    kernel.borrow_mut().live.insert(4, true);
    let candidate = || FixtureScope {
        kernel: kernel.clone(),
        primary: 4,
        targets: BTreeSet::from([4]),
    };
    assert!(matches!(
        registry.register(candidate(), owner("one", 2), vec![route("10.30.0.0/16", 4)]),
        Err(Error::Busy)
    ));
    let mut other_user = owner("one", 1);
    other_user.uid = 502;
    registry
        .register(candidate(), other_user, vec![route("10.30.0.0/16", 4)])
        .unwrap();
    let (mut separate, _) = backend();
    let unowned = FixtureScope {
        kernel: kernel.clone(),
        primary: 5,
        targets: BTreeSet::from([4]),
    };
    assert!(matches!(
        separate.register(unowned, owner("three", 1), vec![route("10.40.0.0/16", 4)]),
        Err(Error::Invalid)
    ));
}

#[test]
fn coordinator_admission_checks_the_registered_uid_profile_and_generation() {
    let (mut registry, kernel) = backend();
    let plan = vec![route("10.20.0.0/16", 3)];
    let _token = register(&mut registry, &kernel, "one", 3, plan.clone());
    let mut coordinator = Coordinator::new(registry).unwrap();
    let mut different_uid = owner("one", 1);
    different_uid.uid = 502;
    for caller in [different_uid, owner("two", 1), owner("one", 2)] {
        assert_eq!(
            coordinator.acquire(caller, &plan).unwrap_err().reason,
            Error::Invalid
        );
    }
    assert_eq!(kernel.borrow().writes, 0);
    let lease = coordinator.acquire(owner("one", 1), &plan).unwrap();
    coordinator.validate(&lease).unwrap();
    assert_eq!(kernel.borrow().writes, 1);
}

#[test]
fn a_route_moved_to_another_owned_target_is_not_treated_as_foreign_cleanup() {
    let (mut registry, kernel) = backend();
    let plan = ppp_networks(&[], 3, true, false, Some(4)).unwrap();
    let token = register(&mut registry, &kernel, "one", 3, plan.clone());
    let original = plan
        .iter()
        .find(|route| route.interface == 3)
        .copied()
        .unwrap();
    let receipt = registry.create(original).unwrap();
    let mut moved = original;
    moved.interface = 4;
    kernel.borrow_mut().routes.insert(moved.key, moved);
    assert_eq!(registry.receipt_state(&receipt), Err(Error::Busy));
    assert_eq!(registry.remove(&receipt), Err(Error::Busy));
    kernel.borrow_mut().live.insert(3, false);
    registry.begin_cleanup(&token).unwrap();
    assert_eq!(registry.finish_cleanup(&token), Err(Error::Busy));
    kernel.borrow_mut().routes.clear();
    registry.finish_cleanup(&token).unwrap();
    assert_eq!(registry.receipt_state(&receipt).unwrap(), Presence::Absent);
}
