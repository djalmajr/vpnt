#[path = "common/routes.rs"]
mod fixture;
use fixture::*;
use vpnt::connection::routes::{Address, Coordinator, Error, Network, NextHop, ppp_networks};
#[test]
fn borrowed_routes_and_shared_nested_networks_survive_unrelated_disconnects() {
    // Mutation: create unconditionally for a borrowed route, or remove a shared
    // entry while it still has users; both destroy this observable topology.
    let kernel = Kernel::default();
    let loan = route("192.0.2.9/32", 2);
    kernel.0.borrow_mut().insert(loan);
    let initial = kernel.0.borrow().rows.clone();
    let outer = route("10.0.0.0/8", 3);
    let inner = route("10.20.0.0/16", 4);
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let a = manager
        .acquire(owner("a", 1), &[loan, outer, outer])
        .unwrap();
    let b = manager
        .acquire(owner("b", 1), &[loan, outer, inner])
        .unwrap();
    assert_eq!(kernel.0.borrow().rows.len(), 3);
    assert_eq!(manager.release(a).unwrap().removed, 0);
    manager.validate(&b).unwrap();
    let cleanup = manager.release(b).unwrap();
    assert_eq!(cleanup.removed, 2);
    assert_eq!(cleanup.borrowed, 1);
    assert_eq!(kernel.0.borrow().rows, initial);
}
#[test]
fn a_conflict_in_the_whole_plan_cannot_leave_an_earlier_route_behind() {
    let kernel = Kernel::default();
    let foreign = route("10.20.0.0/16", 2);
    kernel.0.borrow_mut().insert(foreign);
    let initial = kernel.0.borrow().rows.clone();
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let error = manager
        .acquire(
            owner("a", 1),
            &[route("172.16.0.0/12", 3), route("10.20.0.0/16", 3)],
        )
        .unwrap_err();
    assert_eq!(error.reason, Error::Conflict);
    assert_eq!(kernel.0.borrow().rows, initial);
    let a = manager
        .acquire(owner("a", 1), &[route("10.20.0.0/16", 3), foreign])
        .unwrap_err();
    assert_eq!(a.reason, Error::Conflict);
    assert_eq!(kernel.0.borrow().rows, initial);
}
#[test]
fn partial_failure_rolls_back_networks_before_the_gateway_pin() {
    // Mutation: omit rollback, or iterate release keys forwards. The fixture
    // kernel refuses a premature pin removal, leaving an observable orphan.
    let kernel = Kernel::default();
    let pin = route("203.0.113.8/32", 2);
    let high = route("128.0.0.0/1", 3);
    let low = route("0.0.0.0/1", 3);
    {
        let mut table = kernel.0.borrow_mut();
        table.pin = Some(pin.key);
        table.fail_create = Some(low.key);
    }
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let error = manager
        .acquire(owner("a", 1), &[pin, high, low])
        .unwrap_err();
    assert_eq!(error.reason, Error::Unavailable);
    assert_eq!(error.cleanup.removed, 2);
    assert_eq!(error.cleanup.pending, 0);
    assert!(kernel.0.borrow().rows.is_empty());
    assert_eq!(kernel.0.borrow().disrupted, 0);
    kernel.0.borrow_mut().fail_create = None;
    let lease = manager.acquire(owner("a", 2), &[pin, high, low]).unwrap();
    assert_eq!(manager.release(lease).unwrap().removed, 3);
    assert!(kernel.0.borrow().rows.is_empty());
}
#[test]
fn replacement_even_with_identical_attributes_is_preserved_and_absence_is_clean() {
    let kernel = Kernel::default();
    let route = route("10.20.0.0/16", 3);
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let a = manager.acquire(owner("a", 1), &[route]).unwrap();
    kernel.0.borrow_mut().insert(route);
    let replacement = kernel.0.borrow().rows.clone();
    assert_eq!(manager.validate(&a), Err(Error::Changed));
    let cleanup = manager.release(a).unwrap();
    assert_eq!(cleanup.changed, 1);
    assert_eq!(cleanup.removed, 0);
    assert_eq!(kernel.0.borrow().rows, replacement);
    kernel.0.borrow_mut().rows.clear();
    let a = manager.acquire(owner("a", 2), &[route]).unwrap();
    kernel.0.borrow_mut().rows.clear();
    assert_eq!(manager.release(a).unwrap().absent, 1);
}
#[test]
fn failed_cleanup_stays_pending_and_can_be_retried_after_the_cause_clears() {
    // Mutation: discard the receipt after a remove error, or report shutdown
    // clean just because no session still owns the pending entry.
    let kernel = Kernel::default();
    let route = route("10.20.0.0/16", 3);
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let lease = manager.acquire(owner("a", 1), &[route]).unwrap();
    kernel.0.borrow_mut().fail_remove = true;
    assert_eq!(manager.release(lease).unwrap().pending, 1);
    assert_eq!(manager.close_all().pending, 1);
    assert_eq!(kernel.0.borrow().rows.len(), 1);
    assert_eq!(
        manager.acquire(owner("a", 2), &[route]).unwrap_err().reason,
        Error::Busy
    );
    kernel.0.borrow_mut().fail_remove = false;
    assert_eq!(manager.retry_cleanup().removed, 1);
    assert!(kernel.0.borrow().rows.is_empty());
}
#[test]
fn manager_uid_profile_and_generation_boundaries_do_not_cross() {
    let kernel = Kernel::default();
    let route = route("10.20.0.0/16", 3);
    let mut a = Coordinator::new(kernel.clone()).unwrap();
    let first = a.acquire(owner("same", 1), &[route]).unwrap();
    assert_eq!(
        a.acquire(owner("same", 2), &[route]).unwrap_err().reason,
        Error::Busy
    );
    let mut other = owner("same", 2);
    other.uid = 502;
    let second = a.acquire(other, &[route]).unwrap();
    let other_kernel = Kernel::default();
    let mut b = Coordinator::new(other_kernel.clone()).unwrap();
    let b_lease = b.acquire(owner("same", 1), &[route]).unwrap();
    assert_eq!(b.release(first), Err(Error::Invalid));
    b.validate(&b_lease).unwrap();
    a.release(second).unwrap();
    assert_eq!(a.close_all().removed, 1);
    assert!(kernel.0.borrow().rows.is_empty());
    drop(b);
    assert!(other_kernel.0.borrow().rows.is_empty());
    assert_eq!(
        a.acquire(owner("same", 0), &[route]).unwrap_err().reason,
        Error::Invalid
    );
}
#[test]
fn full_tunnel_plan_preserves_defaults_and_blocks_unsupported_families() {
    // Mutation: omit unsupported-family blackholes, or retain only one /1.
    let routes = ppp_networks(&[], 3, true, false, Some(1)).unwrap();
    assert_eq!(routes.len(), 4);
    for ip in [
        "0.0.0.0",
        "127.255.255.255",
        "128.0.0.0",
        "255.255.255.255",
        "::",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ] {
        let ip = ip.parse().unwrap();
        let matching: Vec<_> = routes
            .iter()
            .filter(|route| route.key.network.contains(ip))
            .collect();
        assert_eq!(matching.len(), 1);
        let route = matching[0];
        assert_eq!(route.key.network.prefix(), 1);
        if ip.is_ipv4() {
            assert_eq!(route.next_hop, NextHop::Interface);
            assert_eq!(route.interface, 3);
        } else {
            assert_eq!(route.next_hop, NextHop::Blackhole);
            assert_eq!(route.interface, 1);
        }
    }
    let both = ppp_networks(&[], 3, true, true, None).unwrap();
    assert!(
        both.iter()
            .all(|route| route.next_hop == NextHop::Interface)
    );
    assert!(ppp_networks(&[], 3, true, false, None).is_err());
    assert!(ppp_networks(&["::/0".into()], 3, true, false, Some(1)).is_err());
    let normalized = ppp_networks(
        &["10.20.1.9/16".into(), "10.20.0.0/16".into()],
        3,
        true,
        false,
        None,
    )
    .unwrap();
    assert_eq!(normalized, vec![route("10.20.0.0/16", 3)]);
}
#[test]
fn network_masks_and_scoped_gateways_retain_their_meaning() {
    let network: Network = "2001:db8:abcd:9876::9/48".parse().unwrap();
    assert_eq!(
        network.address(),
        "2001:db8:abcd::".parse::<std::net::IpAddr>().unwrap()
    );
    assert!(network.contains("2001:db8:abcd:ffff::1".parse().unwrap()));
    assert!(!network.contains("2001:db8:abce::1".parse().unwrap()));
    for text in ["10.0.0.1/33", "::1/129", "10.0.0.1/01", "10.0.0.1/+1"] {
        assert!(text.parse::<Network>().is_err());
    }
    let ip = "fe80::1".parse().unwrap();
    assert!(!Address::unscoped(ip).valid_gateway());
    assert!(Address { ip, zone: 3 }.valid_gateway());
    let mut a = route("10.0.0.0/8", 3);
    a.next_hop = NextHop::Gateway(Address::unscoped("::1".parse().unwrap()));
    assert_eq!(a.validate(), Err(Error::Invalid));
}
