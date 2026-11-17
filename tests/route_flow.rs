#[path = "common/routes.rs"]
mod fixture;
use fixture::*;
use vpnt::connection::routes::{Coordinator, Error};

#[test]
fn connect_pins_transport_before_ppp_and_extends_the_same_generation() {
    let kernel = Kernel::default();
    let pin = route("203.0.113.8/32", 2);
    kernel.0.borrow_mut().pin = Some(pin.key);
    let high = route("128.0.0.0/1", 3);
    let low = route("0.0.0.0/1", 3);
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let lease = manager.acquire(owner("a", 1), &[pin]).unwrap();
    // PPP discovery happens between these phases in the native controller.
    manager.extend(&lease, &[high, low]).unwrap();
    manager.validate(&lease).unwrap();
    assert_eq!(kernel.0.borrow().rows.len(), 3);
    assert_eq!(manager.release(lease).unwrap().removed, 3);
    assert_eq!(kernel.0.borrow().disrupted, 0);
    assert!(kernel.0.borrow().rows.is_empty());
}
#[test]
fn failed_extension_preserves_the_transport_and_removes_only_its_new_networks() {
    let kernel = Kernel::default();
    let pin = route("203.0.113.8/32", 2);
    let high = route("128.0.0.0/1", 3);
    let low = route("0.0.0.0/1", 3);
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let lease = manager.acquire(owner("a", 1), &[pin]).unwrap();
    kernel.0.borrow_mut().fail_create = Some(low.key);
    let error = manager.extend(&lease, &[high, low]).unwrap_err();
    assert_eq!(error.reason, Error::Unavailable);
    assert_eq!(error.cleanup.removed, 1);
    manager.validate(&lease).unwrap();
    assert_eq!(kernel.0.borrow().rows.len(), 1);
    assert!(kernel.0.borrow().rows.contains_key(&pin.key));
    assert_eq!(manager.release(lease).unwrap().removed, 1);
}
#[test]
fn failed_network_cleanup_retains_the_gateway_until_retry_finishes_the_job() {
    // Mutation: continue releasing earlier keys after a later cleanup failure.
    // The pin would disappear while a full-tunnel route still captures it.
    let kernel = Kernel::default();
    let pin = route("203.0.113.8/32", 2);
    let network = route("128.0.0.0/1", 3);
    {
        let mut table = kernel.0.borrow_mut();
        table.pin = Some(pin.key);
        table.fail_remove_key = Some(network.key);
    }
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let lease = manager.acquire(owner("a", 1), &[pin, network]).unwrap();
    assert!(manager.release(lease).unwrap().pending > 0);
    assert!(kernel.0.borrow().rows.contains_key(&pin.key));
    assert_eq!(kernel.0.borrow().disrupted, 0);
    assert_eq!(
        manager.acquire(owner("a", 2), &[pin]).unwrap_err().reason,
        Error::Busy
    );
    kernel.0.borrow_mut().fail_remove_key = None;
    assert_eq!(manager.retry_cleanup().removed, 2);
    assert_eq!(kernel.0.borrow().disrupted, 0);
    assert!(kernel.0.borrow().rows.is_empty());
}

#[test]
fn incomplete_extension_with_pending_rollback_cannot_validate_as_ready() {
    // Mutation: omit claim.failed after a partial extension's rollback fails.
    let kernel = Kernel::default();
    let pin = route("203.0.113.8/32", 2);
    let high = route("128.0.0.0/1", 3);
    let low = route("0.0.0.0/1", 3);
    let mut manager = Coordinator::new(kernel.clone()).unwrap();
    let lease = manager.acquire(owner("a", 1), &[pin]).unwrap();
    {
        let mut table = kernel.0.borrow_mut();
        table.pin = Some(pin.key);
        table.fail_create = Some(low.key);
        table.fail_remove_key = Some(high.key);
    }
    assert_eq!(
        manager
            .extend(&lease, &[high, low])
            .unwrap_err()
            .cleanup
            .pending,
        1
    );
    assert_eq!(manager.validate(&lease), Err(Error::Changed));
    assert_eq!(manager.release(lease).unwrap().pending, 2);
    assert!(kernel.0.borrow().rows.contains_key(&pin.key));
    kernel.0.borrow_mut().fail_remove_key = None;
    assert_eq!(manager.retry_cleanup().removed, 2);
    assert_eq!(kernel.0.borrow().disrupted, 0);
    assert!(kernel.0.borrow().rows.is_empty());
}
