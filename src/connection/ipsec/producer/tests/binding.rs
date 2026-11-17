use super::*;

// Mutations: omit the reservation authority/configuration seal, or ignore a
// durable reqid collision held by a separately-created registry.
#[test]
fn native_admission_requires_the_original_reservation_and_configuration_and_excludes_durable_reqids()
 {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let mut foreign = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("normal", 1)).unwrap();
    let other = registry.reserve(owner("other", 1)).unwrap();
    let conflicting = foreign.reserve(owner("foreign", 1)).unwrap();
    assert_eq!(reservation.reqid(), conflicting.reqid());
    let configuration = config(&registry, &reservation);
    let wrong = config(&registry, &other);
    assert!(matches!(
        context.prepare(&registry, &reservation, &wrong),
        Err(Error::Changed)
    ));
    assert!(matches!(
        context.prepare(&foreign, &reservation, &configuration),
        Err(Error::Changed)
    ));
    assert!(context.store.records().unwrap().is_empty());
    let mut peer = context
        .prepare(&registry, &reservation, &configuration)
        .unwrap();
    let conflict = config(&foreign, &conflicting);
    assert!(matches!(
        context.prepare(&foreign, &conflicting, &conflict),
        Err(Error::Busy)
    ));
    assert_eq!(context.store.records().unwrap().len(), 1);
    peer.retire(reservation.owner()).unwrap();
    registry.release(&reservation).unwrap();
    assert!(context.store.records().unwrap().is_empty());
}
