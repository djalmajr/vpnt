use super::*;
use crate::connection::macos::ipsec_egress::IpsecEgress;
use crate::helper::vici::Message;
use std::{fs, num::NonZeroU16};

pub(super) fn profile(id: &str) -> Profile {
    Profile {
        id: id.into(),
        name: "Bound fixture".into(),
        kind: VpnKind::Ipsec,
        gateway: "192.0.2.200".into(),
        username: "fictional-user".into(),
        port: 8443,
        networks: vec!["10.20.0.0/24".into()],
        certificate: String::new(),
        probe_host: "10.20.0.1".into(),
        probe_port: 8443,
        probe_method: "tcp".into(),
    }
}

pub(super) fn egress(profile: &Profile) -> Arc<IpsecEgress> {
    Arc::new(
        IpsecEgress::select(profile, &token(), Duration::from_secs(3))
            .expect("fixture host route to 192.0.2.200"),
    )
}

pub(super) fn prepared<'a>(
    context: &Arc<NativeContext<'a>>,
    registry: &Registry<NativeObserver<'a, Kernel>>,
    reservation: &Reservation,
    profile: &Profile,
) -> (Config, NativePeer<'a>) {
    context
        .prepare_bound(
            registry,
            reservation,
            profile,
            egress(profile),
            (until(), token()),
        )
        .unwrap()
}

#[test]
fn protected_bound_attempt_persists_index_and_serves_vici_then_retires() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("bound", 7)).unwrap();
    let profile = profile("bound");
    let (config, mut peer) = prepared(&context, &registry, &reservation, &profile);
    assert_eq!(config.name(), "vpnt-502-626f756e64-7");
    let index = NonZeroU16::new(
        peer.producer
            .lock()
            .unwrap()
            .lease
            .record
            .transport_interface
            .unwrap()
            .get(),
    )
    .unwrap();
    assert_eq!(
        context.store.records().unwrap()[0].transport_interface,
        Some(index)
    );
    let conf = fs::read_to_string(
        peer.producer
            .lock()
            .unwrap()
            .lease
            .directory
            .path
            .join("strongswan.conf"),
    )
    .unwrap();
    assert!(conf.contains("vpnt_protect_transport = yes"));
    assert!(conf.contains(&format!("vpnt_ifindex = {}", index.get())));
    let opened = peer.open(reservation.owner(), until(), token()).unwrap();
    let response = opened
        .command("version", Message::new(), &[])
        .unwrap()
        .response;
    assert_eq!(response.get_text("version"), Some("6.1.0"));
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
    registry.release(&reservation).unwrap();
    assert!(context.store.records().unwrap().is_empty());
}

#[test]
fn wrong_profile_canceled_or_expired_budget_refuses_before_persist() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("bound", 7)).unwrap();
    let other = profile("other");
    let egress_other = egress(&other);
    assert_eq!(
        context
            .prepare_bound(
                &registry,
                &reservation,
                &other,
                egress_other,
                (until(), token())
            )
            .map(|_| ()),
        Err(Error::Changed)
    );
    let profile = profile("bound");
    let canceled = Arc::new(AtomicBool::new(true));
    assert_eq!(
        context
            .prepare_bound(
                &registry,
                &reservation,
                &profile,
                egress(&profile),
                (until(), canceled)
            )
            .map(|_| ()),
        Err(Error::Canceled)
    );
    assert_eq!(
        context
            .prepare_bound(
                &registry,
                &reservation,
                &profile,
                egress(&profile),
                (Instant::now(), token())
            )
            .map(|_| ()),
        Err(Error::Timeout)
    );
    assert!(context.store.records().unwrap().is_empty());
}

#[test]
fn stale_binding_is_refused_before_io_and_cleanup_still_stops_the_child() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("bound", 7)).unwrap();
    let profile = profile("bound");
    let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
    peer.producer.lock().unwrap().invalidate_binding();
    assert!(matches!(
        peer.open(reservation.owner(), until(), token()),
        Err(Error::Changed)
    ));
    assert!(peer.producer.lock().unwrap().child_exited());
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
}

#[test]
fn stale_after_attempt_is_latched_and_retire_still_stops() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("bound", 7)).unwrap();
    let profile = profile("bound");
    let (_, mut peer) = prepared(&context, &registry, &reservation, &profile);
    peer.open(reservation.owner(), until(), token()).unwrap();
    peer.producer.lock().unwrap().invalidate_binding();
    assert!(matches!(
        peer.open(reservation.owner(), until(), token()),
        Err(Error::Changed)
    ));
    assert!(
        matches!(
            peer.open(reservation.owner(), until(), token()),
            Err(Error::Changed)
        ),
        "binding failure was not latched"
    );
    assert_eq!(peer.retire(reservation.owner()), Ok(true));
    assert!(peer.producer.lock().unwrap().child_exited());
}

#[test]
fn zero_durable_index_is_refused_by_record_admission() {
    let fixture = Fixture::new();
    let context = fixture.context();
    let mut registry = Registry::new(context.observer(Kernel::default()));
    let reservation = registry.reserve(owner("bound", 7)).unwrap();
    let profile = profile("bound");
    let (_, peer) = prepared(&context, &registry, &reservation, &profile);
    let directory = peer.producer.lock().unwrap().lease.directory.path.clone();
    let claim = directory.join("claim.json");
    let text = fs::read_to_string(&claim).unwrap();
    let start = text.find("\"transport_interface\":").unwrap();
    let after = &text[start + "\"transport_interface\":".len()..];
    let end = after.find(|c: char| !c.is_ascii_digit()).unwrap();
    let patched = format!(
        "{}0{}",
        &text[..start + "\"transport_interface\":".len()],
        &after[end..]
    );
    fs::write(&claim, patched).unwrap();
    assert!(context.store.records().is_err());
}
