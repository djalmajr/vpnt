use super::*;

#[test]
fn rejects_ineligible_remotes_blackhole_and_bad_route_source() {
    let cancel = AtomicBool::new(false);
    let mut fake = sample();
    refused!(
        select_with(
            &mut fake,
            &profile(VpnKind::Ssl, "fixture.example", 443),
            &cancel,
            secs()
        ),
        Error::Invalid
    );
    fake.remotes = [
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "192.0.2.10",
        "fe80::1",
    ]
    .iter()
    .map(|value| value.parse().unwrap())
    .collect();
    let ipsec = profile(VpnKind::Ipsec, "fixture.example", 8443);
    refused!(
        select_with(&mut fake, &ipsec, &cancel, secs()),
        Error::Invalid
    );
    let mut fake = sample();
    fake.routes
        .insert((v4(), 0), record(v4(), 9, NextHop::Blackhole, None));
    refused!(
        select_with(&mut fake, &ipsec, &cancel, secs()),
        Error::Conflict
    );
    for source in ["192.0.2.99", "2001:db8::99"] {
        let mut fake = sample();
        fake.routes.insert(
            (v4(), 0),
            record(
                v4(),
                9,
                NextHop::Interface,
                Some(Address::unscoped(source.parse().unwrap())),
            ),
        );
        refused!(
            select_with(&mut fake, &ipsec, &cancel, secs()),
            Error::Changed
        );
    }
    for source in ["2001:db8::11", "192.0.2.99"] {
        let mut fake = sample();
        fake.sources.insert(v4(), source.parse().unwrap());
        refused!(
            select_with(&mut fake, &ipsec, &cancel, secs()),
            Error::Changed
        );
    }
}
#[test]
fn deadline_cancel_and_timeout_are_bounded() {
    let profile = profile(VpnKind::Ipsec, "fixture.example", 8443);
    let mut fake = sample();
    refused!(
        select_with(&mut fake, &profile, &AtomicBool::new(true), secs()),
        Error::Canceled
    );
    let cancel = AtomicBool::new(false);
    for timeout in [Duration::ZERO, Duration::from_secs(6)] {
        refused!(
            select_with(&mut fake, &profile, &cancel, timeout),
            Error::Invalid
        );
    }
    refused!(
        select_with(&mut fake, &profile, &cancel, Duration::from_nanos(1)),
        Error::TimedOut
    );
}

fn record_network(
    remote: IpAddr,
    prefix: u8,
    index: u16,
    next: NextHop,
    source: Option<Address>,
) -> Record {
    let mut record = record(remote, index, next, source);
    record.key.network = Network::new(remote, prefix).unwrap();
    record
}

#[test]
fn pin_is_host_scoped_and_prefix_changes_are_equivalent() {
    let profile = profile(VpnKind::Ipsec, "fixture.example", 8443);
    let cancel = AtomicBool::new(false);
    let v4 = v4();
    let mut fake = sample();
    fake.routes
        .insert((v4, 0), record_network(v4, 24, 9, NextHop::Interface, None));
    fake.routes
        .insert((v4, 9), record_network(v4, 24, 9, NextHop::Interface, None));
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    assert_eq!(
        egress.gateway_route().key.network,
        Network::host(v4),
        "gateway pin"
    );
    assert_eq!(egress.gateway_route().key.scope, 0);
    assert!(current(&egress, &mut fake, &profile));
    // RTF_IFSCOPE with the captured index is the owner's own scope, not foreign.
    let mut own = sample();
    for lookup in [0, 9] {
        let mut record = record_network(v4, 24, 9, NextHop::Interface, None);
        record.key.scope = 9;
        own.routes.insert((v4, lookup), record);
    }
    let egress = select_with(&mut own, &profile, &cancel, secs()).unwrap();
    assert_eq!(egress.gateway_route().key.scope, 0);
    assert!(current(&egress, &mut own, &profile));
    // A changed prefix with the same pin/next-hop/source is equivalent.
    own.routes
        .insert((v4, 9), record_network(v4, 16, 9, NextHop::Interface, None));
    assert!(current(&egress, &mut own, &profile), "prefix change");
    own.routes.insert(
        (v4, 9),
        record_network(
            v4,
            16,
            9,
            NextHop::Interface,
            Some(Address::unscoped("192.0.2.10".parse().unwrap())),
        ),
    );
    assert!(!current(&egress, &mut own, &profile));
    // Another interface index is foreign and must be refused.
    let mut foreign = sample();
    let mut record = record_network(v4, 24, 9, NextHop::Interface, None);
    record.key.scope = 1;
    foreign.routes.insert((v4, 0), record);
    assert!(
        matches!(
            select_with(&mut foreign, &profile, &cancel, secs()),
            Err(Error::Changed)
        ),
        "foreign scope admitted"
    );
    let mut revalidate = sample();
    let egress = select_with(&mut revalidate, &profile, &cancel, secs()).unwrap();
    let mut record = record_network(v4, 24, 9, NextHop::Interface, None);
    record.key.scope = 1;
    revalidate.routes.insert((v4, 9), record);
    assert!(!current(&egress, &mut revalidate, &profile));
}

#[test]
fn total_budget_is_shared_and_cancel_after_interfaces_is_honored() {
    let profile = profile(VpnKind::Ipsec, "fixture.example", 8443);
    let cancel = AtomicBool::new(false);
    let budget = Duration::from_millis(100);
    let mut fake = sample();
    fake.interface_delay = Duration::from_millis(15);
    fake.route_delay = Duration::from_millis(15);
    let _egress = select_with(&mut fake, &profile, &cancel, budget).unwrap();
    let select_source = fake.source_timeout.unwrap();
    assert!(
        select_source < Duration::from_millis(80),
        "select source did not use the remaining budget: {select_source:?}"
    );
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, budget).unwrap();
    fake.interface_delay = Duration::from_millis(30);
    fake.route_delay = Duration::from_millis(30);
    assert!(
        egress
            .is_current_with(&mut fake, &profile, &cancel, budget)
            .unwrap()
    );
    let current_source = fake.source_timeout.unwrap();
    assert!(
        current_source < Duration::from_millis(80),
        "revalidate source did not use the remaining budget: {current_source:?}"
    );
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, budget).unwrap();
    fake.cancel_after_interfaces = true;
    assert!(
        matches!(
            egress.is_current_with(&mut fake, &profile, &cancel, Duration::from_secs(2)),
            Err(Error::Canceled)
        ),
        "cancel after interfaces"
    );
    cancel.store(false, Ordering::Release);
    let mut fake = sample();
    fake.interface_delay = Duration::from_millis(60);
    let outcome = select_with(&mut fake, &profile, &cancel, Duration::from_millis(50));
    assert!(
        matches!(outcome, Err(Error::TimedOut)),
        "unexpected outcome: {:?}",
        outcome.err()
    );
}

#[test]
fn native_consumer_uses_host_pin_and_accepts_long_revalidation_budget() {
    // Same host-route assumption as the SSL egress test; no packet is sent.
    let profile = profile(VpnKind::Ipsec, "192.0.2.200", 8443);
    let cancel = AtomicBool::new(false);
    let egress = IpsecEgress::select(&profile, &cancel, Duration::from_secs(3))
        .expect("native select budget");
    assert_eq!(
        egress.gateway_route().key.network,
        Network::host("192.0.2.200".parse().unwrap()),
        "native host pin"
    );
    assert_eq!(egress.gateway_route().key.scope, 0);
    assert_eq!(egress.remote(), "192.0.2.200".parse::<IpAddr>().unwrap());
    assert!(egress.local().is_ipv4());
    assert!(egress.interface_index() > 0);
    assert!(
        egress
            .is_current(&profile, &cancel, Duration::from_secs(5))
            .expect("native revalidation budget")
    );
}
