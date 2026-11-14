use super::*;
use crate::connection::{
    macos::routing::{Gateway, Record},
    routes::{Address, Error, Key, Network, NextHop},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::atomic::AtomicBool,
    time::Duration,
};

struct Fake {
    remotes: Vec<IpAddr>,
    interfaces: Interfaces,
    routes: BTreeMap<(IpAddr, u16), Record>,
    sources: BTreeMap<IpAddr, IpAddr>,
    route_calls: Vec<(IpAddr, u16)>,
    source_calls: Vec<(IpAddr, u16)>,
    interface_delay: Duration,
    cancel_after_interfaces: bool,
    route_delay: Duration,
    source_delay: Duration,
    route_timeout: Option<Duration>,
    source_timeout: Option<Duration>,
}

impl Source for Fake {
    fn resolve(&mut self, _: &str, _: Instant, _: &AtomicBool) -> Result<Vec<IpAddr>, Error> {
        Ok(self.remotes.clone())
    }
    fn interfaces(&mut self, _: Instant, cancel: &AtomicBool) -> Result<Interfaces, Error> {
        if !self.interface_delay.is_zero() {
            std::thread::sleep(self.interface_delay);
        }
        if self.cancel_after_interfaces {
            cancel.store(true, Ordering::Release);
        }
        Ok(self.interfaces.clone())
    }
    fn route(
        &mut self,
        address: Address,
        scope: u16,
        timeout: Duration,
        _: &AtomicBool,
    ) -> Result<Record, Error> {
        self.route_timeout = Some(timeout);
        self.route_calls.push((address.ip, scope));
        if !self.route_delay.is_zero() {
            std::thread::sleep(self.route_delay);
        }
        self.routes
            .get(&(address.ip, scope))
            .cloned()
            .ok_or(Error::Changed)
    }
    fn source(
        &mut self,
        remote: IpAddr,
        _: u16,
        index: u16,
        timeout: Duration,
        _: &AtomicBool,
    ) -> Result<IpAddr, Error> {
        self.source_timeout = Some(timeout);
        self.source_calls.push((remote, index));
        if !self.source_delay.is_zero() {
            std::thread::sleep(self.source_delay);
        }
        self.sources.get(&remote).copied().ok_or(Error::Changed)
    }
}

fn interface(name: &str, index: u32, addresses: &[&str]) -> Interface {
    Interface {
        name: name.into(),
        index,
        flags: libc::IFF_UP as u32,
        addresses: addresses
            .iter()
            .map(|value| value.parse::<IpAddr>().unwrap())
            .collect::<BTreeSet<_>>(),
    }
}

fn record(remote: IpAddr, index: u16, next: NextHop, source: Option<Address>) -> Record {
    let (flags, gateway) = match next {
        NextHop::Gateway(value) => (
            libc::RTF_UP | libc::RTF_GATEWAY,
            Some(Gateway::Address(value)),
        ),
        NextHop::Blackhole => (libc::RTF_UP | libc::RTF_BLACKHOLE, None),
        NextHop::Interface => (libc::RTF_UP, None),
    };
    Record {
        key: Key {
            network: Network::host(remote),
            scope: 0,
        },
        interface: index,
        flags,
        gateway,
        source,
    }
}

fn profile(kind: VpnKind, host: &str, port: u16) -> Profile {
    Profile {
        id: "ipsec-egress".into(),
        name: "IPsec egress".into(),
        kind,
        gateway: host.into(),
        username: "fixture".into(),
        networks: vec![],
        port,
        certificate: String::new(),
        probe_host: "192.0.2.1".into(),
        probe_port: 443,
        probe_method: "tcp".into(),
    }
}

fn sample() -> Fake {
    let mut interfaces = Interfaces::default();
    interfaces.entries.insert(
        "en9".into(),
        interface(
            "en9",
            9,
            &["192.0.2.10", "192.0.2.11", "2001:db8::10", "2001:db8::11"],
        ),
    );
    let v4: IpAddr = "198.51.100.1".parse().unwrap();
    let v6: IpAddr = "2001:db8:1::1".parse().unwrap();
    let mut routes = BTreeMap::new();
    for remote in [v4, v6] {
        routes.insert((remote, 0), record(remote, 9, NextHop::Interface, None));
        routes.insert((remote, 9), record(remote, 9, NextHop::Interface, None));
    }
    let mut sources = BTreeMap::new();
    sources.insert(v4, "192.0.2.11".parse().unwrap());
    sources.insert(v6, "2001:db8::11".parse().unwrap());
    Fake {
        remotes: vec![v4, v6],
        interfaces,
        routes,
        sources,
        route_calls: Vec::new(),
        source_calls: Vec::new(),
        interface_delay: Duration::ZERO,
        cancel_after_interfaces: false,
        route_delay: Duration::ZERO,
        source_delay: Duration::ZERO,
        route_timeout: None,
        source_timeout: None,
    }
}

fn v4() -> IpAddr {
    "198.51.100.1".parse().unwrap()
}

fn secs() -> Duration {
    Duration::from_secs(1)
}
fn current(egress: &IpsecEgress, fake: &mut Fake, profile: &Profile) -> bool {
    egress
        .is_current_with(fake, profile, &AtomicBool::new(false), secs())
        .unwrap()
}
macro_rules! refused {
    ($value:expr, $error:pat) => {
        assert!(matches!($value, Err($error)), "unexpected result")
    };
}
#[test]
fn selects_exact_source_for_both_families_and_scoped_revalidation() {
    let profile = profile(VpnKind::Ipsec, "fixture.example", 8443);
    let cancel = AtomicBool::new(false);
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    assert_eq!(
        egress.local(),
        "192.0.2.11".parse::<IpAddr>().unwrap(),
        "exact source"
    );
    assert_eq!(egress.remote(), v4());
    assert_eq!(egress.interface_index(), 9);
    assert_eq!(egress.interface_name(), "en9");
    assert!(current(&egress, &mut fake, &profile));
    assert_eq!(fake.source_calls.last(), Some(&(egress.remote(), 9)));
    assert_eq!(fake.route_calls.last(), Some(&(egress.remote(), 9)));
    let mut fake = sample();
    fake.remotes = vec!["2001:db8:1::1".parse().unwrap()];
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    assert_eq!(egress.local(), "2001:db8::11".parse::<IpAddr>().unwrap());
    assert!(current(&egress, &mut fake, &profile));
}
#[test]
fn interface_route_source_and_scope_changes_invalidate_the_token() {
    let profile = profile(VpnKind::Ipsec, "fixture.example", 8443);
    let cancel = AtomicBool::new(false);
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    fake.interfaces.entries.get_mut("en9").unwrap().index = 10;
    assert!(!current(&egress, &mut fake, &profile));
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    fake.interfaces
        .entries
        .get_mut("en9")
        .unwrap()
        .addresses
        .remove(&"192.0.2.10".parse().unwrap());
    assert!(!current(&egress, &mut fake, &profile));
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    fake.routes.insert(
        (v4(), 9),
        record(
            v4(),
            9,
            NextHop::Gateway(Address::unscoped("192.0.2.1".parse().unwrap())),
            None,
        ),
    );
    assert!(
        !current(&egress, &mut fake, &profile),
        "stale token accepted"
    );
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    fake.sources.insert(v4(), "192.0.2.10".parse().unwrap());
    assert!(!current(&egress, &mut fake, &profile));
    let mut fake = sample();
    let egress = select_with(&mut fake, &profile, &cancel, secs()).unwrap();
    fake.routes.remove(&(v4(), 9));
    assert!(
        egress
            .is_current_with(&mut fake, &profile, &cancel, secs())
            .is_err()
    );
}

mod budget;
