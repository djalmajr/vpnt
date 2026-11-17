//! Read-only selection of the SSL transport path before tunnel routes exist.
//! The resulting token is not deserializable or constructible by the IPC peer.
use super::{
    interfaces::{Interface, Interfaces},
    resolve,
    routing::{Reader, Snapshot, TransportDefault, covers_ipv4},
    tcp,
};
use crate::{
    connection::{
        routes::{
            AcquireError, Address, Backend, Coordinator, Error, Key, Lease, NextHop, Owner, Route,
        },
        ssl::Binding,
    },
    model::{Profile, VpnKind},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
pub struct Egress {
    profile: String,
    host: String,
    port: u16,
    interface: Interface,
    gateway: Ipv4Addr,
    next_hop: NextHop,
    observed_key: Option<Key>,
    source: Option<Address>,
}
impl Egress {
    pub fn select(
        profile: &Profile,
        canceled: &AtomicBool,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if profile.validate().is_err()
            || profile.kind != VpnKind::Ssl
            || timeout.is_zero()
            || timeout > Duration::from_secs(5)
        {
            return Err(Error::Invalid);
        }
        let deadline = Instant::now() + timeout;
        let addresses =
            resolve::gateway_ipv4(&profile.gateway, deadline, canceled).map_err(resolve_error)?;
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let mut reader = Reader::open()?;
        for address in addresses {
            let IpAddr::V4(gateway) = address else {
                continue;
            };
            if !remote(gateway, &interfaces) {
                continue;
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::TimedOut)?;
            let record = reader.lookup(
                Address::unscoped(address),
                0,
                remaining.min(Duration::from_secs(2)),
                canceled,
            )?;
            let route = record.route()?;
            if route.next_hop == NextHop::Blackhole {
                return Err(Error::Conflict);
            }
            let interface = interfaces
                .entries
                .values()
                .find(|interface| interface.index == route.interface as u32)
                .ok_or(Error::Changed)?;
            if interface.flags & libc::IFF_UP as u32 == 0
                || interface.flags & libc::IFF_LOOPBACK as u32 != 0
                || !interface.addresses.iter().any(IpAddr::is_ipv4)
            {
                return Err(Error::Unavailable);
            }
            if let Some(source) = record.source
                && (!source.ip.is_ipv4() || !interface.addresses.contains(&source.ip))
            {
                return Err(Error::Changed);
            }
            let result = Self {
                profile: profile.id.clone(),
                host: profile.gateway.clone(),
                port: profile.port,
                interface: interface.clone(),
                gateway,
                next_hop: route.next_hop,
                observed_key: Snapshot::read()
                    .ok()
                    .and_then(|snapshot| observed_key(&snapshot, route)),
                source: record.source,
            };
            if !result.is_current(profile)? {
                return Err(Error::Changed);
            }
            if canceled.load(Ordering::Acquire) {
                return Err(Error::Canceled);
            }
            return Ok(result);
        }
        Err(Error::Invalid)
    }
    /// Scoped lookup ignores the tunnel's later global /1 routes. The original
    /// egress interface, addresses, next hop and source must remain usable.
    pub fn is_current(&self, profile: &Profile) -> Result<bool, Error> {
        if profile.kind != VpnKind::Ssl
            || profile.id != self.profile
            || profile.gateway != self.host
            || profile.port != self.port
        {
            return Ok(false);
        }
        let interfaces = Interfaces::read().map_err(|_| Error::Unavailable)?;
        let Some(now) = interfaces.entries.get(&self.interface.name) else {
            return Ok(false);
        };
        if now.index != self.interface.index
            || now.flags & libc::IFF_UP as u32 == 0
            || now.addresses != self.interface.addresses
        {
            return Ok(false);
        }
        let index = u16::try_from(now.index).map_err(|_| Error::Invalid)?;
        let record = Reader::open()?.lookup(
            Address::unscoped(IpAddr::V4(self.gateway)),
            index,
            Duration::from_secs(1),
            &AtomicBool::new(false),
        )?;
        let route = record.route()?;
        Ok(route.interface == index
            && route.next_hop == self.next_hop
            && record.source == self.source)
    }
    pub(crate) fn transport_default(&self) -> Result<Option<TransportDefault>, Error> {
        let index = u16::try_from(self.interface.index).map_err(|_| Error::Invalid)?;
        TransportDefault::for_plan(index, self.next_hop, self.observed_key)
    }

    fn validate_on_link_transport(
        &self,
        snapshot: impl FnOnce() -> Result<Snapshot, Error>,
    ) -> Result<(), Error> {
        let interface = u16::try_from(self.interface.index).map_err(|_| Error::Invalid)?;
        let snapshot = snapshot()?;
        let current_key = self.observed_key.and_then(|key| {
            observed_key(
                &snapshot,
                Route {
                    key,
                    interface,
                    next_hop: self.next_hop,
                },
            )
        });
        TransportDefault::for_plan(interface, self.next_hop, current_key).map(|_| ())
    }

    pub(crate) fn binding(&self, profile: &Profile) -> Result<Binding, Error> {
        if !self.is_current(profile)? {
            return Err(Error::Changed);
        }
        Ok(Binding {
            interface: self.interface.name.clone(),
            index: self.interface.index,
            gateway: self.gateway,
        })
    }
}

pub(crate) fn acquire_ssl_routes<B: Backend>(
    routes: &mut Coordinator<B>,
    owner: Owner,
    plan: &[Route],
    egress: Option<&Egress>,
    snapshot: impl FnOnce() -> Result<Snapshot, Error>,
) -> Result<Lease, AcquireError> {
    if covers_ipv4(plan.iter().map(|route| route.key.network))
        && !plan
            .iter()
            .any(|route| TransportDefault::try_from(*route).is_ok())
    {
        egress
            .ok_or(Error::Invalid)?
            .validate_on_link_transport(snapshot)?;
    }
    routes.acquire(owner, plan)
}

fn observed_key(snapshot: &Snapshot, selected: Route) -> Option<Key> {
    let record = snapshot.exact(selected.key).ok().flatten()?;
    (record.route() == Ok(selected)).then_some(record.key)
}

fn remote(address: Ipv4Addr, interfaces: &Interfaces) -> bool {
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
        && !interfaces
            .entries
            .values()
            .any(|interface| interface.addresses.contains(&IpAddr::V4(address)))
}
fn resolve_error(error: tcp::Error) -> Error {
    match error {
        tcp::Error::Canceled => Error::Canceled,
        tcp::Error::TimedOut => Error::TimedOut,
        tcp::Error::Invalid => Error::Invalid,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::macos::routing::Record;

    #[derive(Default)]
    struct RouteFixture {
        installed: Vec<Route>,
        adds: usize,
    }

    impl Backend for RouteFixture {
        type Receipt = Route;

        fn existing(&mut self, key: Key) -> Result<Option<Route>, Error> {
            Ok(self
                .installed
                .iter()
                .find(|route| route.key == key)
                .copied())
        }

        fn create(&mut self, route: Route) -> Result<Route, Error> {
            self.adds += 1;
            self.installed.push(route);
            Ok(route)
        }

        fn receipt_state(
            &mut self,
            receipt: &Route,
        ) -> Result<crate::connection::routes::Presence, Error> {
            use crate::connection::routes::Presence;
            Ok(if self.installed.contains(receipt) {
                Presence::Owned
            } else {
                Presence::Absent
            })
        }

        fn remove(&mut self, receipt: &Route) -> Result<(), Error> {
            self.installed.retain(|route| route != receipt);
            Ok(())
        }
    }

    #[test]
    fn review_ssl_full_plan_uses_stale_on_link_prefix() {
        use crate::connection::{macos::routing::TunnelPlan, routes::ppp_networks};

        let direct = Record {
            key: Key {
                network: "192.0.2.0/24".parse().unwrap(),
                scope: 0,
            },
            interface: 7,
            flags: libc::RTF_UP,
            gateway: None,
            source: None,
        };
        let old = direct.route().unwrap();
        let before = Snapshot {
            records: vec![direct.clone()],
        };
        let mut egress = Egress {
            profile: "review-fixture".into(),
            host: "192.0.2.90".into(),
            port: 443,
            interface: Interface {
                name: "review-fixture".into(),
                index: 7,
                flags: libc::IFF_UP as u32,
                addresses: ["192.0.2.10".parse().unwrap()].into(),
            },
            gateway: "192.0.2.90".parse().unwrap(),
            next_hop: old.next_hop,
            observed_key: observed_key(&before, old),
            source: direct.source,
        };
        assert_eq!(egress.observed_key, Some(old.key));
        assert_eq!(egress.transport_default(), Ok(None));
        let fallback = Record {
            key: Key {
                network: "0.0.0.0/0".parse().unwrap(),
                ..direct.key
            },
            ..direct.clone()
        };
        assert!(fallback.key.network.contains(egress.gateway.into()));
        assert_eq!(fallback.route().unwrap().next_hop, old.next_hop);
        let full = ppp_networks(&[], 3, true, false, Some(4)).unwrap();
        let owner = Owner {
            uid: 501,
            profile: "review-fixture".into(),
            generation: 1,
        };
        let mut routes = Coordinator::new(RouteFixture::default()).unwrap();
        for (name, records) in [
            ("only /0", vec![fallback]),
            ("missing", vec![]),
            ("duplicate", vec![direct.clone(), direct.clone()]),
            (
                "different interface",
                vec![Record {
                    interface: 8,
                    ..direct.clone()
                }],
            ),
            (
                "different next hop",
                vec![Record {
                    flags: direct.flags | libc::RTF_BLACKHOLE,
                    ..direct
                }],
            ),
        ] {
            let result =
                acquire_ssl_routes(&mut routes, owner.clone(), &full, Some(&egress), || {
                    Ok(Snapshot { records })
                });
            assert_eq!(
                result.as_ref().err().map(|error| error.reason),
                Some(Error::Conflict),
                "{name}: {result:?}"
            );
            assert!(
                routes.backend_mut().adds == 0,
                "{name}: ADD before conflict"
            );
        }

        let lease = acquire_ssl_routes(&mut routes, owner.clone(), &full, Some(&egress), || {
            Ok(before)
        })
        .unwrap();
        assert_eq!(routes.backend_mut().installed, full);
        assert_eq!(routes.release(lease).unwrap().removed, full.len());

        let split = ppp_networks(&["10.0.0.0/8".into()], 3, true, false, None).unwrap();
        let lease = acquire_ssl_routes(&mut routes, owner.clone(), &split, Some(&egress), || {
            panic!("split has no on-link proof dependency")
        })
        .unwrap();
        assert_eq!(routes.release(lease).unwrap().removed, split.len());

        egress.next_hop = NextHop::Gateway(Address::unscoped("192.0.2.1".parse().unwrap()));
        let (scoped, default) = TunnelPlan::prepare(
            &[],
            (true, false),
            || egress.transport_default(),
            |plan| plan.bind(3, Some(4)),
        )
        .unwrap();
        assert_eq!(scoped.first(), Some(&default.unwrap().route()));
        let lease = acquire_ssl_routes(&mut routes, owner, &scoped, Some(&egress), || {
            panic!("scoped default uses the existing egress check")
        })
        .unwrap();
        assert_eq!(routes.release(lease).unwrap().removed, scoped.len());
        assert!(routes.backend_mut().installed.is_empty());
    }

    #[test]
    fn ssl_route_proof_requires_the_selected_snapshot_key_and_interface() {
        let mut record = Record {
            key: Key {
                network: "192.0.2.0/24".parse().unwrap(),
                scope: 7,
            },
            interface: 7,
            flags: libc::RTF_UP | libc::RTF_IFSCOPE,
            gateway: None,
            source: None,
        };
        let selected = record.route().unwrap();
        let mut snapshot = Snapshot {
            records: vec![record.clone()],
        };
        assert_eq!(observed_key(&snapshot, selected), Some(selected.key));
        snapshot.records.push(record.clone());
        assert_eq!(observed_key(&snapshot, selected), None);
        record.key.scope = 0;
        snapshot.records = vec![record.clone()];
        assert_eq!(observed_key(&snapshot, selected), None);
        record.key = selected.key;
        record.interface = 8;
        snapshot.records = vec![record];
        assert_eq!(observed_key(&snapshot, selected), None);
    }

    fn profile(host: &str) -> Profile {
        Profile {
            dns_domains: Vec::new(),
            id: "egress-fixture".into(),
            name: "Egress fixture".into(),
            kind: VpnKind::Ssl,
            gateway: host.into(),
            username: "fixture".into(),
            networks: vec![],
            port: 443,
            certificate: String::new(),
            probe_host: "192.0.2.1".into(),
            probe_port: 443,
            probe_method: "tcp".into(),
        }
    }
    #[test]
    fn native_route_selection_is_read_only_and_profile_bound() {
        // TEST-NET is queried only via RTM_GET, never connected to or probed.
        let profile = profile("192.0.2.200");
        let canceled = AtomicBool::new(false);
        let egress = Egress::select(&profile, &canceled, Duration::from_secs(2)).unwrap();
        assert!(egress.is_current(&profile).unwrap());
        let binding = egress.binding(&profile).unwrap();
        assert!(binding.index > 0);
        assert_eq!(binding.gateway, "192.0.2.200".parse::<Ipv4Addr>().unwrap());
        let mut other = profile.clone();
        other.port = 444;
        assert!(!egress.is_current(&other).unwrap());
        other = profile.clone();
        other.gateway = "198.51.100.200".into();
        assert!(!egress.is_current(&other).unwrap());
        other = profile.clone();
        other.id = "other-profile".into();
        assert!(!egress.is_current(&other).unwrap());
        other = profile.clone();
        other.kind = VpnKind::Ipsec;
        assert!(!egress.is_current(&other).unwrap());
    }
    #[test]
    fn local_destinations_and_canceled_gateway_work_cannot_start_a_transport() {
        for host in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            assert!(matches!(
                Egress::select(
                    &profile(host),
                    &AtomicBool::new(false),
                    Duration::from_secs(1)
                ),
                Err(Error::Invalid)
            ));
        }
        assert!(matches!(
            Egress::select(
                &profile("localhost"),
                &AtomicBool::new(true),
                Duration::from_secs(1)
            ),
            Err(Error::Canceled)
        ));
    }
}
