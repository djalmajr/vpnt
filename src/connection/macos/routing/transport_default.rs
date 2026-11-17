//! The only physical-interface route that this backend may mutate.
use super::{Error, Gateway, Key, Network, NextHop, Record, Route};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportDefault(Route);

impl TransportDefault {
    pub(crate) fn from_egress(index: u16, next_hop: NextHop) -> Result<Self, Error> {
        Self::try_from(Route {
            key: Key {
                network: Network::new(Ipv4Addr::UNSPECIFIED.into(), 0)?,
                scope: index,
            },
            interface: index,
            next_hop,
        })
    }

    pub(crate) fn for_plan(
        index: u16,
        next_hop: NextHop,
        observed_key: Option<Key>,
    ) -> Result<Option<Self>, Error> {
        if next_hop == NextHop::Interface {
            if observed_key.is_some_and(|key| {
                key.network.address().is_ipv4()
                    && key.network.prefix() > 1
                    && (key.scope == 0 || key.scope == index)
            }) {
                return Ok(None);
            }
            // SAFETY: fixed NUL-terminated format string without placeholders.
            unsafe {
                libc::syslog(
                    libc::LOG_WARNING,
                    c"vpnt: on-link transport lacks a proven IPv4 route more specific than the tunnel halves"
                        .as_ptr(),
                )
            };
            return Err(Error::Conflict);
        }
        Self::from_egress(index, next_hop).map(Some)
    }

    pub(super) fn add_to_plan(
        plan: &mut Vec<Route>,
        egress: impl FnOnce() -> Result<Option<Self>, Error>,
    ) -> Result<Option<Self>, Error> {
        let lower = Network::new(Ipv4Addr::UNSPECIFIED.into(), 1)?;
        let upper = Network::new(Ipv4Addr::new(128, 0, 0, 0).into(), 1)?;
        let has = |network| plan.iter().any(|route| route.key.network == network);
        if has(lower)
            && has(upper)
            && let Some(default) = egress()?
        {
            // The coordinator acquires in plan order and releases in reverse.
            plan.insert(0, default.0);
            return Ok(Some(default));
        }
        Ok(None)
    }

    pub(in crate::connection::macos) fn route(self) -> Route {
        self.0
    }

    pub(super) fn gateway(self) -> super::Address {
        let NextHop::Gateway(gateway) = self.0.next_hop else {
            unreachable!("transport default constructor validated the gateway");
        };
        gateway
    }

    pub(super) fn matches_static(self, record: &Record) -> bool {
        let required = libc::RTF_STATIC | libc::RTF_IFSCOPE | libc::RTF_GATEWAY;
        record.flags & required == required
            && record.gateway == Some(Gateway::Address(self.gateway()))
            && record.route() == Ok(self.0)
    }
}

impl TryFrom<Route> for TransportDefault {
    type Error = Error;

    fn try_from(route: Route) -> Result<Self, Error> {
        route.validate()?;
        if route.key.network.address() == Ipv4Addr::UNSPECIFIED
            && route.key.network.prefix() == 0
            && route.key.scope == route.interface
            && matches!(route.next_hop, NextHop::Gateway(_))
        {
            Ok(Self(route))
        } else {
            Err(Error::Invalid)
        }
    }
}

#[cfg(test)]
#[test]
fn full_plan_requires_a_more_specific_on_link_ipv4_route() {
    use crate::connection::routes::ppp_networks;
    let full = ppp_networks(&[], 3, true, true, None).unwrap();
    let mut split = ppp_networks(&["10.0.0.0/8".into()], 3, true, true, None).unwrap();
    let on_link = |network: &str| {
        let record = Record {
            key: Key {
                network: network.parse().unwrap(),
                scope: 0,
            },
            interface: 7,
            flags: libc::RTF_UP,
            gateway: None,
            source: None,
        };
        let route = record.route().unwrap();
        TransportDefault::for_plan(route.interface, route.next_hop, Some(record.key))
    };
    assert_eq!(
        TransportDefault::add_to_plan(&mut split, || on_link("0.0.0.0/0")),
        Ok(None)
    );
    let mut plan = full.clone();
    assert_eq!(
        TransportDefault::add_to_plan(&mut plan, || on_link("192.0.2.0/24")),
        Ok(None)
    );
    assert_eq!(plan, full);
    for network in ["0.0.0.0/0", "128.0.0.0/1"] {
        let mut plan = full.clone();
        assert_eq!(
            TransportDefault::add_to_plan(&mut plan, || on_link(network)),
            Err(Error::Conflict),
            "direct physical route {network}"
        );
        assert_eq!(plan, full);
    }
    assert_eq!(
        TransportDefault::add_to_plan(&mut plan, || {
            TransportDefault::for_plan(7, NextHop::Interface, None)
        }),
        Err(Error::Conflict)
    );
    assert_eq!(plan, full);
    assert_eq!(
        TransportDefault::from_egress(7, NextHop::Interface),
        Err(Error::Invalid)
    );
}
