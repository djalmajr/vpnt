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
