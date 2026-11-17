use super::{Error, Key, Network, NextHop, Route};
use std::collections::BTreeSet;

/// Empty networks mean full tunnel, including suppression of an unsupported
/// IP family. Defaults are expanded into /1 pairs rather than replacing /0.
/// The caller supplies a retained sink only when a family needs blocking.
/// Transport egress must be fixed before acquiring these networks.
pub fn ppp_networks(
    networks: &[String],
    interface: u16,
    ipv4: bool,
    ipv6: bool,
    sink: Option<u16>,
) -> Result<Vec<Route>, Error> {
    PppPlan::new(networks, ipv4, ipv6)?.bind(interface, sink)
}

pub(crate) struct PppPlan {
    routes: Vec<(Network, NextHop)>,
}

impl PppPlan {
    pub(crate) fn new(networks: &[String], ipv4: bool, ipv6: bool) -> Result<Self, Error> {
        if (!ipv4 && !ipv6) || networks.len() > 64 {
            return Err(Error::Invalid);
        }
        let full = networks.is_empty();
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        let networks = if full {
            vec!["0.0.0.0/0".into(), "::/0".into()]
        } else {
            networks.to_vec()
        };
        for text in networks {
            let network: Network = text.parse()?;
            let supported = if network.address().is_ipv4() {
                ipv4
            } else {
                ipv6
            };
            if !full && !supported {
                return Err(Error::Invalid);
            }
            let disposition = if supported {
                NextHop::Interface
            } else {
                NextHop::Blackhole
            };
            let expanded = if network.prefix() == 0 {
                if network.address().is_ipv4() {
                    vec!["0.0.0.0/1".parse()?, "128.0.0.0/1".parse()?]
                } else {
                    vec!["::/1".parse()?, "8000::/1".parse()?]
                }
            } else {
                vec![network]
            };
            for network in expanded {
                if seen.insert(network) {
                    result.push((network, disposition));
                }
            }
        }
        Ok(Self { routes: result })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn sink_ipv4(&self) -> Option<bool> {
        self.routes.iter().find_map(|&(network, next_hop)| {
            (next_hop != NextHop::Interface).then_some(network.address().is_ipv4())
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn networks(&self) -> impl Iterator<Item = Network> + '_ {
        self.routes.iter().map(|&(network, _)| network)
    }

    pub(crate) fn bind(self, interface: u16, sink: Option<u16>) -> Result<Vec<Route>, Error> {
        if interface == 0 || sink.is_some_and(|sink| sink == 0 || sink == interface) {
            return Err(Error::Invalid);
        }
        self.routes
            .into_iter()
            .map(|(network, next_hop)| {
                let interface = if next_hop != NextHop::Interface {
                    sink.ok_or(Error::Invalid)?
                } else {
                    interface
                };
                Ok(Route {
                    key: Key { network, scope: 0 },
                    interface,
                    next_hop,
                })
            })
            .collect()
    }
}
