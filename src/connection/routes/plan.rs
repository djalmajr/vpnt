use super::{Error, Key, Network, NextHop, Route};
use std::collections::BTreeSet;

/// Empty networks mean full tunnel, including suppression of an unsupported
/// IP family. Defaults are expanded into /1 pairs rather than replacing /0.
/// The caller must acquire its gateway pins before acquiring these networks.
pub fn ppp_networks(
    networks: &[String],
    interface: u16,
    ipv4: bool,
    ipv6: bool,
    loopback: u16,
) -> Result<Vec<Route>, Error> {
    if interface == 0
        || loopback == 0
        || interface == loopback
        || (!ipv4 && !ipv6)
        || networks.len() > 64
    {
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
        let index = if supported { interface } else { loopback };
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
                result.push(Route {
                    key: Key { network, scope: 0 },
                    interface: index,
                    next_hop: disposition,
                });
            }
        }
    }
    Ok(result)
}
