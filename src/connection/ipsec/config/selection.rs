//! Pure metadata policy: select a negotiated attempt and derive the exact
//! route coverage visible to the Driver. No native authority, traffic proof or
//! `Connected` state is inferred, and no caller string is mutated.
use super::{Config, Error};
use crate::connection::{ipsec::Candidate, routes::Network};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

impl Config {
    /// Refuse partial/ambiguous metadata before the Driver prepares any VIP or
    /// route. Inactive (old REKEYED) candidates are ignored entirely.
    pub fn select<'a>(&self, candidates: &'a [Candidate]) -> Result<&'a Candidate, Error> {
        let mut chosen: Option<&Candidate> = None;
        let mut reference: Option<&Candidate> = None;
        let mut child_ids = BTreeSet::new();
        let mut spi_in = BTreeSet::new();
        let mut spi_out = BTreeSet::new();
        for candidate in candidates.iter().filter(|candidate| candidate.active) {
            self.validate_candidate(candidate)?;
            if !child_ids.insert(candidate.child_id)
                || !spi_in.insert(candidate.spi_in)
                || !spi_out.insert(candidate.spi_out)
            {
                return Err(Error::Invalid);
            }
            if let Some(first) = reference {
                if !same_overlap(first, candidate) {
                    return Err(Error::Changed);
                }
            } else {
                reference = Some(candidate);
            }
            if chosen.is_none_or(|current| candidate.child_id > current.child_id) {
                chosen = Some(candidate);
            }
        }
        chosen.ok_or(Error::Busy)
    }

    /// Revalidate one candidate independently (the caller may hold forged
    /// metadata) and return the exact route plan strings. Full tunnel returns
    /// an empty plan so the existing missing-family sink contract is preserved.
    pub fn route_networks(&self, candidate: &Candidate) -> Result<Vec<String>, Error> {
        self.validate_candidate(candidate)?;
        let requested = self.requested_networks()?;
        let hosts: BTreeSet<bool> = candidate.vips.iter().map(|ip| ip.is_ipv4()).collect();
        if is_full_tunnel(&requested) {
            for family in hosts {
                let family_remote = family_networks(&candidate.remote_ts, family);
                let full: Network = if family { "0.0.0.0/0" } else { "::/0" }
                    .parse()
                    .map_err(|_| Error::Invalid)?;
                if !covers(&family_remote, full) {
                    return Err(Error::Changed);
                }
            }
            return Ok(Vec::new());
        }
        for network in &requested {
            let family = network.address().is_ipv4();
            if !hosts.contains(&family) {
                return Err(Error::Changed);
            }
            if !covers(&family_networks(&candidate.remote_ts, family), *network) {
                return Err(Error::Changed);
            }
        }
        Ok(self.networks.clone())
    }

    fn validate_candidate(&self, candidate: &Candidate) -> Result<(), Error> {
        if !candidate.active {
            return Err(Error::Changed);
        }
        if candidate.reqid != self.reqid
            || candidate.local != self.local
            || candidate.remote != self.remote
            || candidate.local.is_ipv4() != candidate.remote.is_ipv4()
        {
            return Err(Error::Changed);
        }
        if candidate.ike_id == 0
            || candidate.child_id == 0
            || candidate.spi_in == 0
            || candidate.spi_out == 0
            || candidate.local_port == 0
            || candidate.remote_port == 0
        {
            return Err(Error::Invalid);
        }
        if candidate.vips.is_empty() || candidate.vips.len() > 2 {
            return Err(Error::Invalid);
        }
        let mut families = BTreeSet::new();
        for vip in &candidate.vips {
            if !families.insert(vip.is_ipv4()) || !usable(*vip) {
                return Err(Error::Invalid);
            }
        }
        // local_ts is exactly the host selector of each negotiated VIP.
        let expected: BTreeSet<Network> =
            candidate.vips.iter().map(|ip| Network::host(*ip)).collect();
        let local: BTreeSet<Network> = candidate.local_ts.iter().copied().collect();
        if local.len() != candidate.local_ts.len() || local != expected {
            return Err(Error::Invalid);
        }
        // remote_ts is nonempty, deduplicated and bounded by the request.
        if candidate.remote_ts.is_empty() {
            return Err(Error::Invalid);
        }
        let remote: BTreeSet<Network> = candidate.remote_ts.iter().copied().collect();
        if remote.len() != candidate.remote_ts.len() {
            return Err(Error::Invalid);
        }
        let allowed = self.requested_networks()?;
        if !remote.iter().all(|selector| {
            allowed.iter().any(|network| {
                network.address().is_ipv4() == selector.address().is_ipv4()
                    && network.prefix() <= selector.prefix()
                    && network.contains(selector.address())
            })
        }) {
            return Err(Error::Invalid);
        }
        let family_set = |networks: &[Network]| {
            networks
                .iter()
                .map(|network| network.address().is_ipv4())
                .collect::<BTreeSet<_>>()
        };
        if family_set(&candidate.local_ts) != family_set(&candidate.remote_ts) {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn requested_networks(&self) -> Result<Vec<Network>, Error> {
        self.networks
            .iter()
            .map(|network| network.parse().map_err(|_| Error::Invalid))
            .collect()
    }
}

fn same_overlap(first: &Candidate, other: &Candidate) -> bool {
    let set = |values: &[IpAddr]| values.iter().copied().collect::<BTreeSet<_>>();
    let networks = |values: &[Network]| values.iter().copied().collect::<BTreeSet<_>>();
    first.ike_id == other.ike_id
        && first.reqid == other.reqid
        && first.local == other.local
        && first.remote == other.remote
        && first.local_port == other.local_port
        && first.remote_port == other.remote_port
        && first.udp_encap == other.udp_encap
        && set(&first.vips) == set(&other.vips)
        && networks(&first.local_ts) == networks(&other.local_ts)
        && networks(&first.remote_ts) == networks(&other.remote_ts)
}

fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
        && !ip.is_loopback()
        && !matches!(ip, IpAddr::V6(value) if value.is_unicast_link_local())
}

fn is_full_tunnel(requested: &[Network]) -> bool {
    requested.len() == 2
        && requested
            .iter()
            .any(|network| network.address().is_ipv4() && network.prefix() == 0)
        && requested
            .iter()
            .any(|network| !network.address().is_ipv4() && network.prefix() == 0)
}

fn family_networks(networks: &[Network], ipv4: bool) -> Vec<Network> {
    networks
        .iter()
        .copied()
        .filter(|network| network.address().is_ipv4() == ipv4)
        .collect()
}

fn interval(network: Network) -> (u128, u128) {
    let bits: u32 = if network.address().is_ipv4() { 32 } else { 128 };
    let host = bits - u32::from(network.prefix());
    let start = match network.address() {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    };
    let end = if host == 128 {
        u128::MAX
    } else {
        start | ((1u128 << host) - 1)
    };
    (start, end)
}

fn covers(networks: &[Network], requested: Network) -> bool {
    let (start, end) = interval(requested);
    let ipv4 = requested.address().is_ipv4();
    let mut spans: Vec<(u128, u128)> = networks
        .iter()
        .copied()
        .filter(|network| network.address().is_ipv4() == ipv4)
        .map(interval)
        .collect();
    spans.sort_unstable();
    let mut cursor = start;
    for (span_start, span_end) in spans {
        if span_end < cursor {
            continue;
        }
        if span_start > cursor {
            return false;
        }
        if span_end >= end {
            return true;
        }
        cursor = span_end + 1;
    }
    false
}

#[cfg(test)]
mod tests;
