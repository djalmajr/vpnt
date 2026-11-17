use super::{Config, Error};
use crate::{
    connection::routes::Network,
    helper::vici::{CommandResult, Message},
};
use std::{collections::BTreeSet, net::IpAddr};
mod fields;
use fields::*;

/// Daemon-reported metadata to join with native observations. These fields
/// grant no authority to add/delete kernel resources and prove no traffic.
#[derive(Debug, Eq, PartialEq)]
pub struct Candidate {
    pub ike_id: u32,
    pub child_id: u32,
    pub reqid: u16,
    pub local: IpAddr,
    pub remote: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub udp_encap: bool,
    pub spi_in: u32,
    pub spi_out: u32,
    pub local_ts: Vec<Network>,
    pub remote_ts: Vec<Network>,
    pub vips: Vec<IpAddr>,
    pub active: bool,
}

pub(super) fn parse(config: &Config, result: CommandResult) -> Result<Vec<Candidate>, Error> {
    if !result.response.is_empty() {
        return Err(Error::Invalid);
    }
    let mut ike_ids = BTreeSet::new();
    let mut child_ids = BTreeSet::new();
    let mut spis = BTreeSet::new();
    let mut output = Vec::new();
    let allowed = config
        .networks
        .iter()
        .map(|s| network(s))
        .collect::<Result<Vec<_>, _>>()?;
    for (event, root) in result.events {
        if event != "list-sa" || root.len() != 1 {
            return Err(Error::Invalid);
        }
        let ike = root.get_section(config.name()).ok_or(Error::Changed)?;
        let ike_id = number(ike, "uniqueid", false)?;
        if !ike_ids.insert(ike_id) || ike.get_text("version") != Some("2") {
            return Err(Error::Invalid);
        }
        let state = text(ike, "state")?;
        if ![
            "CREATED",
            "CONNECTING",
            "ESTABLISHED",
            "PASSIVE",
            "REKEYING",
            "REKEYED",
            "DELETING",
            "DESTROYING",
        ]
        .contains(&state)
        {
            return Err(Error::Invalid);
        }
        let local = address(text(ike, "local-host")?)?;
        let remote = address(text(ike, "remote-host")?)?;
        if local != config.local || remote != config.remote {
            return Err(Error::Changed);
        }
        let local_port = number(ike, "local-port", true)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let remote_port = number(ike, "remote-port", true)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let initiator = spi(ike, "initiator-spi", 16, true)?;
        let responder = spi(ike, "responder-spi", 16, true)?;
        let vips = vips(ike)?;
        let children = ike.get_section("child-sas").ok_or(Error::Invalid)?;
        if children.sections().count() != children.len() {
            return Err(Error::Invalid);
        }
        for (key, child) in children.sections() {
            let child_id = number(child, "uniqueid", false)?;
            if !child_ids.insert(child_id) || child_ids.len() > 256 {
                return Err(Error::Invalid);
            }
            if key != format!("{}-{child_id}", config.child_name())
                || child.get_text("name") != Some(config.child_name())
            {
                return Err(Error::Changed);
            }
            let reqid = number(child, "reqid", true)?;
            if reqid != u32::from(config.reqid) && reqid != 0 {
                return Err(Error::Changed);
            }
            if child.get_text("mode") != Some("TUNNEL") {
                return Err(Error::Invalid);
            }
            let child_state = text(child, "state")?;
            match child_state {
                "CREATED" | "ROUTED" | "INSTALLING" | "UPDATING" | "RETRYING" | "DESTROYING" => {
                    // vici_query omits installed-only fields in these states.
                    list(child, "local-ts", false)?;
                    list(child, "remote-ts", false)?;
                    continue;
                }
                "INSTALLED" | "REKEYING" | "REKEYED" | "DELETING" | "DELETED" => {}
                _ => return Err(Error::Invalid),
            }
            if reqid == 0
                || initiator == 0
                || responder == 0
                || local_port == 0
                || remote_port == 0
                || ike.get_text("initiator") != Some("yes")
            {
                return Err(Error::Invalid);
            }
            if child.get_text("protocol") != Some("ESP") {
                return Err(Error::Invalid);
            }
            let spi_in = spi(child, "spi-in", 8, false)? as u32;
            let spi_out = spi(child, "spi-out", 8, false)? as u32;
            if !spis.insert((true, spi_in)) || !spis.insert((false, spi_out)) {
                return Err(Error::Invalid);
            }
            let local_ts = selectors(child, "local-ts")?;
            let remote_ts = selectors(child, "remote-ts")?;
            if !local_ts
                .iter()
                .all(|ts| vips.iter().any(|ip| *ts == Network::host(*ip)))
            {
                return Err(Error::Invalid);
            }
            if !remote_ts.iter().all(|ts| {
                allowed
                    .iter()
                    .any(|n| n.prefix() <= ts.prefix() && n.contains(ts.address()))
            }) {
                return Err(Error::Invalid);
            }
            let families = |networks: &[Network]| {
                networks
                    .iter()
                    .map(|n| n.address().is_ipv4())
                    .collect::<BTreeSet<_>>()
            };
            if families(&local_ts) != families(&remote_ts) {
                return Err(Error::Invalid);
            }
            let udp_encap = flag(child, "encap")?;
            output.push(Candidate {
                ike_id,
                child_id,
                reqid: config.reqid,
                local,
                remote,
                local_port,
                remote_port,
                udp_encap,
                spi_in,
                spi_out,
                local_ts,
                remote_ts,
                vips: vips.clone(),
                active: matches!(state, "ESTABLISHED" | "REKEYING")
                    && matches!(child_state, "INSTALLED" | "REKEYING"),
            });
        }
    }
    Ok(output)
}
