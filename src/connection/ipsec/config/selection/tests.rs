use super::{Config, Error};
use crate::{
    connection::{
        ipsec::{Candidate, Observer, Registry},
        routes::{Network, Owner},
    },
    model::{Profile, VpnKind},
};
use std::collections::BTreeSet;

struct Empty;

impl Observer for Empty {
    fn occupied(&mut self) -> Result<BTreeSet<u32>, Error> {
        Ok(BTreeSet::new())
    }

    fn producer_stopped(&mut self, _: &Owner) -> Result<bool, Error> {
        Ok(true)
    }
}

fn profile(networks: &[&str]) -> Profile {
    Profile {
        id: "Selection".into(),
        name: "Selection fixture".into(),
        kind: VpnKind::Ipsec,
        gateway: "vpn.example.com".into(),
        username: "fixture@example.com".into(),
        port: 500,
        certificate: String::new(),
        networks: networks.iter().map(|network| (*network).into()).collect(),
        probe_host: "10.20.0.1".into(),
        probe_port: 8443,
        probe_method: "tcp".into(),
    }
}

fn config(networks: &[&str]) -> Config {
    let mut registry = Registry::new(Empty);
    let owner = Owner {
        uid: 502,
        profile: "Selection".into(),
        generation: 1,
    };
    let reservation = registry.reserve(owner).unwrap();
    Config::new(
        &registry,
        &reservation,
        &profile(networks),
        "192.0.2.2".parse().unwrap(),
        "198.51.100.3".parse().unwrap(),
    )
    .unwrap()
}

fn base(config: &Config) -> Candidate {
    Candidate {
        ike_id: 7,
        child_id: 10,
        reqid: config.reqid,
        local: config.local,
        remote: config.remote,
        local_port: 500,
        remote_port: 500,
        udp_encap: false,
        spi_in: 0x1000,
        spi_out: 0x2000,
        local_ts: vec![Network::host("10.20.0.9".parse().unwrap())],
        remote_ts: vec!["10.20.0.0/24".parse().unwrap()],
        vips: vec!["10.20.0.9".parse().unwrap()],
        active: true,
    }
}

fn dual(config: &Config) -> Candidate {
    let mut candidate = base(config);
    candidate.vips = vec!["10.20.0.9".parse().unwrap(), "2001:db8::9".parse().unwrap()];
    candidate.local_ts = vec![
        Network::host("10.20.0.9".parse().unwrap()),
        Network::host("2001:db8::9".parse().unwrap()),
    ];
    candidate.remote_ts = vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
    candidate
}

#[test]
fn compatible_rekey_overlap_picks_highest_child_id() {
    let config = config(&["10.20.0.0/24"]);
    let mut low = base(&config);
    low.child_id = 10;
    low.spi_in = 1;
    low.spi_out = 2;
    let mut high = base(&config);
    high.child_id = 20;
    high.spi_in = 3;
    high.spi_out = 4;
    high.vips.reverse();
    high.local_ts.reverse();
    high.remote_ts.reverse();
    assert_eq!(config.select(&[low, high]).unwrap().child_id, 20);
}

#[test]
fn incompatible_active_after_a_valid_first_is_changed() {
    let config = config(&["10.20.0.0/24"]);
    let mut bad = base(&config);
    bad.child_id = 11;
    bad.spi_in = 5;
    bad.spi_out = 6;
    bad.udp_encap = true;
    assert_eq!(
        config.select(&[base(&config), bad]).err(),
        Some(Error::Changed)
    );
}

#[test]
fn duplicate_child_ids_or_spis_are_refused() {
    let config = config(&["10.20.0.0/24"]);
    let first = base(&config);
    let mut same_child = base(&config);
    same_child.spi_in = 5;
    same_child.spi_out = 6;
    assert_eq!(
        config.select(&[first, same_child]).err(),
        Some(Error::Invalid)
    );
    let first = base(&config);
    let mut same_in = base(&config);
    same_in.child_id = 11;
    assert_eq!(config.select(&[first, same_in]).err(), Some(Error::Invalid));
    let first = base(&config);
    let mut same_out = base(&config);
    same_out.child_id = 12;
    same_out.spi_in = 7;
    assert_eq!(
        config.select(&[first, same_out]).err(),
        Some(Error::Invalid)
    );
}

#[test]
fn no_active_candidate_is_busy() {
    let config = config(&["10.20.0.0/24"]);
    let mut inactive = base(&config);
    inactive.active = false;
    assert_eq!(config.select(&[inactive]).err(), Some(Error::Busy));
}

#[test]
fn inactive_rekeyed_snapshot_is_ignored() {
    let config = config(&["10.20.0.0/24"]);
    let mut old = base(&config);
    old.active = false;
    old.remote = "203.0.113.9".parse().unwrap();
    old.udp_encap = true;
    assert_eq!(config.select(&[old, base(&config)]).unwrap().child_id, 10);
}

#[test]
fn changed_endpoint_or_reqid_is_changed() {
    let config = config(&["10.20.0.0/24"]);
    let mut remote = base(&config);
    remote.remote = "198.51.100.4".parse().unwrap();
    assert_eq!(config.select(&[remote]).err(), Some(Error::Changed));
    let mut reqid = base(&config);
    reqid.reqid = config.reqid.wrapping_add(1);
    assert_eq!(config.select(&[reqid]).err(), Some(Error::Changed));
}

#[test]
fn wrong_vip_or_selector_metadata_is_refused() {
    let config = config(&["10.20.0.0/24"]);
    let mut vip = base(&config);
    vip.vips = vec!["10.20.0.10".parse().unwrap()];
    assert_eq!(config.select(&[vip]).err(), Some(Error::Invalid));
    let mut family = base(&config);
    family.vips = vec!["10.20.0.9".parse().unwrap(), "2001:db8::9".parse().unwrap()];
    family.local_ts = vec![
        Network::host("10.20.0.9".parse().unwrap()),
        Network::host("2001:db8::9".parse().unwrap()),
    ];
    assert_eq!(config.select(&[family]).err(), Some(Error::Invalid));
    let mut same_family = base(&config);
    same_family.vips = vec!["10.20.0.9".parse().unwrap(), "10.20.0.10".parse().unwrap()];
    same_family.local_ts = vec![
        Network::host("10.20.0.9".parse().unwrap()),
        Network::host("10.20.0.10".parse().unwrap()),
    ];
    assert_eq!(config.select(&[same_family]).err(), Some(Error::Invalid));
}

#[test]
fn full_dual_and_absent_family_plans() {
    let config = config(&[]);
    assert_eq!(config.networks, vec!["0.0.0.0/0", "::/0"]);
    assert_eq!(config.select(&[dual(&config)]).unwrap().child_id, 10);
    assert!(config.route_networks(&dual(&config)).unwrap().is_empty());
    let mut partial = dual(&config);
    partial.remote_ts = vec!["0.0.0.0/0".parse().unwrap(), "::/1".parse().unwrap()];
    assert_eq!(config.route_networks(&partial).err(), Some(Error::Changed));
    let mut v4 = base(&config);
    v4.remote_ts = vec!["0.0.0.0/0".parse().unwrap()];
    assert!(config.route_networks(&v4).unwrap().is_empty());
}

#[test]
fn explicit_union_covers_and_partial_is_rejected() {
    let config = config(&["10.20.0.0/24"]);
    let mut split = base(&config);
    split.remote_ts = vec![
        "10.20.0.0/25".parse().unwrap(),
        "10.20.0.128/25".parse().unwrap(),
    ];
    assert_eq!(config.route_networks(&split).unwrap(), vec!["10.20.0.0/24"]);
    let mut gap = base(&config);
    gap.remote_ts = vec!["10.20.0.0/25".parse().unwrap()];
    assert_eq!(config.route_networks(&gap).err(), Some(Error::Changed));
}

#[test]
fn half_selectors_cover_zero_without_overflow() {
    let config = config(&["0.0.0.0/0"]);
    let mut candidate = base(&config);
    candidate.remote_ts = vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()];
    assert_eq!(
        config.route_networks(&candidate).unwrap(),
        vec!["0.0.0.0/0"]
    );
}

#[test]
fn v6_maximum_address_boundary_is_covered() {
    let config = config(&["::/0"]);
    let mut candidate = base(&config);
    candidate.vips = vec!["2001:db8::9".parse().unwrap()];
    candidate.local_ts = vec![Network::host("2001:db8::9".parse().unwrap())];
    candidate.remote_ts = vec!["::/1".parse().unwrap(), "8000::/1".parse().unwrap()];
    assert_eq!(config.route_networks(&candidate).unwrap(), vec!["::/0"]);
}

#[test]
fn explicit_request_without_its_vip_family_is_changed() {
    let config = config(&["10.20.0.0/24", "2001:db8:1::/48"]);
    assert_eq!(
        config.route_networks(&base(&config)).err(),
        Some(Error::Changed)
    );
}

#[test]
fn route_networks_revalidates_untrusted_metadata() {
    let config = config(&["10.20.0.0/24"]);
    let mut inactive = base(&config);
    inactive.active = false;
    assert_eq!(config.route_networks(&inactive).err(), Some(Error::Changed));
    let mut forged = base(&config);
    forged.local_ts = vec![Network::host("10.20.0.10".parse().unwrap())];
    assert_eq!(config.route_networks(&forged).err(), Some(Error::Invalid));
    let mut outside = base(&config);
    outside.remote_ts = vec!["192.168.0.0/24".parse().unwrap()];
    assert_eq!(config.select(&[outside]).err(), Some(Error::Invalid));
    for vip in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "fe80::1"] {
        let mut bad = base(&config);
        let ip: std::net::IpAddr = vip.parse().unwrap();
        bad.vips = vec![ip];
        bad.local_ts = vec![Network::host(ip)];
        assert_eq!(config.select(&[bad]).err(), Some(Error::Invalid), "{vip}");
    }
    let mut bound = base(&config);
    bound.reqid = 1;
    assert_eq!(config.route_networks(&bound).err(), Some(Error::Changed));
}
