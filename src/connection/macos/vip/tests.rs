//! Fake-seam and SDK-layout tests.
use super::*;
use crate::connection::macos::interfaces::{Interface, Interfaces};
use crate::connection::routes::Network;
use std::collections::BTreeMap;

pub(super) struct Fake {
    pub(super) snapshots: Vec<Interfaces>,
    pub(super) calls: Vec<(String, IpAddr)>,
    pub(super) fail_on: Option<usize>,
}
impl Api for Fake {
    fn interfaces(&mut self) -> io::Result<Interfaces> {
        if self.snapshots.is_empty() {
            return Ok(Interfaces {
                entries: BTreeMap::new(),
            });
        }
        Ok(self.snapshots.remove(0))
    }
    fn assign(&mut self, name: &str, vip: IpAddr) -> io::Result<()> {
        if self.fail_on == Some(self.calls.len()) {
            return Err(io::Error::other("injected"));
        }
        self.calls.push((name.to_owned(), vip));
        Ok(())
    }
}
pub(super) fn interfaces(entries: &[(&str, u32, bool, &[&str])]) -> Interfaces {
    let mut map = BTreeMap::new();
    for (name, index, up, addresses) in entries {
        map.insert(
            (*name).to_owned(),
            Interface {
                name: (*name).to_owned(),
                index: *index,
                flags: (libc::IFF_UP as u32 * *up as u32) | libc::IFF_POINTOPOINT as u32,
                addresses: addresses.iter().map(|t| t.parse().unwrap()).collect(),
            },
        );
    }
    Interfaces { entries: map }
}
pub(super) fn target() -> Target {
    Target {
        name: "utun6".into(),
        index: 6,
    }
}
pub(super) fn expires() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
pub(super) fn ok() -> impl FnMut() -> Result<(), Error> {
    || Ok(())
}
pub(super) fn fake(snapshots: Vec<Interfaces>) -> Fake {
    Fake {
        snapshots,
        calls: Vec::new(),
        fail_on: None,
    }
}

#[test]
fn both_families_are_written_in_order_and_verified_after_each() {
    let v4: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: IpAddr = "2001:db8::10".parse().unwrap();
    let mut fake = fake(vec![
        interfaces(&[("utun6", 6, true, &[])]),
        interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
        interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
        interfaces(&[("utun6", 6, true, &["192.0.2.10", "2001:db8::10"])]),
    ]);
    assign(
        &mut fake,
        &target(),
        &[v4, v6],
        expires(),
        &AtomicBool::new(false),
        &mut ok(),
    )
    .unwrap();
    assert_eq!(fake.calls, vec![("utun6".into(), v4), ("utun6".into(), v6)]);
}

#[test]
fn existing_vip_anywhere_including_owned_index_is_denied_with_zero_writes() {
    for entry in [
        interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
        interfaces(&[("utun6", 6, true, &[]), ("ppp0", 9, true, &["192.0.2.10"])]),
    ] {
        let mut fake = fake(vec![entry]);
        let v4 = "192.0.2.10".parse().unwrap();
        assert_eq!(
            assign(
                &mut fake,
                &target(),
                &[v4],
                expires(),
                &AtomicBool::new(false),
                &mut ok()
            ),
            Err(Error::Busy)
        );
        assert!(fake.calls.is_empty());
    }
}

#[test]
fn missing_name_low_flags_or_wrong_index_is_refused() {
    for entry in [
        interfaces(&[("utun7", 6, true, &[])]),
        interfaces(&[("utun6", 7, true, &[])]),
        interfaces(&[("utun6", 6, false, &[])]),
    ] {
        let mut fake = fake(vec![entry]);
        let v4 = "192.0.2.10".parse().unwrap();
        assert_eq!(
            assign(
                &mut fake,
                &target(),
                &[v4],
                expires(),
                &AtomicBool::new(false),
                &mut ok()
            ),
            Err(Error::Changed)
        );
        assert!(fake.calls.is_empty());
    }
}

#[test]
fn cancel_and_deadline_deny_before_any_write() {
    let v4: IpAddr = "192.0.2.10".parse().unwrap();
    let mut fake = fake(vec![interfaces(&[("utun6", 6, true, &[])])]);
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4],
            expires(),
            &AtomicBool::new(true),
            &mut ok()
        ),
        Err(Error::Canceled)
    );
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4],
            Instant::now(),
            &AtomicBool::new(false),
            &mut ok()
        ),
        Err(Error::Timeout)
    );
    assert!(fake.calls.is_empty());
}

#[test]
fn current_check_failure_denies_before_any_write() {
    let mut fake = fake(vec![interfaces(&[("utun6", 6, true, &[])])]);
    let mut stale = || Err(Error::Changed);
    let v4 = "192.0.2.10".parse().unwrap();
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4],
            expires(),
            &AtomicBool::new(false),
            &mut stale
        ),
        Err(Error::Changed)
    );
    assert!(fake.calls.is_empty());
}

#[test]
fn missing_readback_after_a_write_is_refused() {
    let v4: IpAddr = "192.0.2.10".parse().unwrap();
    let mut fake = fake(vec![
        interfaces(&[("utun6", 6, true, &[])]),
        interfaces(&[("utun6", 6, true, &[])]),
    ]);
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4],
            expires(),
            &AtomicBool::new(false),
            &mut ok()
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(fake.calls.len(), 1);
}

#[test]
fn second_family_failure_keeps_the_first_write_and_reports_the_intent() {
    let v4: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: IpAddr = "2001:db8::10".parse().unwrap();
    let mut fake = Fake {
        snapshots: vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
            interfaces(&[("utun6", 6, true, &["192.0.2.10"])]),
        ],
        calls: Vec::new(),
        fail_on: Some(1),
    };
    assert_eq!(
        assign(
            &mut fake,
            &target(),
            &[v4, v6],
            expires(),
            &AtomicBool::new(false),
            &mut ok()
        ),
        Err(Error::Unavailable)
    );
    assert_eq!(fake.calls, vec![("utun6".into(), v4)]);
}

#[test]
fn candidate_metadata_rules_are_exact() {
    let v4: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: IpAddr = "2001:db8::10".parse().unwrap();
    assert_eq!(validate_candidate(&candidate(&[v4])), Ok(vec![v4]));
    assert_eq!(validate_candidate(&candidate(&[v4, v6])), Ok(vec![v4, v6]));
    let mut inactive = candidate(&[v4]);
    inactive.active = false;
    assert_eq!(validate_candidate(&inactive), Err(Error::Invalid));
    let mut zero = candidate(&[v4]);
    zero.spi_in = 0;
    assert_eq!(validate_candidate(&zero), Err(Error::Invalid));
    assert_eq!(validate_candidate(&candidate(&[])), Err(Error::Invalid));
    assert_eq!(
        validate_candidate(&candidate(&[v4, v4])),
        Err(Error::Invalid)
    );
    for bad in ["0.0.0.0", "127.0.0.1", "169.254.1.1", "fe80::1"] {
        assert_eq!(
            validate_candidate(&candidate(&[bad.parse().unwrap()])),
            Err(Error::Invalid)
        );
    }
    let mut wrong = candidate(&[v4]);
    wrong.local_ts = vec![Network::new("192.0.2.0".parse().unwrap(), 24).unwrap()];
    assert_eq!(validate_candidate(&wrong), Err(Error::Invalid));
    let mut extra = candidate(&[v4]);
    extra.local_ts.push(Network::host(v6));
    assert_eq!(validate_candidate(&extra), Err(Error::Invalid));
}

fn candidate(vips: &[IpAddr]) -> Candidate {
    Candidate {
        ike_id: 1,
        child_id: 2,
        reqid: 3,
        local: "198.51.100.1".parse().unwrap(),
        remote: "198.51.100.2".parse().unwrap(),
        local_port: 500,
        remote_port: 500,
        udp_encap: false,
        spi_in: 0x1111,
        spi_out: 0x2222,
        local_ts: vips.iter().copied().map(Network::host).collect(),
        remote_ts: vec![Network::new("203.0.113.0".parse().unwrap(), 24).unwrap()],
        vips: vips.to_vec(),
        active: true,
    }
}
