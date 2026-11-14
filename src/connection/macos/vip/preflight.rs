//! Per-alias preflight, write and read-back. Enumerate-then-ioctl is not
//! atomic: absence is only what the fresh snapshot observed.

use super::{Api, Target, check};
use crate::connection::ipsec::Error;
use crate::connection::macos::interfaces::Interfaces;
use std::{net::IpAddr, sync::atomic::AtomicBool, time::Instant};

/// Before each alias: current/check, a fresh snapshot, target identity/flags,
/// and only the still-unwritten VIPs must be absent. Already written VIPs must
/// stay on the owned interface and nowhere else.
pub(super) fn assign<A: Api, F: FnMut() -> Result<(), Error>>(
    api: &mut A,
    target: &Target,
    vips: &[IpAddr],
    expires: Instant,
    cancel: &AtomicBool,
    current: &mut F,
) -> Result<(), Error> {
    for (index, &vip) in vips.iter().enumerate() {
        current()?;
        check(expires, cancel)?;
        let snapshot = api.interfaces().map_err(|_| Error::Unavailable)?;
        check(expires, cancel)?;
        preflight_next(&snapshot, target, &vips[..index], &vips[index..])?;
        check(expires, cancel)?;
        current()?;
        check(expires, cancel)?;
        api.assign(&target.name, vip)
            .map_err(|_| Error::Unavailable)?;
        check(expires, cancel)?;
        let after = api.interfaces().map_err(|_| Error::Unavailable)?;
        check(expires, cancel)?;
        verify(&after, target, &vips[..=index])?;
    }
    Ok(())
}

/// One target predicate for preflight, post-write verify and public health.
fn owned_target<'a>(
    interfaces: &'a Interfaces,
    target: &Target,
) -> Result<&'a super::super::interfaces::Interface, Error> {
    let owned = interfaces.entries.get(&target.name).ok_or(Error::Changed)?;
    if owned.index != target.index
        || owned.flags & (libc::IFF_UP as u32 | libc::IFF_POINTOPOINT as u32)
            != libc::IFF_UP as u32 | libc::IFF_POINTOPOINT as u32
    {
        return Err(Error::Changed);
    }
    Ok(owned)
}

fn preflight_next(
    interfaces: &Interfaces,
    target: &Target,
    written: &[IpAddr],
    pending: &[IpAddr],
) -> Result<(), Error> {
    let owned = owned_target(interfaces, target)?;
    for vip in written {
        if !owned.addresses.contains(vip) {
            return Err(Error::Changed);
        }
        if foreign_has(interfaces, target, *vip) {
            return Err(Error::Busy);
        }
    }
    if interfaces
        .entries
        .values()
        .any(|interface| pending.iter().any(|vip| interface.addresses.contains(vip)))
    {
        return Err(Error::Busy);
    }
    Ok(())
}

pub(super) fn verify(
    interfaces: &Interfaces,
    target: &Target,
    expected: &[IpAddr],
) -> Result<(), Error> {
    let owned = owned_target(interfaces, target)?;
    for vip in expected {
        if !owned.addresses.contains(vip) {
            return Err(Error::Unavailable);
        }
        if foreign_has(interfaces, target, *vip) {
            return Err(Error::Busy);
        }
    }
    Ok(())
}

fn foreign_has(interfaces: &Interfaces, target: &Target, vip: IpAddr) -> bool {
    interfaces
        .entries
        .iter()
        .any(|(name, interface)| name != &target.name && interface.addresses.contains(&vip))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Fake, expires, fake, interfaces, ok, target};
    use super::*;

    fn run(fake: &mut Fake, vips: &[&str]) -> Result<(), Error> {
        let vips: Vec<IpAddr> = vips.iter().map(|text| text.parse().unwrap()).collect();
        assign(
            fake,
            &target(),
            &vips,
            expires(),
            &AtomicBool::new(false),
            &mut ok(),
        )
    }

    // Mutation: skip the per-alias preflight (one preflight before the loop),
    // so a VIP that appears foreign before the second write is not refused.
    #[test]
    fn second_vip_appearing_foreign_before_its_write_is_refused_with_one_call() {
        let mut fake = fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[
                ("utun6", 6, true, &["192.0.2.10"]),
                ("ppp0", 9, true, &["2001:db8::10"]),
            ]),
            interfaces(&[
                ("utun6", 6, true, &["192.0.2.10"]),
                ("ppp0", 9, true, &["2001:db8::10"]),
            ]),
        ]);
        assert_eq!(
            run(&mut fake, &["192.0.2.10", "2001:db8::10"]),
            Err(Error::Busy)
        );
        assert_eq!(fake.calls.len(), 1);
    }

    // Same mutation: a pending VIP already present on the owned interface.
    #[test]
    fn second_vip_appearing_on_owned_before_its_write_is_refused_with_one_call() {
        let mut fake = fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[("utun6", 6, true, &["192.0.2.10", "2001:db8::10"])]),
            interfaces(&[("utun6", 6, true, &["192.0.2.10", "2001:db8::10"])]),
        ]);
        assert_eq!(
            run(&mut fake, &["192.0.2.10", "2001:db8::10"]),
            Err(Error::Busy)
        );
        assert_eq!(fake.calls.len(), 1);
    }

    // Mutation: skip the foreign scan in the post-write verify.
    #[test]
    fn written_vip_duplicated_foreign_after_the_write_is_refused() {
        let mut fake = fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[
                ("utun6", 6, true, &["192.0.2.10"]),
                ("ppp0", 9, true, &["192.0.2.10"]),
            ]),
        ]);
        assert_eq!(run(&mut fake, &["192.0.2.10"]), Err(Error::Busy));
        assert_eq!(fake.calls.len(), 1);
    }

    // Mutation: drop the target flags check in the per-alias preflight.
    #[test]
    fn flags_down_between_two_writes_is_changed_without_a_second_call() {
        let mut fake = fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[("utun6", 6, false, &["192.0.2.10"])]),
            interfaces(&[("utun6", 6, false, &["192.0.2.10"])]),
            interfaces(&[("utun6", 6, false, &["192.0.2.10", "2001:db8::10"])]),
        ]);
        assert_eq!(
            run(&mut fake, &["192.0.2.10", "2001:db8::10"]),
            Err(Error::Changed)
        );
        assert_eq!(fake.calls.len(), 1);

        // Flags down after the LAST write: the post-write/health verify must
        // refuse instead of accepting the snapshot on index alone.
        let mut last = super::super::tests::fake(vec![
            interfaces(&[("utun6", 6, true, &[])]),
            interfaces(&[("utun6", 6, false, &["192.0.2.10"])]),
        ]);
        assert_eq!(run(&mut last, &["192.0.2.10"]), Err(Error::Changed));
        assert_eq!(last.calls.len(), 1);
    }
}
