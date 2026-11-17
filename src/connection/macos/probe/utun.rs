//! Owned IPsec utun probe. Reuses the SSL probe loop (`run_until`/`finish`)
//! with an IPsec link that holds the typed pin and the original producer
//! context.
use super::{Kind, Link, Outcome, failure_or, run_until};
use crate::{
    connection::{
        ipsec::NativeContext,
        macos::{
            interfaces::Interface,
            vip::{ConfiguredUtun, Family},
        },
        routes::Owner,
    },
    model::{Profile, VpnKind},
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Probe the owned IPsec utun. `link` is the opaque typed pin and `producer` is
/// the original context/owner whose repeat observation proves the child is
/// still alive; the helper pin alone does not. One absolute deadline is
/// created here, before the first pin validation, and is shared by the
/// `UtunLink` origin observation and the run core (no fresh `now + timeout`).
pub fn probe_utun(
    link: &ConfiguredUtun<'_>,
    producer: (&NativeContext<'_>, &Owner),
    profile: &Profile,
    canceled: &Arc<AtomicBool>,
    timeout: Duration,
) -> Outcome {
    if profile.validate().is_err()
        || profile.kind != VpnKind::Ipsec
        || timeout.is_zero()
        || timeout > Duration::from_secs(30)
    {
        return Outcome::InvalidTarget;
    }
    // The single total deadline starts before the first pin validation. The
    // synchronous validate/interface read cannot be interrupted; the budget is
    // checked immediately afterwards and nothing else runs after known expiry.
    let Some(expires) = Instant::now().checked_add(timeout) else {
        return Outcome::InvalidTarget;
    };
    if canceled.load(Ordering::Acquire) {
        return Outcome::Canceled;
    }
    if link.validate().is_err() {
        return failure_or(canceled.as_ref(), expires, Outcome::InvalidLink);
    }
    // Recheck the shared cancel and the total deadline after the pin work and
    // before building the private view or permitting any traffic.
    if canceled.load(Ordering::Acquire) {
        return Outcome::Canceled;
    }
    if Instant::now() >= expires {
        return Outcome::Unresponsive;
    }
    let mut addresses = BTreeSet::new();
    for family in [Family::V4, Family::V6] {
        if let Some(vip) = link.vip(family) {
            addresses.insert(vip);
        }
    }
    let interface = Interface {
        name: link.name().to_owned(),
        index: link.index(),
        flags: libc::IFF_UP as u32 | libc::IFF_POINTOPOINT as u32,
        addresses,
    };
    let utun = UtunLink {
        interface,
        link,
        context: producer.0,
        owner: producer.1,
        expires,
        cancel: canceled.clone(),
    };
    run_until(&utun, profile, canceled.as_ref(), expires, false)
}

struct UtunLink<'w, 'v, 'c> {
    interface: Interface,
    link: &'w ConfiguredUtun<'v>,
    context: &'w NativeContext<'c>,
    owner: &'w Owner,
    expires: Instant,
    cancel: Arc<AtomicBool>,
}

impl Link for UtunLink<'_, '_, '_> {
    fn interface(&self) -> &Interface {
        &self.interface
    }

    /// Both authorities must hold: the typed pin *and* the fresh observation of
    /// the original child through the original context, on the pinned name and
    /// index. A pinned interface that outlives charon is not alive. The shared
    /// total deadline and cancel are checked before the pin work; the caller's
    /// checked_current gate reclassifies cancel/expiry after it.
    fn current(&self) -> bool {
        if Instant::now() >= self.expires || self.cancel.load(Ordering::Acquire) {
            return false;
        }
        if self.link.validate().is_err() {
            return false;
        }
        let Some(deadline) = Instant::now().checked_add(Duration::from_secs(1)) else {
            return false;
        };
        match self.context.observe_interface(
            self.owner,
            deadline.min(self.expires),
            self.cancel.clone(),
        ) {
            Ok(observed) => {
                observed.name() == self.link.name() && observed.index() == self.link.index()
            }
            Err(_) => false,
        }
    }

    fn kind(&self) -> Kind {
        Kind::Ipsec
    }
}
