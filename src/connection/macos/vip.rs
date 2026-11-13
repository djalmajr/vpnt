//! Private VIP assignment on the retained original utun.
//!
//! Candidate metadata is not authority. The future Driver must first bind the
//! active original owner/profile/reservation and retain its resource claim
//! before preparing or writing; this slice does not close Driver/ledger
//! admission. Only the interface name of the opaque retained capability is
//! written, never a caller string, and no route or `Connected` authority is
//! granted. `ConfiguredUtun` keeps the pin; dropping it closes the last helper
//! reference after the caller stopped and reaped charon in `begin_cleanup`.

use super::{interfaces::Interfaces, utun_observer::RetainedInterface};
use crate::{
    connection::ipsec::{Candidate, Error},
    helper::controller_lock::ControllerLock,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

mod native;
mod preflight;
use preflight::assign;
#[cfg(test)]
mod tests;

pub const MAX_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    V4,
    V6,
}

pub struct ConfiguredUtun<'a> {
    retained: RetainedInterface,
    controller: &'a ControllerLock,
    target: Target,
    vips: Vec<IpAddr>,
}

/// Terminal failure: the original pin and every intended address are returned,
/// including partial assignment intent, so no ledger can lose either.
pub struct VipFailure {
    pub retained: RetainedInterface,
    pub intended: Vec<IpAddr>,
    error: Error,
}

impl VipFailure {
    pub fn error(&self) -> Error {
        self.error
    }

    pub fn intended(&self) -> &[IpAddr] {
        &self.intended
    }
}

#[derive(Clone)]
struct Target {
    name: String,
    index: u32,
}

impl<'a> ConfiguredUtun<'a> {
    /// Assign the negotiated Candidate VIPs to the pinned original utun.
    pub fn configure(
        retained: RetainedInterface,
        candidate: &Candidate,
        controller: &'a ControllerLock,
        timeout: Duration,
        cancel: &AtomicBool,
    ) -> Result<Self, VipFailure> {
        let intended = candidate.vips.clone();
        let vips = match validate_candidate(candidate) {
            Ok(vips) => vips,
            Err(error) => {
                return Err(VipFailure {
                    retained,
                    intended,
                    error,
                });
            }
        };
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(VipFailure {
                retained,
                intended,
                error: Error::Invalid,
            });
        }
        let Some(expires) = Instant::now().checked_add(timeout) else {
            return Err(VipFailure {
                retained,
                intended,
                error: Error::Invalid,
            });
        };
        let target = Target {
            name: retained.name().to_owned(),
            index: retained.index(),
        };
        let mut api = native::Native;
        let outcome = {
            let mut current = || {
                controller.validate().map_err(|_| Error::Changed)?;
                retained.validate().map_err(|_| Error::Changed)
            };
            assign(&mut api, &target, &vips, expires, cancel, &mut current)
        };
        match outcome {
            Ok(()) => Ok(Self {
                retained,
                controller,
                target,
                vips,
            }),
            Err(error) => Err(VipFailure {
                retained,
                intended,
                error,
            }),
        }
    }

    /// Selected VIP for one family, if that family was negotiated.
    pub fn vip(&self, family: Family) -> Option<IpAddr> {
        self.vips.iter().copied().find(|vip| {
            matches!(
                (family, vip),
                (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_))
            )
        })
    }

    pub fn index(&self) -> u32 {
        self.target.index
    }

    pub fn name(&self) -> &str {
        &self.target.name
    }

    pub fn controller(&self) -> &ControllerLock {
        self.controller
    }

    /// Read-only health: the pin still validates and every intended address is
    /// present only on the owned index.
    pub fn validate(&self) -> Result<(), Error> {
        self.retained.validate().map_err(|_| Error::Changed)?;
        self.controller.validate().map_err(|_| Error::Changed)?;
        let interfaces = native::Native
            .interfaces()
            .map_err(|_| Error::Unavailable)?;
        preflight::verify(&interfaces, &self.target, &self.vips)
    }
}

/// Private seam: production uses `native::Native`, tests use a scripted fake.
pub(super) trait Api {
    fn interfaces(&mut self) -> io::Result<Interfaces>;
    fn assign(&mut self, name: &str, vip: IpAddr) -> io::Result<()>;
}

pub(super) fn check(expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if Instant::now() >= expires {
        return Err(Error::Timeout);
    }
    Ok(())
}

/// Candidate metadata rules. Never authority, only the negotiated VIP shape.
pub(super) fn validate_candidate(candidate: &Candidate) -> Result<Vec<IpAddr>, Error> {
    if !candidate.active
        || candidate.ike_id == 0
        || candidate.child_id == 0
        || candidate.reqid == 0
        || candidate.spi_in == 0
        || candidate.spi_out == 0
    {
        return Err(Error::Invalid);
    }
    let vips = &candidate.vips;
    if vips.is_empty() || vips.len() > 2 {
        return Err(Error::Invalid);
    }
    let (mut v4, mut v6) = (false, false);
    for vip in vips {
        match vip {
            IpAddr::V4(address) if !v4 && valid_v4(*address) => v4 = true,
            IpAddr::V6(address) if !v6 && valid_v6(*address) => v6 = true,
            _ => return Err(Error::Invalid),
        }
    }
    if candidate.local_ts.len() != vips.len() {
        return Err(Error::Invalid);
    }
    for vip in vips {
        let prefix = if vip.is_ipv4() { 32 } else { 128 };
        let exact = candidate
            .local_ts
            .iter()
            .any(|network| network.address() == *vip && network.prefix() == prefix);
        if !exact {
            return Err(Error::Invalid);
        }
    }
    for network in &candidate.local_ts {
        if !vips.contains(&network.address()) {
            return Err(Error::Invalid);
        }
    }
    Ok(vips.clone())
}

fn valid_v4(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_link_local()
}

fn valid_v6(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_unicast_link_local()
}
