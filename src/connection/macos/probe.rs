//! Probe evidence for an owned PPP link. This does not install routes or alone
//! authorize Connected; the controller must also hold the required route leases.
use super::{
    interfaces::{Interface, Interfaces},
    ppp::OwnedPpp,
    resolve, tcp,
};
use crate::model::{Profile, VpnKind};
use icmp::ping;
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
// The unchanged SSL fixtures inherit `thread` through `use super::*`.
#[cfg(test)]
use std::thread;

/// Link family: the SSL probe and the owned IPsec utun share one run loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Ssl,
    Ipsec,
}
impl Kind {
    fn vpn(self) -> VpnKind {
        match self {
            Kind::Ssl => VpnKind::Ssl,
            Kind::Ipsec => VpnKind::Ipsec,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Ping,
    Tcp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Responsive(Method),
    Unresponsive,
    Canceled,
    InvalidLink,
    InvalidTarget,
}

trait Link {
    fn interface(&self) -> &Interface;
    fn current(&self) -> bool;
    /// Default keeps every existing/SSL link exactly as before.
    fn kind(&self) -> Kind {
        Kind::Ssl
    }
}
impl Link for OwnedPpp {
    fn interface(&self) -> &Interface {
        &self.interface
    }
    fn current(&self) -> bool {
        self.is_current().unwrap_or(false)
    }
}

pub fn probe(
    link: &OwnedPpp,
    profile: &Profile,
    canceled: &AtomicBool,
    timeout: Duration,
) -> Outcome {
    run(link, profile, canceled, timeout, false)
}

/// The public finite-timeout wrapper: the absolute deadline starts here,
/// before the first link/current observation, and is the only clock the run
/// core uses. The timeout range belongs to the wrapper.
fn run(
    link: &impl Link,
    profile: &Profile,
    canceled: &AtomicBool,
    timeout: Duration,
    allow_local_fixture: bool,
) -> Outcome {
    if timeout.is_zero() || timeout > Duration::from_secs(30) {
        return Outcome::InvalidTarget;
    }
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Outcome::InvalidTarget;
    };
    run_until(link, profile, canceled, deadline, allow_local_fixture)
}

/// Same run loop with one supplied absolute deadline. It never rebases a
/// fresh `now + timeout`; every check and the DNS/traffic caps derive from the
/// remaining part of this Instant.
fn run_until(
    link: &impl Link,
    profile: &Profile,
    canceled: &AtomicBool,
    deadline: Instant,
    allow_local_fixture: bool,
) -> Outcome {
    // Precedence: profile/kind, cancel, total expiry, then link validity.
    if profile.validate().is_err() || profile.kind != link.kind().vpn() {
        return Outcome::InvalidTarget;
    }
    if let Err(outcome) = checked_current(link, canceled, deadline) {
        return outcome;
    }
    // Keep a traffic reserve when only one DNS family completes; the half cap
    // is derived from the remaining total, never from a fresh timeout.
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Outcome::Unresponsive;
    };
    if remaining.is_zero() {
        return Outcome::Unresponsive;
    }
    let interface = link.interface();
    let protocol = u32::from(interface.addresses.iter().any(IpAddr::is_ipv4))
        | (u32::from(interface.addresses.iter().any(IpAddr::is_ipv6)) << 1);
    let dns_deadline = (Instant::now() + (remaining / 2).min(Duration::from_secs(2))).min(deadline);
    let targets = match resolve::resolve(
        &profile.probe_host,
        interface.index,
        protocol,
        dns_deadline,
        canceled,
    ) {
        Ok(targets) => targets,
        Err(tcp::Error::Canceled) => return Outcome::Canceled,
        Err(_) => {
            return match checked_current(link, canceled, deadline) {
                Ok(()) => Outcome::Unresponsive,
                Err(outcome) => outcome,
            };
        }
    };
    let local = match Interfaces::read() {
        Ok(local) => local,
        Err(_) => return failure_or(canceled, deadline, Outcome::InvalidLink),
    };
    let mut attempted = false;
    for target in targets {
        if !remote(target, &local, allow_local_fixture) {
            continue;
        }
        let Some(source) = source(interface, target) else {
            continue;
        };
        if source.is_loopback() && !allow_local_fixture {
            continue;
        }
        attempted = true;
        if let Err(outcome) = checked_current(link, canceled, deadline) {
            return outcome;
        }
        if profile.probe_method == "ping_tcp" && ping(interface, source, target, deadline, canceled)
        {
            return finish(link, Method::Ping, canceled, deadline);
        }
        if let Err(outcome) = checked_current(link, canceled, deadline) {
            return outcome;
        }
        let attempt = (Instant::now() + Duration::from_secs(1)).min(deadline);
        match tcp::connect(
            interface.index,
            source,
            SocketAddr::new(target, profile.probe_port),
            attempt,
            canceled,
        ) {
            // Keep the owned socket live through the final link check.
            Ok(_connection) => return finish(link, Method::Tcp, canceled, deadline),
            Err(tcp::Error::Canceled) => return Outcome::Canceled,
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    if let Err(outcome) = checked_current(link, canceled, deadline) {
        return outcome;
    }
    if attempted {
        Outcome::Unresponsive
    } else {
        Outcome::InvalidTarget
    }
}

/// Cancellation and total expiry win over both a successful and a failed
/// current/pin observation, including one that lands inside the bounded work.
/// False current maps to InvalidLink only after the cancel/expiry rechecks.
fn checked_current(
    link: &impl Link,
    canceled: &AtomicBool,
    deadline: Instant,
) -> Result<(), Outcome> {
    if canceled.load(Ordering::Acquire) {
        return Err(Outcome::Canceled);
    }
    if Instant::now() >= deadline {
        return Err(Outcome::Unresponsive);
    }
    let current = link.current();
    if canceled.load(Ordering::Acquire) {
        return Err(Outcome::Canceled);
    }
    if Instant::now() >= deadline {
        return Err(Outcome::Unresponsive);
    }
    if !current {
        return Err(Outcome::InvalidLink);
    }
    Ok(())
}

/// A non-current failure (bad local view, failed wrapper pin) still lets a
/// cancel or the total deadline take precedence.
fn failure_or(canceled: &AtomicBool, deadline: Instant, failure: Outcome) -> Outcome {
    if canceled.load(Ordering::Acquire) {
        Outcome::Canceled
    } else if Instant::now() >= deadline {
        Outcome::Unresponsive
    } else {
        failure
    }
}

fn finish(link: &impl Link, method: Method, canceled: &AtomicBool, deadline: Instant) -> Outcome {
    match checked_current(link, canceled, deadline) {
        Ok(()) => Outcome::Responsive(method),
        Err(outcome) => outcome,
    }
}

fn remote(address: IpAddr, local: &Interfaces, fixture: bool) -> bool {
    let address = match address {
        IpAddr::V6(value) => value.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        _ => address,
    };
    if address.is_unspecified()
        || address.is_multicast()
        || address == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    {
        return false;
    }
    fixture
        || (!address.is_loopback()
            && !local
                .entries
                .values()
                .any(|interface| interface.addresses.contains(&address)))
}
fn source(interface: &Interface, target: IpAddr) -> Option<IpAddr> {
    interface
        .addresses
        .iter()
        .copied()
        .filter(|address| {
            address.is_ipv4() == target.is_ipv4()
                && !address.is_unspecified()
                && !address.is_multicast()
        })
        .find(|address| match (*address, target) {
            (IpAddr::V6(source), IpAddr::V6(target)) => {
                source.is_unicast_link_local() == target.is_unicast_link_local()
            }
            _ => true,
        })
}

mod icmp;
mod utun;
pub use utun::probe_utun;

#[cfg(test)]
#[path = "probe/current_tests.rs"]
mod current_tests;
#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "probe/utun_tests.rs"]
mod utun_tests;
