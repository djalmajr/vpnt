//! Probe evidence for an owned PPP link. This does not install routes or alone
//! authorize Connected; the controller must also hold the required route leases.
use super::{
    interfaces::{Interface, Interfaces},
    ppp::OwnedPpp,
    resolve, tcp,
};
use crate::{
    helper::process::ManagedChild,
    model::{Profile, VpnKind},
};
use std::{
    net::{IpAddr, SocketAddr},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

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

fn run(
    link: &impl Link,
    profile: &Profile,
    canceled: &AtomicBool,
    timeout: Duration,
    allow_local_fixture: bool,
) -> Outcome {
    if profile.validate().is_err()
        || profile.kind != VpnKind::Ssl
        || timeout.is_zero()
        || timeout > Duration::from_secs(30)
    {
        return Outcome::InvalidTarget;
    }
    if canceled.load(Ordering::Acquire) {
        return Outcome::Canceled;
    }
    if !link.current() {
        return Outcome::InvalidLink;
    }
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Outcome::InvalidTarget;
    };
    let interface = link.interface();
    let protocol = u32::from(interface.addresses.iter().any(IpAddr::is_ipv4))
        | (u32::from(interface.addresses.iter().any(IpAddr::is_ipv6)) << 1);
    let targets = match resolve::resolve(
        &profile.probe_host,
        interface.index,
        protocol,
        // Preserve a budget for traffic when only one DNS family completes.
        (Instant::now() + (timeout / 2).min(Duration::from_secs(2))).min(deadline),
        canceled,
    ) {
        Ok(targets) => targets,
        Err(tcp::Error::Canceled) => return Outcome::Canceled,
        Err(_) => {
            return if link.current() {
                Outcome::Unresponsive
            } else {
                Outcome::InvalidLink
            };
        }
    };
    let local = match Interfaces::read() {
        Ok(local) => local,
        Err(_) => return Outcome::InvalidLink,
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
        if canceled.load(Ordering::Acquire) {
            return Outcome::Canceled;
        }
        if !link.current() {
            return Outcome::InvalidLink;
        }
        if profile.probe_method == "ping_tcp" && ping(interface, source, target, deadline, canceled)
        {
            return finish(link, Method::Ping, canceled, deadline);
        }
        if canceled.load(Ordering::Acquire) {
            return Outcome::Canceled;
        }
        if !link.current() {
            return Outcome::InvalidLink;
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
    if canceled.load(Ordering::Acquire) {
        Outcome::Canceled
    } else if !link.current() {
        Outcome::InvalidLink
    } else if attempted {
        Outcome::Unresponsive
    } else {
        Outcome::InvalidTarget
    }
}

fn finish(link: &impl Link, method: Method, canceled: &AtomicBool, deadline: Instant) -> Outcome {
    if canceled.load(Ordering::Acquire) {
        Outcome::Canceled
    } else if !link.current() {
        Outcome::InvalidLink
    } else if Instant::now() > deadline {
        Outcome::Unresponsive
    } else {
        Outcome::Responsive(method)
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
fn scoped(address: IpAddr, name: &str) -> String {
    match address {
        IpAddr::V6(value) if value.is_unicast_link_local() => format!("{value}%{name}"),
        _ => address.to_string(),
    }
}
fn ping(
    interface: &Interface,
    source: IpAddr,
    target: IpAddr,
    deadline: Instant,
    canceled: &AtomicBool,
) -> bool {
    let mut command = Command::new(if target.is_ipv4() {
        "/sbin/ping"
    } else {
        "/sbin/ping6"
    });
    command.args([
        "-n",
        "-c",
        "1",
        if target.is_ipv4() { "-b" } else { "-B" },
        &interface.name,
        "-S",
        &scoped(source, &interface.name),
        &scoped(target, &interface.name),
    ]);
    let Ok(mut child) = ManagedChild::spawn(&mut command) else {
        return false;
    };
    let until = (Instant::now() + Duration::from_millis(700)).min(deadline);
    let result = loop {
        if canceled.load(Ordering::Acquire) || Instant::now() >= until {
            break false;
        }
        match child.poll() {
            Ok(Some(status)) => break status.success(),
            Err(_) => break false,
            _ => {}
        }
        thread::sleep(Duration::from_millis(5));
    };
    // One numeric target/one echo produces bounded output, retained only in
    // the child's private pipes until exit. No ping output enters the UI/log.
    let _ = child.stop(Duration::from_millis(50));
    result
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
