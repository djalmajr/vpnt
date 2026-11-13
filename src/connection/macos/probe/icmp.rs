//! ICMP fallback for `ping_tcp`, moved unchanged from the probe parent.
use crate::connection::macos::interfaces::Interface;
use crate::helper::process::ManagedChild;
use std::{
    net::IpAddr,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

fn scoped(address: IpAddr, name: &str) -> String {
    match address {
        IpAddr::V6(value) if value.is_unicast_link_local() => format!("{value}%{name}"),
        _ => address.to_string(),
    }
}
pub(super) fn ping(
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
