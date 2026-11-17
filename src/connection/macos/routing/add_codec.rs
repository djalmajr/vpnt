use super::{
    Address, Error, NextHop, Route, TransportDefault,
    codec::{self, put16, put32},
};
use std::{
    mem::{offset_of, size_of},
    net::IpAddr,
};

fn sockaddr(address: Address) -> Vec<u8> {
    let mut bytes = vec![0; if address.ip.is_ipv4() { 16 } else { 28 }];
    bytes[0] = bytes.len() as u8;
    match address.ip {
        IpAddr::V4(value) => {
            bytes[1] = libc::AF_INET as u8;
            bytes[4..8].copy_from_slice(&value.octets());
        }
        IpAddr::V6(value) => {
            bytes[1] = libc::AF_INET6 as u8;
            bytes[8..24].copy_from_slice(&value.octets());
            put32(&mut bytes, 24, address.zone);
        }
    }
    bytes
}
pub(super) fn add(
    route: Route,
    source: Address,
    pid: i32,
    sequence: i32,
) -> Result<Vec<u8>, Error> {
    route.validate()?;
    let ipv4 = route.key.network.address().is_ipv4();
    if pid <= 0
        || sequence <= 0
        || !source.valid_gateway()
        || (source.zone != 0 && source.zone != route.interface as u32)
        || source.ip.is_ipv4() != ipv4
        || matches!(route.next_hop, NextHop::Gateway(_))
        || route.key.scope != 0
    {
        return Err(Error::Invalid);
    }
    let destination = sockaddr(Address::unscoped(route.key.network.address()));
    let source = sockaddr(source);
    let mut link = vec![0; size_of::<libc::sockaddr_dl>()];
    link[0] = link.len() as u8;
    link[1] = libc::AF_LINK as u8;
    put16(&mut link, 2, route.interface);
    let prefix = route.key.network.prefix();
    let mut mask = sockaddr(Address::unscoped(if ipv4 {
        IpAddr::V4(u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0).into())
    } else {
        IpAddr::V6(
            u128::MAX
                .checked_shl(128 - prefix as u32)
                .unwrap_or(0)
                .into(),
        )
    }));
    mask[1] = 0; // masks have no address family in the BSD routing ABI.
    let mut bytes = vec![0; codec::CLASSIC];
    for value in [&destination, &link, &mask, &link, &source] {
        bytes.extend_from_slice(value);
        bytes.resize(codec::rounded(bytes.len()), 0);
    }
    let length = bytes.len() as u16;
    put16(&mut bytes, 0, length);
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = libc::RTM_ADD as u8;
    put16(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_index),
        route.interface,
    );
    let flags = libc::RTF_UP
        | libc::RTF_STATIC
        | if prefix == if ipv4 { 32 } else { 128 } {
            libc::RTF_HOST
        } else {
            0
        }
        | if route.next_hop == NextHop::Blackhole {
            libc::RTF_BLACKHOLE
        } else {
            0
        };
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_flags),
        flags as u32,
    );
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        (libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK | libc::RTA_IFP | libc::RTA_IFA)
            as u32,
    );
    put32(&mut bytes, offset_of!(libc::rt_msghdr, rtm_pid), pid as u32);
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_seq),
        sequence as u32,
    );
    Ok(bytes)
}

#[derive(Clone, Copy)]
pub(super) enum DefaultRequest {
    Add,
    Get,
    Delete,
}

impl DefaultRequest {
    pub(super) fn opcode(self) -> u8 {
        match self {
            Self::Add => libc::RTM_ADD as u8,
            Self::Get => libc::RTM_GET as u8,
            Self::Delete => libc::RTM_DELETE as u8,
        }
    }
}

/// Destination and netmask are fixed at IPv4 /0. Only ADD and DELETE carry
/// the expected gateway. The interface is encoded in rtm_index and IFSCOPE.
pub(super) fn scoped_default(
    request: DefaultRequest,
    route: TransportDefault,
    pid: i32,
    sequence: i32,
) -> Result<Vec<u8>, Error> {
    if pid <= 0 || sequence <= 0 {
        return Err(Error::Invalid);
    }
    let route_value = route.route();
    let zero = Address::unscoped(route_value.key.network.address());
    let mut bytes = vec![0; codec::CLASSIC];
    bytes.extend_from_slice(&sockaddr(zero));

    let mut flags = libc::RTF_UP | libc::RTF_IFSCOPE;
    let mut addrs = libc::RTA_DST | libc::RTA_NETMASK;
    if !matches!(request, DefaultRequest::Get) {
        flags |= libc::RTF_GATEWAY | libc::RTF_STATIC;
        addrs |= libc::RTA_GATEWAY;
        bytes.extend_from_slice(&sockaddr(route.gateway()));
    }
    let mut mask = sockaddr(zero);
    mask[1] = 0;
    bytes.extend_from_slice(&mask);

    let length = bytes.len() as u16;
    put16(&mut bytes, 0, length);
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = request.opcode();
    put16(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_index),
        route_value.key.scope,
    );
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_flags),
        flags as u32,
    );
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        addrs as u32,
    );
    put32(&mut bytes, offset_of!(libc::rt_msghdr, rtm_pid), pid as u32);
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_seq),
        sequence as u32,
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_default_packets_use_exact_network_gateway_and_interface_scope() {
        let router = Address::unscoped("192.0.2.1".parse().unwrap());
        let default = TransportDefault::from_egress(7, NextHop::Gateway(router)).unwrap();
        for (request, opcode, has_gateway) in [
            (DefaultRequest::Add, libc::RTM_ADD, true),
            (DefaultRequest::Get, libc::RTM_GET, false),
            (DefaultRequest::Delete, libc::RTM_DELETE, true),
        ] {
            let packet = scoped_default(request, default, 11, 19).unwrap();
            let frame = codec::frame(&packet).unwrap();
            assert_eq!(frame[3], opcode as u8);
            let flags = codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_flags)).unwrap();
            assert_ne!(flags & libc::RTF_IFSCOPE, 0);
            let addrs = codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_addrs)).unwrap();
            assert_ne!(addrs & libc::RTA_NETMASK, 0);
            assert_eq!(addrs & libc::RTA_GATEWAY != 0, has_gateway);
            let record = codec::record(frame, codec::CLASSIC).unwrap();
            assert_eq!(record.key, default.route().key);
            assert_eq!(record.interface, 7);
            assert_eq!(default.matches_static(&record), has_gateway);
        }
        let mut bad = default.route();
        bad.key.scope = 0;
        assert!(TransportDefault::try_from(bad).is_err());
        bad.key.scope = 8;
        assert!(TransportDefault::try_from(bad).is_err());
        bad.key.scope = 7;
        bad.key.network = "192.0.2.0/24".parse().unwrap();
        assert!(TransportDefault::try_from(bad).is_err());
        let noncanonical = serde_json::from_value(serde_json::json!({
            "address": "192.0.2.9",
            "prefix": 0
        }))
        .unwrap();
        assert!(
            TransportDefault::try_from(Route {
                key: super::super::Key {
                    network: noncanonical,
                    ..default.route().key
                },
                ..default.route()
            })
            .is_err()
        );
        assert!(add(bad, router, 11, 19).is_err());
        bad.next_hop = NextHop::Interface;
        assert!(add(bad, router, 11, 19).is_err());
    }
}
