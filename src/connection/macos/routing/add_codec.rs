use super::{
    Address, Error, NextHop, Route,
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
        || (route.key.scope != 0 && route.key.scope != route.interface)
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
        | if route.key.scope != 0 {
            libc::RTF_IFSCOPE
        } else {
            0
        }
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
