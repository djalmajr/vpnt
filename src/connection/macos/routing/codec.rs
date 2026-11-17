use super::{Address, Error, Gateway, Key, Network, Record};
use std::{
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
pub(super) const CLASSIC: usize = size_of::<libc::rt_msghdr>();
pub(super) const DUMP: usize = size_of::<libc::rt_msghdr2>();
fn invalid() -> Error {
    Error::Invalid
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
pub(super) fn signed(bytes: &[u8], at: usize) -> Result<i32, Error> {
    Ok(u32_at(bytes, at)? as i32)
}
pub(super) fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_ne_bytes());
}
pub(super) fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}
pub(super) fn rounded(length: usize) -> usize {
    length.max(1).div_ceil(4) * 4
}
pub(super) fn frame(bytes: &[u8]) -> Result<&[u8], Error> {
    let length = u16_at(bytes, 0)? as usize;
    if length < 4 || bytes.get(2) != Some(&(libc::RTM_VERSION as u8)) {
        return Err(invalid());
    }
    bytes.get(..length).ok_or_else(invalid)
}
fn ip(bytes: &[u8]) -> Result<Address, Error> {
    match bytes.get(1).copied().map(i32::from) {
        Some(libc::AF_INET) if bytes.len() >= 8 => Ok(Address::unscoped(IpAddr::V4(
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).map_err(|_| invalid())?),
        ))),
        Some(libc::AF_INET6) if bytes.len() >= 28 => {
            let mut value = <[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| invalid())?;
            let mut zone = u32_at(bytes, 24)?;
            if value[0] == 0xfe && value[1] & 0xc0 == 0x80 {
                let embedded = u16::from_be_bytes([value[2], value[3]]) as u32;
                if zone == 0 {
                    zone = embedded;
                } else if embedded != 0 && embedded != zone {
                    return Err(invalid());
                }
                value[2] = 0;
                value[3] = 0;
            }
            Ok(Address {
                ip: IpAddr::V6(Ipv6Addr::from(value)),
                zone,
            })
        }
        _ => Err(invalid()),
    }
}
fn prefix(mask: &[u8], ipv4: bool) -> Result<u8, Error> {
    let (start, width) = if ipv4 { (4, 4) } else { (8, 16) };
    let mut bytes = vec![0u8; width];
    if mask.len() > start {
        let count = (mask.len() - start).min(width);
        bytes[..count].copy_from_slice(&mask[start..start + count]);
    }
    let mut prefix = 0;
    let mut zero = false;
    for byte in bytes {
        for bit in (0..8).rev() {
            if byte & (1 << bit) != 0 {
                if zero {
                    return Err(invalid());
                }
                prefix += 1;
            } else {
                zero = true;
            }
        }
    }
    Ok(prefix)
}
pub(super) fn record(bytes: &[u8], header: usize) -> Result<Record, Error> {
    if bytes.len() < header {
        return Err(invalid());
    }
    let flags = signed(bytes, offset_of!(libc::rt_msghdr, rtm_flags))?;
    let index = u16_at(bytes, offset_of!(libc::rt_msghdr, rtm_index))?;
    let bits = u32_at(bytes, offset_of!(libc::rt_msghdr, rtm_addrs))?;
    if bits & !255 != 0 {
        return Err(invalid());
    }
    let mut addresses: [Option<&[u8]>; 8] = [None; 8];
    let mut offset = header;
    for (bit, address) in addresses.iter_mut().enumerate() {
        if bits & (1 << bit) == 0 {
            continue;
        }
        let length = *bytes.get(offset).ok_or_else(invalid)? as usize;
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        *address = Some(bytes.get(offset..end).ok_or_else(invalid)?);
        offset = offset.checked_add(rounded(length)).ok_or_else(invalid)?;
        if offset > bytes.len() {
            return Err(invalid());
        }
    }
    if offset != bytes.len() {
        return Err(invalid());
    }
    let destination = ip(addresses[0].ok_or_else(invalid)?)?;
    let prefix = if flags & libc::RTF_HOST != 0 {
        if destination.ip.is_ipv4() { 32 } else { 128 }
    } else {
        prefix(addresses[2].ok_or_else(invalid)?, destination.ip.is_ipv4())?
    };
    let network = Network::new(destination.ip, prefix)?;
    let gateway = addresses[1]
        .map(|value| {
            if value.get(1) == Some(&(libc::AF_LINK as u8)) {
                if value.len() < 8
                    || 8usize + value[5] as usize + value[6] as usize + value[7] as usize
                        > value.len()
                {
                    return Err(invalid());
                }
                Ok(Gateway::Link(u16_at(value, 2)?))
            } else {
                ip(value).map(Gateway::Address)
            }
        })
        .transpose()?;
    let source = addresses[5].map(ip).transpose()?;
    if flags & libc::RTF_IFSCOPE != 0 && index == 0 {
        return Err(invalid());
    }
    Ok(Record {
        key: Key {
            network,
            scope: if flags & libc::RTF_IFSCOPE != 0 {
                index
            } else {
                0
            },
        },
        interface: index,
        flags,
        gateway,
        source,
    })
}
pub(super) fn query(
    address: Address,
    scope: u16,
    pid: i32,
    sequence: i32,
) -> Result<Vec<u8>, Error> {
    if pid <= 0 || sequence <= 0 || !address.valid_gateway() {
        return Err(invalid());
    }
    if address.zone > u16::MAX as u32 || (address.zone != 0 && scope as u32 != address.zone) {
        return Err(invalid());
    }
    let length = if address.ip.is_ipv4() { 16 } else { 28 };
    let ifp_len = size_of::<libc::sockaddr_dl>();
    let mut bytes = vec![0; CLASSIC + length + rounded(ifp_len)];
    let total = bytes.len() as u16;
    put16(&mut bytes, 0, total);
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = libc::RTM_GET as u8;
    put16(&mut bytes, offset_of!(libc::rt_msghdr, rtm_index), scope);
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_flags),
        (libc::RTF_UP | if scope != 0 { libc::RTF_IFSCOPE } else { 0 }) as u32,
    );
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        (libc::RTA_DST | libc::RTA_IFP) as u32,
    );
    put32(&mut bytes, offset_of!(libc::rt_msghdr, rtm_pid), pid as u32);
    put32(
        &mut bytes,
        offset_of!(libc::rt_msghdr, rtm_seq),
        sequence as u32,
    );
    let at = CLASSIC;
    bytes[at] = length as u8;
    match address.ip {
        IpAddr::V4(value) => {
            bytes[at + 1] = libc::AF_INET as u8;
            bytes[at + 4..at + 8].copy_from_slice(&value.octets());
        }
        IpAddr::V6(value) => {
            bytes[at + 1] = libc::AF_INET6 as u8;
            bytes[at + 8..at + 24].copy_from_slice(&value.octets());
            put32(&mut bytes, at + 24, address.zone);
        }
    }
    let at = CLASSIC + length;
    bytes[at] = ifp_len as u8;
    bytes[at + 1] = libc::AF_LINK as u8;
    Ok(bytes)
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
