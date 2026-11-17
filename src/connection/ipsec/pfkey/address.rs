use super::{
    Address, Endpoint, Error, Network, Selector,
    wire::{self, Extensions},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn socket(bytes: &[u8]) -> Result<(Endpoint, usize), Error> {
    let length = usize::from(*bytes.first().ok_or(Error::Invalid)?);
    let value = wire::slice(bytes, 0, length)?;
    let family = *value.get(1).ok_or(Error::Invalid)?;
    let address = match i32::from(family) {
        libc::AF_INET if length == 16 => Address::unscoped(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&value[4..8]).map_err(|_| Error::Invalid)?,
        ))),
        libc::AF_INET6 if length == 28 => {
            let mut ip = <[u8; 16]>::try_from(&value[8..24]).map_err(|_| Error::Invalid)?;
            let mut zone = wire::u32_at(value, 24)?;
            if ip[0] == 0xfe && ip[1] & 0xc0 == 0x80 {
                let embedded = u32::from(u16::from_be_bytes([ip[2], ip[3]]));
                if zone == 0 {
                    zone = embedded;
                } else if embedded != 0 && embedded != zone {
                    return Err(Error::Invalid);
                }
                ip[2] = 0;
                ip[3] = 0;
            }
            Address {
                ip: IpAddr::V6(Ipv6Addr::from(ip)),
                zone,
            }
        }
        _ => return Err(Error::Invalid),
    };
    Ok((
        Endpoint {
            address,
            port: wire::net16(value, 2)?,
        },
        length,
    ))
}
fn single(bytes: &[u8]) -> Result<Selector, Error> {
    let (start, n) = socket(wire::slice(
        bytes,
        8,
        bytes.len().checked_sub(8).ok_or(Error::Invalid)?,
    )?)?;
    if bytes.len() != 8 + n.div_ceil(8) * 8 {
        return Err(Error::Invalid);
    }
    let prefix = bytes[5];
    Network::new(start.address.ip, prefix).map_err(|_| Error::Invalid)?;
    Ok(Selector {
        start,
        end: None,
        prefix,
        protocol: bytes[4],
    })
}
pub(super) fn selector(
    ext: &Extensions<'_>,
    normal: u16,
    first: u16,
    last: u16,
) -> Result<Selector, Error> {
    if let Some(value) = ext.optional(normal) {
        if ext.optional(first).is_some() || ext.optional(last).is_some() {
            return Err(Error::Invalid);
        }
        return single(value);
    }
    let mut start = single(ext.get(first)?)?;
    let end = single(ext.get(last)?)?;
    if start.protocol != end.protocol
        || start.prefix != end.prefix
        || start.start.address.ip.is_ipv4() != end.start.address.ip.is_ipv4()
        || start.start.address.zone != end.start.address.zone
        || (start.start.address.ip, start.start.port) > (end.start.address.ip, end.start.port)
    {
        return Err(Error::Invalid);
    }
    start.end = Some(end.start);
    Ok(start)
}
pub(super) fn endpoint(ext: &Extensions<'_>, kind: u16) -> Result<Endpoint, Error> {
    Ok(single(ext.get(kind)?)?.start)
}
