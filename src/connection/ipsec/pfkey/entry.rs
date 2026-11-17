use super::{
    Error, Lifetime, Policy, Request, Sa, address,
    wire::{self, Extensions},
};

pub(super) fn sa(protocol: u8, ext: &Extensions<'_>) -> Result<Sa, Error> {
    let sa = ext.get(1)?;
    let sa2 = ext.get(19)?;
    if ![16, 24].contains(&sa.len())
        || sa2.len() != 16
        || sa[9] > 3
        || sa2[4] > 2
        || ext.optional(18).is_some()
    {
        return Err(Error::Invalid);
    }
    let flags = wire::u32_at(sa, 12)?;
    // The private Darwin sadb_sa_2 natt_port is native endian, unlike the
    // sockaddr ports and SPI. strongSwan 6.1.0 assigns host->get_port() here.
    let natt_port = if flags & 2 != 0 {
        if sa.len() != 24 {
            return Err(Error::Invalid);
        }
        Some(wire::u16_at(sa, 16)?)
    } else {
        None
    };
    let source = address::endpoint(ext, 5)?;
    let destination = address::endpoint(ext, 6)?;
    if source.address.ip.is_ipv4() != destination.address.ip.is_ipv4() {
        return Err(Error::Invalid);
    }
    let lifetime = ext
        .optional(2)
        .map(|bytes| {
            Ok(Lifetime {
                allocations: wire::u32_at(bytes, 4)?,
                bytes: wire::u64_at(bytes, 8)?,
                added: wire::u64_at(bytes, 16)?,
                used: wire::u64_at(bytes, 24)?,
            })
        })
        .transpose()?;
    Ok(Sa {
        protocol,
        spi: wire::net32(sa, 4)?,
        state: sa[9],
        flags,
        reqid: wire::u32_at(sa2, 12)?,
        mode: sa2[4],
        replay_sequence: wire::u32_at(sa2, 8)?,
        source,
        destination,
        natt_port,
        lifetime,
        extra_extensions: ext.extra(&[1, 2, 3, 4, 5, 6, 8, 9, 19]),
    })
}

pub(super) fn policy(ext: &Extensions<'_>) -> Result<Policy, Error> {
    let value = ext.get(18)?;
    if value.len() < 16 || [1, 8, 9, 19].iter().any(|k| ext.optional(*k).is_some()) {
        return Err(Error::Invalid);
    }
    let kind = wire::u16_at(value, 4)?;
    let direction = value[6];
    if kind > 5 || direction > 2 || (kind != 2 && value.len() != 16) {
        return Err(Error::Invalid);
    }
    let source = address::selector(ext, 5, 23, 24)?;
    let destination = address::selector(ext, 6, 25, 26)?;
    if source.protocol != destination.protocol
        || source.start.address.ip.is_ipv4() != destination.start.address.ip.is_ipv4()
    {
        return Err(Error::Invalid);
    }
    let mut remaining = &value[16..];
    let mut requests = Vec::new();
    while !remaining.is_empty() {
        // sadb_x_ipsecrequest_len is bytes, not 64-bit units.
        let length = usize::from(wire::u16_at(remaining, 0)?);
        if length < 8 || length % 8 != 0 || requests.len() >= 64 {
            return Err(Error::Invalid);
        }
        let r = wire::slice(remaining, 0, length)?;
        let protocol = wire::u16_at(r, 2)?;
        if ![50, 51, 108].contains(&protocol) || ![1, 2].contains(&r[4]) || r[5] > 3 {
            return Err(Error::Invalid);
        }
        let endpoints = if length == 8 {
            None
        } else {
            if r[4] != 2 {
                return Err(Error::Invalid);
            }
            let (from, a) = address::socket(&r[8..])?;
            let (to, b) = address::socket(&r[8 + a..])?;
            if 8 + a + b != length || from.address.ip.is_ipv4() != to.address.ip.is_ipv4() {
                return Err(Error::Invalid);
            }
            Some((from, to))
        };
        requests.push(Request {
            protocol,
            mode: r[4],
            level: r[5],
            reqid: wire::u16_at(r, 6)?,
            endpoints,
        });
        remaining = &remaining[length..];
    }
    Ok(Policy {
        id: wire::u32_at(value, 8)?,
        kind,
        direction,
        source,
        destination,
        requests,
        extra_extensions: ext.extra(&[2, 3, 4, 5, 6, 18, 23, 24, 25, 26]),
    })
}
