use super::{Error, Kind};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn slice(bytes: &[u8], at: usize, n: usize) -> Result<&[u8], Error> {
    bytes
        .get(at..at.checked_add(n).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)
}
pub(super) fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_ne_bytes(
        slice(bytes, at, 2)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
pub(super) fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_ne_bytes(
        slice(bytes, at, 4)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
pub(super) fn u64_at(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_ne_bytes(
        slice(bytes, at, 8)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
pub(super) fn net16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        slice(bytes, at, 2)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
pub(super) fn net32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        slice(bytes, at, 4)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
pub(super) struct Header {
    pub kind: Kind,
    pub errno: u8,
    pub satype: u8,
    pub sequence: u32,
    pub pid: u32,
}
impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 16
            || bytes.len() > 524_280
            || bytes[0] != 2
            || usize::from(u16_at(bytes, 4)?) * 8 != bytes.len()
        {
            return Err(Error::Invalid);
        }
        let kind = match bytes[1] {
            10 => Kind::Sad,
            18 => Kind::Spd,
            _ => return Err(Error::Invalid),
        };
        if (kind == Kind::Spd && bytes[3] != 0)
            || (kind == Kind::Sad
                && ![2, 3, 9].contains(&bytes[3])
                && !(bytes[2] != 0 && bytes[3] == 0))
        {
            return Err(Error::Invalid);
        }
        // sadb_msg_reserved is the dump's reference count, not required-zero.
        Ok(Self {
            kind,
            errno: bytes[2],
            satype: bytes[3],
            sequence: u32_at(bytes, 8)?,
            pid: u32_at(bytes, 12)?,
        })
    }
}

// Borrowed only during decode, deliberately without Debug/Clone or any raw
// payload accessor in the public DTO. The owning reader must zero its buffer.
pub(super) struct Extensions<'a>(BTreeMap<u16, &'a [u8]>);
impl<'a> Extensions<'a> {
    pub fn parse(mut bytes: &'a [u8]) -> Result<Self, Error> {
        let mut map = BTreeMap::new();
        while !bytes.is_empty() {
            let len = usize::from(u16_at(bytes, 0)?) * 8;
            let kind = u16_at(bytes, 2)?;
            if len < 8 || kind == 0 || map.len() >= 64 {
                return Err(Error::Invalid);
            }
            let ext = slice(bytes, 0, len)?;
            if map.insert(kind, ext).is_some() {
                return Err(Error::Invalid);
            }
            match kind {
                2..=4 if len != 32 => return Err(Error::Invalid),
                8 | 9 => {
                    let key_bytes = usize::from(u16_at(ext, 4)?).div_ceil(8);
                    if (8 + key_bytes).div_ceil(8) * 8 != len {
                        return Err(Error::Invalid);
                    }
                }
                10 | 11 if len < 16 => return Err(Error::Invalid),
                _ => {}
            }
            bytes = &bytes[len..];
        }
        Ok(Self(map))
    }
    pub fn get(&self, kind: u16) -> Result<&'a [u8], Error> {
        self.optional(kind).ok_or(Error::Invalid)
    }
    pub fn optional(&self, kind: u16) -> Option<&'a [u8]> {
        self.0.get(&kind).copied()
    }
    pub fn extra(&self, known: &[u16]) -> BTreeSet<u16> {
        self.0
            .keys()
            .filter(|k| !known.contains(k))
            .copied()
            .collect()
    }
}
