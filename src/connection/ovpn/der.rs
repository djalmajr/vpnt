//! Bounded DER reader for display metadata only. It does not establish trust.
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 8;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Fields {
    pub(super) subject: Option<String>,
    pub(super) issuer: Option<String>,
    pub(super) not_before: Option<String>,
    pub(super) not_after: Option<String>,
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

pub(super) fn read_certificate(input: &[u8]) -> Fields {
    (input.len() <= MAX_CERTIFICATE_BYTES)
        .then(|| fields(input))
        .flatten()
        .unwrap_or_default()
}

fn read<'a>(input: &mut &'a [u8]) -> Option<Tlv<'a>> {
    let (&tag, rest) = input.split_first()?;
    // Only the low tag-number form occurs in the X.509 structures we read.
    if tag == 0 || tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if !(1..=4).contains(&count) {
            return None;
        }
        let (bytes, tail) = rest.split_at_checked(count)?;
        rest = tail;
        if bytes.first() == Some(&0) {
            return None;
        }
        let length = bytes
            .iter()
            .fold(0u32, |len, byte| (len << 8) | u32::from(*byte));
        if length < 128 {
            return None;
        }
        usize::try_from(length).ok()?
    };
    if length > rest.len() {
        return None;
    }
    let (value, tail) = rest.split_at(length);
    *input = tail;
    Some(Tlv { tag, value })
}

fn expect<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let element = read(input)?;
    (element.tag == tag).then_some(element.value)
}

fn valid_tree(node: &Tlv<'_>, depth: usize) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    if node.tag & 0x20 != 0 {
        let mut children = node.value;
        while !children.is_empty() {
            valid_tree(&read(&mut children)?, depth + 1)?;
        }
    }
    Some(())
}

fn fields(mut input: &[u8]) -> Option<Fields> {
    let certificate = read(&mut input)?;
    if certificate.tag != SEQUENCE || !input.is_empty() {
        return None;
    }
    valid_tree(&certificate, 1)?;
    let mut outer = certificate.value;
    let mut tbs = expect(&mut outer, SEQUENCE)?;
    if tbs.first() == Some(&0xa0) {
        expect(&mut tbs, 0xa0)?;
    }
    expect(&mut tbs, 2)?; // serialNumber
    expect(&mut tbs, SEQUENCE)?; // signature
    let issuer = expect(&mut tbs, SEQUENCE)?;
    let mut validity = expect(&mut tbs, SEQUENCE)?;
    let subject = expect(&mut tbs, SEQUENCE)?;
    let not_before = read(&mut validity).and_then(time);
    let not_after = read(&mut validity).and_then(time);
    Some(Fields {
        issuer: name(issuer),
        subject: name(subject),
        not_before,
        not_after,
    })
}

fn name(mut name: &[u8]) -> Option<String> {
    let mut organization = None;
    while !name.is_empty() {
        let mut attributes = expect(&mut name, SET)?;
        while !attributes.is_empty() {
            let mut attr = expect(&mut attributes, SEQUENCE)?;
            let oid = expect(&mut attr, 6)?;
            let value = read(&mut attr)?;
            if !attr.is_empty() {
                return None;
            }
            match oid {
                [0x55, 4, 3] => return text(value),
                [0x55, 4, 10] if organization.is_none() => organization = text(value),
                _ => {}
            }
        }
    }
    organization
}

fn text(value: Tlv<'_>) -> Option<String> {
    let decoded = match value.tag {
        0x0c => std::str::from_utf8(value.value).ok()?.to_owned(),
        0x13 | 0x16 if value.value.is_ascii() => std::str::from_utf8(value.value).ok()?.to_owned(),
        0x1e if value.value.len().is_multiple_of(2) => value
            .value
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| char::from_u32(u32::from(u16::from_be_bytes(*bytes))))
            .collect::<Option<String>>()?,
        _ => return None,
    };
    if decoded.chars().any(char::is_control) {
        return None;
    }
    Some(decoded.chars().take(200).collect())
}

fn time(value: Tlv<'_>) -> Option<String> {
    let digits = value.value.strip_suffix(b"Z")?;
    let (year, remaining) = match (value.tag, digits.len()) {
        (0x17, 12) => {
            let year = number(&digits[..2])?;
            (year + if year < 50 { 2000 } else { 1900 }, &digits[2..])
        }
        (0x18, 14) => (number(&digits[..4])?, &digits[4..]),
        _ => return None,
    };
    let month = number(&remaining[..2])?;
    let day = number(&remaining[2..4])?;
    let hour = number(&remaining[4..6])?;
    let minute = number(&remaining[6..8])?;
    let second = number(&remaining[8..])?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return None,
    };
    if year == 0 || !(1..=month_days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn number(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0, |value, &byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(byte - b'0'))
    })
}

#[cfg(test)]
#[path = "der_tests.rs"]
mod tests;
