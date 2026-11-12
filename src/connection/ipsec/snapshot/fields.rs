use super::*;
use crate::connection::routes::Address;

pub(super) fn text<'a>(message: &'a Message, key: &str) -> Result<&'a str, Error> {
    message.get_text(key).ok_or(Error::Invalid)
}
pub(super) fn flag(message: &Message, key: &str) -> Result<bool, Error> {
    if message.get_value(key).is_some() {
        return if text(message, key)? == "yes" {
            Ok(true)
        } else {
            Err(Error::Invalid)
        };
    }
    if message.get_list(key).is_some() || message.get_section(key).is_some() {
        return Err(Error::Invalid);
    }
    Ok(false)
}
pub(super) fn number(message: &Message, key: &str, zero: bool) -> Result<u32, Error> {
    let value = text(message, key)?;
    let parsed: u32 = value.parse().map_err(|_| Error::Invalid)?;
    if parsed.to_string() != value || (!zero && parsed == 0) {
        return Err(Error::Invalid);
    }
    Ok(parsed)
}
pub(super) fn spi(message: &Message, key: &str, width: usize, zero: bool) -> Result<u64, Error> {
    let value = text(message, key)?;
    if value.len() != width
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Invalid);
    }
    let parsed = u64::from_str_radix(value, 16).map_err(|_| Error::Invalid)?;
    if !zero && parsed == 0 {
        return Err(Error::Invalid);
    }
    Ok(parsed)
}
pub(super) fn address(value: &str) -> Result<IpAddr, Error> {
    value.parse().map_err(|_| Error::Invalid)
}
pub(super) fn list<'a>(
    message: &'a Message,
    key: &str,
    optional: bool,
) -> Result<Vec<&'a str>, Error> {
    let Some(items) = message.get_list(key) else {
        return if optional && message.get_value(key).is_none() && message.get_section(key).is_none()
        {
            Ok(Vec::new())
        } else {
            Err(Error::Invalid)
        };
    };
    if items.len() > 64 {
        return Err(Error::Invalid);
    }
    items
        .iter()
        .map(|bytes| std::str::from_utf8(bytes).map_err(|_| Error::Invalid))
        .collect()
}
pub(super) fn vips(message: &Message) -> Result<Vec<IpAddr>, Error> {
    let mut result = BTreeSet::new();
    for item in list(message, "local-vips", true)? {
        let ip = address(item)?;
        if !Address::unscoped(ip).valid_gateway() || ip.is_loopback() || !result.insert(ip) {
            return Err(Error::Invalid);
        }
    }
    Ok(result.into_iter().collect())
}
pub(super) fn network(value: &str) -> Result<Network, Error> {
    if value.contains('/') {
        value.parse().map_err(|_| Error::Invalid)
    } else {
        address(value).map(Network::host)
    }
}
pub(super) fn selectors(message: &Message, key: &str) -> Result<Vec<Network>, Error> {
    let mut result = BTreeSet::new();
    for item in list(message, key, false)? {
        if !result.insert(network(item)?) {
            return Err(Error::Invalid);
        }
    }
    if result.is_empty() {
        return Err(Error::Invalid);
    }
    Ok(result.into_iter().collect())
}
