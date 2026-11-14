//! Admission of the plugin list the daemon actually loaded.
//!
//! `stats` reports `plugins` from the loaded `get_name()` values
//! (`vici_query.c:1794`), so it is the real constructor evidence; compile-time
//! symbols and the runtime manifest are not. This module only interprets that
//! list, it never queries anything itself.

use super::Error;
use crate::helper::vici::Message;
use std::collections::BTreeSet;

/// The userspace backend this client is built to drive.
const REQUIRED: [&str; 4] = [
    "kernel-libipsec",
    "kernel-pfroute",
    "socket-default",
    "vici",
];
const MAX_ENTRIES: usize = 128;
const MAX_NAME: usize = 64;

/// A missing, empty, oversized, duplicated or malformed list is incompatible.
/// Any `kernel-*` name outside the required set is refused, so a PF_KEY or
/// netlink backend can never be driven by this configuration. Ordinary plugin
/// names and their order are irrelevant.
pub(super) fn admit(response: &Message) -> Result<(), Error> {
    let plugins = response.get_list("plugins").ok_or(Error::Incompatible)?;
    if plugins.is_empty() || plugins.len() > MAX_ENTRIES {
        return Err(Error::Incompatible);
    }
    let mut seen = BTreeSet::new();
    for item in plugins {
        let name = std::str::from_utf8(item.as_slice()).map_err(|_| Error::Incompatible)?;
        if name.is_empty()
            || name.len() > MAX_NAME
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(Error::Incompatible);
        }
        if !seen.insert(name) {
            return Err(Error::Incompatible);
        }
        if name.starts_with("kernel-") && !REQUIRED.contains(&name) {
            return Err(Error::Incompatible);
        }
    }
    if !REQUIRED.iter().all(|name| seen.contains(name)) {
        return Err(Error::Incompatible);
    }
    Ok(())
}
