//! Read only PPP ownership records from configd. Apple's pppd publishes `pid`
//! and InterfaceName in State:/Network/Service/<service>/PPP. We never mutate
//! the dynamic store or trust a pidfile in the group-writable /var/run directory.
use crate::connection::ssl::InterfaceName;
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::{CFAllocatorRef, CFType, CFTypeRef, TCFType},
    dictionary::CFDictionary,
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use std::{ffi::c_void, ptr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Record {
    pub key: String,
    pub interface: InterfaceName,
    pub pid: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Unavailable;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callback: Option<unsafe extern "C" fn(*const c_void, CFArrayRef, *mut c_void)>,
        context: *mut c_void,
    ) -> CFTypeRef;
    fn SCDynamicStoreCopyMultiple(
        store: CFTypeRef,
        keys: CFArrayRef,
        patterns: CFArrayRef,
    ) -> CFTypeRef;
}

pub(super) fn read() -> Result<Vec<Record>, Unavailable> {
    let name = CFString::new("vpnt PPP ownership");
    // SAFETY: the session has no callback/context and is released under the
    // create rule. Only a fixed PPP-state pattern is read; no configuration is set.
    let reference = unsafe {
        SCDynamicStoreCreate(
            ptr::null(),
            name.as_concrete_TypeRef(),
            None,
            ptr::null_mut(),
        )
    };
    if reference.is_null() {
        return Err(Unavailable);
    }
    // SAFETY: a non-null Create result transfers one retained CF object.
    let store = unsafe { CFType::wrap_under_create_rule(reference) };
    let patterns = CFArray::from_CFTypes(&[CFString::new("^State:/Network/Service/[^/]+/PPP$")]);
    // SAFETY: the live session and immutable pattern array outlive the call;
    // a non-null Copy result transfers its own retain to the caller.
    let reference = unsafe {
        SCDynamicStoreCopyMultiple(
            store.as_CFTypeRef(),
            ptr::null(),
            patterns.as_concrete_TypeRef(),
        )
    };
    if reference.is_null() {
        return Err(Unavailable);
    }
    // SAFETY: non-null Copy result with one owned retain; downcast checks type.
    let value = unsafe { CFType::wrap_under_create_rule(reference) };
    parse(&value)
}

fn field(dictionary: &CFDictionary, key: &str) -> Option<CFType> {
    let key = CFString::new(key);
    let value = *dictionary.find(key.as_CFTypeRef())?;
    // SAFETY: this is a property-list dictionary from configd (or CF fixtures),
    // whose values are CF objects. Retain it before the borrow can end.
    Some(unsafe { CFType::wrap_under_get_rule(value) })
}

fn parse(value: &CFType) -> Result<Vec<Record>, Unavailable> {
    let dictionary = value.downcast::<CFDictionary>().ok_or(Unavailable)?;
    if dictionary.len() > 256 {
        return Err(Unavailable);
    }
    let (keys, values) = dictionary.get_keys_and_values();
    let mut result = Vec::new();
    for (key, value) in keys.into_iter().zip(values) {
        // SAFETY: all keys/values are live CF objects retained by dictionary.
        let key = unsafe { CFType::wrap_under_get_rule(key) }
            .downcast::<CFString>()
            .ok_or(Unavailable)?;
        if key.char_len() > 256 {
            return Err(Unavailable);
        }
        let key = key.to_string();
        let Some(service) = key
            .strip_prefix("State:/Network/Service/")
            .and_then(|value| value.strip_suffix("/PPP"))
        else {
            return Err(Unavailable);
        };
        if service.is_empty() || service.contains('/') || service.chars().any(char::is_control) {
            return Err(Unavailable);
        }
        // SAFETY: value is a live CF object from this property-list dictionary.
        let value = unsafe { CFType::wrap_under_get_rule(value) }
            .downcast::<CFDictionary>()
            .ok_or(Unavailable)?;
        // pppd may publish a partial record during startup or teardown. It
        // cannot authorize a link until both the name and PID are present.
        let Some(name) = field(&value, "InterfaceName") else {
            continue;
        };
        let name = name.downcast::<CFString>().ok_or(Unavailable)?;
        if name.char_len() > 15 {
            return Err(Unavailable);
        }
        let interface = InterfaceName::parse(&name.to_string()).ok_or(Unavailable)?;
        let Some(pid) = field(&value, "pid") else {
            continue;
        };
        let pid = pid
            .downcast::<CFNumber>()
            .and_then(|value| value.to_i64())
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as i64)
            .ok_or(Unavailable)? as u32;
        result.push(Record {
            key,
            interface,
            pid,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(name: CFType, pid: CFType) -> CFType {
        CFDictionary::from_CFType_pairs(&[
            (CFString::new("InterfaceName"), name),
            (CFString::new("pid"), pid),
        ])
        .as_CFType()
    }
    fn records(value: CFType) -> CFType {
        CFDictionary::from_CFType_pairs(&[(
            CFString::new("State:/Network/Service/fixture/PPP"),
            value,
        )])
        .as_CFType()
    }
    #[test]
    fn only_complete_typed_ppp_records_can_authorize_a_candidate() {
        let name = CFString::new("ppp42").as_CFType();
        let pid = CFNumber::from(42).as_CFType();
        assert_eq!(
            parse(&records(record(name.clone(), pid.clone()))).unwrap(),
            vec![Record {
                key: "State:/Network/Service/fixture/PPP".into(),
                interface: InterfaceName::parse("ppp42").unwrap(),
                pid: 42
            }]
        );
        for value in [
            record(name.clone(), name.clone()),
            record(pid.clone(), pid.clone()),
            record(CFString::new("en0").as_CFType(), pid.clone()),
            record(name.clone(), CFNumber::from(0).as_CFType()),
            record(name.clone(), CFNumber::from(-1).as_CFType()),
            record(name.clone(), CFNumber::from(i64::MAX).as_CFType()),
            record(name.clone(), CFNumber::from(42.5).as_CFType()),
        ] {
            assert!(parse(&records(value)).is_err());
        }
        let partial = CFDictionary::from_CFType_pairs(&[(CFString::new("InterfaceName"), name)]);
        assert!(parse(&records(partial.as_CFType())).unwrap().is_empty());
        assert!(parse(&pid).is_err());
        assert!(
            parse(
                &CFDictionary::from_CFType_pairs(&[(
                    CFString::new("State:/Network/Service/../PPP/PPP"),
                    record(CFString::new("ppp42").as_CFType(), pid)
                )])
                .as_CFType()
            )
            .is_err()
        );
    }
    #[test]
    fn native_store_read_never_returns_non_ppp_records() {
        // A read-only native API check. No records/configuration are written,
        // and no personal network metadata is printed or retained in a report.
        for record in read().unwrap() {
            assert!(record.key.starts_with("State:/Network/Service/"));
            assert!(record.key.ends_with("/PPP"));
            assert!(record.pid > 0);
        }
    }
}
