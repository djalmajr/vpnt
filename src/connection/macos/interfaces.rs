use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Interface {
    pub name: String,
    pub index: u32,
    pub flags: u32,
    pub addresses: BTreeSet<IpAddr>,
}
impl Interface {
    pub fn usable_ppp(&self) -> bool {
        self.index != 0
            && self.flags & libc::IFF_UP as u32 != 0
            && self.flags & libc::IFF_POINTOPOINT as u32 != 0
            && self.flags & libc::IFF_LOOPBACK as u32 == 0
    }
}

/// Snapshot before spawning a client. Production never creates interfaces here.
#[derive(Clone, Debug, Default)]
pub struct Interfaces {
    pub(super) entries: BTreeMap<String, Interface>,
}
impl Interfaces {
    pub fn read() -> io::Result<Self> {
        let mut list = ptr::null_mut();
        // SAFETY: getifaddrs initializes a linked list owned until freeifaddrs.
        if unsafe { libc::getifaddrs(&mut list) } != 0 {
            return Err(io::Error::last_os_error());
        }
        struct List(*mut libc::ifaddrs);
        impl Drop for List {
            fn drop(&mut self) {
                // SAFETY: this owner frees the list returned by getifaddrs once.
                unsafe { libc::freeifaddrs(self.0) }
            }
        }
        let owned = List(list);
        let mut current = owned.0;
        let mut result = Self::default();
        let mut count = 0;
        while !current.is_null() {
            count += 1;
            if count > 16_384 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            // SAFETY: current is an entry of the live getifaddrs list.
            let entry = unsafe { &*current };
            if entry.ifa_name.is_null() {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            // SAFETY: getifaddrs supplies a NUL-terminated interface name.
            let name = unsafe { CStr::from_ptr(entry.ifa_name) };
            let text = name
                .to_str()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            if text.is_empty() || text.len() >= libc::IFNAMSIZ {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            // SAFETY: the borrowed C string remains live with the list.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            let interface = result
                .entries
                .entry(text.into())
                .or_insert_with(|| Interface {
                    name: text.into(),
                    index,
                    flags: entry.ifa_flags,
                    addresses: BTreeSet::new(),
                });
            if interface.index != index || interface.flags != entry.ifa_flags {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            // SAFETY: this entry and its native sockaddr belong to the live list.
            if let Some(address) = unsafe { address(entry.ifa_addr) } {
                interface.addresses.insert(address);
            }
            current = entry.ifa_next;
        }
        Ok(result)
    }
    pub(super) fn previously_up(&self, interface: &Interface) -> bool {
        self.entries.values().any(|before| {
            (before.name == interface.name || before.index == interface.index)
                && before.flags & libc::IFF_UP as u32 != 0
        })
    }
}

/// The caller must supply a native sockaddr of its declared size/family.
pub(super) unsafe fn address(value: *const libc::sockaddr) -> Option<IpAddr> {
    if value.is_null() {
        return None;
    }
    // SAFETY: caller supplies a native sockaddr with a valid header.
    let header = unsafe { &*value };
    match header.sa_family as i32 {
        libc::AF_INET if header.sa_len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: header family and length describe sockaddr_in.
            let address = unsafe { &*value.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 if header.sa_len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: header family and length describe sockaddr_in6.
            let address = unsafe { &*value.cast::<libc::sockaddr_in6>() };
            let mut bytes = address.sin6_addr.s6_addr;
            // Darwin may embed a scope zone in a link-local KAME address.
            if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 && address.sin6_scope_id != 0 {
                bytes[2] = 0;
                bytes[3] = 0;
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}
