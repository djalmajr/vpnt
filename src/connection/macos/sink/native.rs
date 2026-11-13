use super::*;
use std::{mem::size_of, os::fd::FromRawFd};

pub(super) struct Native;
const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const OPT_FLAGS: i32 = 1;
const OPT_NAME: i32 = 2;
pub(crate) const ALIAS4: libc::c_ulong = 0x8040_691a;
pub(crate) const ALIAS6: libc::c_ulong = 0x8080_691a;

fn socket(family: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: no memory arguments; transfer a new descriptor into one owner.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: fd remains owned across fcntl.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
pub(super) fn control(id: u32) -> libc::sockaddr_ctl {
    libc::sockaddr_ctl {
        sc_len: size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    }
}
impl Api for Native {
    fn open(&self) -> io::Result<OwnedFd> {
        socket(libc::PF_SYSTEM, libc::SYSPROTO_CONTROL)
    }
    fn connect(&self, fd: RawFd) -> io::Result<()> {
        let mut info = libc::ctl_info {
            ctl_id: 0,
            ctl_name: [0; libc::MAX_KCTL_NAME],
        };
        for (output, byte) in info.ctl_name.iter_mut().zip(CONTROL_NAME) {
            *output = *byte as libc::c_char;
        }
        // SAFETY: CTLIOCGINFO uses exactly the live ctl_info input/output struct.
        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if info.ctl_id == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let address = control(info.ctl_id);
        // SAFETY: address has the declared native sockaddr_ctl layout/length.
        if unsafe {
            libc::connect(
                fd,
                (&address as *const libc::sockaddr_ctl).cast(),
                size_of::<libc::sockaddr_ctl>() as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn name(&self, fd: RawFd) -> io::Result<String> {
        let mut bytes = [0u8; libc::IFNAMSIZ];
        let mut length = bytes.len() as libc::socklen_t;
        // SAFETY: the kernel writes at most the declared live buffer capacity.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                OPT_NAME,
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let length = length as usize;
        if length < 2
            || length > bytes.len()
            || bytes[length - 1] != 0
            || bytes[..length - 1].contains(&0)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        String::from_utf8(bytes[..length - 1].to_vec())
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }
    fn set_flags(&self, fd: RawFd, flags: u32) -> io::Result<()> {
        // SAFETY: UTUN_OPT_FLAGS takes a live native u32 of the supplied size.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                OPT_FLAGS,
                (&flags as *const u32).cast(),
                size_of::<u32>() as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn flags(&self, fd: RawFd) -> io::Result<u32> {
        let mut flags = 0u32;
        let mut length = size_of::<u32>() as libc::socklen_t;
        // SAFETY: getsockopt writes to the live flags value with exact capacity.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                OPT_FLAGS,
                (&mut flags as *mut u32).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of::<u32>() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(flags)
    }
    fn assign(&self, name: &str, source: IpAddr) -> io::Result<()> {
        let mut alias = alias(name, source)?;
        let fd = socket(
            if source.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            0,
        )?;
        // SAFETY: only the private fixed alias encodings below reach ioctl.
        // Sizes/offsets/request numbers are checked by the independent SDK consumer.
        if unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                if source.is_ipv4() { ALIAS4 } else { ALIAS6 },
                alias.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn interfaces(&self) -> io::Result<Interfaces> {
        Interfaces::read()
    }
    fn table(&self) -> Result<Snapshot, Error> {
        Snapshot::read()
    }
    fn random(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        // SAFETY: arc4random_buf initializes the full writable buffer; cannot fail.
        unsafe {
            libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len());
        }
        bytes
    }
}
pub(crate) fn alias(name: &str, source: IpAddr) -> io::Result<Vec<u8>> {
    if name.len() >= libc::IFNAMSIZ || !name.is_ascii() || name.as_bytes().contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = vec![0u8; if source.is_ipv4() { 64 } else { 128 }];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    match source {
        IpAddr::V4(ip) => {
            for offset in [16, 32, 48] {
                bytes[offset] = 16;
                bytes[offset + 1] = libc::AF_INET as u8;
            }
            bytes[20..24].copy_from_slice(&ip.octets());
            bytes[36..40].copy_from_slice(&ip.octets()); // point-to-point peer = local
            bytes[52..56].fill(255); // /32, no connected subnet
        }
        IpAddr::V6(ip) => {
            for offset in [16, 72] {
                bytes[offset] = 28;
                bytes[offset + 1] = libc::AF_INET6 as u8;
            }
            bytes[24..40].copy_from_slice(&ip.octets());
            bytes[80..96].fill(255); // /128; no peer, scope or connected subnet
            bytes[100..104].copy_from_slice(&0x20u32.to_ne_bytes()); // IN6_IFF_NODAD
            bytes[120..128].fill(255); // both lifetimes infinite
        }
    }
    Ok(bytes)
}
