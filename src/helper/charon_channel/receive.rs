//! Bounded `recvmsg` parsing for the FD3 capability.
//!
//! The ancillary buffer is sized from the documented kernel bound, not from the
//! one descriptor this protocol expects: Darwin's `UIPC_MAX_CMSG_FD` is 512 in
//! `uipc_usrreq.c`, and `sockargs` rejects control data above `MCLBYTES`
//! (2048). `CMSG_SPACE(512 * sizeof(int))` covers every cmsg the kernel accepts,
//! so truncation is not a normal outcome. The native proof on the audited
//! 64-bit host accepted 254 rights; this is not a public SDK ABI limit.
//!
//! Every descriptor the kernel *reports* is wrapped immediately, marked
//! close-on-exec, and closed on any validation failure. A truncated control
//! layout can hide installed rights that nothing can close; that case, and only
//! that case, fail-stops the importing process with `_exit` while the fd guard
//! is still held. This module never scans the process to recover an fd.
//!
//! There is no `MSG_PEEK` here. A second, non-blocking `recvmsg` over the same
//! buffer under the same guard collects any already queued extra datagram so its
//! rights are marked and closed before the handoff is refused.

use super::fd_guard;
use std::{
    io,
    mem::size_of,
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

const MAGIC: [u8; 4] = *b"VPUF";
const VERSION: u8 = 1;
/// `VPUF` + version 1 + three reserved zero bytes.
const PAYLOAD: [u8; 8] = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION, 0, 0, 0];
/// `UIPC_MAX_CMSG_FD` in the kernel source. Not reduced per test inside this
/// process: production always receives with the conservative bound.
const CAPACITY: usize = 512;
const CONTROL: usize =
    unsafe { libc::CMSG_SPACE((CAPACITY * size_of::<libc::c_int>()) as libc::c_uint) } as usize;
const _: () = assert!(CONTROL >= 2048 + 12, "ancillary buffer below MCLBYTES");

#[repr(align(8))]
struct Control([u8; CONTROL]);

pub(super) enum Collected {
    Ready(OwnedFd),
    /// The readiness wait raced; retry without holding the guard.
    Retry,
}

struct Raw {
    length: usize,
    payload: [u8; PAYLOAD.len()],
    flags: i32,
    descriptors: Vec<OwnedFd>,
    malformed: bool,
}

/// Receives and validates the single handoff. Must run under the fd guard. On
/// success exactly one descriptor is returned; every other outcome drops the
/// collected descriptors.
pub(super) fn collect(fd: RawFd) -> io::Result<Collected> {
    let Some(raw) = receive_raw(fd)? else {
        return Ok(Collected::Retry);
    };
    validate(&raw)?;
    // A second queued datagram is not part of the single handoff. Consume it
    // over the same buffer, close whatever it delivered, and refuse. The real
    // plugin closes FD3 right after send, so a peer close observed only here
    // (ECONNRESET) is the normal end of the channel, not a failed handoff.
    match receive_raw(fd) {
        Ok(None) => {}
        Ok(Some(_)) => return Err(invalid_data()),
        Err(error) if error.raw_os_error() == Some(libc::ECONNRESET) => {}
        Err(error) => return Err(error),
    }
    let mut descriptors = raw.descriptors;
    if descriptors.len() != 1 {
        return Err(invalid_data());
    }
    Ok(Collected::Ready(descriptors.remove(0)))
}

fn validate(raw: &Raw) -> io::Result<()> {
    if raw.malformed
        || raw.flags & libc::MSG_TRUNC != 0
        || raw.length != PAYLOAD.len()
        || raw.payload != PAYLOAD
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn receive_raw(fd: RawFd) -> io::Result<Option<Raw>> {
    receive_raw_limited(fd, CONTROL)
}

/// Test-only entry for the fail-stop branch: the same real `recvmsg` over a
/// deliberately smaller declared control length. Production always uses
/// `CONTROL`; nothing here is reachable from the helper's normal path.
#[cfg(test)]
pub(super) fn receive_once_limited(fd: RawFd, controllen: usize) -> io::Result<()> {
    receive_raw_limited(fd, controllen).map(|_| ())
}

fn receive_raw_limited(fd: RawFd, controllen: usize) -> io::Result<Option<Raw>> {
    let mut payload = [0u8; PAYLOAD.len()];
    let mut control = Control([0u8; CONTROL]);
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: msghdr is a plain C struct; all-zero bits are valid.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = controllen.min(CONTROL) as _;
    // SAFETY: descriptor is live, iovec/control buffers are valid and sized.
    let length = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    if length < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            // `EWOULDBLOCK` is the same value as `EAGAIN` here.
            Some(libc::EINTR) | Some(libc::EAGAIN) => Ok(None),
            // `unp_externalize` reserves every receiving slot before it
            // installs anything and rolls back on failure, so this is a
            // missing-slot error with no descriptor delivered. Propagate it;
            // never fail-stop the helper for a lack of slots.
            Some(libc::EMSGSIZE) => Err(error),
            _ => Err(error),
        };
    }
    let mut raw = Raw {
        length: length as usize,
        payload,
        flags: message.msg_flags,
        descriptors: Vec::new(),
        malformed: false,
    };
    // SAFETY: the kernel filled the control buffer; every pointer stays within
    // it and CMSG_NXTHDR validates bounds and alignment before returning.
    unsafe {
        let mut cursor = libc::CMSG_FIRSTHDR(&message);
        while !cursor.is_null() {
            let cmsg = &*cursor;
            let cmsg_len = cmsg.cmsg_len as usize;
            let base = libc::CMSG_LEN(0) as usize;
            if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
                raw.malformed = true;
            } else if cmsg_len < base
                || cmsg_len > controllen
                || !(cmsg_len - base).is_multiple_of(size_of::<libc::c_int>())
            {
                // A length that cannot describe an integral number of fds could
                // hide installed rights in the unparsed tail.
                fd_guard::fail_stop();
            } else {
                let data = libc::CMSG_DATA(cursor);
                let count = (cmsg_len - base) / size_of::<libc::c_int>();
                for index in 0..count {
                    let pointer = data.add(index * size_of::<libc::c_int>()) as *const libc::c_int;
                    let descriptor = pointer.read_unaligned();
                    if descriptor < 0 {
                        raw.malformed = true;
                        continue;
                    }
                    // SAFETY: the kernel installed this descriptor here; this
                    // OwnedFd becomes its only owner and closes it on drop.
                    raw.descriptors.push(OwnedFd::from_raw_fd(descriptor));
                    if fd_guard::mark_cloexec(descriptor).is_err() {
                        raw.malformed = true;
                    }
                }
            }
            cursor = libc::CMSG_NXTHDR(&message, cursor);
        }
    }
    if raw.flags & libc::MSG_CTRUNC != 0 {
        // The kernel installed descriptors it did not report: nothing can close
        // or mark them. Fail-stop before any spawn can inherit them.
        fd_guard::fail_stop();
    }
    Ok(Some(raw))
}

fn invalid_data() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
