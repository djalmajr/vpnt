//! Observation-only adapter for the owned child's utun control socket.
//!
//! The C shim (`native/utun_socket.c`) owns the SDK `socket_fdinfo` layout and
//! returns fixed primitives. This wrapper validates that private ABI and yields
//! a typed unit/stamp observation. It never authorizes routes, cleanup or any
//! mutation, and it never exposes the kernel correlation stamps.
use std::ffi::c_int;
use std::fmt;
use std::mem::size_of;

const ABI_VERSION: u32 = 1;
const ABI_SIZE: u32 = 40;
const STATUS_MATCH: i32 = 0;
const STATUS_NOT_UTUN: i32 = 1;
const STATUS_CHANGED: i32 = 2;
const STATUS_PERMISSION: i32 = 3;
const STATUS_UNAVAILABLE: i32 = 4;
const STATUS_ABI: i32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
struct Raw {
    version: u32,
    size: u32,
    status: i32,
    unit: u32,
    reserved: u32,
    socket: u64,
    pcb: u64,
}

const _: () = assert!(size_of::<Raw>() as u32 == ABI_SIZE);

unsafe extern "C" {
    fn vpnt_utun_socketinfo(pid: c_int, fd: c_int, out: *mut Raw, out_size: u32) -> i32;
}

/// A live utun-control observation for the child that owns this descriptor.
///
/// Valid only for the descriptor/PID pair passed to [`observe`]; it is not a
/// cleanup, ownership or route receipt.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) unit: u32,
    /// Opaque kernel correlation stamp; never logged or returned publicly.
    pub(crate) socket: u64,
    /// Opaque kernel correlation stamp; never logged or returned publicly.
    pub(crate) pcb: u64,
}

impl fmt::Debug for Observation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Observation")
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// A real socket in the child, but not the utun control socket.
    NotUtun,
    /// The descriptor, PID or its socket changed/closed or is not inspectable.
    Changed,
    /// The process information call was denied.
    Permission,
    /// The native call failed for another reason or returned a short record.
    Unavailable,
    /// The native ABI, version, size or reserved fields do not match.
    Abi,
}

/// Observe one descriptor of the internal owned child.
///
/// `pid`/`fd` are producer-internal; this is not an IPC or public surface.
pub(crate) fn observe(pid: u32, fd: i32) -> Result<Observation, Error> {
    if pid == 0 || pid > i32::MAX as u32 || fd < 0 {
        return Err(Error::Changed);
    }
    let mut raw = Raw {
        version: 0,
        size: 0,
        status: 0,
        unit: 0,
        reserved: 0,
        socket: 0,
        pcb: 0,
    };
    let size = size_of::<Raw>() as u32;
    // SAFETY: `raw` is a correctly sized writable private-ABI object and the
    // shim validates the pointer/size before writing.
    let status = unsafe { vpnt_utun_socketinfo(pid as c_int, fd, &mut raw, size) };
    validate(&raw, size, status)
}

fn validate(raw: &Raw, size: u32, status: i32) -> Result<Observation, Error> {
    if status == STATUS_ABI {
        return Err(Error::Abi);
    }
    if raw.version != ABI_VERSION || raw.size != size || raw.status != status || raw.reserved != 0 {
        return Err(Error::Abi);
    }
    match status {
        STATUS_MATCH if raw.unit > 0 => Ok(Observation {
            unit: raw.unit,
            socket: raw.socket,
            pcb: raw.pcb,
        }),
        STATUS_MATCH => Err(Error::Abi),
        STATUS_NOT_UTUN => Err(Error::NotUtun),
        STATUS_CHANGED => Err(Error::Changed),
        STATUS_PERMISSION => Err(Error::Permission),
        STATUS_UNAVAILABLE => Err(Error::Unavailable),
        _ => Err(Error::Abi),
    }
}

#[cfg(test)]
mod tests;
