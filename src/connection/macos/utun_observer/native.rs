//! Kernel-backed source for the bounded utun observer.
use super::{Error, Source};
use crate::connection::macos::utun_socket;
use std::{
    ffi::{CStr, CString, c_char, c_int},
    mem, ptr,
};

pub(super) struct Live {
    pid: u32,
}

impl Live {
    pub(super) fn new(pid: u32) -> Self {
        Self { pid }
    }
}

impl Source for Live {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn hint(&mut self) -> Result<usize, Error> {
        let size = mem::size_of::<libc::proc_fdinfo>();
        // SAFETY: a null buffer with size zero only requests the entry hint.
        let length = unsafe {
            libc::proc_pidinfo(
                self.pid as c_int,
                libc::PROC_PIDLISTFDS,
                0,
                ptr::null_mut(),
                0,
            )
        };
        if length < 0 {
            return Err(Error::Unavailable);
        }
        Ok(length as usize / size)
    }

    fn list(&mut self, capacity: usize) -> Result<Vec<(i32, u32)>, Error> {
        let size = mem::size_of::<libc::proc_fdinfo>();
        let bytes = capacity.checked_mul(size).ok_or(Error::Invalid)?;
        if bytes > i32::MAX as usize {
            return Err(Error::Invalid);
        }
        let mut buffer = Vec::new();
        buffer.resize_with(capacity, || libc::proc_fdinfo {
            proc_fd: -1,
            proc_fdtype: 0,
        });
        // SAFETY: the writable buffer holds `capacity` entries and the kernel
        // writes at most that many bytes.
        let length = unsafe {
            libc::proc_pidinfo(
                self.pid as c_int,
                libc::PROC_PIDLISTFDS,
                0,
                buffer.as_mut_ptr().cast(),
                bytes as c_int,
            )
        };
        if length < 0 {
            return Err(Error::Unavailable);
        }
        let length = length as usize;
        if length > bytes || !length.is_multiple_of(size) {
            return Err(Error::Invalid);
        }
        Ok(buffer[..length / size]
            .iter()
            .map(|entry| (entry.proc_fd, entry.proc_fdtype))
            .collect())
    }

    fn socket(&mut self, fd: i32) -> Result<utun_socket::Observation, utun_socket::Error> {
        utun_socket::observe(self.pid, fd)
    }

    fn index_of(&mut self, name: &str) -> u32 {
        let Ok(name) = CString::new(name) else {
            return 0;
        };
        // SAFETY: a NUL-terminated name is passed to the read-only lookup.
        unsafe { libc::if_nametoindex(name.as_ptr()) }
    }

    fn name_of(&mut self, index: u32) -> Option<String> {
        let mut buffer = [0 as c_char; libc::IF_NAMESIZE];
        // SAFETY: the buffer has IF_NAMESIZE bytes and the call is read-only.
        let name = unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) };
        if name.is_null() {
            return None;
        }
        // SAFETY: if_indextoname returned a NUL-terminated name in `buffer`.
        let name = unsafe { CStr::from_ptr(name) };
        name.to_str().ok().map(str::to_owned)
    }
}
