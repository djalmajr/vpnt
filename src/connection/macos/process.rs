//! Read-only process identity and kernel exit observation. This module never
//! signals a PID read from a pidfile, nor enumerates processes by name.
use std::{
    ffi::CStr,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    ptr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Identity {
    pub pid: u32,
    pub start: (u64, u64),
}
#[derive(Debug)]
pub(super) struct Process {
    pub identity: Identity,
    pub parent: u32,
    pub uid: u32,
    pub real_uid: u32,
    pub running: bool,
    pub executable: PathBuf,
}
fn bsd(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: proc_bsdinfo contains only integer fields and byte arrays.
    let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
    // SAFETY: a correctly sized writable struct is supplied to the native API.
    let size = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            mem::size_of_val(&info) as i32,
        )
    };
    if size as usize != mem::size_of_val(&info) || info.pbi_pid != pid {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    Ok(info)
}
impl Process {
    pub fn read(pid: u32) -> io::Result<Self> {
        let before = bsd(pid)?;
        let mut path = [0u8; 4096];
        // SAFETY: path is a writable native path buffer of the advertised size.
        let length =
            unsafe { libc::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32) };
        if length <= 0 || length as usize >= path.len() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let executable = CStr::from_bytes_until_nul(&path)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
            .to_str()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let after = bsd(pid)?;
        if before.pbi_start_tvsec != after.pbi_start_tvsec
            || before.pbi_start_tvusec != after.pbi_start_tvusec
            || before.pbi_ppid != after.pbi_ppid
            || before.pbi_uid != after.pbi_uid
            || before.pbi_ruid != after.pbi_ruid
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(Self {
            identity: Identity {
                pid,
                start: (after.pbi_start_tvsec, after.pbi_start_tvusec),
            },
            parent: after.pbi_ppid,
            uid: after.pbi_uid,
            real_uid: after.pbi_ruid,
            // PROC_FLAG_INEXIT = 4 in the public libproc/proc_info.h header.
            running: after.pbi_status != libc::SZOMB && after.pbi_flags & 4 == 0,
            executable: executable.into(),
        })
    }
}

pub(super) struct ExitWatch {
    fd: OwnedFd,
    pid: u32,
    exited: bool,
}
impl ExitWatch {
    pub fn attach(identity: &Identity) -> io::Result<Self> {
        // SAFETY: kqueue creates a new descriptor with no pointer arguments.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: transfer the freshly created descriptor to exactly one owner.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fd is live; F_SETFD takes integer flags.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let event = libc::kevent {
            ident: identity.pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: ptr::null_mut(),
        };
        // SAFETY: one valid registration; no output buffer or wait is requested.
        if unsafe { libc::kevent(fd.as_raw_fd(), &event, 1, ptr::null_mut(), 0, ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if Process::read(identity.pid)?.identity != *identity {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(Self {
            fd,
            pid: identity.pid,
            exited: false,
        })
    }
    pub fn exited(&mut self) -> io::Result<bool> {
        if self.exited {
            return Ok(true);
        }
        // SAFETY: kevent has no invalid all-zero bit patterns.
        let mut event: libc::kevent = unsafe { mem::zeroed() };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid one-event output and nonblocking timeout are supplied.
        let count =
            unsafe { libc::kevent(self.fd.as_raw_fd(), ptr::null(), 0, &mut event, 1, &timeout) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 1 {
            if event.ident != self.pid as usize
                || event.flags & libc::EV_ERROR != 0
                || event.fflags & libc::NOTE_EXIT == 0
            {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            self.exited = true;
        }
        Ok(self.exited)
    }
}
