use super::super::local_socket::peer_uid;
use std::{
    io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
};

pub(crate) struct Caller {
    pub uid: u32,
    pub stream: UnixStream,
}
impl Caller {
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let descriptor = fd.as_raw_fd();
        let mut kind = 0i32;
        let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
        // SAFETY: a live owned descriptor and an integer output of matching size.
        if unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut i32).cast(),
                &mut length,
            )
        } != 0
            || kind != libc::SOCK_STREAM
            || length as usize != std::mem::size_of_val(&kind)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Both ends must be unnamed. A connection to another user's named
        // echo/service socket must not turn that service UID into authority.
        if !anonymous(descriptor, true)? || !anonymous(descriptor, false)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // SAFETY: prevent the helper control capability from reaching exec'ed
        // clients. The conversion transfers this descriptor into one owner.
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = UnixStream::from(fd);
        let uid = peer_uid(&stream)?;
        if uid == 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self { uid, stream })
    }
}

fn anonymous(fd: i32, peer: bool) -> io::Result<bool> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: both APIs write to the complete zero-initialized sockaddr_un.
    // The connected peer check also rejects listeners and unconnected sockets.
    let result = unsafe {
        if peer {
            libc::getpeername(
                fd,
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut length,
            )
        } else {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut length,
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(
        length as usize >= std::mem::offset_of!(libc::sockaddr_un, sun_path)
            && length as usize <= std::mem::size_of_val(&address)
            && address.sun_family as i32 == libc::AF_UNIX
            && !address.sun_path.iter().any(|byte| *byte != 0),
    )
}
