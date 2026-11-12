use super::*;
use crate::helper::local_socket::{Budget, connect_deadline};
use std::{
    fs,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
};
pub(super) fn stamp(path: &Path, owner: u32) -> Result<files::Stamp, Error> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Unavailable
        } else {
            Error::Changed
        }
    })?;
    if !meta.file_type().is_socket()
        || meta.uid() != owner
        || meta.nlink() != 1
        || meta.mode() & 0o7007 != 0
        || meta.mode() & 0o600 != 0o600
    {
        return Err(Error::Changed);
    }
    crate::fs_permissions::check_path(path, true).map_err(|_| Error::Changed)?;
    Ok(files::Stamp::of(&meta))
}
pub(super) fn connect(
    path: &Path,
    owner: u32,
    pid: u32,
    expires: Instant,
    cancel: Arc<AtomicBool>,
) -> Result<Client, Error> {
    let budget = Budget::until(expires, Some(cancel.clone())).map_err(map)?;
    let stream = connect_deadline(path, &budget).map_err(map)?;
    let mut peer: i32 = 0;
    let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
    // SOL_LOCAL/LOCAL_PEERPID from the Darwin sys/un.h API. PID is bound to
    // this connected endpoint, never recovered from a named PID file.
    // SAFETY: stream is live and the integer output and length match.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            2,
            (&mut peer as *mut i32).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&peer)
        || peer <= 0
        || peer as u32 != pid
    {
        return Err(Error::Changed);
    }
    Client::from_stream_until(stream, owner, expires, cancel).map_err(|e| match e {
        crate::helper::vici::Error::Canceled => Error::Canceled,
        crate::helper::vici::Error::Timeout => Error::Timeout,
        _ => Error::Changed,
    })
}
fn map(e: std::io::Error) -> Error {
    match crate::helper::vici::Error::from(e) {
        crate::helper::vici::Error::Canceled => Error::Canceled,
        crate::helper::vici::Error::Timeout => Error::Timeout,
        _ => Error::Unavailable,
    }
}
