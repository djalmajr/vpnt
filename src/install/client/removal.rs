use super::*;
use crate::install::protocol::{self, Reply, Request};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
};
pub(super) fn exchange(
    stream: &mut UnixStream,
    id: &str,
    expires: Instant,
    state: &State,
) -> Result<Option<Receipt>, Error> {
    let mut input = Vec::new();
    match read(stream, &mut input, expires, state)? {
        Some(Reply::Ready { format, version })
            if format == protocol::FORMAT && version == env!("CARGO_PKG_VERSION") => {}
        Some(Reply::Ready { .. }) => return Err(Error::Incompatible),
        Some(Reply::Failed { error, .. }) => return Err(Error::Rejected(error)),
        _ => return Err(Error::InvalidReply),
    }
    let deadline = expires.min(Instant::now() + Duration::from_secs(5));
    let mut bytes =
        serde_json::to_vec(&Request { id: id.into() }).map_err(|_| Error::Unavailable)?;
    bytes.push(b'\n');
    let mut written = 0;
    while written < bytes.len() {
        check(state, deadline)?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(Error::Unavailable),
        }
    }
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| Error::Unavailable)?;
    let result = match read(stream, &mut input, deadline, state)? {
        Some(Reply::Removed {
            id: got,
            component_present,
        }) if got == id => Ok(Some(Receipt::Removed { component_present })),
        Some(Reply::Failed {
            id: Some(got),
            error,
        }) if got == id => Err(Error::Rejected(error)),
        _ => return Err(Error::InvalidReply),
    };
    if read(stream, &mut input, deadline, state)?.is_some() {
        return Err(Error::InvalidReply);
    }
    result
}
fn read(
    stream: &mut UnixStream,
    input: &mut Vec<u8>,
    expires: Instant,
    state: &State,
) -> Result<Option<Reply>, Error> {
    loop {
        check(state, expires)?;
        if let Some(end) = input.iter().position(|b| *b == b'\n') {
            if end + 1 > 4096 {
                return Err(Error::InvalidReply);
            }
            let frame = input.drain(..=end).collect::<Vec<_>>();
            return serde_json::from_slice(&frame)
                .map(Some)
                .map_err(|_| Error::InvalidReply);
        }
        if input.len() >= 4096 {
            return Err(Error::InvalidReply);
        }
        let mut buffer = [0; 1024];
        match stream.read(&mut buffer) {
            Ok(0) => {
                return if input.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::InvalidReply)
                };
            }
            Ok(n) => input.extend_from_slice(&buffer[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(Error::Unavailable),
        }
    }
}
