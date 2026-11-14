use super::*;
use crate::helper::protocol::{self, Message};
use std::{
    io::{BufReader, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::Stdio,
    time::Duration,
};
use zeroize::Zeroizing;

pub(super) fn run(
    mut command: Command,
    request: AdminRequest,
    locale: Locale,
    expires: Instant,
    state: Arc<State>,
) {
    let result = (|| {
        let mut bytes = Zeroizing::new(Vec::new());
        protocol::write_admin_request(&mut *bytes, &request).map_err(|_| Error::Unavailable)?;
        protocol::read_admin_request(&mut BufReader::new(bytes.as_slice()))
            .map_err(|_| Error::Unavailable)?;
        let (mut channel, capability) = UnixStream::pair().map_err(|_| Error::Unavailable)?;
        channel
            .set_nonblocking(true)
            .map_err(|_| Error::Unavailable)?;
        let remaining = expires.saturating_duration_since(Instant::now());
        if remaining.is_zero() || remaining > Duration::from_secs(120) {
            return Err(Error::Expired);
        }
        let until = monotonic_ns()?
            .checked_add(u64::try_from(remaining.as_nanos()).map_err(|_| Error::Expired)?)
            .ok_or(Error::Expired)?;
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("SUDO_ASKPASS", paths::ASKPASS)
            .env("VPNT_AUTH_LOCALE", locale.code())
            .env("VPNT_AUTH_UNTIL_NS", until.to_string())
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(capability)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        check(&state, expires)?;
        let mut child = command.spawn().map_err(|_| Error::Unavailable)?;
        drop(command);
        let result = transaction(&mut channel, &bytes, &request.id, expires, &state);
        if let Err(error) = result {
            publish(&state, Err(error));
        }
        let _ = channel.shutdown(Shutdown::Both);
        drop(channel);
        drop(bytes);
        let exited = child.wait().map_err(|_| Error::Unavailable)?;
        result.and(if exited.success() {
            Ok(())
        } else {
            Err(Error::Unavailable)
        })
    })();
    publish(&state, result);
    state.finished.store(true, Ordering::Release);
}
fn publish(state: &State, result: Result<(), Error>) {
    if let Ok(mut slot) = state.result.lock()
        && slot.is_none()
    {
        *slot = Some(result);
    }
}
fn check(state: &State, expires: Instant) -> Result<(), Error> {
    if state.stop.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    if Instant::now() >= expires {
        return Err(Error::Expired);
    }
    Ok(())
}
fn transaction(
    channel: &mut UnixStream,
    bytes: &[u8],
    id: &str,
    expires: Instant,
    state: &State,
) -> Result<(), Error> {
    let mut input = Vec::new();
    match read(channel, &mut input, expires, state)? {
        Some(Message::AdminReady {
            protocol_version: _,
            version,
        }) if version == env!("CARGO_PKG_VERSION") => {}
        Some(Message::AdminReady { .. }) => return Err(Error::Incompatible),
        Some(Message::Fatal { error }) => return Err(Error::Rejected(error)),
        _ => return Err(Error::InvalidReply),
    }
    let deadline = expires.min(Instant::now() + Duration::from_secs(5));
    let mut written = 0;
    while written < bytes.len() {
        check(state, deadline)?;
        match channel.write(&bytes[written..]) {
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
    check(state, deadline)?;
    channel
        .shutdown(Shutdown::Write)
        .map_err(|_| Error::Unavailable)?;
    let result = match read(channel, &mut input, deadline, state)? {
        Some(Message::Accepted { id: got }) if got == id => Ok(()),
        Some(Message::Failed { id: got, error }) if got == id => Err(Error::Rejected(error)),
        Some(Message::Fatal { error }) => Err(Error::Rejected(error)),
        _ => return Err(Error::InvalidReply),
    };
    if read(channel, &mut input, deadline, state)?.is_some() {
        return Err(Error::InvalidReply);
    }
    result
}
fn read(
    channel: &mut UnixStream,
    input: &mut Vec<u8>,
    expires: Instant,
    state: &State,
) -> Result<Option<Message>, Error> {
    loop {
        check(state, expires)?;
        if let Some(end) = input.iter().position(|b| *b == b'\n') {
            if end + 1 > 4096 {
                return Err(Error::InvalidReply);
            }
            let frame: Vec<_> = input.drain(..=end).collect();
            return protocol::read_message(&mut BufReader::new(frame.as_slice())).map_err(|e| {
                if e == protocol::ProtocolError::UnsupportedVersion {
                    Error::Incompatible
                } else {
                    Error::InvalidReply
                }
            });
        }
        if input.len() >= 4096 {
            return Err(Error::InvalidReply);
        }
        let mut bytes = [0; 1024];
        match channel.read(&mut bytes) {
            Ok(0) => {
                return if input.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::InvalidReply)
                };
            }
            Ok(n) => input.extend_from_slice(&bytes[..n]),
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
pub(crate) fn monotonic_ns() -> Result<u64, Error> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(Error::Unavailable);
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|n| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|sub| n.checked_add(sub))
        })
        .ok_or(Error::Unavailable)
}
