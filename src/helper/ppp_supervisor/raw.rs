//! Allocation-free IO used in the child before exec. No Rust locks/formatting.
use std::io;
const TIMEOUT_MS: i64 = 5_000;
fn now() -> io::Result<i64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime initializes this valid native timespec output.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value
        .tv_sec
        .saturating_mul(1000)
        .saturating_add(value.tv_nsec / 1_000_000))
}
pub(super) fn deadline() -> io::Result<i64> {
    Ok(now()?.saturating_add(TIMEOUT_MS))
}
pub(super) fn frame(magic: [u8; 4], pid: u32) -> [u8; 8] {
    let mut frame = [0u8; 8];
    frame[..4].copy_from_slice(&magic);
    frame[4..].copy_from_slice(&pid.to_be_bytes());
    frame
}
fn wait(fd: i32, events: i16, deadline: i64) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_sub(now()?);
        if remaining <= 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut item = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one valid descriptor record; poll writes only revents.
        let count = unsafe { libc::poll(&mut item, 1, remaining.min(i32::MAX as i64) as i32) };
        if count > 0 {
            return Ok(());
        }
        if count < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
pub(super) fn read(fd: i32, mut bytes: &mut [u8], deadline: i64) -> io::Result<()> {
    while !bytes.is_empty() {
        wait(fd, libc::POLLIN, deadline)?;
        // SAFETY: the supplied live buffer has at least bytes.len() capacity.
        let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        bytes = &mut bytes[count as usize..];
    }
    Ok(())
}
pub(super) fn write(fd: i32, mut bytes: &[u8], deadline: i64) -> io::Result<()> {
    while !bytes.is_empty() {
        wait(fd, libc::POLLOUT, deadline)?;
        // SAFETY: the buffer is initialized and live across this write. It is
        // used only on our private socket or announcement pipe, never stdio.
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        if count < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        bytes = &bytes[count as usize..];
    }
    Ok(())
}
pub(super) fn exchange(fd: i32, request: [u8; 8], magic: [u8; 4], pid: u32) -> io::Result<()> {
    let deadline = deadline()?;
    write(fd, &request, deadline)?;
    let mut reply = [0u8; 8];
    read(fd, &mut reply, deadline)?;
    if reply != frame(magic, pid) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
