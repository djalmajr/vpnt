use super::{Address, Error, Key, Network, NextHop, Reader, Route, add_codec, codec};
use crate::{
    connection::macos::{ppp::OwnedPpp, ppp_attachment::PppAttachment, sink::OwnedSink, tcp},
    helper::controller_lock::ControllerLock,
};
use std::{
    io,
    mem::{offset_of, size_of},
    os::fd::{AsRawFd, OwnedFd},
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    time::{Duration, Instant},
};

static NEXT_ADD: AtomicI32 = AtomicI32::new(1);
/// An attempted ADD must stay in the cleanup plan even if its ACK is lost.
/// This is not an identity for a route object and never authorizes DELETE.
#[must_use = "retain attempted routes until interface teardown and observed cleanup"]
pub struct AddReceipt {
    route: Route,
    confirmation: Result<(), Error>,
}
impl AddReceipt {
    pub fn route(&self) -> Route {
        self.route
    }
    pub fn confirmation(&self) -> Result<(), Error> {
        self.confirmation
    }
}
pub struct AddWriter<'a> {
    fd: OwnedFd,
    controller: &'a ControllerLock,
}
impl<'a> AddWriter<'a> {
    pub fn open(controller: &'a ControllerLock) -> Result<Self, Error> {
        // SAFETY: UID queries have no memory preconditions.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(Error::Unavailable);
        }
        controller.validate().map_err(|_| Error::Changed)?;
        Ok(Self {
            fd: Reader::open()?.fd,
            controller,
        })
    }
    /// The interface/index/source come only from the retained PPP capability,
    /// never from IPC. Unsupported address families require a separate owned
    /// sink; this method cannot silently send them through another interface.
    pub fn add(
        &mut self,
        ppp: &OwnedPpp,
        attachment: &PppAttachment<'_>,
        network: Network,
        timeout: Duration,
        canceled: &AtomicBool,
    ) -> Result<AddReceipt, Error> {
        if !std::ptr::eq(self.controller, attachment.controller())
            || ppp.index() != attachment.index() as u32
        {
            return Err(Error::Invalid);
        }
        attachment.validate().map_err(|_| Error::Changed)?;
        if !ppp.is_current().map_err(|_| Error::Unavailable)? {
            return Err(Error::Changed);
        }
        let source = attachment
            .source(network.address().is_ipv4())
            .ok_or(Error::Invalid)?;
        let route = Route {
            key: Key { network, scope: 0 },
            interface: attachment.index(),
            next_hop: NextHop::Interface,
        };
        let source = Address {
            ip: source,
            zone: if matches!(source,std::net::IpAddr::V6(value) if value.is_unicast_link_local()) {
                attachment.index() as u32
            } else {
                0
            },
        };
        let mut receipt = exchange(&self.fd, route, source, timeout, canceled)?;
        if attachment.validate().is_err() || !ppp.is_current().unwrap_or(false) {
            receipt.confirmation = Err(Error::Changed);
        }
        Ok(receipt)
    }
    pub(super) fn add_sink(
        &mut self,
        sink: &OwnedSink<'_>,
        network: Network,
        timeout: Duration,
        canceled: &AtomicBool,
    ) -> Result<AddReceipt, Error> {
        if !std::ptr::eq(self.controller, sink.controller()) {
            return Err(Error::Invalid);
        }
        sink.validate()?;
        let source = sink
            .source(network.address().is_ipv4())
            .ok_or(Error::Invalid)?;
        let route = Route {
            key: Key { network, scope: 0 },
            interface: sink.index(),
            next_hop: NextHop::Blackhole,
        };
        let mut receipt = exchange(
            &self.fd,
            route,
            Address::unscoped(source),
            timeout,
            canceled,
        )?;
        if sink.validate().is_err() {
            receipt.confirmation = Err(Error::Changed);
        }
        Ok(receipt)
    }
}
fn sequence() -> Result<i32, Error> {
    let mut value = NEXT_ADD.load(Ordering::Relaxed);
    loop {
        let next = value.checked_add(1).ok_or(Error::Limit)?;
        match NEXT_ADD.compare_exchange_weak(value, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(value),
            Err(current) => value = current,
        }
    }
}
fn exchange(
    fd: &OwnedFd,
    route: Route,
    source: Address,
    timeout: Duration,
    canceled: &AtomicBool,
) -> Result<AddReceipt, Error> {
    if timeout.is_zero() || timeout > Duration::from_secs(2) {
        return Err(Error::Invalid);
    }
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    let pid = i32::try_from(std::process::id()).map_err(|_| Error::Invalid)?;
    let sequence = sequence()?;
    let packet = add_codec::add(route, source, pid, sequence)?;
    let deadline = Instant::now() + timeout;
    tcp::wait(fd.as_raw_fd(), libc::POLLOUT, deadline, canceled).map_err(wait_error)?;
    if canceled.load(Ordering::Acquire) {
        return Err(Error::Canceled);
    }
    // SAFETY: the owned nonblocking socket and complete ADD packet are live.
    // Every result after this point retains an attempted-route receipt.
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    let confirmation = if sent < 0 {
        Err(kernel_error(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ))
    } else if sent != packet.len() as isize {
        Err(Error::Unavailable)
    } else {
        confirm(fd, route, source, pid, sequence, deadline, canceled)
    };
    Ok(AddReceipt {
        route,
        confirmation,
    })
}
fn confirm(
    fd: &OwnedFd,
    route: Route,
    source: Address,
    pid: i32,
    sequence: i32,
    deadline: Instant,
    canceled: &AtomicBool,
) -> Result<(), Error> {
    let mut bytes = vec![0; 65_536];
    for _ in 0..4096 {
        tcp::wait(fd.as_raw_fd(), libc::POLLIN, deadline, canceled).map_err(wait_error)?;
        // SAFETY: the live buffer has the supplied capacity, sufficient for
        // any u16-sized routing frame. Socket remains owned throughout.
        let length =
            unsafe { libc::recv(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if length < 0 {
            if matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(Error::Unavailable);
        }
        let frame = codec::frame(&bytes[..length as usize])?;
        if frame.len() != length as usize {
            return Err(Error::Invalid);
        }
        if frame[3] != libc::RTM_ADD as u8 {
            continue;
        }
        if frame.len() < size_of::<libc::rt_msghdr>() {
            return Err(Error::Invalid);
        }
        if codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_pid))? != pid
            || codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_seq))? != sequence
        {
            continue;
        }
        let errno = codec::signed(frame, offset_of!(libc::rt_msghdr, rtm_errno))?;
        if errno != 0 {
            return Err(kernel_error(errno));
        }
        if canceled.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        let actual = codec::record(frame, codec::CLASSIC)?;
        if actual.route()? != route || actual.source != Some(source) {
            return Err(Error::Changed);
        }
        return Ok(());
    }
    Err(Error::Limit)
}
fn kernel_error(errno: i32) -> Error {
    if errno == libc::EEXIST {
        Error::Conflict
    } else {
        Error::Unavailable
    }
}
fn wait_error(error: tcp::Error) -> Error {
    match error {
        tcp::Error::Canceled => Error::Canceled,
        tcp::Error::TimedOut => Error::TimedOut,
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
#[path = "write_tests.rs"]
mod tests;
