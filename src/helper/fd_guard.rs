//! One helper-wide critical section around `fork/exec` and received descriptors.
//!
//! SCM_RIGHTS installs a descriptor in this process before `recvmsg` returns,
//! and macOS has no `MSG_CMSG_CLOEXEC`; the descriptor is inheritable until the
//! receiver marks it. Every own child spawn takes this same guard, so no fork
//! can happen between the kernel install and that `fcntl`. The guard is never
//! held while waiting for readiness or for a child to exit.
//!
//! If the kernel reports truncated ancillary data while the receiver uses its
//! full-size buffer, some installed descriptor was not reported: it can be
//! neither closed nor marked close-on-exec. The receiver then fail-stops this
//! process with `_exit`, still under the guard, instead of returning rights it
//! cannot account for. The kernel closes every descriptor on exit.

use super::local_socket::Budget;
use std::{
    io,
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::Duration,
};

static SPAWN_AND_RECEIVE: Mutex<()> = Mutex::new(());

/// Exit code of the importer fail-stop (root decision). Never a core dump.
pub(crate) const FAIL_STOP_EXIT: libc::c_int = 78;

/// Ordinary spawns serialize with descriptor reception. They do not claim hard
/// realtime; the critical sections are short and never wait for I/O.
pub(crate) fn spawn() -> MutexGuard<'static, ()> {
    SPAWN_AND_RECEIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bounded acquisition for the receive path: `try_lock` plus budget checks, so
/// a busy helper cannot hold the caller past its deadline or cancellation.
pub(crate) fn receive(budget: &Budget) -> io::Result<MutexGuard<'static, ()>> {
    loop {
        budget.check()?;
        match SPAWN_AND_RECEIVE.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                let wait = budget.poll_timeout()?.clamp(1, 5);
                thread::sleep(Duration::from_millis(wait as u64));
            }
        }
    }
}

/// Marks one kernel-delivered descriptor close-on-exec. The caller owns the
/// descriptor and must close it when this fails or when the message is refused.
pub(crate) fn mark_cloexec(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: the descriptor was just delivered by the kernel; F_SETFD takes
    // integer flags and touches no memory. F_SETFL is deliberately not used.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fail-stop the importing process without unwinding, flushing or a core dump.
/// The caller must hold the fd guard and must not have released anything to a
/// spawn; the kernel closes every descriptor, including unreported ones.
pub(crate) fn fail_stop() -> ! {
    // SAFETY: `_exit` is async-signal-safe and terminates immediately.
    unsafe { libc::_exit(FAIL_STOP_EXIT) }
}
