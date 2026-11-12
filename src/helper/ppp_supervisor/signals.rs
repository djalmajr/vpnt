use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};
pub(super) static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: i32) {
    INTERRUPTED.store(true, Ordering::Release);
}
pub(super) struct Guard {
    previous: Vec<(i32, libc::sigaction)>,
}
impl Guard {
    pub fn install() -> io::Result<Self> {
        INTERRUPTED.store(false, Ordering::Release);
        let mut guard = Self { previous: vec![] };
        for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
            // SAFETY: sigaction is a C POD; both values are initialized before use.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = interrupt as *const () as usize;
            // SAFETY: action/previous/mask are live native structs; the handler
            // performs only a lock-free atomic store, no IO or unwinding.
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error());
            }
            guard.previous.push((signal, previous));
        }
        Ok(guard)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        for (signal, action) in &self.previous {
            // SAFETY: restore the native action saved for this exact signal.
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}
