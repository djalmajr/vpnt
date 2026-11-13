//! Bounded owner lookup shared by read-only observation and typed take.
//!
//! Both callers run the same `try_lock`/deadline/cancel loop over the active
//! map: no blocking wait, no unbounded scan and no producer respawn.
use super::{Producer, map_check, map_observe};
use crate::connection::{
    ipsec::Error,
    macos::utun_observer::{self, InterfaceObservation, RetainedInterface},
    routes::Owner,
};
use std::{
    sync::{TryLockError, Weak, atomic::AtomicBool},
    time::{Duration, Instant},
};

fn with_active<'a, T>(
    context: &super::super::NativeContext<'a>,
    owner: &Owner,
    expires: Instant,
    cancel: &AtomicBool,
    mut action: impl FnMut(&mut Producer<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    loop {
        utun_observer::check(expires, cancel).map_err(map_check)?;
        let live: Vec<super::super::SharedProducer<'a>> = match context.active.try_lock() {
            Ok(map) => map.values().filter_map(Weak::upgrade).collect(),
            Err(TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
            Err(TryLockError::WouldBlock) => {
                utun_observer::check(expires, cancel).map_err(map_check)?;
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
        };
        let mut matching: Option<super::super::SharedProducer<'a>> = None;
        let mut busy = false;
        for producer in live {
            let matches = match producer.try_lock() {
                Ok(guard) => {
                    let matches = guard.lease.record.owner() == *owner;
                    drop(guard);
                    matches
                }
                Err(TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
                Err(TryLockError::WouldBlock) => {
                    busy = true;
                    false
                }
            };
            if matches {
                if matching.is_some() {
                    return Err(Error::Changed);
                }
                matching = Some(producer);
            }
        }
        if busy {
            utun_observer::check(expires, cancel).map_err(map_check)?;
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        let Some(producer) = matching else {
            return Err(Error::Unavailable);
        };
        loop {
            utun_observer::check(expires, cancel).map_err(map_check)?;
            match producer.try_lock() {
                Ok(mut producer) => return action(&mut producer),
                Err(TryLockError::Poisoned(_)) => return Err(Error::Unavailable),
                Err(TryLockError::WouldBlock) => {
                    utun_observer::check(expires, cancel).map_err(map_check)?;
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
}

pub(crate) fn observe_active<'a>(
    context: &super::super::NativeContext<'a>,
    owner: &Owner,
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<InterfaceObservation, Error> {
    with_active(context, owner, expires, cancel, |producer| {
        producer.observe_interface(owner, expires, cancel)
    })
}

pub(crate) fn take_active<'a>(
    context: &super::super::NativeContext<'a>,
    owner: &Owner,
    expires: Instant,
    cancel: &AtomicBool,
) -> Result<RetainedInterface, Error> {
    with_active(context, owner, expires, cancel, |producer| {
        producer.take_interface(owner, expires, cancel)
    })
}

impl<'a> Producer<'a> {
    /// Take the typed retained interface exactly once for this attempt. The
    /// cached descriptor is consumed even when admission refuses it.
    pub(super) fn take_interface(
        &mut self,
        owner: &Owner,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<RetainedInterface, Error> {
        if self.lease.record.owner() != *owner || self.retired || self.released || !self.attempted {
            return Err(Error::Changed);
        }
        self.current(expires, cancel)?;
        let descriptor = self.descriptor.take().ok_or(Error::Changed)?;
        let observation = self.observe_child(expires, cancel)?;
        self.current(expires, cancel)?;
        let retained = RetainedInterface::admit(descriptor, observation, expires, cancel)
            .map_err(map_observe)?;
        self.current(expires, cancel)?;
        Ok(retained)
    }
    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn invalidate_binding(&mut self) {
        if let Some(binding) = self.binding.as_mut() {
            binding.invalidate_for_test();
        }
    }
    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn fail_next_binding(&mut self, error: Error) {
        if let Some(binding) = self.binding.as_ref() {
            binding.fail_next_validation(error);
        }
    }
    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn child_exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_none_or(|c| c.poll().unwrap().is_some())
    }
    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn cached_fd(&self) -> Option<i32> {
        self.descriptor
            .as_ref()
            .map(|descriptor| descriptor.raw_fd())
    }
    #[cfg(test)]
    pub(in crate::connection::ipsec::producer) fn status(
        &mut self,
    ) -> Option<std::process::ExitStatus> {
        self.child.as_mut().and_then(|c| c.poll().unwrap())
    }
}
