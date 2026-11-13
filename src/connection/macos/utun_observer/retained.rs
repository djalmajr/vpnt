//! Typed retained utun interface bound to the child's received capability.
//!
//! The received descriptor is pinned here together with the observation of the
//! original child's utun. Admission and revalidation require the kernel SDK to
//! report the same unit/socket/pcb for *this* descriptor in *this* process, and
//! the interface name/index to agree in both directions. It carries no route,
//! VIP or cleanup authority; dropping it closes the last helper reference.
use super::{Error, InterfaceObservation, Source, check, native, utun_socket};
use crate::helper::charon_channel::Descriptor;
use std::{
    fmt,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

/// A retained, non-serializable interface. Not `Clone`: exactly one owner.
pub struct RetainedInterface {
    descriptor: Descriptor,
    observation: InterfaceObservation,
}

impl RetainedInterface {
    /// Crate-private admission from the real child observation. The descriptor
    /// is consumed on refusal, so a mismatching handoff cannot be retried.
    pub(crate) fn admit(
        descriptor: Descriptor,
        observation: InterfaceObservation,
        expires: Instant,
        cancel: &AtomicBool,
    ) -> Result<Self, Error> {
        check(expires, cancel)?;
        let retained = Self {
            descriptor,
            observation,
        };
        retained.validate_stamps(expires, cancel)?;
        if !reverse_ok(&retained.observation) {
            return Err(Error::Changed);
        }
        check(expires, cancel)?;
        Ok(retained)
    }

    pub fn name(&self) -> &str {
        self.observation.name()
    }

    pub fn index(&self) -> u32 {
        self.observation.index()
    }

    /// Read-only revalidation: same kernel stamps for this descriptor and the
    /// same reverse name/index mapping. Internals keep their private error;
    /// the public surface reports the advertised admission error.
    pub fn validate(&self) -> Result<(), crate::connection::ipsec::Error> {
        self.validate_inner().map_err(public_error)
    }

    fn validate_inner(&self) -> Result<(), Error> {
        let expires = Instant::now() + Duration::from_secs(1);
        let cancel = AtomicBool::new(false);
        self.validate_stamps(expires, &cancel)?;
        if reverse_ok(&self.observation) {
            Ok(())
        } else {
            Err(Error::Changed)
        }
    }

    fn validate_stamps(&self, expires: Instant, cancel: &AtomicBool) -> Result<(), Error> {
        check(expires, cancel)?;
        let observed = utun_socket::observe(std::process::id(), self.descriptor.raw_fd())
            .map_err(map_socket)?;
        check(expires, cancel)?;
        if stamps_match(&self.observation, &observed) {
            Ok(())
        } else {
            Err(Error::Changed)
        }
    }
}

impl fmt::Debug for RetainedInterface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedInterface")
            .field("name", &self.observation.name())
            .field("index", &self.observation.index())
            .finish_non_exhaustive()
    }
}

/// The same kernel socket must back the received descriptor and the child's
/// observed utun.
fn stamps_match(observation: &InterfaceObservation, observed: &utun_socket::Observation) -> bool {
    observed.unit == observation.unit
        && observed.socket == observation.socket
        && observed.pcb == observation.pcb
}

/// Reuses the observer's existing `Live` source instead of a second SDK lookup.
fn index_of(name: &str) -> u32 {
    Source::index_of(&mut native::Live::new(0), name)
}

fn name_of(index: u32) -> Option<String> {
    Source::name_of(&mut native::Live::new(0), index)
}

#[cfg(test)]
impl InterfaceObservation {
    /// Synthetic observation for the correlation tests only; no kernel query
    /// and no production source ever builds one.
    pub(crate) fn synthetic_for_test(
        name: &str,
        index: u32,
        unit: u32,
        socket: u64,
        pcb: u64,
    ) -> Self {
        Self {
            name: name.to_owned(),
            index,
            fd: -1,
            unit,
            pid: 0,
            socket,
            pcb,
        }
    }
}

fn reverse_ok(observation: &InterfaceObservation) -> bool {
    let index = observation.index();
    index != 0
        && index_of(observation.name()) == index
        && name_of(index).as_deref() == Some(observation.name())
}

/// Private admission errors mapped onto the public contract; no internal
/// variant name or type escapes.
fn public_error(error: Error) -> crate::connection::ipsec::Error {
    use crate::connection::ipsec::Error as Public;
    match error {
        Error::Changed | Error::Ambiguous => Public::Changed,
        Error::Canceled => Public::Canceled,
        Error::Timeout => Public::Timeout,
        Error::Unavailable | Error::NotFound => Public::Unavailable,
        Error::Exhausted => Public::Exhausted,
        Error::Permission => Public::PermissionDenied,
        Error::Invalid => Public::Invalid,
    }
}

fn map_socket(error: utun_socket::Error) -> Error {
    match error {
        utun_socket::Error::NotUtun | utun_socket::Error::Changed | utun_socket::Error::Abi => {
            Error::Changed
        }
        utun_socket::Error::Permission => Error::Permission,
        utun_socket::Error::Unavailable => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic: exercises the correlation comparison only. A real typed utun
    // positive is not run anywhere in this slice.
    #[test]
    fn synthetic_stamp_comparison_accepts_a_match_and_refuses_every_mismatch() {
        let observation = InterfaceObservation::synthetic_for_test("utun6", 12, 7, 0x55, 0x77);
        let observed = utun_socket::Observation {
            unit: 7,
            socket: 0x55,
            pcb: 0x77,
        };
        assert!(stamps_match(&observation, &observed));
        for wrong in [
            utun_socket::Observation {
                unit: 8,
                ..observed
            },
            utun_socket::Observation {
                socket: 0x56,
                ..observed
            },
            utun_socket::Observation {
                pcb: 0x78,
                ..observed
            },
        ] {
            assert!(!stamps_match(&observation, &wrong));
        }
    }

    // Synthetic negative for the reverse mapping; the positive direction needs
    // the host interface table, so it is left to the real observation path.
    #[test]
    fn synthetic_reverse_mapping_refuses_a_name_the_host_does_not_map() {
        let observation = InterfaceObservation::synthetic_for_test("vpnt-none", 12, 7, 0x55, 0x77);
        assert!(!reverse_ok(&observation));
        let zero = InterfaceObservation::synthetic_for_test("utun6", 0, 7, 0x55, 0x77);
        assert!(!reverse_ok(&zero));
    }
}
