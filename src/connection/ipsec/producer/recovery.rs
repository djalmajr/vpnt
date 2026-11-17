//! Startup observer. It never attaches to or terminates an orphaned daemon.
use super::{
    Error, NativeContext, Process,
    record::{Birth, Record},
    state::{ObserveOrphan, Store},
};
use crate::{
    connection::{
        ipsec::pfkey::{Entry, Kind, read::Reader},
        macos::ipsec_early_cleanup,
        routes::Owner,
    },
    helper::{
        controller_lock::ControllerLock,
        runtime::cleanup::{self, Reason},
    },
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

struct NativeObserver<'a>(&'a ControllerLock, Instant);

impl ObserveOrphan for NativeObserver<'_> {
    fn birth_absent(&mut self, birth: &Birth) -> Result<bool, Error> {
        match Process::read(birth.pid) {
            Ok(process) => Ok(process.identity.start != birth.start),
            Err(_) => {
                // SAFETY: validated birth PID is positive. Signal zero only
                // queries existence, including when libproc could not read it.
                if unsafe { libc::kill(birth.pid as i32, 0) } == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    Ok(true)
                } else {
                    Err(Error::Unavailable)
                }
            }
        }
    }

    fn resources_absent(&mut self, record: &Record) -> Result<bool, Reason> {
        let link = record
            .link
            .as_ref()
            .map(|link| (link.name.as_str(), link.index.get(), link.vips.as_slice()));
        if !ipsec_early_cleanup::orphan_absent(link, &record.networks)
            .map_err(|_| Reason::ObservationFailed)?
        {
            return Ok(false);
        }
        // IKE and userspace ESP state die with charon. Also require complete,
        // read-only Darwin SAD and SPD dumps for the durable reqid.
        let reader = Reader::new(self.0).map_err(|_| Reason::ObservationFailed)?;
        let cancel = Arc::new(AtomicBool::new(false));
        for kind in [Kind::Sad, Kind::Spd] {
            let collection = reader
                .collect(kind, self.1, cancel.clone())
                .map_err(|_| Reason::ObservationFailed)?;
            for entry in collection.entries {
                if namespace_occupied(kind, &entry, record.reqid)? {
                    return Err(Reason::NamespaceOccupied);
                }
            }
        }
        Ok(true)
    }
}

fn namespace_occupied(kind: Kind, entry: &Entry, reqid: u16) -> Result<bool, Reason> {
    match (kind, entry) {
        (Kind::Sad, Entry::Sa(sa)) => Ok(sa.reqid == u32::from(reqid)),
        (Kind::Spd, Entry::Policy(policy)) => {
            Ok(policy.requests.iter().any(|request| request.reqid == reqid))
        }
        _ => Err(Reason::ObservationFailed),
    }
}

impl NativeContext<'_> {
    pub(crate) fn recover_orphans(controller: &ControllerLock, uid: u32) {
        // SAFETY: UID queries have no memory preconditions.
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } || controller.validate().is_err()
        {
            return;
        }
        let unknown = Owner {
            uid,
            profile: "ipsec".into(),
            generation: 0,
        };
        let report = |owner: Option<&Owner>, reason| {
            cleanup::begin();
            cleanup::mark(reason);
            cleanup::finish(controller.directory(), owner.unwrap_or(&unknown), false);
        };
        let result = Process::read(std::process::id())
            .map_err(|_| Reason::ObservationFailed)
            .and_then(|process| {
                Store::recover_orphans(
                    controller,
                    0,
                    &Birth::from(&process.identity),
                    &mut NativeObserver(controller, Instant::now() + Duration::from_secs(2)),
                    report,
                )
            });
        if let Err(reason) = result {
            report(None, reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{
        ipsec::pfkey::{Endpoint, Policy, Request, Sa, Selector},
        routes::Address,
    };

    #[test]
    fn startup_orphan_distinguishes_live_birth_reused_pid_and_absent_pid() {
        let fixture = super::super::tests::Fixture::new();
        let process = Process::read(std::process::id()).unwrap();
        let actual = Birth::from(&process.identity);
        let mut observer = NativeObserver(&fixture.controller, Instant::now());
        assert_eq!(observer.birth_absent(&actual), Ok(false));
        let reused = Birth {
            start: (1, 0),
            ..actual
        };
        assert_eq!(observer.birth_absent(&reused), Ok(true));
        let absent = Birth {
            pid: i32::MAX as u32,
            start: (1, 0),
        };
        assert_eq!(observer.birth_absent(&absent), Ok(true));
    }

    #[test]
    fn startup_orphan_rejects_matching_sad_and_spd_entries_and_wrong_dump_kind() {
        let endpoint = Endpoint {
            address: Address::unscoped("192.0.2.1".parse().unwrap()),
            port: 0,
        };
        let sa = Entry::Sa(Sa {
            protocol: 50,
            spi: 1,
            state: 1,
            flags: 0,
            reqid: 7,
            mode: 1,
            replay_sequence: 0,
            source: endpoint,
            destination: endpoint,
            natt_port: None,
            lifetime: None,
            extra_extensions: Default::default(),
        });
        let selector = Selector {
            start: endpoint,
            end: None,
            prefix: 32,
            protocol: 0,
        };
        let policy = Entry::Policy(Policy {
            id: 1,
            kind: 2,
            direction: 1,
            source: selector.clone(),
            destination: selector,
            requests: vec![Request {
                protocol: 50,
                mode: 1,
                level: 1,
                reqid: 7,
                endpoints: None,
            }],
            extra_extensions: Default::default(),
        });
        for (kind, entry) in [(Kind::Sad, sa), (Kind::Spd, policy)] {
            assert_eq!(namespace_occupied(kind, &entry, 7), Ok(true));
            assert_eq!(namespace_occupied(kind, &entry, 8), Ok(false));
            assert_eq!(
                namespace_occupied(kind, &Entry::KernelError(0), 7),
                Err(Reason::ObservationFailed)
            );
        }
    }
}
