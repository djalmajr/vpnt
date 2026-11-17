//! Startup observer. It never attaches to or terminates an orphaned daemon.
use super::{
    Error, NativeContext, Process,
    record::{self, Birth, Record},
    state::{ObserveOrphan, Store},
};
use crate::{
    connection::{
        ipsec::pfkey::{Entry, Kind, read::Reader},
        macos::{Interfaces, ipsec_early_cleanup, routing::Snapshot},
        routes::{Error as RouteError, Owner},
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

/// Read-only views the startup proof needs. Production reads the kernel; the
/// tests inject each one, failures included, without root.
pub(super) trait OrphanReads {
    fn interfaces(&mut self) -> Result<Interfaces, RouteError>;
    fn routes(&mut self) -> Result<Snapshot, RouteError>;
    /// `kern.boottime` as `(seconds, microseconds)`, the same wall clock and
    /// layout as a recorded [`Birth::start`]. Unlike a recorded start, the
    /// kernel shifts it by every step of the wall clock: a forward step after
    /// the controller started moves it past that start.
    fn boot(&mut self) -> Result<(u64, u64), RouteError>;
    /// Start of PID 1 (launchd), fixed at its fork like a recorded
    /// [`Birth::start`]; a later clock step does not move it.
    fn launchd_start(&mut self) -> Result<(u64, u64), RouteError>;
    /// Current `kern.bootsessionuuid`.
    fn boot_session(&mut self) -> Result<String, RouteError>;
    fn pfkey(&mut self, kind: Kind) -> Result<Vec<Entry>, RouteError>;
}

struct NativeReads<'a>(&'a ControllerLock, Instant);

impl OrphanReads for NativeReads<'_> {
    fn interfaces(&mut self) -> Result<Interfaces, RouteError> {
        Interfaces::read().map_err(|_| RouteError::Unavailable)
    }

    fn routes(&mut self) -> Result<Snapshot, RouteError> {
        Snapshot::read()
    }

    fn boot(&mut self) -> Result<(u64, u64), RouteError> {
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        let mut value = std::mem::MaybeUninit::<libc::timeval>::zeroed();
        let mut size = std::mem::size_of::<libc::timeval>();
        // SAFETY: the MIB and the output buffer are valid for the sizes given;
        // the result is used only when the kernel filled the whole timeval.
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                value.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || size != std::mem::size_of::<libc::timeval>() {
            return Err(RouteError::Unavailable);
        }
        // SAFETY: the kernel wrote a complete timeval (checked above).
        let value = unsafe { value.assume_init() };
        let seconds = u64::try_from(value.tv_sec).map_err(|_| RouteError::Unavailable)?;
        let micros = u64::try_from(value.tv_usec).map_err(|_| RouteError::Unavailable)?;
        Ok((seconds, micros))
    }

    fn launchd_start(&mut self) -> Result<(u64, u64), RouteError> {
        Process::read(1)
            .map(|process| process.identity.start)
            .map_err(|_| RouteError::Unavailable)
    }

    fn boot_session(&mut self) -> Result<String, RouteError> {
        boot_session()
    }

    fn pfkey(&mut self, kind: Kind) -> Result<Vec<Entry>, RouteError> {
        // IKE and userspace ESP state die with charon. The kernel SAD and SPD
        // survive the process, so a complete read-only dump is required.
        let reader = Reader::new(self.0).map_err(|_| RouteError::Unavailable)?;
        reader
            .collect(kind, self.1, Arc::new(AtomicBool::new(false)))
            .map(|collection| collection.entries)
            .map_err(|_| RouteError::Unavailable)
    }
}

/// The current `kern.bootsessionuuid`, read without privileges. Only the
/// canonical UUID form is accepted.
pub(super) fn boot_session() -> Result<String, RouteError> {
    let mut bytes = [0u8; 64];
    let mut size = bytes.len();
    // SAFETY: the name is NUL-terminated and the buffer is valid for `size`
    // bytes; the kernel reports the length it wrote.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || size > bytes.len() {
        return Err(RouteError::Unavailable);
    }
    let text = std::ffi::CStr::from_bytes_until_nul(&bytes[..size])
        .map_err(|_| RouteError::Unavailable)?
        .to_str()
        .map_err(|_| RouteError::Unavailable)?;
    if !record::boot_session_valid(text) {
        return Err(RouteError::Unavailable);
    }
    Ok(text.to_owned())
}

/// A boot after the recorded controller started destroys every UTUN, VIP and
/// route the claim could own. Only a strictly later boot counts; a record
/// without a comparable start (no seconds) never does.
fn booted_after(controller: &Birth, boot: (u64, u64)) -> bool {
    controller.start.0 > 0 && boot > controller.start
}

/// Reboot proof. A claim that recorded its boot session is decided by that
/// UUID alone: a different current session proves a reboot, the same one
/// denies it, and no clock is read. A legacy claim compares its controller
/// start with the earlier of `kern.boottime` and launchd's start: a forward
/// clock step after the controller started moves the boottime but not
/// launchd's start; a backward step between the two lowers the boottime. When
/// launchd's start cannot be read the boottime alone decides.
fn rebooted(record: &Record, reads: &mut impl OrphanReads) -> Result<bool, RouteError> {
    if let Some(recorded) = &record.boot_session {
        return Ok(reads.boot_session()? != *recorded);
    }
    let boot = reads.boot()?;
    if !booted_after(&record.controller, boot) {
        return Ok(false);
    }
    Ok(match reads.launchd_start() {
        Ok(launchd) => booted_after(&record.controller, boot.min(launchd)),
        Err(_) => true,
    })
}

/// UTUN, VIP and route absence. A claim with a recorded link is checked
/// against it. When that evidence cannot decide (no link, or a possible sink:
/// see [`ipsec_early_cleanup::needs_fallback`]), only a reboot proves absence
/// on a host with system UTUNs; otherwise the conservative fallback decides.
fn host_absent(record: &Record, reads: &mut impl OrphanReads) -> Result<bool, RouteError> {
    let link = record
        .link
        .as_ref()
        .map(|link| (link.name.as_str(), link.index.get(), link.vips.as_slice()));
    if ipsec_early_cleanup::needs_fallback(link, &record.networks) && rebooted(record, reads)? {
        return Ok(true);
    }
    let interfaces = reads.interfaces()?;
    let table = reads.routes()?;
    ipsec_early_cleanup::orphan_observed(link, &record.networks, &interfaces, &table)
}

/// Every failed read is `ObservationFailed` and keeps the claim. SAD and SPD
/// are always read, after a boot proof too: any entry for the reqid keeps it.
pub(super) fn resources_absent_with(
    record: &Record,
    reads: &mut impl OrphanReads,
) -> Result<bool, Reason> {
    if !host_absent(record, reads).map_err(|_| Reason::ObservationFailed)? {
        return Ok(false);
    }
    for kind in [Kind::Sad, Kind::Spd] {
        let entries = reads.pfkey(kind).map_err(|_| Reason::ObservationFailed)?;
        for entry in entries {
            if namespace_occupied(kind, &entry, record.reqid)? {
                return Err(Reason::NamespaceOccupied);
            }
        }
    }
    Ok(true)
}

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
        resources_absent_with(record, &mut NativeReads(self.0, self.1))
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
    use super::super::record::{LinkClaim, Stage};
    use super::*;
    use crate::connection::{
        ipsec::pfkey::{Endpoint, Policy, Request, Sa, Selector},
        macos::vip::RetiredUtun,
        routes::Address,
    };

    const START: (u64, u64) = (1_000, 0);

    fn endpoint() -> Endpoint {
        Endpoint {
            address: Address::unscoped("192.0.2.1".parse().unwrap()),
            port: 0,
        }
    }

    fn sa(reqid: u32) -> Entry {
        Entry::Sa(Sa {
            protocol: 50,
            spi: 1,
            state: 1,
            flags: 0,
            reqid,
            mode: 1,
            replay_sequence: 0,
            source: endpoint(),
            destination: endpoint(),
            natt_port: None,
            lifetime: None,
            extra_extensions: Default::default(),
        })
    }

    fn policy(reqid: u16) -> Entry {
        let selector = Selector {
            start: endpoint(),
            end: None,
            prefix: 32,
            protocol: 0,
        };
        Entry::Policy(Policy {
            id: 1,
            kind: 2,
            direction: 1,
            source: selector.clone(),
            destination: selector,
            requests: vec![Request {
                protocol: 50,
                mode: 1,
                level: 1,
                reqid,
                endpoints: None,
            }],
            extra_extensions: Default::default(),
        })
    }

    fn record(link: Option<LinkClaim>) -> Record {
        let record = Record {
            version: 1,
            session: "0".repeat(32),
            uid: 501,
            profile: "orphan".into(),
            generation: 7,
            reqid: 7,
            connection: format!("vpnt-501-{}-7", "6f727068616e"),
            local: "192.0.2.2".parse().unwrap(),
            remote: "192.0.2.1".parse().unwrap(),
            networks: vec!["10.20.0.0/24".into()],
            controller: Birth {
                pid: 123,
                start: START,
            },
            runtime_hash: "a".repeat(64),
            configuration_hash: "b".repeat(64),
            transport_interface: None,
            stage: Stage::Stopped,
            child: Some(Birth {
                pid: 124,
                start: (1_001, 0),
            }),
            link,
            boot_session: None,
        };
        record.valid().unwrap();
        record
    }

    const SESSION: &str = "CE2DD70F-0000-4000-8000-000000000001";
    const OTHER_SESSION: &str = "CE2DD70F-0000-4000-8000-000000000002";

    /// A full tunnel with one VIP family: the controller may have opened a
    /// sink, so the claim's own link cannot settle absence.
    fn sink() -> Record {
        let mut record = linked();
        record.networks = vec!["0.0.0.0/0".into(), "::/0".into()];
        record.valid().unwrap();
        record
    }

    fn with_session(mut record: Record) -> Record {
        record.boot_session = Some(SESSION.into());
        record.valid().unwrap();
        record
    }

    fn linked() -> Record {
        record(Some(LinkClaim {
            name: "utun7".into(),
            index: std::num::NonZeroU16::new(7).unwrap(),
            vips: vec!["192.0.2.10".parse().unwrap()],
        }))
    }

    /// Injected kernel views. `system_utun` is the UTUN every Mac keeps;
    /// `retained` keeps the linked claim's own utun7 present.
    struct Fake {
        fail: Option<&'static str>,
        system_utun: bool,
        retained: bool,
        boot: (u64, u64),
        launchd: Result<(u64, u64), RouteError>,
        session: &'static str,
        sa: bool,
        policy: bool,
        log: Vec<&'static str>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                fail: None,
                system_utun: true,
                retained: false,
                boot: (2_000, 0),
                launchd: Ok((1_999, 0)),
                session: SESSION,
                sa: false,
                policy: false,
                log: Vec::new(),
            }
        }
    }

    impl Fake {
        fn read(&mut self, name: &'static str) -> Result<(), RouteError> {
            self.log.push(name);
            if self.fail == Some(name) {
                Err(RouteError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    impl OrphanReads for Fake {
        fn interfaces(&mut self) -> Result<Interfaces, RouteError> {
            self.read("interfaces")?;
            let up = libc::IFF_UP as u32;
            let mut entries: Vec<(&str, u32, u32, &[&str])> = vec![("en0", 2, up, &[])];
            if self.system_utun {
                entries.push(("utun0", 9, up, &[]));
            }
            if self.retained {
                entries.push(("utun7", 7, up, &[]));
            }
            Ok(RetiredUtun::view_for_test(&entries))
        }

        fn routes(&mut self) -> Result<Snapshot, RouteError> {
            self.read("routes")?;
            Ok(Snapshot {
                records: Vec::new(),
            })
        }

        fn boot(&mut self) -> Result<(u64, u64), RouteError> {
            self.read("boot")?;
            Ok(self.boot)
        }

        fn launchd_start(&mut self) -> Result<(u64, u64), RouteError> {
            self.read("launchd")?;
            self.launchd
        }

        fn boot_session(&mut self) -> Result<String, RouteError> {
            self.read("boot_session")?;
            Ok(self.session.into())
        }

        fn pfkey(&mut self, kind: Kind) -> Result<Vec<Entry>, RouteError> {
            match kind {
                Kind::Sad => {
                    self.read("sad")?;
                    Ok(if self.sa {
                        vec![sa(8), sa(7)]
                    } else {
                        vec![sa(8)]
                    })
                }
                Kind::Spd => {
                    self.read("spd")?;
                    Ok(if self.policy {
                        vec![policy(8), policy(7)]
                    } else {
                        vec![policy(8)]
                    })
                }
            }
        }
    }

    #[test]
    fn startup_orphan_unlinked_claim_after_a_later_boot_is_absent_on_a_host_with_utuns() {
        let mut later = Fake::default();
        assert_eq!(resources_absent_with(&record(None), &mut later), Ok(true));
        assert_eq!(later.log, ["boot", "launchd", "sad", "spd"]);
        let mut by_micros = Fake {
            boot: (START.0, 1),
            ..Default::default()
        };
        assert_eq!(
            resources_absent_with(&record(None), &mut by_micros),
            Ok(true)
        );
    }

    #[test]
    fn startup_orphan_unlinked_claim_without_a_later_boot_stays() {
        for boot in [(500, 0), START, (START.0 - 1, 999_999)] {
            let mut earlier = Fake {
                boot,
                ..Default::default()
            };
            assert_eq!(
                resources_absent_with(&record(None), &mut earlier),
                Ok(false),
                "{boot:?}"
            );
            assert_eq!(earlier.log, ["boot", "interfaces", "routes"]);
        }
        // Control: the existing fallback still decides on a host without UTUNs.
        let mut bare = Fake {
            boot: (500, 0),
            system_utun: false,
            ..Default::default()
        };
        assert_eq!(resources_absent_with(&record(None), &mut bare), Ok(true));
        assert_eq!(bare.log, ["boot", "interfaces", "routes", "sad", "spd"]);
    }

    #[test]
    fn startup_orphan_unlinked_claim_keeps_kernel_sas_and_policies_after_a_boot() {
        let mut with_sa = Fake {
            sa: true,
            ..Default::default()
        };
        assert_eq!(
            resources_absent_with(&record(None), &mut with_sa),
            Err(Reason::NamespaceOccupied)
        );
        assert_eq!(with_sa.log, ["boot", "launchd", "sad"]);
        let mut with_policy = Fake {
            policy: true,
            ..Default::default()
        };
        assert_eq!(
            resources_absent_with(&record(None), &mut with_policy),
            Err(Reason::NamespaceOccupied)
        );
        assert_eq!(with_policy.log, ["boot", "launchd", "sad", "spd"]);
    }

    #[test]
    fn startup_orphan_unlinked_claim_without_a_comparable_start_stays() {
        let mut unstamped = record(None);
        unstamped.controller.start = (0, 0);
        let mut later = Fake::default();
        assert_eq!(resources_absent_with(&unstamped, &mut later), Ok(false));
        assert_eq!(later.log, ["boot", "interfaces", "routes"]);
    }

    #[test]
    fn startup_orphan_linked_claim_ignores_the_boot_and_checks_its_utun() {
        let mut present = Fake {
            retained: true,
            ..Default::default()
        };
        assert_eq!(resources_absent_with(&linked(), &mut present), Ok(false));
        assert_eq!(present.log, ["interfaces", "routes"]);
        let mut gone = Fake::default();
        assert_eq!(resources_absent_with(&linked(), &mut gone), Ok(true));
        assert_eq!(gone.log, ["interfaces", "routes", "sad", "spd"]);
    }

    #[test]
    fn startup_orphan_every_failed_read_is_an_observation_failure() {
        let unlinked_earlier = || {
            let mut record = record(None);
            record.controller.start = (3_000, 0);
            record
        };
        let cases: [(&str, Record); 8] = [
            ("boot", record(None)),
            ("boot", sink()),
            ("boot_session", with_session(sink())),
            ("interfaces", linked()),
            ("interfaces", unlinked_earlier()),
            ("routes", linked()),
            ("sad", record(None)),
            ("spd", linked()),
        ];
        for (fail, record) in cases {
            let mut reads = Fake {
                fail: Some(fail),
                system_utun: false,
                ..Default::default()
            };
            assert_eq!(
                resources_absent_with(&record, &mut reads),
                Err(Reason::ObservationFailed),
                "{fail}"
            );
            assert_eq!(reads.log.last(), Some(&fail));
        }
    }

    #[test]
    fn startup_orphan_linked_sink_claim_needs_a_later_boot() {
        let mut later = Fake::default();
        assert_eq!(resources_absent_with(&sink(), &mut later), Ok(true));
        assert_eq!(later.log, ["boot", "launchd", "sad", "spd"]);
        for boot in [(500, 0), START] {
            let mut earlier = Fake {
                boot,
                ..Default::default()
            };
            assert_eq!(
                resources_absent_with(&sink(), &mut earlier),
                Ok(false),
                "{boot:?}"
            );
            assert_eq!(earlier.log, ["boot", "interfaces", "routes"]);
        }
        // SAD and SPD still decide after the boot proof.
        let mut with_sa = Fake {
            sa: true,
            ..Default::default()
        };
        assert_eq!(
            resources_absent_with(&sink(), &mut with_sa),
            Err(Reason::NamespaceOccupied)
        );
        assert_eq!(with_sa.log, ["boot", "launchd", "sad"]);
        // Control: two VIP families have no sink, so the boot is not read.
        let mut dual = sink();
        dual.link
            .as_mut()
            .unwrap()
            .vips
            .push("2001:db8::10".parse().unwrap());
        dual.valid().unwrap();
        let mut gone = Fake::default();
        assert_eq!(resources_absent_with(&dual, &mut gone), Ok(true));
        assert_eq!(gone.log, ["interfaces", "routes", "sad", "spd"]);
    }

    #[test]
    fn startup_orphan_recorded_boot_session_alone_decides() {
        for record in [with_session(record(None)), with_session(sink())] {
            // A different session proves the reboot even with the clock saying
            // the boot came before the controller started.
            let mut rebooted = Fake {
                session: OTHER_SESSION,
                boot: (500, 0),
                ..Default::default()
            };
            assert_eq!(resources_absent_with(&record, &mut rebooted), Ok(true));
            assert_eq!(rebooted.log, ["boot_session", "sad", "spd"]);
            // The same session denies it even with a later boot on the clock.
            let mut same = Fake::default();
            assert_eq!(resources_absent_with(&record, &mut same), Ok(false));
            assert_eq!(same.log, ["boot_session", "interfaces", "routes"]);
            let mut failed = Fake {
                fail: Some("boot_session"),
                ..Default::default()
            };
            assert_eq!(
                resources_absent_with(&record, &mut failed),
                Err(Reason::ObservationFailed)
            );
            assert_eq!(failed.log, ["boot_session"]);
        }
    }

    #[test]
    fn startup_orphan_legacy_claim_uses_the_earlier_of_boottime_and_launchd() {
        // A forward clock step after the controller started moved the boottime
        // past it; launchd's start did not move.
        let mut stepped = Fake {
            launchd: Ok((START.0 - 10, 0)),
            ..Default::default()
        };
        assert_eq!(
            resources_absent_with(&record(None), &mut stepped),
            Ok(false)
        );
        assert_eq!(stepped.log, ["boot", "launchd", "interfaces", "routes"]);
        let mut equal = Fake {
            launchd: Ok(START),
            ..Default::default()
        };
        assert_eq!(resources_absent_with(&sink(), &mut equal), Ok(false));
        // An unreadable launchd start leaves the boottime alone in charge.
        let mut unreadable = Fake {
            fail: Some("launchd"),
            ..Default::default()
        };
        assert_eq!(
            resources_absent_with(&record(None), &mut unreadable),
            Ok(true)
        );
        assert_eq!(unreadable.log, ["boot", "launchd", "sad", "spd"]);
    }

    #[test]
    fn startup_orphan_boot_session_is_optional_and_canonical() {
        let mut bytes = serde_json::to_value(record(None)).unwrap();
        assert!(bytes.get("boot_session").is_none());
        bytes.as_object_mut().unwrap().remove("boot_session");
        let legacy: Record = serde_json::from_value(bytes.clone()).unwrap();
        assert_eq!(legacy.boot_session, None);
        bytes["boot_session"] = SESSION.into();
        let stamped: Record = serde_json::from_value(bytes).unwrap();
        assert_eq!(stamped.boot_session.as_deref(), Some(SESSION));
        for bad in [
            "",
            "CE2DD70F00004000800000000000000A",
            "CE2DD70F-0000-4000-8000-00000000000",
            "CE2DD70F-0000-4000-8000-00000000000G",
            "CE2DD70F-0000-4000-8000-000000000001-0",
        ] {
            let mut record = record(None);
            record.boot_session = Some(bad.into());
            assert!(record.valid().is_err(), "{bad}");
        }
        // The host's own session reads without privileges and validates.
        let current = boot_session().unwrap();
        assert!(record::boot_session_valid(&current), "{current}");
    }

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
