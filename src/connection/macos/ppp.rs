//! Read-only proof that a PPP interface belongs to our still-owned SSL client.
//! configd records correlate an attempt; this module never signals a PID from them.
use super::{
    interfaces::{Interface, Interfaces},
    ppp_control::Proof,
    process::{ExitWatch, Identity, Process},
    store::{self, Record},
};
use crate::{connection::ssl::SslDriver, helper::paths};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipError {
    NotReady,
    ForeignLink,
    Unavailable,
}

pub struct OwnedPpp {
    pub(super) interface: Interface,
    parent: Identity,
    ppp: Identity,
    watches: Mutex<(ExitWatch, ExitWatch)>,
    service_key: String,
    owner: u32,
    parent_program: PathBuf,
    ppp_program: PathBuf,
    supervision: Option<Arc<Proof>>,
}
struct Policy<'a> {
    owner: u32,
    parent_program: &'a Path,
    ppp_program: &'a Path,
}

#[cfg(not(test))]
type DiscoveryDriver = SslDriver;
#[cfg(test)]
pub(crate) trait DiscoveryDriver {
    fn poll(&mut self) -> std::io::Result<crate::connection::ssl::Update>;
    fn supervised_ppp(&self) -> Option<Arc<Proof>>;
}
#[cfg(test)]
impl DiscoveryDriver for SslDriver {
    fn poll(&mut self) -> std::io::Result<crate::connection::ssl::Update> {
        SslDriver::poll(self)
    }
    fn supervised_ppp(&self) -> Option<Arc<Proof>> {
        SslDriver::supervised_ppp(self)
    }
}
#[cfg(test)]
thread_local! {
    static DISCOVERY_POLICY: std::cell::RefCell<Option<(u32, PathBuf, PathBuf)>> = const { std::cell::RefCell::new(None) };
}

impl OwnedPpp {
    #[cfg_attr(test, allow(private_interfaces))]
    pub fn discover(
        #[cfg(not(test))] driver: &mut DiscoveryDriver,
        #[cfg(test)] driver: &mut dyn DiscoveryDriver,
        before: &Interfaces,
    ) -> Result<Self, OwnershipError> {
        let update = driver.poll().map_err(|_| OwnershipError::Unavailable)?;
        if update.exited || update.failure.is_some() || update.start_error.is_some() {
            return Err(OwnershipError::NotReady);
        }
        let supervision = driver.supervised_ppp().ok_or(OwnershipError::NotReady)?;
        if !supervision
            .current()
            .map_err(|_| OwnershipError::Unavailable)?
        {
            return Err(OwnershipError::NotReady);
        }
        #[cfg(not(test))]
        let now = Interfaces::read().map_err(|_| OwnershipError::Unavailable)?;
        #[cfg(test)]
        let now = current_interfaces().map_err(|_| OwnershipError::Unavailable)?;
        let service = supervision.child().service();
        let (record, records) =
            store::read_attempt(service).map_err(|_| OwnershipError::Unavailable)?;
        let record = record.ok_or(OwnershipError::NotReady)?;
        let parent_program = Path::new(paths::PPP_SUPERVISOR);
        #[cfg(test)]
        let policy_override = DISCOVERY_POLICY.with(|slot| slot.borrow().clone());
        #[cfg(test)]
        let (owner, parent_program, ppp_program) = policy_override.as_ref().map_or(
            (0, parent_program, Path::new("/usr/sbin/pppd")),
            |(owner, parent, ppp)| (*owner, parent.as_path(), ppp.as_path()),
        );
        #[cfg(not(test))]
        let (owner, ppp_program) = (0, Path::new("/usr/sbin/pppd"));
        let mut proof = discover(
            (supervision.supervisor().pid, supervision.child().pid),
            &service.key(),
            before,
            &now,
            &record,
            &records,
            Policy {
                owner,
                parent_program,
                ppp_program,
            },
        )?;
        if proof.parent != *supervision.supervisor()
            || proof.ppp != **supervision.child()
            || !same_attempt(service, &record)?
            || !supervision
                .current()
                .map_err(|_| OwnershipError::Unavailable)?
        {
            return Err(OwnershipError::ForeignLink);
        }
        proof.supervision = Some(supervision);
        Ok(proof)
    }
    pub fn name(&self) -> &str {
        &self.interface.name
    }
    pub fn index(&self) -> u32 {
        self.interface.index
    }
    pub fn addresses(&self) -> impl Iterator<Item = std::net::IpAddr> + '_ {
        self.interface.addresses.iter().copied()
    }

    /// Revalidate before and after every probe/route operation. Kernel exit
    /// watches retain identity even after a PID is reaped and later reused.
    pub fn is_current(&self) -> Result<bool, OwnershipError> {
        if let Some(proof) = &self.supervision
            && !proof.current().map_err(|_| OwnershipError::Unavailable)?
        {
            return Ok(false);
        }
        if self.exited()? {
            return Ok(false);
        }
        let Ok(parent) = Process::read(self.parent.pid) else {
            return Ok(false);
        };
        let Ok(ppp) = Process::read(self.ppp.pid) else {
            return Ok(false);
        };
        if parent.identity != self.parent
            || ppp.identity != self.ppp
            || !related(
                &parent,
                &ppp,
                self.owner,
                &self.parent_program,
                &self.ppp_program,
            )
        {
            return Ok(false);
        }
        let Some(proof) = &self.supervision else {
            return Ok(false);
        };
        let (attempt, records) = store::read_attempt(proof.child().service())
            .map_err(|_| OwnershipError::Unavailable)?;
        let Ok(record) = unique_record(&records, &self.interface.name) else {
            return Ok(false);
        };
        if attempt.as_ref() != Some(record)
            || record.pid.is_some_and(|pid| pid != self.ppp.pid)
            || record.key != self.service_key
        {
            return Ok(false);
        }
        let interfaces = current_interfaces().map_err(|_| OwnershipError::Unavailable)?;
        let Some(now) = interfaces.entries.get(&self.interface.name) else {
            return Ok(false);
        };
        Ok(now.index == self.interface.index
            && now.usable_ppp()
            && now.addresses == self.interface.addresses
            && same_attempt(proof.child().service(), record)?
            && proof.current().map_err(|_| OwnershipError::Unavailable)?
            && !self.exited()?)
    }
    /// Both retained kernel exit watches, not a PID lookup. Interface and route
    /// cleanup still need independent observation after these processes exit.
    pub fn processes_exited(&self) -> Result<bool, OwnershipError> {
        let mut watches = self
            .watches
            .lock()
            .map_err(|_| OwnershipError::Unavailable)?;
        Ok(watches
            .0
            .exited()
            .map_err(|_| OwnershipError::Unavailable)?
            && watches
                .1
                .exited()
                .map_err(|_| OwnershipError::Unavailable)?
            && self
                .supervision
                .as_ref()
                .map_or(Ok(true), |proof| proof.exited())
                .map_err(|_| OwnershipError::Unavailable)?)
    }
    /// PPP only, not route cleanup. A still-up interface without a new verified
    /// owner is not declared clean merely because the direct client exited.
    pub fn ppp_gone(&self) -> Result<bool, OwnershipError> {
        if !self.processes_exited()? {
            return Ok(false);
        }
        let interfaces = Interfaces::read().map_err(|_| OwnershipError::Unavailable)?;
        let Some(now) = interfaces.entries.get(&self.interface.name) else {
            return Ok(true);
        };
        if now.index != self.interface.index || now.flags & libc::IFF_UP as u32 == 0 {
            return Ok(true);
        }
        let records = store::read().map_err(|_| OwnershipError::Unavailable)?;
        let Ok(record) = unique_record(&records, &self.interface.name) else {
            return Ok(false);
        };
        let Some(pid) = record.pid else {
            return Ok(false);
        };
        let Ok(current) = Process::read(pid) else {
            return Ok(false);
        };
        Ok(current.identity != self.ppp
            && current.running
            && current.uid == self.owner
            && current.real_uid == self.owner
            && current.executable == self.ppp_program)
    }
    fn exited(&self) -> Result<bool, OwnershipError> {
        let mut watches = self
            .watches
            .lock()
            .map_err(|_| OwnershipError::Unavailable)?;
        Ok(watches
            .0
            .exited()
            .map_err(|_| OwnershipError::Unavailable)?
            || watches
                .1
                .exited()
                .map_err(|_| OwnershipError::Unavailable)?)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_INTERFACES: std::cell::RefCell<Option<Interfaces>> = const { std::cell::RefCell::new(None) };
}

fn current_interfaces() -> std::io::Result<Interfaces> {
    #[cfg(test)]
    if let Some(interfaces) = TEST_INTERFACES.with(|slot| slot.borrow().clone()) {
        return Ok(interfaces);
    }
    Interfaces::read()
}

fn same_attempt(
    service: &crate::helper::ppp_supervisor::ServiceId,
    expected: &Record,
) -> Result<bool, OwnershipError> {
    let (attempt, records) =
        store::read_attempt(service).map_err(|_| OwnershipError::Unavailable)?;
    Ok(attempt.as_ref() == Some(expected)
        && unique_record(&records, expected.interface.as_str()).ok() == Some(expected))
}

fn unique_record<'a>(records: &'a [Record], name: &str) -> Result<&'a Record, OwnershipError> {
    let mut matches = records
        .iter()
        .filter(|record| record.interface.as_str() == name);
    let record = matches.next().ok_or(OwnershipError::NotReady)?;
    if matches.next().is_some() {
        return Err(OwnershipError::ForeignLink);
    }
    Ok(record)
}

fn discover(
    (parent_pid, child_pid): (u32, u32),
    service_key: &str,
    before: &Interfaces,
    now: &Interfaces,
    record: &Record,
    records: &[Record],
    policy: Policy<'_>,
) -> Result<OwnedPpp, OwnershipError> {
    let parent = Process::read(parent_pid).map_err(|_| OwnershipError::NotReady)?;
    if !parent.running
        || parent.uid != policy.owner
        || parent.real_uid != policy.owner
        || parent.executable != policy.parent_program
    {
        return Err(OwnershipError::ForeignLink);
    }
    // UUID is not secret. We trust root and writers with the applicable
    // SCDynamicStore-write-access entitlement as OS components:
    // https://github.com/apple-oss-distributions/configd/blob/main/configd.tproj/session.c#L966
    // Never authorize from the interface name printed by openfortivpn.
    if record.key != service_key {
        return Err(OwnershipError::NotReady);
    }
    if record.pid.is_some_and(|pid| pid != child_pid) {
        return Err(OwnershipError::ForeignLink);
    }
    if unique_record(records, record.interface.as_str())? != record {
        return Err(OwnershipError::ForeignLink);
    }
    let ppp = Process::read(child_pid).map_err(|_| OwnershipError::NotReady)?;
    if !related(
        &parent,
        &ppp,
        policy.owner,
        policy.parent_program,
        policy.ppp_program,
    ) {
        return Err(OwnershipError::ForeignLink);
    }
    let interface = now
        .entries
        .get(record.interface.as_str())
        .ok_or(OwnershipError::NotReady)?;
    if !interface.usable_ppp() || interface.addresses.is_empty() {
        return Err(OwnershipError::NotReady);
    }
    if before.previously_up(interface) {
        return Err(OwnershipError::ForeignLink);
    }
    let watches = (
        ExitWatch::attach(&parent.identity).map_err(|_| OwnershipError::NotReady)?,
        ExitWatch::attach(&ppp.identity).map_err(|_| OwnershipError::NotReady)?,
    );
    // Registration/path reads must not hide an intervening exit or reparent.
    let current_parent = Process::read(parent_pid).map_err(|_| OwnershipError::NotReady)?;
    let current_ppp = Process::read(child_pid).map_err(|_| OwnershipError::NotReady)?;
    if current_parent.identity != parent.identity
        || current_ppp.identity != ppp.identity
        || !related(
            &current_parent,
            &current_ppp,
            policy.owner,
            policy.parent_program,
            policy.ppp_program,
        )
    {
        return Err(OwnershipError::ForeignLink);
    }
    Ok(OwnedPpp {
        interface: interface.clone(),
        parent: parent.identity,
        ppp: ppp.identity,
        watches: Mutex::new(watches),
        service_key: record.key.clone(),
        owner: policy.owner,
        parent_program: policy.parent_program.into(),
        ppp_program: policy.ppp_program.into(),
        supervision: None,
    })
}
fn related(
    parent: &Process,
    ppp: &Process,
    owner: u32,
    parent_program: &Path,
    ppp_program: &Path,
) -> bool {
    parent.running
        && ppp.running
        && parent.uid == owner
        && parent.real_uid == owner
        && ppp.uid == owner
        && ppp.real_uid == owner
        && parent.executable == parent_program
        && ppp.executable == ppp_program
        && ppp.parent == parent.identity.pid
        && ppp.identity.start >= parent.identity.start
        && ppp.identity.pid != parent.identity.pid
}
#[cfg(test)]
#[path = "ppp_tests.rs"]
mod tests;
