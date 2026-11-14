//! Read-only proof that a PPP interface belongs to our still-owned SSL client.
//! configd records supply candidate PIDs only; this module never signals one.
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

impl OwnedPpp {
    pub fn discover(driver: &mut SslDriver, before: &Interfaces) -> Result<Self, OwnershipError> {
        let update = driver.poll().map_err(|_| OwnershipError::Unavailable)?;
        if update.exited || update.failure.is_some() || update.start_error.is_some() {
            return Err(OwnershipError::NotReady);
        }
        let now = Interfaces::read().map_err(|_| OwnershipError::Unavailable)?;
        let records = store::read().map_err(|_| OwnershipError::Unavailable)?;
        let supervision = driver.supervised_ppp().ok_or(OwnershipError::NotReady)?;
        if !supervision
            .current()
            .map_err(|_| OwnershipError::Unavailable)?
        {
            return Err(OwnershipError::NotReady);
        }
        let parent_program = Path::new(paths::PPP_SUPERVISOR);
        let mut proof = discover(
            supervision.supervisor().pid,
            before,
            &now,
            &records,
            Policy {
                owner: 0,
                parent_program,
                ppp_program: Path::new("/usr/sbin/pppd"),
            },
        )?;
        if proof.parent != *supervision.supervisor() || proof.ppp != *supervision.child() {
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
        let records = store::read().map_err(|_| OwnershipError::Unavailable)?;
        let Ok(record) = unique_record(&records, &self.interface.name) else {
            return Ok(false);
        };
        if record.pid != self.ppp.pid || record.key != self.service_key {
            return Ok(false);
        }
        let interfaces = Interfaces::read().map_err(|_| OwnershipError::Unavailable)?;
        let Some(now) = interfaces.entries.get(&self.interface.name) else {
            return Ok(false);
        };
        Ok(now.index == self.interface.index
            && now.usable_ppp()
            && now.addresses == self.interface.addresses
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
        let Ok(current) = Process::read(record.pid) else {
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
    parent_pid: u32,
    before: &Interfaces,
    now: &Interfaces,
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
    // Ignore the interface name printed by openfortivpn. Upstream can choose
    // another PPP interface when two tunnels have the same negotiated address.
    // Identify our unique child and its interface using configd + kernel data.
    let mut candidate = None;
    for record in records {
        let Ok(ppp) = Process::read(record.pid) else {
            continue;
        };
        if ppp.parent != parent_pid {
            continue;
        }
        if !related(
            &parent,
            &ppp,
            policy.owner,
            policy.parent_program,
            policy.ppp_program,
        ) || candidate.is_some()
        {
            return Err(OwnershipError::ForeignLink);
        }
        candidate = Some((record, ppp));
    }
    let (record, ppp) = candidate.ok_or(OwnershipError::NotReady)?;
    unique_record(records, record.interface.as_str())?;
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
    let current_ppp = Process::read(record.pid).map_err(|_| OwnershipError::NotReady)?;
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
