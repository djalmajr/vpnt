use super::{Error, payload, policy, valid_hash};
use payload::Payload;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
mod checks;
mod image;
mod journal;
mod plan;
mod receipt;
mod tree;
use checks::Checks;
use image::{Image, Stamp, hash};
use journal::Journal;
use receipt::Receipt;
use tree::Tree;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub users: Vec<u32>,
    pub files: usize,
    pub cleanup_pending: bool,
}
struct Executor {
    tree: Tree,
    checks: Checks,
    #[cfg(test)]
    fault: Option<tests::Fault>,
}
impl Executor {
    fn activate(&mut self, payload: &Payload) -> Result<Outcome, Error> {
        // Finish admission before creating even the protected bootstrap tree.
        payload.revalidate()?;
        if payload.owner() != self.tree.owner {
            return Err(Error::PermissionDenied);
        }
        let _guard = self.tree.bootstrap()?;
        Journal::recover(&self.tree)?;
        self.checks.installed(&[])?;
        let old = Receipt::load(&self.tree)?;
        if let Some(old) = &old {
            old.verify(&self.tree)?;
        }
        let plan = plan::Plan::activate(&self.tree, old.as_ref(), payload)?;
        self.tree.user(payload.summary().uid)?;
        self.apply(plan)
    }
    fn remove(&mut self, uid: u32) -> Result<Outcome, Error> {
        policy::account(uid)?;
        let _guard = self.tree.bootstrap()?;
        Journal::recover(&self.tree)?;
        self.checks.installed(&[])?;
        let old = Receipt::load(&self.tree)?.ok_or(Error::Conflict)?;
        old.verify(&self.tree)?;
        let plan = plan::Plan::remove(&self.tree, &old, uid)?;
        self.apply(plan)
    }
    fn apply(&mut self, plan: plan::Plan) -> Result<Outcome, Error> {
        let policy_paths = plan
            .result
            .users
            .keys()
            .map(|uid| self.tree.resolve(&format!("policy/{uid}")))
            .collect::<Result<Vec<_>, _>>()?;
        if plan.wanted.is_empty() {
            self.checks.installed(&policy_paths)?;
            return Ok(outcome(&plan.result, false));
        }
        for (key, next) in &plan.wanted {
            if key.starts_with("policy/")
                && let Some(next) = next
            {
                self.checks.syntax_image(next)?;
            }
        }
        let journal = Journal::prepare(&self.tree, &plan.wanted, &plan.before)?;
        let result = (|| {
            for entry in journal
                .entries
                .iter()
                .filter(|e| e.key.starts_with("policy/"))
            {
                if let Some(current) = image::snapshot(&self.tree, &entry.key)? {
                    if !image::same(Some(&current), entry.before.as_ref()) {
                        return Err(Error::Conflict);
                    }
                    image::set(&self.tree, &entry.key, entry.before.as_ref(), None)?;
                    self.step()?;
                }
            }
            for phase in [0, 1, 2] {
                for (key, next) in plan.wanted.iter().filter(|(key, _)| rank(key) == phase) {
                    let before = if key.starts_with("policy/") {
                        None
                    } else {
                        plan.before[key].as_ref()
                    };
                    image::set(&self.tree, key, before, next.as_ref())?;
                    self.step()?;
                }
            }
            journal.verify(&self.tree, true)?;
            plan.result.verify(&self.tree)?;
            self.checks.installed(&policy_paths)
        })();
        if let Err(error) = result {
            journal
                .rollback(&self.tree)
                .map_err(|_| Error::RecoveryRequired)?;
            let previous = Receipt::load(&self.tree)?;
            let old_policies = previous
                .as_ref()
                .map(|r| {
                    r.users
                        .keys()
                        .map(|uid| self.tree.resolve(&format!("policy/{uid}")))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            self.checks
                .installed(&old_policies)
                .map_err(|_| Error::RecoveryRequired)?;
            journal
                .settle(&self.tree, false)
                .map_err(|_| Error::RecoveryRequired)?;
            return Err(error);
        }
        let cleanup_pending = journal
            .settle(&self.tree, true)
            .map_err(|_| Error::RecoveryRequired)?;
        Ok(outcome(&plan.result, cleanup_pending))
    }
    fn step(&mut self) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(fault) = &mut self.fault {
            fault.step(&self.tree)?;
        }
        Ok(())
    }
}
fn rank(key: &str) -> u8 {
    if key.starts_with("policy/") {
        2
    } else if key == "receipt" {
        1
    } else {
        0
    }
}
fn outcome(receipt: &Receipt, cleanup_pending: bool) -> Outcome {
    Outcome {
        users: receipt.users.keys().copied().collect(),
        files: receipt.files.len(),
        cleanup_pending,
    }
}

mod access;
pub(crate) use access::admit_uid;
pub use access::{activate_staged, remove_inherited};

fn system() -> Executor {
    Executor {
        tree: Tree::system(),
        checks: Checks {
            global: "/private/etc/sudoers".into(),
        },
        #[cfg(test)]
        fault: None,
    }
}
fn root() -> Result<(), Error> {
    if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
        Err(Error::PermissionDenied)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
