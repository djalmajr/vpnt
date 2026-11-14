use super::{AcquireError, BTreeMap, Backend, Claim, Coordinator, Error, Lease, Owner, Route};
impl<B: Backend> Coordinator<B> {
    pub fn acquire(&mut self, owner: Owner, routes: &[Route]) -> Result<Lease, AcquireError> {
        self.acquire_guarded(owner, routes, || Ok(()))
    }

    /// Same acquire with a caller-budget precondition before claim creation and
    /// between every admitted/attached operation. The guard is a pure
    /// precondition; it never grants route authority.
    pub fn acquire_guarded<F: FnMut() -> Result<(), Error>>(
        &mut self,
        owner: Owner,
        routes: &[Route],
        mut check: F,
    ) -> Result<Lease, AcquireError> {
        check()?;
        if !owner.valid() || routes.is_empty() {
            return Err(Error::Invalid.into());
        }
        if self.claims.len() >= 64 {
            return Err(Error::Limit.into());
        }
        if self
            .claims
            .values()
            .any(|claim| claim.owner.uid == owner.uid && claim.owner.profile == owner.profile)
        {
            return Err(Error::Busy.into());
        }
        check()?;
        self.next = self.next.checked_add(1).ok_or(Error::Limit)?;
        let token = self.next;
        self.claims.insert(
            token,
            Claim {
                owner,
                keys: Vec::new(),
                releasing: false,
                failed: false,
            },
        );
        let lease = Lease {
            manager: self.manager,
            token,
        };
        match self.extend_guarded(&lease, routes, check) {
            Ok(()) => Ok(lease),
            Err(error) => {
                let mut cleanup = error.cleanup;
                cleanup.merge(self.release_token(token));
                // Count resources still pending, not repeated attempts.
                cleanup.pending = self.claims.get(&token).map_or(0, |claim| claim.keys.len());
                Err(AcquireError {
                    reason: error.reason,
                    cleanup,
                })
            }
        }
    }
    /// Append post-PPP routes to the generation that already holds gateway
    /// pins. An incomplete extension never authorizes Connected. On pending
    /// rollback the caller must stop the client, then release the retained lease.
    pub fn extend(&mut self, lease: &Lease, routes: &[Route]) -> Result<(), AcquireError> {
        self.extend_guarded(lease, routes, || Ok(()))
    }

    /// Append routes under the same caller budget. Guard failures before the
    /// first attach leave old keys untouched; failures after any attempt use
    /// the same extension failure/release-tail rollback as an operation error.
    pub fn extend_guarded<F: FnMut() -> Result<(), Error>>(
        &mut self,
        lease: &Lease,
        routes: &[Route],
        mut check: F,
    ) -> Result<(), AcquireError> {
        check()?;
        self.validate(lease)?;
        if routes.is_empty() || routes.len() > 128 {
            return Err(Error::Invalid.into());
        }
        let mut desired = BTreeMap::new();
        let mut keys = Vec::new();
        let existing = &self.claims.get(&lease.token).ok_or(Error::Invalid)?.keys;
        let keep = existing.len();
        for &route in routes {
            route.validate()?;
            if let Some(old) = desired.insert(route.key, route) {
                if old != route {
                    return Err(Error::Conflict.into());
                }
            } else if !existing.contains(&route.key) {
                keys.push(route.key);
            }
        }
        if keep + keys.len() > 128 || self.entries.len() + keys.len() > 8192 {
            return Err(Error::Limit.into());
        }
        let owner = self
            .claims
            .get(&lease.token)
            .ok_or(Error::Invalid)?
            .owner
            .clone();
        for route in desired.values() {
            check()?;
            self.admit(&owner, *route)?;
            check()?;
        }
        for key in keys {
            if let Err(reason) = check() {
                return Err(self.extension_failure(lease.token, keep, reason));
            }
            if let Err(reason) = self.attach(lease.token, desired[&key]) {
                return Err(self.extension_failure(lease.token, keep, reason));
            }
            if let Err(reason) = check() {
                return Err(self.extension_failure(lease.token, keep, reason));
            }
        }
        if let Err(reason) = self.validate(lease) {
            return Err(self.extension_failure(lease.token, keep, reason));
        }
        if let Err(reason) = check() {
            return Err(self.extension_failure(lease.token, keep, reason));
        }
        Ok(())
    }
    fn extension_failure(&mut self, token: u64, keep: usize, reason: Error) -> AcquireError {
        let cleanup = self.release_tail(token, keep);
        if cleanup.pending != 0
            && let Some(claim) = self.claims.get_mut(&token)
        {
            claim.failed = true;
        }
        AcquireError { reason, cleanup }
    }
}

#[cfg(test)]
mod guard_tests;
