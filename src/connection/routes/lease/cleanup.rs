use super::{Backend, Cleanup, Coordinator, Error, Key, Lease, Presence};
impl<B: Backend> Coordinator<B> {
    pub fn release(&mut self, lease: Lease) -> Result<Cleanup, Error> {
        if lease.manager != self.manager
            || !self
                .claims
                .get(&lease.token)
                .is_some_and(|claim| !claim.releasing)
        {
            return Err(Error::Invalid);
        }
        Ok(self.release_token(lease.token))
    }
    pub fn retry_cleanup(&mut self) -> Cleanup {
        let tokens: Vec<_> = self
            .claims
            .iter()
            .filter(|(_, claim)| claim.releasing)
            .map(|(token, _)| *token)
            .collect();
        let mut result = Cleanup::default();
        for token in tokens {
            result.merge(self.release_token(token));
        }
        result
    }
    pub fn close_all(&mut self) -> Cleanup {
        let tokens: Vec<_> = self.claims.keys().copied().rev().collect();
        let mut result = Cleanup::default();
        for token in tokens {
            result.merge(self.release_token(token));
        }
        result
    }
    pub(super) fn release_token(&mut self, token: u64) -> Cleanup {
        let Some(claim) = self.claims.get_mut(&token) else {
            return Cleanup::default();
        };
        claim.releasing = true;
        let result = self.release_tail(token, 0);
        if self
            .claims
            .get(&token)
            .is_some_and(|claim| claim.keys.is_empty())
        {
            self.claims.remove(&token);
        }
        result
    }
    pub(super) fn release_tail(&mut self, token: u64, keep: usize) -> Cleanup {
        let mut result = Cleanup::default();
        while let Some(claim) = self.claims.get(&token) {
            if claim.keys.len() <= keep {
                break;
            }
            let Some(&key) = claim.keys.last() else {
                break;
            };
            if let Some(entry) = self.entries.get_mut(&key) {
                entry.users.remove(&token);
            }
            let step = self.cleanup_key(key);
            result.merge(step);
            if step.pending != 0 {
                // Keep earlier dependencies, including the transport pin, until
                // the failed network cleanup can be retried successfully.
                if let Some(entry) = self.entries.get_mut(&key) {
                    entry.users.insert(token);
                }
                result.pending = self
                    .claims
                    .get(&token)
                    .map_or(0, |claim| claim.keys.len().saturating_sub(keep));
                break;
            }
            if let Some(claim) = self.claims.get_mut(&token) {
                claim.keys.pop();
            }
        }
        result
    }
    fn cleanup_key(&mut self, key: Key) -> Cleanup {
        let Some(entry) = self.entries.get(&key) else {
            return Cleanup::default();
        };
        if !entry.users.is_empty() {
            return Cleanup::default();
        }
        let Some(receipt) = &entry.receipt else {
            self.entries.remove(&key);
            return Cleanup {
                borrowed: 1,
                ..Cleanup::default()
            };
        };
        match self.backend.receipt_state(receipt) {
            Ok(Presence::Absent) => {
                self.entries.remove(&key);
                Cleanup {
                    absent: 1,
                    ..Cleanup::default()
                }
            }
            Ok(Presence::Replaced) | Err(Error::Changed) => {
                self.entries.remove(&key);
                Cleanup {
                    changed: 1,
                    ..Cleanup::default()
                }
            }
            Err(_) => Cleanup {
                pending: 1,
                ..Cleanup::default()
            },
            Ok(Presence::Owned) => match self.backend.remove(receipt) {
                Ok(()) => {
                    self.entries.remove(&key);
                    Cleanup {
                        removed: 1,
                        ..Cleanup::default()
                    }
                }
                Err(Error::Changed) => {
                    self.entries.remove(&key);
                    Cleanup {
                        changed: 1,
                        ..Cleanup::default()
                    }
                }
                Err(_) => Cleanup {
                    pending: 1,
                    ..Cleanup::default()
                },
            },
        }
    }
}
impl<B: Backend> Drop for Coordinator<B> {
    fn drop(&mut self) {
        self.close_all();
        self.retry_cleanup();
    }
}
