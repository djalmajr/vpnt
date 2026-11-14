//! Selected negotiated attempt for the future Driver. Daemon metadata plus the
//! covered plan only: no native ownership, alias, route or traffic proof. The
//! caller must separately prove profile use, the typed pin/original producer and
//! the route leases before `Connected`.
use super::*;
use crate::connection::{ipsec::Candidate, routes::Owner};

impl<N: Observer, P: Peer> Control<N, P> {
    /// Run the existing full `snapshot` batch, select the single compatible
    /// active attempt, return it with the configured coverage, then recheck the
    /// same call and reservation before yielding.
    pub fn selected(
        &mut self,
        expires: Instant,
        cancel: Arc<AtomicBool>,
    ) -> Result<(Candidate, Vec<String>), Error> {
        let mut candidates = self.snapshot(expires, cancel.clone())?;
        let child_id = self.config.select(&candidates)?.child_id;
        let position = candidates
            .iter()
            .position(|candidate| candidate.child_id == child_id)
            .ok_or(Error::Changed)?;
        let candidate = candidates.remove(position);
        let networks = self.config.route_networks(&candidate)?;
        let call = Call { expires, cancel };
        call.check()?;
        self.validate()?;
        Ok((candidate, networks))
    }

    /// Immutable reservation owner metadata; no release or mutation authority.
    pub fn owner(&self) -> &Owner {
        self.reservation.owner()
    }
}
