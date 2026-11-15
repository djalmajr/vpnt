use super::*;
use crate::helper::runtime::cleanup::{self as diagnostic, Reason};

impl NativeAttempt<'_> {
    pub(super) fn cleanup_network(&mut self) -> bool {
        // A canceled connection may have reached PPP before the last poll.
        // Capture proof while its original parent is still alive, if possible.
        if self.link.is_none() && self.client.is_some() && !self.stopped {
            let _ = self.discover();
        }
        if !self.stopped {
            self.stopped = self
                .client
                .as_mut()
                .is_none_or(|client| client.stop().is_ok());
        }
        self.credentials = None;
        if self.uncertain_cleanup {
            return diagnostic::refuse(Reason::UncertainCleanup);
        }
        if !self.stopped {
            return diagnostic::refuse(Reason::ProducerNotStopped);
        }
        if !self.spawn_attempted {
            return true;
        }
        let Some(client) = &mut self.client else {
            return diagnostic::refuse(Reason::ProducerMissing);
        };
        if !client.children_complete().unwrap_or(false) {
            return diagnostic::refuse(Reason::ChildrenIncomplete);
        }
        // A birth grant predates configd/address discovery. Process receipts
        // alone cannot prove that implicit network resources were removed.
        let Some(link) = &self.link else {
            if !client.ppp_may_have_run() {
                return true;
            }
            let (Some(before), Some(routes), Some(proof)) =
                (&self.before, &self.before_routes, client.supervised_ppp())
            else {
                return diagnostic::refuse(Reason::LinkEvidence);
            };
            return ppp_early_cleanup::complete(before, routes, proof.child()).unwrap_or(false)
                || diagnostic::refuse(Reason::EarlyAbsence);
        };
        let Ok(mut routes) = self.routes.lock() else {
            return diagnostic::refuse(Reason::RouteLock);
        };
        if let Some(lease) = self.lease.take()
            && routes.release(lease).is_err()
        {
            self.uncertain_cleanup = true;
            return diagnostic::refuse(Reason::RouteRelease);
        }
        if let Some(token) = &self.token {
            if !routes.backend_mut().begin_cleanup(token).unwrap_or(false) {
                return diagnostic::refuse(Reason::RouteBegin);
            }
            routes.retry_cleanup();
            if routes.has_owner(&self.owner) {
                return diagnostic::refuse(Reason::RouteOwner);
            }
            if routes.backend_mut().finish_cleanup(token).is_err() {
                return diagnostic::refuse(Reason::RouteFinish);
            }
            self.token = None;
        }
        routes.retry_cleanup();
        if routes.has_owner(&self.owner) {
            return diagnostic::refuse(Reason::RouteOwner);
        }
        if routes.backend_mut().reap_retired().is_err() {
            return diagnostic::refuse(Reason::RetiredResources);
        }
        routes
            .backend_mut()
            .ppp_cleanup_complete(link)
            .unwrap_or(false)
            || diagnostic::refuse(Reason::EarlyAbsence)
    }
}
