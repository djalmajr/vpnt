use super::*;

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
        if !self.stopped || self.uncertain_cleanup {
            return false;
        }
        if !self.spawn_attempted {
            return true;
        }
        let Some(client) = &mut self.client else {
            return false;
        };
        if !client.children_complete().unwrap_or(false) {
            return false;
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
                return false;
            };
            return ppp_early_cleanup::complete(before, routes, proof.child()).unwrap_or(false);
        };
        let Ok(mut routes) = self.routes.lock() else {
            return false;
        };
        if let Some(lease) = self.lease.take()
            && routes.release(lease).is_err()
        {
            self.uncertain_cleanup = true;
            return false;
        }
        if let Some(token) = &self.token {
            if !routes.backend_mut().begin_cleanup(token).unwrap_or(false) {
                return false;
            }
            routes.retry_cleanup();
            if routes.has_owner(&self.owner) || routes.backend_mut().finish_cleanup(token).is_err()
            {
                return false;
            }
            self.token = None;
        }
        routes.retry_cleanup();
        !routes.has_owner(&self.owner)
            && routes.backend_mut().reap_retired().is_ok()
            && routes
                .backend_mut()
                .ppp_cleanup_complete(link)
                .unwrap_or(false)
    }
}
