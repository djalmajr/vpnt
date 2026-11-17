use super::*;
use crate::helper::vici::{self, CommandResult};
use std::{sync::atomic::Ordering, time::Duration};

pub(super) struct Call {
    pub expires: Instant,
    pub cancel: Arc<AtomicBool>,
}
impl Call {
    pub fn check(&self) -> Result<(), Error> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(Error::Canceled);
        }
        if Instant::now() >= self.expires {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    pub fn remaining(&self) -> Result<Duration, Error> {
        self.check()?;
        self.expires
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .map(|d| d.min(Duration::from_secs(120)))
            .ok_or(Error::Timeout)
    }
}

impl<N: Observer, P: Peer> Control<N, P> {
    pub(super) fn exchange(
        &mut self,
        call: &Call,
        name: &str,
        request: Message,
        events: &[&str],
    ) -> Result<CommandResult, Error> {
        self.validate()?;
        call.check()?;
        let client = self
            .peer
            .open(self.reservation.owner(), call.expires, call.cancel.clone())?;
        call.check()?;
        self.validate()?;
        let response = client.command(name, request, events).map_err(map_error)?;
        call.check()?;
        self.validate()?;
        Ok(response)
    }
    pub(super) fn ack(&mut self, call: &Call, name: &str, request: Message) -> Result<(), Error> {
        let response = self.exchange(call, name, request, &[])?.response;
        match response.get_text("success") {
            Some("yes") => Ok(()),
            Some("no") => Err(Error::Rejected),
            _ => Err(Error::Invalid),
        }
    }
}
fn map_error(error: vici::Error) -> Error {
    match error {
        vici::Error::Canceled => Error::Canceled,
        vici::Error::Timeout => Error::Timeout,
        vici::Error::Io => Error::Unavailable,
        _ => Error::Invalid,
    }
}
