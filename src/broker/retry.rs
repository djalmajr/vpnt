use crate::helper::client::{Client, Error};
use std::time::{Duration, Instant};

pub(super) struct Retry {
    connect: Box<dyn FnMut() -> Result<Client, Error> + Send>,
    next: Instant,
    delay: Duration,
    minimum: Duration,
}
impl Retry {
    pub(super) fn runtime() -> Self {
        Self::new(Client::runtime, Duration::from_secs(1))
    }
    fn new(
        connect: impl FnMut() -> Result<Client, Error> + Send + 'static,
        minimum: Duration,
    ) -> Self {
        Self {
            connect: Box::new(connect),
            next: Instant::now(),
            delay: minimum,
            minimum,
        }
    }
    #[cfg(test)]
    pub(super) fn fixture(connect: impl FnMut() -> Result<Client, Error> + Send + 'static) -> Self {
        Self::new(connect, Duration::from_millis(20))
    }
    pub(super) fn attempt(&mut self, previous: Option<&Client>) -> Option<Result<Client, Error>> {
        if Instant::now() < self.next || previous.is_some_and(|c| !c.finished()) {
            return None;
        }
        let result = (self.connect)();
        if result.is_err() {
            self.defer();
        }
        Some(result)
    }
    pub(super) fn defer(&mut self) {
        self.next = Instant::now() + self.delay;
        self.delay = (self.delay * 2).min(Duration::from_secs(30));
    }
    pub(super) fn ready(&mut self) {
        self.delay = self.minimum;
    }
    pub(super) fn wake(&mut self) {
        self.next = Instant::now();
        self.delay = self.minimum;
    }
}
