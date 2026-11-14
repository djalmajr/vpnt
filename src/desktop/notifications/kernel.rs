//! Send decision kernel shared by the native adapter and its fake tests.
//!
//! This type owns no native handle and performs no I/O. [`send`] is the only
//! production send path: it drives one notice through the settings read, at
//! most one authorization request, at most one delivery, and rechecks the
//! caller's revocable token before asking for permission and again
//! immediately before the delivery attempt.

use crate::notifications::Notice;
use std::sync::{Arc, Mutex, MutexGuard, atomic::Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Status {
    NotDetermined,
    Denied,
    Authorized,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Drop,
    Request,
    Deliver,
}

/// Native service surface used by [`send`]. The real implementation talks to
/// `UNUserNotificationCenter`; the private fake answers synchronously. Every
/// method may run on a framework callback queue. Callbacks may be retained until
/// completion and invoked more than once; the kernel ignores repeats.
pub(super) trait Channel: Send + Sync {
    /// Read the current authorization settings without requesting anything.
    fn settings(&self, done: Callback<Status>);
    /// Ask the user once. Never called unless the notice is still current.
    fn authorize(&self, done: Callback<bool>);
    /// Queue the notification. Called at most once, never for a stale notice.
    fn deliver(&self, notice: Notice);
}

pub(super) type Handle = Arc<dyn Channel>;
pub(super) type Callback<T> = Box<dyn FnMut(T) + Send>;

pub(super) struct Decision {
    notice: Option<Notice>,
    requested: bool,
    done: bool,
}

impl Decision {
    pub(super) fn new(notice: Notice) -> Self {
        Self {
            notice: Some(notice),
            requested: false,
            done: false,
        }
    }

    /// True only while the caller's episode is still current.
    pub(super) fn current(&self) -> bool {
        self.notice
            .as_ref()
            .is_some_and(|notice| notice.current.load(Ordering::Acquire))
    }

    /// Settings already fetched. Denied/unknown never request; a second
    /// callback while authorization is pending is ignored, not re-requested.
    pub(super) fn on_settings(&mut self, status: Status) -> Step {
        if self.done {
            return Step::Drop;
        }
        if !self.current() {
            self.done = true;
            return Step::Drop;
        }
        if self.requested {
            return Step::Drop;
        }
        match status {
            Status::Authorized => {
                self.done = true;
                Step::Deliver
            }
            Status::NotDetermined => {
                self.requested = true;
                Step::Request
            }
            Status::Denied | Status::Unsupported => {
                self.done = true;
                Step::Drop
            }
        }
    }

    /// Authorization callback. The token is rechecked before yielding delivery.
    pub(super) fn on_authorization(&mut self, granted: bool) -> Step {
        if self.done || !self.requested {
            self.done = true;
            return Step::Drop;
        }
        self.done = true;
        if !granted || !self.current() {
            return Step::Drop;
        }
        Step::Deliver
    }

    /// Last gate before the native request: a token revoked between the
    /// decision and the delivery attempt yields no delivery.
    pub(super) fn take_notice(&mut self) -> Option<Notice> {
        let notice = self.notice.take()?;
        if notice.current.load(Ordering::Acquire) {
            Some(notice)
        } else {
            None
        }
    }
}

pub(super) type Shared = Arc<Mutex<Decision>>;

/// Production send sequence for one notice. Nothing is requested or delivered
/// when the caller's token is already revoked.
pub(super) fn send(notice: Notice, channel: Handle) {
    if !notice.current.load(Ordering::Acquire) {
        return;
    }
    let state: Shared = Arc::new(Mutex::new(Decision::new(notice)));
    let settings_state = state.clone();
    let settings_channel = channel.clone();
    channel.settings(Box::new(move |status| {
        let (step, notice) = advance(&settings_state, |decision| decision.on_settings(status));
        match step {
            Step::Drop => {}
            Step::Deliver => deliver(settings_channel.clone(), notice),
            Step::Request => authorize(settings_state.clone(), settings_channel.clone()),
        }
    }));
}

/// Authorization request half of [`send`], exposed so the pre-request token
/// gate can be exercised against a state built by the same kernel steps.
pub(super) fn authorize(state: Shared, channel: Handle) {
    // Recheck the episode token immediately before asking the user.
    if !is_current(&state) {
        return;
    }
    let grant_state = state.clone();
    let grant_channel = channel.clone();
    channel.authorize(Box::new(move |granted| {
        let (step, notice) = advance(&grant_state, |decision| decision.on_authorization(granted));
        if step == Step::Deliver {
            deliver(grant_channel.clone(), notice);
        }
    }));
}

fn deliver(channel: Handle, notice: Option<Notice>) {
    let Some(notice) = notice else {
        return;
    };
    // Last token gate, immediately before the native request is queued.
    if !notice.current.load(Ordering::Acquire) {
        return;
    }
    channel.deliver(notice);
}

fn advance<F>(state: &Shared, step: F) -> (Step, Option<Notice>)
where
    F: FnOnce(&mut Decision) -> Step,
{
    let mut decision = lock(state);
    let step = step(&mut decision);
    let notice = if step == Step::Deliver {
        decision.take_notice()
    } else {
        None
    };
    (step, notice)
}

fn is_current(state: &Shared) -> bool {
    lock(state).current()
}

fn lock(state: &Shared) -> MutexGuard<'_, Decision> {
    state.lock().unwrap_or_else(|error| error.into_inner())
}
