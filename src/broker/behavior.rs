//! Episode policy over the helper's current, validated generation/counter.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(super) struct Policy {
    generation: u64,
    notified: bool,
    queued: bool,
    attempted: Option<u64>,
    notice: Option<Arc<AtomicBool>>,
}
pub(super) struct Effects {
    pub notice: Option<Arc<AtomicBool>>,
    pub reconnect: bool,
}
impl Policy {
    pub fn state(&mut self, generation: u64, state: State) {
        if self.generation != generation || state != State::Unresponsive {
            self.revoke();
            self.notified = false;
            self.queued = false;
        }
        self.generation = generation;
        if state == State::Connected {
            self.attempted = None;
        }
    }
    pub fn observe(
        &mut self,
        generation: u64,
        state: State,
        failures: u32,
        prefs: Preferences,
    ) -> Effects {
        self.state(generation, state);
        if !prefs.notify {
            self.revoke();
        }
        if !prefs.reconnect {
            self.queued = false;
        }
        let mut effects = Effects {
            notice: None,
            reconnect: false,
        };
        if state != State::Unresponsive || generation == 0 {
            return effects;
        }
        if prefs.notify && !self.notified {
            let current = Arc::new(AtomicBool::new(true));
            self.notice = Some(current.clone());
            self.notified = true;
            effects.notice = Some(current);
        }
        if prefs.reconnect && failures == 3 && self.attempted != Some(generation) && !self.queued {
            self.queued = true;
            effects.reconnect = true;
        }
        effects
    }
    pub fn tried(&mut self, generation: u64) {
        self.attempted = Some(generation);
        self.queued = false;
    }
    pub fn defer(&mut self, generation: u64) {
        if self.attempted == Some(generation) {
            self.attempted = None;
        }
        self.queued = true;
    }
    pub fn unqueue(&mut self) {
        self.queued = false;
    }
    fn revoke(&mut self) {
        if let Some(token) = self.notice.take() {
            token.store(false, Ordering::Release);
        }
    }
}
impl Drop for Policy {
    fn drop(&mut self) {
        self.revoke();
    }
}
