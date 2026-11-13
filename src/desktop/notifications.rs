//! Native macOS notification adapter.
//!
//! Construction only checks the application bundle and never requests
//! permission. A send follows the shared decision kernel: inspect settings,
//! lazily request authorization only for an explicit notice when the status is
//! not determined, and deliver at most once. The caller's revocable `current`
//! token is checked before authorization and again immediately before delivery.
//! No subprocess, AppleScript or fallback notification path exists.

mod kernel;
mod native;
#[cfg(test)]
mod tests;

use crate::notifications::{Notice, Notifier};
use objc2_foundation::NSBundle;
use std::sync::atomic::Ordering;

const BUNDLE_ID: &str = "dev.vpnt.app";
const MAX_ID: usize = 128;
const MAX_TITLE: usize = 128;
const MAX_BODY: usize = 512;

pub(crate) struct Adapter {
    available: bool,
    backend: Backend,
}

enum Backend {
    Native,
    #[cfg(test)]
    Fake(tests::FakeService),
}

impl Adapter {
    /// Construct only for the real application bundle. Unbundled/test binaries
    /// and other bundle identifiers get `None`; nothing is requested or sent.
    pub(crate) fn current_bundle() -> Option<Self> {
        let identifier = NSBundle::mainBundle()
            .bundleIdentifier()
            .map(|value| value.to_string());
        supported_bundle(identifier.as_deref()).then_some(Self {
            available: true,
            backend: Backend::Native,
        })
    }
}

impl Notifier for Adapter {
    fn send(&mut self, notice: Notice) {
        if !self.available || !notice.current.load(Ordering::Acquire) {
            return;
        }
        let Some(notice) = bounded(notice) else {
            return;
        };
        match &self.backend {
            Backend::Native => native::send(notice),
            #[cfg(test)]
            Backend::Fake(fake) => kernel::send(notice, fake.handle()),
        }
    }
}

fn supported_bundle(identifier: Option<&str>) -> bool {
    identifier == Some(BUNDLE_ID)
}

fn bounded(notice: Notice) -> Option<Notice> {
    if notice.id.is_empty()
        || notice.title.is_empty()
        || notice.body.is_empty()
        || notice.id.len() > MAX_ID
        || notice.title.len() > MAX_TITLE
        || notice.body.len() > MAX_BODY
    {
        return None;
    }
    Some(notice)
}

#[cfg(test)]
impl Adapter {
    pub(super) fn for_test(available: bool, fake: tests::FakeService) -> Self {
        Self {
            available,
            backend: Backend::Fake(fake),
        }
    }
}
