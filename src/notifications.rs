//! Portable notification contract.
//!
//! Callers own the localized copy and the per-episode liveness token. The
//! desktop adapter is the only implementation that talks to the OS; headless
//! callers can use [`Noop`]. No payload here carries credentials, paths or a
//! connection handle.

use std::sync::{Arc, atomic::AtomicBool};

/// One notification request. `title` and `body` are shared localized catalog
/// strings provided by the caller; `current` is the caller's revocable token
/// for this episode. It is checked before authorization and again immediately
/// before delivery.
#[derive(Clone)]
pub struct Notice {
    pub id: String,
    pub title: String,
    pub body: String,
    pub current: Arc<AtomicBool>,
}

/// Best-effort notification sink. Delivery must never block or change the
/// connection/cleanup path.
pub trait Notifier {
    fn send(&mut self, notice: Notice);
}

/// Inert notifier for headless, test or unavailable contexts.
pub struct Noop;

impl Notifier for Noop {
    fn send(&mut self, _notice: Notice) {}
}
