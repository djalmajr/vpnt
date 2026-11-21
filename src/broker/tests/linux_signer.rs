//! The app signer's tests on Linux, where the rest of the broker suite does not
//! build. OVPN needs no stored secret; the store only counts reads.
use super::*;
use crate::secrets::{Credentials, SecretError};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Secrets {
    loads: Arc<AtomicUsize>,
}
impl Secrets {
    fn new() -> Self {
        Self {
            loads: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl SecretStore for Secrets {
    fn contains(&self, _: &str, _: VpnKind) -> Result<bool, SecretError> {
        Ok(true)
    }
    fn load(&self, _: &str, _: VpnKind) -> Result<Credentials, SecretError> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        Ok(Credentials {
            password: "".into(),
            psk: "".into(),
        })
    }
    fn save(&self, _: &str, _: VpnKind, _: &Credentials) -> Result<(), SecretError> {
        Ok(())
    }
    fn remove(&self, _: &str, _: VpnKind) -> Result<(), SecretError> {
        Ok(())
    }
}

#[path = "signer.rs"]
mod signer;
