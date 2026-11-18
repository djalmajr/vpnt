//! Reservations live in the controller, not the worker stack. An abandoned
//! attempt cannot make its profile editable while cleanup is still uncertain.
use crate::{
    model::Profile,
    storage::{ProfileReservation, ProfileStore, StoreError},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

struct Reservation {
    profile: ProfileReservation,
    live: bool,
    identity: Arc<()>,
}
type Reservations = Arc<Mutex<BTreeMap<(String, u64), Reservation>>>;
pub(super) struct Profiles {
    store: ProfileStore,
    reservations: Reservations,
}
pub(super) struct ProfileUse {
    key: (String, u64),
    reservations: Reservations,
    identity: Arc<()>,
}
impl Profiles {
    #[cfg(test)]
    pub(super) fn fixture(store: ProfileStore) -> Self {
        Self::new(store)
    }
    #[cfg(target_os = "macos")]
    pub(super) fn for_user(uid: u32) -> Result<Self, StoreError> {
        Ok(Self::new(ProfileStore::for_user(uid)?))
    }
    fn new(store: ProfileStore) -> Self {
        Self {
            store,
            reservations: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
    pub(super) fn load(&self) -> Result<Vec<Profile>, StoreError> {
        self.store.load()
    }
    pub(super) fn begin(
        &self,
        profile: &Profile,
        generation: u64,
    ) -> Result<ProfileUse, StoreError> {
        if generation == 0 {
            return Err(StoreError::InvalidData);
        }
        let reservation = self.store.reserve(&profile.id)?;
        let current = self
            .store
            .load()?
            .into_iter()
            .find(|p| p.id == profile.id)
            .ok_or(StoreError::NotFound)?;
        if current != *profile {
            return Err(StoreError::InvalidData);
        }
        let key = (profile.id.clone(), generation);
        let identity = Arc::new(());
        self.reservations
            .lock()
            .map_err(|_| StoreError::Io)?
            .insert(
                key.clone(),
                Reservation {
                    profile: reservation,
                    live: true,
                    identity: identity.clone(),
                },
            );
        Ok(ProfileUse {
            key,
            reservations: self.reservations.clone(),
            identity,
        })
    }
    pub(super) fn idle(&self) -> bool {
        self.reservations.try_lock().is_ok_and(|r| r.is_empty())
    }
    /// Keep the reservation set stable throughout recovery's scan. A new
    /// attempt cannot publish its journal until its reservation is present.
    pub(super) fn with_live<T>(
        &self,
        action: impl FnOnce(&std::collections::BTreeSet<(String, u64)>) -> T,
    ) -> Result<T, StoreError> {
        let reservations = self.reservations.lock().map_err(|_| StoreError::Io)?;
        let live = reservations
            .iter()
            .filter(|(_, reservation)| reservation.live)
            .map(|(key, _)| key.clone())
            .collect();
        Ok(action(&live))
    }
}
impl ProfileUse {
    /// Hold the reservation through the durable write and release only after
    /// the action commits successfully. `busy` is the error when the
    /// reservations are locked elsewhere; `error` covers the rest.
    pub(super) fn abandon_after<T, E>(
        &self,
        busy: impl FnOnce() -> E,
        error: impl Fn() -> E,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.locked(busy, error, true, action)
    }
    /// Same lock and check as `abandon_after`, but the reservation stays.
    pub(super) fn hold<T, E>(
        &self,
        busy: impl FnOnce() -> E,
        error: impl Fn() -> E,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.locked(busy, error, false, action)
    }
    fn locked<T, E>(
        &self,
        busy: impl FnOnce() -> E,
        error: impl Fn() -> E,
        release: bool,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let mut all = self.reservations.try_lock().map_err(|held| match held {
            std::sync::TryLockError::WouldBlock => busy(),
            std::sync::TryLockError::Poisoned(_) => error(),
        })?;
        if !all.contains_key(&self.key) {
            return Err(error());
        }
        let value = action()?;
        if release {
            all.remove(&self.key);
        }
        Ok(value)
    }
    pub(super) fn validate(&self) -> Result<(), StoreError> {
        self.reservations
            .lock()
            .map_err(|_| StoreError::Io)?
            .get(&self.key)
            .ok_or(StoreError::InvalidData)?
            .profile
            .validate()
    }
    pub(super) fn complete(&self) -> Result<(), StoreError> {
        let mut all = self.reservations.lock().map_err(|_| StoreError::Io)?;
        all.get(&self.key)
            .ok_or(StoreError::InvalidData)?
            .profile
            .validate()?;
        all.remove(&self.key);
        Ok(())
    }
    /// Release without asserting cleanup. Only call after durable fencing.
    #[allow(dead_code)] // The native abandonment path is not connected yet.
    pub(super) fn abandon(&self) -> Result<(), StoreError> {
        self.reservations
            .lock()
            .map_err(|_| StoreError::Io)?
            .remove(&self.key)
            .map(|_| ())
            .ok_or(StoreError::InvalidData)
    }
}

impl Drop for ProfileUse {
    fn drop(&mut self) {
        // The reservation deliberately outlives an unwound worker, but its
        // fence must no longer be exempt from recovery after that worker dies.
        if let Ok(mut all) = self.reservations.lock()
            && let Some(reservation) = all.get_mut(&self.key)
            && Arc::ptr_eq(&reservation.identity, &self.identity)
        {
            reservation.live = false;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod abandon_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn abandon_releases_only_the_named_reservation() {
        struct Root(std::path::PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(
            std::env::current_dir()
                .unwrap()
                .join("output/fixtures")
                .join(format!(
                    "profile-abandon-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )),
        );
        fs::create_dir_all(&root.0).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let store = ProfileStore::open(&root.0, uid).unwrap();
        let profile = |id: &str| -> Profile {
            serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"ssl","gateway":"vpn.example.test","username":"fictional","networks":["10.20.0.0/24"],"port":443,"certificate":"","probeHost":"10.20.0.15","probePort":8443,"probeMethod":"tcp"})).unwrap()
        };
        let first = profile("first");
        let second = profile("second");
        store.save(first.clone()).unwrap();
        store.save(second.clone()).unwrap();
        let profiles = Profiles::fixture(ProfileStore::open(&root.0, uid).unwrap());
        let first_use = profiles.begin(&first, 1).unwrap();
        let second_use = profiles.begin(&second, 1).unwrap();
        assert!(!profiles.idle());
        let held = profiles.reservations.lock().unwrap();
        let observed = std::thread::scope(|scope| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            let profiles = &profiles;
            let first_use = &first_use;
            scope.spawn(move || {
                let idle = profiles.idle();
                let abandon =
                    first_use.abandon_after(|| StoreError::Busy, || StoreError::Io, || Ok(()));
                let _ = send.send((idle, abandon));
            });
            let observed = receive.recv_timeout(std::time::Duration::from_millis(250));
            drop(held);
            observed
        });
        assert_eq!(observed.unwrap(), (false, Err(StoreError::Busy)));
        assert_eq!(store.remove("first"), Err(StoreError::Busy));
        first_use.abandon().unwrap();
        assert_eq!(store.remove("second"), Err(StoreError::Busy));
        assert!(!profiles.idle());
        second_use.complete().unwrap();
        assert!(profiles.idle());
        assert_eq!(first_use.abandon(), Err(StoreError::InvalidData));
        store.remove("first").unwrap();
        store.remove("second").unwrap();
    }
}
