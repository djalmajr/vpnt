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

type Reservations = Arc<Mutex<BTreeMap<(String, u64), ProfileReservation>>>;
pub(super) struct Profiles {
    store: ProfileStore,
    reservations: Reservations,
}
pub(super) struct ProfileUse {
    key: (String, u64),
    reservations: Reservations,
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
        self.reservations
            .lock()
            .map_err(|_| StoreError::Io)?
            .insert(key.clone(), reservation);
        Ok(ProfileUse {
            key,
            reservations: self.reservations.clone(),
        })
    }
    pub(super) fn idle(&self) -> bool {
        self.reservations.lock().is_ok_and(|r| r.is_empty())
    }
}
impl ProfileUse {
    pub(super) fn validate(&self) -> Result<(), StoreError> {
        self.reservations
            .lock()
            .map_err(|_| StoreError::Io)?
            .get(&self.key)
            .ok_or(StoreError::InvalidData)?
            .validate()
    }
    pub(super) fn complete(&self) -> Result<(), StoreError> {
        let mut all = self.reservations.lock().map_err(|_| StoreError::Io)?;
        all.get(&self.key)
            .ok_or(StoreError::InvalidData)?
            .validate()?;
        all.remove(&self.key);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
