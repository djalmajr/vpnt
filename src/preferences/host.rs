//! Host-side preference effects. Loading a saved choice never registers a
//! login item; the observed system status is the startup source of truth.
use super::Preferences;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupStatus {
    Disabled,
    Enabled,
    RequiresApproval,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Expired,
    Storage,
    StartupUnavailable,
    StartupRequiresApproval,
    StartupFailed,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::Expired => "backend_unavailable",
            Self::Storage => "preferences_unavailable",
            Self::StartupUnavailable | Self::StartupFailed => "startup_unavailable",
            Self::StartupRequiresApproval => "startup_requires_approval",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub error: Error,
    /// Keep a completed native effect visible even if a later step fails.
    pub observed: Preferences,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupFailure {
    pub observed: Option<StartupStatus>,
}
pub trait Backend {
    fn load(&mut self) -> Result<Option<Preferences>, Error>;
    fn save(&mut self, preferences: Preferences) -> Result<(), Error>;
    fn startup_status(&mut self) -> StartupStatus;
    fn set_startup(&mut self, enabled: bool) -> Result<StartupStatus, StartupFailure>;
}
pub trait Host {
    fn current(&self) -> Preferences;
    fn apply(&mut self, desired: Preferences, expires: Instant) -> Result<Preferences, Failure>;
}
/// A real host whose storage could not be read must not silently become a
/// successful, volatile preference store. Automatic effects default off.
pub struct Unavailable {
    error: Error,
}
impl Unavailable {
    pub fn new(error: Error) -> Self {
        Self { error }
    }
}
impl Host for Unavailable {
    fn current(&self) -> Preferences {
        Preferences {
            notify: false,
            ..Preferences::default()
        }
    }
    fn apply(&mut self, _: Preferences, _: Instant) -> Result<Preferences, Failure> {
        Err(Failure {
            error: self.error,
            observed: self.current(),
        })
    }
}
pub struct Coordinator<B> {
    backend: B,
    current: Preferences,
}
impl<B: Backend> Coordinator<B> {
    pub fn restore(mut backend: B) -> Result<Self, Error> {
        let mut current = backend.load()?.unwrap_or_default();
        current.startup = backend.startup_status() == StartupStatus::Enabled;
        Ok(Self { backend, current })
    }
    fn failure(&self, error: Error) -> Failure {
        Failure {
            error,
            observed: self.current,
        }
    }
    fn check(&self, expires: Instant) -> Result<(), Failure> {
        if Instant::now() >= expires {
            Err(self.failure(Error::Expired))
        } else {
            Ok(())
        }
    }
    fn observe(&mut self, status: StartupStatus) {
        if status != StartupStatus::Unavailable {
            self.current.startup = status == StartupStatus::Enabled;
        }
    }
}
impl<B: Backend> Host for Coordinator<B> {
    fn current(&self) -> Preferences {
        self.current
    }
    fn apply(
        &mut self,
        mut desired: Preferences,
        expires: Instant,
    ) -> Result<Preferences, Failure> {
        self.check(expires)?;
        // Detect intent before refreshing external state. Changing interval or
        // notification settings must never reassert a cached startup choice.
        let change_startup = desired.startup != self.current.startup;
        let status = self.backend.startup_status();
        self.observe(status);
        self.check(expires)?;
        if change_startup {
            if status == StartupStatus::Unavailable {
                return Err(self.failure(Error::StartupUnavailable));
            }
            match self.backend.set_startup(desired.startup) {
                Ok(status) => {
                    self.observe(status);
                    if desired.startup && status == StartupStatus::RequiresApproval {
                        return Err(self.failure(Error::StartupRequiresApproval));
                    }
                    if self.current.startup != desired.startup {
                        return Err(self.failure(Error::StartupFailed));
                    }
                }
                Err(error) => {
                    if let Some(status) = error.observed {
                        self.observe(status);
                    }
                    return Err(self.failure(Error::StartupFailed));
                }
            }
        }
        self.check(expires)?;
        desired.startup = self.current.startup;
        self.backend
            .save(desired)
            .map_err(|error| self.failure(error))?;
        self.current = desired;
        // SDK/storage operations already in flight cannot be interrupted. A
        // late success remains observable instead of pretending it was undone.
        self.check(expires)?;
        Ok(self.current)
    }
}

/// Existing non-desktop/test callers may keep ordinary choices in memory;
/// startup stays unavailable until an explicit native backend is injected.
#[derive(Default)]
pub struct Memory {
    preferences: Option<Preferences>,
}
impl Coordinator<Memory> {
    pub fn memory() -> Self {
        Self {
            backend: Memory::default(),
            current: Preferences::default(),
        }
    }
}
impl Backend for Memory {
    fn load(&mut self) -> Result<Option<Preferences>, Error> {
        Ok(self.preferences)
    }
    fn save(&mut self, preferences: Preferences) -> Result<(), Error> {
        self.preferences = Some(preferences);
        Ok(())
    }
    fn startup_status(&mut self) -> StartupStatus {
        StartupStatus::Unavailable
    }
    fn set_startup(&mut self, _: bool) -> Result<StartupStatus, StartupFailure> {
        Err(StartupFailure { observed: None })
    }
}

#[cfg(test)]
mod tests;
