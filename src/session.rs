use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Off,
    Connecting,
    Verifying,
    Connected,
    Unresponsive,
    Reconnecting,
    Disconnecting,
    Dropped,
    CredentialsRejected,
    GatewayTimeout,
    MissingSecret,
    MissingProgram,
    Offline,
    HelperMissing,
}

impl ConnectionState {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Connecting
                | Self::Verifying
                | Self::Connected
                | Self::Unresponsive
                | Self::Reconnecting
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Completion {
    TunnelReady,
    ProbePassed,
    ProbeFailed,
    Stopped,
    UnexpectedExit,
    CredentialsRejected,
    GatewayTimeout,
}

/// Each operation invalidates results from earlier attempts, including probes.
#[derive(Debug, Default)]
pub struct Session {
    state: ConnectionState,
    generation: u64,
}

impl Session {
    pub fn with_state(state: ConnectionState) -> Self {
        Self {
            state,
            generation: 0,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn start(&mut self, state: ConnectionState) -> u64 {
        self.generation += 1;
        self.state = state;
        self.generation
    }

    pub fn connect(&mut self) -> u64 {
        self.start(ConnectionState::Connecting)
    }

    pub fn reconnect(&mut self) -> u64 {
        self.start(ConnectionState::Reconnecting)
    }

    pub fn disconnect(&mut self) -> u64 {
        self.start(ConnectionState::Disconnecting)
    }

    pub fn complete(&mut self, generation: u64, result: Completion) -> bool {
        use ConnectionState as S;
        if generation != self.generation {
            return false;
        }
        self.state = match (self.state, result) {
            (S::Connecting | S::Reconnecting, Completion::TunnelReady) => S::Verifying,
            (S::Verifying | S::Connected | S::Unresponsive, Completion::ProbePassed) => {
                S::Connected
            }
            (S::Verifying | S::Connected | S::Unresponsive, Completion::ProbeFailed) => {
                S::Unresponsive
            }
            (S::Disconnecting, Completion::Stopped) => S::Off,
            (state, Completion::UnexpectedExit) if state.active() => S::Dropped,
            (S::Connecting | S::Reconnecting, Completion::CredentialsRejected) => {
                S::CredentialsRejected
            }
            (S::Connecting | S::Reconnecting, Completion::GatewayTimeout) => S::GatewayTimeout,
            _ => return false,
        };
        true
    }
}
