//! Same types as src/Types. Everything is also re-exported from this module, as Types/index.ts does.
pub mod bussines;
pub mod call;
pub mod chat;
pub mod contact;
pub mod group_metadata;
pub mod label;
pub mod message;
pub mod mex;
pub mod product;
pub mod socket;
pub mod state;
pub mod usync;
/// Types/Auth.ts lives in `crate::auth`.
pub mod auth_types {
    pub use crate::auth::*;
}
pub use crate::auth::*;
pub use crate::events::*;
pub use crate::signal::repository::{E2ESession, EncryptedMessage, GroupEncrypted, MigrationResult, PreKeyPub, SessionValidation, SignalRepository, SignedPreKeyPub};
pub use bussines::*;
pub use call::*;
pub use chat::*;
pub use contact::*;
pub use group_metadata::*;
pub use label::*;
pub use message::*;
pub use mex::*;
pub use product::*;
pub use socket::*;
pub use state::*;
pub use usync::*;

/// `Partial<SocketConfig> & { auth }`: start from `default_connection_config()` and set `auth`.
pub type UserFacingSocketConfig = SocketConfig;

/// Same values as the enum in Types/index.ts. `connectionLost` and `timedOut` share 408.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DisconnectReason(pub u16);
impl DisconnectReason {
    pub const CONNECTION_CLOSED: DisconnectReason = DisconnectReason(428);
    pub const CONNECTION_LOST: DisconnectReason = DisconnectReason(408);
    pub const CONNECTION_REPLACED: DisconnectReason = DisconnectReason(440);
    pub const TIMED_OUT: DisconnectReason = DisconnectReason(408);
    pub const LOGGED_OUT: DisconnectReason = DisconnectReason(401);
    pub const BAD_SESSION: DisconnectReason = DisconnectReason(500);
    pub const RESTART_REQUIRED: DisconnectReason = DisconnectReason(515);
    pub const MULTIDEVICE_MISMATCH: DisconnectReason = DisconnectReason(411);
    pub const FORBIDDEN: DisconnectReason = DisconnectReason(403);
    pub const UNAVAILABLE_SERVICE: DisconnectReason = DisconnectReason(503);
    /// Same as `DisconnectReason[code]`. A shared value gives the last name, as in TypeScript.
    pub fn name(self) -> Option<&'static str> {
        match self.0 {
            428 => Some("connectionClosed"),
            408 => Some("timedOut"),
            440 => Some("connectionReplaced"),
            401 => Some("loggedOut"),
            500 => Some("badSession"),
            515 => Some("restartRequired"),
            411 => Some("multideviceMismatch"),
            403 => Some("forbidden"),
            503 => Some("unavailableService"),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WAInitResponse {
    pub r#ref: String,
    pub ttl: u64,
    pub status: u16,
}
pub type CurveKeyPair = crate::crypto::KeyPair;
