//! Same types as Types/State.ts. Dates are milliseconds since the epoch.
use super::contact::Contact;
use crate::error::Boom;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum SyncState {
    /// The socket is connecting, but we haven't received pending notifications yet.
    #[default]
    Connecting,
    /// Pending notifications received. Buffering events until we decide whether to sync or not.
    AwaitingInitialSync,
    /// The initial app state sync (history, etc.) is in progress. Buffering continues.
    Syncing,
    /// Initial sync is complete, or was skipped. The socket is fully operational and events are processed in real-time.
    Online,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WAConnectionState {
    Open,
    Connecting,
    Close,
}
impl WAConnectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            WAConnectionState::Open => "open",
            WAConnectionState::Connecting => "connecting",
            WAConnectionState::Close => "close",
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct LastDisconnect {
    pub error: Option<Boom>,
    pub date_ms: i64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct LegacyConnectionState {
    pub phone_connected: bool,
    pub user: Option<Contact>,
}
/// `Partial<ConnectionState>`, and the state itself: `connection` is `None` only in an update.
/// `Some(None)` in `qr` is the `qr: undefined` that clears an old value.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ConnectionState {
    /// connection is now open, connecting or closed
    pub connection: Option<WAConnectionState>,
    /// the error that caused the connection to close
    pub last_disconnect: Option<LastDisconnect>,
    /// is this a new login
    pub is_new_login: Option<bool>,
    /// the current QR code
    pub qr: Option<Option<String>>,
    /// has the device received all pending notifications while it was offline
    pub received_pending_notifications: Option<bool>,
    /// legacy connection options
    pub legacy: Option<LegacyConnectionState>,
    /// if the client is shown as an active, online client.
    /// If this is false, the primary phone and other devices will receive notifs
    pub is_online: Option<bool>,
    /// When you are in this state, WhatsApp prevents outgoing messages and calls.
    pub reachout_time_lock: Option<ReachoutTimelockState>,
}
pub type ConnectionStateUpdate = ConnectionState;
impl ConnectionState {
    /// Same as `Object.assign(self, update)`.
    pub fn assign(&mut self, u: &ConnectionState) {
        fn set<T: Clone>(a: &mut Option<T>, b: &Option<T>) {
            if b.is_some() {
                *a = b.clone();
            }
        }
        set(&mut self.connection, &u.connection);
        set(&mut self.last_disconnect, &u.last_disconnect);
        set(&mut self.is_new_login, &u.is_new_login);
        set(&mut self.qr, &u.qr);
        set(&mut self.received_pending_notifications, &u.received_pending_notifications);
        set(&mut self.legacy, &u.legacy);
        set(&mut self.is_online, &u.is_online);
        set(&mut self.reachout_time_lock, &u.reachout_time_lock);
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReachoutTimelockState {
    pub is_active: Option<bool>,
    pub time_enforcement_ends_ms: Option<i64>,
    pub enforcement_type: Option<ReachoutTimelockEnforcementType>,
}
macro_rules! str_enum {
    ($name:ident { $($v:ident),* $(,)? }) => {
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name { $($v),* }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $($name::$v => stringify!($v)),* }
            }
            pub fn parse(s: &str) -> Option<$name> {
                match s { $(stringify!($v) => Some($name::$v),)* _ => None }
            }
        }
    };
}
str_enum!(ReachoutTimelockEnforcementType {
    BIZ_COMMERCE_VIOLATION_ALCOHOL,
    BIZ_COMMERCE_VIOLATION_ADULT,
    BIZ_COMMERCE_VIOLATION_ANIMALS,
    BIZ_COMMERCE_VIOLATION_BODY_PARTS_FLUIDS,
    BIZ_COMMERCE_VIOLATION_DATING,
    BIZ_COMMERCE_VIOLATION_DIGITAL_SERVICES_PRODUCTS,
    BIZ_COMMERCE_VIOLATION_DRUGS,
    BIZ_COMMERCE_VIOLATION_DRUGS_ONLY_OTC,
    BIZ_COMMERCE_VIOLATION_GAMBLING,
    BIZ_COMMERCE_VIOLATION_HEALTHCARE,
    BIZ_COMMERCE_VIOLATION_REAL_FAKE_CURRENCY,
    BIZ_COMMERCE_VIOLATION_SUPPLEMENTS,
    BIZ_COMMERCE_VIOLATION_TOBACCO,
    BIZ_COMMERCE_VIOLATION_VIOLENT_CONTENT,
    BIZ_COMMERCE_VIOLATION_WEAPONS,
    BIZ_QUALITY,
    DEFAULT,
    WEB_COMPANION_ONLY,
});
str_enum!(NewChatMessageCappingStatusType { NONE, FIRST_WARNING, SECOND_WARNING, CAPPED });
str_enum!(NewChatMessageCappingMVStatusType { NOT_ELIGIBLE, NOT_ACTIVE, ACTIVE, ACTIVE_UPGRADE_AVAILABLE });
str_enum!(NewChatMessageCappingOTEStatusType { NOT_ELIGIBLE, ELIGIBLE, ACTIVE_IN_CURRENT_CYCLE, EXHAUSTED });
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewChatMessageCapInfo {
    pub total_quota: Option<u32>,
    pub used_quota: Option<u32>,
    pub cycle_start_timestamp: Option<String>,
    pub cycle_end_timestamp: Option<String>,
    pub server_sent_timestamp: Option<String>,
    pub ote_status: Option<NewChatMessageCappingOTEStatusType>,
    pub mv_status: Option<NewChatMessageCappingMVStatusType>,
    pub capping_status: Option<NewChatMessageCappingStatusType>,
}
