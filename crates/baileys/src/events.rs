//! Same events as Types/Events.ts, and the emitter contract.
//!
//! A `BaileysEvent` has one variant for each entry of `BaileysEventMap`. Listeners subscribe by `EventKind`.
//! `on` returns a `ListenerId`, and `off` takes it, because Rust closures have no identity to compare.
use crate::auth::{CredsUpdate, LidMapping};
use crate::error::Boom;
use crate::types::*;
use crate::utils::generics::JsMap;
use std::sync::Arc;
use waproto::pb::{Bytes, Json};
use waproto::{PastParticipants, Reaction};
use waproto::history_sync::HistorySyncType;
use waproto::sync_action_value::notification_activity_setting_action::NotificationActivitySetting;
use waproto::sync_action_value::{PrivacySettingChannelsPersonalisedRecommendationAction, PrivacySettingDisableLinkPreviewsAction, PrivacySettingRelayAllCalls, StatusPrivacyAction, TimeFormatAction};

/// `messaging-history.set`. The `Option<Option<_>>` fields use `Some(None)` for null.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MessagingHistorySet {
    pub chats: Vec<Chat>,
    pub contacts: Vec<Contact>,
    pub messages: Vec<WAMessage>,
    pub lid_pn_mappings: Option<Vec<LidMapping>>,
    pub is_latest: Option<bool>,
    pub progress: Option<Option<f64>>,
    pub sync_type: Option<Option<HistorySyncType>>,
    pub past_participants: Option<Option<Vec<PastParticipants>>>,
    pub chunk_order: Option<Option<u32>>,
    pub peer_data_request_session_id: Option<Option<String>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HistorySyncStatus {
    Complete,
    Paused,
}
/// signals history sync milestones (completion or stall) per sync type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessagingHistoryStatus {
    /// which sync phase this status refers to
    pub sync_type: HistorySyncType,
    /// the status of this sync phase
    pub status: HistorySyncStatus,
    /// progress === 100 was received from the server.
    /// when false, completion was inferred via timeout (no more chunks arriving).
    pub explicit: bool,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct PresenceUpdate {
    pub id: String,
    pub presences: Vec<(String, PresenceData)>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum MessagesDelete {
    Keys(Vec<WAMessageKey>),
    All { jid: String },
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MediaRetryData {
    pub ciphertext: Bytes,
    pub iv: Bytes,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MessageMediaUpdate {
    pub key: WAMessageKey,
    pub media: Option<MediaRetryData>,
    pub error: Option<Boom>,
}
/// add/update the given messages. If they were received while the connection was online,
/// the update will have type: "notify"
/// if requestId is provided, then the messages was received from the phone due to it being unavailable
#[derive(Clone, Debug, PartialEq)]
pub struct MessagesUpsert {
    pub messages: Vec<WAMessage>,
    pub r#type: MessageUpsertType,
    pub request_id: Option<String>,
}
/// If the reaction was removed, then `reaction.text` is empty.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MessageReaction {
    pub key: WAMessageKey,
    pub reaction: Reaction,
}
/// apply an action to participants in a group
#[derive(Clone, Debug, PartialEq)]
pub struct GroupParticipantsUpdate {
    pub id: String,
    pub author: String,
    pub author_pn: Option<String>,
    pub author_username: Option<String>,
    pub participants: Vec<GroupParticipant>,
    pub action: ParticipantAction,
}
#[derive(Clone, Debug, PartialEq)]
pub struct GroupJoinRequest {
    pub id: String,
    pub author: String,
    pub author_pn: Option<String>,
    pub author_username: Option<String>,
    pub participant: String,
    pub participant_pn: Option<String>,
    pub action: RequestJoinAction,
    pub method: Option<RequestJoinMethod>,
}
/// update the labels assigned to a group participant
#[derive(Clone, Debug, PartialEq, Default)]
pub struct GroupMemberTagUpdate {
    pub group_id: String,
    pub participant: String,
    pub participant_alt: Option<String>,
    pub label: String,
    pub message_timestamp: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListUpdateType {
    Add,
    Remove,
}
impl ListUpdateType {
    pub fn as_str(self) -> &'static str {
        match self {
            ListUpdateType::Add => "add",
            ListUpdateType::Remove => "remove",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct NewsletterReactionData {
    pub code: Option<String>,
    pub count: Option<u64>,
    pub removed: Option<bool>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum SettingsUpdate {
    UnarchiveChats(bool),
    Locale(String),
    DisableLinkPreviews(PrivacySettingDisableLinkPreviewsAction),
    TimeFormat(TimeFormatAction),
    PrivacySettingRelayAllCalls(PrivacySettingRelayAllCalls),
    StatusPrivacy(StatusPrivacyAction),
    NotificationActivitySetting(NotificationActivitySetting),
    ChannelsPersonalisedRecommendation(PrivacySettingChannelsPersonalisedRecommendationAction),
}
#[derive(Clone, Debug, PartialEq)]
pub enum BaileysEvent {
    /// connection state has been updated -- WS closed, opened, connecting etc.
    ConnectionUpdate(ConnectionStateUpdate),
    /// credentials updated -- some metadata, keys or something
    CredsUpdate(Box<CredsUpdate>),
    /// set chats (history sync), everything is reverse chronologically sorted
    MessagingHistorySet(MessagingHistorySet),
    MessagingHistoryStatus(MessagingHistoryStatus),
    /// upsert chats
    ChatsUpsert(Vec<Chat>),
    /// update the given chats
    ChatsUpdate(Vec<ChatUpdate>),
    LidMappingUpdate(LidMapping),
    /// delete chats with given ID
    ChatsDelete(Vec<String>),
    /// presence of contact in a chat updated
    PresenceUpdate(PresenceUpdate),
    ContactsUpsert(Vec<Contact>),
    ContactsUpdate(Vec<ContactUpdate>),
    MessagesDelete(MessagesDelete),
    MessagesUpdate(Vec<WAMessageUpdate>),
    MessagesMediaUpdate(Vec<MessageMediaUpdate>),
    MessagesUpsert(MessagesUpsert),
    /// message was reacted to
    MessagesReaction(Vec<MessageReaction>),
    MessageReceiptUpdate(Vec<MessageUserReceiptUpdate>),
    GroupsUpsert(Vec<GroupMetadata>),
    GroupsUpdate(Vec<GroupMetadataUpdate>),
    GroupParticipantsUpdate(GroupParticipantsUpdate),
    GroupJoinRequest(GroupJoinRequest),
    GroupMemberTagUpdate(GroupMemberTagUpdate),
    BlocklistSet { blocklist: Vec<String> },
    BlocklistUpdate { blocklist: Vec<String>, r#type: ListUpdateType },
    /// Receive an update on a call, including when the call was received, rejected, accepted
    Call(Vec<WACallEvent>),
    LabelsEdit(Label),
    LabelsAssociation { association: LabelAssociation, r#type: ListUpdateType },
    /// Newsletter-related events
    NewsletterReaction { id: String, server_id: String, reaction: NewsletterReactionData },
    NewsletterView { id: String, server_id: String, count: u64 },
    NewsletterParticipantsUpdate { id: String, author: String, user: String, new_role: String, action: String },
    NewsletterSettingsUpdate { id: String, update: Json },
    MessageCappingUpdate(NewChatMessageCapInfo),
    /// Settings and actions sync events
    ChatsLock { id: String, locked: bool },
    SettingsUpdate(SettingsUpdate),
}
macro_rules! event_kinds {
    ($($v:ident = $s:literal),* $(,)?) => {
        /// The name of an event: a key of `BaileysEventMap`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum EventKind { $($v),* }
        impl EventKind {
            pub const ALL: &'static [EventKind] = &[$(EventKind::$v),*];
            /// The event name in upstream, such as `messages.upsert`.
            pub fn name(self) -> &'static str {
                match self { $(EventKind::$v => $s),* }
            }
            pub fn from_name(s: &str) -> Option<EventKind> {
                match s { $($s => Some(EventKind::$v),)* _ => None }
            }
        }
    };
}
event_kinds!(
    ConnectionUpdate = "connection.update",
    CredsUpdate = "creds.update",
    MessagingHistorySet = "messaging-history.set",
    MessagingHistoryStatus = "messaging-history.status",
    ChatsUpsert = "chats.upsert",
    ChatsUpdate = "chats.update",
    LidMappingUpdate = "lid-mapping.update",
    ChatsDelete = "chats.delete",
    PresenceUpdate = "presence.update",
    ContactsUpsert = "contacts.upsert",
    ContactsUpdate = "contacts.update",
    MessagesDelete = "messages.delete",
    MessagesUpdate = "messages.update",
    MessagesMediaUpdate = "messages.media-update",
    MessagesUpsert = "messages.upsert",
    MessagesReaction = "messages.reaction",
    MessageReceiptUpdate = "message-receipt.update",
    GroupsUpsert = "groups.upsert",
    GroupsUpdate = "groups.update",
    GroupParticipantsUpdate = "group-participants.update",
    GroupJoinRequest = "group.join-request",
    GroupMemberTagUpdate = "group.member-tag.update",
    BlocklistSet = "blocklist.set",
    BlocklistUpdate = "blocklist.update",
    Call = "call",
    LabelsEdit = "labels.edit",
    LabelsAssociation = "labels.association",
    NewsletterReaction = "newsletter.reaction",
    NewsletterView = "newsletter.view",
    NewsletterParticipantsUpdate = "newsletter-participants.update",
    NewsletterSettingsUpdate = "newsletter-settings.update",
    MessageCappingUpdate = "message-capping.update",
    ChatsLock = "chats.lock",
    SettingsUpdate = "settings.update",
);
impl BaileysEvent {
    pub fn kind(&self) -> EventKind {
        match self {
            BaileysEvent::ConnectionUpdate(_) => EventKind::ConnectionUpdate,
            BaileysEvent::CredsUpdate(_) => EventKind::CredsUpdate,
            BaileysEvent::MessagingHistorySet(_) => EventKind::MessagingHistorySet,
            BaileysEvent::MessagingHistoryStatus(_) => EventKind::MessagingHistoryStatus,
            BaileysEvent::ChatsUpsert(_) => EventKind::ChatsUpsert,
            BaileysEvent::ChatsUpdate(_) => EventKind::ChatsUpdate,
            BaileysEvent::LidMappingUpdate(_) => EventKind::LidMappingUpdate,
            BaileysEvent::ChatsDelete(_) => EventKind::ChatsDelete,
            BaileysEvent::PresenceUpdate(_) => EventKind::PresenceUpdate,
            BaileysEvent::ContactsUpsert(_) => EventKind::ContactsUpsert,
            BaileysEvent::ContactsUpdate(_) => EventKind::ContactsUpdate,
            BaileysEvent::MessagesDelete(_) => EventKind::MessagesDelete,
            BaileysEvent::MessagesUpdate(_) => EventKind::MessagesUpdate,
            BaileysEvent::MessagesMediaUpdate(_) => EventKind::MessagesMediaUpdate,
            BaileysEvent::MessagesUpsert(_) => EventKind::MessagesUpsert,
            BaileysEvent::MessagesReaction(_) => EventKind::MessagesReaction,
            BaileysEvent::MessageReceiptUpdate(_) => EventKind::MessageReceiptUpdate,
            BaileysEvent::GroupsUpsert(_) => EventKind::GroupsUpsert,
            BaileysEvent::GroupsUpdate(_) => EventKind::GroupsUpdate,
            BaileysEvent::GroupParticipantsUpdate(_) => EventKind::GroupParticipantsUpdate,
            BaileysEvent::GroupJoinRequest(_) => EventKind::GroupJoinRequest,
            BaileysEvent::GroupMemberTagUpdate(_) => EventKind::GroupMemberTagUpdate,
            BaileysEvent::BlocklistSet { .. } => EventKind::BlocklistSet,
            BaileysEvent::BlocklistUpdate { .. } => EventKind::BlocklistUpdate,
            BaileysEvent::Call(_) => EventKind::Call,
            BaileysEvent::LabelsEdit(_) => EventKind::LabelsEdit,
            BaileysEvent::LabelsAssociation { .. } => EventKind::LabelsAssociation,
            BaileysEvent::NewsletterReaction { .. } => EventKind::NewsletterReaction,
            BaileysEvent::NewsletterView { .. } => EventKind::NewsletterView,
            BaileysEvent::NewsletterParticipantsUpdate { .. } => EventKind::NewsletterParticipantsUpdate,
            BaileysEvent::NewsletterSettingsUpdate { .. } => EventKind::NewsletterSettingsUpdate,
            BaileysEvent::MessageCappingUpdate(_) => EventKind::MessageCappingUpdate,
            BaileysEvent::ChatsLock { .. } => EventKind::ChatsLock,
            BaileysEvent::SettingsUpdate(_) => EventKind::SettingsUpdate,
        }
    }
}
/// `Partial<BaileysEventMap>`: each kind appears at most once, in the order that upstream builds the map.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BaileysEventData(pub Vec<BaileysEvent>);
impl BaileysEventData {
    pub fn get(&self, kind: EventKind) -> Option<&BaileysEvent> {
        self.0.iter().find(|e| e.kind() == kind)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> std::slice::Iter<'_, BaileysEvent> {
        self.0.iter()
    }
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct HistorySets {
    pub chats: JsMap<Chat>,
    pub contacts: JsMap<Contact>,
    pub messages: JsMap<WAMessage>,
    pub empty: bool,
    pub is_latest: bool,
    /// `Some(None)` is null.
    pub progress: Option<Option<f64>>,
    pub sync_type: Option<Option<HistorySyncType>>,
    pub past_participants: Option<Vec<PastParticipants>>,
    pub chunk_order: Option<Option<u32>>,
    pub peer_data_request_session_id: Option<Option<String>>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct BufferedMessageUpsert {
    pub r#type: MessageUpsertType,
    pub message: WAMessage,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BufferedReactions {
    pub key: WAMessageKey,
    pub reactions: Vec<Reaction>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BufferedReceipts {
    pub key: WAMessageKey,
    pub user_receipt: Vec<MessageUserReceipt>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BufferedEventData {
    pub history_sets: HistorySets,
    pub chat_upserts: JsMap<Chat>,
    pub chat_updates: JsMap<ChatUpdate>,
    pub chat_deletes: JsMap<()>,
    pub contact_upserts: JsMap<Contact>,
    pub contact_updates: JsMap<ContactUpdate>,
    pub message_upserts: JsMap<BufferedMessageUpsert>,
    pub message_updates: JsMap<WAMessageUpdate>,
    pub message_deletes: JsMap<WAMessageKey>,
    pub message_reactions: JsMap<BufferedReactions>,
    pub message_receipts: JsMap<BufferedReceipts>,
    pub group_updates: JsMap<GroupMetadataUpdate>,
}
pub type Listener = Arc<dyn Fn(&BaileysEvent) + Send + Sync>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListenerId(pub u64);
/// The emitter contract. The socket code takes `&dyn BaileysEventEmitter`, so a test can pass a
/// recording mock and implement only these four methods.
pub trait BaileysEventEmitter: Send + Sync {
    fn on(&self, event: EventKind, listener: Listener) -> ListenerId;
    fn off(&self, event: EventKind, listener: ListenerId);
    fn remove_all_listeners(&self, event: EventKind);
    fn emit(&self, event: BaileysEvent) -> bool;
}
