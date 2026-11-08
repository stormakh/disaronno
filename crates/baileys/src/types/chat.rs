//! Same types as Types/Chat.ts.
//!
//! `Chat` is `proto::Conversation`. The generator adds the JavaScript-only fields: `last_message_recv_timestamp()`
//! and `timestamp()` never reach the wire. `unread_count` is `i32` because Baileys stores -1 in it. An explicit
//! null is `set_pinned_null()`, with `pinned_is_null()` to read it, and `assign_from` is `Object.assign`.
use super::auth_types::AccountSettings;
use super::bussines::QuickReplyAction;
use super::label::{ChatLabelAssociationActionBody, LabelActionBody, MessageLabelAssociationActionBody};
use super::message::{MinimalMessage, WAMessageKey};
use crate::events::BufferedEventData;
use std::sync::Arc;
use waproto::sync_action_value::{ContactAction, PrivacySettingDisableLinkPreviewsAction, SyncActionMessageRange};
use waproto::syncd_mutation::SyncdOperation;
use waproto::{SyncActionData, SyncActionValue};

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($v:ident = $s:literal),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name { $($v),* }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $($name::$v => $s),* }
            }
            pub fn parse(s: &str) -> Option<$name> {
                match s { $($s => Some($name::$v),)* _ => None }
            }
        }
    };
}
str_enum!(
    /// privacy settings in WhatsApp Web
    WAPrivacyValue { All = "all", Contacts = "contacts", ContactBlacklist = "contact_blacklist", None = "none" }
);
str_enum!(WAPrivacyOnlineValue { All = "all", MatchLastSeen = "match_last_seen" });
str_enum!(WAPrivacyGroupAddValue { All = "all", Contacts = "contacts", ContactBlacklist = "contact_blacklist" });
str_enum!(WAReadReceiptsValue { All = "all", None = "none" });
str_enum!(WAPrivacyCallValue { All = "all", Known = "known" });
str_enum!(WAPrivacyMessagesValue { All = "all", Contacts = "contacts" });
str_enum!(
    /// set of statuses visible to other people
    WAPresence { Unavailable = "unavailable", Available = "available", Composing = "composing", Recording = "recording", Paused = "paused" }
);
str_enum!(WAPatchName { CriticalBlock = "critical_block", CriticalUnblockLow = "critical_unblock_low", RegularHigh = "regular_high", RegularLow = "regular_low", Regular = "regular" });
pub const ALL_WA_PATCH_NAMES: [WAPatchName; 5] = [WAPatchName::CriticalBlock, WAPatchName::CriticalUnblockLow, WAPatchName::RegularHigh, WAPatchName::RegularLow, WAPatchName::Regular];

#[derive(Clone, Debug, PartialEq)]
pub struct PresenceData {
    pub last_known_presence: WAPresence,
    pub last_seen: Option<u64>,
    pub group_online_count: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotListInfo {
    pub jid: String,
    pub persona_id: String,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ChatMutation {
    pub sync_action: SyncActionData,
    pub index: Vec<String>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct WAPatchCreate {
    pub sync_action: SyncActionValue,
    pub index: Vec<String>,
    pub r#type: WAPatchName,
    pub api_version: u32,
    pub operation: SyncdOperation,
}
pub type Chat = waproto::Conversation;
/// Returns true if the update should be applied, false if it can be discarded, and `None`
/// if the condition is not yet fulfilled.
pub type ChatUpdateConditional = Arc<dyn Fn(&BufferedEventData) -> Option<bool> + Send + Sync>;
/// `Partial<Chat & { conditional, timestamp }>`. Reads and writes reach the chat through `Deref`.
#[derive(Clone, Default)]
pub struct ChatUpdate {
    pub chat: Chat,
    /// If set, the event buffer checks the condition before it applies the update.
    /// Right now, used to determine when to release an app state sync event.
    pub conditional: Option<ChatUpdateConditional>,
}
impl ChatUpdate {
    pub fn new(chat: Chat) -> ChatUpdate {
        ChatUpdate { chat, conditional: None }
    }
}
impl std::ops::Deref for ChatUpdate {
    type Target = Chat;
    fn deref(&self) -> &Chat {
        &self.chat
    }
}
impl std::ops::DerefMut for ChatUpdate {
    fn deref_mut(&mut self) -> &mut Chat {
        &mut self.chat
    }
}
impl PartialEq for ChatUpdate {
    fn eq(&self, o: &ChatUpdate) -> bool {
        self.chat == o.chat && self.conditional.is_some() == o.conditional.is_some()
    }
}
impl std::fmt::Debug for ChatUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatUpdate").field("chat", &self.chat).field("conditional", &self.conditional.is_some()).finish()
    }
}
/// the last messages in a chat, sorted reverse-chronologically. That is, the latest message should be first in the chat
/// for MD modifications, the last message in the array (i.e. the earlist message) must be the last message recv in the chat
#[derive(Clone, Debug, PartialEq)]
pub enum LastMessageList {
    Messages(Vec<MinimalMessage>),
    Range(SyncActionMessageRange),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarredMessage {
    pub id: String,
    pub from_me: Option<bool>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum ChatModification {
    Archive { archive: bool, last_messages: LastMessageList },
    PushNameSetting(String),
    Pin(bool),
    /// mute for duration, or provide timestamp of mute to remove. `None` is null.
    Mute(Option<u64>),
    Clear { clear: bool, last_messages: LastMessageList },
    DeleteForMe { delete_media: bool, key: WAMessageKey, timestamp: u64 },
    Star { messages: Vec<StarredMessage>, star: bool },
    MarkRead { mark_read: bool, last_messages: LastMessageList },
    Delete { last_messages: LastMessageList },
    /// `None` is null.
    Contact(Option<ContactAction>),
    DisableLinkPreviews(PrivacySettingDisableLinkPreviewsAction),
    AddLabel(LabelActionBody),
    AddChatLabel(ChatLabelAssociationActionBody),
    RemoveChatLabel(ChatLabelAssociationActionBody),
    AddMessageLabel(MessageLabelAssociationActionBody),
    RemoveMessageLabel(MessageLabelAssociationActionBody),
    QuickReply(QuickReplyAction),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct InitialReceivedChat {
    /// the last message received from the other party
    pub last_msg_recv_timestamp: Option<u64>,
    /// the absolute last message in the chat
    pub last_msg_timestamp: u64,
}
pub type InitialReceivedChatsState = rustc_hash::FxHashMap<String, InitialReceivedChat>;
#[derive(Clone, Debug, PartialEq, Default)]
pub struct InitialAppStateSyncOptions {
    pub account_settings: AccountSettings,
}
