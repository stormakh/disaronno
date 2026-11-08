//! Same types as Types/Message.ts.
//!
//! `WAMessage` is `proto::WebMessageInfo` and `WAMessageKey` is `proto::MessageKey`. The generator adds the
//! JavaScript-only fields, so `key.remote_jid_alt()`, `key.set_participant_alt(..)` and `msg.category()` work
//! like proto fields but never reach the wire or `to_json`.
use super::socket::{CacheStore, RequestInit};
use crate::defaults::MediaType;
use crate::error::Result;
use crate::utils::logger::Logger;
use crate::wabinary::BinaryNode;
use std::sync::Arc;
use waproto::message::{ContactMessage, ExtendedTextMessage, ImageMessage, ListResponseMessage, LocationMessage, ReactionMessage};
use waproto::pb::Bytes;

pub type WAMessage = waproto::WebMessageInfo;
pub type WAMessageContent = waproto::Message;
pub type WAContactMessage = ContactMessage;
pub type WAContactsArrayMessage = waproto::message::ContactsArrayMessage;
pub type WAMessageKey = waproto::MessageKey;
pub type WATextMessage = ExtendedTextMessage;
pub type WAContextInfo = waproto::ContextInfo;
pub type WALocationMessage = LocationMessage;
pub type WAMessageStubType = waproto::web_message_info::StubType;
pub type WAMessageStatus = waproto::web_message_info::Status;
/// Set of message types that are supported by the library: a field name of `proto::Message`.
pub type MessageType = &'static str;

/// Bytes that are read when they are needed, in place of a Node `Readable`.
pub trait MediaStream: Send + Sync {
    /// Reads up to `buf.len()` bytes and returns how many. 0 means the end of the stream.
    fn read(&self, buf: &mut [u8]) -> Result<usize>;
}
#[derive(Clone)]
pub enum WAMediaUpload {
    Buffer(Bytes),
    Stream(Arc<dyn MediaStream>),
    Url(String),
}
impl std::fmt::Debug for WAMediaUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WAMediaUpload::Buffer(b) => write!(f, "Buffer({} bytes)", b.len()),
            WAMediaUpload::Stream(_) => f.write_str("Stream"),
            WAMediaUpload::Url(u) => write!(f, "Url({u})"),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WAMessageAddressingMode {
    Pn,
    Lid,
}
impl WAMessageAddressingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            WAMessageAddressingMode::Pn => "pn",
            WAMessageAddressingMode::Lid => "lid",
        }
    }
}
pub const MESSAGE_WITH_CONTEXT_INFO: [&str; 31] = [
    "imageMessage",
    "contactMessage",
    "locationMessage",
    "extendedTextMessage",
    "documentMessage",
    "audioMessage",
    "videoMessage",
    "call",
    "contactsArrayMessage",
    "liveLocationMessage",
    "templateMessage",
    "stickerMessage",
    "groupInviteMessage",
    "templateButtonReplyMessage",
    "productMessage",
    "listMessage",
    "orderMessage",
    "listResponseMessage",
    "buttonsMessage",
    "buttonsResponseMessage",
    "interactiveMessage",
    "interactiveResponseMessage",
    "pollCreationMessage",
    "requestPhoneNumberMessage",
    "messageHistoryBundle",
    "eventMessage",
    "newsletterAdminInviteMessage",
    "albumMessage",
    "stickerPackMessage",
    "pollResultSnapshotMessage",
    "messageHistoryNotice",
];
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DownloadableMessage {
    pub media_key: Option<Bytes>,
    pub direct_path: Option<String>,
    pub url: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageReceiptType {
    Read,
    ReadSelf,
    HistSync,
    PeerMsg,
    Sender,
    Inactive,
    Played,
}
impl MessageReceiptType {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageReceiptType::Read => "read",
            MessageReceiptType::ReadSelf => "read-self",
            MessageReceiptType::HistSync => "hist_sync",
            MessageReceiptType::PeerMsg => "peer_msg",
            MessageReceiptType::Sender => "sender",
            MessageReceiptType::Inactive => "inactive",
            MessageReceiptType::Played => "played",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MediaConnHost {
    pub hostname: String,
    pub max_content_length_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MediaConnInfo {
    pub auth: String,
    pub ttl: u64,
    pub hosts: Vec<MediaConnHost>,
    pub fetch_date_ms: i64,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct WAUrlInfo {
    pub canonical_url: String,
    pub matched_text: String,
    pub title: String,
    pub description: Option<String>,
    pub jpeg_thumbnail: Option<Bytes>,
    pub high_quality_thumbnail: Option<ImageMessage>,
    pub original_thumbnail_url: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Mentionable {
    /// list of jids that are mentioned in the accompanying text
    pub mentions: Option<Vec<String>>,
    /// mention all
    pub mention_all: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct PollMessageOptions {
    pub name: String,
    pub selectable_count: Option<u32>,
    pub values: Vec<String>,
    /// 32 byte message secret to encrypt poll selections
    pub message_secret: Option<Bytes>,
    pub to_announcement_group: Option<bool>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallType {
    Audio,
    Video,
}
impl CallType {
    pub fn as_str(self) -> &'static str {
        match self {
            CallType::Audio => "audio",
            CallType::Video => "video",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct EventMessageOptions {
    pub name: String,
    pub description: Option<String>,
    pub start_date_ms: i64,
    pub end_date_ms: Option<i64>,
    pub location: Option<WALocationMessage>,
    pub call: Option<CallType>,
    pub is_cancelled: Option<bool>,
    pub is_schedule_call: Option<bool>,
    pub extra_guests_allowed: Option<bool>,
    pub message_secret: Option<Bytes>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AlbumMessageOptions {
    /// Number of images expected in the album
    pub expected_image_count: Option<u32>,
    /// Number of videos expected in the album
    pub expected_video_count: Option<u32>,
}
/// The first group of fields of `AnyMediaMessageContent`, one variant per media type.
#[derive(Clone, Debug)]
pub enum MediaContent {
    Image { image: WAMediaUpload, caption: Option<String>, jpeg_thumbnail: Option<String>, mentions: Mentionable, context_info: Option<waproto::ContextInfo>, width: Option<u32>, height: Option<u32> },
    Video { video: WAMediaUpload, caption: Option<String>, gif_playback: Option<bool>, jpeg_thumbnail: Option<String>, ptv: Option<bool>, mentions: Mentionable, context_info: Option<waproto::ContextInfo>, width: Option<u32>, height: Option<u32> },
    Audio { audio: WAMediaUpload, ptt: Option<bool>, seconds: Option<u32> },
    Sticker { sticker: WAMediaUpload, is_animated: Option<bool>, width: Option<u32>, height: Option<u32> },
    Document { document: WAMediaUpload, mimetype: String, file_name: Option<String>, caption: Option<String>, context_info: Option<waproto::ContextInfo> },
}
#[derive(Clone, Debug)]
pub struct AnyMediaMessageContent {
    pub media: MediaContent,
    pub mimetype: Option<String>,
    pub edit: Option<WAMessageKey>,
    /// key of the parent albumMessage to associate this media with
    pub album_parent_key: Option<WAMessageKey>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ButtonReplyInfo {
    pub display_text: String,
    pub id: String,
    pub index: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ButtonReplyType {
    Template,
    Plain,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GroupInviteInfo {
    pub invite_code: String,
    pub invite_expiration: u64,
    pub text: String,
    pub jid: String,
    pub subject: String,
}
#[derive(Clone, Debug)]
pub struct WASendableProduct {
    /// `productImage` of this snapshot is not read. `product_image` takes its place.
    pub snapshot: waproto::message::product_message::ProductSnapshot,
    pub product_image: WAMediaUpload,
}
#[derive(Clone, Debug)]
pub enum RegularContent {
    Text {
        text: String,
        /// `Some(None)` is null: send no preview.
        link_preview: Option<Option<WAUrlInfo>>,
        mentions: Mentionable,
        context_info: Option<waproto::ContextInfo>,
        edit: Option<WAMessageKey>,
    },
    Media(Box<AnyMediaMessageContent>),
    Event(Box<EventMessageOptions>),
    Poll { poll: PollMessageOptions, mentions: Mentionable, context_info: Option<waproto::ContextInfo>, edit: Option<WAMessageKey> },
    Album { album: AlbumMessageOptions, context_info: Option<waproto::ContextInfo>, mentions: Mentionable },
    Contacts { display_name: Option<String>, contacts: Vec<ContactMessage> },
    Location(WALocationMessage),
    React(ReactionMessage),
    ButtonReply { button_reply: ButtonReplyInfo, r#type: ButtonReplyType },
    GroupInvite(GroupInviteInfo),
    /// `contextInfo` of this message is not read.
    ListReply(ListResponseMessage),
    Pin {
        pin: WAMessageKey,
        r#type: waproto::pin_in_chat::Type,
        /// 24 hours, 7 days or 30 days, in seconds
        time: Option<u32>,
    },
    Product { product: Box<WASendableProduct>, business_owner_jid: Option<String>, body: Option<String>, footer: Option<String> },
    SharePhoneNumber(bool),
    RequestPhoneNumber(bool),
}
#[derive(Clone, Debug)]
pub struct AnyRegularMessageContent {
    pub content: RegularContent,
    pub view_once: Option<bool>,
}
impl From<RegularContent> for AnyRegularMessageContent {
    fn from(content: RegularContent) -> AnyRegularMessageContent {
        AnyRegularMessageContent { content, view_once: None }
    }
}
/// `disappearingMessagesInChat`: a flag or a duration in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisappearingMessages {
    Enabled(bool),
    Seconds(u32),
}
#[derive(Clone, Debug)]
pub enum AnyMessageContent {
    Regular(Box<AnyRegularMessageContent>),
    Forward { forward: Box<WAMessage>, force: Option<bool> },
    /// Delete your message or anyone's message in a group (admin required)
    Delete(WAMessageKey),
    DisappearingMessagesInChat(DisappearingMessages),
    LimitSharing(bool),
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct GroupMetadataParticipants {
    pub participants: Vec<super::group_metadata::GroupParticipant>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RelayParticipant {
    pub jid: String,
    pub count: u32,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MessageRelayOptions {
    /// override the message ID with a custom provided string
    pub message_id: Option<String>,
    /// should we use group metadata cache, or fetch afresh from the server; default assumed to be "true"
    pub use_cached_group_metadata: Option<bool>,
    /// only send to a specific participant; used when a message decryption fails for a single user
    pub participant: Option<RelayParticipant>,
    /// additional attributes to add to the WA binary node
    pub additional_attributes: Option<Vec<(String, String)>>,
    pub additional_nodes: Option<Vec<BinaryNode>>,
    /// should we use the devices cache, or fetch afresh from the server; default assumed to be "true"
    pub use_user_devices_cache: Option<bool>,
    /// jid list of participants for status@broadcast
    pub status_jid_list: Option<Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EphemeralExpiration {
    Seconds(u32),
    Text(String),
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MiscMessageGenerationOptions {
    pub message_id: Option<String>,
    pub use_cached_group_metadata: Option<bool>,
    /// optional, if you want to manually set the timestamp of the message
    pub timestamp_ms: Option<i64>,
    /// the message you want to quote
    pub quoted: Option<WAMessage>,
    /// disappearing messages settings
    pub ephemeral_expiration: Option<EphemeralExpiration>,
    /// timeout for media upload to WA server
    pub media_upload_timeout_ms: Option<u64>,
    /// jid list of participants for status@broadcast
    pub status_jid_list: Option<Vec<String>>,
    /// backgroundcolor for status
    pub background_color: Option<String>,
    /// font type for status
    pub font: Option<i32>,
    /// if it is broadcast
    pub broadcast: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MessageGenerationOptionsFromContent {
    pub misc: MiscMessageGenerationOptions,
    pub user_jid: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaUploadOpts {
    pub file_enc_sha256_b64: String,
    pub media_type: MediaType,
    pub timeout_ms: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MediaUploadResult {
    pub media_url: String,
    pub direct_path: String,
    pub meta_hmac: Option<String>,
    pub ts: Option<u64>,
    pub fbid: Option<u64>,
}
pub type WAMediaUploadFunction = Arc<dyn Fn(&str, &MediaUploadOpts) -> Result<MediaUploadResult> + Send + Sync>;
#[derive(Clone)]
pub struct MediaGenerationOptions {
    pub logger: Option<Arc<dyn Logger>>,
    pub media_type_override: Option<MediaType>,
    pub upload: WAMediaUploadFunction,
    /// cache media so it does not have to be uploaded again
    pub media_cache: Option<Arc<dyn CacheStore>>,
    pub media_upload_timeout_ms: Option<u64>,
    pub options: Option<RequestInit>,
    pub background_color: Option<String>,
    pub font: Option<i32>,
}
pub type GetUrlInfo = Arc<dyn Fn(&str) -> Option<WAUrlInfo> + Send + Sync>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfilePictureType {
    Image,
    Preview,
}
pub type GetProfilePicUrl = Arc<dyn Fn(&str, ProfilePictureType) -> Option<String> + Send + Sync>;
pub type GetCallLink = Arc<dyn Fn(CallType, Option<u64>) -> Option<String> + Send + Sync>;
#[derive(Clone)]
pub struct MessageContentGenerationOptions {
    pub media: MediaGenerationOptions,
    pub get_url_info: Option<GetUrlInfo>,
    pub get_profile_pic_url: Option<GetProfilePicUrl>,
    pub get_call_link: Option<GetCallLink>,
    pub jid: Option<String>,
}
#[derive(Clone)]
pub struct MessageGenerationOptions {
    pub content: MessageContentGenerationOptions,
    pub from_content: MessageGenerationOptionsFromContent,
}
/// Type of message upsert
/// 1. notify => notify the user, this message was just received
/// 2. append => append the message to the chat history, no notification required
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageUpsertType {
    Append,
    Notify,
}
impl MessageUpsertType {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageUpsertType::Append => "append",
            MessageUpsertType::Notify => "notify",
        }
    }
}
pub type MessageUserReceipt = waproto::UserReceipt;
/// `update` is `Partial<WAMessage>`: only the fields that are set apply.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct WAMessageUpdate {
    pub update: WAMessage,
    pub key: WAMessageKey,
}
#[derive(Clone, Debug, PartialEq)]
pub enum WAMessageCursor {
    Before(Option<WAMessageKey>),
    After(Option<WAMessageKey>),
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MessageUserReceiptUpdate {
    pub key: WAMessageKey,
    pub receipt: MessageUserReceipt,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MediaDecryptionKeyInfo {
    pub iv: Vec<u8>,
    pub cipher_key: Vec<u8>,
    pub mac_key: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct MinimalMessage {
    pub key: WAMessageKey,
    pub message_timestamp: Option<u64>,
}
