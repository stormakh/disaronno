//! Same types as Types/Socket.ts.
use super::auth_types::{AuthenticationState, SignalAuthState, TransactionCapabilityOptions};
use super::group_metadata::GroupMetadata;
use super::message::{MediaConnHost, WAMessageKey};
use crate::error::Result;
use crate::signal::lid_mapping::PnToLidFn;
use crate::signal::repository::SignalRepository;
use crate::utils::logger::Logger;
use std::any::Any;
use std::sync::Arc;
use waproto::Message;
use waproto::message::HistorySyncNotification;

pub type WAVersion = [u32; 3];
pub type WABrowserDescription = [String; 3];

/// A cached value. `cache_get` and `cache_set` handle the type for you.
pub type CacheValue = Arc<dyn Any + Send + Sync>;
pub trait CacheStore: Send + Sync {
    /// get a cached key and change the stats
    fn get(&self, key: &str) -> Option<CacheValue>;
    /// set a key in the cache
    fn set(&self, key: &str, value: CacheValue);
    /// delete a key from the cache
    fn del(&self, key: &str);
    /// flush all data
    fn flush_all(&self);
    fn close(&self) {}
    /// `PossiblyExtendedCacheStore` batch calls. The defaults do what upstream does without them.
    fn mget(&self, keys: &[String]) -> Vec<(String, Option<CacheValue>)> {
        keys.iter().map(|k| (k.clone(), self.get(k))).collect()
    }
    fn mset(&self, entries: Vec<(String, CacheValue)>) {
        for (k, v) in entries {
            self.set(&k, v);
        }
    }
    fn mdel(&self, keys: &[String]) {
        for k in keys {
            self.del(k);
        }
    }
}
pub type PossiblyExtendedCacheStore = dyn CacheStore;
pub fn cache_get<T: Any + Send + Sync>(store: &dyn CacheStore, key: &str) -> Option<Arc<T>> {
    store.get(key).and_then(|v| v.downcast::<T>().ok())
}
pub fn cache_set<T: Any + Send + Sync>(store: &dyn CacheStore, key: &str, value: T) {
    store.set(key, Arc::new(value));
}

/// One HTTP response, with the whole body. `utils::http` is the default transport.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub body: Vec<u8>,
}
impl HttpResponse {
    /// Same as `response.ok`.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}
pub trait HttpClient: Send + Sync {
    fn get(&self, url: &str, headers: &[(String, String)]) -> Result<HttpResponse>;
    /// POST of a file, as media upload does. The default uses `utils::http`.
    fn post_file(&self, url: &str, file_path: &str, headers: &[(String, String)], timeout_ms: Option<u64>) -> Result<HttpResponse> {
        crate::utils::http::post_file(url, file_path, headers, timeout_ms)
    }
}
/// `RequestInit` of `fetch`. Without a client, `utils::http` does the work.
#[derive(Clone, Default)]
pub struct RequestInit {
    pub headers: Vec<(String, String)>,
    pub client: Option<Arc<dyn HttpClient>>,
}
impl RequestInit {
    pub fn get(&self, url: &str, headers: &[(String, String)]) -> Result<HttpResponse> {
        let headers = if headers.is_empty() { &self.headers } else { headers };
        match &self.client {
            Some(c) => c.get(url, headers),
            None => crate::utils::http::get(url, headers),
        }
    }
}
/// `recipient_jid` is the extra field of `PatchedMessageWithRecipientJID`.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct PatchedMessageWithRecipientJID {
    pub message: Message,
    pub recipient_jid: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AppStateMacVerification {
    pub patch: bool,
    pub snapshot: bool,
}
pub type MakeTransport = Arc<dyn Fn(&SocketConfig) -> Result<Arc<dyn crate::socket::client::Transport>> + Send + Sync>;
pub type MakeSignalRepository = Arc<dyn Fn(SignalAuthState, Arc<dyn Logger>, Option<PnToLidFn>) -> Arc<dyn SignalRepository> + Send + Sync>;
#[derive(Clone)]
pub struct SocketConfig {
    /// the WS url to connect to WA
    pub wa_web_socket_url: String,
    /// Fails the connection if the socket times out in this interval
    pub connect_timeout_ms: u64,
    /// Default timeout for queries, `None` for no timeout
    pub default_query_timeout_ms: Option<u64>,
    /// ping-pong interval for WS connection
    pub keep_alive_interval_ms: u64,
    /// proxy agent, in the form that the transport wants
    pub agent: Option<Arc<dyn Any + Send + Sync>>,
    /// logger
    pub logger: Arc<dyn Logger>,
    /// version to connect with
    pub version: WAVersion,
    /// override browser config
    pub browser: WABrowserDescription,
    /// Initial pushName carried in the registration ClientPayload (used by mock servers for deterministic phone assignment).
    pub push_name: Option<String>,
    /// agent used for fetch requests -- uploading/downloading media
    pub fetch_agent: Option<Arc<dyn Any + Send + Sync>>,
    /// should events be emitted for actions done by this socket connection
    pub emit_own_events: bool,
    /// custom upload hosts to upload media to
    pub custom_upload_hosts: Vec<MediaConnHost>,
    /// time to wait between sending new retry requests
    pub retry_request_delay_ms: u64,
    /// max retry count
    pub max_msg_retry_count: u32,
    /// time to wait for the generation of the next QR in ms
    pub qr_timeout: Option<u64>,
    /// provide an auth state object to maintain the auth state
    pub auth: Option<AuthenticationState>,
    /// manage history processing with this control; by default will sync up everything
    pub should_sync_history_message: Arc<dyn Fn(&HistorySyncNotification) -> bool + Send + Sync>,
    /// transaction capability options for SignalKeyStore
    pub transaction_opts: TransactionCapabilityOptions,
    /// marks the client as online whenever the socket successfully connects
    pub mark_online_on_connect: bool,
    /// alphanumeric country code (USA -> US) for the number used
    pub country_code: String,
    /// provide a cache to store media, so does not have to be re-uploaded
    pub media_cache: Option<Arc<dyn CacheStore>>,
    /// map to store the retry counts for failed messages;
    /// used to determine whether to retry a message or not
    pub msg_retry_counter_cache: Option<Arc<dyn CacheStore>>,
    /// provide a cache to store a user's device list
    pub user_devices_cache: Option<Arc<dyn CacheStore>>,
    /// cache to store call offers
    pub call_offer_cache: Option<Arc<dyn CacheStore>>,
    /// cache to track placeholder resends
    pub placeholder_resend_cache: Option<Arc<dyn CacheStore>>,
    /// width for link preview images
    pub link_preview_image_thumbnail_width: u32,
    /// Should Baileys ask the phone for full history, will be received async
    pub sync_full_history: bool,
    /// Should baileys fire init queries automatically, default true
    pub fire_init_queries: bool,
    /// generate a high quality link preview, entails uploading the jpegThumbnail to WA
    pub generate_high_quality_link_preview: bool,
    /// Enable automatic session recreation for failed messages
    pub enable_auto_session_recreation: bool,
    /// Enable recent message caching for retry handling
    pub enable_recent_message_cache: bool,
    /// Returns if a jid should be ignored, no event for that jid will be triggered.
    /// Messages from that jid will also not be decrypted
    pub should_ignore_jid: Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>,
    /// Optionally patch the message before sending out
    pub patch_message_before_sending: Arc<dyn Fn(Message, Option<&[String]>) -> Vec<PatchedMessageWithRecipientJID> + Send + Sync>,
    /// verify app state MACs
    pub app_state_mac_verification: AppStateMacVerification,
    /// options for HTTP fetch requests
    pub options: RequestInit,
    /// fetch a message from your store
    /// implement this so that messages failed to send
    /// (solves the "this message can take a while" issue) can be retried
    pub get_message: Arc<dyn Fn(&WAMessageKey) -> Option<Message> + Send + Sync>,
    /// cached group metadata, use to prevent redundant requests to WA & speed up msg sending
    pub cached_group_metadata: Arc<dyn Fn(&str) -> Option<GroupMetadata> + Send + Sync>,
    pub make_signal_repository: MakeSignalRepository,
    /// The public key that must sign the server certificate. The default is the real WhatsApp key.
    /// A mock server sets its own test root here. Only the certificate check reads this value.
    pub wa_cert_public_key: [u8; 32],
    /// Makes the transport. The default (`None`) is the WebSocket client of `socket::client`.
    pub make_transport: Option<MakeTransport>,
}
