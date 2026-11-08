//! Same values as Defaults/index.ts.
use crate::signal::repository::LibSignalRepository;
use crate::types::*;
use crate::utils::browser_utils::Browsers;
use crate::utils::logger::default_logger;
use std::sync::Arc;
use waproto::history_sync::HistorySyncType;

pub const VERSION: WAVersion = [2, 3000, 1043857760];
pub const UNAUTHORIZED_CODES: [u16; 3] = [401, 403, 419];
pub const DEFAULT_ORIGIN: &str = "https://web.whatsapp.com";
pub const CALL_VIDEO_PREFIX: &str = "https://call.whatsapp.com/video/";
pub const CALL_AUDIO_PREFIX: &str = "https://call.whatsapp.com/voice/";
pub const DEF_CALLBACK_PREFIX: &str = "CB:";
pub const DEF_TAG_PREFIX: &str = "TAG:";
pub const PHONE_CONNECTION_CB: &str = "CB:Pong";
pub const WA_ADV_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 0];
pub const WA_ADV_DEVICE_SIG_PREFIX: [u8; 2] = [6, 1];
pub const WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 5];
pub const WA_ADV_HOSTED_DEVICE_SIG_PREFIX: [u8; 2] = [6, 6];
pub const WA_DEFAULT_EPHEMERAL: u32 = 7 * 24 * 60 * 60;
/// Status messages older than 24 hours are considered expired
pub const STATUS_EXPIRY_SECONDS: u32 = 24 * 60 * 60;
/// WA Web enforces a 14-day maximum age for placeholder resend requests
pub const PLACEHOLDER_MAX_AGE_SECONDS: u32 = 14 * 24 * 60 * 60;
pub const NOISE_MODE: &str = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0";
pub const DICT_VERSION: u8 = 3;
pub const KEY_BUNDLE_TYPE: [u8; 1] = [5];
pub const NOISE_WA_HEADER: [u8; 4] = [87, 65, 6, DICT_VERSION];

/// The first match at or after `from` of URL_REGEX:
/// `https:\/\/(?![^:@\/\s]+:[^:@\/\s]+@)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?(\/[^\s]*)?`.
/// Returns the start and end offsets.
pub fn find_url(text: &str, from: usize) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let mut at = from;
    while let Some(p) = text.get(at..)?.find("https://") {
        let start = at + p;
        let host = start + 8;
        at = host;
        if has_credentials(&b[host..]) {
            continue;
        }
        let run = b[host..].iter().position(|c| !(c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-')).map_or(b.len(), |n| host + n);
        // the host part is greedy, so try the last dot first
        let dot = (host + 1..run).rev().find(|d| b[*d] == b'.' && b[*d + 1..run].iter().take(2).filter(|c| c.is_ascii_alphabetic()).count() == 2);
        let Some(dot) = dot else { continue };
        let mut end = dot + 1 + b[dot + 1..run].iter().position(|c| !c.is_ascii_alphabetic()).unwrap_or(run - dot - 1);
        if b.get(end) == Some(&b':') {
            let digits = b[end + 1..].iter().position(|c| !c.is_ascii_digit()).unwrap_or(b.len() - end - 1);
            if digits > 0 {
                end += 1 + digits;
            }
        }
        if b.get(end) == Some(&b'/') {
            end += text[end..].find(char::is_whitespace).unwrap_or(text.len() - end);
        }
        return Some((start, end));
    }
    None
}
/// The negative lookahead: `user:password@` right after the scheme.
fn has_credentials(b: &[u8]) -> bool {
    let stop = |c: &u8| *c == b':' || *c == b'@' || *c == b'/' || c.is_ascii_whitespace();
    let user = b.iter().position(stop).unwrap_or(b.len());
    if user == 0 || b.get(user) != Some(&b':') {
        return false;
    }
    let rest = &b[user + 1..];
    let pass = rest.iter().position(stop).unwrap_or(rest.len());
    pass > 0 && rest.get(pass) == Some(&b'@')
}
pub mod wa_cert_details {
    pub const SERIAL: u32 = 0;
    pub const ISSUER: &str = "WhatsAppLongTerm1";
    pub const PUBLIC_KEY: [u8; 32] = [0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b];
}
pub const PROCESSABLE_HISTORY_TYPES: [HistorySyncType; 7] = [HistorySyncType::INITIAL_BOOTSTRAP, HistorySyncType::PUSH_NAME, HistorySyncType::RECENT, HistorySyncType::FULL, HistorySyncType::ON_DEMAND, HistorySyncType::NON_BLOCKING_DATA, HistorySyncType::INITIAL_STATUS_V3];
/// Times in seconds.
pub mod default_cache_ttls {
    pub const SIGNAL_STORE: u64 = 5 * 60;
    pub const MSG_RETRY: u64 = 60 * 60;
    pub const CALL_OFFER: u64 = 5 * 60;
    pub const USER_DEVICES: u64 = 5 * 60;
}
/// `DEFAULT_CONNECTION_CONFIG`. `auth` is `None` here and must be set before use.
pub fn default_connection_config() -> SocketConfig {
    SocketConfig {
        version: VERSION,
        browser: Browsers::mac_os("Chrome"),
        wa_web_socket_url: "wss://web.whatsapp.com/ws/chat".to_string(),
        connect_timeout_ms: 20_000,
        keep_alive_interval_ms: 30_000,
        logger: default_logger().child(&[("class", "baileys")]),
        emit_own_events: true,
        default_query_timeout_ms: Some(60_000),
        custom_upload_hosts: Vec::new(),
        retry_request_delay_ms: 250,
        max_msg_retry_count: 5,
        fire_init_queries: true,
        auth: None,
        mark_online_on_connect: true,
        sync_full_history: true,
        patch_message_before_sending: Arc::new(|message, _| vec![PatchedMessageWithRecipientJID { message, recipient_jid: None }]),
        should_sync_history_message: Arc::new(|n| n.sync_type().map(|t| t.0) != Some(HistorySyncType::FULL.0)),
        should_ignore_jid: Arc::new(|_| Some(false)),
        link_preview_image_thumbnail_width: 192,
        transaction_opts: TransactionCapabilityOptions { max_commit_retries: 10, delay_between_tries_ms: 3000 },
        generate_high_quality_link_preview: false,
        enable_auto_session_recreation: true,
        enable_recent_message_cache: true,
        options: RequestInit::default(),
        app_state_mac_verification: AppStateMacVerification { patch: false, snapshot: false },
        country_code: "US".to_string(),
        get_message: Arc::new(|_| None),
        cached_group_metadata: Arc::new(|_| None),
        make_signal_repository: Arc::new(|auth, _logger, pn_to_lid| Arc::new(LibSignalRepository::new(auth.creds, auth.keys, pn_to_lid))),
        wa_cert_public_key: wa_cert_details::PUBLIC_KEY,
        make_transport: None,
        agent: None,
        push_name: None,
        fetch_agent: None,
        qr_timeout: None,
        media_cache: None,
        msg_retry_counter_cache: None,
        user_devices_cache: None,
        call_offer_cache: None,
        placeholder_resend_cache: None,
    }
}
macro_rules! media_types {
    ($($v:ident = $s:literal, $info:literal, $path:expr;)*) => {
        /// `keyof typeof MEDIA_HKDF_KEY_MAPPING`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum MediaType { $($v),* }
        impl MediaType {
            pub fn as_str(self) -> &'static str {
                match self { $(MediaType::$v => $s),* }
            }
            pub fn parse(s: &str) -> Option<MediaType> {
                match s { $($s => Some(MediaType::$v),)* _ => None }
            }
            /// The value in MEDIA_HKDF_KEY_MAPPING.
            pub fn hkdf_key(self) -> &'static str {
                match self { $(MediaType::$v => $info),* }
            }
            /// The value in MEDIA_PATH_MAP.
            pub fn path(self) -> Option<&'static str> {
                match self { $(MediaType::$v => $path),* }
            }
        }
    };
}
media_types! {
    Audio = "audio", "Audio", Some("/mms/audio");
    Document = "document", "Document", Some("/mms/document");
    Gif = "gif", "Video", None;
    Image = "image", "Image", Some("/mms/image");
    Ppic = "ppic", "", None;
    Product = "product", "Image", None;
    Ptt = "ptt", "Audio", None;
    Sticker = "sticker", "Image", Some("/mms/image");
    Video = "video", "Video", Some("/mms/video");
    ThumbnailDocument = "thumbnail-document", "Document Thumbnail", None;
    ThumbnailImage = "thumbnail-image", "Image Thumbnail", None;
    ThumbnailVideo = "thumbnail-video", "Video Thumbnail", None;
    ThumbnailLink = "thumbnail-link", "Link Thumbnail", Some("/mms/image");
    MdMsgHist = "md-msg-hist", "History", Some("/mms/md-app-state");
    MdAppState = "md-app-state", "App State", Some("");
    ProductCatalogImage = "product-catalog-image", "", Some("/product/image");
    PaymentBgImage = "payment-bg-image", "Payment Background", None;
    Ptv = "ptv", "Video", None;
    BizCoverPhoto = "biz-cover-photo", "Image", Some("/pps/biz-cover-photo");
}
/// `Object.keys(MEDIA_PATH_MAP)`.
pub const MEDIA_KEYS: [MediaType; 10] = [MediaType::Image, MediaType::Video, MediaType::Document, MediaType::Audio, MediaType::Sticker, MediaType::ThumbnailLink, MediaType::ProductCatalogImage, MediaType::MdAppState, MediaType::MdMsgHist, MediaType::BizCoverPhoto];
/// 120s timeout for history sync stall detection, same as WA Web's handleChunkProgress / restartPausedTimer (g = 120)
pub const HISTORY_SYNC_PAUSED_TIMEOUT_MS: u64 = 120_000;
pub const MIN_PREKEY_COUNT: u32 = 5;
pub const INITIAL_PREKEY_COUNT: u32 = 812;
pub const UPLOAD_TIMEOUT: u64 = 30000;
pub mod time_ms {
    pub const MINUTE: u64 = 60 * 1000;
    pub const HOUR: u64 = 60 * 60 * 1000;
    pub const DAY: u64 = 24 * 60 * 60 * 1000;
    pub const WEEK: u64 = 7 * 24 * 60 * 60 * 1000;
}
