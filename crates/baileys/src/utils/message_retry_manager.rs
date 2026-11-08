//! Same as Utils/message-retry-manager.ts.
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::time::{Timeout, now_ms, set_timeout};
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use waproto::Message;
use waproto::pb::Json;

/// Number of sent messages to cache in memory for handling retry receipts
const RECENT_MESSAGES_SIZE: usize = 512;
const MESSAGE_KEY_SEPARATOR: char = '\0';
/// Timeout for session recreation - 1 hour
const RECREATE_SESSION_TIMEOUT: i64 = 60 * 60 * 1000;
const PHONE_REQUEST_DELAY: u64 = 3000;

#[derive(Clone, Debug, PartialEq)]
pub struct RecentMessage {
    pub message: Message,
    pub timestamp: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RetryStatistics {
    pub total_retries: u64,
    pub successful_retries: u64,
    pub failed_retries: u64,
    pub media_retries: u64,
    pub session_recreations: u64,
    pub phone_requests: u64,
}
/// Retry reason codes matching WhatsApp Web's Signal error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryReason {
    UnknownError = 0,
    SignalErrorNoSession = 1,
    SignalErrorInvalidKey = 2,
    SignalErrorInvalidKeyId = 3,
    /// MAC verification failed - most common cause of decryption failures
    SignalErrorInvalidMessage = 4,
    SignalErrorInvalidSignature = 5,
    SignalErrorFutureMessage = 6,
    /// Explicit MAC failure - session is definitely out of sync
    SignalErrorBadMac = 7,
    SignalErrorInvalidSession = 8,
    SignalErrorInvalidMsgKey = 9,
    BadBroadcastEphemeralSetting = 10,
    UnknownCompanionNoPrekey = 11,
    AdvFailure = 12,
    StatusRevokeDelay = 13,
}
impl RetryReason {
    /// Same as `RetryReason[code]`.
    pub fn name(self) -> &'static str {
        match self {
            RetryReason::UnknownError => "UnknownError",
            RetryReason::SignalErrorNoSession => "SignalErrorNoSession",
            RetryReason::SignalErrorInvalidKey => "SignalErrorInvalidKey",
            RetryReason::SignalErrorInvalidKeyId => "SignalErrorInvalidKeyId",
            RetryReason::SignalErrorInvalidMessage => "SignalErrorInvalidMessage",
            RetryReason::SignalErrorInvalidSignature => "SignalErrorInvalidSignature",
            RetryReason::SignalErrorFutureMessage => "SignalErrorFutureMessage",
            RetryReason::SignalErrorBadMac => "SignalErrorBadMac",
            RetryReason::SignalErrorInvalidSession => "SignalErrorInvalidSession",
            RetryReason::SignalErrorInvalidMsgKey => "SignalErrorInvalidMsgKey",
            RetryReason::BadBroadcastEphemeralSetting => "BadBroadcastEphemeralSetting",
            RetryReason::UnknownCompanionNoPrekey => "UnknownCompanionNoPrekey",
            RetryReason::AdvFailure => "AdvFailure",
            RetryReason::StatusRevokeDelay => "StatusRevokeDelay",
        }
    }
    fn from_code(code: i64) -> Option<RetryReason> {
        Some(match code {
            0 => RetryReason::UnknownError,
            1 => RetryReason::SignalErrorNoSession,
            2 => RetryReason::SignalErrorInvalidKey,
            3 => RetryReason::SignalErrorInvalidKeyId,
            4 => RetryReason::SignalErrorInvalidMessage,
            5 => RetryReason::SignalErrorInvalidSignature,
            6 => RetryReason::SignalErrorFutureMessage,
            7 => RetryReason::SignalErrorBadMac,
            8 => RetryReason::SignalErrorInvalidSession,
            9 => RetryReason::SignalErrorInvalidMsgKey,
            10 => RetryReason::BadBroadcastEphemeralSetting,
            11 => RetryReason::UnknownCompanionNoPrekey,
            12 => RetryReason::AdvFailure,
            13 => RetryReason::StatusRevokeDelay,
            _ => return None,
        })
    }
}
/// Error codes that indicate a MAC failure and require immediate session recreation
fn is_mac_code(r: RetryReason) -> bool {
    matches!(r, RetryReason::SignalErrorInvalidMessage | RetryReason::SignalErrorBadMac)
}

/// JavaScript `parseInt(s, 10)`, as saturated integers. `None` is `NaN`.
fn parse_int(s: &str) -> Option<i64> {
    let t = s.trim_start_matches(|c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}');
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let end = t.bytes().position(|c| !c.is_ascii_digit()).unwrap_or(t.len());
    if end == 0 {
        return None;
    }
    let n = t[..end].bytes().fold(0i64, |n, c| n.saturating_mul(10).saturating_add((c - b'0') as i64));
    Some(if neg { -n } else { n })
}

/// The clock of `lru-cache`, which does not move with changes to the wall clock.
fn mono_ms() -> i64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

struct Slot<V> {
    value: V,
    recency: u64,
    expiry: (i64, u64),
}
/// The part of `lru-cache` this file uses. `ttlAutopurge` removes an item when its time passes.
/// There are no timers here: each call first removes what `ttlAutopurge` would have removed, so
/// callers see the same state and `dispose` runs in the same order.
struct LruCache<V> {
    /// 0 means no limit.
    max: usize,
    ttl_ms: i64,
    update_age_on_get: bool,
    map: FxHashMap<Arc<str>, Slot<V>>,
    by_recency: BTreeMap<u64, Arc<str>>,
    by_expiry: BTreeMap<(i64, u64), Arc<str>>,
    seq: u64,
    /// The keys that `dispose` must see, when `track_disposed` is set.
    track_disposed: bool,
    disposed: Vec<Arc<str>>,
}
impl<V> LruCache<V> {
    fn new(max: usize, ttl_ms: i64, update_age_on_get: bool, track_disposed: bool) -> LruCache<V> {
        LruCache { max, ttl_ms, update_age_on_get, map: FxHashMap::default(), by_recency: BTreeMap::new(), by_expiry: BTreeMap::new(), seq: 0, track_disposed, disposed: Vec::new() }
    }
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
    /// An item is stale when its age is more than the TTL.
    fn purge(&mut self, now: i64) {
        while let Some((k, key)) = self.by_expiry.first_key_value() {
            if k.0 >= now {
                break;
            }
            let key = key.clone();
            self.delete_at(&key);
        }
    }
    fn delete_at(&mut self, key: &str) {
        if let Some((k, slot)) = self.map.remove_entry(key) {
            self.by_recency.remove(&slot.recency);
            self.by_expiry.remove(&slot.expiry);
            if self.track_disposed {
                self.disposed.push(k);
            }
        }
    }
    fn set(&mut self, key: &str, value: V, now: i64) {
        self.purge(now);
        self.delete_at(key);
        if self.max != 0 && self.map.len() >= self.max {
            if let Some((_, oldest)) = self.by_recency.first_key_value() {
                let oldest = oldest.clone();
                self.delete_at(&oldest);
            }
        }
        let key: Arc<str> = Arc::from(key);
        let recency = self.next_seq();
        let expiry = (now + self.ttl_ms, recency);
        self.by_recency.insert(recency, key.clone());
        self.by_expiry.insert(expiry, key.clone());
        self.map.insert(key, Slot { value, recency, expiry });
    }
    fn get(&mut self, key: &str, now: i64) -> Option<&V> {
        self.purge(now);
        let recency = self.next_seq();
        let ttl_ms = self.ttl_ms;
        let update_age = self.update_age_on_get;
        let (k, slot) = self.map.get_key_value(key).map(|(k, s)| (k.clone(), (s.recency, s.expiry)))?;
        self.by_recency.remove(&slot.0);
        self.by_recency.insert(recency, k.clone());
        let mut expiry = slot.1;
        if update_age {
            self.by_expiry.remove(&expiry);
            expiry = (now + ttl_ms, recency);
            self.by_expiry.insert(expiry, k);
        }
        let s = self.map.get_mut(key)?;
        s.recency = recency;
        s.expiry = expiry;
        Some(&s.value)
    }
    fn delete(&mut self, key: &str, now: i64) {
        self.purge(now);
        self.delete_at(key);
    }
    fn clear(&mut self) {
        self.map.clear();
        self.by_recency.clear();
        self.by_expiry.clear();
        self.disposed.clear();
    }
}

struct Inner {
    recent_messages_map: LruCache<Arc<RecentMessage>>,
    message_key_index: FxHashMap<String, String>,
    session_recreate_history: LruCache<i64>,
    retry_counters: LruCache<u64>,
    base_keys: LruCache<Vec<u8>>,
    /// The token tells a fired timer from a newer request for the same message.
    pending_phone_requests: FxHashMap<String, (u64, Timeout)>,
    next_token: u64,
    statistics: RetryStatistics,
}
impl Inner {
    /// The `dispose` option of `recentMessagesMap`. Like upstream, it deletes the index entry by
    /// message ID, even when that entry now points to the same ID for another recipient.
    fn run_dispose(&mut self) {
        for key in self.recent_messages_map.disposed.drain(..) {
            if let Some(i) = key.rfind(MESSAGE_KEY_SEPARATOR) {
                self.message_key_index.remove(&key[i + MESSAGE_KEY_SEPARATOR.len_utf8()..]);
            }
        }
    }
    fn cancel_pending_phone_request(&mut self, logger: &dyn Logger, message_id: &str) {
        if let Some((_, timeout)) = self.pending_phone_requests.remove(message_id) {
            timeout.cancel();
            if logger.is_enabled(LogLevel::Debug) {
                logger.debug(&format!("Cancelled pending phone request for message {message_id}"));
            }
        }
    }
    fn remove_recent_message(&mut self, message_id: &str) {
        let Some(key_str) = self.message_key_index.get(message_id).cloned() else {
            return;
        };
        self.recent_messages_map.delete(&key_str, mono_ms());
        self.run_dispose();
        self.message_key_index.remove(message_id);
    }
}

/// The result of `should_recreate_session`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecreateDecision {
    pub reason: String,
    pub recreate: bool,
}

/// All methods take `&self`, so the socket threads can share one manager.
pub struct MessageRetryManager {
    inner: Arc<Mutex<Inner>>,
    logger: Arc<dyn Logger>,
    max_msg_retry_count: u64,
}
impl MessageRetryManager {
    pub fn new(logger: Arc<dyn Logger>, max_msg_retry_count: u32) -> MessageRetryManager {
        const MINUTE: i64 = 60 * 1000;
        MessageRetryManager {
            inner: Arc::new(Mutex::new(Inner {
                recent_messages_map: LruCache::new(RECENT_MESSAGES_SIZE, 5 * MINUTE, false, true),
                message_key_index: FxHashMap::default(),
                session_recreate_history: LruCache::new(0, RECREATE_SESSION_TIMEOUT * 2, false, false),
                retry_counters: LruCache::new(0, 15 * MINUTE, true, false),
                base_keys: LruCache::new(1024, 15 * MINUTE, false, false),
                pending_phone_requests: FxHashMap::default(),
                next_token: 0,
                statistics: RetryStatistics::default(),
            })),
            logger,
            max_msg_retry_count: max_msg_retry_count as u64,
        }
    }
    /// Add a recent message to the cache for retry handling
    pub fn add_recent_message(&self, to: &str, id: &str, message: Message) {
        let key_str = key_to_string(to, id);
        let mut g = self.inner.lock().unwrap();
        g.recent_messages_map.set(&key_str, Arc::new(RecentMessage { message, timestamp: now_ms() }), mono_ms());
        g.run_dispose();
        g.message_key_index.insert(id.to_string(), key_str);
        drop(g);
        if self.logger.is_enabled(LogLevel::Debug) {
            self.logger.debug(&format!("Added message to retry cache: {to}/{id}"));
        }
    }
    /// Get a recent message from the cache
    pub fn get_recent_message(&self, to: &str, id: &str) -> Option<Arc<RecentMessage>> {
        let key_str = key_to_string(to, id);
        let mut g = self.inner.lock().unwrap();
        let r = g.recent_messages_map.get(&key_str, mono_ms()).cloned();
        g.run_dispose();
        r
    }
    /// Check if a session should be recreated based on retry count, history, and error code.
    /// MAC errors (codes 4 and 7) trigger immediate session recreation regardless of timeout.
    pub fn should_recreate_session(&self, jid: &str, has_session: bool, error_code: Option<RetryReason>) -> RecreateDecision {
        let mut g = self.inner.lock().unwrap();
        // If we don't have a session, always recreate
        if !has_session {
            g.session_recreate_history.set(jid, now_ms(), mono_ms());
            g.statistics.session_recreations += 1;
            return RecreateDecision { reason: "we don't have a Signal session with them".to_string(), recreate: true };
        }
        // IMMEDIATE recreation for MAC errors - session is definitely out of sync
        if let Some(code) = error_code.filter(|c| is_mac_code(*c)) {
            g.session_recreate_history.set(jid, now_ms(), mono_ms());
            g.statistics.session_recreations += 1;
            drop(g);
            if self.logger.is_enabled(LogLevel::Warn) {
                let obj = Json::Obj(vec![("jid".to_string(), Json::Str(jid.to_string())), ("errorCode".to_string(), Json::Str(code.name().to_string()))]);
                self.logger.warn_obj(&obj, "MAC error detected, forcing immediate session recreation");
            }
            return RecreateDecision { reason: format!("MAC error (code {}: {}), immediate session recreation", code as i32, code.name()), recreate: true };
        }
        let now = now_ms();
        let prev_time = g.session_recreate_history.get(jid, mono_ms()).copied();
        // If no previous recreation or it's been more than an hour
        if prev_time.is_none_or(|p| p == 0 || now - p > RECREATE_SESSION_TIMEOUT) {
            g.session_recreate_history.set(jid, now, mono_ms());
            g.statistics.session_recreations += 1;
            return RecreateDecision { reason: "retry count > 1 and over an hour since last recreation".to_string(), recreate: true };
        }
        RecreateDecision { reason: String::new(), recreate: false }
    }
    /// Parse error code from retry receipt's retry node.
    /// Returns `None` if no error code is present.
    pub fn parse_retry_error_code(&self, error_attr: Option<&str>) -> Option<RetryReason> {
        let code = parse_int(error_attr.filter(|e| !e.is_empty())?)?;
        // Validate it's a known RetryReason
        Some(RetryReason::from_code(code).unwrap_or(RetryReason::UnknownError))
    }
    /// Check if an error code indicates a MAC failure
    pub fn is_mac_error(&self, error_code: Option<RetryReason>) -> bool {
        error_code.is_some_and(is_mac_code)
    }
    /// Increment retry counter for a message
    pub fn increment_retry_count(&self, message_id: &str) -> u64 {
        let mut g = self.inner.lock().unwrap();
        let now = mono_ms();
        let n = g.retry_counters.get(message_id, now).copied().unwrap_or(0) + 1;
        g.retry_counters.set(message_id, n, now);
        g.statistics.total_retries += 1;
        n
    }
    /// Get retry count for a message
    pub fn get_retry_count(&self, message_id: &str) -> u64 {
        self.inner.lock().unwrap().retry_counters.get(message_id, mono_ms()).copied().unwrap_or(0)
    }
    /// Check if message has exceeded maximum retry attempts
    pub fn has_exceeded_max_retries(&self, message_id: &str) -> bool {
        self.get_retry_count(message_id) >= self.max_msg_retry_count
    }
    /// Mark retry as successful
    pub fn mark_retry_success(&self, message_id: &str) {
        let mut g = self.inner.lock().unwrap();
        g.statistics.successful_retries += 1;
        // Clean up retry counter for successful message
        g.retry_counters.delete(message_id, mono_ms());
        g.cancel_pending_phone_request(self.logger.as_ref(), message_id);
        g.remove_recent_message(message_id);
    }
    /// Mark retry as failed
    pub fn mark_retry_failed(&self, message_id: &str) {
        let mut g = self.inner.lock().unwrap();
        g.statistics.failed_retries += 1;
        g.retry_counters.delete(message_id, mono_ms());
        g.cancel_pending_phone_request(self.logger.as_ref(), message_id);
        g.remove_recent_message(message_id);
    }
    /// Schedule a phone request with delay. `delay_ms` is 3000 when `None`.
    pub fn schedule_phone_request(&self, message_id: &str, callback: impl FnOnce() + Send + 'static, delay_ms: Option<u64>) {
        let delay = delay_ms.unwrap_or(PHONE_REQUEST_DELAY);
        let mut g = self.inner.lock().unwrap();
        // Cancel any existing request for this message
        g.cancel_pending_phone_request(self.logger.as_ref(), message_id);

        g.next_token += 1;
        let token = g.next_token;
        let inner = self.inner.clone();
        let id = message_id.to_string();
        // The task takes the lock first, so it also sees a cancel that comes too late for the timer.
        let timeout = set_timeout(delay, move || {
            let mut g = inner.lock().unwrap();
            if g.pending_phone_requests.get(&id).is_some_and(|p| p.0 == token) {
                g.pending_phone_requests.remove(&id);
                g.statistics.phone_requests += 1;
                drop(g);
                callback();
            }
        });
        g.pending_phone_requests.insert(message_id.to_string(), (token, timeout));
        drop(g);
        if self.logger.is_enabled(LogLevel::Debug) {
            self.logger.debug(&format!("Scheduled phone request for message {message_id} with {delay}ms delay"));
        }
    }
    /// Cancel pending phone request
    pub fn cancel_pending_phone_request(&self, message_id: &str) {
        self.inner.lock().unwrap().cancel_pending_phone_request(self.logger.as_ref(), message_id);
    }
    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.recent_messages_map.clear();
        g.message_key_index.clear();
        g.session_recreate_history.clear();
        g.retry_counters.clear();
        g.base_keys.clear();
        let ids: Vec<String> = g.pending_phone_requests.keys().cloned().collect();
        for id in ids {
            g.cancel_pending_phone_request(self.logger.as_ref(), &id);
        }
        g.statistics = RetryStatistics::default();
    }
    pub fn save_base_key(&self, addr: &str, msg_id: &str, base_key: &[u8]) {
        self.inner.lock().unwrap().base_keys.set(&base_key_id(addr, msg_id), base_key.to_vec(), mono_ms());
    }
    pub fn has_same_base_key(&self, addr: &str, msg_id: &str, base_key: &[u8]) -> bool {
        self.inner.lock().unwrap().base_keys.get(&base_key_id(addr, msg_id), mono_ms()).is_some_and(|s| s.as_slice() == base_key)
    }
    pub fn delete_base_key(&self, addr: &str, msg_id: &str) {
        self.inner.lock().unwrap().base_keys.delete(&base_key_id(addr, msg_id), mono_ms());
    }
    /// A private field upstream. Rust callers have no other way to read it.
    pub fn statistics(&self) -> RetryStatistics {
        self.inner.lock().unwrap().statistics
    }
}
fn key_to_string(to: &str, id: &str) -> String {
    let mut s = String::with_capacity(to.len() + id.len() + 1);
    s.push_str(to);
    s.push(MESSAGE_KEY_SEPARATOR);
    s.push_str(id);
    s
}
fn base_key_id(addr: &str, msg_id: &str) -> String {
    format!("{addr}:{msg_id}")
}
