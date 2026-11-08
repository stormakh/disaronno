//! Same as Socket/socket.ts: connects to WA servers and performs
//! - simple queries (no retry mechanism, wait for connection establishment)
//! - listen to messages and emit events
//! - query phone connection
use super::chats::ChatsState;
use super::client::{Transport, make_web_socket_client};
use super::messages_recv::RecvState;
use super::messages_send::SendState;
use super::mex::execute_wmex_query;
use crate::auth::*;
use crate::crypto::{self, KeyPair};
use crate::defaults::*;
use crate::error::{Boom, Result};
use crate::events::*;
use crate::types::*;
use crate::utils::auth_utils::add_transaction_capability;
use crate::utils::companion_reg_client_utils::{build_pairing_qr_data, get_companion_platform_id};
use crate::utils::event_buffer::{EventBuffer, make_event_buffer};
use crate::utils::generics::{bind_wait_for_connection_update, bytes_to_crockford, generate_md_tag_prefix, get_code_from_ws_error, get_error_code_from_stream_error, Resolver};
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::noise::{Frame, NoiseHandler};
use crate::utils::signal::{get_next_pre_keys_stanza, xmpp_signed_pre_key};
use crate::utils::time::{THREAD_STACK, Timeout, now_ms, set_timeout};
use crate::utils::validate_connection::{configure_successful_pairing, generate_login_node, generate_registration_node, node_to_json};
use crate::wabinary::*;
use crate::wam::BinaryInfo;
use crate::wausync::{USyncQuery, USyncQueryResult, USyncUser};
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::ops::Deref;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::ThreadId;
use std::time::{Duration, Instant};
use waproto::HandshakeMessage;
use waproto::handshake_message::{ClientFinish, ClientHello};
use waproto::pb::{Json, PbMessage, base64_encode};

const WS_CONNECTING: u8 = 0;
const WS_OPEN: u8 = 1;
const WS_CLOSING: u8 = 2;
const WS_CLOSED: u8 = 3;
/// How long `end` waits for the threads of the socket and for a running listener.
const END_WAIT_MS: u64 = 5000;
const LANE_IDLE_MS: u64 = 5000;

pub type WsListener = Arc<dyn Fn(&BinaryNode) + Send + Sync>;
pub type SocketEndHandler = Arc<dyn Fn(Option<&Boom>) + Send + Sync>;
/// A function that handles one frame on a lane.
type LaneHandler = fn(&Socket, &BinaryNode);

/// The `ws` field of upstream: the state of the connection, and listeners for raw stanza events
/// such as `CB:iq,,pair-success`. Built-in handlers are direct calls, so a socket without custom
/// listeners builds none of these event names.
pub struct WsClient {
    transport: Arc<dyn Transport>,
    state: AtomicU8,
    next_listener: AtomicU64,
    has_listeners: AtomicBool,
    listeners: Mutex<Vec<(u64, String, WsListener)>>,
}
impl WsClient {
    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == WS_OPEN
    }
    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) == WS_CLOSED
    }
    pub fn is_closing(&self) -> bool {
        self.state.load(Ordering::Acquire) == WS_CLOSING
    }
    pub fn is_connecting(&self) -> bool {
        self.state.load(Ordering::Acquire) == WS_CONNECTING
    }
    /// Listens for a stanza event: `frame`, `TAG:<id>`, or a `CB:` name as in upstream.
    /// The listener runs on a lane, in frame order.
    pub fn on(&self, event: &str, listener: WsListener) -> u64 {
        let id = self.next_listener.fetch_add(1, Ordering::Relaxed) + 1;
        self.listeners.lock().unwrap().push((id, event.to_string(), listener));
        self.has_listeners.store(true, Ordering::Release);
        id
    }
    pub fn off(&self, id: u64) {
        let mut l = self.listeners.lock().unwrap();
        l.retain(|(i, _, _)| *i != id);
        self.has_listeners.store(!l.is_empty(), Ordering::Release);
    }
    pub fn remove_all_listeners(&self, event: &str) {
        let mut l = self.listeners.lock().unwrap();
        l.retain(|(_, e, _)| e != event);
        self.has_listeners.store(!l.is_empty(), Ordering::Release);
    }
    fn emit(&self, event: &str, frame: &BinaryNode) -> bool {
        let found: Vec<WsListener> = self.listeners.lock().unwrap().iter().filter(|(_, e, _)| e == event).map(|(_, _, f)| f.clone()).collect();
        for f in &found {
            f(frame);
        }
        !found.is_empty()
    }
    fn set_state(&self, s: u8) {
        self.state.store(s, Ordering::Release);
    }
}
enum Job {
    Frame(LaneHandler, BinaryNode),
    Task(Box<dyn FnOnce(Socket) + Send>),
}
#[derive(Default)]
struct LaneState {
    jobs: VecDeque<Job>,
    /// A thread runs this lane now.
    running: bool,
}
/// A lane has a thread only while it has work, and for `LANE_IDLE_MS` after that.
#[derive(Default)]
struct Lane {
    state: Mutex<LaneState>,
    wake: Condvar,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaneId {
    /// Message stanzas, and the upsert of the messages this client sends.
    Message,
    /// Everything else: receipts, notifications, calls, `ib`, and the fire-and-forget work.
    Control,
}
struct Waiter {
    id: u64,
    result: Resolver<BinaryNode>,
}
#[derive(Default)]
struct ThreadTrack {
    /// Started and not yet ended. It goes up before the spawn, so `end` cannot miss a new thread.
    live: usize,
    ids: Vec<ThreadId>,
}
/// One entry of the result of `on_whats_app`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnWhatsAppResult {
    pub jid: String,
    pub exists: bool,
}
struct PairRefs {
    refs: Mutex<VecDeque<String>>,
    noise_key_b64: String,
    identity_key_b64: String,
    adv_b64: String,
}
pub struct SocketInner {
    me: WeakSocket,
    pub config: SocketConfig,
    pub logger: Arc<dyn Logger>,
    pub ev: EventBuffer,
    pub ws: WsClient,
    pub creds: SharedCreds,
    /// The key store with the transaction capability, as `sock.authState.keys`.
    pub keys: Arc<dyn SignalKeyStore>,
    /// `authState.keys` of the config, without the transaction layer.
    raw_keys: Arc<dyn SignalKeyStore>,
    pub signal_repository: Arc<dyn SignalRepository>,
    /// telemetry buffer, as `sock.wamBuffer`
    pub wam_buffer: Mutex<BinaryInfo>,

    ephemeral_key_pair: KeyPair,
    noise: Mutex<NoiseHandler>,
    /// Held while a frame is encoded and written, so frames reach the wire in counter order.
    write_lock: Mutex<()>,
    waiters: Mutex<FxHashMap<String, Vec<Waiter>>>,
    next_waiter: AtomicU64,
    uq_tag_id: String,
    epoch: AtomicU64,
    server_time_offset_ms: AtomicI64,
    last_date_recv: AtomicI64,
    closed: AtomicBool,
    started: AtomicBool,
    handshake_done: AtomicBool,
    did_start_buffer: AtomicBool,
    stop_lock: Mutex<()>,
    stop_wake: Condvar,
    qr_timer: Mutex<Option<Timeout>>,
    handshake_timer: Mutex<Option<Timeout>>,
    keep_alive_timer: Mutex<Option<Timeout>>,
    /// The upload in flight. A second caller waits for this one, as `uploadPreKeysPromise` does.
    upload_pre_keys_in_flight: Mutex<Option<Resolver<()>>>,
    socket_end_handlers: Mutex<Vec<SocketEndHandler>>,
    threads: Mutex<ThreadTrack>,
    threads_done: Condvar,
    lane_message: Lane,
    lane_control: Lane,

    pub(crate) chats: ChatsState,
    pub(crate) send: SendState,
    pub(crate) recv: RecvState,
}
/// The socket. Clones share one connection. Call `end` to stop it: its threads hold it until then.
#[derive(Clone)]
pub struct Socket(pub Arc<SocketInner>);
impl Deref for Socket {
    type Target = SocketInner;
    fn deref(&self) -> &SocketInner {
        &self.0
    }
}
/// A handle that a stored closure can hold without keeping the socket alive.
pub(crate) type WeakSocket = Weak<SocketInner>;
pub(crate) fn upgrade(w: &WeakSocket) -> Option<Socket> {
    w.upgrade().map(Socket)
}
pub(crate) fn jstr(s: &str) -> Json {
    Json::Str(s.to_string())
}
pub(crate) fn connection_closed() -> Boom {
    Boom::status("Connection Closed", DisconnectReason::CONNECTION_CLOSED.0)
}
/// `+value` of an attribute.
pub(crate) fn attr_num(a: Option<&str>) -> f64 {
    match a {
        None => f64::NAN,
        Some(v) => {
            let t = v.trim();
            if t.is_empty() { 0.0 } else { t.parse::<f64>().unwrap_or(f64::NAN) }
        }
    }
}
/// The bytes or text of a node as a string, as `content.toString()`.
pub(crate) fn content_string(n: Option<&BinaryNode>) -> Option<String> {
    crate::wausync::protocols::content_text(n?.content.as_ref())
}
/// `makeSocket` and the layers above it. See `make_wa_socket`.
pub fn make_socket(config: SocketConfig) -> Result<Socket> {
    let logger = config.logger.clone();
    let auth = config.auth.clone().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'creds')"))?;
    if config.browser[1].to_lowercase().contains("android") {
        logger.warn("Using the Android browser is experimental and may lead to unexpected behavior. Use at your own risk.");
    }
    let sync_disabled = PROCESSABLE_HISTORY_TYPES.iter().all(|t| !(config.should_sync_history_message)(&waproto::message::HistorySyncNotification::default().with_sync_type(waproto::message::HistorySyncType(t.0))));
    if sync_disabled {
        logger.warn("DANGER: DISABLING ALL SYNC BY shouldSyncHistoryMsg PREVENTS BAILEYS FROM ACCESSING INITIAL LID MAPPINGS, LEADING TO INSTABILIY AND SESSION ERRORS");
    }
    if config.wa_web_socket_url.starts_with("tcp://") {
        return Err(Boom::status("Mobile API is not supported anymore", DisconnectReason::LOGGED_OUT.0));
    }
    // Upstream compares `url.protocol` with `wss`, but the value is `wss:`, so it never adds the
    // `ED` parameter with the routing info. The Noise intro header carries the routing info. Same here.

    // ephemeral key pair used to encrypt/decrypt communication. Unique for each connection
    let ephemeral_key_pair = crypto::generate_key_pair();
    let routing_info = auth.creds.lock().unwrap().routing_info.clone();
    let mut noise = NoiseHandler::with_logger(&ephemeral_key_pair, &NOISE_WA_HEADER, routing_info.as_ref().map(|r| r.as_slice()), Some(logger.clone()));
    noise.set_root_public_key(config.wa_cert_public_key);
    let transport = match &config.make_transport {
        Some(f) => f(&config)?,
        None => make_web_socket_client(&config)?,
    };
    let ev = make_event_buffer(logger.clone());
    // add transaction capability
    let keys: Arc<dyn SignalKeyStore> = add_transaction_capability(auth.keys.clone(), logger.clone(), config.transaction_opts);
    let signal_creds = SignalCreds::from_auth(&auth.creds.lock().unwrap());
    let inner = Arc::new_cyclic(|weak: &WeakSocket| {
        let pn_weak = weak.clone();
        let pn_to_lid: crate::signal::lid_mapping::PnToLidFn = Arc::new(move |jids: &[String]| match upgrade(&pn_weak) {
            Some(s) => s.pn_from_lid_usync(jids),
            None => Ok(None),
        });
        let signal_repository = (config.make_signal_repository)(SignalAuthState { creds: signal_creds.clone(), keys: keys.clone() }, logger.clone(), Some(pn_to_lid));
        SocketInner {
            me: weak.clone(),
            logger: logger.clone(),
            ev: ev.clone(),
            ws: WsClient { transport: transport.clone(), state: AtomicU8::new(WS_CONNECTING), next_listener: AtomicU64::new(0), has_listeners: AtomicBool::new(false), listeners: Mutex::new(Vec::new()) },
            creds: auth.creds.clone(),
            keys: keys.clone(),
            raw_keys: auth.keys.clone(),
            signal_repository,
            wam_buffer: Mutex::new(BinaryInfo::new()),
            ephemeral_key_pair: ephemeral_key_pair.clone(),
            noise: Mutex::new(noise),
            write_lock: Mutex::new(()),
            waiters: Mutex::new(FxHashMap::default()),
            next_waiter: AtomicU64::new(0),
            uq_tag_id: generate_md_tag_prefix(),
            epoch: AtomicU64::new(1),
            server_time_offset_ms: AtomicI64::new(0),
            last_date_recv: AtomicI64::new(0),
            closed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            handshake_done: AtomicBool::new(false),
            did_start_buffer: AtomicBool::new(false),
            stop_lock: Mutex::new(()),
            stop_wake: Condvar::new(),
            qr_timer: Mutex::new(None),
            handshake_timer: Mutex::new(None),
            keep_alive_timer: Mutex::new(None),
            upload_pre_keys_in_flight: Mutex::new(None),
            socket_end_handlers: Mutex::new(Vec::new()),
            threads: Mutex::new(ThreadTrack::default()),
            threads_done: Condvar::new(),
            lane_message: Lane::default(),
            lane_control: Lane::default(),
            chats: ChatsState::new(&config),
            send: SendState::new(&config, weak.clone()),
            recv: RecvState::new(&config, weak.clone()),
            config: config.clone(),
        }
    });
    let sock = Socket(inner);
    sock.register_core_listeners();
    sock.register_chats_listeners();
    sock.register_send_listeners();
    sock.register_recv_listeners();
    Ok(sock)
}
impl SocketInner {
    pub(crate) fn self_weak(&self) -> WeakSocket {
        self.me.clone()
    }
    pub fn generate_message_tag(&self) -> String {
        let n = self.epoch.fetch_add(1, Ordering::Relaxed);
        let mut s = String::with_capacity(self.uq_tag_id.len() + 8);
        s.push_str(&self.uq_tag_id);
        s.push_str(&n.to_string());
        s
    }
    /// `sock.type`.
    pub fn r#type(&self) -> &'static str {
        "md"
    }
    /// `sock.user`.
    pub fn user(&self) -> Option<Contact> {
        self.creds.lock().unwrap().me.clone()
    }
    pub(crate) fn me_id(&self) -> Option<String> {
        self.creds.lock().unwrap().me.as_ref().map(|m| m.id.clone())
    }
    pub(crate) fn me_lid(&self) -> Option<String> {
        self.creds.lock().unwrap().me.as_ref().and_then(|m| m.lid.clone())
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    /// Upstream emits the whole creds object in some places. With threads, a copy of all fields could
    /// undo the update of another thread, so only the changed fields go out. `me` goes with them,
    /// so that the listener does not see a change of the name.
    pub(crate) fn emit_creds_fields(&self, mut update: CredsUpdate) {
        update.me = Some(self.creds.lock().unwrap().me.clone());
        self.ev.emit(BaileysEvent::CredsUpdate(Box::new(update)));
    }
    /// `keys.transaction`, with the value of `work` as the result.
    pub(crate) fn transaction<T>(&self, key: &str, mut work: impl FnMut() -> Result<T>) -> Result<T> {
        let mut out = None;
        self.keys.transaction(
            &mut || {
                out = Some(work()?);
                Ok(())
            },
            key,
        )?;
        out.ok_or_else(|| Boom::new("transaction did not run"))
    }
    /// send a raw buffer
    pub fn send_raw_message(&self, data: &[u8]) -> Result<()> {
        if !self.ws.is_open() {
            return Err(connection_closed());
        }
        let _order = self.write_lock.lock().unwrap();
        let bytes = self.noise.lock().unwrap().encode_frame(data)?;
        self.ws.transport.send(&bytes)
    }
    /// send a binary node
    pub fn send_node(&self, frame: &BinaryNode) -> Result<()> {
        if self.logger.is_enabled(LogLevel::Trace) {
            self.logger.trace_obj(&Json::Obj(vec![("xml".to_string(), Json::Str(binary_node_to_string(frame, 0)))]), "xml send");
        }
        let buff = encode_binary_node(frame)?;
        self.send_raw_message(&buff)
    }
    fn add_waiter(&self, msg_id: &str) -> (u64, Resolver<BinaryNode>) {
        let id = self.next_waiter.fetch_add(1, Ordering::Relaxed);
        let result = Resolver::new();
        let mut w = self.waiters.lock().unwrap();
        // inside the lock, so that `end` cannot miss this waiter
        if self.is_closed() {
            result.reject(connection_closed());
        } else {
            w.entry(msg_id.to_string()).or_default().push(Waiter { id, result: result.clone() });
        }
        (id, result)
    }
    fn remove_waiter(&self, msg_id: &str, id: u64) {
        let mut w = self.waiters.lock().unwrap();
        if let Some(list) = w.get_mut(msg_id) {
            list.retain(|x| x.id != id);
            if list.is_empty() {
                w.remove(msg_id);
            }
        }
    }
    /// Wait for a message with a certain tag to be received.
    /// `timeout_ms` is the default query timeout when `None`. A timeout gives `Ok(None)`.
    pub fn wait_for_message(&self, msg_id: &str, timeout_ms: Option<u64>) -> Result<Option<BinaryNode>> {
        let (id, result) = self.add_waiter(msg_id);
        let timeout = timeout_ms.or(self.config.default_query_timeout_ms).filter(|t| *t > 0);
        let r = result.wait(timeout);
        self.remove_waiter(msg_id, id);
        match r {
            Some(Ok(n)) => Ok(Some(n)),
            Some(Err(e)) => Err(e),
            None => {
                self.logger.warn("timed out waiting for message");
                Ok(None)
            }
        }
    }
    /// send a query, and wait for its response. auto-generates message ID if not provided
    ///
    /// Same timeout rules as upstream: with an explicit `timeout_ms` a timeout is the error `Timed Out`
    /// (408). With `None`, the default query timeout gives `Ok(None)`, as `undefined` upstream.
    pub fn query(&self, mut node: BinaryNode, timeout_ms: Option<u64>) -> Result<Option<BinaryNode>> {
        if node.attr("id").is_none_or(str::is_empty) {
            node.attrs.set("id", self.generate_message_tag());
        }
        let msg_id = node.attr("id").unwrap_or_default().to_string();
        if self.logger.is_enabled(LogLevel::Trace) {
            self.logger.trace_obj(&Json::Obj(vec![("xml".to_string(), Json::Str(binary_node_to_string(&node, 0)))]), "xml send");
        }
        // the tree does not stay in memory during the wait for the reply
        let stanza = encode_binary_node(&node)?;
        drop(node);
        self.query_encoded(&msg_id, stanza, timeout_ms)
    }
    /// `query` for a stanza that is encoded already, with `msg_id` as its id.
    fn query_encoded(&self, msg_id: &str, stanza: Vec<u8>, timeout_ms: Option<u64>) -> Result<Option<BinaryNode>> {
        let (id, result) = self.add_waiter(msg_id);
        let sent = self.send_raw_message(&stanza);
        drop(stanza);
        if let Err(e) = sent {
            self.remove_waiter(msg_id, id);
            return Err(e);
        }
        let explicit = timeout_ms.filter(|t| *t > 0);
        let timeout = explicit.or(self.config.default_query_timeout_ms.filter(|t| *t > 0));
        let r = result.wait(timeout);
        self.remove_waiter(msg_id, id);
        match r {
            Some(Ok(n)) => {
                assert_node_error_free(&n)?;
                Ok(Some(n))
            }
            Some(Err(e)) => Err(e),
            None if explicit.is_some() => Err(Boom::status("Timed Out", DisconnectReason::TIMED_OUT.0)),
            None => {
                self.logger.warn("timed out waiting for message");
                Ok(None)
            }
        }
    }
    /// Validate current key-bundle on server; on failure, trigger pre-key upload and rethrow
    pub fn digest_key_bundle(&self) -> Result<()> {
        let res = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "get"), ("xmlns", "encrypt")]), vec![BinaryNode::tag("digest", Attrs::new())]), None)?;
        if get_binary_node_child(res.as_ref(), "digest").is_none() {
            upgrade(&self.me).ok_or_else(connection_closed)?.upload_pre_keys(None)?;
            return Err(Boom::new("encrypt/get digest returned no digest node"));
        }
        Ok(())
    }
    /// Rotate our signed pre-key on server; on failure, run digest as fallback and rethrow
    pub fn rotate_signed_pre_key(&self) -> Result<()> {
        let (identity, key_id) = {
            let c = self.creds.lock().unwrap();
            (c.signed_identity_key.clone(), c.signed_pre_key.key_id)
        };
        let skey = crypto::signed_key_pair(&identity, key_id + 1);
        let rotate = BinaryNode::with_nodes("rotate", Attrs::new(), vec![xmpp_signed_pre_key(&skey)]);
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "encrypt")]), vec![rotate]), None)?;
        // Persist new signed pre-key in creds
        self.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { signed_pre_key: Some(skey), ..CredsUpdate::default() })));
        Ok(())
    }
    pub fn execute_usync_query(&self, usync_query: &USyncQuery) -> Result<Option<USyncQueryResult>> {
        if usync_query.protocols.is_empty() {
            return Err(Boom::new("USyncQuery must have at least one protocol"));
        }
        // todo: validate users, throw WARNING on no valid users
        // variable below has only validated users
        let user_nodes = usync_query
            .users
            .iter()
            .map(|user| {
                let mut attrs = Attrs::new();
                if user.phone.as_deref().is_none_or(str::is_empty) {
                    if let Some(id) = &user.id {
                        attrs.set("jid", id.as_str());
                    }
                }
                BinaryNode::with_nodes("user", attrs, usync_query.protocols.iter().filter_map(|p| p.get_user_element(user)).collect())
            })
            .collect();
        let list_node = BinaryNode::with_nodes("list", Attrs::new(), user_nodes);
        let query_node = BinaryNode::with_nodes("query", Attrs::new(), usync_query.protocols.iter().map(|p| p.get_query_element()).collect());
        let mut usync_attrs = Attrs::from([("context", usync_query.context.as_str()), ("mode", usync_query.mode.as_str())]);
        usync_attrs.set("sid", self.generate_message_tag());
        usync_attrs.set("last", "true");
        usync_attrs.set("index", "0");
        let iq = BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "get"), ("xmlns", "usync")]), vec![BinaryNode::with_nodes("usync", usync_attrs, vec![query_node, list_node])]);
        let result = self.query(iq, None)?;
        usync_query.parse_usync_query_result(result.as_ref())
    }
    pub fn on_whats_app(&self, phone_number: &[String]) -> Result<Option<Vec<OnWhatsAppResult>>> {
        let mut usync_query = USyncQuery::new();
        let mut contact_enabled = false;
        for jid in phone_number {
            if is_lid_user(jid) {
                self.logger.warn("LIDs are not supported with onWhatsApp");
                continue;
            }
            if !contact_enabled {
                contact_enabled = true;
                usync_query = usync_query.with_contact_protocol();
            }
            let cleaned = jid.replacen('+', "", 1);
            let digits = cleaned.split('@').next().unwrap_or("").split(':').next().unwrap_or("");
            let mut phone = String::with_capacity(digits.len() + 1);
            phone.push('+');
            phone.push_str(digits);
            usync_query.add_user(USyncUser::new().with_phone(phone));
        }
        if usync_query.users.is_empty() {
            return Ok(Some(Vec::new())); // return early without forcing an empty query
        }
        Ok(self.execute_usync_query(&usync_query)?.map(|results| results.list.iter().filter(|a| a.contact()).map(|a| OnWhatsAppResult { jid: a.id.clone(), exists: a.contact() }).collect()))
    }
    pub(crate) fn pn_from_lid_usync(&self, jids: &[String]) -> Result<Option<Vec<LidMapping>>> {
        let mut usync_query = USyncQuery::new().with_lid_protocol().with_context("background");
        for jid in jids {
            if is_lid_user(jid) {
                self.logger.warn("LID user found in LID fetch call");
                continue;
            }
            usync_query.add_user(USyncUser::new().with_id(jid.as_str()));
        }
        if usync_query.users.is_empty() {
            return Ok(Some(Vec::new())); // return early without forcing an empty query
        }
        let results = self.execute_usync_query(&usync_query)?;
        Ok(Some(results.map_or_else(Vec::new, |r| r.list.iter().filter_map(|a| a.lid().map(|lid| LidMapping { pn: a.id.clone(), lid: lid.as_str().to_string() })).collect())))
    }
    /// log & process any unexpected errors
    pub fn on_unexpected_error(&self, err: &Boom, msg: &str) {
        self.logger.error(&format!("unexpected error in '{msg}': {err}"));
    }
    fn get_available_pre_keys_on_server(&self) -> Result<f64> {
        let mut attrs = Attrs::new();
        attrs.set("id", self.generate_message_tag());
        attrs.set("xmlns", "encrypt");
        attrs.set("type", "get");
        attrs.set("to", S_WHATSAPP_NET);
        let result = self.query(BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::tag("count", Attrs::new())]), None)?;
        let count_child = get_binary_node_child(result.as_ref(), "count").ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'attrs')"))?;
        Ok(attr_num(count_child.attr("value")))
    }
    fn upload_logic(&self, count: u32, retry_count: u32) -> Result<()> {
        self.logger.info("uploading pre-keys");
        // Generate and save pre-keys atomically (prevents ID collisions on retry)
        let tx_key = self.me_id().unwrap_or_else(|| "upload-pre-keys".to_string());
        let msg_id = self.generate_message_tag();
        let stanza = self.transaction(&tx_key, || {
            let state = AuthenticationState { creds: self.creds.clone(), keys: self.keys.clone() };
            let (update, stanza) = get_next_pre_keys_stanza(&state, count, &msg_id)?;
            // Update credentials immediately to prevent duplicate IDs on retry
            self.ev.emit(BaileysEvent::CredsUpdate(Box::new(update)));
            Ok(stanza)
        })?;
        // Upload to server (outside transaction, can fail without affecting local keys)
        match self.query_encoded(&msg_id, stanza, None) {
            Ok(_) => {
                self.logger.info("uploaded pre-keys successfully");
                Ok(())
            }
            Err(upload_error) => {
                self.logger.error(&format!("Failed to upload pre-keys to server: {upload_error}"));
                if retry_count < 3 && !self.is_closed() {
                    let backoff_delay = (1000u64 << retry_count).min(10000);
                    self.sleep_until_closed(backoff_delay);
                    return self.upload_logic(count, retry_count + 1);
                }
                Err(upload_error)
            }
        }
    }
    pub fn verify_current_pre_key_exists(&self) -> Result<(bool, u32)> {
        let next = self.creds.lock().unwrap().next_pre_key_id;
        let current_pre_key_id = next.saturating_sub(1);
        if current_pre_key_id == 0 {
            return Ok((false, 0));
        }
        let exists = self.keys.get_one(KeyKind::PreKey, &current_pre_key_id.to_string())?.is_some();
        Ok((exists, current_pre_key_id))
    }
    /// Waits for `ms`, and stops early when the socket ends.
    pub(crate) fn sleep_until_closed(&self, ms: u64) {
        let end = Instant::now() + Duration::from_millis(ms);
        let mut g = self.stop_lock.lock().unwrap();
        while !self.is_closed() {
            let now = Instant::now();
            if now >= end {
                return;
            }
            g = self.stop_wake.wait_timeout(g, end - now).unwrap().0;
        }
    }
    pub(crate) fn is_socket_thread(&self) -> bool {
        let me = std::thread::current().id();
        self.threads.lock().unwrap().ids.contains(&me)
    }
    fn wait_for_threads(&self) {
        if self.is_socket_thread() {
            return;
        }
        let end = Instant::now() + Duration::from_millis(END_WAIT_MS);
        let mut t = self.threads.lock().unwrap();
        while t.live > 0 {
            let now = Instant::now();
            if now >= end {
                self.logger.warn("threads of the socket did not stop in time");
                return;
            }
            t = self.threads_done.wait_timeout(t, end - now).unwrap().0;
        }
    }
    fn lane(&self, id: LaneId) -> &Lane {
        match id {
            LaneId::Message => &self.lane_message,
            LaneId::Control => &self.lane_control,
        }
    }
    fn push_job(&self, id: LaneId, job: Job) {
        let lane = self.lane(id);
        let mut st = lane.state.lock().unwrap();
        st.jobs.push_back(job);
        if st.running {
            lane.wake.notify_one();
            return;
        }
        let Some(sock) = upgrade(&self.me) else { return };
        st.running = true;
        drop(st);
        let name = if id == LaneId::Message { "wa-messages" } else { "wa-control" };
        sock.spawn_thread(name, move |s| s.run_lane(id));
    }
    fn stop_lanes(&self) {
        for id in [LaneId::Message, LaneId::Control] {
            let lane = self.lane(id);
            lane.state.lock().unwrap().jobs = VecDeque::new();
            lane.wake.notify_all();
        }
    }
    pub fn update_server_time_offset(&self, node: &BinaryNode) {
        let Some(t_value) = node.attr("t").filter(|v| !v.is_empty()) else { return };
        let parsed = attr_num(Some(t_value));
        if parsed.is_nan() || parsed <= 0.0 {
            return;
        }
        self.server_time_offset_ms.store(parsed as i64 * 1000 - now_ms(), Ordering::Relaxed);
    }
    fn get_unified_session_id(&self) -> String {
        let offset_ms = 3 * time_ms::DAY as i64;
        let now = now_ms() + self.server_time_offset_ms.load(Ordering::Relaxed);
        ((now + offset_ms) % time_ms::WEEK as i64).to_string()
    }
    pub fn send_unified_session(&self) {
        if !self.ws.is_open() {
            return;
        }
        let node = BinaryNode::with_nodes("ib", Attrs::new(), vec![BinaryNode::tag("unified_session", Attrs::from([("id", self.get_unified_session_id())]))]);
        if let Err(e) = self.send_node(&node) {
            self.logger.debug(&format!("failed to send unified_session telemetry: {e}"));
        }
    }
    pub fn register_socket_end_handler(&self, handler: SocketEndHandler) {
        self.socket_end_handlers.lock().unwrap().push(handler);
    }
    pub fn wait_for_connection_update(&self, check: Arc<dyn Fn(&BaileysEvent) -> bool + Send + Sync>, timeout_ms: Option<u64>) -> Result<()> {
        bind_wait_for_connection_update(&self.ev, check, timeout_ms)
    }
    pub fn send_wam_buffer(&self, wam_buffer: &[u8]) -> Result<Option<BinaryNode>> {
        let mut attrs = Attrs::new();
        attrs.set("to", S_WHATSAPP_NET);
        attrs.set("id", self.generate_message_tag());
        attrs.set("xmlns", "w:stats");
        let add = BinaryNode::with_bytes("add", Attrs::from([("t", (now_ms() as f64 / 1000.0).round().to_string())]), wam_buffer);
        self.query(BinaryNode::with_nodes("iq", attrs, vec![add]), None)
    }
    fn generate_pairing_key(&self) -> Result<Vec<u8>> {
        let (code, public) = {
            let c = self.creds.lock().unwrap();
            (c.pairing_code.clone().unwrap_or_default(), c.pairing_ephemeral_key_pair.public)
        };
        let mut salt = [0u8; 32];
        crypto::random_bytes(&mut salt);
        let mut random_iv = [0u8; 16];
        crypto::random_bytes(&mut random_iv);
        let key = crypto::derive_pairing_code_key(&code, &salt);
        let ciphered = crypto::aes_encrypt_ctr(&public, &key, &random_iv)?;
        Ok([&salt[..], &random_iv[..], &ciphered[..]].concat())
    }
    pub fn request_pairing_code(&self, phone_number: &str, custom_pairing_code: Option<&str>) -> Result<String> {
        let pairing_code = match custom_pairing_code {
            Some(c) => c.to_string(),
            None => {
                let mut b = [0u8; 5];
                crypto::random_bytes(&mut b);
                bytes_to_crockford(&b)
            }
        };
        if custom_pairing_code.is_some_and(|c| !c.is_empty() && c.chars().count() != 8) {
            return Err(Boom::new("Custom pairing code must be exactly 8 chars"));
        }
        let me_id = jid_encode(phone_number, "s.whatsapp.net", None, None);
        {
            let mut c = self.creds.lock().unwrap();
            c.pairing_code = Some(pairing_code.clone());
            c.me = Some(Contact { id: me_id.clone(), name: Some("~".to_string()), ..Contact::default() });
        }
        self.emit_creds_fields(CredsUpdate { pairing_code: Some(Some(pairing_code.clone())), ..CredsUpdate::default() });
        let browser = &self.config.browser;
        let noise_public = self.creds.lock().unwrap().noise_key.public;
        let mut display = String::with_capacity(browser[1].len() + browser[0].len() + 3);
        display.push_str(&browser[1]);
        display.push_str(" (");
        display.push_str(&browser[0]);
        display.push(')');
        let content = vec![
            BinaryNode::with_bytes("link_code_pairing_wrapped_companion_ephemeral_pub", Attrs::new(), self.generate_pairing_key()?),
            BinaryNode::with_bytes("companion_server_auth_key_pub", Attrs::new(), noise_public),
            BinaryNode::with_text("companion_platform_id", Attrs::new(), get_companion_platform_id(browser)),
            BinaryNode::with_text("companion_platform_display", Attrs::new(), display),
            BinaryNode::with_text("link_code_pairing_nonce", Attrs::new(), "0"),
        ];
        let reg = BinaryNode::with_nodes("link_code_companion_reg", Attrs::from([("jid", me_id.as_str()), ("stage", "companion_hello"), ("should_show_push_notification", "true")]), content);
        let mut attrs = Attrs::new();
        attrs.set("to", S_WHATSAPP_NET);
        attrs.set("type", "set");
        attrs.set("id", self.generate_message_tag());
        attrs.set("xmlns", "md");
        self.send_node(&BinaryNode::with_nodes("iq", attrs, vec![reg]))?;
        Ok(pairing_code)
    }
    /// Fetches your account's standing when it comes to restrictions.
    pub fn fetch_account_reachout_timelock(&self) -> Result<ReachoutTimelockState> {
        let r = execute_wmex_query(self, Json::Obj(Vec::new()), query_ids::REACHOUT_TIMELOCK, xwa_paths::XWA2_FETCH_ACCOUNT_REACHOUT_TIMELOCK)?;
        let ends = r.get("time_enforcement_ends").and_then(Json::as_str).filter(|v| !v.is_empty() && *v != "0");
        let result = ReachoutTimelockState {
            is_active: Some(r.get("is_active").and_then(Json::as_bool).unwrap_or(false)),
            time_enforcement_ends_ms: ends.and_then(|v| v.parse::<i64>().ok()).map(|v| v * 1000),
            enforcement_type: Some(r.get("enforcement_type").and_then(Json::as_str).and_then(ReachoutTimelockEnforcementType::parse).unwrap_or(ReachoutTimelockEnforcementType::DEFAULT)),
        };
        self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { reachout_time_lock: Some(result.clone()), ..ConnectionState::default() }));
        Ok(result)
    }
    /// Fetches your account's new chat limits.
    pub fn fetch_new_chat_message_cap(&self) -> Result<NewChatMessageCapInfo> {
        let variables = Json::Obj(vec![("input".to_string(), Json::Obj(vec![("type".to_string(), jstr("INDIVIDUAL_NEW_CHAT_MSG"))]))]);
        let r = execute_wmex_query(self, variables, query_ids::MESSAGE_CAPPING_INFO, xwa_paths::XWA2_MESSAGE_CAPPING_INFO)?;
        Ok(parse_new_chat_message_cap(&r))
    }
    pub fn signal(&self) -> &dyn SignalRepository {
        self.signal_repository.as_ref()
    }
}
pub(crate) fn parse_new_chat_message_cap(r: &Json) -> NewChatMessageCapInfo {
    let text = |k: &str| r.get(k).and_then(Json::as_str).map(str::to_string);
    let num = |k: &str| r.get(k).and_then(Json::as_f64).map(|v| v as u32);
    NewChatMessageCapInfo {
        total_quota: num("total_quota"),
        used_quota: num("used_quota"),
        cycle_start_timestamp: text("cycle_start_timestamp"),
        cycle_end_timestamp: text("cycle_end_timestamp"),
        server_sent_timestamp: text("server_sent_timestamp"),
        ote_status: r.get("ote_status").and_then(Json::as_str).and_then(NewChatMessageCappingOTEStatusType::parse),
        mv_status: r.get("mv_status").and_then(Json::as_str).and_then(NewChatMessageCappingMVStatusType::parse),
        capping_status: r.get("capping_status").and_then(Json::as_str).and_then(NewChatMessageCappingStatusType::parse),
    }
}
impl Socket {
    pub(crate) fn weak(&self) -> WeakSocket {
        Arc::downgrade(&self.0)
    }
    /// Starts a tracked thread. `end` waits for all of them.
    pub(crate) fn spawn_thread(&self, name: &str, work: impl FnOnce(Socket) + Send + 'static) {
        self.threads.lock().unwrap().live += 1;
        let sock = self.clone();
        let r = std::thread::Builder::new().name(name.to_string()).stack_size(THREAD_STACK).spawn(move || {
            sock.threads.lock().unwrap().ids.push(std::thread::current().id());
            let guard = ThreadGuard(sock.clone());
            work(sock);
            drop(guard);
        });
        if let Err(e) = r {
            let mut t = self.threads.lock().unwrap();
            t.live -= 1;
            self.threads_done.notify_all();
            drop(t);
            self.on_unexpected_error(&Boom::new(e.to_string()), name);
        }
    }
    /// Runs work on a lane, after what is queued there.
    pub(crate) fn on_lane(&self, id: LaneId, work: impl FnOnce(Socket) + Send + 'static) {
        self.push_job(id, Job::Task(Box::new(work)));
    }
    /// A fire-and-forget promise of upstream. It can wait for a reply, as any work on a lane can, but
    /// it must not wait for other work on the control lane.
    pub(crate) fn spawn_task(&self, name: &'static str, work: impl FnOnce(Socket) -> Result<()> + Send + 'static) {
        self.on_lane(LaneId::Control, move |s| {
            if let Err(e) = work(s.clone()) {
                s.on_unexpected_error(&e, name);
            }
        });
    }
    /// generates and uploads a set of pre-keys to the server
    pub fn upload_pre_keys(&self, count: Option<u32>) -> Result<()> {
        let count = count.unwrap_or(MIN_PREKEY_COUNT);
        /// `wait` takes the value, so each waiter puts it back for the next one.
        fn wait_shared(r: &Resolver<()>, ms: Option<u64>) -> Option<Result<()>> {
            let out = r.wait(ms);
            match &out {
                Some(Ok(())) => r.resolve(()),
                Some(Err(e)) => r.reject(e.clone()),
                None => {}
            }
            out
        }
        let mine = {
            let mut g = self.0.upload_pre_keys_in_flight.lock().unwrap();
            if let Some(r) = g.as_ref() {
                let other = r.clone();
                drop(g);
                self.logger.debug("Pre-key upload already in progress, waiting for completion");
                return match wait_shared(&other, Some(UPLOAD_TIMEOUT)) {
                    Some(Ok(())) => Ok(()),
                    Some(Err(e)) => Err(e),
                    None => Err(Boom::status("Pre-key upload timeout", 408)),
                };
            }
            let r = Resolver::new();
            *g = Some(r.clone());
            r
        };
        // Add timeout protection: the work goes on in its thread when the caller gives up
        let done = mine.clone();
        self.spawn_thread("upload-pre-keys", move |s| {
            let r = s.upload_logic(count, 0);
            *s.0.upload_pre_keys_in_flight.lock().unwrap() = None;
            match r {
                Ok(()) => done.resolve(()),
                Err(e) => done.reject(e),
            }
        });
        match wait_shared(&mine, Some(UPLOAD_TIMEOUT)) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => {
                // a later caller can start again, as upstream clears its promise after the race
                *self.0.upload_pre_keys_in_flight.lock().unwrap() = None;
                Err(Boom::status("Pre-key upload timeout", 408))
            }
        }
    }
    pub fn upload_pre_keys_to_server_if_required(&self) {
        let run = || -> Result<()> {
            let pre_key_count = self.get_available_pre_keys_on_server()?;
            let count = if pre_key_count == 0.0 { INITIAL_PREKEY_COUNT } else { MIN_PREKEY_COUNT };
            let (current_pre_key_exists, current_pre_key_id) = self.verify_current_pre_key_exists()?;
            let low_server_count = pre_key_count <= count as f64;
            let missing_current_pre_key = !current_pre_key_exists && current_pre_key_id > 0;
            if low_server_count || missing_current_pre_key {
                self.upload_pre_keys(Some(count))?;
            }
            Ok(())
        };
        if let Err(e) = run() {
            // Don't throw - allow connection to continue even if pre-key check fails
            self.logger.error(&format!("Failed to check/upload pre-keys during initialization: {e}"));
        }
    }
    /// i have no idea why this exists. pls enlighten me
    fn send_passive_iq(&self, tag: &str) -> Result<Option<BinaryNode>> {
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("xmlns", "passive"), ("type", "set")]), vec![BinaryNode::tag(tag, Attrs::new())]), None)
    }
    /// logout & invalidate connection
    pub fn logout(&self, msg: Option<&str>) -> Result<()> {
        if let Some(jid) = self.me_id() {
            let mut attrs = Attrs::new();
            attrs.set("to", S_WHATSAPP_NET);
            attrs.set("type", "set");
            attrs.set("id", self.generate_message_tag());
            attrs.set("xmlns", "md");
            let remove = BinaryNode::tag("remove-companion-device", Attrs::from([("jid", jid.as_str()), ("reason", "user_initiated")]));
            self.send_node(&BinaryNode::with_nodes("iq", attrs, vec![remove]))?;
        }
        self.end(Some(Boom::status(msg.unwrap_or("Intentional Logout"), DisconnectReason::LOGGED_OUT.0)));
        Ok(())
    }
    /// Blocks until the transport is open, or fails when the connection closes first.
    pub fn wait_for_socket_open(&self) -> Result<()> {
        loop {
            if self.ws.is_open() {
                return Ok(());
            }
            if self.ws.is_closed() || self.ws.is_closing() || self.is_closed() {
                return Err(connection_closed());
            }
            self.sleep_until_closed(5);
        }
    }
    /// Starts the connection. `make_wa_socket` does not do this, so that you can add listeners first.
    /// Does nothing on a second call.
    pub fn connect(&self) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.me_id().is_some_and(|i| !i.is_empty()) {
            // start buffering important events
            // if we're logged in
            self.ev.buffer();
            self.did_start_buffer.store(true, Ordering::Release);
        }
        self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { connection: Some(WAConnectionState::Connecting), received_pending_notifications: Some(false), qr: Some(None), ..ConnectionState::default() }));
        self.spawn_thread("wa-reader", |s| s.run_reader());
    }
    fn run_lane(&self, id: LaneId) {
        let lane = self.lane(id);
        let idle = Duration::from_millis(LANE_IDLE_MS);
        loop {
            let job = {
                let mut st = lane.state.lock().unwrap();
                loop {
                    if self.is_closed() {
                        st.running = false;
                        return;
                    }
                    if let Some(job) = st.jobs.pop_front() {
                        break job;
                    }
                    let (next, wait) = lane.wake.wait_timeout(st, idle).unwrap();
                    st = next;
                    if wait.timed_out() && st.jobs.is_empty() {
                        // the same lock as `push_job`, so that a new job starts a new thread
                        st.running = false;
                        st.jobs = VecDeque::new();
                        drop(st);
                        super::release_free_memory();
                        return;
                    }
                }
            };
            // A throw in an upstream handler is a report. A panic is the closest thing to a throw.
            let ran = catch_unwind(AssertUnwindSafe(|| match job {
                Job::Frame(handler, node) => handler(self, &node),
                Job::Task(work) => work(self.clone()),
            }));
            if ran.is_err() {
                self.on_unexpected_error(&Boom::new("handler panicked"), "lane job");
            }
        }
    }
    fn run_reader(&self) {
        if let Err(e) = self.ws.transport.connect() {
            self.end(Some(map_web_socket_error(&e)));
            return;
        }
        if self.is_closed() {
            return;
        }
        self.ws.set_state(WS_OPEN);
        if let Err(err) = self.validate_connection() {
            self.logger.error(&format!("error in validating connection: {err}"));
            self.end(Some(err));
            return;
        }
        while !self.is_closed() {
            match self.ws.transport.recv() {
                Ok(Some(data)) => self.on_message_received(&data),
                Ok(None) => {
                    self.end(Some(Boom::status("Connection Terminated", DisconnectReason::CONNECTION_CLOSED.0)));
                    return;
                }
                Err(e) => {
                    self.end(Some(map_web_socket_error(&e)));
                    return;
                }
            }
        }
    }
    /// connection handshake: sends the hello. `on_handshake_frame` does the rest.
    fn validate_connection(&self) -> Result<()> {
        let hello = HandshakeMessage::default().with_client_hello(ClientHello::default().with_ephemeral(self.ephemeral_key_pair.public));
        self.logger.info("connected to WA");
        let weak = self.weak();
        let timer = set_timeout(self.config.connect_timeout_ms, move || {
            if let Some(s) = upgrade(&weak) {
                if !s.handshake_done.load(Ordering::Acquire) {
                    s.end(Some(Boom::status("Timed Out", DisconnectReason::TIMED_OUT.0)));
                }
            }
        });
        *self.handshake_timer.lock().unwrap() = Some(timer);
        self.send_raw_message(&hello.encode())
    }
    fn on_handshake_frame(&self, data: &[u8]) -> Result<()> {
        let handshake = HandshakeMessage::decode(data)?;
        let (noise_key, me) = {
            let c = self.creds.lock().unwrap();
            (c.noise_key.clone(), c.me.clone())
        };
        let key_enc = self.noise.lock().unwrap().process_handshake(&handshake, &noise_key)?;
        let node = match me {
            None => {
                self.logger.info("not logged in, attempting registration...");
                let signal = SignalCreds::from_auth(&self.creds.lock().unwrap());
                generate_registration_node(&signal, &self.config)
            }
            Some(me) => {
                self.logger.info("logging in...");
                generate_login_node(&me.id, &self.config)?
            }
        };
        // the frame is encoded before `finish_init`, and written after it, so that no server frame
        // can reach `decode_frame` before the transport keys are ready
        let _order = self.write_lock.lock().unwrap();
        let bytes = {
            let mut noise = self.noise.lock().unwrap();
            let payload_enc = noise.encrypt(&node.encode())?;
            let finish = HandshakeMessage::default().with_client_finish(ClientFinish::default().with_static(key_enc).with_payload(payload_enc));
            let bytes = noise.encode_frame(&finish.encode())?;
            noise.finish_init();
            bytes
        };
        self.ws.transport.send(&bytes)?;
        drop(_order);
        self.handshake_done.store(true, Ordering::Release);
        if let Some(t) = self.handshake_timer.lock().unwrap().take() {
            t.cancel();
        }
        self.start_keep_alive_request();
        Ok(())
    }
    fn on_message_received(&self, data: &[u8]) {
        let mut frames = Vec::with_capacity(1);
        let r = self.noise.lock().unwrap().decode_frame(data, &mut |f| frames.push(f));
        for frame in frames {
            // reset ping timeout
            self.last_date_recv.store(now_ms(), Ordering::Relaxed);
            match frame {
                Frame::Raw(bytes) => {
                    if !self.handshake_done.load(Ordering::Acquire) {
                        if let Err(err) = self.on_handshake_frame(&bytes) {
                            self.logger.error(&format!("error in validating connection: {err}"));
                            self.end(Some(err));
                            return;
                        }
                    }
                }
                Frame::Node(node) => self.on_node(node),
            }
        }
        if let Err(e) = r {
            // Upstream gets an unhandled rejection here. The Noise counters are lost, so no later frame can be read.
            self.end(Some(e));
        }
    }
    /// The routes of the `CB:` listeners of upstream. See the comment at the top of `socket/mod.rs`.
    fn route(&self, node: &BinaryNode) -> Option<(LaneId, LaneHandler)> {
        let first_child = match &node.content {
            Some(Content::Nodes(n)) => n.first().map(|c| c.tag.as_str()),
            _ => None,
        };
        match node.tag.as_str() {
            "message" => Some((LaneId::Message, |s, n| s.on_cb_message(n))),
            "receipt" => Some((LaneId::Control, |s, n| s.on_cb_receipt(n))),
            "notification" => Some((LaneId::Control, |s, n| s.on_cb_notification(n))),
            "call" => Some((LaneId::Control, |s, n| s.on_cb_call(n))),
            "ack" if node.attr("class") == Some("message") => Some((LaneId::Control, |s, n| s.on_cb_ack_message(n))),
            "presence" | "chatstate" => Some((LaneId::Control, |s, n| s.handle_presence_update(n))),
            "iq" => match first_child {
                Some("pair-device") if node.attr("type") == Some("set") => Some((LaneId::Control, |s, n| s.on_cb_pair_device(n))),
                Some("pair-success") => Some((LaneId::Control, |s, n| s.on_cb_pair_success(n))),
                _ => None,
            },
            "success" => Some((LaneId::Control, |s, n| s.on_cb_success(n))),
            "ib" => match first_child {
                Some("offline_preview") => Some((LaneId::Control, |s, n| s.on_cb_offline_preview(n))),
                Some("edge_routing") => Some((LaneId::Control, |s, n| s.on_cb_edge_routing(n))),
                Some("offline") => Some((LaneId::Control, |s, n| s.on_cb_offline(n))),
                Some("dirty") => Some((LaneId::Control, |s, n| s.on_cb_dirty(n))),
                _ => None,
            },
            _ => None,
        }
    }
    /// The frames that end the connection run here on the reader thread, in frame order.
    /// Nothing can be waited for after them, so the rule for handlers does not apply.
    fn on_fatal_frame(&self, node: &BinaryNode) -> bool {
        match node.tag.as_str() {
            // the server terminated the connection
            "xmlstreamend" => self.end(Some(Boom::status("Connection Terminated by Server", DisconnectReason::CONNECTION_CLOSED.0))),
            "stream:error" => {
                self.logger.error("stream errored out");
                let info = get_error_code_from_stream_error(node);
                let data = get_all_binary_node_children(node).first().map_or_else(|| node_to_json(node), node_to_json);
                let mut e = Boom::with_data(format!("Stream Errored ({})", info.reason), data);
                e.status_code = Some(info.status_code);
                self.end(Some(e));
            }
            // stream fail, possible logout
            "failure" => {
                let reason = node.attr("reason").filter(|r| !r.is_empty()).map_or(500.0, |r| attr_num(Some(r)));
                let data = Json::Obj(node.attrs.iter().map(|(k, v)| (k.to_string(), jstr(v))).collect());
                let mut e = Boom::with_data("Connection Failure", data);
                e.status_code = Some(if reason.is_nan() { 0 } else { reason as u16 });
                self.end(Some(e));
            }
            "ib" if get_all_binary_node_children(node).first().is_some_and(|c| c.tag.as_str() == "downgrade_webclient") => {
                self.end(Some(Boom::status("Multi-device beta not joined", DisconnectReason::MULTIDEVICE_MISMATCH.0)));
            }
            _ => return false,
        }
        true
    }
    fn on_node(&self, node: BinaryNode) {
        if self.logger.is_enabled(LogLevel::Trace) {
            self.logger.trace_obj(&Json::Obj(vec![("xml".to_string(), Json::Str(binary_node_to_string(&node, 0))), ("msg".to_string(), jstr("recv xml"))]), "recv xml");
        }
        if self.on_fatal_frame(&node) {
            return;
        }
        let route = self.route(&node);
        let custom = self.ws.has_listeners.load(Ordering::Acquire);
        let waiters = node.attr("id").and_then(|id| self.waiters.lock().unwrap().remove(id));
        if custom {
            self.push_job(LaneId::Control, Job::Frame(|s, n| s.emit_custom(n), node.clone()));
        }
        match (waiters, route) {
            (Some(mut w), None) => {
                // the usual reply to a query: no copy of the node is made
                let last = w.pop();
                for x in w {
                    x.result.resolve(node.clone());
                }
                if let Some(x) = last {
                    x.result.resolve(node);
                }
            }
            (Some(w), Some((lane, handler))) => {
                for x in w {
                    x.result.resolve(node.clone());
                }
                self.push_job(lane, Job::Frame(handler, node));
            }
            (None, Some((lane, handler))) => self.push_job(lane, Job::Frame(handler, node)),
            (None, None) => {
                if !custom && self.logger.is_enabled(LogLevel::Debug) {
                    self.logger.debug("communication recv: unhandled");
                }
            }
        }
    }
    /// Emits the stanza event names of upstream to the listeners of `ws.on`.
    fn emit_custom(&self, frame: &BinaryNode) {
        let ws = &self.ws;
        ws.emit("frame", frame);
        if let Some(id) = frame.attr("id") {
            ws.emit(&format!("{DEF_TAG_PREFIX}{id}"), frame);
        }
        let l0 = frame.tag.as_str();
        let l2 = match &frame.content {
            Some(Content::Nodes(n)) => n.first().map_or("", |c| c.tag.as_str()),
            _ => "",
        };
        for (key, value) in frame.attrs.iter() {
            ws.emit(&format!("{DEF_CALLBACK_PREFIX}{l0},{key}:{value},{l2}"), frame);
            ws.emit(&format!("{DEF_CALLBACK_PREFIX}{l0},{key}:{value}"), frame);
            ws.emit(&format!("{DEF_CALLBACK_PREFIX}{l0},{key}"), frame);
        }
        ws.emit(&format!("{DEF_CALLBACK_PREFIX}{l0},,{l2}"), frame);
        ws.emit(&format!("{DEF_CALLBACK_PREFIX}{l0}"), frame);
    }
    /// Ends the connection and stops every thread of this socket.
    ///
    /// Called from a thread of the socket, such as in a listener, this does not wait for the other
    /// threads, because they may wait for the caller. They stop on their own soon after.
    ///
    /// Different from upstream: pending queries fail at once with `Connection Closed`. Upstream removes
    /// their close listeners here, so they only end at their timeout. A thread cannot wait that long.
    pub fn end(&self, error: Option<Boom>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            self.logger.trace("connection already closed");
            self.wait_for_threads();
            return;
        }
        self.logger.info(if error.is_some() { "connection errored" } else { "connection closed" });
        {
            let _g = self.stop_lock.lock().unwrap();
            self.stop_wake.notify_all();
        }
        if let Some(t) = self.qr_timer.lock().unwrap().take() {
            t.cancel();
        }
        if let Some(t) = self.handshake_timer.lock().unwrap().take() {
            t.cancel();
        }
        if let Some(t) = self.keep_alive_timer.lock().unwrap().take() {
            t.cancel();
        }
        self.ws.remove_all_listeners("close");
        self.ws.remove_all_listeners("open");
        self.ws.remove_all_listeners("message");
        self.signal_repository.close();
        if !self.ws.is_closed() {
            self.ws.set_state(WS_CLOSING);
            self.ws.transport.close();
            self.ws.set_state(WS_CLOSED);
        }
        let waiters = std::mem::take(&mut *self.waiters.lock().unwrap());
        for w in waiters.into_values().flatten() {
            w.result.reject(connection_closed());
        }
        self.stop_lanes();
        let handlers = self.socket_end_handlers.lock().unwrap().clone();
        for handler in &handlers {
            if catch_unwind(AssertUnwindSafe(|| handler(error.as_ref()))).is_err() {
                self.logger.error("error in socket end handler");
            }
        }
        self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { connection: Some(WAConnectionState::Close), last_disconnect: Some(LastDisconnect { error, date_ms: now_ms() }), ..ConnectionState::default() }));
        // Another thread that dispatches has the event above in its queue. A wait gives it time, so
        // that the caller usually sees the close first. A slow listener still gets the event after this.
        if !self.is_socket_thread() {
            self.ev.wait_dispatch_idle(END_WAIT_MS);
        }
        self.ev.destroy_after_dispatch();
        self.wait_for_threads();
    }
    fn start_keep_alive_request(&self) {
        let weak = self.weak();
        let timer = set_timeout(self.config.keep_alive_interval_ms, move || {
            if let Some(s) = upgrade(&weak) {
                s.keep_alive_tick();
            }
        });
        *self.keep_alive_timer.lock().unwrap() = Some(timer);
    }
    fn keep_alive_tick(&self) {
        if self.is_closed() {
            return;
        }
        let interval = self.config.keep_alive_interval_ms;
        if self.last_date_recv.load(Ordering::Relaxed) == 0 {
            self.last_date_recv.store(now_ms(), Ordering::Relaxed);
        }
        let diff = now_ms() - self.last_date_recv.load(Ordering::Relaxed);
        // check if it's been a suspicious amount of time since the server responded with our last seen
        // it could be that the network is down
        if diff > interval as i64 + 5000 {
            self.end(Some(Boom::status("Connection was lost", DisconnectReason::CONNECTION_LOST.0)));
            return;
        } else if self.ws.is_open() {
            // if its all good, send a keep alive request. Any frame back resets the timer, so
            // this does not wait for the reply, and can still see a lost connection.
            let mut attrs = Attrs::new();
            attrs.set("id", self.generate_message_tag());
            attrs.set("to", S_WHATSAPP_NET);
            attrs.set("type", "get");
            attrs.set("xmlns", "w:p");
            if let Err(err) = self.send_node(&BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::tag("ping", Attrs::new())])) {
                self.logger.error(&format!("error in sending keep alive: {err}"));
            }
        } else {
            self.logger.warn("keep alive called when WS not open");
        }
        self.start_keep_alive_request();
    }
    fn gen_pair_qr(&self, refs: Arc<PairRefs>, qr_ms: u64) {
        if !self.ws.is_open() {
            return;
        }
        let next = refs.refs.lock().unwrap().pop_front();
        let Some(reference) = next else {
            self.end(Some(Boom::status("QR refs attempts ended", DisconnectReason::TIMED_OUT.0)));
            return;
        };
        let qr = build_pairing_qr_data(&reference, &refs.noise_key_b64, &refs.identity_key_b64, &refs.adv_b64, &self.config.browser);
        self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { qr: Some(Some(qr)), ..ConnectionState::default() }));
        let weak = self.weak();
        let next_ms = self.config.qr_timeout.filter(|t| *t > 0).unwrap_or(20_000); // shorter subsequent qrs
        let timer = set_timeout(qr_ms, move || {
            if let Some(s) = upgrade(&weak) {
                s.gen_pair_qr(refs, next_ms);
            }
        });
        *self.qr_timer.lock().unwrap() = Some(timer);
    }
    /// QR gen
    fn on_cb_pair_device(&self, stanza: &BinaryNode) {
        let mut attrs = Attrs::from([("to", S_WHATSAPP_NET), ("type", "result")]);
        attrs.set("id", stanza.attr("id").unwrap_or_default());
        if let Err(e) = self.send_node(&BinaryNode::tag("iq", attrs)) {
            self.on_unexpected_error(&e, "pair-device");
            return;
        }
        let pair_device_node = get_binary_node_child(Some(stanza), "pair-device");
        let refs = get_binary_node_children(pair_device_node, "ref").into_iter().map(|r| content_string(Some(r)).unwrap_or_default()).collect();
        let (noise_key_b64, identity_key_b64, adv_b64) = {
            let c = self.creds.lock().unwrap();
            (base64_encode(&c.noise_key.public), base64_encode(&c.signed_identity_key.public), c.adv_secret_key.clone())
        };
        let qr_ms = self.config.qr_timeout.filter(|t| *t > 0).unwrap_or(60_000); // time to let a QR live
        self.gen_pair_qr(Arc::new(PairRefs { refs: Mutex::new(refs), noise_key_b64, identity_key_b64, adv_b64 }), qr_ms);
    }
    /// device paired for the first time
    /// if device pairs successfully, the server asks to restart the connection
    fn on_cb_pair_success(&self, stanza: &BinaryNode) {
        self.logger.debug("pair success recv");
        let run = || -> Result<()> {
            self.update_server_time_offset(stanza);
            let creds = self.creds.lock().unwrap().clone();
            let paired = configure_successful_pairing(stanza, &creds)?;
            self.logger.info("pairing configured successfully, expect to restart the connection...");
            self.ev.emit(BaileysEvent::CredsUpdate(Box::new(paired.creds)));
            self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { is_new_login: Some(true), qr: Some(None), ..ConnectionState::default() }));
            self.send_node(&paired.reply)?;
            self.send_unified_session();
            Ok(())
        };
        if let Err(error) = run() {
            self.logger.info(&format!("error in pairing: {error}"));
            self.end(Some(error));
        }
    }
    /// login complete
    fn on_cb_success(&self, node: &BinaryNode) {
        self.update_server_time_offset(node);
        self.upload_pre_keys_to_server_if_required();
        match self.send_passive_iq("active") {
            Ok(_) => {
                // After successful login, validate our key-bundle against server
                if let Err(e) = self.digest_key_bundle() {
                    self.logger.warn(&format!("failed to run digest after login: {e}"));
                }
            }
            Err(err) => self.logger.warn(&format!("failed to send initial passive iq: {err}")),
        }
        self.logger.info("opened connection to WA");
        // will never happen in all likelyhood -- but just in case WA sends success on first try
        if let Some(t) = self.qr_timer.lock().unwrap().take() {
            t.cancel();
        }
        let me = self.creds.lock().unwrap().me.clone().unwrap_or_default();
        let lid = node.attr("lid").map(str::to_string);
        self.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { me: Some(Some(Contact { lid: lid.clone(), ..me })), ..CredsUpdate::default() })));
        self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { connection: Some(WAConnectionState::Open), ..ConnectionState::default() }));
        self.send_unified_session();
        if let (Some(my_lid), Some(my_pn)) = (lid.filter(|l| !l.is_empty()), self.me_id().filter(|i| !i.is_empty())) {
            self.spawn_task("own LID session", move |s| {
                // Store our own LID-PN mapping
                s.signal_repository.lid_mapping().store_lid_pn_mappings(&[LidMapping { lid: my_lid.clone(), pn: my_pn.clone() }])?;
                // Create device list for our own user (needed for bulk migration)
                let decoded = jid_decode(&my_pn).ok_or_else(|| Boom::type_error("Cannot destructure property 'user' of undefined"))?;
                let device = decoded.device.unwrap_or(0).to_string();
                s.raw_keys.set_one(KeyKind::DeviceList, decoded.user, Some(KeyValue::DeviceList(vec![device])))?;
                // migrate our own session
                s.signal_repository.migrate_session(&my_pn, &my_lid)?;
                s.logger.info("Own LID session created successfully");
                Ok(())
            });
        }
    }
    fn on_cb_offline_preview(&self, _node: &BinaryNode) {
        self.logger.info("offline preview received");
        let r = self.send_node(&BinaryNode::with_nodes("ib", Attrs::new(), vec![BinaryNode::tag("offline_batch", Attrs::from([("count", "100")]))]));
        if let Err(e) = r {
            self.on_unexpected_error(&e, "offline_preview");
        }
    }
    fn on_cb_edge_routing(&self, node: &BinaryNode) {
        let edge_routing_node = get_binary_node_child(Some(node), "edge_routing");
        let routing_info = get_binary_node_child_buffer(edge_routing_node, "routing_info");
        if let Some(info) = routing_info {
            self.emit_creds_fields(CredsUpdate { routing_info: Some(Some(info.clone())), ..CredsUpdate::default() });
        }
    }
    /// called when all offline notifs are handled
    fn on_cb_offline(&self, node: &BinaryNode) {
        let child = get_binary_node_child(Some(node), "offline");
        let offline_notifs = child.and_then(|c| c.attr("count")).unwrap_or("0");
        self.logger.info(&format!("handled {offline_notifs} offline messages/notifications"));
        if self.did_start_buffer.load(Ordering::Acquire) {
            self.ev.flush();
            self.logger.trace("flushed events for initial buffer");
        }
        self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { received_pending_notifications: Some(true), ..ConnectionState::default() }));
    }
    fn on_cb_dirty(&self, node: &BinaryNode) {
        let Some(dirty) = get_binary_node_child(Some(node), "dirty") else {
            self.on_unexpected_error(&Boom::type_error("Cannot destructure property 'attrs' of undefined"), "dirty");
            return;
        };
        self.on_dirty_chats(node, dirty);
        self.on_dirty_groups(dirty);
        self.on_dirty_communities(dirty);
    }
    fn register_core_listeners(&self) {
        // update credentials when required
        let weak = self.weak();
        self.ev.on_emit(
            EventKind::CredsUpdate,
            Arc::new(move |e: &BaileysEvent| {
                let (BaileysEvent::CredsUpdate(update), Some(s)) = (e, upgrade(&weak)) else { return };
                let name = update.me.as_ref().and_then(|m| m.as_ref()).and_then(|m| m.name.clone());
                let old = {
                    let mut c = s.creds.lock().unwrap();
                    let old = c.me.as_ref().and_then(|m| m.name.clone());
                    c.assign(update);
                    old
                };
                // if name has just been received
                // Same odd case as upstream: an update without `me` reads as an undefined name, so a
                // client with a name sends a presence with no name here.
                if old != name {
                    let mut attrs = Attrs::new();
                    if let Some(n) = &name {
                        attrs.set("name", n.as_str());
                    }
                    if let Err(err) = s.send_node(&BinaryNode::tag("presence", attrs)) {
                        s.logger.warn(&format!("error in sending presence update on name change: {err}"));
                    }
                }
            }),
        );
    }
}
struct ThreadGuard(Socket);
impl Drop for ThreadGuard {
    fn drop(&mut self) {
        let me = std::thread::current().id();
        let mut t = match self.0.threads.lock() {
            Ok(t) => t,
            Err(e) => e.into_inner(),
        };
        t.live -= 1;
        t.ids.retain(|i| *i != me);
        self.0.threads_done.notify_all();
    }
}
/// map the websocket error to the right type
/// so it can be retried by the caller
fn map_web_socket_error(error: &Boom) -> Boom {
    let mut message = String::with_capacity(error.message.len() + 18);
    message.push_str("WebSocket Error (");
    message.push_str(&error.message);
    message.push(')');
    Boom::status(message, get_code_from_ws_error(&error.message, None))
}
