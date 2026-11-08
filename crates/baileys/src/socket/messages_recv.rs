//! Same as Socket/messages-recv.ts.
use super::LaneId;
use super::groups::{extract_group_metadata, parse_group_participant};
use super::socket::{Socket, SocketInner, WeakSocket, attr_num, content_string, jstr, parse_new_chat_message_cap, upgrade};
use crate::auth::*;
use crate::crypto;
use crate::defaults::*;
use crate::error::{Boom, Result};
use crate::events::*;
use crate::types::*;
use crate::utils::decode_wa_message::*;
use crate::utils::generics::*;
use crate::utils::history::get_history_msg;
use crate::utils::identity_change_handler::{IdentityChangeContext, IdentityChangeResult, handle_identity_change};
use crate::utils::make_mutex::{Mutex as FifoLock, make_mutex};
use crate::utils::messages_media::decode_media_retry_node;
use crate::utils::node_cache::NodeCache;
use crate::utils::offline_node_processor::{MessageType, NodeProcessorMap, OfflineNodeProcessor, OfflineNodeProcessorDeps, make_offline_node_processor};
use crate::utils::process_message::clean_message;
use crate::utils::signal::{extract_e2e_session_from_retry_receipt, get_next_pre_keys, xmpp_pre_key, xmpp_signed_pre_key};
use crate::utils::stanza_ack::build_ack_stanza;
use crate::utils::tc_token_utils::*;
use crate::utils::time::{Timeout, now_ms, set_timeout};
use crate::utils::validate_connection::encode_signed_device_identity;
use crate::wabinary::*;
use rustc_hash::FxHashSet;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use waproto::message::peer_data_operation_request_message::{HistorySyncOnDemandRequest, PlaceholderMessageResendRequest};
use waproto::message::protocol_message::Type as ProtocolType;
use waproto::message::{Call as CallMessage, PeerDataOperationRequestMessage, PeerDataOperationRequestType, ProtocolMessage};
use waproto::pb::{Bytes, Json, PbMessage, Str};
use waproto::web_message_info::{Status, StubType};

pub struct RecvState {
    /// this mutex ensures that each retryRequest will wait for the previous one to finish
    retry_mutex: FifoLock,
    msg_retry_cache: Arc<dyn CacheStore>,
    call_offer_cache: Arc<dyn CacheStore>,
    /// Debounce identity-change session refreshes per JID to avoid bursts
    identity_assert_debounce: Arc<dyn CacheStore>,
    send_active_receipts: AtomicBool,
    /// Mirrors WAWeb/Handle/PreKeyLow.js: skip a re-issued notification with the same stanza id.
    in_flight_pre_key_low: Mutex<FxHashSet<String>>,
    /// In-memory cache of storage JIDs with stored tctokens, seeded from the persisted index.
    /// Used to coalesce writes during a session; pruning always re-reads the persisted index
    /// to cover writes made by other layers (e.g. history sync).
    tc_token_known_jids: Mutex<FxHashSet<String>>,
    tc_token_index_timer: Mutex<Option<Timeout>>,
    /// timestamp of last tctoken prune run — throttles to once per 24h
    last_tc_token_prune_ts: AtomicI64,
    /// dedupe in-flight 463 recovery token issuance by target JID
    in_flight_463_recoveries: Mutex<FxHashSet<String>>,
    offline_node_processor: OfflineNodeProcessor,
}
fn processor(weak: &WeakSocket, handler: fn(&SocketInner, &BinaryNode) -> Result<()>) -> crate::utils::offline_node_processor::NodeProcessor {
    let weak = weak.clone();
    Box::new(move |node: &BinaryNode| match upgrade(&weak) {
        Some(s) => handler(&s, node),
        None => Ok(()),
    })
}
impl RecvState {
    pub fn new(config: &SocketConfig, weak: WeakSocket) -> RecvState {
        let mut map: NodeProcessorMap = NodeProcessorMap::default();
        map.insert(MessageType::Message, processor(&weak, |s, n| s.handle_message(n)));
        map.insert(MessageType::Call, processor(&weak, |s, n| s.handle_call(n)));
        map.insert(MessageType::Receipt, processor(&weak, |s, n| s.handle_receipt(n)));
        map.insert(MessageType::Notification, processor(&weak, |s, n| s.handle_notification(n)));
        let (open_weak, err_weak) = (weak.clone(), weak);
        let deps = OfflineNodeProcessorDeps {
            is_ws_open: Box::new(move || upgrade(&open_weak).is_some_and(|s| s.ws.is_open())),
            on_unexpected_error: Box::new(move |e, m| {
                if let Some(s) = upgrade(&err_weak) {
                    s.on_unexpected_error(e, m);
                }
            }),
            yield_to_event_loop: Box::new(|| std::thread::yield_now()),
        };
        RecvState {
            retry_mutex: make_mutex(),
            msg_retry_cache: config.msg_retry_counter_cache.clone().unwrap_or_else(|| Arc::new(NodeCache::new(default_cache_ttls::MSG_RETRY))),
            call_offer_cache: config.call_offer_cache.clone().unwrap_or_else(|| Arc::new(NodeCache::new(default_cache_ttls::CALL_OFFER))),
            identity_assert_debounce: Arc::new(NodeCache::new(5)),
            send_active_receipts: AtomicBool::new(false),
            in_flight_pre_key_low: Mutex::new(FxHashSet::default()),
            tc_token_known_jids: Mutex::new(FxHashSet::default()),
            tc_token_index_timer: Mutex::new(None),
            last_tc_token_prune_ts: AtomicI64::new(0),
            in_flight_463_recoveries: Mutex::new(FxHashSet::default()),
            offline_node_processor: make_offline_node_processor(map, deps, None),
        }
    }
}
/// `result.key` of `processNotification`: only the fields that the case sets override the base key.
#[derive(Default)]
struct NotificationKey {
    participant: Option<Option<String>>,
    participant_alt: Option<Option<String>>,
}
#[derive(Default)]
struct NotificationResult {
    msg: WAMessage,
    key: NotificationKey,
    /// Upstream checks `Object.keys(result).length`, and a key that holds undefined also counts.
    any: bool,
}
fn str_list(v: Vec<String>) -> Vec<Str> {
    v.into_iter().map(|s| Str::from(s.as_str())).collect()
}
fn to_required_buffer(data: Option<&Bytes>) -> Result<&Bytes> {
    data.ok_or_else(|| Boom::status("Invalid buffer", 400))
}
fn is_valid_enforcement_type(value: Option<&str>) -> Option<ReachoutTimelockEnforcementType> {
    value.and_then(ReachoutTimelockEnforcementType::parse)
}
impl SocketInner {
    fn me_id_or_err(&self) -> Result<String> {
        self.me_id().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'id')"))
    }
    pub fn fetch_message_history(&self, count: u32, oldest_msg_key: &WAMessageKey, oldest_msg_timestamp: i64) -> Result<String> {
        if self.me_id().is_none_or(|i| i.is_empty()) {
            return Err(Boom::new("Not authenticated"));
        }
        let mut req = HistorySyncOnDemandRequest::default().with_oldest_msg_timestamp_ms(oldest_msg_timestamp).with_on_demand_msg_count(count as i32);
        if let Some(v) = oldest_msg_key.remote_jid() {
            req.set_chat_jid(v.clone());
        }
        if let Some(v) = oldest_msg_key.from_me() {
            req.set_oldest_msg_from_me(v);
        }
        if let Some(v) = oldest_msg_key.id() {
            req.set_oldest_msg_id(v.clone());
        }
        let pdo_message = PeerDataOperationRequestMessage::default().with_history_sync_on_demand_request(req).with_peer_data_operation_request_type(PeerDataOperationRequestType::HISTORY_SYNC_ON_DEMAND);
        self.send_peer_data_operation_message(pdo_message)
    }
    /// The value is the id of the request, `RESOLVED` when the message arrived during the wait, and
    /// `None` when a resend was already requested.
    pub fn request_placeholder_resend(&self, message_key: &WAMessageKey, msg_data: Option<WAMessage>) -> Result<Option<String>> {
        if self.me_id().is_none_or(|i| i.is_empty()) {
            return Err(Boom::new("Not authenticated"));
        }
        let cache = self.chats.placeholder_resend_cache.clone();
        let id = message_key.id().map_or(String::new(), |i| i.as_str().to_string());
        if cache.get(&id).is_some() {
            self.logger.debug("already requested resend");
            return Ok(None);
        }
        // Store original message data so PDO response handler can preserve
        // metadata (LID details, timestamps, etc.) that the phone may omit
        match msg_data {
            Some(d) => cache_set(cache.as_ref(), &id, d),
            None => cache_set(cache.as_ref(), &id, true),
        }
        self.sleep_until_closed(2000);
        if cache.get(&id).is_none() {
            self.logger.debug("message received while resend requested");
            return Ok(Some("RESOLVED".to_string()));
        }
        let pdo_message = PeerDataOperationRequestMessage::default().with_placeholder_message_resend_request(vec![PlaceholderMessageResendRequest::default().with_message_key(message_key.clone())]).with_peer_data_operation_request_type(PeerDataOperationRequestType::PLACEHOLDER_MESSAGE_RESEND);
        let logger = self.logger.clone();
        let (later, later_id) = (cache.clone(), id);
        set_timeout(8_000, move || {
            if later.get(&later_id).is_some() {
                logger.debug("PDO message without response after 8 seconds. Phone possibly offline");
                later.del(&later_id);
            }
        });
        self.send_peer_data_operation_message(pdo_message).map(Some)
    }
    fn handle_mex_notification(&self, node: &BinaryNode) -> Result<()> {
        let Some(update_node) = get_binary_node_child(Some(node), "update") else {
            return self.handle_legacy_mex_newsletter_notification(node);
        };
        let Some(op_name) = update_node.attr("op_name").filter(|o| !o.is_empty()) else {
            self.logger.warn("mex notification missing op_name, fallback to legacy");
            return self.handle_legacy_mex_newsletter_notification(node);
        };
        let mex_response = match content_string(Some(update_node)).map(|t| Json::parse(&t)) {
            Some(Ok(j)) => j,
            _ => {
                self.logger.error(&format!("failed to parse mex notification JSON: {op_name}"));
                return Ok(());
            }
        };
        if mex_response.get("errors").and_then(Json::as_arr).is_some_and(|e| !e.is_empty()) {
            self.logger.warn(&format!("mex notification has GQL errors: {op_name}"));
            return Ok(());
        }
        let Some(data) = mex_response.get("data").filter(|d| !matches!(d, Json::Null)) else {
            self.logger.warn(&format!("mex notification has null data: {op_name}"));
            return Ok(());
        };
        match op_name {
            "NotificationUserReachoutTimelockUpdate" => self.handle_reachout_timelock_notification(data),
            "MessageCappingInfoNotification" => self.handle_message_capping_notification(data),
            // newsletter ops still use the legacy <mex> child structure
            "NotificationNewsletterUpdate" | "NotificationLinkedProfilesUpdates" | "NotificationNewsletterAdminPromote" | "NotificationNewsletterAdminDemote" | "NotificationNewsletterUserSettingChange" | "NotificationNewsletterJoin" | "NotificationNewsletterLeave" | "NotificationNewsletterStateChange" | "NotificationNewsletterAdminMetadataUpdate" | "NotificationNewsletterOwnerUpdate" | "NotificationNewsletterAdminInviteRevoke" | "NotificationNewsletterWamoSubStatusChange" | "NotificationNewsletterBlockUser" | "NotificationNewsletterPaidPartnership" | "NotificationNewsletterMilestone" | "NewsletterResponseStateUpdate" => {
                return self.handle_legacy_mex_newsletter_notification(node);
            }
            _ => self.logger.debug(&format!("unhandled mex notification: {op_name}")),
        }
        Ok(())
    }
    fn handle_reachout_timelock_notification(&self, data: &Json) {
        let Some(payload) = data.get("xwa2_notify_account_reachout_timelock") else {
            self.logger.warn("reachout timelock notification missing payload");
            return;
        };
        let emit = |state: ReachoutTimelockState| {
            self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { reachout_time_lock: Some(state), ..ConnectionState::default() }));
        };
        if payload.get("is_active").and_then(Json::as_bool) != Some(true) {
            self.logger.info("reachout timelock restriction lifted");
            emit(ReachoutTimelockState { is_active: Some(false), time_enforcement_ends_ms: None, enforcement_type: Some(ReachoutTimelockEnforcementType::DEFAULT) });
            return;
        }
        // WA Web defaults to now+60s when the server omits the expiry
        let time_enforcement_ends = payload.get("time_enforcement_ends").and_then(Json::as_str).filter(|e| !e.is_empty()).and_then(|e| e.parse::<i64>().ok()).map_or_else(|| now_ms() + 60_000, |e| e * 1000);
        let enforcement_type = is_valid_enforcement_type(payload.get("enforcement_type").and_then(Json::as_str)).unwrap_or(ReachoutTimelockEnforcementType::DEFAULT);
        self.logger.info("reachout timelock restriction set");
        emit(ReachoutTimelockState { is_active: Some(true), time_enforcement_ends_ms: Some(time_enforcement_ends), enforcement_type: Some(enforcement_type) });
    }
    fn handle_message_capping_notification(&self, data: &Json) {
        let Some(payload) = data.get("xwa2_notify_new_chat_messages_capping_info_update") else {
            self.logger.warn("message capping notification missing payload");
            return;
        };
        self.logger.info("received message capping update");
        self.ev.emit(BaileysEvent::MessageCappingUpdate(parse_new_chat_message_cap(payload)));
    }
    fn handle_legacy_mex_newsletter_notification(&self, node: &BinaryNode) -> Result<()> {
        let mex_node = get_binary_node_child(Some(node), "mex");
        let payload_node = match mex_node.filter(|m| m.content.is_some()) {
            Some(m) => Some(m),
            None => get_binary_node_child(Some(node), "update").or_else(|| get_all_binary_node_children(node).first()),
        };
        let Some(payload_node) = payload_node.filter(|p| p.content.is_some()) else {
            self.logger.warn("invalid mex newsletter notification");
            return Ok(());
        };
        if matches!(payload_node.content, Some(Content::Nodes(_))) {
            self.logger.warn("invalid mex newsletter notification payload format");
            return Ok(());
        }
        let data = match content_string(Some(payload_node)).map(|t| Json::parse(&t)) {
            Some(Ok(j)) => j,
            _ => {
                self.logger.error("failed to parse mex newsletter notification");
                return Ok(());
            }
        };
        let operation = data.get("operation").and_then(Json::as_str).or_else(|| payload_node.attr("op_name"));
        let linked = data.get("data").and_then(|d| d.get("xwa2_notify_linked_profiles")).map(|l| vec![l.clone()]);
        let updates = data.get("updates").and_then(Json::as_arr).or(linked.as_ref());
        let (Some(updates), Some(operation)) = (updates, operation.filter(|o| !o.is_empty())) else {
            self.logger.warn("invalid mex newsletter notification content");
            return Ok(());
        };
        self.logger.info("got mex newsletter notification");
        let text = |u: &Json, k: &str| u.get(k).and_then(Json::as_str).map(str::to_string);
        match operation {
            "NotificationNewsletterUpdate" => {
                for update in updates {
                    if let (Some(id), Some(settings)) = (text(update, "jid"), update.get("settings").filter(|s| matches!(s, Json::Obj(o) if !o.is_empty()))) {
                        self.ev.emit(BaileysEvent::NewsletterSettingsUpdate { id, update: settings.clone() });
                    }
                }
            }
            "NotificationNewsletterAdminPromote" => {
                for update in updates {
                    if let (Some(id), Some(user)) = (text(update, "jid"), text(update, "user")) {
                        self.ev.emit(BaileysEvent::NewsletterParticipantsUpdate { id, author: node.attr("from").unwrap_or_default().to_string(), user, new_role: "ADMIN".to_string(), action: "promote".to_string() });
                    }
                }
            }
            "NotificationLinkedProfilesUpdates" => {
                for update in updates {
                    let lid = text(update, "jid");
                    let mut mappings = Vec::new();
                    for profile in update.get("added_profiles").and_then(Json::as_arr).map_or(&[][..], |a| a.as_slice()) {
                        let pn = profile.as_str().map(str::to_string).or_else(|| text(profile, "pn")).or_else(|| text(profile, "jid"));
                        if let (Some(lid), Some(pn)) = (lid.as_ref().filter(|l| !l.is_empty()), pn.filter(|p| !p.is_empty())) {
                            let mapping = LidMapping { lid: lid.clone(), pn };
                            self.ev.emit(BaileysEvent::LidMappingUpdate(mapping.clone()));
                            mappings.push(mapping);
                        }
                    }
                    self.signal_repository.lid_mapping().store_lid_pn_mappings(&mappings)?;
                }
            }
            _ => self.logger.info(&format!("unhandled mex newsletter notification: {operation}")),
        }
        Ok(())
    }
    /// Handles newsletter notifications
    fn handle_newsletter_notification(&self, node: &BinaryNode) -> Result<()> {
        let from = node.attr("from").unwrap_or_default();
        let author = node.attr("participant").unwrap_or_default();
        for child in get_all_binary_node_children(node) {
            self.logger.debug("got newsletter notification");
            match child.tag.as_str() {
                "reaction" => {
                    self.ev.emit(BaileysEvent::NewsletterReaction {
                        id: from.to_string(),
                        server_id: child.attr("message_id").unwrap_or_default().to_string(),
                        reaction: NewsletterReactionData { code: get_binary_node_child_string(Some(child), "reaction"), count: Some(1), removed: None },
                    });
                }
                "view" => {
                    let count = content_string(Some(child)).filter(|c| !c.is_empty()).and_then(|c| c.trim().parse::<u64>().ok()).unwrap_or(0);
                    self.ev.emit(BaileysEvent::NewsletterView { id: from.to_string(), server_id: child.attr("message_id").unwrap_or_default().to_string(), count });
                }
                "participant" => {
                    self.ev.emit(BaileysEvent::NewsletterParticipantsUpdate {
                        id: from.to_string(),
                        author: author.to_string(),
                        user: child.attr("jid").unwrap_or_default().to_string(),
                        action: child.attr("action").unwrap_or_default().to_string(),
                        new_role: child.attr("role").unwrap_or_default().to_string(),
                    });
                }
                "update" => {
                    if let Some(settings_node) = get_binary_node_child(Some(child), "settings") {
                        let mut update = Vec::new();
                        if let Some(name) = content_string(get_binary_node_child(Some(settings_node), "name")) {
                            update.push(("name".to_string(), Json::Str(name)));
                        }
                        if let Some(description) = content_string(get_binary_node_child(Some(settings_node), "description")) {
                            update.push(("description".to_string(), Json::Str(description)));
                        }
                        self.ev.emit(BaileysEvent::NewsletterSettingsUpdate { id: from.to_string(), update: Json::Obj(update) });
                    }
                }
                "message" => {
                    let plaintext_node = get_binary_node_child(Some(child), "plaintext");
                    let bytes = match plaintext_node.and_then(|p| p.content.as_ref()) {
                        Some(Content::Binary(b)) => Some(b.as_slice().to_vec()),
                        Some(Content::Text(t)) => Some(t.as_str().as_bytes().to_vec()),
                        _ => None,
                    };
                    if let Some(bytes) = bytes {
                        let run = || -> Result<()> {
                            let message_proto = waproto::Message::decode(&bytes)?;
                            let mut key = WAMessageKey::default().with_remote_jid(from).with_from_me(false); // TODO: is this really true though
                            if let Some(id) = child.attr("message_id").filter(|i| !i.is_empty()).or_else(|| child.attr("server_id")) {
                                key.set_id(id);
                            }
                            let full_message = WAMessage::default().with_key(key).with_message(message_proto).with_message_timestamp(attr_num(child.attr("t")) as u64);
                            self.upsert_message(full_message, MessageUpsertType::Append)
                        };
                        match run() {
                            Ok(()) => self.logger.debug("Processed plaintext newsletter message"),
                            Err(error) => self.logger.error(&format!("Failed to decode plaintext newsletter message: {error}")),
                        }
                    }
                }
                _ => self.logger.warn("Unknown newsletter notification child"),
            }
        }
        Ok(())
    }
    pub fn send_message_ack(&self, node: &BinaryNode, error_code: Option<u32>) -> Result<()> {
        let me = self.me_id();
        let stanza = build_ack_stanza(node, error_code, me.as_deref());
        self.logger.debug("sent ack");
        self.send_node(&stanza)
    }
    pub fn reject_call(&self, call_id: &str, call_from: &str) -> Result<()> {
        let me = self.me_id_or_err()?;
        let reject = BinaryNode::tag("reject", Attrs::from([("call-id", call_id), ("call-creator", call_from), ("count", "0")]));
        self.query(BinaryNode::with_nodes("call", Attrs::from([("from", me.as_str()), ("to", call_from)]), vec![reject]), None)?;
        Ok(())
    }
    pub fn send_retry_request(&self, node: &BinaryNode, force_include_keys: bool) -> Result<()> {
        let mut force_include_keys = force_include_keys;
        let (me_id, me_lid) = (self.me_id_or_err()?, self.me_lid().unwrap_or_default());
        let DecodedMessageNode { full_message, .. } = decode_message_node(node, &me_id, &me_lid)?;
        let msg_key = full_message.key().cloned().unwrap_or_default();
        let msg_id = msg_key.id().map_or(String::new(), |i| i.as_str().to_string());
        let mut key = String::with_capacity(msg_id.len() + 24);
        key.push_str(&msg_id);
        key.push(':');
        key.push_str(msg_key.participant().map_or("undefined", |p| p.as_str()));
        let cache = self.recv.msg_retry_cache.as_ref();
        let manager = self.send.message_retry_manager.clone();
        if let Some(m) = &manager {
            // Check if we've exceeded max retries using the new system
            if m.has_exceeded_max_retries(&msg_id) {
                self.logger.debug("reached retry limit with new retry manager, clearing");
                m.mark_retry_failed(&msg_id);
                return Ok(());
            }
            // Increment retry count using new system
            let retry_count = m.increment_retry_count(&msg_id);
            // Use the new retry count for the rest of the logic
            cache_set(cache, &key, retry_count);
        } else {
            // Fallback to old system
            let retry_count = cache_get::<u64>(cache, &key).map_or(0, |v| *v);
            if retry_count >= self.config.max_msg_retry_count as u64 {
                self.logger.debug("reached retry limit, clearing");
                cache.del(&key);
                return Ok(());
            }
            cache_set(cache, &key, retry_count + 1);
        }
        let retry_count = cache_get::<u64>(cache, &key).map_or(1, |v| *v);
        let (account, signed_pre_key, identity_key, registration_id) = {
            let c = self.creds.lock().unwrap();
            (c.account.clone(), c.signed_pre_key.clone(), c.signed_identity_key.clone(), c.registration_id)
        };
        let from_jid = node.attr("from").unwrap_or_default().to_string();
        // Check if we should recreate the session
        let mut should_recreate_session = false;
        if let Some(m) = manager.as_ref().filter(|_| self.config.enable_auto_session_recreation && retry_count > 1) {
            let mut run = || -> Result<()> {
                // Check if we have a session with this JID
                let session_id = self.signal_repository.jid_to_signal_protocol_address(&from_jid)?;
                let has_session = self.signal_repository.validate_session(&from_jid);
                let result = m.should_recreate_session(&from_jid, has_session.exists, None);
                should_recreate_session = result.recreate;
                if should_recreate_session {
                    self.logger.debug("recreating session for retry");
                    // Delete existing session to force recreation
                    self.keys.set_one(KeyKind::Session, &session_id, None)?;
                    force_include_keys = true;
                }
                Ok(())
            };
            if let Err(error) = run() {
                self.logger.warn(&format!("failed to check session recreation: {error}"));
            }
        }
        if retry_count <= 2 {
            // Use new retry manager for phone requests if available
            if let Some(m) = &manager {
                // Schedule phone request with delay (like whatsmeow)
                let weak = self.self_weak();
                let scheduled_key = msg_key.clone();
                m.schedule_phone_request(
                    &msg_id,
                    move || {
                        if let Some(s) = upgrade(&weak) {
                            if let Err(error) = s.request_placeholder_resend(&scheduled_key, None) {
                                s.logger.warn(&format!("failed to send scheduled phone request: {error}"));
                            }
                        }
                    },
                    None,
                );
            } else {
                // Fallback to immediate request
                self.request_placeholder_resend(&msg_key, None)?;
                self.logger.debug("sendRetryRequest: requested placeholder resend");
            }
        }
        let account = account.as_ref().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'accountSignatureKey')"))?;
        let device_identity = encode_signed_device_identity(account, true);
        let tx_key = self.me_id().filter(|i| !i.is_empty()).unwrap_or_else(|| "sendRetryRequest".to_string());
        self.transaction(&tx_key, || {
            let mut retry_attrs = Attrs::from([("count", retry_count.to_string())]);
            retry_attrs.set("id", node.attr("id").unwrap_or_default());
            retry_attrs.set("t", node.attr("t").unwrap_or_default());
            retry_attrs.set("v", "1");
            // ADD ERROR FIELD
            retry_attrs.set("error", "0");
            let mut content = vec![BinaryNode::tag("retry", retry_attrs), BinaryNode::with_bytes("registration", Attrs::new(), encode_big_endian(registration_id, 4))];
            let mut attrs = Attrs::from([("id", msg_id.as_str()), ("type", "retry"), ("to", from_jid.as_str())]);
            if let Some(r) = node.attr("recipient").filter(|r| !r.is_empty()) {
                attrs.set("recipient", r);
            }
            if let Some(p) = node.attr("participant").filter(|p| !p.is_empty()) {
                attrs.set("participant", p);
            }
            if retry_count > 1 || force_include_keys || should_recreate_session {
                let creds = self.creds.lock().unwrap().clone();
                let (update, pre_keys) = get_next_pre_keys(&creds, self.keys.as_ref(), 1)?;
                let (key_id, key) = pre_keys.first().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'public')"))?;
                content.push(BinaryNode::with_nodes(
                    "keys",
                    Attrs::new(),
                    vec![
                        BinaryNode::with_bytes("type", Attrs::new(), KEY_BUNDLE_TYPE),
                        BinaryNode::with_bytes("identity", Attrs::new(), identity_key.public),
                        xmpp_pre_key(key, *key_id),
                        xmpp_signed_pre_key(&signed_pre_key),
                        BinaryNode::with_bytes("device-identity", Attrs::new(), device_identity.clone()),
                    ],
                ));
                self.ev.emit(BaileysEvent::CredsUpdate(Box::new(update)));
            }
            self.send_node(&BinaryNode::with_nodes("receipt", attrs, content))?;
            self.logger.info("sent retry receipt");
            Ok(())
        })
    }
    /// Fire-and-forget tctoken re-issuance after a peer's device identity changed.
    /// Mirrors WAWebSendTcTokenWhenDeviceIdentityChange — runs in parallel with
    /// the session refresh (not after it).
    fn reissue_tc_token_after_identity_change(&self, from: &str) {
        let Some(sock) = upgrade(&self.self_weak()) else { return };
        let from = from.to_string();
        sock.on_lane(LaneId::Control, move |s| {
            let run = || -> Result<()> {
                let lid_mapping = s.signal_repository.lid_mapping();
                let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);
                let get_pn = |lid: &str| lid_mapping.get_pn_for_lid(lid);
                let normalized_jid = jid_normalized_user(&from);
                let tc_jid = resolve_tc_token_jid(&normalized_jid, &get_lid)?;
                let sender_ts = match s.keys.get_one(KeyKind::TcToken, &tc_jid)? {
                    Some(KeyValue::TcToken(e)) => e.sender_timestamp,
                    _ => None,
                };
                let Some(sender_ts) = sender_ts.filter(|t| !is_tc_token_expired(Some(*t))) else { return Ok(()) };
                s.logger.debug("identity changed, re-issuing tctoken");
                let issue_to_lid = s.chats.server_props.lid_trusted_token_issue_to_lid.load(Ordering::Relaxed);
                let issue_jid = resolve_issuance_jid(&normalized_jid, issue_to_lid, &get_lid, Some(&get_pn))?;
                let result = s.issue_privacy_tokens(&[issue_jid], Some(sender_ts as i64))?;
                let empty = BinaryNode::tag("iq", Attrs::new());
                let track = |jid: &str| s.track_tc_token_jid(jid);
                store_tc_tokens_from_iq_result(result.as_ref().unwrap_or(&empty), &tc_jid, s.keys.as_ref(), &get_lid, Some(&track))
            };
            if let Err(err) = run() {
                s.logger.debug(&format!("failed to re-issue tctoken after identity change: {err}"));
            }
        });
    }
    fn handle_encrypt_notification(&self, node: &BinaryNode) -> Result<()> {
        let from = node.attr("from");
        if from == Some(S_WHATSAPP_NET) {
            let stanza_id = node.attr("id").filter(|i| !i.is_empty());
            if stanza_id.is_some_and(|i| self.recv.in_flight_pre_key_low.lock().unwrap().contains(i)) {
                return Ok(());
            }
            let count = attr_num(get_binary_node_child(Some(node), "count").ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'attrs')"))?.attr("value"));
            let should_upload_more_pre_keys = count < MIN_PREKEY_COUNT as f64;
            self.logger.debug("recv pre-key count");
            if should_upload_more_pre_keys {
                if let Some(i) = stanza_id {
                    self.recv.in_flight_pre_key_low.lock().unwrap().insert(i.to_string());
                }
                let r = upgrade(&self.self_weak()).ok_or_else(super::socket::connection_closed).and_then(|s| s.upload_pre_keys(None));
                if let Some(i) = stanza_id {
                    self.recv.in_flight_pre_key_low.lock().unwrap().remove(i);
                }
                r?;
            }
        } else {
            let (w1, w2, w3) = (self.self_weak(), self.self_weak(), self.self_weak());
            let result = handle_identity_change(
                node,
                &IdentityChangeContext {
                    me_id: self.me_id(),
                    me_lid: self.me_lid(),
                    validate_session: Arc::new(move |jid: &str| match upgrade(&w1) {
                        Some(s) => Ok(s.signal_repository.validate_session(jid)),
                        None => Err(super::socket::connection_closed()),
                    }),
                    assert_sessions: Arc::new(move |jids: &[String], force: bool| match upgrade(&w2) {
                        Some(s) => s.assert_sessions(jids, force),
                        None => Err(super::socket::connection_closed()),
                    }),
                    debounce_cache: self.recv.identity_assert_debounce.clone(),
                    logger: self.logger.clone(),
                    on_before_session_refresh: Some(Arc::new(move |from: &str| {
                        if let Some(s) = upgrade(&w3) {
                            s.reissue_tc_token_after_identity_change(from);
                        }
                    })),
                },
            )?;
            if result == IdentityChangeResult::NoIdentityNode {
                self.logger.info("unknown encrypt notification");
            }
        }
        Ok(())
    }
    fn handle_group_notification(&self, full_node: &BinaryNode, child: Option<&BinaryNode>, result: &mut NotificationResult) -> Result<()> {
        // TODO: Support PN/LID (Here is only LID now)
        let Some(child) = child else { return Ok(()) };
        let acting_participant_lid = full_node.attr("participant");
        let acting_participant_pn = full_node.attr("participant_pn");
        let acting_participant_username = full_node.attr("participant_username");
        let first = get_binary_node_child(Some(child), "participant");
        let affected_participant_lid = first.and_then(|p| p.attr("jid")).filter(|j| !j.is_empty()).or(acting_participant_lid);
        let affected_participant_pn = first.and_then(|p| p.attr("phone_number")).filter(|j| !j.is_empty()).or(acting_participant_pn);
        let msg = &mut result.msg;
        let lid_pn_json = |lid: Option<&str>, pn: Option<&str>| {
            let mut o = Vec::new();
            if let Some(l) = lid {
                o.push(("lid".to_string(), jstr(l)));
            }
            if let Some(p) = pn {
                o.push(("pn".to_string(), jstr(p)));
            }
            Json::Obj(o).stringify()
        };
        let tag = child.tag.as_str();
        match tag {
            "create" => {
                let metadata = extract_group_metadata(child)?;
                msg.set_message_stub_type(StubType::GROUP_CREATE);
                msg.set_message_stub_parameters(vec![Str::from(metadata.subject.as_str())]);
                result.key.participant = Some(metadata.owner.clone());
                result.key.participant_alt = Some(metadata.owner_pn.clone());
                result.any = true;
                let mut chat = Chat::new();
                chat.set_id(metadata.id.as_str());
                chat.set_name(metadata.subject.as_str());
                if let Some(c) = metadata.creation {
                    chat.set_conversation_timestamp(c);
                }
                self.ev.emit(BaileysEvent::ChatsUpsert(vec![chat]));
                let mut group = metadata;
                group.author = acting_participant_lid.map(str::to_string);
                group.author_pn = acting_participant_pn.map(str::to_string);
                group.author_username = acting_participant_username.map(str::to_string);
                self.ev.emit(BaileysEvent::GroupsUpsert(vec![group]));
            }
            "ephemeral" | "not_ephemeral" => {
                let expiration = attr_num(Some(child.attr("expiration").filter(|e| !e.is_empty()).unwrap_or("0")));
                msg.set_message(waproto::Message::default().with_protocol_message(ProtocolMessage::default().with_type(ProtocolType::EPHEMERAL_SETTING).with_ephemeral_expiration(expiration as u32)));
                result.any = true;
            }
            "modify" => {
                let old_number = get_binary_node_children(Some(child), "participant").into_iter().map(|p| p.attr("jid").unwrap_or_default().to_string()).collect();
                msg.set_message_stub_parameters(str_list(old_number));
                msg.set_message_stub_type(StubType::GROUP_PARTICIPANT_CHANGE_NUMBER);
                result.any = true;
            }
            "promote" | "demote" | "remove" | "add" | "leave" => {
                let stub = match tag {
                    "promote" => StubType::GROUP_PARTICIPANT_PROMOTE,
                    "demote" => StubType::GROUP_PARTICIPANT_DEMOTE,
                    "remove" => StubType::GROUP_PARTICIPANT_REMOVE,
                    "add" => StubType::GROUP_PARTICIPANT_ADD,
                    _ => StubType::GROUP_PARTICIPANT_LEAVE,
                };
                msg.set_message_stub_type(stub);
                let nodes = get_binary_node_children(Some(child), "participant");
                let participants: Vec<GroupParticipant> = nodes.iter().map(|n| parse_group_participant(n)).collect();
                // if recv. "remove" message and sender removed themselves
                // mark as left
                if let [only] = participants.as_slice() {
                    if tag == "remove" && (are_jids_same_user(Some(&only.id), acting_participant_lid) || are_jids_same_user(Some(&only.id), acting_participant_pn)) {
                        msg.set_message_stub_type(StubType::GROUP_PARTICIPANT_LEAVE);
                    }
                }
                let params = participants
                    .iter()
                    .map(|a| {
                        let mut o = vec![("id".to_string(), jstr(&a.id))];
                        for (k, v) in [("phoneNumber", &a.phone_number), ("lid", &a.lid), ("username", &a.username)] {
                            if let Some(v) = v {
                                o.push((k.to_string(), jstr(v)));
                            }
                        }
                        o.push(("admin".to_string(), a.admin.flatten().map_or(Json::Null, |g| jstr(g.as_str()))));
                        Json::Obj(o).stringify()
                    })
                    .collect();
                msg.set_message_stub_parameters(str_list(params));
                result.any = true;
            }
            "subject" => {
                msg.set_message_stub_type(StubType::GROUP_CHANGE_SUBJECT);
                msg.set_message_stub_parameters(vec![Str::from(child.attr("subject").unwrap_or_default())]);
                result.any = true;
            }
            "description" => {
                let description = content_string(get_binary_node_child(Some(child), "body")).filter(|d| !d.is_empty());
                msg.set_message_stub_type(StubType::GROUP_CHANGE_DESCRIPTION);
                if let Some(d) = description {
                    msg.set_message_stub_parameters(vec![Str::from(d.as_str())]);
                }
                result.any = true;
            }
            "announcement" | "not_announcement" => {
                msg.set_message_stub_type(StubType::GROUP_CHANGE_ANNOUNCE);
                msg.set_message_stub_parameters(vec![Str::from(if tag == "announcement" { "on" } else { "off" })]);
                result.any = true;
            }
            "locked" | "unlocked" => {
                msg.set_message_stub_type(StubType::GROUP_CHANGE_RESTRICT);
                msg.set_message_stub_parameters(vec![Str::from(if tag == "locked" { "on" } else { "off" })]);
                result.any = true;
            }
            "invite" => {
                msg.set_message_stub_type(StubType::GROUP_CHANGE_INVITE_LINK);
                msg.set_message_stub_parameters(vec![Str::from(child.attr("code").unwrap_or_default())]);
                result.any = true;
            }
            "member_add_mode" => {
                if let Some(add_mode) = content_string(Some(child)) {
                    msg.set_message_stub_type(StubType::GROUP_MEMBER_ADD_MODE);
                    msg.set_message_stub_parameters(vec![Str::from(add_mode.as_str())]);
                    result.any = true;
                }
            }
            "membership_approval_mode" => {
                if let Some(approval_mode) = get_binary_node_child(Some(child), "group_join") {
                    msg.set_message_stub_type(StubType::GROUP_MEMBERSHIP_JOIN_APPROVAL_MODE);
                    msg.set_message_stub_parameters(vec![Str::from(approval_mode.attr("state").unwrap_or_default())]);
                    result.any = true;
                }
            }
            "created_membership_requests" => {
                msg.set_message_stub_type(StubType::GROUP_MEMBERSHIP_JOIN_APPROVAL_REQUEST_NON_ADMIN_ADD);
                msg.set_message_stub_parameters(vec![Str::from(lid_pn_json(affected_participant_lid, affected_participant_pn).as_str()), Str::from("created"), Str::from(child.attr("request_method").unwrap_or_default())]);
                result.any = true;
            }
            "revoked_membership_requests" => {
                let is_denied = are_jids_same_user(affected_participant_lid, acting_participant_lid);
                // TODO: LIDMAPPING SUPPORT
                msg.set_message_stub_type(StubType::GROUP_MEMBERSHIP_JOIN_APPROVAL_REQUEST_NON_ADMIN_ADD);
                msg.set_message_stub_parameters(vec![Str::from(lid_pn_json(affected_participant_lid, affected_participant_pn).as_str()), Str::from(if is_denied { "revoked" } else { "rejected" })]);
                result.any = true;
            }
            _ => {}
        }
        Ok(())
    }
    fn handle_devices_notification(&self, node: &BinaryNode) -> Result<()> {
        let child = get_all_binary_node_children(node).first();
        let from = jid_normalized_user(node.attr("from").unwrap_or_default());
        let Some(child) = child else {
            self.logger.debug("devices notification missing child, skipping");
            return Ok(());
        };
        let tag = child.tag.as_str();
        let devices = get_binary_node_children(Some(child), "device");
        let me = self.user();
        if are_jids_same_user(Some(&from), me.as_ref().map(|m| m.id.as_str())) || are_jids_same_user(Some(&from), me.as_ref().and_then(|m| m.lid.as_deref())) {
            self.logger.info("got my own devices");
        }
        if devices.is_empty() {
            self.logger.debug("no devices in notification, skipping");
            return Ok(());
        }
        // user, then the entries of the user
        let mut by_user: JsMap<Vec<(String, crate::utils::signal::DeviceJid)>> = JsMap::new();
        for d in devices {
            let Some(jid) = d.attr("jid").filter(|j| !j.is_empty()) else { continue };
            let Some(parts) = jid_decode(jid) else {
                self.logger.debug("failed to decode device jid, skipping");
                continue;
            };
            let entry = (jid.to_string(), crate::utils::signal::DeviceJid { user: parts.user.to_string(), device: parts.device, domain_type: parts.domain_type, server: parts.server.to_string() });
            if let Some(l) = by_user.get_mut(parts.user) {
                l.push(entry);
            } else {
                by_user.insert(parts.user, vec![entry]);
            }
        }
        if by_user.is_empty() {
            return Ok(());
        }
        let cache = self.send.user_devices_cache.as_ref();
        self.send.devices_mutex.mutex(|| -> Result<()> {
            for (user, entries) in by_user.iter() {
                if tag == "update" {
                    self.logger.debug("device list updated, dropping cached devices");
                    cache.del(user);
                    continue;
                }
                if tag == "remove" {
                    let jids: Vec<String> = entries.iter().map(|e| e.0.clone()).collect();
                    self.signal_repository.delete_session(&jids)?;
                }
                let existing_cache: Vec<crate::utils::signal::DeviceJid> = cache_get::<Vec<crate::utils::signal::DeviceJid>>(cache, user).map_or_else(Vec::new, |v| (*v).clone());
                if existing_cache.is_empty() {
                    // No baseline yet; skip applying the delta so getUSyncDevices can
                    // later fetch the full device list. Caching just the notification
                    // entries would make a partial list look authoritative.
                    self.logger.debug("device list not cached, deferring to USync refresh");
                    continue;
                }
                let affected: Vec<Option<u32>> = entries.iter().map(|e| e.1.device).collect();
                let mut updated_devices: Vec<crate::utils::signal::DeviceJid> = existing_cache.into_iter().filter(|d| !affected.contains(&d.device)).collect();
                match tag {
                    "add" => {
                        self.logger.info("devices added");
                        updated_devices.extend(entries.iter().map(|e| e.1.clone()));
                    }
                    "remove" => self.logger.info("devices removed"),
                    _ => {
                        self.logger.debug("Unknown device list change tag");
                        continue;
                    }
                }
                if updated_devices.is_empty() {
                    cache.del(user);
                } else {
                    cache_set(cache, user, updated_devices);
                }
            }
            Ok(())
        })
    }
    fn process_notification(&self, node: &BinaryNode) -> Result<Option<NotificationResult>> {
        let mut result = NotificationResult::default();
        let child = get_all_binary_node_children(node).first();
        let from = jid_normalized_user(node.attr("from").unwrap_or_default());
        match node.attr("type") {
            Some("newsletter") => self.handle_newsletter_notification(node)?,
            Some("mex") => self.handle_mex_notification(node)?,
            // TODO: HANDLE PARTICIPANT_PN
            Some("w:gp2") => self.handle_group_notification(node, child, &mut result)?,
            Some("mediaretry") => {
                let event = decode_media_retry_node(node)?;
                self.ev.emit(BaileysEvent::MessagesMediaUpdate(vec![event]));
            }
            Some("encrypt") => self.handle_encrypt_notification(node)?,
            Some("devices") => {
                if let Err(error) = self.handle_devices_notification(node) {
                    self.logger.error(&format!("failed to handle devices notification: {error}"));
                }
            }
            Some("server_sync") => {
                if let Some(update) = get_binary_node_child(Some(node), "collection") {
                    if let Some(name) = update.attr("name").and_then(WAPatchName::parse) {
                        self.resync_app_state(&[name], false)?;
                    }
                }
            }
            Some("picture") => {
                let set_picture = get_binary_node_child(Some(node), "set");
                let del_picture = get_binary_node_child(Some(node), "delete");
                // TODO: WAJIDHASH stuff proper support inhouse
                let id = if from.is_empty() { set_picture.or(del_picture).and_then(|n| n.attr("hash")).unwrap_or_default().to_string() } else { from.clone() };
                let mut contact = Contact::new(id);
                contact.img_url = Some(Some(if set_picture.is_some() { "changed" } else { "removed" }.to_string()));
                self.ev.emit(BaileysEvent::ContactsUpdate(vec![ContactUpdate::new(contact)]));
                if is_jid_group(&from) {
                    let n = set_picture.or(del_picture);
                    result.msg.set_message_stub_type(StubType::GROUP_CHANGE_ICON);
                    if let Some(s) = set_picture {
                        result.msg.set_message_stub_parameters(vec![Str::from(s.attr("id").unwrap_or_default())]);
                    }
                    if let Some(a) = n.and_then(|x| x.attr("author")) {
                        result.msg.set_participant(a);
                    }
                    result.key.participant = Some(set_picture.and_then(|s| s.attr("author")).map(str::to_string));
                    result.any = true;
                }
            }
            Some("account_sync") => {
                let child = child.ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'tag')"))?;
                if child.tag.as_str() == "disappearing_mode" {
                    let new_duration = attr_num(child.attr("duration"));
                    let timestamp = attr_num(child.attr("t"));
                    self.logger.info("updated account disappearing mode");
                    let mut account_settings = self.creds.lock().unwrap().account_settings.clone();
                    account_settings.default_disappearing_mode = Some(DefaultDisappearingMode { ephemeral_expiration: Some(new_duration as u32), ephemeral_setting_timestamp: Some(timestamp as u64) });
                    self.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { account_settings: Some(account_settings), ..CredsUpdate::default() })));
                } else if child.tag.as_str() == "blocklist" {
                    for item in get_binary_node_children(Some(child), "item") {
                        let blocklist = vec![item.attr("jid").unwrap_or_default().to_string()];
                        let r#type = if item.attr("action") == Some("block") { ListUpdateType::Add } else { ListUpdateType::Remove };
                        self.ev.emit(BaileysEvent::BlocklistUpdate { blocklist, r#type });
                    }
                }
            }
            Some("link_code_companion_reg") => self.handle_link_code_companion_reg(node)?,
            Some("privacy_token") => self.handle_privacy_token_notification(node)?,
            _ => {}
        }
        Ok(result.any.then_some(result))
    }
    fn handle_link_code_companion_reg(&self, node: &BinaryNode) -> Result<()> {
        let link_code_companion_reg = get_binary_node_child(Some(node), "link_code_companion_reg");
        let reference = to_required_buffer(get_binary_node_child_buffer(link_code_companion_reg, "link_code_pairing_ref"))?;
        let primary_identity_public_key = to_required_buffer(get_binary_node_child_buffer(link_code_companion_reg, "primary_identity_pub"))?;
        let primary_ephemeral_public_key_wrapped = to_required_buffer(get_binary_node_child_buffer(link_code_companion_reg, "link_code_pairing_wrapped_primary_ephemeral_pub"))?;
        let code_pairing_public_key = self.decipher_link_public_key(primary_ephemeral_public_key_wrapped.as_slice())?;
        let (pairing_private, identity) = {
            let c = self.creds.lock().unwrap();
            (c.pairing_ephemeral_key_pair.private, c.signed_identity_key.clone())
        };
        let companion_shared_key = crypto::shared_key(&pairing_private, &code_pairing_public_key)?;
        let mut random = [0u8; 32];
        crypto::random_bytes(&mut random);
        let mut link_code_salt = [0u8; 32];
        crypto::random_bytes(&mut link_code_salt);
        let link_code_pairing_expanded = crypto::hkdf(&companion_shared_key, 32, Some(&link_code_salt), b"link_code_pairing_key_bundle_encryption_key");
        let encrypt_payload = [&identity.public[..], primary_identity_public_key.as_slice(), &random[..]].concat();
        let mut encrypt_iv = [0u8; 12];
        crypto::random_bytes(&mut encrypt_iv);
        let encrypted = crypto::aes_encrypt_gcm(&encrypt_payload, &link_code_pairing_expanded, &encrypt_iv, &[])?;
        let encrypted_payload = [&link_code_salt[..], &encrypt_iv[..], &encrypted[..]].concat();
        let identity_shared_key = crypto::shared_key(&identity.private, primary_identity_public_key.as_slice())?;
        let identity_payload = [&companion_shared_key[..], &identity_shared_key[..], &random[..]].concat();
        let adv = waproto::pb::base64_encode(&crypto::hkdf(&identity_payload, 32, None, b"adv_secret"));
        // here upstream changes the creds in place, and saves them with the emit after the query
        self.creds.lock().unwrap().adv_secret_key = adv.clone();
        let me_id = self.me_id().unwrap_or_default();
        let content = vec![BinaryNode::with_bytes("link_code_pairing_wrapped_key_bundle", Attrs::new(), encrypted_payload), BinaryNode::with_bytes("companion_identity_public", Attrs::new(), identity.public), BinaryNode::with_bytes("link_code_pairing_ref", Attrs::new(), reference.clone())];
        let mut attrs = Attrs::new();
        attrs.set("to", S_WHATSAPP_NET);
        attrs.set("type", "set");
        attrs.set("id", self.generate_message_tag());
        attrs.set("xmlns", "md");
        self.query(BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::with_nodes("link_code_companion_reg", Attrs::from([("jid", me_id.as_str()), ("stage", "companion_finish")]), content)]), None)?;
        self.emit_creds_fields(CredsUpdate { registered: Some(true), adv_secret_key: Some(adv), ..CredsUpdate::default() });
        Ok(())
    }
    fn flush_tc_token_index(&self) -> Result<()> {
        if let Some(t) = self.recv.tc_token_index_timer.lock().unwrap().take() {
            t.cancel();
        }
        // Merge with whatever is already persisted so we don't clobber writes from other
        // paths (history sync, concurrent sessions on the same store).
        let known: Vec<String> = self.recv.tc_token_known_jids.lock().unwrap().iter().cloned().collect();
        let write = build_merged_tc_token_index_write(self.keys.as_ref(), &known)?;
        self.keys.set_one(KeyKind::TcToken, TC_TOKEN_INDEX_KEY, Some(KeyValue::TcToken(write)))
    }
    fn schedule_tc_token_index_save(&self) {
        let mut g = self.recv.tc_token_index_timer.lock().unwrap();
        if let Some(t) = g.take() {
            t.cancel();
        }
        let weak = self.self_weak();
        *g = Some(set_timeout(5000, move || {
            let Some(s) = upgrade(&weak) else { return };
            s.recv.tc_token_index_timer.lock().unwrap().take();
            if let Err(err) = s.flush_tc_token_index() {
                s.logger.warn(&format!("failed to save tctoken index: {err}"));
            }
        }));
    }
    fn track_tc_token_jid(&self, jid: &str) {
        if !jid.is_empty() && jid != TC_TOKEN_INDEX_KEY && self.recv.tc_token_known_jids.lock().unwrap().insert(jid.to_string()) {
            self.schedule_tc_token_index_save();
        }
    }
    fn handle_privacy_token_notification(&self, node: &BinaryNode) -> Result<()> {
        if get_binary_node_child(Some(node), "tokens").is_none() {
            return Ok(());
        }
        let from = jid_normalized_user(node.attr("from").unwrap_or_default());
        let lid_mapping = self.signal_repository.lid_mapping();
        let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);
        // WA Web uses: senderLid ?? toLid(from) for the storage key
        // The sender_lid attribute provides the LID directly when available
        let sender_lid = node.attr("sender_lid").filter(|l| !l.is_empty() && is_lid_user(&jid_normalized_user(l))).map(jid_normalized_user);
        let fallback_jid = match sender_lid {
            Some(l) => l,
            None => resolve_tc_token_jid(&from, &get_lid)?,
        };
        self.logger.debug("processing privacy token notification");
        let track = |jid: &str| self.track_tc_token_jid(jid);
        store_tc_tokens_from_iq_result(node, &fallback_jid, self.keys.as_ref(), &get_lid, Some(&track))
    }
    fn decipher_link_public_key(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 80 {
            return Err(Boom::status("Invalid buffer", 400));
        }
        let salt = &data[..32];
        let code = self.creds.lock().unwrap().pairing_code.clone().unwrap_or_default();
        let secret_key = crypto::derive_pairing_code_key(&code, salt);
        crypto::aes_decrypt_ctr(&data[48..80], &secret_key, &data[32..48])
    }
    fn retry_key(id: &str, participant: &str) -> String {
        let mut key = String::with_capacity(id.len() + participant.len() + 1);
        key.push_str(id);
        key.push(':');
        key.push_str(participant);
        key
    }
    fn will_send_message_again(&self, id: &str, participant: &str) -> bool {
        let retry_count = cache_get::<u64>(self.recv.msg_retry_cache.as_ref(), &Self::retry_key(id, participant)).map_or(0, |v| *v);
        retry_count < self.config.max_msg_retry_count as u64
    }
    fn update_send_message_again_count(&self, id: &str, participant: &str) {
        let key = Self::retry_key(id, participant);
        let cache = self.recv.msg_retry_cache.as_ref();
        let new_value = cache_get::<u64>(cache, &key).map_or(0, |v| *v) + 1;
        cache_set(cache, &key, new_value);
    }
    fn send_messages_again(&self, key: &WAMessageKey, ids: &[String], retry_node: Option<&BinaryNode>, receipt_node: &BinaryNode) -> Result<()> {
        let remote_jid = key.remote_jid().map_or("", |s| s.as_str());
        let participant = key.participant().map(|p| p.as_str()).filter(|p| !p.is_empty()).unwrap_or(remote_jid);
        let count_attr = retry_node.and_then(|r| r.attr("count"));
        let retry_count_raw = attr_num(count_attr);
        let retry_count = if retry_count_raw.is_nan() || retry_count_raw == 0.0 { 1 } else { retry_count_raw as u32 };
        let msg_id = ids.first().map(String::as_str).filter(|i| !i.is_empty());
        let manager = self.send.message_retry_manager.as_ref();
        // Try to get messages from cache first, then fallback to getMessage
        let mut msgs: Vec<Option<waproto::Message>> = Vec::with_capacity(ids.len());
        for id in ids {
            let mut msg = None;
            // Try to get from retry cache first if enabled
            if let Some(m) = manager {
                if let Some(cached) = m.get_recent_message(remote_jid, id) {
                    msg = Some(cached.message.clone());
                    self.logger.debug("found message in retry cache");
                    // Mark retry as successful since we found the message
                    m.mark_retry_success(id);
                }
            }
            // Fallback to getMessage if not found in cache
            if msg.is_none() {
                let mut lookup = key.clone();
                lookup.set_id(id.as_str());
                msg = (self.config.get_message)(&lookup);
                if msg.is_some() {
                    self.logger.debug("found message via getMessage");
                    // Also mark as successful if found via getMessage
                    if let Some(m) = manager {
                        m.mark_retry_success(id);
                    }
                }
            }
            msgs.push(msg);
        }
        // if it's the primary jid sending the request
        // just re-send the message to everyone
        // prevents the first message decryption failure
        let send_to_all = jid_decode(participant).and_then(|d| d.device).unwrap_or(0) == 0;
        let session_id = self.signal_repository.jid_to_signal_protocol_address(participant)?;
        let mut injected_from_bundle = false;
        if let Some(bundle) = extract_e2e_session_from_retry_receipt(receipt_node) {
            match self.signal_repository.inject_e2e_session(participant, &bundle.as_session()) {
                Ok(()) => {
                    injected_from_bundle = true;
                    self.logger.debug("injected session from retry receipt key bundle");
                }
                Err(error) => self.logger.warn(&format!("failed to inject session from retry receipt: {error}")),
            }
        }
        if !injected_from_bundle {
            if let Some(received_reg_id) = get_binary_node_child_uint(Some(receipt_node), "registration", 4) {
                if let Some((_, stored)) = self.signal_repository.get_session_info(participant)? {
                    if stored != 0 && stored != received_reg_id {
                        self.logger.info("reg id mismatch on retry without bundle, deleting session");
                        self.keys.set_one(KeyKind::Session, &session_id, None)?;
                    }
                }
            }
        }
        const BASE_KEY_CHECK_RETRY: u32 = 2;
        if let (Some(id), Some(m)) = (msg_id, manager) {
            if let Some((base_key, _)) = self.signal_repository.get_session_info(participant)? {
                if retry_count == BASE_KEY_CHECK_RETRY {
                    m.save_base_key(&session_id, id, &base_key);
                } else if retry_count > BASE_KEY_CHECK_RETRY {
                    if m.has_same_base_key(&session_id, id, &base_key) {
                        self.logger.warn("base key collision on retry, forcing fresh session");
                        self.keys.set_one(KeyKind::Session, &session_id, None)?;
                    }
                    m.delete_base_key(&session_id, id);
                }
            }
        }
        if let Some(m) = manager.filter(|_| self.config.enable_auto_session_recreation && retry_count > 1 && !injected_from_bundle) {
            let run = || -> Result<()> {
                let has_session = self.signal_repository.validate_session(participant);
                let result = m.should_recreate_session(participant, has_session.exists, None);
                if result.recreate {
                    self.logger.debug("recreating session for outgoing retry");
                    self.keys.set_one(KeyKind::Session, &session_id, None)?;
                }
                Ok(())
            };
            if let Err(error) = run() {
                self.logger.warn(&format!("failed to check session recreation for outgoing retry: {error}"));
            }
        }
        if !injected_from_bundle {
            self.assert_sessions(&[participant.to_string()], true)?;
        }
        if is_jid_group(remote_jid) {
            self.keys.set_one(KeyKind::SenderKeyMemory, remote_jid, None)?;
        }
        self.logger.debug("prepared session for retry resend");
        for (i, msg) in msgs.iter().enumerate() {
            let id = &ids[i];
            if id.is_empty() {
                continue;
            }
            match msg.as_ref().filter(|_| self.will_send_message_again(id, participant)) {
                Some(m) => {
                    self.update_send_message_again_count(id, participant);
                    let mut opts = MessageRelayOptions { message_id: Some(id.clone()), ..MessageRelayOptions::default() };
                    if send_to_all {
                        opts.use_user_devices_cache = Some(false);
                    } else {
                        opts.participant = Some(RelayParticipant { jid: participant.to_string(), count: if retry_count_raw.is_nan() { 0 } else { retry_count_raw as u32 } });
                    }
                    self.relay_message(remote_jid, m, opts)?;
                }
                None => self.logger.debug("recv retry request, but message not available"),
            }
        }
        Ok(())
    }
    fn handle_receipt(&self, node: &BinaryNode) -> Result<()> {
        let from = node.attr("from").unwrap_or_default();
        let is_lid = from.contains("lid");
        let me = self.user();
        let attr_participant = node.attr("participant");
        let is_node_from_me = are_jids_same_user(attr_participant.filter(|p| !p.is_empty()).or(Some(from)), if is_lid { me.as_ref().and_then(|m| m.lid.as_deref()) } else { me.as_ref().map(|m| m.id.as_str()) });
        let remote_jid = if !is_node_from_me || is_jid_group(from) { Some(from) } else { node.attr("recipient") };
        let attr_type = node.attr("type");
        let recipient = node.attr("recipient").filter(|r| !r.is_empty());
        let from_me = recipient.is_none() || (matches!(attr_type, Some("retry") | Some("sender")) && is_node_from_me);
        let mut key = WAMessageKey::default().with_id("").with_from_me(from_me);
        if let Some(r) = remote_jid {
            key.set_remote_jid(r);
        }
        if let Some(p) = attr_participant {
            key.set_participant(p);
        }
        let mut ids = vec![node.attr("id").unwrap_or_default().to_string()];
        if let Some(Content::Nodes(content)) = &node.content {
            if let Some(first) = content.first() {
                ids.extend(get_binary_node_children(Some(first), "item").into_iter().map(|i| i.attr("id").unwrap_or_default().to_string()));
            }
        }
        let with_id = |id: &String| {
            let mut k = key.clone();
            k.set_id(id.as_str());
            k
        };
        let r = self.chats.receipt_mutex.mutex(|| -> Result<()> {
            let status = get_status_from_receipt_type(attr_type);
            // basically, we only want to know when a message from us has been delivered to/read by the other person
            // or another device of ours has read some messages
            if let Some(status) = status.filter(|s| s.0 >= Status::SERVER_ACK.0 || !is_node_from_me) {
                let rj = remote_jid.unwrap_or_default();
                if is_jid_group(rj) || is_jid_status_broadcast(rj) {
                    if let Some(p) = attr_participant.filter(|p| !p.is_empty()) {
                        let t = attr_num(node.attr("t")) as i64;
                        let updates = ids
                            .iter()
                            .map(|id| {
                                let mut receipt = MessageUserReceipt::default().with_user_jid(jid_normalized_user(p));
                                if status == Status::DELIVERY_ACK {
                                    receipt.set_receipt_timestamp(t);
                                } else {
                                    receipt.set_read_timestamp(t);
                                }
                                MessageUserReceiptUpdate { key: with_id(id), receipt }
                            })
                            .collect();
                        self.ev.emit(BaileysEvent::MessageReceiptUpdate(updates));
                    }
                } else {
                    let t = attr_num(Some(node.attr("t").unwrap_or("0"))) as u64;
                    self.ev.emit(BaileysEvent::MessagesUpdate(ids.iter().map(|id| WAMessageUpdate { key: with_id(id), update: WAMessage::default().with_status(status).with_message_timestamp(t) }).collect()));
                }
            }
            if attr_type == Some("retry") {
                // correctly set who is asking for the retry
                let mut retry_key = key.clone();
                if key.participant().is_none_or(|p| p.as_str().is_empty()) {
                    retry_key.set_participant(from);
                }
                let participant = retry_key.participant().map_or("", |p| p.as_str()).to_string();
                let retry_node = get_binary_node_child(Some(node), "retry");
                if !ids[0].is_empty() && !participant.is_empty() && self.will_send_message_again(&ids[0], &participant) {
                    if from_me {
                        self.update_send_message_again_count(&ids[0], &participant);
                        self.logger.debug("recv retry request");
                        if let Err(error) = self.send_messages_again(&retry_key, &ids, retry_node, node) {
                            self.logger.error(&format!("error in sending message again: {error}"));
                        }
                    } else {
                        self.logger.info("recv retry for not fromMe message");
                    }
                } else {
                    self.logger.info("will not send message again, as sent too many times");
                }
            }
            Ok(())
        });
        if let Err(ack_err) = self.send_message_ack(node, None) {
            self.logger.error(&format!("failed to ack receipt: {ack_err}"));
        }
        r
    }
    fn handle_notification(&self, node: &BinaryNode) -> Result<()> {
        let remote_jid = node.attr("from");
        let r = self.chats.notification_mutex.mutex(|| -> Result<()> {
            let Some(result) = self.process_notification(node)? else { return Ok(()) };
            let NotificationResult { mut msg, key: k, .. } = result;
            let me = self.me_id_or_err()?;
            let from_me = are_jids_same_user(node.attr("participant").filter(|p| !p.is_empty()).or(remote_jid), Some(&me));
            let ctx = extract_addressing_context(node);
            let mut key = WAMessageKey::default().with_from_me(from_me);
            if let Some(v) = remote_jid {
                key.set_remote_jid(v);
            }
            let participant = match k.participant {
                Some(over) => over,
                None => node.attr("participant").map(str::to_string),
            };
            if let Some(v) = participant {
                key.set_participant(v.as_str());
            }
            let participant_alt = match k.participant_alt {
                Some(over) => over,
                None => ctx.sender_alt.map(str::to_string),
            };
            if let Some(v) = participant_alt {
                key.set_participant_alt(v.as_str());
            }
            if let Some(v) = node.attr("participant_username") {
                key.set_participant_username(v);
            }
            key.set_addressing_mode(ctx.addressing_mode);
            if let Some(v) = node.attr("id") {
                key.set_id(v);
            }
            msg.set_key(key);
            if msg.participant().is_none() {
                if let Some(p) = node.attr("participant") {
                    msg.set_participant(p);
                }
            }
            msg.set_message_timestamp(attr_num(node.attr("t")) as u64);
            self.upsert_message(msg, MessageUpsertType::Append)
        });
        if let Err(ack_err) = self.send_message_ack(node, None) {
            self.logger.error(&format!("failed to ack notification: {ack_err}"));
        }
        r
    }
    fn handle_message(&self, node: &BinaryNode) -> Result<()> {
        let enc_node = get_binary_node_child(Some(node), "enc");
        // TODO: temporary fix for crashes and issues resulting of failed msmsg decryption
        if enc_node.and_then(|e| e.attr("type")) == Some("msmsg") {
            self.logger.debug("ignored msmsg");
            return self.send_message_ack(node, Some(nack_reasons::MISSING_MESSAGE_SECRET));
        }
        let acked = AtomicBool::new(false);
        let run = || -> Result<()> {
            let (me_id, me_lid) = (self.me_id_or_err()?, self.me_lid().unwrap_or_default());
            let mut decrypted = decrypt_message_node(node, &me_id, &me_lid, self.signal_repository.as_ref(), self.logger.as_ref())?;
            {
                let k = decrypted.full_message.key();
                let alt = k.and_then(|k| k.participant_alt().or_else(|| k.remote_jid_alt())).map(|a| a.as_str()).filter(|a| !a.is_empty());
                // store new mappings we didn't have before
                if let Some(alt) = alt {
                    let primary_jid = k.and_then(|k| k.participant().filter(|p| !p.as_str().is_empty()).or_else(|| k.remote_jid())).map_or("", |p| p.as_str());
                    let lid_mapping = self.signal_repository.lid_mapping();
                    if jid_decode(alt).map(|d| d.server) == Some("lid") {
                        if lid_mapping.get_pn_for_lid(alt)?.is_none() {
                            lid_mapping.store_lid_pn_mappings(&[LidMapping { lid: alt.to_string(), pn: primary_jid.to_string() }])?;
                            self.signal_repository.migrate_session(primary_jid, alt)?;
                        }
                    } else {
                        lid_mapping.store_lid_pn_mappings(&[LidMapping { lid: primary_jid.to_string(), pn: alt.to_string() }])?;
                        self.signal_repository.migrate_session(alt, primary_jid)?;
                    }
                }
            }
            self.chats.message_mutex.mutex(|| -> Result<()> {
                // Upstream uses one transaction per sender here, and `relay_message` uses one per
                // account, so a send and a decrypt can each overwrite the session of the other. On
                // threads that happens often, and the ratchet then fails. One key stops it.
                self.transaction(&me_id, || decrypted.decrypt())?;
                let category = decrypted.category;
                let author = decrypted.author.clone();
                let mut msg = std::mem::take(&mut decrypted.full_message);
                let key = msg.key().cloned().unwrap_or_default();
                let (remote, id) = (key.remote_jid().map_or("", |s| s.as_str()).to_string(), key.id().map_or("", |s| s.as_str()).to_string());
                if let (Some(m), Some(content)) = (&self.send.message_retry_manager, msg.message()) {
                    if !remote.is_empty() && !id.is_empty() {
                        m.add_recent_message(&remote, &id, content.clone());
                    }
                }
                // message failed to decrypt
                if msg.message_stub_type() == Some(StubType::CIPHERTEXT) && msg.category().map(|c| c.as_str()) != Some("peer") {
                    let first_param = msg.message_stub_parameters().first().map(|p| p.as_str().to_string());
                    if first_param.as_deref() == Some(MISSING_KEYS_ERROR_TEXT) {
                        acked.store(true, Ordering::Relaxed);
                        return self.send_message_ack(node, Some(nack_reasons::PARSING_ERROR));
                    }
                    if first_param.as_deref() == Some(NO_MESSAGE_FOUND_ERROR_TEXT) {
                        // Message arrived without encryption (e.g. CTWA ads messages).
                        // Check if this is eligible for placeholder resend (matching WA Web filters).
                        let unavailable_type = get_binary_node_child(Some(node), "unavailable").and_then(|u| u.attr("type"));
                        if matches!(unavailable_type, Some("bot_unavailable_fanout") | Some("hosted_unavailable_fanout") | Some("view_once_unavailable_fanout")) {
                            self.logger.debug("skipping placeholder resend for excluded unavailable type");
                            acked.store(true, Ordering::Relaxed);
                            return self.send_message_ack(node, None);
                        }
                        let message_age = unix_timestamp_seconds(None) - msg.message_timestamp().unwrap_or(0) as i64;
                        if message_age > PLACEHOLDER_MAX_AGE_SECONDS as i64 {
                            self.logger.debug("skipping placeholder resend for old message");
                            acked.store(true, Ordering::Relaxed);
                            return self.send_message_ack(node, None);
                        }
                        // Request the real content from the phone via placeholder resend PDO.
                        // Upsert the CIPHERTEXT stub as a placeholder (like WA Web's processPlaceholderMsg),
                        // and store the requestId in stubParameters[1] so users can correlate
                        // with the incoming PDO response event.
                        let mut clean_key = WAMessageKey::default();
                        if let Some(v) = key.remote_jid() {
                            clean_key.set_remote_jid(v.clone());
                        }
                        if let Some(v) = key.from_me() {
                            clean_key.set_from_me(v);
                        }
                        if let Some(v) = key.id() {
                            clean_key.set_id(v.clone());
                        }
                        if let Some(v) = key.participant() {
                            clean_key.set_participant(v.clone());
                        }
                        // Cache the original message metadata so the PDO response handler
                        // can preserve key fields (LID details etc.) that the phone may omit
                        let mut msg_data = WAMessage::default().with_key(key.clone());
                        if let Some(v) = msg.message_timestamp() {
                            msg_data.set_message_timestamp(v);
                        }
                        if let Some(v) = msg.push_name() {
                            msg_data.set_push_name(v.clone());
                        }
                        if let Some(v) = msg.participant() {
                            msg_data.set_participant(v.clone());
                        }
                        if let Some(v) = msg.verified_biz_name() {
                            msg_data.set_verified_biz_name(v.clone());
                        }
                        if let Some(sock) = upgrade(&self.self_weak()) {
                            let update_key = key.clone();
                            sock.spawn_thread("placeholder-resend", move |s| match s.request_placeholder_resend(&clean_key, Some(msg_data)) {
                                Ok(Some(request_id)) if request_id != "RESOLVED" => {
                                    let update = WAMessage::default().with_message_stub_parameters(vec![Str::from(NO_MESSAGE_FOUND_ERROR_TEXT), Str::from(request_id.as_str())]);
                                    s.ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key: update_key, update }]));
                                }
                                Ok(_) => {}
                                Err(err) => s.logger.warn(&format!("failed to request placeholder resend for unavailable message: {err}")),
                            });
                        }
                        acked.store(true, Ordering::Relaxed);
                        self.send_message_ack(node, None)?;
                        // Don't return — fall through to upsertMessage so the stub is emitted
                    } else {
                        // Skip retry for expired status messages (>24h old)
                        if is_jid_status_broadcast(&remote) {
                            let message_age = unix_timestamp_seconds(None) - msg.message_timestamp().unwrap_or(0) as i64;
                            if message_age > STATUS_EXPIRY_SECONDS as i64 {
                                self.logger.debug("skipping retry for expired status message");
                                acked.store(true, Ordering::Relaxed);
                                return self.send_message_ack(node, None);
                            }
                        }
                        self.logger.debug("[handleMessage] Attempting retry request for failed decryption");
                        // WAWeb only retry-receipts here; server emits PreKeyLow if prekeys run low.
                        self.recv.retry_mutex.mutex(|| -> Result<()> {
                            if !self.ws.is_open() {
                                self.logger.debug("Connection closed, skipping retry");
                                return Ok(());
                            }
                            let enc_node = get_binary_node_child(Some(node), "enc");
                            match self.send_retry_request(node, enc_node.is_none()) {
                                Ok(()) => {
                                    if self.config.retry_request_delay_ms != 0 {
                                        self.sleep_until_closed(self.config.retry_request_delay_ms);
                                    }
                                }
                                Err(err) => self.logger.error(&format!("Failed to send retry: {err}")),
                            }
                            acked.store(true, Ordering::Relaxed);
                            self.send_message_ack(node, Some(nack_reasons::UNHANDLED_ERROR))
                        })?;
                    }
                } else {
                    if let Some(m) = self.send.message_retry_manager.as_ref().filter(|_| !id.is_empty()) {
                        m.cancel_pending_phone_request(&id);
                    }
                    if !is_jid_newsletter(&remote) {
                        // no type in the receipt => message delivered
                        let mut r#type: Option<&str> = None;
                        let mut participant = key.participant().map(|p| p.as_str().to_string());
                        if category == Some("peer") {
                            // special peer message
                            r#type = Some("peer_msg");
                        } else if key.from_me() == Some(true) {
                            // message was sent by us from a different device
                            r#type = Some("sender");
                            // need to specially handle this case
                            if is_lid_user(&remote) || key.remote_jid_alt().is_some_and(|a| is_lid_user(a.as_str())) {
                                participant = Some(author.clone()); // TODO: investigate sending receipts to LIDs and not PNs
                            }
                        } else if !self.recv.send_active_receipts.load(Ordering::Relaxed) {
                            r#type = Some("inactive");
                        }
                        acked.store(true, Ordering::Relaxed);
                        self.send_receipt(&remote, participant.as_deref(), std::slice::from_ref(&id), r#type)?;
                        // send ack for history message
                        if msg.message().and_then(get_history_msg).is_some() {
                            let jid = jid_normalized_user(&remote);
                            self.send_receipt(&jid, None, std::slice::from_ref(&id), Some("hist_sync"))?; // TODO: investigate
                        }
                    } else {
                        acked.store(true, Ordering::Relaxed);
                        self.send_message_ack(node, None)?;
                        self.logger.debug("processed newsletter message without receipts");
                    }
                }
                clean_message(&mut msg, &me_id, &me_lid)?;
                self.upsert_message(msg, if node.attr("offline").is_some_and(|o| !o.is_empty()) { MessageUpsertType::Append } else { MessageUpsertType::Notify })
            })
        };
        if let Err(error) = run() {
            self.logger.error(&format!("error in handling message: {error}"));
            if !acked.load(Ordering::Relaxed) {
                if let Err(ack_err) = self.send_message_ack(node, Some(nack_reasons::UNHANDLED_ERROR)) {
                    self.logger.error(&format!("failed to ack message after error: {ack_err}"));
                }
            }
        }
        Ok(())
    }
    fn handle_call(&self, node: &BinaryNode) -> Result<()> {
        let run = || -> Result<()> {
            let info_child = get_all_binary_node_children(node).first().ok_or_else(|| Boom::new("Missing call info in call node"))?;
            let status = get_call_status_from_node(info_child);
            let call_id = info_child.attr("call-id").unwrap_or_default().to_string();
            let from = info_child.attr("from").filter(|f| !f.is_empty()).or_else(|| info_child.attr("call-creator")).unwrap_or_default().to_string();
            let mut call = WACallEvent {
                chat_id: node.attr("from").unwrap_or_default().to_string(),
                from,
                caller_pn: info_child.attr("caller_pn").map(str::to_string),
                is_group: None,
                group_jid: None,
                id: call_id,
                date_ms: attr_num(node.attr("t")) as i64 * 1000,
                is_video: None,
                status,
                offline: node.attr("offline").is_some_and(|o| !o.is_empty()),
                latency_ms: None,
            };
            if status == WACallUpdateType::Relaylatency {
                let latency_value = info_child.attr("latency").filter(|v| !v.is_empty()).or_else(|| info_child.attr("latency_ms").filter(|v| !v.is_empty())).or_else(|| info_child.attr("latency-ms"));
                let latency = attr_num(latency_value.filter(|v| !v.is_empty()));
                if latency.is_finite() {
                    call.latency_ms = Some(latency as u32);
                }
            }
            let cache = self.recv.call_offer_cache.as_ref();
            if status == WACallUpdateType::Offer {
                call.is_video = Some(get_binary_node_child(Some(info_child), "video").is_some());
                call.is_group = Some(info_child.attr("type") == Some("group") || info_child.attr("group-jid").is_some_and(|g| !g.is_empty()));
                call.group_jid = info_child.attr("group-jid").map(str::to_string);
                cache_set(cache, &call.id, call.clone());
            }
            // use existing call info to populate this event
            if let Some(existing_call) = cache_get::<WACallEvent>(cache, &call.id) {
                call.is_video = existing_call.is_video;
                call.is_group = existing_call.is_group;
                if call.caller_pn.as_deref().is_none_or(str::is_empty) {
                    call.caller_pn = existing_call.caller_pn.clone();
                }
            }
            // delete data once call has ended
            if matches!(status, WACallUpdateType::Reject | WACallUpdateType::Accept | WACallUpdateType::Timeout | WACallUpdateType::Terminate) {
                cache.del(&call.id);
            }
            self.ev.emit(BaileysEvent::Call(vec![call]));
            Ok(())
        };
        if let Err(error) = run() {
            self.logger.error(&format!("error in handling call: {error}"));
        }
        if let Err(ack_err) = self.send_message_ack(node, None) {
            self.logger.error(&format!("failed to ack call: {ack_err}"));
        }
        Ok(())
    }
    fn handle_bad_ack(&self, node: &BinaryNode) -> Result<()> {
        let mut key = WAMessageKey::default().with_from_me(true);
        if let Some(v) = node.attr("from") {
            key.set_remote_jid(v);
        }
        if let Some(v) = node.attr("id") {
            key.set_id(v);
        }
        // WARNING: REFRAIN FROM ENABLING THIS FOR NOW. IT WILL CAUSE A LOOP
        // current hypothesis is that if pash is sent in the ack
        // it means -- the message hasn't reached all devices yet
        // we'll retry sending the message here

        // error in acknowledgement,
        // device could not display the message
        if let Some(error) = node.attr("error").filter(|e| !e.is_empty()) {
            let is_reachout_timelocked = error.parse::<u32>().ok() == Some(nack_reasons::SENDER_REACHOUT_TIMELOCKED);
            if error == server_error_codes::MESSAGE_ACCOUNT_RESTRICTION {
                // 463 = 1:1 message missing privacy token (tctoken). Usually means the
                // account is restricted: WhatsApp blocks starting new chats but preserves
                // existing ones, since established chats already carry a tctoken.
                // WA Web prevents this client-side (disables the compose bar).
                // No retry — retrying counts as another "reach out" and worsens the restriction.
                self.logger.warn("error 463: account restricted or missing tctoken for contact");
                if let Some(ack_from) = node.attr("from").filter(|f| !f.is_empty()) {
                    if self.recv.in_flight_463_recoveries.lock().unwrap().insert(ack_from.to_string()) {
                        if let Some(sock) = upgrade(&self.self_weak()) {
                            let ack_from = ack_from.to_string();
                            sock.on_lane(LaneId::Control, move |s| {
                                let run = || -> Result<()> {
                                    let lid_mapping = s.signal_repository.lid_mapping();
                                    let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);
                                    let get_pn = |lid: &str| lid_mapping.get_pn_for_lid(lid);
                                    let tc_storage_jid = resolve_tc_token_jid(&ack_from, &get_lid)?;
                                    let issue_to_lid = s.chats.server_props.lid_trusted_token_issue_to_lid.load(Ordering::Relaxed);
                                    let issue_jid = resolve_issuance_jid(&ack_from, issue_to_lid, &get_lid, Some(&get_pn))?;
                                    let result = s.issue_privacy_tokens(&[issue_jid], Some(unix_timestamp_seconds(None)))?;
                                    let empty = BinaryNode::tag("iq", Attrs::new());
                                    let track = |jid: &str| s.track_tc_token_jid(jid);
                                    store_tc_tokens_from_iq_result(result.as_ref().unwrap_or(&empty), &tc_storage_jid, s.keys.as_ref(), &get_lid, Some(&track))
                                };
                                match run() {
                                    Ok(()) => s.logger.debug("completed 463 token recovery issuance"),
                                    Err(err) => s.logger.debug(&format!("failed 463 token recovery issuance: {err}")),
                                }
                                s.recv.in_flight_463_recoveries.lock().unwrap().remove(&ack_from);
                            });
                        }
                    }
                }
            } else if error == server_error_codes::SMAX_INVALID {
                self.logger.warn("smax-invalid (479): stanza rejected by server — likely stale device session or malformed addressing");
            } else if is_reachout_timelocked {
                // user is temporarily restricted, fetch current restriction details
                if let Err(err) = self.fetch_account_reachout_timelock() {
                    self.logger.warn(&format!("failed to fetch reachout timelock: {err}"));
                }
                self.logger.warn("received error in ack");
            } else {
                self.logger.warn("received error in ack");
            }
            let params = if is_reachout_timelocked { vec![Str::from(error), Str::from(ACCOUNT_RESTRICTED_TEXT)] } else { vec![Str::from(error)] };
            self.ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key, update: WAMessage::default().with_status(Status::ERROR).with_message_stub_parameters(params) }]));
        }
        Ok(())
    }
    /// processes a node with the given function
    /// and adds the task to the existing buffer if we're buffering events
    fn process_node_with_buffer(&self, node: &BinaryNode, identifier: &str, exec: fn(&SocketInner, &BinaryNode) -> Result<()>) {
        self.ev.buffer();
        if let Err(err) = exec(self, node) {
            self.on_unexpected_error(&err, identifier);
        }
        self.ev.flush();
    }
    fn process_node(&self, r#type: MessageType, node: &BinaryNode, identifier: &str, exec: fn(&SocketInner, &BinaryNode) -> Result<()>) {
        // Fast path: ack and drop ignored JIDs before entering the buffer/queue
        let from = node.attr("from").filter(|f| !f.is_empty());
        let mut ignore_jid = from;
        if let (MessageType::Receipt, Some(f)) = (r#type, from) {
            let is_lid = f.contains("lid");
            let me = self.user();
            let is_node_from_me = are_jids_same_user(node.attr("participant").filter(|p| !p.is_empty()).or(Some(f)), if is_lid { me.as_ref().and_then(|m| m.lid.as_deref()) } else { me.as_ref().map(|m| m.id.as_str()) });
            ignore_jid = if !is_node_from_me || is_jid_group(f) { Some(f) } else { node.attr("recipient") };
        }
        if let Some(j) = ignore_jid.filter(|j| !j.is_empty() && *j != S_WHATSAPP_NET) {
            if (self.config.should_ignore_jid)(j) == Some(true) {
                if let Err(e) = self.send_message_ack(node, (r#type == MessageType::Message).then_some(nack_reasons::UNHANDLED_ERROR)) {
                    self.on_unexpected_error(&e, identifier);
                }
                return;
            }
        }
        if node.attr("offline").is_some_and(|o| !o.is_empty()) {
            self.recv.offline_node_processor.enqueue(r#type, node.clone());
        } else {
            self.process_node_with_buffer(node, identifier, exec);
        }
    }
    /// recv a message
    pub(crate) fn on_cb_message(&self, node: &BinaryNode) {
        self.process_node(MessageType::Message, node, "processing message", |s, n| s.handle_message(n));
    }
    pub(crate) fn on_cb_call(&self, node: &BinaryNode) {
        self.process_node(MessageType::Call, node, "handling call", |s, n| s.handle_call(n));
    }
    pub(crate) fn on_cb_receipt(&self, node: &BinaryNode) {
        self.process_node(MessageType::Receipt, node, "handling receipt", |s, n| s.handle_receipt(n));
    }
    pub(crate) fn on_cb_notification(&self, node: &BinaryNode) {
        self.process_node(MessageType::Notification, node, "handling notification", |s, n| s.handle_notification(n));
    }
    pub(crate) fn on_cb_ack_message(&self, node: &BinaryNode) {
        if let Err(error) = self.handle_bad_ack(node) {
            self.on_unexpected_error(&error, "handling bad ack");
        }
    }
    fn prune_expired_tc_tokens(&self) -> Result<()> {
        // Union with the persisted index picks up JIDs added by other layers
        // (history sync) without needing inter-module wiring.
        let persisted = read_tc_token_index(self.keys.as_ref())?;
        let mut all_jids: Vec<String> = self.recv.tc_token_known_jids.lock().unwrap().iter().cloned().collect();
        for jid in persisted {
            if !all_jids.contains(&jid) {
                all_jids.push(jid);
            }
        }
        if all_jids.is_empty() {
            return Ok(());
        }
        let all_tokens = self.keys.get(KeyKind::TcToken, &all_jids)?;
        let mut writes: Vec<KeyWrite> = Vec::new();
        let mut survivors: Vec<String> = Vec::new();
        let mut mutated = 0;
        for jid in &all_jids {
            let Some(KeyValue::TcToken(entry)) = all_tokens.get(jid) else {
                // Tracked but nothing in store — drop from index.
                mutated += 1;
                continue;
            };
            let has_peer_token = !entry.token.is_empty();
            let peer_token_expired = has_peer_token && is_tc_token_expired_str(entry.timestamp.as_deref());
            let has_sender_ts = entry.sender_timestamp.is_some();
            let sender_ts_expired = has_sender_ts && is_tc_token_expired(entry.sender_timestamp);
            let keep_peer_token = has_peer_token && !peer_token_expired;
            let keep_sender_ts = has_sender_ts && !sender_ts_expired;
            if !keep_peer_token && !keep_sender_ts {
                writes.push((KeyKind::TcToken, jid.clone(), None));
                mutated += 1;
            } else if peer_token_expired && keep_sender_ts {
                writes.push((KeyKind::TcToken, jid.clone(), Some(KeyValue::TcToken(TcTokenEntry { token: Bytes::new(), timestamp: None, sender_timestamp: entry.sender_timestamp }))));
                survivors.push(jid.clone());
                mutated += 1;
            } else {
                survivors.push(jid.clone());
            }
        }
        if mutated == 0 {
            return Ok(());
        }
        let index = Json::Arr(survivors.iter().map(|s| jstr(s)).collect()).stringify();
        writes.push((KeyKind::TcToken, TC_TOKEN_INDEX_KEY.to_string(), Some(KeyValue::TcToken(TcTokenEntry { token: Bytes::from(index.as_bytes()), timestamp: None, sender_timestamp: None }))));
        self.keys.set(writes)?;
        let mut known = self.recv.tc_token_known_jids.lock().unwrap();
        known.clear();
        known.extend(survivors);
        drop(known);
        self.logger.debug("pruned expired tctokens");
        Ok(())
    }
}
impl Socket {
    pub(crate) fn register_recv_listeners(&self) {
        match read_tc_token_index(self.keys.as_ref()) {
            Ok(jids) => self.recv.tc_token_known_jids.lock().unwrap().extend(jids),
            Err(err) => self.logger.warn(&format!("failed to load tctoken index: {err}")),
        }
        let weak = self.weak();
        self.ev.on(
            EventKind::Call,
            Arc::new(move |e: &BaileysEvent| {
                let (BaileysEvent::Call(calls), Some(s)) = (e, upgrade(&weak)) else { return };
                let Some(call) = calls.first() else { return };
                // missed call + group call notification message generation
                let group = call.is_group == Some(true);
                let video = call.is_video == Some(true);
                if !(call.status == WACallUpdateType::Timeout || (call.status == WACallUpdateType::Offer && group)) {
                    return;
                }
                let key = WAMessageKey::default().with_remote_jid(call.chat_id.as_str()).with_id(call.id.as_str()).with_from_me(false);
                let mut msg = WAMessage::default().with_key(key).with_message_timestamp((call.date_ms / 1000) as u64);
                if call.status == WACallUpdateType::Timeout {
                    msg.set_message_stub_type(match (group, video) {
                        (true, true) => StubType::CALL_MISSED_GROUP_VIDEO,
                        (true, false) => StubType::CALL_MISSED_GROUP_VOICE,
                        (false, true) => StubType::CALL_MISSED_VIDEO,
                        (false, false) => StubType::CALL_MISSED_VOICE,
                    });
                } else {
                    msg.set_message(waproto::Message::default().with_call(CallMessage::default().with_call_key(call.id.as_bytes())));
                }
                let r#type = if call.offline { MessageUpsertType::Append } else { MessageUpsertType::Notify };
                s.spawn_task("call upsert", move |s| s.upsert_message(msg, r#type));
            }),
        );
        let weak = self.weak();
        self.ev.on(
            EventKind::ConnectionUpdate,
            Arc::new(move |e: &BaileysEvent| {
                let (BaileysEvent::ConnectionUpdate(u), Some(s)) = (e, upgrade(&weak)) else { return };
                if let Some(is_online) = u.is_online {
                    s.recv.send_active_receipts.store(is_online, Ordering::Relaxed);
                }
                // Flush pending tctoken index save on disconnect to avoid writing after close
                if u.connection == Some(WAConnectionState::Close) {
                    let timer = s.recv.tc_token_index_timer.lock().unwrap().take();
                    if let Some(t) = timer {
                        t.cancel();
                        // Best-effort flush — may fail if store is already closed
                        let _ = s.flush_tc_token_index();
                    }
                }
                // Prune expired tctokens when coming online, at most once per 24 hours
                // Matches WA Web's CLEAN_TC_TOKENS task
                if u.is_online == Some(true) {
                    let now = now_ms();
                    let last = s.recv.last_tc_token_prune_ts.load(Ordering::Relaxed);
                    if now - last >= time_ms::DAY as i64 {
                        s.recv.last_tc_token_prune_ts.store(now, Ordering::Relaxed);
                        s.on_lane(LaneId::Control, |s| {
                            if let Err(err) = s.prune_expired_tc_tokens() {
                                s.logger.warn(&format!("failed to prune expired tctokens: {err}"));
                            }
                        });
                    }
                }
            }),
        );
        let weak = self.weak();
        self.register_socket_end_handler(Arc::new(move |_| {
            let Some(s) = upgrade(&weak) else { return };
            if s.config.msg_retry_counter_cache.is_none() {
                s.recv.msg_retry_cache.close();
            }
            if s.config.call_offer_cache.is_none() {
                s.recv.call_offer_cache.close();
            }
            s.recv.identity_assert_debounce.close();
            s.recv.send_active_receipts.store(false, Ordering::Relaxed);
        }));
    }
}
