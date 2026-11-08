//! Same as Socket/messages-send.ts.
use super::LaneId;
use super::socket::{Socket, SocketInner, WeakSocket, upgrade};
use crate::auth::*;
use crate::defaults::*;
use crate::error::{Boom, Result};
use crate::events::*;
use crate::signal::lid_mapping::LidMappingStore;
use crate::types::*;
use crate::utils::auth_utils::assert_me_id;
use crate::utils::generics::*;
use crate::utils::link_preview::{URLGenerationOptions, get_url_info};
use crate::utils::make_mutex::{KeyedMutex, Mutex as FifoLock, make_keyed_mutex, make_mutex};
use crate::utils::message_retry_manager::MessageRetryManager;
use crate::utils::messages::*;
use crate::utils::messages_media::{DEF_MEDIA_HOST, decrypt_media_retry_data, encrypt_media_retry_request, get_status_code_for_media_retry, get_url_from_direct_path, get_wa_upload_to_server};
use crate::utils::node_cache::NodeCache;
use crate::utils::reporting_utils::{get_message_reporting_token, should_include_reporting_token};
use crate::utils::signal::{DeviceJid, extract_device_jids, parse_and_inject_e2e_sessions};
use crate::utils::tc_token_utils::*;
use crate::utils::time::now_ms;
use crate::utils::validate_connection::encode_signed_device_identity;
use crate::wabinary::*;
use crate::wausync::{USyncQuery, USyncUser};
use rustc_hash::FxHashSet;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use waproto::media_retry_notification::ResultType;
use waproto::message::protocol_message::Type as ProtocolType;
use waproto::message::{DeviceSentMessage, PeerDataOperationRequestMessage, ProtocolMessage, SenderKeyDistributionMessage};
use waproto::pb::{Bytes, PbMessage};
use waproto::{MemberLabel, Message};

/// Device info with wire JID
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceWithJid {
    pub user: String,
    pub device: Option<u32>,
    pub jid: String,
}
pub struct SendState {
    /// Set of tctoken storage JIDs with a fire-and-forget `issuePrivacyTokens` IQ in flight.
    /// Prevents duplicate IQs from rapid back-to-back sends before `senderTimestamp` persists.
    /// Entries are always removed when the task ends, so the set is bounded by concurrency.
    in_flight_tc_token_issuance: Mutex<FxHashSet<String>>,
    pub user_devices_cache: Arc<dyn CacheStore>,
    /// Serializes writes to userDevicesCache across USync refresh and device-notification handling.
    pub devices_mutex: FifoLock,
    pub message_retry_manager: Option<Arc<MessageRetryManager>>,
    /// Prevent race conditions in Signal session encryption by user
    encryption_mutex: KeyedMutex,
    media_conn: Mutex<Option<MediaConnInfo>>,
    /// Per-socket media host; updated whenever media_conn is fetched. Defaults to the public WhatsApp host.
    media_host: Mutex<String>,
    pub wa_upload_to_server: WAMediaUploadFunction,
}
impl SendState {
    pub fn new(config: &SocketConfig, weak: WeakSocket) -> SendState {
        let refresh: crate::utils::messages_media::RefreshMediaConn = Arc::new(move |force: bool| match upgrade(&weak) {
            Some(s) => s.refresh_media_conn(force),
            None => Err(super::socket::connection_closed()),
        });
        SendState {
            in_flight_tc_token_issuance: Mutex::new(FxHashSet::default()),
            user_devices_cache: config.user_devices_cache.clone().unwrap_or_else(|| Arc::new(NodeCache::new(default_cache_ttls::USER_DEVICES))),
            devices_mutex: make_mutex(),
            message_retry_manager: config.enable_recent_message_cache.then(|| Arc::new(MessageRetryManager::new(config.logger.clone(), config.max_msg_retry_count))),
            encryption_mutex: make_keyed_mutex(),
            media_conn: Mutex::new(None),
            media_host: Mutex::new(DEF_MEDIA_HOST.to_string()),
            wa_upload_to_server: get_wa_upload_to_server(config, refresh),
        }
    }
}
fn extra_get<'a>(a: &'a [(String, String)], k: &str) -> Option<&'a str> {
    a.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}
fn extra_set(a: &mut Vec<(String, String)>, k: &str, v: &str) {
    match a.iter_mut().find(|(n, _)| n == k) {
        Some(e) => e.1 = v.to_string(),
        None => a.push((k.to_string(), v.to_string())),
    }
}
fn user_of(jid: &str) -> Result<String> {
    Ok(jid_decode(jid).ok_or_else(|| Boom::type_error("Cannot destructure property 'user' of undefined"))?.user.to_string())
}
pub fn get_media_type(message: &Message) -> &'static str {
    if message.image_message().is_some() {
        "image"
    } else if let Some(v) = message.video_message() {
        if v.gif_playback() == Some(true) { "gif" } else { "video" }
    } else if let Some(a) = message.audio_message() {
        if a.ptt() == Some(true) { "ptt" } else { "audio" }
    } else if message.contact_message().is_some() {
        "vcard"
    } else if message.document_message().is_some() {
        "document"
    } else if message.contacts_array_message().is_some() {
        "contact_array"
    } else if message.live_location_message().is_some() {
        "livelocation"
    } else if message.sticker_message().is_some() {
        "sticker"
    } else if message.list_message().is_some() {
        "list"
    } else if message.list_response_message().is_some() {
        "list_response"
    } else if message.buttons_response_message().is_some() {
        "buttons_response"
    } else if message.order_message().is_some() {
        "order"
    } else if message.product_message().is_some() {
        "product"
    } else if message.interactive_response_message().is_some() {
        "native_flow_response"
    } else if message.group_invite_message().is_some() {
        "url"
    } else {
        ""
    }
}
pub fn get_message_type(message: &Message) -> &'static str {
    let Some(n) = normalize_message_content(Some(message)) else { return "text" };
    if n.reaction_message().is_some() || n.enc_reaction_message().is_some() {
        return "reaction";
    }
    if n.poll_creation_message().is_some() || n.poll_creation_message_v2().is_some() || n.poll_creation_message_v3().is_some() || n.poll_update_message().is_some() {
        return "poll";
    }
    if n.event_message().is_some() {
        return "event";
    }
    if !get_media_type(n).is_empty() {
        return "media";
    }
    "text"
}
impl SocketInner {
    pub fn get_media_host(&self) -> String {
        self.send.media_host.lock().unwrap().clone()
    }
    pub fn refresh_media_conn(&self, force_get: bool) -> Result<MediaConnInfo> {
        // the lock stays held during the query, so that callers share one fetch as they share a promise upstream
        let mut media_conn = self.send.media_conn.lock().unwrap();
        if let Some(m) = media_conn.as_ref() {
            if !force_get && now_ms() - m.fetch_date_ms <= m.ttl as i64 * 1000 {
                return Ok(m.clone());
            }
        }
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("type", "set"), ("xmlns", "w:m"), ("to", S_WHATSAPP_NET)]), vec![BinaryNode::tag("media_conn", Attrs::new())]), None)?;
        let media_conn_node = get_binary_node_child(result.as_ref(), "media_conn").ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'attrs')"))?;
        // TODO: explore full length of data that whatsapp provides
        let node = MediaConnInfo {
            hosts: get_binary_node_children(Some(media_conn_node), "host")
                .into_iter()
                .map(|h| MediaConnHost { hostname: h.attr("hostname").unwrap_or_default().to_string(), max_content_length_bytes: h.attr("maxContentLengthBytes").and_then(|v| v.parse().ok()).unwrap_or(0) })
                .collect(),
            auth: media_conn_node.attr("auth").unwrap_or_default().to_string(),
            ttl: media_conn_node.attr("ttl").and_then(|v| v.parse().ok()).unwrap_or(0),
            fetch_date_ms: now_ms(),
        };
        self.logger.debug("fetched media conn");
        if let Some(h) = node.hosts.first() {
            *self.send.media_host.lock().unwrap() = h.hostname.clone();
        }
        *media_conn = Some(node.clone());
        Ok(node)
    }
    /// generic send receipt function
    /// used for receipts of phone call, read, delivery etc.
    pub fn send_receipt(&self, jid: &str, participant: Option<&str>, message_ids: &[String], r#type: Option<&str>) -> Result<()> {
        let Some(first) = message_ids.first() else {
            return Err(Boom::new("missing ids in receipt"));
        };
        let mut attrs = Attrs::from([("id", first.as_str())]);
        if matches!(r#type, Some("read") | Some("read-self")) {
            attrs.set("t", unix_timestamp_seconds(None).to_string());
        }
        if r#type == Some("sender") && (is_pn_user(jid) || is_lid_user(jid)) {
            attrs.set("recipient", jid);
            attrs.set("to", participant.unwrap_or_default());
        } else {
            attrs.set("to", jid);
            if let Some(p) = participant.filter(|p| !p.is_empty()) {
                attrs.set("participant", p);
            }
        }
        if let Some(t) = r#type.filter(|t| !t.is_empty()) {
            attrs.set("type", t);
        }
        let node = if message_ids.len() > 1 {
            let items = message_ids[1..].iter().map(|id| BinaryNode::tag("item", Attrs::from([("id", id.as_str())]))).collect();
            BinaryNode::with_nodes("receipt", attrs, vec![BinaryNode::with_nodes("list", Attrs::new(), items)])
        } else {
            BinaryNode::tag("receipt", attrs)
        };
        self.send_node(&node)
    }
    /// Correctly bulk send receipts to multiple chats, participants
    pub fn send_receipts(&self, keys: &[WAMessageKey], r#type: Option<&str>) -> Result<()> {
        for recp in aggregate_message_keys_not_from_me(keys) {
            self.send_receipt(&recp.jid, recp.participant.as_deref(), &recp.message_ids, r#type)?;
        }
        Ok(())
    }
    /// Bulk read messages. Keys can be from different chats & participants
    pub fn read_messages(&self, keys: &[WAMessageKey]) -> Result<()> {
        let privacy_settings = self.fetch_privacy_settings(false)?;
        // based on privacy settings, we have to change the read type
        let read_type = if privacy_settings.get("readreceipts") == Some("all") { "read" } else { "read-self" };
        self.send_receipts(keys, Some(read_type))
    }
    /// Fetch all the devices we've to send a message to
    pub fn get_usync_devices(&self, jids: &[String], use_cache: bool, ignore_zero_devices: bool) -> Result<Vec<DeviceWithJid>> {
        let mut device_results = Vec::new();
        if !use_cache {
            self.logger.debug("not using cache for devices");
        }
        let mut to_fetch = Vec::new();
        let mut jids_with_user = Vec::with_capacity(jids.len());
        for jid in jids {
            let decoded = jid_decode(jid);
            if let Some(d) = &decoded {
                if let Some(device) = d.device.filter(|_| !d.user.is_empty()) {
                    device_results.push(DeviceWithJid { user: d.user.to_string(), device: Some(device), jid: jid.clone() });
                    continue;
                }
            }
            jids_with_user.push((jid_normalized_user(jid), decoded.map(|d| d.user.to_string())));
        }
        let cache = self.send.user_devices_cache.as_ref();
        for (jid, user) in jids_with_user {
            if use_cache {
                let devices = user.as_deref().and_then(|u| cache_get::<Vec<DeviceJid>>(cache, u));
                if let Some(devices) = devices {
                    device_results.extend(devices.iter().map(|d| DeviceWithJid { user: d.user.clone(), device: d.device, jid: jid_encode(&d.user, &d.server, d.device, None) }));
                    self.logger.trace("using cache for devices");
                } else {
                    to_fetch.push(jid);
                }
            } else {
                to_fetch.push(jid);
            }
        }
        if to_fetch.is_empty() {
            return Ok(device_results);
        }
        let mut requested_lid_users: FxHashSet<String> = FxHashSet::default();
        for jid in &to_fetch {
            if is_lid_user(jid) || is_hosted_lid_user(jid) {
                if let Some(d) = jid_decode(jid) {
                    requested_lid_users.insert(d.user.to_string());
                }
            }
        }
        let mut query = USyncQuery::new().with_context("message").with_device_protocol().with_lid_protocol();
        for jid in &to_fetch {
            query.add_user(USyncUser::new().with_id(jid.as_str())); // todo: investigate - the idea here is that <user> should have an inline lid field with the lid being the pn equivalent
        }
        let Some(result) = self.execute_usync_query(&query)? else { return Ok(device_results) };
        // TODO: LID MAP this stuff (lid protocol will now return lid with devices)
        let lid_results: Vec<LidMapping> = result.list.iter().filter_map(|a| a.lid().map(|lid| LidMapping { lid: lid.as_str().to_string(), pn: a.id.clone() })).collect();
        if !lid_results.is_empty() {
            self.logger.trace("Storing LID maps from device call");
            self.signal_repository.lid_mapping().store_lid_pn_mappings(&lid_results)?;
            // Force-refresh sessions for newly mapped LIDs to align identity addressing
            let lids: Vec<String> = lid_results.into_iter().map(|a| a.lid).collect();
            if let Err(e) = self.assert_sessions(&lids, true) {
                self.logger.warn(&format!("failed to assert sessions for newly mapped LIDs: {e}"));
            }
        }
        let (me_id, me_lid) = (self.me_id().unwrap_or_default(), self.me_lid().unwrap_or_default());
        let extracted = extract_device_jids(&result.list, &me_id, &me_lid, ignore_zero_devices)?;
        let mut device_map: JsMap<Vec<DeviceJid>> = JsMap::new();
        for item in extracted {
            if let Some(l) = device_map.get_mut(&item.user) {
                l.push(item);
            } else {
                let key = item.user.clone();
                device_map.insert(key, vec![item]);
            }
        }
        // Process each user's devices as a group for bulk LID migration
        for (user, user_devices) in device_map.iter() {
            let _is_lid_user = requested_lid_users.contains(user);
            // Process all devices for this user
            for item in user_devices {
                // upstream encodes the same value on both sides of its `isLidUser` check
                let final_jid = jid_encode(&item.user, &item.server, item.device, None);
                device_results.push(DeviceWithJid { user: item.user.clone(), device: item.device, jid: final_jid });
            }
        }
        self.send.devices_mutex.mutex(|| {
            let entries: Vec<(String, CacheValue)> = device_map.iter().map(|(k, v)| (k.to_string(), Arc::new(v.clone()) as CacheValue)).collect();
            // the trait default sets one by one when the cache has no batch write
            cache.mset(entries);
        });
        let user_device_updates: Vec<KeyWrite> = device_map.iter().filter(|(_, d)| !d.is_empty()).map(|(k, d)| (KeyKind::DeviceList, k.to_string(), Some(KeyValue::DeviceList(d.iter().map(|x| x.device.unwrap_or(0).to_string()).collect())))).collect();
        if !user_device_updates.is_empty() {
            match self.keys.set(user_device_updates) {
                Ok(()) => self.logger.debug("stored user device lists for bulk migration"),
                Err(error) => self.logger.warn(&format!("failed to store user device lists: {error}")),
            }
        }
        Ok(device_results)
    }
    /// Update Member Label
    pub fn update_member_label(&self, jid: &str, member_label: &str) -> Result<String> {
        let label: String = member_label.chars().take(30).collect();
        let msg = Message::default().with_protocol_message(ProtocolMessage::default().with_type(ProtocolType::GROUP_MEMBER_LABEL_CHANGE).with_member_label(MemberLabel::default().with_label(label).with_label_timestamp(unix_timestamp_seconds(None))));
        let meta = BinaryNode::tag("meta", Attrs::from([("tag_reason", "user_update"), ("appdata", "member_tag")]));
        self.relay_message(jid, &msg, MessageRelayOptions { additional_nodes: Some(vec![meta]), ..MessageRelayOptions::default() })
    }
    pub fn assert_sessions(&self, jids: &[String], force: bool) -> Result<bool> {
        let mut unique: Vec<&String> = Vec::with_capacity(jids.len());
        for j in jids {
            if !unique.contains(&j) {
                unique.push(j);
            }
        }
        self.logger.debug("assertSessions call with jids");
        let mut jids_requiring_fetch: Vec<String> = Vec::new();
        for jid in unique {
            if !force && self.signal_repository.validate_session(jid).exists {
                continue;
            }
            jids_requiring_fetch.push(jid.clone());
        }
        if jids_requiring_fetch.is_empty() {
            return Ok(false);
        }
        // LID if mapped, otherwise original
        let mut wire_jids: Vec<String> = jids_requiring_fetch.iter().filter(|j| is_lid_user(j) || is_hosted_lid_user(j)).cloned().collect();
        let pns: Vec<String> = jids_requiring_fetch.iter().filter(|j| is_pn_user(j) || is_hosted_pn_user(j)).cloned().collect();
        if let Some(mappings) = self.signal_repository.lid_mapping().get_lids_for_pns(&pns)? {
            wire_jids.extend(mappings.into_iter().map(|a| a.lid));
        }
        self.logger.debug("fetching sessions");
        let users = wire_jids
            .iter()
            .map(|jid| {
                let mut attrs = Attrs::from([("jid", jid.as_str())]);
                if force {
                    attrs.set("reason", "identity");
                }
                BinaryNode::tag("user", attrs)
            })
            .collect();
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("xmlns", "encrypt"), ("type", "get"), ("to", S_WHATSAPP_NET)]), vec![BinaryNode::with_nodes("key", Attrs::new(), users)]), None)?;
        let empty = BinaryNode::tag("iq", Attrs::new());
        parse_and_inject_e2e_sessions(result.as_ref().unwrap_or(&empty), self.signal_repository.as_ref())?;
        Ok(true)
    }
    pub fn send_peer_data_operation_message(&self, pdo_message: PeerDataOperationRequestMessage) -> Result<String> {
        //TODO: for later, abstract the logic to send a Peer Message instead of just PDO - useful for App State Key Resync with phone
        let me_id = self.me_id().filter(|i| !i.is_empty()).ok_or_else(|| Boom::new("Not authenticated"))?;
        let protocol_message = Message::default().with_protocol_message(ProtocolMessage::default().with_peer_data_operation_request_message(pdo_message).with_type(ProtocolType::PEER_DATA_OPERATION_REQUEST_MESSAGE));
        let me_jid = jid_normalized_user(&me_id);
        self.relay_message(
            &me_jid,
            &protocol_message,
            MessageRelayOptions {
                additional_attributes: Some(vec![("category".to_string(), "peer".to_string()), ("push_priority".to_string(), "high_force".to_string())]),
                additional_nodes: Some(vec![BinaryNode::tag("meta", Attrs::from([("appdata", "default")]))]),
                ..MessageRelayOptions::default()
            },
        )
    }
    /// The nodes for each recipient, and if any of them needs our device identity.
    pub fn create_participant_nodes(&self, recipient_jids: &[String], message: &Message, extra_attrs: &[(String, String)], dsm_message: Option<&Message>) -> Result<(Vec<BinaryNode>, bool)> {
        if recipient_jids.is_empty() {
            return Ok((Vec::new(), false));
        }
        let patched = (self.config.patch_message_before_sending)(message.clone(), Some(recipient_jids));
        // one message without a jid is the case where upstream gets a plain message, not an array
        let shared: Option<&Message> = match patched.as_slice() {
            [one] if one.recipient_jid.is_none() => Some(&one.message),
            _ => None,
        };
        let pairs: Vec<(&str, &Message)> = match shared {
            Some(m) => recipient_jids.iter().map(|j| (j.as_str(), m)).collect(),
            None => patched.iter().filter_map(|p| p.recipient_jid.as_deref().filter(|j| !j.is_empty()).map(|j| (j, &p.message))).collect(),
        };
        let mut should_include_device_identity = false;
        let (me_id, me_lid) = (self.me_id().unwrap_or_default(), self.me_lid());
        let me_lid_user = me_lid.as_deref().and_then(jid_decode).map(|d| d.user.to_string());
        let mut nodes = Vec::with_capacity(pairs.len());
        for (jid, patched_message) in pairs {
            let mut encrypt_one = || -> Result<BinaryNode> {
                let mut msg_to_encrypt = patched_message;
                if let Some(dsm) = dsm_message {
                    let target_user = user_of(jid)?;
                    let own_pn_user = user_of(&me_id)?;
                    let is_own_user = target_user == own_pn_user || me_lid_user.as_deref() == Some(target_user.as_str());
                    let is_exact_sender_device = jid == me_id || me_lid.as_deref() == Some(jid);
                    if is_own_user && !is_exact_sender_device {
                        msg_to_encrypt = dsm;
                        self.logger.debug("Using DSM for own device");
                    }
                }
                let bytes = encode_wa_message(msg_to_encrypt);
                self.send.encryption_mutex.mutex(jid, || {
                    let encrypted = self.signal_repository.encrypt_message(jid, &bytes)?;
                    if encrypted.msg_type == "pkmsg" {
                        should_include_device_identity = true;
                    }
                    let mut enc_attrs = Attrs::from([("v", "2"), ("type", encrypted.msg_type)]);
                    for (k, v) in extra_attrs {
                        enc_attrs.set(k.as_str(), v.as_str());
                    }
                    Ok(BinaryNode::with_nodes("to", Attrs::from([("jid", jid)]), vec![BinaryNode::with_bytes("enc", enc_attrs, encrypted.ciphertext)]))
                })
            };
            match encrypt_one() {
                Ok(node) => nodes.push(node),
                Err(err) => self.logger.error(&format!("Failed to encrypt for recipient {jid}: {err}")),
            }
        }
        if nodes.is_empty() {
            return Err(Boom::status("All encryptions failed", 500));
        }
        Ok((nodes, should_include_device_identity))
    }
    fn patch_one(&self, message: &Message, recipients: Option<&[String]>) -> Vec<PatchedMessageWithRecipientJID> {
        (self.config.patch_message_before_sending)(message.clone(), recipients)
    }
    pub fn relay_message(&self, jid: &str, message: &Message, options: MessageRelayOptions) -> Result<String> {
        let MessageRelayOptions { message_id, use_cached_group_metadata, participant, additional_attributes, additional_nodes, use_user_devices_cache, status_jid_list } = options;
        let (me_id, me_lid, account) = {
            let c = self.creds.lock().unwrap();
            (assert_me_id(&c)?.to_string(), c.me.as_ref().and_then(|m| m.lid.clone()).filter(|l| !l.is_empty()), c.account.clone())
        };
        let is_retry_resend = participant.as_ref().is_some_and(|p| !p.jid.is_empty());
        let status_jid = STORIES_JID;
        let decoded = jid_decode(jid).ok_or_else(|| Boom::type_error("Cannot destructure property 'user' of undefined"))?;
        let (user, server) = (decoded.user.to_string(), decoded.server.to_string());
        let is_group = server == "g.us";
        let is_status = jid == status_jid;
        let is_lid = server == "lid";
        let is_newsletter = server == "newsletter";
        let is_group_or_status = is_group || is_status;
        let msg_id = message_id.filter(|i| !i.is_empty()).unwrap_or_else(|| generate_message_id_v2(Some(&me_id)));
        let use_user_devices_cache = use_user_devices_cache != Some(false);
        let use_cached_group_metadata = use_cached_group_metadata != Some(false) && !is_status;
        let destination_jid = if is_status { status_jid.to_string() } else { jid.to_string() };
        let mut devices: Vec<DeviceWithJid> = Vec::new();
        let mut me_msg = Message::default().with_device_sent_message(DeviceSentMessage::default().with_destination_jid(destination_jid.as_str()).with_message(message.clone()));
        if let Some(c) = message.message_context_info() {
            me_msg.set_message_context_info(c.clone());
        }
        let mut additional_attributes = additional_attributes.unwrap_or_default();
        if let Some(p) = &participant {
            if !is_group && !is_status {
                extra_set(&mut additional_attributes, "device_fanout", "false");
            }
            let d = jid_decode(&p.jid).ok_or_else(|| Boom::type_error("Cannot destructure property 'user' of undefined"))?;
            devices.push(DeviceWithJid { user: d.user.to_string(), device: d.device, jid: p.jid.clone() });
        }
        let additional_nodes = additional_nodes.unwrap_or_default();
        let status_jid_list = status_jid_list.unwrap_or_default();
        let lid_mapping: Arc<LidMappingStore> = self.signal_repository.lid_mapping();
        let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);

        self.transaction(&me_id, || {
            let mut devices = devices.clone();
            let mut additional_attributes = additional_attributes.clone();
            let mut should_include_device_identity = is_retry_resend;
            let mut extra_attrs: Vec<(String, String)> = Vec::new();
            let mut participants: Vec<BinaryNode> = Vec::new();
            let mut binary_node_content: Vec<BinaryNode> = Vec::new();
            let mut reporting_message: Option<Message> = None;
            let media_type = get_media_type(message);
            if !media_type.is_empty() {
                extra_attrs.push(("mediatype".to_string(), media_type.to_string()));
            }
            if is_newsletter {
                let patched = self.patch_one(message, Some(&[]));
                let bytes = encode_newsletter_message(patched.first().map_or(message, |p| &p.message));
                binary_node_content.push(BinaryNode::with_bytes("plaintext", Attrs::new(), bytes));
                let mut attrs = Attrs::from([("to", jid), ("id", msg_id.as_str()), ("type", get_message_type(message))]);
                for (k, v) in &additional_attributes {
                    attrs.set(k.as_str(), v.as_str());
                }
                return self.send_node(&BinaryNode::with_nodes("message", attrs, binary_node_content));
            }
            let normalized = normalize_message_content(Some(message));
            if normalized.is_some_and(|n| n.pin_in_chat_message().is_some() || n.reaction_message().is_some()) {
                extra_attrs.push(("decrypt-fail".to_string(), "hide".to_string())); // todo: expand for reactions and other types
            }
            if is_group_or_status && !is_retry_resend {
                let mut group_data = if use_cached_group_metadata { (self.config.cached_group_metadata)(jid) } else { None }; // todo: should we rely on the cache specially if the cache is outdated and the metadata has new fields?
                if group_data.is_some() {
                    self.logger.trace("using cached group metadata");
                } else if !is_status {
                    group_data = Some(self.group_metadata(jid)?); // TODO: start storing group participant list + addr mode in Signal & stop relying on this
                }
                let mut sender_key_map: HashMap<String, bool> = if participant.is_none() && !is_status {
                    // what if sender memory is less accurate than the cached metadata
                    // on participant change in group, we should do sender memory manipulation
                    match self.keys.get_one(KeyKind::SenderKeyMemory, jid)? { // TODO: check out what if the sender key memory doesn't include the LID stuff now?
                        Some(KeyValue::SenderKeyMemory(m)) => m,
                        _ => HashMap::new(),
                    }
                } else {
                    HashMap::new()
                };
                let mut participants_list: Vec<String> = group_data.as_ref().map_or_else(Vec::new, |g| g.participants.iter().map(|p| p.id.clone()).collect());
                if let Some(d) = group_data.as_ref().and_then(|g| g.ephemeral_duration).filter(|d| *d > 0) {
                    extra_set(&mut additional_attributes, "expiration", &d.to_string());
                }
                if is_status {
                    participants_list.extend(status_jid_list.iter().cloned());
                }
                let additional_devices = self.get_usync_devices(&participants_list, use_user_devices_cache, false)?;
                devices.extend(additional_devices);
                if is_group {
                    extra_set(&mut additional_attributes, "addressing_mode", group_data.as_ref().and_then(|g| g.addressing_mode).map_or("lid", |m| m.as_str()));
                }
                let patched = self.patch_one(message, None);
                let [one] = patched.as_slice() else {
                    return Err(Boom::new("Per-jid patching is not supported in groups"));
                };
                if one.recipient_jid.is_some() {
                    return Err(Boom::new("Per-jid patching is not supported in groups"));
                }
                let bytes = encode_wa_message(&one.message);
                reporting_message = Some(one.message.clone());
                let group_addressing_mode = extra_get(&additional_attributes, "addressing_mode").or_else(|| group_data.as_ref().and_then(|g| g.addressing_mode).map(|m| m.as_str())).unwrap_or("lid");
                let group_sender_identity = match (&me_lid, group_addressing_mode) {
                    (Some(l), "lid") => l.as_str(),
                    _ => me_id.as_str(),
                };
                let enc = self.signal_repository.encrypt_group_message(&destination_jid, group_sender_identity, &bytes)?;
                let mut sender_key_recipients: Vec<String> = Vec::new();
                for device in &devices {
                    let device_jid = &device.jid;
                    let has_key = sender_key_map.get(device_jid).copied().unwrap_or(false);
                    if (!has_key || participant.is_some()) && !is_hosted_lid_user(device_jid) && !is_hosted_pn_user(device_jid) && device.device != Some(99) {
                        //todo: revamp all this logic
                        // the goal is to follow with what I said above for each group, and instead of a true false map of ids, we can set an array full of those the app has already sent pkmsgs
                        sender_key_recipients.push(device_jid.clone());
                        sender_key_map.insert(device_jid.clone(), true);
                    }
                }
                if !sender_key_recipients.is_empty() {
                    self.logger.debug("sending new sender key");
                    let sender_key_msg = Message::default().with_sender_key_distribution_message(SenderKeyDistributionMessage::default().with_axolotl_sender_key_distribution_message(enc.sender_key_distribution_message.clone()).with_group_id(destination_jid.as_str()));
                    self.assert_sessions(&sender_key_recipients, false)?;
                    let (nodes, include) = self.create_participant_nodes(&sender_key_recipients, &sender_key_msg, &extra_attrs, None)?;
                    should_include_device_identity = should_include_device_identity || include;
                    participants.extend(nodes);
                }
                let mut enc_attrs = Attrs::from([("v", "2"), ("type", "skmsg")]);
                for (k, v) in &extra_attrs {
                    enc_attrs.set(k.as_str(), v.as_str());
                }
                binary_node_content.push(BinaryNode::with_bytes("enc", enc_attrs, enc.ciphertext));
                self.keys.set_one(KeyKind::SenderKeyMemory, jid, Some(KeyValue::SenderKeyMemory(sender_key_map)))?;
            } else {
                // ADDRESSING CONSISTENCY: Match own identity to conversation context
                // TODO: investigate if this is true
                let own_id = match (&me_lid, is_lid) {
                    (Some(l), true) => l.as_str(),
                    _ => me_id.as_str(),
                };
                let own_user = user_of(own_id)?;
                if participant.is_none() {
                    let patched = self.patch_one(message, Some(std::slice::from_ref(&destination_jid)));
                    let found = patched.iter().find(|p| p.recipient_jid.as_deref() == Some(jid)).or_else(|| patched.first());
                    reporting_message = found.map(|p| p.message.clone());
                }
                if !is_retry_resend {
                    let target_user_server = if is_lid { "lid" } else { "s.whatsapp.net" };
                    devices.push(DeviceWithJid { user: user.clone(), device: Some(0), jid: jid_encode(&user, target_user_server, Some(0), None) }); // rajeh, todo: this entire logic is convoluted and weird.
                    if user != own_user {
                        let own_user_server = if is_lid { "lid" } else { "s.whatsapp.net" };
                        let own_user_for_addressing = match (&me_lid, is_lid) {
                            (Some(l), true) => user_of(l)?,
                            _ => user_of(&me_id)?,
                        };
                        devices.push(DeviceWithJid { user: own_user_for_addressing.clone(), device: Some(0), jid: jid_encode(&own_user_for_addressing, own_user_server, Some(0), None) });
                    }
                    if extra_get(&additional_attributes, "category") != Some("peer") {
                        // Clear placeholders and enumerate actual devices
                        devices.clear();
                        // Use conversation-appropriate sender identity
                        let sender_identity = match (&me_lid, is_lid) {
                            (Some(l), true) => jid_encode(&user_of(l)?, "lid", None, None),
                            _ => jid_encode(&user_of(&me_id)?, "s.whatsapp.net", None, None),
                        };
                        // Enumerate devices for sender and target with consistent addressing
                        let session_devices = self.get_usync_devices(&[sender_identity, jid.to_string()], true, false)?;
                        devices.extend(session_devices);
                        self.logger.debug("Device enumeration complete with unified addressing");
                    }
                }
                let mut all_recipients: Vec<String> = Vec::new();
                let mut me_recipients: Vec<String> = Vec::new();
                let mut other_recipients: Vec<String> = Vec::new();
                let me_pn_user = user_of(&me_id)?;
                let me_lid_user = me_lid.as_deref().map(user_of).transpose()?;
                for DeviceWithJid { user, jid, .. } in &devices {
                    let is_exact_sender_device = *jid == me_id || me_lid.as_deref() == Some(jid.as_str());
                    if is_exact_sender_device {
                        self.logger.debug("Skipping exact sender device (whatsmeow pattern)");
                        continue;
                    }
                    // Check if this is our device (could match either PN or LID user)
                    let is_me = *user == me_pn_user || me_lid_user.as_deref() == Some(user.as_str());
                    if is_me {
                        me_recipients.push(jid.clone());
                    } else {
                        other_recipients.push(jid.clone());
                    }
                    all_recipients.push(jid.clone());
                }
                self.assert_sessions(&all_recipients, false)?;
                // For own devices: use DSM if available (1:1 chats only)
                let (me_nodes, s1) = self.create_participant_nodes(&me_recipients, &me_msg, &extra_attrs, None)?;
                let (other_nodes, s2) = self.create_participant_nodes(&other_recipients, message, &extra_attrs, Some(&me_msg))?;
                participants.extend(me_nodes);
                participants.extend(other_nodes);
                if !me_recipients.is_empty() || !other_recipients.is_empty() {
                    let mut all: Vec<String> = me_recipients.iter().chain(other_recipients.iter()).cloned().collect();
                    extra_attrs.push(("phash".to_string(), generate_participant_hash_v2(&mut all)));
                }
                should_include_device_identity = should_include_device_identity || s1 || s2;
            }
            if let Some(p) = participant.as_ref().filter(|_| is_retry_resend) {
                let is_participant_lid = is_lid_user(&p.jid);
                let is_me = are_jids_same_user(Some(&p.jid), if is_participant_lid { me_lid.as_deref() } else { Some(&me_id) });
                let mut message_to_send = message.clone();
                if is_group_or_status {
                    let mut group_sender_identity = None;
                    if let Some(l) = me_lid.as_deref().filter(|l| self.signal_repository.has_sender_key(&destination_jid, l).unwrap_or(false)) {
                        group_sender_identity = Some(l);
                    } else if self.signal_repository.has_sender_key(&destination_jid, &me_id)? {
                        group_sender_identity = Some(me_id.as_str());
                    }
                    if let Some(identity) = group_sender_identity {
                        match self.signal_repository.get_sender_key_distribution_message(&destination_jid, identity) {
                            Ok(skdm) => message_to_send.set_sender_key_distribution_message(SenderKeyDistributionMessage::default().with_group_id(destination_jid.as_str()).with_axolotl_sender_key_distribution_message(skdm)),
                            Err(err) => self.logger.warn(&format!("failed to build SKDM for retry, sending without it: {err}")),
                        }
                    }
                }
                let encoded_message_to_send = if is_me {
                    encode_wa_message(&Message::default().with_device_sent_message(DeviceSentMessage::default().with_destination_jid(destination_jid.as_str()).with_message(message_to_send)))
                } else {
                    encode_wa_message(&message_to_send)
                };
                let encrypted = self.signal_repository.encrypt_message(&p.jid, &encoded_message_to_send)?;
                let mut enc_attrs = Attrs::from([("v", "2"), ("type", encrypted.msg_type)]);
                enc_attrs.set("count", p.count.to_string());
                binary_node_content.push(BinaryNode::with_bytes("enc", enc_attrs, encrypted.ciphertext));
            }
            if !participants.is_empty() {
                if extra_get(&additional_attributes, "category") == Some("peer") {
                    // push only enc
                    if let Some(Content::Nodes(n)) = &participants[0].content {
                        if let Some(peer_node) = n.first() {
                            binary_node_content.push(peer_node.clone());
                        }
                    }
                } else {
                    binary_node_content.push(BinaryNode::with_nodes("participants", Attrs::new(), std::mem::take(&mut participants)));
                }
            }
            let mut attrs = Attrs::from([("id", msg_id.as_str()), ("to", destination_jid.as_str()), ("type", get_message_type(message))]);
            for (k, v) in &additional_attributes {
                attrs.set(k.as_str(), v.as_str());
            }
            // if the participant to send to is explicitly specified (generally retry recp)
            // ensure the message is only sent to that person
            // if a retry receipt is sent to everyone -- it'll fail decryption for everyone else who received the msg
            if let Some(p) = &participant {
                if is_jid_group(&destination_jid) {
                    attrs.set("to", destination_jid.as_str());
                    attrs.set("participant", p.jid.as_str());
                } else if are_jids_same_user(Some(&p.jid), Some(&me_id)) {
                    attrs.set("to", p.jid.as_str());
                    attrs.set("recipient", destination_jid.as_str());
                } else {
                    attrs.set("to", p.jid.as_str());
                }
            } else {
                attrs.set("to", destination_jid.as_str());
            }
            let mut content = binary_node_content;
            if should_include_device_identity {
                let account = account.as_ref().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'accountSignatureKey')"))?;
                content.push(BinaryNode::with_bytes("device-identity", Attrs::new(), encode_signed_device_identity(account, true)));
                self.logger.debug("adding device identity");
            }
            if let Some(reporting) = reporting_message.as_ref().filter(|r| !is_retry_resend && !is_newsletter && r.message_context_info().and_then(|c| c.message_secret()).is_some() && should_include_reporting_token(r)) {
                let encoded = encode_wa_message(reporting);
                let mut reporting_key = WAMessageKey::default().with_id(msg_id.as_str()).with_from_me(true).with_remote_jid(destination_jid.as_str());
                if let Some(p) = &participant {
                    reporting_key.set_participant(p.jid.as_str());
                }
                match get_message_reporting_token(&encoded, reporting, &reporting_key) {
                    Ok(Some(node)) => {
                        content.push(node);
                        self.logger.trace("added reporting token to message");
                    }
                    Ok(None) => {}
                    Err(error) => self.logger.warn(&format!("failed to attach reporting token: {error}")),
                }
            }
            // WA Web never attaches tctoken to peer (AppStateSync) messages — server rejects with 479
            let is_peer_message = extra_get(&additional_attributes, "category") == Some("peer");
            let is_1on1_send = !is_group && !is_retry_resend && !is_status && !is_newsletter && !is_peer_message;
            // Resolve destination to LID for tctoken storage — matches Signal session key pattern
            let tc_token_jid = if is_1on1_send { resolve_tc_token_jid(&destination_jid, &get_lid)? } else { destination_jid.clone() };
            let existing_token_entry = if is_1on1_send {
                match self.keys.get_one(KeyKind::TcToken, &tc_token_jid)? {
                    Some(KeyValue::TcToken(e)) => Some(e),
                    _ => None,
                }
            } else {
                None
            };
            let mut tc_token_buffer = existing_token_entry.as_ref().map(|e| e.token.clone()).filter(|t| !t.is_empty());
            // Treat expired tokens the same as missing — clear from cache
            if let (Some(_), Some(entry)) = (&tc_token_buffer, &existing_token_entry) {
                if is_tc_token_expired_str(entry.timestamp.as_deref()) {
                    self.logger.debug("tctoken expired, clearing");
                    tc_token_buffer = None;
                    // Preserve senderTimestamp so the fire-and-forget issuance dedupe survives cleanup.
                    let cleared = entry.sender_timestamp.map(|s| KeyValue::TcToken(TcTokenEntry { token: Bytes::new(), timestamp: None, sender_timestamp: Some(s) }));
                    if let Err(err) = self.keys.set_one(KeyKind::TcToken, &tc_token_jid, cleared) {
                        self.logger.debug(&format!("failed to persist tctoken expiry cleanup: {err}"));
                    }
                }
            }
            if let Some(t) = tc_token_buffer.filter(|_| self.chats.server_props.privacy_token_on_1to1.load(std::sync::atomic::Ordering::Relaxed)) {
                content.push(BinaryNode::with_bytes("tctoken", Attrs::new(), t));
            }
            content.extend(additional_nodes.iter().cloned());
            self.logger.debug("sending message");
            self.send_node(&BinaryNode::with_nodes("message", attrs, content))?;
            // Fire-and-forget: issue our token to the contact AFTER message send.
            // WA Web skips protocol messages and PSA/bot contacts (TcTokenChatAction: isRegularUser)
            let is_protocol_msg = normalized.is_some_and(|n| n.protocol_message().is_some());
            let is_bot_or_psa = destination_jid == PSA_WID || is_jid_bot(&destination_jid) || is_jid_meta_ai(&destination_jid);
            let sender_timestamp = existing_token_entry.as_ref().and_then(|e| e.sender_timestamp);
            if is_1on1_send && !is_protocol_msg && !is_bot_or_psa && should_send_new_tc_token(sender_timestamp) && self.send.in_flight_tc_token_issuance.lock().unwrap().insert(tc_token_jid.clone()) {
                self.spawn_tc_token_issuance(destination_jid.clone(), tc_token_jid.clone());
            }
            // Add message to retry cache if enabled
            if let Some(m) = self.send.message_retry_manager.as_ref().filter(|_| participant.is_none()) {
                m.add_recent_message(&destination_jid, &msg_id, message.clone());
            }
            Ok(())
        })?;
        Ok(msg_id)
    }
    fn spawn_tc_token_issuance(&self, destination_jid: String, tc_token_jid: String) {
        let Some(sock) = upgrade(&self.self_weak()) else { return };
        let issue_timestamp = unix_timestamp_seconds(None);
        sock.on_lane(LaneId::Control, move |s| {
            let lid_mapping = s.signal_repository.lid_mapping();
            let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);
            let get_pn = |lid: &str| lid_mapping.get_pn_for_lid(lid);
            let run = || -> Result<()> {
                let issue_to_lid = s.chats.server_props.lid_trusted_token_issue_to_lid.load(std::sync::atomic::Ordering::Relaxed);
                let issue_jid = resolve_issuance_jid(&destination_jid, issue_to_lid, &get_lid, Some(&get_pn))?;
                let result = s.issue_privacy_tokens(&[issue_jid], Some(issue_timestamp))?;
                let empty = BinaryNode::tag("iq", Attrs::new());
                store_tc_tokens_from_iq_result(result.as_ref().unwrap_or(&empty), &tc_token_jid, s.keys.as_ref(), &get_lid, None)?;
                let current_entry = match s.keys.get_one(KeyKind::TcToken, &tc_token_jid)? {
                    Some(KeyValue::TcToken(e)) => Some(e),
                    _ => None,
                };
                let index_write = build_merged_tc_token_index_write(s.keys.as_ref(), std::slice::from_ref(&tc_token_jid))?;
                let mut entry = current_entry.unwrap_or_default();
                entry.sender_timestamp = Some(issue_timestamp as f64);
                s.keys.set(vec![(KeyKind::TcToken, tc_token_jid.clone(), Some(KeyValue::TcToken(entry))), (KeyKind::TcToken, TC_TOKEN_INDEX_KEY.to_string(), Some(KeyValue::TcToken(index_write)))])
            };
            if let Err(err) = run() {
                s.logger.debug(&format!("fire-and-forget tctoken issuance failed: {err}"));
            }
            s.send.in_flight_tc_token_issuance.lock().unwrap().remove(&tc_token_jid);
        });
    }
    pub fn issue_privacy_tokens(&self, jids: &[String], timestamp: Option<i64>) -> Result<Option<BinaryNode>> {
        let t = timestamp.unwrap_or_else(|| unix_timestamp_seconds(None)).to_string();
        let tokens = jids
            .iter()
            .map(|jid| {
                let n = jid_normalized_user(jid);
                BinaryNode::tag("token", Attrs::from([("jid", n.as_str()), ("t", t.as_str()), ("type", "trusted_contact")]))
            })
            .collect();
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "privacy")]), vec![BinaryNode::with_nodes("tokens", Attrs::new(), tokens)]), None)
    }
    /// Asks the phone to re-upload a media message, and waits for the new URL.
    pub fn update_media_message(&self, mut message: WAMessage) -> Result<WAMessage> {
        let content = assert_media_content(message.message())?;
        let media_key_of = |c: &MediaMessage| -> Option<Bytes> {
            match c {
                MediaMessage::Document(m) => m.media_key().cloned(),
                MediaMessage::Image(m) => m.media_key().cloned(),
                MediaMessage::Video(m) => m.media_key().cloned(),
                MediaMessage::Audio(m) => m.media_key().cloned(),
                MediaMessage::Sticker(m) => m.media_key().cloned(),
            }
        };
        let media_key = media_key_of(&content).unwrap_or_default();
        let me_id = self.me_id().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'id')"))?;
        let key = message.key().cloned().unwrap_or_default();
        let msg_id = key.id().map_or(String::new(), |i| i.as_str().to_string());
        let node = encrypt_media_retry_request(&key, media_key.as_slice(), &me_id)?;
        // the listener goes first: the reply can arrive before `send_node` returns
        let waiter: Resolver<MessageMediaUpdate> = Resolver::new();
        let (found, close, wanted) = (waiter.clone(), waiter.clone(), msg_id.clone());
        // `on_emit`, so that this also works in a listener, where a queued event could never run
        let media_id = self.ev.on_emit(
            EventKind::MessagesMediaUpdate,
            Arc::new(move |e: &BaileysEvent| {
                if let BaileysEvent::MessagesMediaUpdate(list) = e {
                    if let Some(r) = list.iter().find(|c| c.key.id().map(|i| i.as_str()) == Some(wanted.as_str())) {
                        found.resolve(r.clone());
                    }
                }
            }),
        );
        let close_id = self.ev.on_emit(
            EventKind::ConnectionUpdate,
            Arc::new(move |e: &BaileysEvent| {
                if let BaileysEvent::ConnectionUpdate(u) = e {
                    if u.connection == Some(WAConnectionState::Close) {
                        close.reject(u.last_disconnect.as_ref().and_then(|d| d.error.clone()).unwrap_or_else(super::socket::connection_closed));
                    }
                }
            }),
        );
        let sent = self.send_node(&node);
        let outcome = match sent {
            Ok(()) => waiter.wait(None).unwrap_or_else(|| Err(super::socket::connection_closed())),
            Err(e) => Err(e),
        };
        self.ev.off_emit(media_id);
        self.ev.off_emit(close_id);
        let result = outcome?;
        if let Some(error) = result.error {
            return Err(error);
        }
        let media = result.media.ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'ciphertext')"))?;
        let retry = decrypt_media_retry_data(media.ciphertext.as_slice(), media.iv.as_slice(), media_key.as_slice(), &msg_id)?;
        if retry.result() != Some(ResultType::SUCCESS) {
            let code = retry.result().map_or(0, |r| r.0);
            let name = retry.result().and_then(|r| r.name()).unwrap_or("undefined");
            let mut e = Boom::with_data(format!("Media re-upload failed by device ({name})"), retry.to_json());
            e.status_code = Some(get_status_code_for_media_retry(code).unwrap_or(404));
            return Err(e);
        }
        let direct_path = retry.direct_path().map(|d| d.as_str().to_string());
        let host = self.get_media_host();
        let url = direct_path.as_deref().map(|d| get_url_from_direct_path(d, Some(&host)));
        // `normalize` reaches the same inner message that `assert_media_content` read. A template has a
        // copy there, and upstream also changes only a copy in that case.
        macro_rules! set_paths {
            ($get:ident, $get_mut:ident) => {
                if let Some(c) = normalize_message_content_mut(message.message_mut()) {
                    if c.$get().is_some() {
                        let m = c.$get_mut();
                        match &direct_path {
                            Some(d) => m.set_direct_path(d.as_str()),
                            None => m.clear_direct_path(),
                        }
                        match &url {
                            Some(u) => m.set_url(u.as_str()),
                            None => m.clear_url(),
                        }
                    }
                }
            };
        }
        match content {
            MediaMessage::Document(_) => set_paths!(document_message, document_message_mut),
            MediaMessage::Image(_) => set_paths!(image_message, image_message_mut),
            MediaMessage::Video(_) => set_paths!(video_message, video_message_mut),
            MediaMessage::Audio(_) => set_paths!(audio_message, audio_message_mut),
            MediaMessage::Sticker(_) => set_paths!(sticker_message, sticker_message_mut),
        }
        self.logger.debug("media update successful");
        let mut update = WAMessage::default();
        if let Some(m) = message.message() {
            update.set_message(m.clone());
        }
        self.ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key, update }]));
        Ok(message)
    }
    fn message_generation_options(&self, options: MiscMessageGenerationOptions) -> Result<MessageGenerationOptions> {
        let weak = self.self_weak();
        let upload = self.send.wa_upload_to_server.clone();
        let logger = self.logger.clone();
        let (width, hq, http) = (self.config.link_preview_image_thumbnail_width, self.config.generate_high_quality_link_preview, self.config.options.clone());
        let preview_upload = upload.clone();
        let get_url: GetUrlInfo = Arc::new(move |text: &str| {
            let opts = URLGenerationOptions { thumbnail_width: width, timeout_ms: 3_000, headers: http.headers.clone(), logger: Some(logger.clone()), upload_image: if hq { Some(preview_upload.clone()) } else { None } };
            get_url_info(text, &opts).ok().flatten()
        });
        let weak_pic = weak.clone();
        //TODO: CACHE
        let get_profile_pic: GetProfilePicUrl = Arc::new(move |jid: &str, t: ProfilePictureType| {
            let s = upgrade(&weak_pic)?;
            s.profile_picture_url(jid, if t == ProfilePictureType::Image { "image" } else { "preview" }, None).ok().flatten()
        });
        let get_call_link: GetCallLink = Arc::new(move |t: CallType, start: Option<u64>| {
            let s = upgrade(&weak)?;
            s.create_call_link(t, start, None).ok().flatten()
        });
        let media = MediaGenerationOptions {
            logger: Some(self.logger.clone()),
            media_type_override: None,
            upload,
            media_cache: self.config.media_cache.clone(),
            media_upload_timeout_ms: options.media_upload_timeout_ms,
            options: Some(self.config.options.clone()),
            background_color: options.background_color.clone(),
            font: options.font,
        };
        let mut misc = options;
        let user_jid = self.me_id().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'id')"))?;
        if misc.message_id.is_none() {
            misc.message_id = Some(generate_message_id_v2(Some(&user_jid)));
        }
        Ok(MessageGenerationOptions { content: MessageContentGenerationOptions { media, get_url_info: Some(get_url), get_profile_pic_url: Some(get_profile_pic), get_call_link: Some(get_call_link), jid: None }, from_content: MessageGenerationOptionsFromContent { misc, user_jid } })
    }
    /// The value is `None` for a change of the disappearing mode of a group, which sends no message.
    pub fn send_message(&self, jid: &str, content: &AnyMessageContent, options: MiscMessageGenerationOptions) -> Result<Option<WAMessage>> {
        if let (AnyMessageContent::DisappearingMessagesInChat(d), true) = (content, is_jid_group(jid)) {
            let value = match d {
                DisappearingMessages::Enabled(true) => WA_DEFAULT_EPHEMERAL,
                DisappearingMessages::Enabled(false) => 0,
                DisappearingMessages::Seconds(s) => *s,
            };
            self.group_toggle_ephemeral(jid, value)?;
            return Ok(None);
        }
        let use_cached_group_metadata = options.use_cached_group_metadata;
        let status_jid_list = options.status_jid_list.clone();
        let full_msg = generate_wa_message(jid, content, &self.message_generation_options(options)?)?;
        let regular = match content {
            AnyMessageContent::Regular(r) => Some(&r.content),
            _ => None,
        };
        let mut additional_attributes: Vec<(String, String)> = Vec::new();
        let mut additional_nodes: Vec<BinaryNode> = Vec::new();
        let edit_key = match regular {
            Some(RegularContent::Text { edit, .. }) | Some(RegularContent::Poll { edit, .. }) => edit.as_ref(),
            _ => None,
        };
        // required for delete
        if let AnyMessageContent::Delete(key) = content {
            // if the chat is a group, and I am not the author, then delete the message as an admin
            let group = key.remote_jid().is_some_and(|r| is_jid_group(r.as_str()));
            let edit = if group && key.from_me() != Some(true) { "8" } else { "7" };
            additional_attributes.push(("edit".to_string(), edit.to_string()));
        } else if edit_key.is_some() {
            additional_attributes.push(("edit".to_string(), "1".to_string()));
        } else if matches!(regular, Some(RegularContent::Pin { .. })) {
            additional_attributes.push(("edit".to_string(), "2".to_string()));
        } else if matches!(regular, Some(RegularContent::Poll { .. })) {
            additional_nodes.push(BinaryNode::tag("meta", Attrs::from([("polltype", "creation")])));
        } else if matches!(regular, Some(RegularContent::Event(_))) {
            additional_nodes.push(BinaryNode::tag("meta", Attrs::from([("event_type", "creation")])));
        }
        let message = full_msg.message().cloned().unwrap_or_default();
        self.relay_message(
            jid,
            &message,
            MessageRelayOptions {
                message_id: full_msg.key().and_then(|k| k.id()).map(|i| i.as_str().to_string()),
                use_cached_group_metadata,
                additional_attributes: Some(additional_attributes),
                status_jid_list,
                additional_nodes: Some(additional_nodes),
                ..MessageRelayOptions::default()
            },
        )?;
        if self.config.emit_own_events {
            if let Some(sock) = upgrade(&self.self_weak()) {
                let own = full_msg.clone();
                sock.on_lane(LaneId::Message, move |s| {
                    if let Err(e) = s.chats.message_mutex.mutex(|| s.upsert_message(own, MessageUpsertType::Append)) {
                        s.on_unexpected_error(&e, "own message upsert");
                    }
                });
            }
        }
        Ok(Some(full_msg))
    }
}
impl Socket {
    pub(crate) fn register_send_listeners(&self) {
        let weak = self.weak();
        self.register_socket_end_handler(Arc::new(move |_| {
            let Some(s) = upgrade(&weak) else { return };
            if s.config.user_devices_cache.is_none() {
                s.send.user_devices_cache.close();
            }
            *s.send.media_conn.lock().unwrap() = None;
            if let Some(m) = &s.send.message_retry_manager {
                m.clear();
            }
        }));
    }
}
