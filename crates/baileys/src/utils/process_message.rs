//! Same behavior as Utils/process-message.ts.
use crate::auth::{AuthenticationCreds, CredsUpdate, KeyKind, KeyValue, LidMapping, SignalKeyStore, TcTokenEntry};
use crate::error::{Boom, Result};
use crate::events::{BaileysEvent, BaileysEventEmitter, GroupJoinRequest, GroupMemberTagUpdate, GroupParticipantsUpdate, MessageReaction, MessagesUpsert, MessagingHistorySet};
use crate::signal::repository::SignalRepository;
use crate::types::*;
use crate::utils::generics::{JsMap, get_key_author, to_number};
use crate::utils::history::download_and_process_history_sync_notification;
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::messages::{get_content_type, normalize_message_content, normalize_message_content_mut};
use crate::utils::tc_token_utils::{build_merged_tc_token_index_write, js_to_number, resolve_tc_token_jid, TC_TOKEN_INDEX_KEY};
use crate::wabinary::{are_jids_same_user, is_hosted_lid_user, is_hosted_pn_user, is_jid_broadcast, is_jid_status_broadcast, is_lid_user, jid_decode, jid_encode, jid_normalized_user};
use crate::{crypto, types::WAMessageStubType as Stub};
use waproto::history_sync::HistorySyncType;
use waproto::message::protocol_message::Type as ProtocolType;
use waproto::message::{EventResponseMessage, FutureProofMessage, PollVoteMessage};
use waproto::pb::{Json, PbMessage, base64_encode};
use waproto::{EventResponse, HistorySyncMsg, LIDMigrationMappingSyncPayload, Reaction, WebMessageInfo};

fn is_real_stub(t: Option<WAMessageStubType>) -> bool {
    matches!(t, Some(WAMessageStubType::CALL_MISSED_GROUP_VIDEO | WAMessageStubType::CALL_MISSED_GROUP_VOICE | WAMessageStubType::CALL_MISSED_VIDEO | WAMessageStubType::CALL_MISSED_VOICE | WAMessageStubType::GROUP_PARTICIPANT_ADD))
}
fn store_tc_tokens_from_history_sync(chats: &[Chat], signal_repository: &dyn SignalRepository, key_store: &dyn SignalKeyStore, logger: Option<&dyn Logger>) -> Result<()> {
    struct Candidate {
        storage_jid: String,
        token: waproto::pb::Bytes,
        ts: f64,
        sender_ts: Option<f64>,
    }
    let lid_mapping = signal_repository.lid_mapping();
    let get_lid_for_pn = |pn: &str| lid_mapping.get_lid_for_pn(pn);
    let mut candidates: Vec<Candidate> = Vec::new();
    for chat in chats {
        let ts = to_number(chat.tc_token_timestamp());
        if let Some(token) = chat.tc_token().filter(|t| !t.is_empty() && ts > 0.0) {
            let jid = jid_normalized_user(chat.id().map_or("", |s| s.as_str()));
            let storage_jid = resolve_tc_token_jid(&jid, &get_lid_for_pn)?;
            candidates.push(Candidate { storage_jid, token: token.clone(), ts, sender_ts: chat.tc_token_sender_timestamp().filter(|t| *t != 0).map(|t| t as f64) });
        }
    }
    if candidates.is_empty() {
        return Ok(());
    }
    let jids: Vec<String> = candidates.iter().map(|c| c.storage_jid.clone()).collect();
    let existing = key_store.get(KeyKind::TcToken, &jids)?;
    let mut entries: JsMap<TcTokenEntry> = JsMap::new();
    for c in candidates {
        let existing_entry = match existing.get(&c.storage_jid) {
            Some(KeyValue::TcToken(e)) => Some(e),
            _ => None,
        };
        let existing_ts = existing_entry.and_then(|e| e.timestamp.as_deref()).filter(|t| !t.is_empty()).map_or(0.0, js_to_number);
        if existing_ts > 0.0 && existing_ts >= c.ts {
            continue;
        }
        let sender_timestamp = c.sender_ts.or_else(|| existing_entry.and_then(|e| e.sender_timestamp));
        entries.insert(c.storage_jid, TcTokenEntry { token: c.token, timestamp: Some(waproto::pb::js_number(c.ts)), sender_timestamp });
    }
    if entries.is_empty() {
        return Ok(());
    }
    if let Some(l) = logger {
        l.debug(&format!("storing tctokens from history sync: {}", entries.len()));
    }
    let store = || -> Result<()> {
        // Include updated __index so cross-session pruning picks these JIDs up.
        let added: Vec<String> = entries.iter().map(|(k, _)| k.to_string()).collect();
        let index = build_merged_tc_token_index_write(key_store, &added)?;
        let mut writes: Vec<KeyWrite> = entries.iter().map(|(k, v)| (KeyKind::TcToken, k.to_string(), Some(KeyValue::TcToken(v.clone())))).collect();
        writes.push((KeyKind::TcToken, TC_TOKEN_INDEX_KEY.to_string(), Some(KeyValue::TcToken(index))));
        key_store.set(writes)
    };
    if let Err(err) = store() {
        if let Some(l) = logger {
            l.warn(&format!("failed to store tctokens from history sync: {err}"));
        }
    }
    Ok(())
}
fn clean_jid(jid: Option<&str>) -> String {
    let jid = jid.unwrap_or("");
    if is_hosted_pn_user(jid) || is_hosted_lid_user(jid) {
        let user = jid_decode(jid).map_or("", |d| d.user);
        return jid_encode(user, if is_hosted_pn_user(jid) { "s.whatsapp.net" } else { "lid" }, None, None);
    }
    jid_normalized_user(jid)
}
/// Cleans a received message to further processing
pub fn clean_message(message: &mut WAMessage, me_id: &str, me_lid: &str) -> Result<()> {
    // ensure remoteJid and participant doesn't have device or agent in it
    let key = message.key_mut();
    let remote = clean_jid(key.remote_jid().map(|s| s.as_str()));
    key.set_remote_jid(remote);
    let participant = clean_jid(key.participant().map(|s| s.as_str()));
    key.set_participant(participant);
    let from_me = key.from_me() == Some(true);
    let outer_remote = key.remote_jid().cloned();
    let outer_participant = key.participant().cloned();
    if message.message().is_none() {
        return Ok(());
    }
    let Some(content) = normalize_message_content_mut(message.message_mut()) else { return Ok(()) };
    let normalise_key = |msg_key: Option<&mut WAMessageKey>| -> Result<()> {
        // if the reaction is from another user
        // we've to correctly map the key to this user's perspective
        if from_me {
            return Ok(());
        }
        let Some(msg_key) = msg_key else {
            return Err(Boom::new("Cannot read properties of undefined (reading 'fromMe')"));
        };
        // if the sender believed the message being reacted to is not from them
        // we've to correct the key to be from them, or some other participant
        let was_from_me = msg_key.from_me() == Some(true);
        let author = msg_key.participant().filter(|p| !p.is_empty()).or(msg_key.remote_jid()).map(|s| s.as_str());
        let next = !was_from_me && (are_jids_same_user(author, Some(me_id)) || are_jids_same_user(author, Some(me_lid)));
        msg_key.set_from_me(next);
        // set the remoteJid to being the same as the chat the message came from
        // TODO: investigate inconsistencies
        match &outer_remote {
            Some(r) => msg_key.set_remote_jid(r.clone()),
            None => msg_key.clear_remote_jid(),
        }
        // set participant of the message
        if msg_key.participant().is_none_or(|p| p.is_empty()) {
            match &outer_participant {
                Some(p) => msg_key.set_participant(p.clone()),
                None => msg_key.clear_participant(),
            }
        }
        Ok(())
    };
    // if the message has a reaction, ensure fromMe & remoteJid are from our perspective
    if content.reaction_message().is_some() {
        let r = content.reaction_message_mut();
        let has_key = r.key().is_some();
        normalise_key(if has_key { Some(r.key_mut()) } else { None })?;
    }
    if content.poll_update_message().is_some() {
        let p = content.poll_update_message_mut();
        let has_key = p.poll_creation_message_key().is_some();
        normalise_key(if has_key { Some(p.poll_creation_message_key_mut()) } else { None })?;
    }
    Ok(())
}
pub fn is_real_message(message: &WAMessage) -> bool {
    let normalized = normalize_message_content(message.message());
    let has_some_content = get_content_type(normalized).is_some();
    (normalized.is_some() || is_real_stub(message.message_stub_type()))
        && has_some_content
        && normalized.is_none_or(|c| c.protocol_message().is_none() && c.reaction_message().is_none() && c.poll_update_message().is_none())
}
pub fn should_increment_chat_unread(message: &WAMessage) -> bool {
    message.key().and_then(|k| k.from_me()) != Some(true) && message.message_stub_type().is_none_or(|t| t.0 == 0)
}
/// Get the ID of the chat from the given key.
/// Typically -- that'll be the remoteJid, but for broadcasts, it'll be the participant
pub fn get_chat_id(key: &WAMessageKey) -> Result<String> {
    let from_me = key.from_me();
    let flag = || from_me.map_or(Json::Null, Json::Bool);
    let Some(remote_jid) = key.remote_jid().filter(|r| !r.is_empty()) else {
        let data = Json::Obj(vec![("participant".to_string(), key.participant().map_or(Json::Null, |p| Json::Str(p.to_string()))), ("fromMe".to_string(), flag())]);
        return Err(Boom::with_data("Cannot derive chat id: message key is missing remoteJid", data));
    };
    if is_jid_broadcast(remote_jid) && !is_jid_status_broadcast(remote_jid) && from_me != Some(true) {
        let Some(participant) = key.participant().filter(|p| !p.is_empty()) else {
            let data = Json::Obj(vec![("remoteJid".to_string(), Json::Str(remote_jid.to_string())), ("fromMe".to_string(), flag())]);
            return Err(Boom::with_data("Cannot derive chat id: broadcast message key is missing participant", data));
        };
        return Ok(participant.as_str().to_string());
    }
    Ok(remote_jid.as_str().to_string())
}
/// additional info about the poll required for decryption
pub struct PollContext<'a> {
    /// normalised jid of the person that created the poll
    pub poll_creator_jid: &'a str,
    /// ID of the poll creation message
    pub poll_msg_id: &'a str,
    /// poll creation message enc key
    pub poll_enc_key: &'a [u8],
    /// jid of the person that voted
    pub voter_jid: &'a str,
}
/// additional info about the event required for decryption
pub struct EventContext<'a> {
    /// normalised jid of the person that created the event
    pub event_creator_jid: &'a str,
    /// ID of the event creation message
    pub event_msg_id: &'a str,
    /// event creation message enc key
    pub event_enc_key: &'a [u8],
    /// jid of the person that responded
    pub responder_jid: &'a str,
}
fn decrypt_with_secret(enc_payload: Option<&[u8]>, enc_iv: Option<&[u8]>, msg_id: &str, creator: &str, actor: &str, label: &str, enc_key: &[u8]) -> Result<Vec<u8>> {
    let mut sign = Vec::with_capacity(msg_id.len() + creator.len() + actor.len() + label.len() + 1);
    sign.extend_from_slice(msg_id.as_bytes());
    sign.extend_from_slice(creator.as_bytes());
    sign.extend_from_slice(actor.as_bytes());
    sign.extend_from_slice(label.as_bytes());
    sign.push(1);
    let key0 = crypto::hmac_sha256(&[0u8; 32], enc_key);
    let dec_key = crypto::hmac_sha256(&key0, &sign);
    let mut aad = Vec::with_capacity(msg_id.len() + actor.len() + 1);
    aad.extend_from_slice(msg_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(actor.as_bytes());
    let missing = || Boom::new("Cannot read properties of undefined (reading 'subarray')");
    crypto::aes_decrypt_gcm(enc_payload.ok_or_else(missing)?, &dec_key, enc_iv.ok_or_else(missing)?, &aad)
}
/// Decrypt a poll vote. Returns the list of SHA256 options.
pub fn decrypt_poll_vote(enc_payload: Option<&[u8]>, enc_iv: Option<&[u8]>, ctx: &PollContext<'_>) -> Result<PollVoteMessage> {
    let decrypted = decrypt_with_secret(enc_payload, enc_iv, ctx.poll_msg_id, ctx.poll_creator_jid, ctx.voter_jid, "Poll Vote", ctx.poll_enc_key)?;
    Ok(PollVoteMessage::decode(&decrypted)?)
}
/// Decrypt an event response.
pub fn decrypt_event_response(enc_payload: Option<&[u8]>, enc_iv: Option<&[u8]>, ctx: &EventContext<'_>) -> Result<EventResponseMessage> {
    let decrypted = decrypt_with_secret(enc_payload, enc_iv, ctx.event_msg_id, ctx.event_creator_jid, ctx.responder_jid, "Event Response", ctx.event_enc_key)?;
    Ok(EventResponseMessage::decode(&decrypted)?)
}
pub struct ProcessMessageContext<'a> {
    pub should_process_history_msg: bool,
    pub placeholder_resend_cache: Option<&'a dyn CacheStore>,
    pub creds: &'a AuthenticationCreds,
    pub key_store: &'a dyn SignalKeyStore,
    pub ev: &'a dyn BaileysEventEmitter,
    pub logger: Option<&'a dyn Logger>,
    pub options: &'a RequestInit,
    pub signal_repository: &'a dyn SignalRepository,
    pub get_message: &'a (dyn Fn(&WAMessageKey) -> Option<WAMessageContent> + Send + Sync),
}
fn parse_participants(message: &WAMessage) -> Result<Vec<GroupParticipant>> {
    let mut out = Vec::with_capacity(message.message_stub_parameters().len());
    for a in message.message_stub_parameters() {
        out.push(parse_participant(&Json::parse(a)?));
    }
    Ok(out)
}
fn parse_participant(j: &Json) -> GroupParticipant {
    let text = |k: &str| j.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let contact = Contact {
        id: text("id").unwrap_or_default(),
        lid: text("lid"),
        phone_number: text("phoneNumber"),
        name: text("name"),
        notify: text("notify"),
        username: text("username"),
        verified_name: text("verifiedName"),
        img_url: j.get("imgUrl").map(|v| v.as_str().map(str::to_string)),
        status: text("status"),
    };
    let admin = j.get("admin").map(|v| match v.as_str() {
        Some("admin") => Some(GroupAdmin::Admin),
        Some("superadmin") => Some(GroupAdmin::Superadmin),
        _ => None,
    });
    GroupParticipant { contact, is_admin: j.get("isAdmin").and_then(Json::as_bool), is_super_admin: j.get("isSuperAdmin").and_then(Json::as_bool), admin }
}
/// `message.key` with another `id`.
fn key_with_id(message: &WAMessage, id: Option<&waproto::pb::Str>) -> WAMessageKey {
    let mut key = message.key().cloned().unwrap_or_default();
    match id {
        Some(i) => key.set_id(i.clone()),
        None => key.clear_id(),
    }
    key
}
fn not_read(what: &str) -> Boom {
    Boom::new(format!("Cannot read properties of undefined (reading '{what}')"))
}
pub fn process_message(message: &WAMessage, ctx: &ProcessMessageContext<'_>) -> Result<()> {
    let ProcessMessageContext { should_process_history_msg, placeholder_resend_cache, creds, key_store, ev, logger, options, signal_repository, get_message } = *ctx;
    let me_id = creds.me.as_ref().map(|m| m.id.as_str()).ok_or_else(|| not_read("id"))?;
    let default_key = WAMessageKey::new();
    let message_key = message.key().unwrap_or(&default_key);

    let mut chat = Chat::new();
    chat.set_id(jid_normalized_user(&get_chat_id(message_key)?));
    // `chat.name = undefined` still adds a key, and upstream then emits the update
    let mut has_empty_key = false;
    let is_real_msg = is_real_message(message);
    if is_real_msg {
        chat.set_messages(vec![HistorySyncMsg::new().with_message(message.clone())]);
        chat.set_conversation_timestamp(to_number(message.message_timestamp()) as u64);
        // only increment unread count if not CIPHERTEXT and from another person
        if should_increment_chat_unread(message) {
            chat.set_unread_count(1);
        }
    }
    let content = normalize_message_content(message.message());
    let from_me = message_key.from_me() == Some(true);
    // unarchive chat if it's a real message, or someone reacted to our message
    // and we've the unarchive chats setting on
    let reacted_to_me = content.and_then(|c| c.reaction_message()).and_then(|r| r.key()).and_then(|k| k.from_me()) == Some(true);
    if (is_real_msg || reacted_to_me) && creds.account_settings.unarchive_chats {
        chat.set_archived(false);
        chat.set_read_only(false);
    }
    if let Some(protocol_msg) = content.and_then(|c| c.protocol_message()) {
        let msg_type = protocol_msg.r#type();
        // Mirror whatsmeow's `handleProtocolMessage` guard, but applied only to
        // the protocol message types that originate from our own device -- an
        // attacker could otherwise spoof any of these to manipulate local state.
        let self_only = matches!(msg_type, Some(ProtocolType::HISTORY_SYNC_NOTIFICATION | ProtocolType::APP_STATE_SYNC_KEY_SHARE | ProtocolType::LID_MIGRATION_MAPPING_SYNC | ProtocolType::PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE));
        if self_only && !from_me {
            if let Some(l) = logger {
                l.warn("dropping spoofed self-only protocolMessage from non-self origin");
            }
            return Ok(());
        }
        match msg_type {
            Some(ProtocolType::HISTORY_SYNC_NOTIFICATION) => {
                let hist = protocol_msg.history_sync_notification().ok_or_else(|| not_read("syncType"))?;
                let is_latest = creds.processed_history_messages.is_empty();
                if let Some(l) = logger {
                    l.info("got history notification");
                }
                if should_process_history_msg {
                    let on_demand = hist.sync_type().is_some_and(|t| t.0 == HistorySyncType::ON_DEMAND.0);
                    // TODO: investigate
                    if !on_demand {
                        let mut processed = creds.processed_history_messages.clone();
                        processed.push(MinimalMessage { key: message_key.clone(), message_timestamp: message.message_timestamp() });
                        ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { processed_history_messages: Some(processed), ..CredsUpdate::default() })));
                    }
                    let data = download_and_process_history_sync_notification(hist, options, logger)?;
                    if !data.lid_pn_mappings.is_empty() {
                        if let Some(l) = logger {
                            l.debug("processing LID-PN mappings from history sync");
                        }
                        if let Err(err) = signal_repository.lid_mapping().store_lid_pn_mappings(&data.lid_pn_mappings) {
                            if let Some(l) = logger {
                                l.warn(&format!("failed to store LID-PN mappings from history sync: {err}"));
                            }
                        }
                    }
                    store_tc_tokens_from_history_sync(&data.chats, signal_repository, key_store, logger)?;
                    ev.emit(BaileysEvent::MessagingHistorySet(MessagingHistorySet {
                        chats: data.chats,
                        contacts: data.contacts,
                        messages: data.messages,
                        lid_pn_mappings: Some(data.lid_pn_mappings),
                        is_latest: if on_demand { None } else { Some(is_latest) },
                        progress: Some(data.progress.map(f64::from)),
                        sync_type: Some(data.sync_type),
                        past_participants: data.past_participants.map(Some),
                        chunk_order: Some(hist.chunk_order()),
                        peer_data_request_session_id: Some(hist.peer_data_request_session_id().map(|s| s.as_str().to_string())),
                    }));
                }
            }
            Some(ProtocolType::APP_STATE_SYNC_KEY_SHARE) => {
                let keys = protocol_msg.app_state_sync_key_share().ok_or_else(|| not_read("keys"))?.keys();
                if keys.is_empty() {
                    if let Some(l) = logger {
                        l.info("recv app state sync with 0 keys");
                    }
                } else {
                    let mut new_app_state_sync_key_id = String::new();
                    key_store.transaction(
                        &mut || {
                            for k in keys {
                                let key_id = k.key_id().and_then(|i| i.key_id()).ok_or_else(|| not_read("keyId"))?;
                                let str_key_id = base64_encode(key_id);
                                let data = k.key_data().cloned().unwrap_or_default();
                                key_store.set_one(KeyKind::AppStateSyncKey, &str_key_id, Some(KeyValue::AppStateSyncKey(data)))?;
                                new_app_state_sync_key_id = str_key_id;
                            }
                            Ok(())
                        },
                        me_id,
                    )?;
                    if let Some(l) = logger {
                        l.info(&format!("injecting new app state sync keys: {new_app_state_sync_key_id}"));
                    }
                    ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { my_app_state_key_id: Some(Some(new_app_state_sync_key_id)), ..CredsUpdate::default() })));
                }
            }
            Some(ProtocolType::REVOKE) => {
                let id = protocol_msg.key().ok_or_else(|| not_read("id"))?.id();
                let mut update = WebMessageInfo::new();
                update.set_message_null();
                update.set_message_stub_type(Stub::REVOKE);
                update.set_key(message_key.clone());
                ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key: key_with_id(message, id), update }]));
            }
            Some(ProtocolType::EPHEMERAL_SETTING) => {
                chat.set_ephemeral_setting_timestamp(to_number(message.message_timestamp()) as i64);
                match protocol_msg.ephemeral_expiration().filter(|e| *e != 0) {
                    Some(e) => chat.set_ephemeral_expiration(e),
                    None => chat.set_ephemeral_expiration_null(),
                }
            }
            Some(ProtocolType::PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE) => {
                if let Some(response) = protocol_msg.peer_data_operation_request_response_message() {
                    // TODO: IMPLEMENT HISTORY SYNC ETC (sticker uploads etc.).
                    for result in response.peer_data_operation_result() {
                        let Some(bytes) = result.placeholder_message_resend_response().and_then(|r| r.web_message_info_bytes()) else { continue };
                        let run = || -> Result<()> {
                            let web_message_info = WebMessageInfo::decode(bytes)?;
                            let msg_id = web_message_info.key().and_then(|k| k.id()).filter(|i| !i.is_empty());
                            // Retrieve cached original message data (preserves LID details,
                            // timestamps, etc. that the phone may omit in its PDO response)
                            let cached_data = match (msg_id, placeholder_resend_cache) {
                                (Some(id), Some(cache)) => {
                                    let v = cache_get::<WAMessage>(cache, id);
                                    cache.del(id);
                                    v
                                }
                                _ => None,
                            };
                            let final_msg = match cached_data {
                                Some(cached) => {
                                    // Apply decoded message content onto cached metadata (preserves LID etc.)
                                    let mut merged = (*cached).clone();
                                    match web_message_info.message() {
                                        Some(m) => merged.set_message(m.clone()),
                                        None => merged.clear_message(),
                                    }
                                    if let Some(t) = web_message_info.message_timestamp().filter(|t| *t != 0) {
                                        merged.set_message_timestamp(t);
                                    }
                                    merged
                                }
                                None => web_message_info,
                            };
                            if let Some(l) = logger {
                                l.debug("received placeholder resend");
                            }
                            ev.emit(BaileysEvent::MessagesUpsert(MessagesUpsert { messages: vec![final_msg], r#type: MessageUpsertType::Notify, request_id: response.stanza_id().map(|s| s.as_str().to_string()) }));
                            Ok(())
                        };
                        if let Err(err) = run() {
                            if let Some(l) = logger {
                                l.warn(&format!("failed to decode placeholder resend response: {err}"));
                            }
                        }
                    }
                }
            }
            Some(ProtocolType::MESSAGE_EDIT) => {
                let mut update = WebMessageInfo::new();
                let mut inner = FutureProofMessage::new();
                if let Some(m) = protocol_msg.edited_message() {
                    inner.set_message(m.clone());
                }
                update.message_mut().set_edited_message(inner);
                match protocol_msg.timestamp_ms() {
                    Some(ms) => update.set_message_timestamp(ms.div_euclid(1000) as u64),
                    None => {
                        if let Some(t) = message.message_timestamp() {
                            update.set_message_timestamp(t);
                        }
                    }
                }
                // flip the sender / fromMe properties because they're in the perspective of the sender
                ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key: key_with_id(message, protocol_msg.key().and_then(|k| k.id())), update }]));
            }
            Some(ProtocolType::GROUP_MEMBER_LABEL_CHANGE) => {
                if let Some(label) = protocol_msg.member_label().and_then(|l| l.label()).filter(|l| !l.is_empty()) {
                    ev.emit(BaileysEvent::GroupMemberTagUpdate(GroupMemberTagUpdate {
                        group_id: chat.id().map_or("", |s| s.as_str()).to_string(),
                        label: label.as_str().to_string(),
                        participant: message_key.participant().map_or("", |s| s.as_str()).to_string(),
                        participant_alt: message_key.participant_alt().map(|s| s.as_str().to_string()),
                        message_timestamp: message.message_timestamp(),
                    }));
                }
            }
            Some(ProtocolType::LID_MIGRATION_MAPPING_SYNC) => {
                let encoded = protocol_msg.lid_migration_mapping_sync_message().and_then(|m| m.encoded_mapping_payload()).ok_or_else(|| not_read("length"))?;
                let payload = LIDMigrationMappingSyncPayload::decode(encoded)?;
                if let Some(l) = logger {
                    l.debug("got lid mappings and chat db migration timestamp");
                }
                let mut pairs = Vec::with_capacity(payload.pn_to_lid_mappings().len());
                for m in payload.pn_to_lid_mappings() {
                    let lid = m.latest_lid().or(m.assigned_lid()).unwrap_or(0);
                    pairs.push(LidMapping { lid: format!("{lid}@lid"), pn: format!("{}@s.whatsapp.net", m.pn().unwrap_or(0)) });
                }
                signal_repository.lid_mapping().store_lid_pn_mappings(&pairs)?;
                for LidMapping { pn, lid } in &pairs {
                    signal_repository.migrate_session(pn, lid)?;
                }
            }
            _ => {}
        }
    } else if let Some(reaction_message) = content.and_then(|c| c.reaction_message()) {
        let mut reaction = Reaction::new();
        reaction.set_key(message_key.clone());
        if let Some(v) = reaction_message.text() {
            reaction.set_text(v.clone());
        }
        if let Some(v) = reaction_message.grouping_key() {
            reaction.set_grouping_key(v.clone());
        }
        if let Some(v) = reaction_message.sender_timestamp_ms() {
            reaction.set_sender_timestamp_ms(v);
        }
        ev.emit(BaileysEvent::MessagesReaction(vec![MessageReaction { reaction, key: reaction_message.key().cloned().unwrap_or_default() }]));
    } else if let Some(enc_event_response) = content.and_then(|c| c.enc_event_response_message()) {
        let creation_msg_key = enc_event_response.event_creation_message_key().ok_or_else(|| not_read("participant"))?;
        // we need to fetch the event creation message to get the event enc key
        match get_message(creation_msg_key) {
            None => {
                if let Some(l) = logger {
                    l.warn("event creation message not found, cannot decrypt response");
                }
            }
            Some(event_msg) => {
                let run = || -> Result<()> {
                    let me_id_normalised = jid_normalized_user(me_id);
                    // all jids need to be PN
                    let event_creator_key = creation_msg_key.participant().filter(|p| !p.is_empty()).or(creation_msg_key.remote_jid()).map_or("", |s| s.as_str());
                    let event_creator_pn = if is_lid_user(event_creator_key) { signal_repository.lid_mapping().get_pn_for_lid(event_creator_key)? } else { Some(event_creator_key.to_string()) };
                    let mut creator_key = WAMessageKey::new();
                    creator_key.set_remote_jid(jid_normalized_user(event_creator_pn.as_deref().unwrap_or("")));
                    creator_key.set_from_me(event_creator_pn.as_deref() == Some(me_id_normalised.as_str()));
                    let event_creator_jid = get_key_author(Some(&creator_key), &me_id_normalised).to_string();
                    let responder_jid = get_key_author(Some(message_key), &me_id_normalised).to_string();
                    let Some(event_enc_key) = event_msg.message_context_info().and_then(|c| c.message_secret()) else {
                        if let Some(l) = logger {
                            l.warn("event response: missing messageSecret for decryption");
                        }
                        return Ok(());
                    };
                    let response_msg = decrypt_event_response(
                        enc_event_response.enc_payload().map(|b| &b[..]),
                        enc_event_response.enc_iv().map(|b| &b[..]),
                        &EventContext { event_enc_key, event_creator_jid: &event_creator_jid, event_msg_id: creation_msg_key.id().map_or("", |s| s.as_str()), responder_jid: &responder_jid },
                    )?;
                    // upstream writes `senderTimestampMs` and `response` on this object. The proto fields hold the same values here.
                    let mut event_response = EventResponse::new();
                    event_response.set_event_response_message_key(message_key.clone());
                    if let Some(t) = response_msg.timestamp_ms() {
                        event_response.set_timestamp_ms(t);
                    }
                    event_response.set_event_response_message(response_msg);
                    let mut update = WebMessageInfo::new();
                    update.set_event_responses(vec![event_response]);
                    ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key: creation_msg_key.clone(), update }]));
                    Ok(())
                };
                if let Err(err) = run() {
                    if let Some(l) = logger {
                        l.warn(&format!("failed to decrypt event response: {err}"));
                    }
                }
            }
        }
    } else if let Some(stub) = message.message_stub_type().filter(|t| t.0 != 0) {
        let jid = message_key.remote_jid().map_or("", |s| s.as_str());
        let params = message.message_stub_parameters();
        let first = params.first().map(|s| s.as_str());
        let emit_participants_update = |participants: Vec<GroupParticipant>, action: ParticipantAction| {
            ev.emit(BaileysEvent::GroupParticipantsUpdate(GroupParticipantsUpdate {
                id: jid.to_string(),
                author: message_key.participant().map_or("", |s| s.as_str()).to_string(),
                author_pn: message_key.participant_alt().map(|s| s.as_str().to_string()),
                author_username: message_key.participant_username().map(|s| s.as_str().to_string()),
                participants,
                action,
            }));
        };
        let emit_group_update = |mut update: GroupMetadataUpdate| {
            update.id = Some(jid.to_string());
            update.author = message_key.participant().map(|s| s.as_str().to_string());
            update.author_pn = message_key.participant_alt().map(|s| s.as_str().to_string());
            update.author_username = message_key.participant_username().map(|s| s.as_str().to_string());
            ev.emit(BaileysEvent::GroupsUpdate(vec![update]));
        };
        let includes_me = |participants: &[GroupParticipant]| participants.iter().any(|p| are_jids_same_user(Some(me_id), p.phone_number.as_deref())); // ADD SUPPORT FOR LID
        match stub {
            Stub::GROUP_PARTICIPANT_CHANGE_NUMBER => emit_participants_update(parse_participants(message)?, ParticipantAction::Modify),
            Stub::GROUP_PARTICIPANT_LEAVE | Stub::GROUP_PARTICIPANT_REMOVE => {
                let participants = parse_participants(message)?;
                let me = includes_me(&participants);
                emit_participants_update(participants, ParticipantAction::Remove);
                // mark the chat read only if you left the group
                if me {
                    chat.set_read_only(true);
                }
            }
            Stub::GROUP_PARTICIPANT_ADD | Stub::GROUP_PARTICIPANT_INVITE | Stub::GROUP_PARTICIPANT_ADD_REQUEST_JOIN => {
                let participants = parse_participants(message)?;
                if includes_me(&participants) {
                    chat.set_read_only(false);
                }
                emit_participants_update(participants, ParticipantAction::Add);
            }
            Stub::GROUP_PARTICIPANT_DEMOTE => emit_participants_update(parse_participants(message)?, ParticipantAction::Demote),
            Stub::GROUP_PARTICIPANT_PROMOTE => emit_participants_update(parse_participants(message)?, ParticipantAction::Promote),
            Stub::GROUP_CHANGE_ANNOUNCE => emit_group_update(GroupMetadataUpdate { announce: Some(first == Some("true") || first == Some("on")), ..GroupMetadataUpdate::default() }),
            Stub::GROUP_CHANGE_RESTRICT => emit_group_update(GroupMetadataUpdate { restrict: Some(first == Some("true") || first == Some("on")), ..GroupMetadataUpdate::default() }),
            Stub::GROUP_CHANGE_SUBJECT => {
                match first {
                    Some(name) => chat.set_name(name),
                    None => has_empty_key = true,
                }
                emit_group_update(GroupMetadataUpdate { subject: first.map(str::to_string), ..GroupMetadataUpdate::default() });
            }
            Stub::GROUP_CHANGE_DESCRIPTION => {
                match first {
                    Some(description) => chat.set_description(description),
                    None => has_empty_key = true,
                }
                emit_group_update(GroupMetadataUpdate { desc: first.map(str::to_string), ..GroupMetadataUpdate::default() });
            }
            Stub::GROUP_CHANGE_INVITE_LINK => emit_group_update(GroupMetadataUpdate { invite_code: first.map(str::to_string), ..GroupMetadataUpdate::default() }),
            Stub::GROUP_MEMBER_ADD_MODE => emit_group_update(GroupMetadataUpdate { member_add_mode: Some(first == Some("all_member_add")), ..GroupMetadataUpdate::default() }),
            Stub::GROUP_MEMBERSHIP_JOIN_APPROVAL_MODE => emit_group_update(GroupMetadataUpdate { join_approval_mode: Some(first == Some("on")), ..GroupMetadataUpdate::default() }),
            Stub::GROUP_MEMBERSHIP_JOIN_APPROVAL_REQUEST_NON_ADMIN_ADD => {
                // TODO: Add other events
                let parsed = Json::parse(first.ok_or_else(|| Boom::new("\"undefined\" is not valid JSON"))?)?;
                let field = |k: &str| parsed.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let action = match params.get(1).map(|s| s.as_str()) {
                    Some("created") => Some(RequestJoinAction::Created),
                    Some("revoked") => Some(RequestJoinAction::Revoked),
                    Some("rejected") => Some(RequestJoinAction::Rejected),
                    _ => None,
                };
                // the type of `action` has only these values, so another value has no event
                if let Some(action) = action {
                    ev.emit(BaileysEvent::GroupJoinRequest(GroupJoinRequest {
                        id: jid.to_string(),
                        author: message_key.participant().map_or("", |s| s.as_str()).to_string(),
                        author_pn: message_key.participant_alt().map(|s| s.as_str().to_string()),
                        author_username: message_key.participant_username().map(|s| s.as_str().to_string()),
                        participant: field("lid"),
                        participant_pn: Some(field("pn")).filter(|p| !p.is_empty()),
                        action,
                        method: params.get(2).and_then(|s| RequestJoinMethod::parse(s)),
                    }));
                } else if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Warn)) {
                    l.warn("group join request with an unknown action");
                }
            }
            _ => {}
        }
    }
    if chat.set_field_names().count() > 1 || has_empty_key {
        ev.emit(BaileysEvent::ChatsUpdate(vec![ChatUpdate::new(chat)]));
    }
    Ok(())
}
