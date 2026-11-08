//! Same behavior as Utils/decode-wa-message.ts.
use crate::error::{Boom, Result};
use crate::signal::repository::SignalRepository;
use crate::types::{WAMessage, WAMessageContent, WAMessageKey};
use crate::utils::generics::unpad_random_max16;
use crate::utils::logger::Logger;
use crate::utils::tc_token_utils::js_to_number;
use crate::wabinary::{BinaryNode, Content, are_jids_same_user, is_hosted_lid_user, is_hosted_pn_user, is_jid_broadcast, is_jid_group, is_jid_meta_ai, is_jid_newsletter, is_lid_user, is_pn_user};
use waproto::pb::{Json, PbMessage, Str};
use waproto::web_message_info::{Status, StubType};
use waproto::{VerifiedNameCertificate, verified_name_certificate};

pub fn get_decryption_jid(sender: &str, repository: &dyn SignalRepository) -> Result<String> {
    if is_lid_user(sender) || is_hosted_lid_user(sender) {
        return Ok(sender.to_string());
    }
    let mapped = repository.lid_mapping().get_lid_for_pn(sender)?;
    Ok(mapped.filter(|m| !m.is_empty()).unwrap_or_else(|| sender.to_string()))
}
fn store_mapping_from_envelope(stanza: &BinaryNode, sender: &str, repository: &dyn SignalRepository, decryption_jid: &str, logger: &dyn Logger) {
    // TODO: Handle hosted IDs
    let ctx = extract_addressing_context(stanza);
    let Some(sender_alt) = ctx.sender_alt.filter(|a| is_lid_user(a) && is_pn_user(sender) && decryption_jid == sender) else {
        return;
    };
    let run = || -> Result<()> {
        repository.lid_mapping().store_lid_pn_mappings(&[crate::auth::LidMapping { lid: sender_alt.to_string(), pn: sender.to_string() }])?;
        repository.migrate_session(sender, sender_alt)?;
        Ok(())
    };
    match run() {
        Ok(()) => logger.debug("Stored LID mapping from envelope"),
        Err(e) => logger.warn(&format!("Failed to store LID mapping: {e}")),
    }
}
pub const NO_MESSAGE_FOUND_ERROR_TEXT: &str = "Message absent from node";
pub const MISSING_KEYS_ERROR_TEXT: &str = "Key used already or never filled";
pub const ACCOUNT_RESTRICTED_TEXT: &str = "Your account has been restricted";
/// Retry configuration for failed decryption
pub mod decryption_retry_config {
    pub const MAX_RETRIES: u32 = 3;
    pub const BASE_DELAY_MS: u64 = 100;
    pub const SESSION_RECORD_ERRORS: [&str; 2] = ["No session record", "SessionError: No session record"];
}
/// NACK reason codes we send to the server (client to server)
pub mod nack_reasons {
    pub const SENDER_REACHOUT_TIMELOCKED: u32 = 463;
    pub const PARSING_ERROR: u32 = 487;
    pub const UNRECOGNIZED_STANZA: u32 = 488;
    pub const UNRECOGNIZED_STANZA_CLASS: u32 = 489;
    pub const UNRECOGNIZED_STANZA_TYPE: u32 = 490;
    pub const INVALID_PROTOBUF: u32 = 491;
    pub const INVALID_HOSTED_COMPANION_STANZA: u32 = 493;
    pub const MISSING_MESSAGE_SECRET: u32 = 495;
    pub const SIGNAL_ERROR_OLD_COUNTER: u32 = 496;
    pub const MESSAGE_DELETED_ON_PEER: u32 = 499;
    pub const UNHANDLED_ERROR: u32 = 500;
    pub const UNSUPPORTED_ADMIN_REVOKE: u32 = 550;
    pub const UNSUPPORTED_LID_GROUP: u32 = 551;
    pub const DB_OPERATION_FAILED: u32 = 552;
}
/// Server-side error codes returned in ack stanzas (server to client) that we
/// currently have dedicated handlers for. Extend as more handlers are added.
/// Distinct from the client-side NackReason enum (WAWebCreateNackFromStanza).
pub mod server_error_codes {
    /// 1:1 message missing privacy token (tctoken). Usually means the account is
    /// restricted: WhatsApp blocks starting new chats but preserves existing ones,
    /// since established chats already carry a tctoken.
    pub const MESSAGE_ACCOUNT_RESTRICTION: &str = "463";
    /// Stanza validation failure (SMAX_INVALID) -- likely stale device session
    pub const SMAX_INVALID: &str = "479";
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressingContext<'a> {
    pub addressing_mode: &'a str,
    pub sender_alt: Option<&'a str>,
    pub recipient_alt: Option<&'a str>,
}
/// `a || b || c` over attributes.
fn first_attr<'a>(stanza: &'a BinaryNode, names: &[&str]) -> Option<&'a str> {
    for n in names {
        if let Some(v) = stanza.attr(n).filter(|v| !v.is_empty()) {
            return Some(v);
        }
    }
    None
}
pub fn extract_addressing_context(stanza: &BinaryNode) -> AddressingContext<'_> {
    let sender = first_attr(stanza, &["participant", "from"]);
    let addressing_mode = match stanza.attr("addressing_mode").filter(|v| !v.is_empty()) {
        Some(v) => v,
        None if sender.is_some_and(|s| s.ends_with("lid")) => "lid",
        None => "pn",
    };
    let (sender_alt, recipient_alt) = if addressing_mode == "lid" {
        // Message is LID-addressed: sender is LID, extract corresponding PN
        // without device data
        (first_attr(stanza, &["participant_pn", "sender_pn", "peer_recipient_pn"]), stanza.attr("recipient_pn"))
    } else {
        // Message is PN-addressed: sender is PN, extract corresponding LID
        // without device data
        (first_attr(stanza, &["participant_lid", "sender_lid", "peer_recipient_lid"]), stanza.attr("recipient_lid"))
    };
    AddressingContext { addressing_mode, sender_alt, recipient_alt }
}
fn stanza_error(message: &str, stanza: &BinaryNode) -> Boom {
    let attrs = stanza.attrs.iter().map(|(k, v)| (k.to_string(), Json::Str(v.to_string()))).collect();
    Boom::with_data(message, Json::Obj(vec![("tag".to_string(), Json::Str(stanza.tag.to_string())), ("attrs".to_string(), Json::Obj(attrs))]))
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DecodedMessageNode {
    pub full_message: WAMessage,
    pub author: String,
    pub sender: String,
}
/// Decode the received node as a message.
/// this will only parse the message, not decrypt it
pub fn decode_message_node(stanza: &BinaryNode, me_id: &str, me_lid: &str) -> Result<DecodedMessageNode> {
    let mut from_me = false;
    let Some(msg_id) = stanza.attr("id").filter(|v| !v.is_empty()) else {
        return Err(stanza_error("Invalid message stanza: missing id attribute", stanza));
    };
    let Some(from) = stanza.attr("from").filter(|v| !v.is_empty()) else {
        return Err(stanza_error("Invalid message stanza: missing from attribute", stanza));
    };
    let participant = stanza.attr("participant");
    let truthy_participant = participant.filter(|v| !v.is_empty());
    let recipient = stanza.attr("recipient").filter(|v| !v.is_empty());
    let ctx = extract_addressing_context(stanza);
    let is_me = |jid: &str| are_jids_same_user(Some(jid), Some(me_id));
    let is_me_lid = |jid: &str| are_jids_same_user(Some(jid), Some(me_lid));
    let msg_type_is_chat;
    let msg_type_is_newsletter;
    let chat_id;
    let author;
    if is_pn_user(from) || is_lid_user(from) || is_hosted_lid_user(from) || is_hosted_pn_user(from) {
        if let Some(r) = recipient.filter(|r| !is_jid_meta_ai(r)) {
            if !is_me(from) && !is_me_lid(from) {
                return Err(stanza_error("receipient present, but msg not from me", stanza));
            }
            from_me = true;
            chat_id = r;
        } else {
            // Peer-routed self stanzas (history sync, app-state sync, etc.) arrive
            // with `from` set to our own device but no `recipient` attribute --
            // still mark as fromMe so self-only protocolMessage handlers run.
            if is_me(from) || is_me_lid(from) {
                from_me = true;
            }
            chat_id = from;
        }
        msg_type_is_chat = true;
        msg_type_is_newsletter = false;
        author = from;
    } else if is_jid_group(from) {
        let Some(p) = truthy_participant else {
            return Err(Boom::new("No participant in group message"));
        };
        if is_me(p) || is_me_lid(p) {
            from_me = true;
        }
        msg_type_is_chat = false;
        msg_type_is_newsletter = false;
        author = p;
        chat_id = from;
    } else if is_jid_broadcast(from) {
        let Some(p) = truthy_participant else {
            return Err(Boom::new("No participant in group message"));
        };
        from_me = is_me(p);
        msg_type_is_chat = false;
        msg_type_is_newsletter = false;
        chat_id = from;
        author = p;
    } else if is_jid_newsletter(from) {
        msg_type_is_chat = false;
        msg_type_is_newsletter = true;
        chat_id = from;
        author = from;
        if is_me(from) || is_me_lid(from) {
            from_me = true;
        }
    } else {
        return Err(stanza_error("Unknown message type", stanza));
    }
    let group_chat = is_jid_group(chat_id);
    let mut key = WAMessageKey::new();
    key.set_remote_jid(chat_id);
    if !group_chat {
        if let Some(v) = ctx.sender_alt {
            key.set_remote_jid_alt(v);
        }
        if let Some(v) = first_attr(stanza, &["peer_recipient_username", "recipient_username"]) {
            key.set_remote_jid_username(v);
        }
    }
    key.set_from_me(from_me);
    key.set_id(msg_id);
    if let Some(p) = participant {
        key.set_participant(p);
    }
    if group_chat {
        if let Some(v) = ctx.sender_alt {
            key.set_participant_alt(v);
        }
    }
    if truthy_participant.is_some() {
        if let Some(v) = stanza.attr("participant_username") {
            key.set_participant_username(v);
        }
    }
    key.set_addressing_mode(ctx.addressing_mode);
    if msg_type_is_newsletter {
        if let Some(v) = stanza.attr("server_id").filter(|v| !v.is_empty()) {
            key.set_server_id(v);
        }
    }
    let mut full_message = WAMessage::new();
    full_message.set_key(key);
    if let Some(v) = stanza.attr("category") {
        full_message.set_category(v);
    }
    let t = js_to_number(stanza.attr("t").unwrap_or("x"));
    if t.is_finite() {
        full_message.set_message_timestamp(t as u64);
    }
    if let Some(v) = stanza.attr("notify") {
        full_message.set_push_name(v);
    }
    full_message.set_broadcast(is_jid_broadcast(from));
    if from_me {
        full_message.set_status(Status::SERVER_ACK);
    }
    Ok(DecodedMessageNode { full_message, author: author.to_string(), sender: if msg_type_is_chat { author.to_string() } else { chat_id.to_string() } })
}
/// `decryptMessageNode`. The `decrypt` closure of upstream is the `decrypt` method here.
pub struct DecryptedMessageNode<'a> {
    pub full_message: WAMessage,
    pub category: Option<&'a str>,
    pub author: String,
    sender: String,
    stanza: &'a BinaryNode,
    repository: &'a dyn SignalRepository,
    logger: &'a dyn Logger,
}
pub fn decrypt_message_node<'a>(stanza: &'a BinaryNode, me_id: &str, me_lid: &str, repository: &'a dyn SignalRepository, logger: &'a dyn Logger) -> Result<DecryptedMessageNode<'a>> {
    let DecodedMessageNode { full_message, author, sender } = decode_message_node(stanza, me_id, me_lid)?;
    Ok(DecryptedMessageNode { full_message, category: stanza.attr("category"), author, sender, stanza, repository, logger })
}
impl DecryptedMessageNode<'_> {
    fn decrypt_one(&self, tag: &str, e2e_attr: Option<&str>, content: &[u8], decryption_jid: &str) -> Result<WAMessageContent> {
        let e2e_type = if tag == "plaintext" { Some("plaintext") } else { e2e_attr };
        let decoded = match e2e_type {
            Some("skmsg") => WAMessageContent::decode(unpad_random_max16(&self.repository.decrypt_group_message(&self.sender, &self.author, content)?)?)?,
            Some(t @ ("pkmsg" | "msg")) => WAMessageContent::decode(unpad_random_max16(&self.repository.decrypt_message(decryption_jid, t, content)?)?)?,
            Some("plaintext") => WAMessageContent::decode(content)?,
            other => return Err(Boom::new(format!("Unknown e2e type: {}", other.unwrap_or("undefined")))),
        };
        let msg = match decoded.device_sent_message().and_then(|d| d.message()) {
            Some(inner) => inner.clone(),
            None => decoded,
        };
        if let Some(skdm) = msg.sender_key_distribution_message() {
            let group_id = skdm.group_id().map(|s| s.as_str());
            let data = skdm.axolotl_sender_key_distribution_message().map_or(&[][..], |b| &b[..]);
            if let Err(err) = self.repository.process_sender_key_distribution_message(group_id, data, &self.author) {
                self.logger.error(&format!("failed to process sender key distribution message: {err}"));
            }
        }
        Ok(msg)
    }
    pub fn decrypt(&mut self) -> Result<()> {
        let mut decryptables = 0;
        let stanza = self.stanza;
        if let Some(Content::Nodes(nodes)) = &stanza.content {
            for node in nodes {
                let (tag, attrs_type) = (node.tag.as_str(), node.attr("type"));
                let bytes = match &node.content {
                    Some(Content::Binary(b)) => Some(b),
                    _ => None,
                };
                if let (true, Some(content)) = (tag == "verified_name", bytes) {
                    let cert = VerifiedNameCertificate::decode(content)?;
                    let details = verified_name_certificate::Details::decode(cert.details().map_or(&[][..], |b| &b[..]))?;
                    match details.verified_name() {
                        Some(v) => self.full_message.set_verified_biz_name(v.clone()),
                        None => self.full_message.clear_verified_biz_name(),
                    }
                }
                if tag == "unavailable" && attrs_type == Some("view_once") {
                    self.full_message.key_mut().set_is_view_once(true); // TODO: remove from here and add a STUB TYPE
                }
                if tag == "enc" {
                    if let Some(c) = node.attr("count").filter(|c| !c.is_empty()) {
                        self.full_message.set_retry_count(js_to_number(c) as u32);
                    }
                }
                if tag != "enc" && tag != "plaintext" {
                    continue;
                }
                let Some(content) = bytes else { continue };
                decryptables += 1;
                let decryption_jid = get_decryption_jid(&self.author, self.repository)?;
                if tag != "plaintext" {
                    // TODO: Handle hosted devices
                    store_mapping_from_envelope(stanza, &self.author, self.repository, &decryption_jid, self.logger);
                }
                match self.decrypt_one(tag, attrs_type, content, &decryption_jid) {
                    Ok(msg) => {
                        if self.full_message.message().is_some() {
                            self.full_message.message_mut().assign_from(&msg);
                        } else {
                            self.full_message.set_message(msg);
                        }
                    }
                    Err(err) => {
                        self.logger.error(&format!("failed to decrypt message: {err} (session record error: {})", is_session_record_error(&err)));
                        self.full_message.set_message_stub_type(StubType::CIPHERTEXT);
                        self.full_message.set_message_stub_parameters(vec![Str::from(err.message.as_str())]);
                    }
                }
            }
        }
        // if nothing was found to decrypt
        if decryptables == 0 && self.full_message.key().and_then(|k| k.is_view_once()) != Some(true) {
            self.full_message.set_message_stub_type(StubType::CIPHERTEXT);
            self.full_message.set_message_stub_parameters(vec![Str::from(NO_MESSAGE_FOUND_ERROR_TEXT)]);
        }
        Ok(())
    }
}
/// Utility function to check if an error is related to missing session record
fn is_session_record_error(error: &Boom) -> bool {
    decryption_retry_config::SESSION_RECORD_ERRORS.iter().any(|p| error.message.contains(p))
}
