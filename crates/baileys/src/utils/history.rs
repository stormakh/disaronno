//! Same behavior as Utils/history.ts.
use crate::auth::LidMapping;
use crate::defaults::MediaType;
use crate::error::{Boom, Result};
use crate::types::{Chat, Contact, DownloadableMessage, RequestInit, WAMessage, WAMessageContent, WAMessageStubType};
use crate::utils::generics::to_number;
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::messages::normalize_message_content;
use crate::utils::messages_media::{MediaDownloadOptions, download_content_from_message, stream_reader};
use crate::wabinary::{is_hosted_lid_user, is_hosted_pn_user, is_lid_user, is_pn_user};
use std::io::Read;
use waproto::history_sync::HistorySyncType;
use waproto::message::HistorySyncNotification;
use waproto::pb::{PbMessage, Str};
use waproto::{HistorySync, HistorySyncMsg, PastParticipants};

fn extract_pn_from_messages(messages: &[HistorySyncMsg]) -> Option<String> {
    for item in messages {
        let Some(message) = item.message() else { continue };
        // Only extract from outgoing messages (fromMe: true) in 1:1 chats
        // because userReceipt.userJid is the recipient's JID
        if message.key().and_then(|k| k.from_me()) != Some(true) {
            continue;
        }
        let Some(user_jid) = message.user_receipt().first().and_then(|r| r.user_jid()) else { continue };
        if is_pn_user(user_jid) || is_hosted_pn_user(user_jid) {
            return Some(user_jid.as_str().to_string());
        }
    }
    None
}
fn inflate(reader: impl Read) -> Result<HistorySync> {
    let mut buffer = Vec::new();
    flate2::read::ZlibDecoder::new(reader).read_to_end(&mut buffer).map_err(|e| Boom::new(e.to_string()))?;
    Ok(HistorySync::decode(&buffer)?)
}
pub fn download_history(msg: &HistorySyncNotification, options: &RequestInit) -> Result<HistorySync> {
    let download = DownloadableMessage { media_key: msg.media_key().cloned(), direct_path: msg.direct_path().map(|s| s.as_str().to_string()), url: None };
    let opts = MediaDownloadOptions { options: Some(options.clone()), ..MediaDownloadOptions::default() };
    let stream = download_content_from_message(&download, MediaType::MdMsgHist, &opts)?;
    // Inflate the decrypted stream directly
    // This avoids allocating an intermediate buffer for the compressed data
    inflate(stream_reader(&stream))
}
/// What `processHistoryMessage` returns. `past_participants` is `None` when the payload does not have it.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ProcessedHistory {
    pub chats: Vec<Chat>,
    pub contacts: Vec<Contact>,
    pub messages: Vec<WAMessage>,
    pub lid_pn_mappings: Vec<LidMapping>,
    pub past_participants: Option<Vec<PastParticipants>>,
    pub sync_type: Option<HistorySyncType>,
    pub progress: Option<u32>,
}
fn truthy(s: Option<&Str>) -> Option<&str> {
    s.map(|v| v.as_str()).filter(|v| !v.is_empty())
}
pub fn process_history_message(mut item: HistorySync, logger: Option<&dyn Logger>) -> Result<ProcessedHistory> {
    let mut messages: Vec<WAMessage> = Vec::new();
    let mut contacts: Vec<Contact> = Vec::new();
    let mut chats: Vec<Chat> = Vec::new();
    let mut lid_pn_mappings: Vec<LidMapping> = Vec::new();
    if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Trace)) {
        l.trace(&format!("processing history of type {}", item.sync_type().map_or_else(|| "undefined".to_string(), |t| t.0.to_string())));
    }
    // Extract LID-PN mappings for all sync types
    for m in item.phone_number_to_lid_mappings() {
        if let (Some(lid), Some(pn)) = (truthy(m.lid_jid()), truthy(m.pn_jid())) {
            lid_pn_mappings.push(LidMapping { lid: lid.to_string(), pn: pn.to_string() });
        }
    }
    let sync_type = item.sync_type();
    match sync_type {
        Some(HistorySyncType::INITIAL_BOOTSTRAP | HistorySyncType::RECENT | HistorySyncType::FULL | HistorySyncType::ON_DEMAND) => {
            let conversations = std::mem::take(item.conversations_mut());
            chats.reserve(conversations.len());
            for mut chat in conversations {
                let chat_id = chat.id().map_or("", |s| s.as_str()).to_string();
                let display = truthy(chat.display_name()).or(truthy(chat.name())).or(truthy(chat.username()));
                contacts.push(Contact {
                    id: chat_id.clone(),
                    name: display.map(str::to_string),
                    username: truthy(chat.username()).map(str::to_string),
                    lid: truthy(chat.lid_jid()).or(truthy(chat.account_lid())).map(str::to_string),
                    phone_number: truthy(chat.pn_jid()).map(str::to_string),
                    ..Contact::default()
                });
                let is_lid = is_lid_user(&chat_id) || is_hosted_lid_user(&chat_id);
                let is_pn = is_pn_user(&chat_id) || is_hosted_pn_user(&chat_id);
                let pn_jid = truthy(chat.pn_jid());
                if is_lid && pn_jid.is_some() {
                    lid_pn_mappings.push(LidMapping { lid: chat_id.clone(), pn: pn_jid.unwrap_or("").to_string() });
                } else if is_pn && truthy(chat.lid_jid()).is_some() {
                    lid_pn_mappings.push(LidMapping { lid: truthy(chat.lid_jid()).unwrap_or("").to_string(), pn: chat_id.clone() });
                } else if is_lid && pn_jid.is_none() {
                    // Fallback: extract PN from userReceipt in messages when pnJid is missing
                    if let Some(pn) = extract_pn_from_messages(chat.messages()) {
                        lid_pn_mappings.push(LidMapping { lid: chat_id.clone(), pn });
                    }
                }
                let msgs = std::mem::take(chat.messages_mut());
                chat.clear_messages();
                let mut has_recv_timestamp = chat.last_message_recv_timestamp().is_some_and(|t| t != 0);
                messages.reserve(msgs.len());
                let mut kept_first = false;
                for mut hist in msgs {
                    if hist.message().is_none() {
                        return Err(Boom::new("Cannot read properties of undefined (reading 'key')"));
                    }
                    let message = std::mem::take(hist.message_mut());
                    if !kept_first {
                        // keep only the most recent message in the chat array
                        kept_first = true;
                        chat.set_messages(vec![HistorySyncMsg::new().with_message(message.clone())]);
                    }
                    if !has_recv_timestamp && message.key().and_then(|k| k.from_me()) != Some(true) {
                        let ts = to_number(message.message_timestamp());
                        if ts != 0.0 {
                            chat.set_last_message_recv_timestamp(ts as u64);
                            has_recv_timestamp = true;
                        }
                    }
                    let is_biz = matches!(message.message_stub_type(), Some(WAMessageStubType::BIZ_PRIVACY_MODE_TO_BSP | WAMessageStubType::BIZ_PRIVACY_MODE_TO_FB));
                    if is_biz {
                        if let Some(name) = truthy(message.message_stub_parameters().first()) {
                            let key = message.key();
                            let id = key.and_then(|k| truthy(k.participant())).or_else(|| key.and_then(|k| k.remote_jid()).map(|s| s.as_str())).unwrap_or("");
                            contacts.push(Contact { id: id.to_string(), verified_name: Some(name.to_string()), ..Contact::default() });
                        }
                    }
                    messages.push(message);
                }
                chats.push(chat);
            }
        }
        Some(HistorySyncType::PUSH_NAME) => {
            for c in item.pushnames() {
                contacts.push(Contact { id: c.id().map_or("", |s| s.as_str()).to_string(), notify: c.pushname().map(|s| s.as_str().to_string()), ..Contact::default() });
            }
        }
        _ => {}
    }
    let past_participants = if item.set_field_names().any(|n| n == "pastParticipants") { Some(std::mem::take(item.past_participants_mut())) } else { None };
    Ok(ProcessedHistory { chats, contacts, messages, lid_pn_mappings, past_participants, sync_type, progress: item.progress() })
}
pub fn download_and_process_history_sync_notification(msg: &HistorySyncNotification, options: &RequestInit, logger: Option<&dyn Logger>) -> Result<ProcessedHistory> {
    let history_msg = match msg.initial_hist_bootstrap_inline_payload() {
        Some(p) => inflate(&p[..])?,
        None => download_history(msg, options)?,
    };
    process_history_message(history_msg, logger)
}
pub fn get_history_msg(message: &WAMessageContent) -> Option<&HistorySyncNotification> {
    normalize_message_content(Some(message))?.protocol_message()?.history_sync_notification()
}
