//! Same behavior as Utils/messages.ts.
use crate::crypto;
use crate::defaults::{CALL_AUDIO_PREFIX, CALL_VIDEO_PREFIX, MediaType, WA_DEFAULT_EPHEMERAL, find_url};
use crate::error::{Boom, Result};
use crate::types::*;
use crate::utils::generics::{generate_message_id_v2, get_key_author, unix_timestamp_seconds};
use crate::utils::logger::Logger;
use crate::utils::messages_media::{
    DecryptedMediaStream, EncryptedStream, EncryptedStreamOptions, MediaDownloadOptions, MediaInput, RawMediaUploadData, ThumbnailMediaType, download_with_info, encrypted_stream, generate_thumbnail, get_audio_duration, get_audio_waveform, get_raw_media_upload_data,
    hkdf_info_key, to_buffer,
};
use crate::utils::reporting_utils::should_include_reporting_token;
use crate::utils::time::now_ms;
use crate::wabinary::{is_jid_group, is_jid_newsletter, is_jid_status_broadcast, jid_normalized_user};
use std::sync::Arc;
use waproto::message::poll_creation_message::Option as PollOption;
use waproto::message::protocol_message::Type as ProtocolType;
use waproto::message::{AudioMessage, DocumentMessage, FutureProofMessage, GroupInviteMessage, ImageMessage, PollCreationMessage, ProductMessage, ProtocolMessage, StickerMessage, VideoMessage};
use waproto::pb::{Json, PbMessage, Str, base64_decode, base64_encode};
use waproto::web_message_info::Status;
use waproto::{ContextInfo, EventResponse, MessageAssociation, MessageContextInfo, PollUpdate, Reaction};

/// The first field name that holds message content. Fields are in field number order.
pub fn get_content_type(content: Option<&WAMessageContent>) -> Option<&'static str> {
    content?.set_field_names().find(|k| (*k == "conversation" || k.contains("Message")) && *k != "senderKeyDistributionMessage")
}
#[derive(Clone, Copy)]
enum FutureProof {
    Ephemeral,
    ViewOnce,
    DocumentWithCaption,
    ViewOnceV2,
    ViewOnceV2Extension,
    Edited,
    AssociatedChild,
    GroupStatus,
    GroupStatusV2,
}
fn future_proof_kind(m: &WAMessageContent) -> Option<FutureProof> {
    if m.ephemeral_message().is_some() {
        Some(FutureProof::Ephemeral)
    } else if m.view_once_message().is_some() {
        Some(FutureProof::ViewOnce)
    } else if m.document_with_caption_message().is_some() {
        Some(FutureProof::DocumentWithCaption)
    } else if m.view_once_message_v2().is_some() {
        Some(FutureProof::ViewOnceV2)
    } else if m.view_once_message_v2_extension().is_some() {
        Some(FutureProof::ViewOnceV2Extension)
    } else if m.edited_message().is_some() {
        Some(FutureProof::Edited)
    } else if m.associated_child_message().is_some() {
        Some(FutureProof::AssociatedChild)
    } else if m.group_status_message().is_some() {
        Some(FutureProof::GroupStatus)
    } else if m.group_status_message_v2().is_some() {
        Some(FutureProof::GroupStatusV2)
    } else {
        None
    }
}
/// Removes the wrapper messages, such as ephemeral and view once.
pub fn normalize_message_content(content: Option<&WAMessageContent>) -> Option<&WAMessageContent> {
    let mut content = content?;
    // set max iterations to prevent an infinite loop
    for _ in 0..5 {
        let inner = content
            .ephemeral_message()
            .or_else(|| content.view_once_message())
            .or_else(|| content.document_with_caption_message())
            .or_else(|| content.view_once_message_v2())
            .or_else(|| content.view_once_message_v2_extension())
            .or_else(|| content.edited_message())
            .or_else(|| content.associated_child_message())
            .or_else(|| content.group_status_message())
            .or_else(|| content.group_status_message_v2());
        let Some(inner) = inner else { break };
        match inner.message() {
            Some(m) => content = m,
            // `content = inner.message` is undefined: the loop then finds no wrapper and returns it
            None => return None,
        }
    }
    Some(content)
}
fn future_proof_mut(m: &mut WAMessageContent, kind: FutureProof) -> &mut FutureProofMessage {
    match kind {
        FutureProof::Ephemeral => m.ephemeral_message_mut(),
        FutureProof::ViewOnce => m.view_once_message_mut(),
        FutureProof::DocumentWithCaption => m.document_with_caption_message_mut(),
        FutureProof::ViewOnceV2 => m.view_once_message_v2_mut(),
        FutureProof::ViewOnceV2Extension => m.view_once_message_v2_extension_mut(),
        FutureProof::Edited => m.edited_message_mut(),
        FutureProof::AssociatedChild => m.associated_child_message_mut(),
        FutureProof::GroupStatus => m.group_status_message_mut(),
        FutureProof::GroupStatusV2 => m.group_status_message_v2_mut(),
    }
}
fn normalize_mut_at(content: &mut WAMessageContent, depth: u32) -> Option<&mut WAMessageContent> {
    if depth == 5 {
        return Some(content);
    }
    let Some(kind) = future_proof_kind(content) else { return Some(content) };
    let inner = future_proof_mut(content, kind);
    if inner.message().is_none() {
        return None;
    }
    normalize_mut_at(inner.message_mut(), depth + 1)
}
/// `normalize_message_content` for code that changes the inner message.
pub fn normalize_message_content_mut(content: &mut WAMessageContent) -> Option<&mut WAMessageContent> {
    normalize_mut_at(content, 0)
}
/// `msg.user_receipt_mut()` is the usual argument.
pub fn update_message_with_receipt(user_receipt: &mut Vec<MessageUserReceipt>, receipt: MessageUserReceipt) {
    match user_receipt.iter_mut().find(|m| m.user_jid() == receipt.user_jid()) {
        Some(recp) => recp.assign_from(&receipt),
        None => user_receipt.push(receipt),
    }
}
/// `msg.reactions_mut()` is the usual argument.
pub fn update_message_with_reaction(reactions: &mut Vec<Reaction>, mut reaction: Reaction) {
    let author_id = get_key_author(reaction.key(), "me").to_string();
    reactions.retain(|r| get_key_author(r.key(), "me") != author_id);
    if reaction.text().is_none_or(|t| t.is_empty()) {
        reaction.set_text("");
    }
    reactions.push(reaction);
}
/// `msg.poll_updates_mut()` is the usual argument.
pub fn update_message_with_poll_update(poll_updates: &mut Vec<PollUpdate>, update: PollUpdate) {
    let author_id = get_key_author(update.poll_update_message_key(), "me").to_string();
    poll_updates.retain(|r| get_key_author(r.poll_update_message_key(), "me") != author_id);
    if update.vote().is_some_and(|v| !v.selected_options().is_empty()) {
        poll_updates.push(update);
    }
}
/// `msg.event_responses_mut()` is the usual argument.
pub fn update_message_with_event_response(event_responses: &mut Vec<EventResponse>, update: EventResponse) {
    let author_id = get_key_author(update.event_response_message_key(), "me").to_string();
    event_responses.retain(|r| get_key_author(r.event_response_message_key(), "me") != author_id);
    event_responses.push(update);
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VoteAggregation {
    pub name: String,
    pub voters: Vec<String>,
}
/// Aggregates all poll updates in a poll. Returns a list of options & their voters.
pub fn get_aggregate_votes_in_poll_message(message: Option<&WAMessageContent>, poll_updates: &[PollUpdate], me_id: Option<&str>) -> Vec<VoteAggregation> {
    let me_id = me_id.unwrap_or("me");
    let creation = message.and_then(|m| m.poll_creation_message().or_else(|| m.poll_creation_message_v2()).or_else(|| m.poll_creation_message_v3()));
    let opts: &[PollOption] = creation.map_or(&[], |p| p.options());
    let mut map: crate::utils::generics::JsMap<VoteAggregation> = crate::utils::generics::JsMap::new();
    for opt in opts {
        let name = opt.option_name().map_or("", |s| s.as_str());
        let hash = String::from_utf8_lossy(&crypto::sha256(name.as_bytes())).into_owned();
        map.insert(hash, VoteAggregation { name: name.to_string(), voters: Vec::new() });
    }
    for update in poll_updates {
        let Some(vote) = update.vote() else { continue };
        for option in vote.selected_options() {
            let hash = String::from_utf8_lossy(option).into_owned();
            if !map.contains_key(&hash) {
                map.insert(hash.clone(), VoteAggregation { name: "Unknown".to_string(), voters: Vec::new() });
            }
            if let Some(data) = map.get_mut(&hash) {
                data.voters.push(get_key_author(update.poll_update_message_key(), me_id).to_string());
            }
        }
    }
    map.into_values()
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ResponseAggregation {
    pub response: String,
    pub responders: Vec<String>,
}
/// Aggregates all event responses in an event message.
/// Upstream reads `update.eventResponse`, which `proto.EventResponse` does not have, so its count of
/// responders stays empty for messages of that type. This port gives the same result.
pub fn get_aggregate_responses_in_event_message(_event_responses: &[EventResponse], _me_id: Option<&str>) -> Vec<ResponseAggregation> {
    ["GOING", "NOT_GOING", "MAYBE"].iter().map(|t| ResponseAggregation { response: t.to_string(), responders: Vec::new() }).collect()
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AggregatedKeys {
    pub jid: String,
    pub participant: Option<String>,
    pub message_ids: Vec<String>,
}
/// Given a list of message keys, aggregates them by chat & sender. Useful for sending read receipts in bulk
pub fn aggregate_message_keys_not_from_me(keys: &[WAMessageKey]) -> Vec<AggregatedKeys> {
    let mut map: crate::utils::generics::JsMap<AggregatedKeys> = crate::utils::generics::JsMap::new();
    for k in keys {
        if k.from_me() == Some(true) {
            continue;
        }
        let jid = k.remote_jid().map_or("", |s| s.as_str());
        let participant = k.participant().map(|s| s.as_str());
        let uq_key = format!("{}:{}", k.remote_jid().map_or("undefined", |s| s.as_str()), participant.unwrap_or(""));
        if !map.contains_key(&uq_key) {
            map.insert(uq_key.clone(), AggregatedKeys { jid: jid.to_string(), participant: participant.map(str::to_string), message_ids: Vec::new() });
        }
        if let Some(e) = map.get_mut(&uq_key) {
            e.message_ids.push(k.id().map_or("", |s| s.as_str()).to_string());
        }
    }
    map.into_values()
}
/// Returns the device predicted by message ID
pub fn get_device(id: &str) -> &'static str {
    // `.` of a JavaScript regex stops at line ends
    let dots = id.chars().take_while(|c| !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')).map(char::len_utf16).sum::<usize>();
    let whole = dots == id.encode_utf16().count();
    if id.starts_with("3A") && whole && dots == 20 {
        "ios"
    } else if id.starts_with("3E") && whole && dots == 22 {
        "web"
    } else if whole && (dots == 21 || dots == 32) {
        "android"
    } else if id.starts_with("3F") || (whole && dots == 18) {
        "desktop"
    } else {
        "unknown"
    }
}
/// Uses a regex to test whether the string contains a URL, and returns the URL if it does.
pub fn extract_url_from_text(text: &str) -> Option<&str> {
    let (from, to) = find_url(text, 0)?;
    text.get(from..to)
}
pub fn generate_link_preview_if_required(text: &str, get_url_info: Option<&GetUrlInfo>, _logger: Option<&dyn Logger>) -> Option<WAUrlInfo> {
    let url = extract_url_from_text(text)?;
    // an error in the callback has no return path here: the callback gives `None`, as the ignored error of upstream does
    (get_url_info?)(url)
}
/// `assertColor` with a string. The number form of upstream returns nothing, and this type has no number form.
fn assert_color(color: &str) -> u32 {
    let mut hex = color.trim().replacen('#', "", 1);
    if hex.encode_utf16().count() <= 6 {
        hex = format!("FF{hex:0>6}");
    }
    // `parseInt` stops at the first bad digit, and the value is stored as `>>> 0`
    let mut v = 0u32;
    for c in hex.chars() {
        let Some(d) = c.to_digit(16) else { break };
        v = v.wrapping_mul(16).wrapping_add(d);
    }
    v
}
/// The fields of `MediaUploadData`, which upstream spreads over the media proto with `fromObject`.
#[derive(Default)]
struct UploadData {
    caption: Option<String>,
    ptt: Option<bool>,
    ptv: Option<bool>,
    seconds: Option<f64>,
    gif_playback: Option<bool>,
    file_name: Option<String>,
    jpeg_thumbnail: Option<String>,
    mimetype: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    waveform: Option<Vec<u8>>,
    background_argb: Option<u32>,
    is_animated: Option<bool>,
    context_info: Option<ContextInfo>,
    view_once: Option<bool>,
}
fn apply_image(m: &mut ImageMessage, d: &UploadData) {
    if let Some(v) = &d.caption {
        m.set_caption(v);
    }
    if let Some(v) = &d.jpeg_thumbnail {
        m.set_jpeg_thumbnail(base64_decode(v));
    }
    if let Some(v) = &d.mimetype {
        m.set_mimetype(v);
    }
    if let Some(v) = d.width {
        m.set_width(v);
    }
    if let Some(v) = d.height {
        m.set_height(v);
    }
    if let Some(v) = &d.context_info {
        m.set_context_info(v.clone());
    }
    if let Some(v) = d.view_once {
        m.set_view_once(v);
    }
}
fn apply_video(m: &mut VideoMessage, d: &UploadData) {
    if let Some(v) = &d.caption {
        m.set_caption(v);
    }
    if let Some(v) = d.gif_playback {
        m.set_gif_playback(v);
    }
    if let Some(v) = &d.jpeg_thumbnail {
        m.set_jpeg_thumbnail(base64_decode(v));
    }
    if let Some(v) = &d.mimetype {
        m.set_mimetype(v);
    }
    if let Some(v) = d.width {
        m.set_width(v);
    }
    if let Some(v) = d.height {
        m.set_height(v);
    }
    if let Some(v) = &d.context_info {
        m.set_context_info(v.clone());
    }
    if let Some(v) = d.view_once {
        m.set_view_once(v);
    }
}
fn apply_audio(m: &mut AudioMessage, d: &UploadData) {
    if let Some(v) = d.ptt {
        m.set_ptt(v);
    }
    if let Some(v) = d.seconds {
        m.set_seconds(v as u32);
    }
    if let Some(v) = &d.mimetype {
        m.set_mimetype(v);
    }
    if let Some(v) = &d.waveform {
        m.set_waveform(v.clone());
    }
    if let Some(v) = d.background_argb {
        m.set_background_argb(v);
    }
    if let Some(v) = d.view_once {
        m.set_view_once(v);
    }
}
fn apply_sticker(m: &mut StickerMessage, d: &UploadData) {
    if let Some(v) = d.is_animated {
        m.set_is_animated(v);
    }
    if let Some(v) = &d.mimetype {
        m.set_mimetype(v);
    }
    if let Some(v) = d.width {
        m.set_width(v);
    }
    if let Some(v) = d.height {
        m.set_height(v);
    }
}
fn apply_document(m: &mut DocumentMessage, d: &UploadData) {
    if let Some(v) = &d.mimetype {
        m.set_mimetype(v);
    }
    if let Some(v) = &d.file_name {
        m.set_file_name(v);
    }
    if let Some(v) = &d.caption {
        m.set_caption(v);
    }
    if let Some(v) = &d.context_info {
        m.set_context_info(v.clone());
    }
}
/// The result of the upload, which goes first in the object that upstream gives to `fromObject`.
struct Uploaded<'a> {
    media_url: &'a str,
    direct_path: &'a str,
    file_sha256: &'a [u8],
    file_length: u64,
    enc: Option<&'a EncryptedStream>,
}
macro_rules! set_uploaded {
    ($m:expr, $u:expr) => {{
        $m.set_url($u.media_url);
        $m.set_direct_path($u.direct_path);
        $m.set_file_sha256($u.file_sha256);
        $m.set_file_length($u.file_length);
        if let Some(e) = $u.enc {
            $m.set_media_key(e.media_key);
            $m.set_file_enc_sha256(e.file_enc_sha256);
            $m.set_media_key_timestamp(unix_timestamp_seconds(None));
        }
    }};
}
fn build_media(kind: MediaKind, u: &Uploaded<'_>, d: &UploadData) -> WAMessageContent {
    let mut obj = WAMessageContent::new();
    match kind {
        MediaKind::Image => {
            let m = obj.image_message_mut();
            set_uploaded!(m, u);
            apply_image(m, d);
        }
        MediaKind::Video => {
            let m = obj.video_message_mut();
            set_uploaded!(m, u);
            apply_video(m, d);
        }
        MediaKind::Audio => {
            let m = obj.audio_message_mut();
            set_uploaded!(m, u);
            apply_audio(m, d);
        }
        MediaKind::Sticker => {
            let m = obj.sticker_message_mut();
            set_uploaded!(m, u);
            apply_sticker(m, d);
        }
        MediaKind::Document => {
            let m = obj.document_message_mut();
            set_uploaded!(m, u);
            apply_document(m, d);
        }
    }
    obj
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum MediaKind {
    Image,
    Video,
    Audio,
    Sticker,
    Document,
}
impl MediaKind {
    fn media_type(self) -> MediaType {
        match self {
            MediaKind::Image => MediaType::Image,
            MediaKind::Video => MediaType::Video,
            MediaKind::Audio => MediaType::Audio,
            MediaKind::Sticker => MediaType::Sticker,
            MediaKind::Document => MediaType::Document,
        }
    }
}
/// MIMETYPE_MAP.
fn default_mimetype(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Image => "image/jpeg",
        MediaKind::Video => "video/mp4",
        MediaKind::Document => "application/pdf",
        MediaKind::Audio => "audio/ogg; codecs=opus",
        MediaKind::Sticker => "image/webp",
    }
}
fn split_media<'a>(message: &'a AnyMediaMessageContent, view_once: Option<bool>) -> (MediaKind, &'a WAMediaUpload, UploadData) {
    let mut d = UploadData { mimetype: message.mimetype.clone(), view_once, ..UploadData::default() };
    match &message.media {
        MediaContent::Image { image, caption, jpeg_thumbnail, context_info, width, height, .. } => {
            d.caption = caption.clone();
            d.jpeg_thumbnail = jpeg_thumbnail.clone();
            d.context_info = context_info.clone();
            d.width = *width;
            d.height = *height;
            (MediaKind::Image, image, d)
        }
        MediaContent::Video { video, caption, gif_playback, jpeg_thumbnail, ptv, context_info, width, height, .. } => {
            d.caption = caption.clone();
            d.gif_playback = *gif_playback;
            d.jpeg_thumbnail = jpeg_thumbnail.clone();
            d.ptv = *ptv;
            d.context_info = context_info.clone();
            d.width = *width;
            d.height = *height;
            (MediaKind::Video, video, d)
        }
        MediaContent::Audio { audio, ptt, seconds } => {
            d.ptt = *ptt;
            d.seconds = seconds.map(f64::from);
            (MediaKind::Audio, audio, d)
        }
        MediaContent::Sticker { sticker, is_animated, width, height } => {
            d.is_animated = *is_animated;
            d.width = *width;
            d.height = *height;
            (MediaKind::Sticker, sticker, d)
        }
        MediaContent::Document { document, mimetype, file_name, caption, context_info } => {
            d.mimetype = Some(message.mimetype.clone().unwrap_or_else(|| mimetype.clone()));
            d.file_name = file_name.clone();
            d.caption = caption.clone();
            d.context_info = context_info.clone();
            (MediaKind::Document, document, d)
        }
    }
}
fn apply_upload_data_to_cached(obj: &mut WAMessageContent, kind: MediaKind, d: &UploadData) -> Result<()> {
    let missing = || Boom::new("Cannot convert undefined or null to object");
    match kind {
        MediaKind::Image => {
            if obj.image_message().is_none() {
                return Err(missing());
            }
            apply_image(obj.image_message_mut(), d);
        }
        MediaKind::Video => {
            if obj.video_message().is_none() {
                return Err(missing());
            }
            apply_video(obj.video_message_mut(), d);
        }
        MediaKind::Audio => {
            if obj.audio_message().is_none() {
                return Err(missing());
            }
            apply_audio(obj.audio_message_mut(), d);
        }
        MediaKind::Sticker => {
            if obj.sticker_message().is_none() {
                return Err(missing());
            }
            apply_sticker(obj.sticker_message_mut(), d);
        }
        MediaKind::Document => {
            if obj.document_message().is_none() {
                return Err(missing());
            }
            apply_document(obj.document_message_mut(), d);
        }
    }
    Ok(())
}
fn move_video_to_ptv(obj: &mut WAMessageContent) {
    if let Some(v) = obj.video_message().cloned() {
        obj.set_ptv_message(v);
        obj.clear_video_message();
    }
}
pub fn prepare_wa_message_media(message: &AnyMediaMessageContent, options: &MessageContentGenerationOptions) -> Result<WAMessageContent> {
    prepare_media(message, None, options)
}
/// `view_once` stands for the `viewOnce` that the spread of upstream carries over to the media proto.
fn prepare_media(message: &AnyMediaMessageContent, view_once: Option<bool>, options: &MessageContentGenerationOptions) -> Result<WAMessageContent> {
    let media_opts = &options.media;
    let logger = media_opts.logger.as_deref();
    let (kind, media, mut upload_data) = split_media(message, view_once);
    let media_type = kind.media_type();
    // check if cacheable + generate cache key
    let cacheable_key = match (media, &media_opts.media_cache) {
        (WAMediaUpload::Url(u), Some(_)) if !u.is_empty() => Some(format!("{}:{u}", media_type.as_str())),
        _ => None,
    };
    if kind == MediaKind::Document && upload_data.file_name.as_deref().is_none_or(str::is_empty) {
        upload_data.file_name = Some("file".to_string());
    }
    if upload_data.mimetype.as_deref().is_none_or(str::is_empty) {
        upload_data.mimetype = Some(default_mimetype(kind).to_string());
    }
    let cache = media_opts.media_cache.as_deref();
    if let (Some(key), Some(cache)) = (&cacheable_key, cache) {
        if let Some(buff) = cache_get::<Vec<u8>>(cache, key) {
            if let Some(l) = logger {
                l.debug("got media cache hit");
            }
            let mut obj = WAMessageContent::decode(&buff)?;
            apply_upload_data_to_cached(&mut obj, kind, &upload_data)?;
            return Ok(obj);
        }
    }
    let upload_type = media_opts.media_type_override.unwrap_or(media_type);
    if options.jid.as_deref().is_some_and(is_jid_newsletter) {
        if let Some(l) = logger {
            l.info("Preparing raw media for newsletter");
        }
        let RawMediaUploadData { file_path, file_sha256, file_length } = get_raw_media_upload_data(media, upload_type, logger)?;
        let upload_opts = MediaUploadOpts { file_enc_sha256_b64: base64_encode(&file_sha256), media_type, timeout_ms: media_opts.media_upload_timeout_ms };
        let result = (media_opts.upload)(&file_path, &upload_opts);
        let removed = std::fs::remove_file(&file_path);
        let MediaUploadResult { media_url, direct_path, .. } = result?;
        removed.map_err(|e| Boom::new(e.to_string()))?;
        let mut obj = build_media(kind, &Uploaded { media_url: &media_url, direct_path: &direct_path, file_sha256: &file_sha256, file_length, enc: None }, &upload_data);
        if upload_data.ptv == Some(true) {
            move_video_to_ptv(&mut obj);
        }
        if obj.sticker_message().is_some() {
            obj.sticker_message_mut().set_sticker_sent_ts(now_ms());
        }
        if let (Some(key), Some(cache)) = (&cacheable_key, cache) {
            if let Some(l) = logger {
                l.debug("set cache");
            }
            cache_set(cache, key, obj.encode());
        }
        return Ok(obj);
    }
    let requires_duration = kind == MediaKind::Audio && upload_data.seconds.is_none();
    let requires_thumbnail = matches!(kind, MediaKind::Image | MediaKind::Video) && upload_data.jpeg_thumbnail.is_none();
    let requires_waveform = kind == MediaKind::Audio && upload_data.ptt == Some(true) && upload_data.waveform.is_none();
    let background = media_opts.background_color.as_deref().filter(|c| !c.is_empty() && kind == MediaKind::Audio && upload_data.ptt == Some(true));
    let requires_original = requires_duration || requires_thumbnail;
    let enc_opts = EncryptedStreamOptions { save_original_file_if_required: requires_original, logger: media_opts.logger.clone(), opts: media_opts.options.clone(), max_content_length: None };
    let enc = encrypted_stream(media, upload_type, &enc_opts)?;
    let upload_opts = MediaUploadOpts { file_enc_sha256_b64: base64_encode(&enc.file_enc_sha256), media_type, timeout_ms: media_opts.media_upload_timeout_ms };
    let uploaded = (media_opts.upload)(&enc.enc_file_path, &upload_opts);
    if uploaded.is_ok() {
        if let Err(error) = compute_extra_info(&enc, kind, &mut upload_data, requires_thumbnail, requires_duration, requires_waveform, background, logger) {
            if let Some(l) = logger {
                l.warn(&format!("failed to obtain extra info: {error}"));
            }
        }
    }
    let removed = std::fs::remove_file(&enc.enc_file_path).and_then(|_| enc.original_file_path.as_ref().map_or(Ok(()), std::fs::remove_file));
    if let Some(l) = logger {
        match removed {
            Ok(()) => l.debug("removed tmp files"),
            Err(_) => l.warn("failed to remove tmp file"),
        }
    }
    let MediaUploadResult { media_url, direct_path, .. } = uploaded?;
    if let Some(l) = logger {
        l.debug("uploaded media");
    }
    let mut obj = build_media(kind, &Uploaded { media_url: &media_url, direct_path: &direct_path, file_sha256: &enc.file_sha256, file_length: enc.file_length, enc: Some(&enc) }, &upload_data);
    if upload_data.ptv == Some(true) {
        move_video_to_ptv(&mut obj);
    }
    if let (Some(key), Some(cache)) = (&cacheable_key, cache) {
        if let Some(l) = logger {
            l.debug("set cache");
        }
        cache_set(cache, key, obj.encode());
    }
    Ok(obj)
}
#[allow(clippy::too_many_arguments)]
fn compute_extra_info(enc: &EncryptedStream, kind: MediaKind, d: &mut UploadData, thumbnail: bool, duration: bool, waveform: bool, background: Option<&str>, logger: Option<&dyn Logger>) -> Result<()> {
    let original = enc.original_file_path.as_deref().unwrap_or("");
    if thumbnail {
        let thumb_type = if kind == MediaKind::Image { ThumbnailMediaType::Image } else { ThumbnailMediaType::Video };
        let t = generate_thumbnail(original, thumb_type, logger)?;
        d.jpeg_thumbnail = t.thumbnail;
        if d.width.is_none_or(|w| w == 0) {
            if let Some(o) = t.original_image_dimensions {
                d.width = Some(o.width);
                d.height = Some(o.height);
                if let Some(l) = logger {
                    l.debug("set dimensions");
                }
            }
        }
        if let Some(l) = logger {
            l.debug("generated thumbnail");
        }
    }
    if duration {
        d.seconds = get_audio_duration(MediaInput::Path(original))?;
        if let Some(l) = logger {
            l.debug("computed audio duration");
        }
    }
    if waveform {
        d.waveform = get_audio_waveform(MediaInput::Path(original), logger);
        if let Some(l) = logger {
            l.debug("processed waveform");
        }
    }
    if let Some(c) = background {
        d.background_argb = Some(assert_color(c));
        if let Some(l) = logger {
            l.debug("computed backgroundColor audio status");
        }
    }
    Ok(())
}
pub fn prepare_disappearing_message_setting_content(ephemeral_expiration: Option<u32>) -> WAMessageContent {
    let mut p = ProtocolMessage::new();
    p.set_type(ProtocolType::EPHEMERAL_SETTING);
    p.set_ephemeral_expiration(ephemeral_expiration.unwrap_or(0));
    let mut inner = WAMessageContent::new();
    inner.set_protocol_message(p);
    let mut f = FutureProofMessage::new();
    f.set_message(inner);
    let mut m = WAMessageContent::new();
    m.set_ephemeral_message(f);
    m
}
/// `m[field].contextInfo` when the proto of that field has it.
fn context_info_mut<'a>(m: &'a mut WAMessageContent, field: &str) -> Option<&'a mut ContextInfo> {
    Some(match field {
        "imageMessage" => m.image_message_mut().context_info_mut(),
        "contactMessage" => m.contact_message_mut().context_info_mut(),
        "locationMessage" => m.location_message_mut().context_info_mut(),
        "extendedTextMessage" => m.extended_text_message_mut().context_info_mut(),
        "documentMessage" => m.document_message_mut().context_info_mut(),
        "audioMessage" => m.audio_message_mut().context_info_mut(),
        "videoMessage" => m.video_message_mut().context_info_mut(),
        "call" => m.call_mut().context_info_mut(),
        "contactsArrayMessage" => m.contacts_array_message_mut().context_info_mut(),
        "liveLocationMessage" => m.live_location_message_mut().context_info_mut(),
        "templateMessage" => m.template_message_mut().context_info_mut(),
        "stickerMessage" => m.sticker_message_mut().context_info_mut(),
        "groupInviteMessage" => m.group_invite_message_mut().context_info_mut(),
        "templateButtonReplyMessage" => m.template_button_reply_message_mut().context_info_mut(),
        "productMessage" => m.product_message_mut().context_info_mut(),
        "listMessage" => m.list_message_mut().context_info_mut(),
        "orderMessage" => m.order_message_mut().context_info_mut(),
        "listResponseMessage" => m.list_response_message_mut().context_info_mut(),
        "buttonsMessage" => m.buttons_message_mut().context_info_mut(),
        "buttonsResponseMessage" => m.buttons_response_message_mut().context_info_mut(),
        "interactiveMessage" => m.interactive_message_mut().context_info_mut(),
        "interactiveResponseMessage" => m.interactive_response_message_mut().context_info_mut(),
        "pollCreationMessage" => m.poll_creation_message_mut().context_info_mut(),
        "requestPhoneNumberMessage" => m.request_phone_number_message_mut().context_info_mut(),
        "pollCreationMessageV2" => m.poll_creation_message_v2_mut().context_info_mut(),
        "pollCreationMessageV3" => m.poll_creation_message_v3_mut().context_info_mut(),
        "ptvMessage" => m.ptv_message_mut().context_info_mut(),
        "messageHistoryBundle" => m.message_history_bundle_mut().context_info_mut(),
        "eventMessage" => m.event_message_mut().context_info_mut(),
        "newsletterAdminInviteMessage" => m.newsletter_admin_invite_message_mut().context_info_mut(),
        "albumMessage" => m.album_message_mut().context_info_mut(),
        "stickerPackMessage" => m.sticker_pack_message_mut().context_info_mut(),
        "pollResultSnapshotMessage" => m.poll_result_snapshot_message_mut().context_info_mut(),
        "richResponseMessage" => m.rich_response_message_mut().context_info_mut(),
        "messageHistoryNotice" => m.message_history_notice_mut().context_info_mut(),
        "pollCreationMessageV5" => m.poll_creation_message_v5_mut().context_info_mut(),
        "newsletterFollowerInviteMessageV2" => m.newsletter_follower_invite_message_v2_mut().context_info_mut(),
        "pollResultSnapshotMessageV3" => m.poll_result_snapshot_message_v3_mut().context_info_mut(),
        _ => return None,
    })
}
/// Generate forwarded message content like WA does. `force_forward` will show the message as forwarded
/// even if it is from you.
pub fn generate_forward_message_content(message: &WAMessage, force_forward: Option<bool>) -> Result<WAMessageContent> {
    let Some(content) = message.message() else {
        return Err(Boom::status("no content in message", 400));
    };
    // hacky copy
    let normalized = normalize_message_content(Some(content)).ok_or_else(|| Boom::new("Cannot read properties of undefined (reading 'encode')"))?;
    let mut content = WAMessageContent::decode(&normalized.encode())?;
    let mut key = content.set_field_names().next();
    let existing_score = match key {
        Some(k) => context_info_mut(&mut content, k).and_then(|c| c.forwarding_score()).unwrap_or(0),
        None => 0,
    };
    let from_me = message.key().and_then(|k| k.from_me()) == Some(true);
    let score = existing_score + if from_me && force_forward != Some(true) { 0 } else { 1 };
    if key == Some("conversation") {
        let text = content.conversation().map_or_else(String::new, |s| s.as_str().to_string());
        content.extended_text_message_mut().set_text(text);
        content.clear_conversation();
        key = Some("extendedTextMessage");
    }
    let Some(key) = key else {
        return Err(Boom::new("Cannot set properties of undefined (setting 'contextInfo')"));
    };
    if let Some(ci) = context_info_mut(&mut content, key) {
        let mut next = ContextInfo::new();
        if score > 0 {
            next.set_forwarding_score(score);
            next.set_is_forwarded(true);
        }
        *ci = next;
    }
    Ok(content)
}
fn random_secret() -> [u8; 32] {
    let mut b = [0u8; 32];
    crypto::random_bytes(&mut b);
    b
}
fn text_content(text: &str, link_preview: &Option<Option<WAUrlInfo>>, options: &MessageContentGenerationOptions) -> WAMessageContent {
    let mut m = WAMessageContent::new();
    let ext = m.extended_text_message_mut();
    ext.set_text(text);
    let generated;
    let url_info = match link_preview {
        Some(v) => v.as_ref(),
        None => {
            generated = generate_link_preview_if_required(text, options.get_url_info.as_ref(), options.media.logger.as_deref());
            generated.as_ref()
        }
    };
    if let Some(u) = url_info {
        ext.set_matched_text(&u.matched_text);
        if let Some(t) = &u.jpeg_thumbnail {
            ext.set_jpeg_thumbnail(t.clone());
        }
        if let Some(d) = &u.description {
            ext.set_description(d);
        }
        ext.set_title(&u.title);
        ext.set_preview_type(waproto::message::extended_text_message::PreviewType(0));
        if let Some(img) = &u.high_quality_thumbnail {
            if let Some(v) = img.direct_path() {
                ext.set_thumbnail_direct_path(v.clone());
            }
            if let Some(v) = img.media_key() {
                ext.set_media_key(v.clone());
            }
            if let Some(v) = img.media_key_timestamp() {
                ext.set_media_key_timestamp(v);
            }
            if let Some(v) = img.width() {
                ext.set_thumbnail_width(v);
            }
            if let Some(v) = img.height() {
                ext.set_thumbnail_height(v);
            }
            if let Some(v) = img.file_sha256() {
                ext.set_thumbnail_sha256(v.clone());
            }
            if let Some(v) = img.file_enc_sha256() {
                ext.set_thumbnail_enc_sha256(v.clone());
            }
        }
    }
    if let Some(c) = options.media.background_color.as_deref().filter(|c| !c.is_empty()) {
        ext.set_background_argb(assert_color(c));
    }
    if let Some(f) = options.media.font.filter(|f| *f != 0) {
        ext.set_font(waproto::message::extended_text_message::FontType(f));
    }
    m
}
/// The media variant that holds this field carries the `ptv` video through a plain `{ video }` object.
fn media_only(video: &WAMediaUpload) -> AnyMediaMessageContent {
    AnyMediaMessageContent {
        media: MediaContent::Video { video: video.clone(), caption: None, gif_playback: None, jpeg_thumbnail: None, ptv: None, mentions: Mentionable::default(), context_info: None, width: None, height: None },
        mimetype: None,
        edit: None,
        album_parent_key: None,
    }
}
fn image_only(image: &WAMediaUpload) -> AnyMediaMessageContent {
    AnyMediaMessageContent {
        media: MediaContent::Image { image: image.clone(), caption: None, jpeg_thumbnail: None, mentions: Mentionable::default(), context_info: None, width: None, height: None },
        mimetype: None,
        edit: None,
        album_parent_key: None,
    }
}
pub fn generate_wa_message_content(message: &AnyMessageContent, options: &MessageContentGenerationOptions) -> Result<WAMessageContent> {
    let mut mentions: Option<&Mentionable> = None;
    let mut extra_context: Option<&ContextInfo> = None;
    let mut edit: Option<&WAMessageKey> = None;
    let mut album_parent_key: Option<&WAMessageKey> = None;
    let mut view_once = false;
    // `Object.keys(m)[0]` is the first key that the code sets. A poll sets `messageContextInfo` first.
    let mut first_key_is_context_info = false;
    let mut plain_context = false;
    let mut m = match message {
        AnyMessageContent::Delete(key) => {
            let mut p = ProtocolMessage::new();
            p.set_key(key.clone());
            p.set_type(ProtocolType::REVOKE);
            let mut m = WAMessageContent::new();
            m.set_protocol_message(p);
            m
        }
        AnyMessageContent::Forward { forward, force } => generate_forward_message_content(forward, *force)?,
        AnyMessageContent::DisappearingMessagesInChat(d) => {
            let exp = match d {
                DisappearingMessages::Enabled(true) => WA_DEFAULT_EPHEMERAL,
                DisappearingMessages::Enabled(false) => 0,
                DisappearingMessages::Seconds(s) => *s,
            };
            prepare_disappearing_message_setting_content(Some(exp))
        }
        AnyMessageContent::LimitSharing(on) => {
            let mut l = waproto::LimitSharing::new();
            l.set_sharing_limited(*on);
            l.set_trigger(waproto::limit_sharing::TriggerType(1));
            l.set_limit_sharing_setting_timestamp(now_ms());
            l.set_initiated_by_me(true);
            let mut p = ProtocolMessage::new();
            p.set_type(ProtocolType::LIMIT_SHARING);
            p.set_limit_sharing(l);
            let mut m = WAMessageContent::new();
            m.set_protocol_message(p);
            m
        }
        AnyMessageContent::Regular(regular) => {
            view_once = regular.view_once == Some(true);
            match &regular.content {
                RegularContent::Text { text, link_preview, mentions: men, context_info, edit: e } => {
                    mentions = Some(men);
                    extra_context = context_info.as_ref();
                    edit = e.as_ref();
                    plain_context = true;
                    text_content(text, link_preview, options)
                }
                RegularContent::Contacts { display_name, contacts } => {
                    let mut m = WAMessageContent::new();
                    match contacts.len() {
                        0 => return Err(Boom::status("require atleast 1 contact", 400)),
                        1 => m.set_contact_message(contacts[0].clone()),
                        _ => {
                            let a = m.contacts_array_message_mut();
                            if let Some(n) = display_name {
                                a.set_display_name(n);
                            }
                            a.set_contacts(contacts.clone());
                        }
                    }
                    m
                }
                RegularContent::Location(l) => {
                    let mut m = WAMessageContent::new();
                    m.set_location_message(l.clone());
                    m
                }
                RegularContent::React(r) => {
                    let mut react = r.clone();
                    if react.sender_timestamp_ms().is_none_or(|t| t == 0) {
                        react.set_sender_timestamp_ms(now_ms());
                    }
                    let mut m = WAMessageContent::new();
                    m.set_reaction_message(react);
                    m
                }
                RegularContent::GroupInvite(g) => {
                    let mut m = WAMessageContent::new();
                    let mut inv = GroupInviteMessage::new();
                    inv.set_invite_code(&g.invite_code);
                    inv.set_invite_expiration(g.invite_expiration as i64);
                    inv.set_caption(&g.text);
                    inv.set_group_jid(&g.jid);
                    inv.set_group_name(&g.subject);
                    //TODO: use built-in interface and get disappearing mode info etc.
                    //TODO: cache / use store!?
                    if let Some(pfp) = &options.get_profile_pic_url {
                        if let Some(url) = pfp(&g.jid, ProfilePictureType::Preview).filter(|u| !u.is_empty()) {
                            // upstream sends only the dispatcher of the options here, not their headers
                            let init = RequestInit { headers: Vec::new(), client: options.media.options.as_ref().and_then(|o| o.client.clone()) };
                            let resp = init.get(&url, &[])?;
                            if resp.ok() {
                                inv.set_jpeg_thumbnail(resp.body);
                            }
                        }
                    }
                    m.set_group_invite_message(inv);
                    m
                }
                RegularContent::Pin { pin, r#type, time } => {
                    let mut m = WAMessageContent::new();
                    let p = m.pin_in_chat_message_mut();
                    p.set_key(pin.clone());
                    p.set_type(waproto::message::pin_in_chat_message::Type(r#type.0));
                    p.set_sender_timestamp_ms(now_ms());
                    let secs = if r#type.0 == 1 { time.filter(|t| *t != 0).unwrap_or(86400) } else { 0 };
                    m.message_context_info_mut().set_message_add_on_duration_in_secs(secs);
                    m
                }
                RegularContent::ButtonReply { button_reply, r#type } => {
                    let mut m = WAMessageContent::new();
                    match r#type {
                        ButtonReplyType::Template => {
                            let t = m.template_button_reply_message_mut();
                            t.set_selected_display_text(&button_reply.display_text);
                            t.set_selected_id(&button_reply.id);
                            t.set_selected_index(button_reply.index);
                        }
                        ButtonReplyType::Plain => {
                            let b = m.buttons_response_message_mut();
                            b.set_selected_button_id(&button_reply.id);
                            b.set_selected_display_text(&button_reply.display_text);
                            b.set_type(waproto::message::buttons_response_message::Type::DISPLAY_TEXT);
                        }
                    }
                    m
                }
                RegularContent::Product { product, business_owner_jid, body, footer } => {
                    let prepared = prepare_media(&image_only(&product.product_image), None, options)?;
                    let mut snapshot = product.snapshot.clone();
                    match prepared.image_message() {
                        Some(i) => snapshot.set_product_image(i.clone()),
                        None => snapshot.clear_product_image(),
                    }
                    let mut pm = ProductMessage::new();
                    pm.set_product(snapshot);
                    if let Some(v) = business_owner_jid {
                        pm.set_business_owner_jid(v);
                    }
                    if let Some(v) = body {
                        pm.set_body(v);
                    }
                    if let Some(v) = footer {
                        pm.set_footer(v);
                    }
                    let mut m = WAMessageContent::new();
                    m.set_product_message(pm);
                    m
                }
                RegularContent::ListReply(l) => {
                    let mut m = WAMessageContent::new();
                    m.set_list_response_message(l.clone());
                    m
                }
                RegularContent::Event(event) => {
                    let mut m = WAMessageContent::new();
                    let start_time = event.start_date_ms.div_euclid(1000);
                    let e = m.event_message_mut();
                    if let (Some(call), Some(get_call_link)) = (event.call, &options.get_call_link) {
                        let token = get_call_link(call, Some(start_time as u64));
                        let prefix = if call == CallType::Audio { CALL_AUDIO_PREFIX } else { CALL_VIDEO_PREFIX };
                        e.set_join_link(format!("{prefix}{}", token.as_deref().unwrap_or("undefined")));
                    }
                    e.set_name(&event.name);
                    if let Some(d) = &event.description {
                        e.set_description(d);
                    }
                    e.set_start_time(start_time);
                    if let Some(end) = event.end_date_ms {
                        e.set_end_time(end / 1000);
                    }
                    e.set_is_canceled(event.is_cancelled.unwrap_or(false));
                    if let Some(v) = event.extra_guests_allowed {
                        e.set_extra_guests_allowed(v);
                    }
                    e.set_is_schedule_call(event.is_schedule_call.unwrap_or(false));
                    if let Some(l) = &event.location {
                        e.set_location(l.clone());
                    }
                    let secret = event.message_secret.clone().unwrap_or_else(|| random_secret().into());
                    m.message_context_info_mut().set_message_secret(secret);
                    m
                }
                RegularContent::Poll { poll, mentions: men, context_info, edit: e } => {
                    mentions = Some(men);
                    extra_context = context_info.as_ref();
                    edit = e.as_ref();
                    first_key_is_context_info = true;
                    let selectable = poll.selectable_count.unwrap_or(0);
                    if selectable as usize > poll.values.len() {
                        return Err(Boom::status(format!("poll.selectableCount in poll should be >= 0 and <= {}", poll.values.len()), 400));
                    }
                    let mut m = WAMessageContent::new();
                    // encKey
                    let secret = poll.message_secret.clone().unwrap_or_else(|| random_secret().into());
                    m.message_context_info_mut().set_message_secret(secret);
                    let mut creation = PollCreationMessage::new();
                    creation.set_name(&poll.name);
                    creation.set_selectable_options_count(selectable);
                    let options_list: Vec<PollOption> = poll.values.iter().map(|v| PollOption::new().with_option_name(v)).collect();
                    creation.set_options(options_list);
                    if poll.to_announcement_group == Some(true) {
                        // poll v2 is for community announcement groups (single select and multiple)
                        m.set_poll_creation_message_v2(creation);
                    } else if selectable == 1 {
                        //poll v3 is for single select polls
                        m.set_poll_creation_message_v3(creation);
                    } else {
                        // poll for multiple choice polls
                        m.set_poll_creation_message(creation);
                    }
                    m
                }
                RegularContent::Album { album, context_info, mentions: men } => {
                    mentions = Some(men);
                    extra_context = context_info.as_ref();
                    plain_context = true;
                    let mut m = WAMessageContent::new();
                    let a = m.album_message_mut();
                    if let Some(v) = album.expected_image_count {
                        a.set_expected_image_count(v);
                    }
                    if let Some(v) = album.expected_video_count {
                        a.set_expected_video_count(v);
                    }
                    m
                }
                RegularContent::SharePhoneNumber(_) => {
                    let mut m = WAMessageContent::new();
                    m.protocol_message_mut().set_type(ProtocolType::SHARE_PHONE_NUMBER);
                    m
                }
                RegularContent::RequestPhoneNumber(_) => {
                    let mut m = WAMessageContent::new();
                    m.set_request_phone_number_message(waproto::message::RequestPhoneNumberMessage::new());
                    m
                }
                RegularContent::Media(media) => {
                    edit = media.edit.as_ref();
                    album_parent_key = media.album_parent_key.as_ref();
                    match &media.media {
                        MediaContent::Image { mentions: men, context_info, .. } | MediaContent::Video { mentions: men, context_info, .. } => {
                            mentions = Some(men);
                            extra_context = context_info.as_ref();
                        }
                        MediaContent::Document { context_info, .. } => extra_context = context_info.as_ref(),
                        _ => {}
                    }
                    if let MediaContent::Video { video, ptv: Some(true), .. } = &media.media {
                        let prepared = prepare_media(&media_only(video), None, options)?;
                        let mut m = WAMessageContent::new();
                        if let Some(v) = prepared.video_message() {
                            m.set_ptv_message(v.clone());
                        }
                        m
                    } else {
                        prepare_media(media, regular.view_once, options)?
                    }
                }
            }
        }
    };
    if view_once {
        let mut f = FutureProofMessage::new();
        f.set_message(m);
        let mut wrapped = WAMessageContent::new();
        wrapped.set_view_once_message(f);
        m = wrapped;
    }
    let first_key = if first_key_is_context_info && !view_once { None } else { m.set_field_names().next() };
    if let Some(men) = mentions {
        let list = men.mentions.as_ref().filter(|l| !l.is_empty());
        let all = men.mention_all == Some(true);
        if list.is_some() || all {
            if let Some(ci) = first_key.and_then(|k| context_info_mut(&mut m, k)) {
                if let Some(l) = list {
                    ci.set_mentioned_jid(l.iter().map(|s| Str::from(s.as_str())).collect::<Vec<_>>());
                }
                if all {
                    ci.set_non_jid_mentions(1u32);
                } else if plain_context {
                    // a plain object has no `contextInfo` yet, so upstream writes both fields
                    ci.set_non_jid_mentions(0u32);
                }
            }
        }
    }
    if let Some(key) = edit {
        let mut p = ProtocolMessage::new();
        p.set_key(key.clone());
        p.set_edited_message(m);
        p.set_timestamp_ms(now_ms());
        p.set_type(ProtocolType::MESSAGE_EDIT);
        m = WAMessageContent::new();
        m.set_protocol_message(p);
    }
    if let Some(extra) = extra_context {
        // after an edit, the first key is `protocolMessage`, which has no `contextInfo`
        let k = if edit.is_some() { Some("protocolMessage") } else { first_key };
        if let Some(ci) = k.and_then(|k| context_info_mut(&mut m, k)) {
            ci.assign_from(extra);
        }
    }
    if let Some(parent) = album_parent_key {
        let mut assoc = MessageAssociation::new();
        assoc.set_association_type(waproto::message_association::AssociationType::MEDIA_ALBUM);
        assoc.set_parent_message_key(parent.clone());
        m.message_context_info_mut().set_message_association(assoc);
    }
    if should_include_reporting_token(&m) {
        let ctx: &mut MessageContextInfo = m.message_context_info_mut();
        if ctx.message_secret().is_none() {
            ctx.set_message_secret(random_secret());
        }
    }
    Ok(m)
}
fn js_u32(n: f64) -> u32 {
    if n.is_finite() { (n.trunc() as i64) as u32 } else { 0 }
}
/// A message built here with `create`. `message` is taken by value, because upstream changes the object.
pub fn generate_wa_message_from_content(jid: &str, mut message: WAMessageContent, options: &MessageGenerationOptionsFromContent) -> Result<WAMessage> {
    let misc = &options.misc;
    // set timestamp to now
    // if not specified
    let timestamp = unix_timestamp_seconds(misc.timestamp_ms);
    let not_object = |text: &str| Boom::new(format!("Cannot use 'in' operator to search for 'contextInfo' in {text}"));
    let inner = normalize_message_content_mut(&mut message);
    let key = get_content_type(inner.as_deref());
    if let Some(quoted) = misc.quoted.as_ref().filter(|_| !is_jid_newsletter(jid)) {
        let quoted_key = quoted.key();
        let from_me = quoted_key.and_then(|k| k.from_me()) == Some(true);
        let participant = if from_me {
            options.user_jid.clone() // TODO: Add support for LIDs
        } else {
            let candidates = [quoted.participant(), quoted_key.and_then(|k| k.participant()), quoted_key.and_then(|k| k.remote_jid())];
            candidates.into_iter().flatten().find(|s| !s.is_empty()).map_or_else(String::new, |s| s.as_str().to_string())
        };
        let Some(quoted_msg) = normalize_message_content(quoted.message()) else {
            return Err(Boom::new("Cannot read properties of undefined (reading 'undefined')"));
        };
        // strip any redundant properties
        let msg_type = get_content_type(Some(quoted_msg));
        let mut stripped = Json::Obj(Vec::new());
        if let (Some(t), Json::Obj(all)) = (msg_type, quoted_msg.to_json()) {
            if let Some((name, mut value)) = all.into_iter().find(|(k, _)| k == t) {
                if let Json::Obj(fields) = &mut value {
                    fields.retain(|(k, _)| k != "contextInfo");
                }
                stripped = Json::Obj(vec![(name, value)]);
            }
        }
        let stripped = WAMessageContent::from_json(&stripped)?;
        let inner = match inner {
            Some(i) => i,
            None => return Err(not_object("undefined")),
        };
        let Some(k) = key else { return Err(not_object("undefined")) };
        if k == "conversation" {
            return Err(not_object(inner.conversation().map_or("", |s| s.as_str())));
        }
        let mut ctx = context_info_mut(inner, k).map_or_else(ContextInfo::new, |c| c.clone());
        ctx.set_participant(jid_normalized_user(&participant));
        match quoted_key.and_then(|k| k.id()) {
            Some(id) => ctx.set_stanza_id(id.clone()),
            None => ctx.clear_stanza_id(),
        }
        ctx.set_quoted_message(stripped);
        // if a participant is quoted, then it must be a group
        // hence, remoteJid of group must also be entered
        let quoted_remote = quoted_key.and_then(|k| k.remote_jid());
        if quoted_remote.is_none_or(|r| r.as_str() != jid) {
            match quoted_remote {
                Some(r) => ctx.set_remote_jid(r.clone()),
                None => ctx.clear_remote_jid(),
            }
        }
        if let Some(target) = context_info_mut(inner, k) {
            *target = ctx;
        }
        return finish_from_content(jid, message, options, key, timestamp);
    }
    if let Some(inner) = inner {
        apply_ephemeral(jid, inner, key, misc)?;
    } else if ephemeral_applies(jid, key, misc) {
        return Err(Boom::new("Cannot read properties of undefined (reading 'undefined')"));
    }
    build_web_message_info(jid, message, options, timestamp)
}
fn finish_from_content(jid: &str, mut message: WAMessageContent, options: &MessageGenerationOptionsFromContent, key: Option<&'static str>, timestamp: i64) -> Result<WAMessage> {
    if let Some(inner) = normalize_message_content_mut(&mut message) {
        apply_ephemeral(jid, inner, key, &options.misc)?;
    }
    build_web_message_info(jid, message, options, timestamp)
}
fn ephemeral_applies(jid: &str, key: Option<&str>, misc: &MiscMessageGenerationOptions) -> bool {
    // if we want to send a disappearing message
    expiration_of(misc).is_some()
        // and it's not a protocol message -- delete, toggle disappear message
        && key != Some("protocolMessage")
        // already not converted to disappearing message
        && key != Some("ephemeralMessage")
        // newsletters don't support ephemeral messages
        && !is_jid_newsletter(jid)
}
/// The value of `ephemeralExpiration` when it is truthy, as `>>> 0` stores it.
fn expiration_of(misc: &MiscMessageGenerationOptions) -> Option<u32> {
    match misc.ephemeral_expiration.as_ref()? {
        EphemeralExpiration::Seconds(0) => None,
        EphemeralExpiration::Seconds(s) => Some(*s),
        EphemeralExpiration::Text(t) if t.is_empty() => None,
        EphemeralExpiration::Text(t) => Some(js_u32(t.trim().parse::<f64>().unwrap_or(f64::NAN))),
    }
}
fn apply_ephemeral(jid: &str, inner: &mut WAMessageContent, key: Option<&'static str>, misc: &MiscMessageGenerationOptions) -> Result<()> {
    if !ephemeral_applies(jid, key, misc) {
        return Ok(());
    }
    let Some(k) = key else {
        return Err(Boom::new("Cannot read properties of undefined (reading 'contextInfo')"));
    };
    if k == "conversation" {
        return Err(Boom::new("Cannot create property 'contextInfo' on string"));
    }
    if let Some(ci) = context_info_mut(inner, k) {
        ci.set_expiration(expiration_of(misc).unwrap_or(WA_DEFAULT_EPHEMERAL));
    }
    Ok(())
}
fn build_web_message_info(jid: &str, message: WAMessageContent, options: &MessageGenerationOptionsFromContent, timestamp: i64) -> Result<WAMessage> {
    let misc = &options.misc;
    let mut key = WAMessageKey::new();
    key.set_remote_jid(jid);
    key.set_from_me(true);
    match misc.message_id.as_deref().filter(|i| !i.is_empty()) {
        Some(id) => key.set_id(id),
        None => key.set_id(generate_message_id_v2(None)),
    }
    let mut o = WAMessage::new();
    o.set_key(key);
    o.set_message(message);
    o.set_message_timestamp(timestamp as u64);
    if is_jid_group(jid) || is_jid_status_broadcast(jid) {
        o.set_participant(&options.user_jid); // TODO: Add support for LIDs
    }
    o.set_status(Status::PENDING);
    Ok(o)
}
pub fn generate_wa_message(jid: &str, content: &AnyMessageContent, options: &MessageGenerationOptions) -> Result<WAMessage> {
    let mut opts = options.content.clone();
    // ensure msg ID is with every log
    if let Some(l) = &opts.media.logger {
        let id = options.from_content.misc.message_id.as_deref().unwrap_or("");
        opts.media.logger = Some(l.child(&[("msgId", id)]));
    }
    // Pass jid in the options to generateWAMessageContent
    opts.jid = Some(jid.to_string());
    let message = generate_wa_message_content(content, &opts)?;
    generate_wa_message_from_content(jid, message, &options.from_content)
}
macro_rules! extract_from_template {
    ($msg:expr, $text:expr) => {{
        let mut o = WAMessageContent::new();
        if let Some(v) = $msg.image_message() {
            o.set_image_message(v.clone());
        } else if let Some(v) = $msg.document_message() {
            o.set_document_message(v.clone());
        } else if let Some(v) = $msg.video_message() {
            o.set_video_message(v.clone());
        } else if let Some(v) = $msg.location_message() {
            o.set_location_message(v.clone());
        } else {
            let text: Option<&waproto::pb::Str> = $text;
            o.set_conversation(text.map_or("", |s| s.as_str()));
        }
        o
    }};
}
/// Extract the true message content from a message
/// Eg. extracts the inner message from a disappearing message/view once message
pub fn extract_message_content(content: Option<&WAMessageContent>) -> Option<WAMessageContent> {
    let content = normalize_message_content(content)?;
    if let Some(b) = content.buttons_message() {
        return Some(extract_from_template!(b, b.content_text()));
    }
    if let Some(t) = content.template_message() {
        if let Some(h) = t.hydrated_four_row_template() {
            return Some(extract_from_template!(h, h.hydrated_content_text()));
        }
        if let Some(h) = t.hydrated_template() {
            return Some(extract_from_template!(h, h.hydrated_content_text()));
        }
        if let Some(f) = t.four_row_template() {
            return Some(extract_from_template!(f, None));
        }
    }
    Some(content.clone())
}
pub type ReuploadRequest = Arc<dyn Fn(&WAMessage) -> Result<WAMessage> + Send + Sync>;
/// The context of `downloadMediaMessage`. Upstream retries when `error.status` is 410 or 404. Its own download
/// error is a Boom, and a Boom has `output.statusCode` but no `status`, so that retry does not run. This port
/// gives the same result: `reupload_request` stays in the API and no download error starts it.
#[derive(Clone)]
pub struct DownloadMediaMessageContext {
    pub reupload_request: ReuploadRequest,
    pub logger: Arc<dyn Logger>,
}
/// Downloads the given message. Throws an error if it's not a media message
pub fn download_media_message(message: &WAMessage, options: &MediaDownloadOptions, _ctx: Option<&DownloadMediaMessageContext>) -> Result<DecryptedMediaStream> {
    let m_content = extract_message_content(message.message()).ok_or_else(|| {
        let mut e = Boom::with_data("No message present", message.to_json());
        e.status_code = Some(400);
        e
    })?;
    let content_type = get_content_type(Some(&m_content));
    let not_media = || Boom::new(format!("\"{}\" message is not a media message", content_type.unwrap_or("undefined")));
    let text = |s: Option<&waproto::pb::Str>| s.map(|v| v.as_str().to_string());
    let (download, info) = match content_type {
        Some("imageMessage") => {
            let v = m_content.image_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.direct_path()), url: text(v.url()) }, hkdf_info_key(MediaType::Image))
        }
        Some("videoMessage") => {
            let v = m_content.video_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.direct_path()), url: text(v.url()) }, hkdf_info_key(MediaType::Video))
        }
        Some("ptvMessage") => {
            let v = m_content.ptv_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.direct_path()), url: text(v.url()) }, hkdf_info_key(MediaType::Ptv))
        }
        Some("audioMessage") => {
            let v = m_content.audio_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.direct_path()), url: text(v.url()) }, hkdf_info_key(MediaType::Audio))
        }
        Some("stickerMessage") => {
            let v = m_content.sticker_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.direct_path()), url: text(v.url()) }, hkdf_info_key(MediaType::Sticker))
        }
        Some("documentMessage") => {
            let v = m_content.document_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.direct_path()), url: text(v.url()) }, hkdf_info_key(MediaType::Document))
        }
        // `url` is in the proto of a location, and `location` has no HKDF info
        Some("locationMessage") => {
            let v = m_content.location_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: None, direct_path: None, url: text(v.url()) }, "WhatsApp undefined Keys".to_string())
        }
        Some("extendedTextMessage") => {
            let v = m_content.extended_text_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.thumbnail_direct_path()), url: None }, hkdf_info_key(MediaType::ThumbnailLink))
        }
        Some("stickerPackMessage") => {
            let v = m_content.sticker_pack_message().ok_or_else(not_media)?;
            (DownloadableMessage { media_key: v.media_key().cloned(), direct_path: text(v.thumbnail_direct_path()), url: None }, hkdf_info_key(MediaType::ThumbnailLink))
        }
        _ => return Err(not_media()),
    };
    download_with_info(&download, &info, options)
}
/// `downloadMediaMessage` with type `buffer`.
pub fn download_media_message_buffer(message: &WAMessage, options: &MediaDownloadOptions, ctx: Option<&DownloadMediaMessageContext>) -> Result<Vec<u8>> {
    to_buffer(&download_media_message(message, options, ctx)?)
}
/// The media message inside `assertMediaContent`.
#[derive(Clone, Debug, PartialEq)]
pub enum MediaMessage {
    Document(DocumentMessage),
    Image(ImageMessage),
    Video(VideoMessage),
    Audio(AudioMessage),
    Sticker(StickerMessage),
}
/// Checks whether the given message is a media message; if it is returns the inner content
pub fn assert_media_content(content: Option<&WAMessageContent>) -> Result<MediaMessage> {
    let content = extract_message_content(content);
    let found = content.as_ref().and_then(|c| {
        if let Some(v) = c.document_message() {
            Some(MediaMessage::Document(v.clone()))
        } else if let Some(v) = c.image_message() {
            Some(MediaMessage::Image(v.clone()))
        } else if let Some(v) = c.video_message() {
            Some(MediaMessage::Video(v.clone()))
        } else if let Some(v) = c.audio_message() {
            Some(MediaMessage::Audio(v.clone()))
        } else {
            c.sticker_message().map(|v| MediaMessage::Sticker(v.clone()))
        }
    });
    found.ok_or_else(|| {
        let mut e = Boom::with_data("given message is not a media message", content.as_ref().map_or(Json::Null, PbMessage::to_json));
        e.status_code = Some(400);
        e
    })
}
