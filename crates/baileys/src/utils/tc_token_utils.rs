//! Same behavior as Utils/tc-token-utils.ts.
use crate::auth::{KeyKind, KeyValue, SignalKeyStore, TcTokenEntry};
use crate::error::Result;
use crate::utils::time::now_ms;
use crate::wabinary::{Attrs, BinaryNode, Content, get_binary_node_child, get_binary_node_children, is_hosted_lid_user, is_hosted_pn_user, is_jid_meta_ai, is_lid_user, is_pn_user, jid_normalized_user};
use waproto::pb::{Bytes, Json};

/// Same phone-number pattern as WABinary's isJidBot, applied against the user part so the check is invariant
/// to @c.us and @s.whatsapp.net normalization: `^1313555\d{4}$|^131655500\d{2}$`.
fn is_bot_phone(user: &str) -> bool {
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|c| c.is_ascii_digit());
    user.strip_prefix("1313555").is_some_and(|r| digits(r, 4)) || user.strip_prefix("131655500").is_some_and(|r| digits(r, 2))
}
/// Mirrors WA Web's `Wid.isRegularUser()` (user, and not PSA, and not Bot). Used to gate tctoken storage against
/// malformed notifications. Works for both pre- and post-normalized JIDs (`@c.us` vs `@s.whatsapp.net`).
fn is_regular_user(jid: &str) -> bool {
    if jid.is_empty() {
        return false;
    }
    let user = jid.split('@').next().unwrap_or("");
    if user == "0" || is_bot_phone(user) || is_jid_meta_ai(jid) {
        return false;
    }
    is_pn_user(jid) || is_lid_user(jid) || is_hosted_pn_user(jid) || is_hosted_lid_user(jid) || jid.ends_with("@c.us")
}
const TC_TOKEN_BUCKET_DURATION: f64 = 604800.0; // 7 days
const TC_TOKEN_NUM_BUCKETS: f64 = 4.0; // ~28-day rolling window

/// Sentinel key under `tctoken` store holding a JSON array of tracked storage JIDs for cross-session pruning.
pub const TC_TOKEN_INDEX_KEY: &str = "__index";

/// Read the persisted tctoken JID index and return its entries (never contains the sentinel key itself).
pub fn read_tc_token_index(keys: &dyn SignalKeyStore) -> Result<Vec<String>> {
    let Some(KeyValue::TcToken(entry)) = keys.get_one(KeyKind::TcToken, TC_TOKEN_INDEX_KEY)? else {
        return Ok(Vec::new());
    };
    if entry.token.is_empty() {
        return Ok(Vec::new());
    }
    let Ok(Json::Arr(parsed)) = Json::parse(&String::from_utf8_lossy(&entry.token)) else {
        return Ok(Vec::new());
    };
    Ok(parsed.iter().filter_map(|j| j.as_str()).filter(|j| !j.is_empty() && *j != TC_TOKEN_INDEX_KEY).map(str::to_string).collect())
}
/// The value to write under `TC_TOKEN_INDEX_KEY`: the merged index (persisted, then added).
pub fn build_merged_tc_token_index_write(keys: &dyn SignalKeyStore, added_jids: &[String]) -> Result<TcTokenEntry> {
    let mut merged = read_tc_token_index(keys)?;
    let mut seen: rustc_hash::FxHashSet<String> = merged.iter().cloned().collect();
    for jid in added_jids {
        if !jid.is_empty() && jid != TC_TOKEN_INDEX_KEY && seen.insert(jid.clone()) {
            merged.push(jid.clone());
        }
    }
    let text = Json::Arr(merged.into_iter().map(Json::Str).collect()).stringify();
    Ok(TcTokenEntry { token: Bytes::from_vec(text.into_bytes()), timestamp: None, sender_timestamp: None })
}
/// Same as `parseInt(s)`: leading space, a sign, and the digits up to the first other character.
fn parse_int(s: &str) -> f64 {
    let t = s.trim_start();
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let end = t.bytes().position(|c| !c.is_ascii_digit()).unwrap_or(t.len());
    if end == 0 {
        return f64::NAN;
    }
    let v: f64 = t[..end].parse().unwrap_or(f64::NAN);
    if neg { -v } else { v }
}
/// Same as `Number(s)`.
pub(crate) fn js_to_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    for (p, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(r) = t.strip_prefix(p) {
            return u64::from_str_radix(r, radix).map_or(f64::NAN, |v| v as f64);
        }
    }
    match t {
        "Infinity" | "+Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ if t.bytes().any(|c| c.is_ascii_alphabetic() && c != b'e' && c != b'E') => f64::NAN,
        _ => t.parse().unwrap_or(f64::NAN),
    }
}
fn now_seconds() -> f64 {
    (now_ms() as f64 / 1000.0).floor()
}
/// WA Web has separate sender/receiver AB props for these but they're identical today.
/// `None` is null or undefined.
pub fn is_tc_token_expired(timestamp: Option<f64>) -> bool {
    let Some(ts) = timestamp else { return true };
    if ts.is_nan() {
        return true;
    }
    let current_bucket = (now_seconds() / TC_TOKEN_BUCKET_DURATION).floor();
    let cutoff_bucket = current_bucket - (TC_TOKEN_NUM_BUCKETS - 1.0);
    ts < cutoff_bucket * TC_TOKEN_BUCKET_DURATION
}
/// `isTcTokenExpired` with a string timestamp.
pub fn is_tc_token_expired_str(timestamp: Option<&str>) -> bool {
    is_tc_token_expired(timestamp.map(parse_int))
}
pub fn should_send_new_tc_token(sender_timestamp: Option<f64>) -> bool {
    let Some(ts) = sender_timestamp else { return true };
    (now_seconds() / TC_TOKEN_BUCKET_DURATION).floor() > (ts / TC_TOKEN_BUCKET_DURATION).floor()
}
pub type GetJidFor<'a> = &'a dyn Fn(&str) -> Result<Option<String>>;
/// Resolve JID to LID for tctoken storage (WA Web stores under LID)
pub fn resolve_tc_token_jid(jid: &str, get_lid_for_pn: GetJidFor<'_>) -> Result<String> {
    if is_lid_user(jid) {
        return Ok(jid.to_string());
    }
    Ok(get_lid_for_pn(jid)?.unwrap_or_else(|| jid.to_string()))
}
/// Resolve target JID for issuing privacy token based on AB prop 14303
pub fn resolve_issuance_jid(jid: &str, issue_to_lid: bool, get_lid_for_pn: GetJidFor<'_>, get_pn_for_lid: Option<GetJidFor<'_>>) -> Result<String> {
    if issue_to_lid {
        if is_lid_user(jid) {
            return Ok(jid.to_string());
        }
        return Ok(get_lid_for_pn(jid)?.unwrap_or_else(|| jid.to_string()));
    }
    if !is_lid_user(jid) {
        return Ok(jid.to_string());
    }
    if let Some(f) = get_pn_for_lid {
        return Ok(f(jid)?.unwrap_or_else(|| jid.to_string()));
    }
    Ok(jid.to_string())
}
fn or_base(base_content: Vec<BinaryNode>) -> Option<Vec<BinaryNode>> {
    if base_content.is_empty() { None } else { Some(base_content) }
}
fn try_build_tc_token(jid: &str, base_content: &mut Vec<BinaryNode>, keys: &dyn SignalKeyStore, get_lid_for_pn: GetJidFor<'_>) -> Result<bool> {
    let storage_jid = resolve_tc_token_jid(jid, get_lid_for_pn)?;
    let entry = match keys.get_one(KeyKind::TcToken, &storage_jid)? {
        Some(KeyValue::TcToken(e)) => Some(e),
        _ => None,
    };
    if let Some(e) = entry.as_ref().filter(|e| !e.token.is_empty() && !is_tc_token_expired_str(e.timestamp.as_deref()) && e.timestamp.is_some()) {
        let t = e.timestamp.as_deref().unwrap_or("");
        base_content.push(BinaryNode::with_bytes("tctoken", Attrs::from([("t", t)]), e.token.clone()));
        return Ok(true);
    }
    if let Some(e) = entry {
        // Preserve senderTimestamp so shouldSendNewTcToken() keeps its dedupe state
        // after we drop the unusable peer token. Only wipe the record entirely when
        // there's nothing worth keeping.
        let cleared = e.sender_timestamp.map(|s| KeyValue::TcToken(TcTokenEntry { token: Bytes::new(), timestamp: None, sender_timestamp: Some(s) }));
        keys.set_one(KeyKind::TcToken, &storage_jid, cleared)?;
    }
    Ok(false)
}
/// A failure of the store gives the same result as a missing token.
pub fn build_tc_token_from_jid(jid: &str, mut base_content: Vec<BinaryNode>, keys: &dyn SignalKeyStore, get_lid_for_pn: GetJidFor<'_>) -> Option<Vec<BinaryNode>> {
    match try_build_tc_token(jid, &mut base_content, keys, get_lid_for_pn) {
        Ok(true) => Some(base_content),
        _ => or_base(base_content),
    }
}
pub fn store_tc_tokens_from_iq_result(result: &BinaryNode, fallback_jid: &str, keys: &dyn SignalKeyStore, get_lid_for_pn: GetJidFor<'_>, on_new_jid_stored: Option<&dyn Fn(&str)>) -> Result<()> {
    let Some(tokens_node) = get_binary_node_child(Some(result), "tokens") else {
        return Ok(());
    };
    for token_node in get_binary_node_children(Some(tokens_node), "token") {
        let content = match &token_node.content {
            Some(Content::Binary(b)) if token_node.attr("type") == Some("trusted_contact") => b,
            _ => continue,
        };
        // In notifications tokenNode.attrs.jid is your own device JID, not the sender's
        let source = if fallback_jid.is_empty() { token_node.attr("jid").unwrap_or("") } else { fallback_jid };
        let raw_jid = jid_normalized_user(source);
        if !is_regular_user(&raw_jid) {
            continue;
        }
        let storage_jid = resolve_tc_token_jid(&raw_jid, get_lid_for_pn)?;
        let existing = match keys.get_one(KeyKind::TcToken, &storage_jid)? {
            Some(KeyValue::TcToken(e)) => Some(e),
            _ => None,
        };
        let number_of = |t: Option<&str>| t.filter(|s| !s.is_empty()).map_or(0.0, js_to_number);
        let existing_ts = number_of(existing.as_ref().and_then(|e| e.timestamp.as_deref()));
        let incoming_ts = number_of(token_node.attr("t"));
        // timestamp-less tokens would be immediately expired
        if incoming_ts.is_nan() || incoming_ts == 0.0 {
            continue;
        }
        if existing_ts > 0.0 && existing_ts > incoming_ts {
            continue;
        }
        let entry = TcTokenEntry { token: content.clone(), timestamp: token_node.attr("t").map(str::to_string), sender_timestamp: existing.and_then(|e| e.sender_timestamp) };
        keys.set_one(KeyKind::TcToken, &storage_jid, Some(KeyValue::TcToken(entry)))?;
        if let Some(f) = on_new_jid_stored {
            f(&storage_jid);
        }
    }
    Ok(())
}
