//! Same behavior as Utils/reporting-utils.ts.
use crate::crypto;
use crate::error::{Boom, Result};
use crate::types::{WAMessageContent, WAMessageKey};
use crate::wabinary::{Attrs, BinaryNode};

/// `m` of upstream is an empty `children`, which skips every nested field.
pub struct ReportingField {
    pub f: i32,
    pub m: bool,
    pub s: &'static [ReportingField],
}
const fn leaf(f: i32) -> ReportingField {
    ReportingField { f, m: false, s: &[] }
}
const fn nest(f: i32, s: &'static [ReportingField]) -> ReportingField {
    ReportingField { f, m: false, s }
}
const fn msg(f: i32) -> ReportingField {
    ReportingField { f, m: true, s: &[] }
}
static CTX: [ReportingField; 2] = [leaf(21), leaf(22)];
static LOC: [ReportingField; 2] = [leaf(1), leaf(2)];
static REPLY: [ReportingField; 4] = [leaf(2), nest(3, &LOC), nest(5, &CTX), nest(8, &LOC)];
static FIRST: [ReportingField; 1] = [msg(1)];
static SHORT: [ReportingField; 1] = [leaf(1)];
static F3: [ReportingField; 6] = [leaf(2), leaf(3), leaf(8), leaf(11), nest(17, &CTX), leaf(25)];
static F4: [ReportingField; 3] = [leaf(1), leaf(16), nest(17, &CTX)];
static F5: [ReportingField; 5] = [leaf(3), leaf(4), leaf(5), leaf(16), nest(17, &CTX)];
static F6: [ReportingField; 3] = [leaf(1), nest(17, &CTX), leaf(30)];
static F7: [ReportingField; 5] = [leaf(2), leaf(7), leaf(10), nest(17, &CTX), leaf(20)];
static F8: [ReportingField; 5] = [leaf(2), leaf(7), leaf(9), nest(17, &CTX), leaf(21)];
static F9: [ReportingField; 6] = [leaf(2), leaf(6), leaf(7), leaf(13), nest(17, &CTX), leaf(20)];
static F12: [ReportingField; 4] = [leaf(1), leaf(2), msg(14), leaf(15)];
static F18: [ReportingField; 3] = [leaf(6), leaf(16), nest(17, &CTX)];
static F26: [ReportingField; 5] = [leaf(4), leaf(5), leaf(8), leaf(13), nest(17, &CTX)];
static F28: [ReportingField; 6] = [leaf(1), leaf(2), leaf(4), leaf(5), leaf(6), nest(7, &CTX)];
static F88: [ReportingField; 3] = [leaf(1), nest(2, &SHORT), nest(3, &CTX)];
static REPORTING_FIELDS: [ReportingField; 27] = [
    leaf(1),
    nest(3, &F3),
    nest(4, &F4),
    nest(5, &F5),
    nest(6, &F6),
    nest(7, &F7),
    nest(8, &F8),
    nest(9, &F9),
    nest(12, &F12),
    nest(18, &F18),
    nest(26, &F26),
    nest(28, &F28),
    nest(37, &FIRST),
    nest(49, &REPLY),
    nest(53, &FIRST),
    nest(55, &FIRST),
    nest(58, &FIRST),
    nest(59, &FIRST),
    nest(60, &REPLY),
    nest(64, &REPLY),
    nest(66, &F9),
    nest(74, &FIRST),
    nest(87, &FIRST),
    nest(88, &F88),
    nest(92, &FIRST),
    nest(93, &FIRST),
    nest(94, &FIRST),
];
const ENC_SECRET_REPORT_TOKEN: &str = "Report Token";
const WIRE_VARINT: i32 = 0;
const WIRE_FIXED64: i32 = 1;
const WIRE_BYTES: i32 = 2;
const WIRE_FIXED32: i32 = 5;

pub fn should_include_reporting_token(message: &WAMessageContent) -> bool {
    message.reaction_message().is_none() && message.enc_reaction_message().is_none() && message.enc_event_response_message().is_none() && message.poll_update_message().is_none()
}
fn generate_msg_secret_key(modification_type: &str, orig_msg_id: &str, orig_msg_sender: &str, modification_sender: &str, orig_msg_secret: &[u8]) -> Vec<u8> {
    let mut info = String::with_capacity(orig_msg_id.len() + orig_msg_sender.len() + modification_sender.len() + modification_type.len());
    // the bytes of upstream become a latin1 string, which the HKDF info reads back as UTF-8
    for part in [orig_msg_id, orig_msg_sender, modification_sender, modification_type] {
        for b in part.bytes() {
            info.push(b as char);
        }
    }
    crypto::hkdf(orig_msg_secret, 32, None, info.as_bytes())
}
/// `(value, bytes)`. The value is a 32-bit int, because the JavaScript `|` and `<<` work on one.
fn decode_varint(buffer: &[u8], offset: usize) -> Option<(i32, usize)> {
    let (mut value, mut bytes, mut shift) = (0i32, 0usize, 0u32);
    while offset + bytes < buffer.len() {
        let current = buffer[offset + bytes];
        value |= ((current & 0x7f) as i32).wrapping_shl(shift);
        bytes += 1;
        if current & 0x80 == 0 {
            return Some((value, bytes));
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    None
}
fn encode_varint(value: i32, out: &mut Vec<u8>) {
    let mut remaining = value as u32;
    while remaining > 0x7f {
        out.push((remaining & 0x7f) as u8 | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}
/// A piece of the result: bytes of the input, or a nested field that was built again.
enum Piece {
    Range(usize, usize),
    Built(Vec<u8>),
}
fn extract_reporting_token_content(data: &[u8], cfg: &[ReportingField]) -> Option<Vec<u8>> {
    let mut out: Vec<(i32, Piece)> = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let (tag, tag_bytes) = decode_varint(data, i)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x7;
        let field_start = i;
        i += tag_bytes;
        let field_cfg = cfg.iter().find(|f| f.f == field_num);
        let end = match wire_type {
            WIRE_VARINT => {
                let (_, n) = decode_varint(data, i)?;
                i + n
            }
            WIRE_FIXED64 => i + 8,
            WIRE_FIXED32 => i + 4,
            WIRE_BYTES => {
                let (len, n) = decode_varint(data, i)?;
                let val_start = i + n;
                // a negative length moves back in upstream and can loop forever: here it stops the parse
                let val_end = val_start.checked_add_signed(len as isize).filter(|e| *e >= val_start)?;
                if val_end > data.len() {
                    return None;
                }
                let Some(field_cfg) = field_cfg else {
                    i = val_end;
                    continue;
                };
                if field_cfg.m || !field_cfg.s.is_empty() {
                    let sub = extract_reporting_token_content(&data[val_start..val_end], field_cfg.s)?;
                    if !sub.is_empty() {
                        let mut built = Vec::with_capacity(sub.len() + 8);
                        encode_varint(tag, &mut built);
                        encode_varint(sub.len() as i32, &mut built);
                        built.extend_from_slice(&sub);
                        out.push((field_num, Piece::Built(built)));
                    }
                } else {
                    out.push((field_num, Piece::Range(field_start, val_end)));
                }
                i = val_end;
                continue;
            }
            _ => return None,
        };
        if end > data.len() {
            return None;
        }
        if field_cfg.is_some() {
            out.push((field_num, Piece::Range(field_start, end)));
        }
        i = end;
    }
    out.sort_by_key(|p| p.0);
    let mut o = Vec::with_capacity(data.len());
    for (_, piece) in &out {
        match piece {
            Piece::Range(a, b) => o.extend_from_slice(&data[*a..*b]),
            Piece::Built(b) => o.extend_from_slice(b),
        }
    }
    Some(o)
}
pub fn get_message_reporting_token(msg_protobuf: &[u8], message: &WAMessageContent, key: &WAMessageKey) -> Result<Option<BinaryNode>> {
    let Some(msg_secret) = message.message_context_info().and_then(|c| c.message_secret()) else {
        return Ok(None);
    };
    let Some(id) = key.id().filter(|i| !i.is_empty()) else {
        return Ok(None);
    };
    let remote = key.remote_jid().map(|s| s.as_str());
    let participant_or_remote = key.participant().map(|s| s.as_str()).filter(|p| !p.is_empty()).or(remote);
    let from_me = key.from_me() == Some(true);
    let (from, to) = if from_me { (remote, participant_or_remote) } else { (participant_or_remote, remote) };
    let missing = || Boom::new("The first argument must be of type string or an instance of Buffer. Received undefined");
    let reporting_secret = generate_msg_secret_key(ENC_SECRET_REPORT_TOKEN, id, from.ok_or_else(missing)?, to.ok_or_else(missing)?, msg_secret);
    let Some(content) = extract_reporting_token_content(msg_protobuf, &REPORTING_FIELDS).filter(|c| !c.is_empty()) else {
        return Ok(None);
    };
    let reporting_token = crypto::hmac_sha256(&reporting_secret, &content);
    let token = BinaryNode::with_bytes("reporting_token", Attrs::from([("v", "2")]), &reporting_token[..16]);
    Ok(Some(BinaryNode::with_nodes("reporting", Attrs::new(), vec![token])))
}
