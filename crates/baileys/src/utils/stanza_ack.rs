//! Same as Utils/stanza-ack.ts.
use crate::wabinary::{Attrs, BinaryNode};

/// Builds an ACK stanza for a received node. Pure function, with no I/O or side effects.
///
/// Mirrors WhatsApp Web's ACK construction:
/// - WAWebHandleMsgSendAck.sendAck / sendNack
/// - WAWebCreateNackFromStanza.createNackFromStanza
pub fn build_ack_stanza(node: &BinaryNode, error_code: Option<u32>, me_id: Option<&str>) -> BinaryNode {
    let a = &node.attrs;
    let mut attrs = Attrs(Vec::with_capacity(7));
    // a missing `id` or `from` is undefined upstream, and the encoder drops undefined values
    if let Some(id) = a.get("id") {
        attrs.set("id", id);
    }
    if let Some(from) = a.get("from") {
        attrs.set("to", from);
    }
    attrs.set("class", node.tag.clone());

    if let Some(code) = error_code.filter(|c| *c != 0) {
        attrs.set("error", code.to_string());
    }
    // an empty attribute is falsy upstream
    for k in ["participant", "recipient", "type"] {
        if let Some(v) = a.get(k).filter(|v| !v.is_empty()) {
            attrs.set(k, v);
        }
    }
    // WA Web WAWebHandleMsgSendAck.sendAck/sendNack always include `from` for message-class ACKs
    if node.tag.as_str() == "message" {
        if let Some(me) = me_id.filter(|m| !m.is_empty()) {
            attrs.set("from", me);
        }
    }
    BinaryNode::tag("ack", attrs)
}
