//! Port of Utils/decode-wa-message.test.ts.
use baileys::error::Boom;
use baileys::utils::decode_wa_message::decode_message_node;
use baileys::wabinary::{Attrs, BinaryNode};

const ME_ID: &str = "5511999999999@s.whatsapp.net";
const ME_LID: &str = "111111111111111@lid";
const PEER_ID: &str = "5511888888888@s.whatsapp.net";
const GROUP_ID: &str = "120363000000000000@g.us";

fn message(attrs: &[(&str, &str)]) -> BinaryNode {
    let mut a = Attrs::from([("t", "1700000000")]);
    for (k, v) in attrs {
        a.set(*k, *v);
    }
    BinaryNode::with_nodes("message", a, vec![])
}
fn capture_throw(stanza: &BinaryNode) -> Boom {
    decode_message_node(stanza, ME_ID, ME_LID).err().expect("expected function to throw")
}

#[test]
fn t_decodemessagenode_validation_throws_boom_when_stanza_has_no_id_attribute() {
    let stanza = message(&[("from", PEER_ID)]);
    let err = capture_throw(&stanza);
    assert!(err.message.contains("missing id"), "{}", err.message);
}
#[test]
fn t_decodemessagenode_validation_throws_boom_when_stanza_has_no_from_attribute() {
    let stanza = message(&[("id", "MSG_1")]);
    let err = capture_throw(&stanza);
    assert!(err.message.contains("missing from"), "{}", err.message);
}
#[test]
fn t_decodemessagenode_validation_throws_boom_for_an_unknown_jid_type() {
    let stanza = message(&[("id", "MSG_1"), ("from", "unknown@server")]);
    assert!(capture_throw(&stanza).message.contains("Unknown message type"));
}
#[test]
fn t_decodemessagenode_validation_throws_boom_for_group_message_without_participant() {
    let stanza = message(&[("id", "MSG_1"), ("from", GROUP_ID)]);
    assert!(capture_throw(&stanza).message.contains("No participant"));
}
#[test]
fn t_decodemessagenode_happy_paths_decodes_a_1_1_incoming_chat_message() {
    let stanza = message(&[("id", "MSG_1"), ("from", PEER_ID)]);
    let result = decode_message_node(&stanza, ME_ID, ME_LID).unwrap();
    let key = result.full_message.key().unwrap();
    assert_eq!(key.id().unwrap(), "MSG_1");
    assert_eq!(key.remote_jid().unwrap(), PEER_ID);
    assert_ne!(key.from_me(), Some(true));
    assert_eq!(result.author, PEER_ID);
}
#[test]
fn t_decodemessagenode_happy_paths_decodes_an_outgoing_chat_message_recipient_set_from_me() {
    let stanza = message(&[("id", "MSG_2"), ("from", ME_ID), ("recipient", PEER_ID)]);
    let result = decode_message_node(&stanza, ME_ID, ME_LID).unwrap();
    let key = result.full_message.key().unwrap();
    assert_eq!(key.from_me(), Some(true));
    assert_eq!(key.remote_jid().unwrap(), PEER_ID);
}
#[test]
fn t_decodemessagenode_happy_paths_rejects_a_recipient_tagged_message_that_is_not_from_me() {
    let stanza = message(&[("id", "MSG_3"), ("from", PEER_ID), ("recipient", ME_ID)]);
    assert!(capture_throw(&stanza).message.contains("not from me"));
}
#[test]
fn t_decodemessagenode_happy_paths_decodes_a_group_message() {
    let stanza = message(&[("id", "MSG_G"), ("from", GROUP_ID), ("participant", PEER_ID)]);
    let result = decode_message_node(&stanza, ME_ID, ME_LID).unwrap();
    let key = result.full_message.key().unwrap();
    assert_eq!(key.remote_jid().unwrap(), GROUP_ID);
    assert_eq!(key.participant().unwrap(), PEER_ID);
    assert_eq!(result.author, PEER_ID);
}
