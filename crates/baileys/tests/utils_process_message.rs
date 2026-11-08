//! Port of Utils/process-message.test.ts.
use baileys::proto::message::ReactionMessage;
use baileys::proto::{Message, MessageKey, WebMessageInfo};
use baileys::utils::process_message::{clean_message, get_chat_id};

const ME_ID: &str = "me@s.whatsapp.net";
const ME_LID: &str = "me@lid";
const OTHER_USER_ID: &str = "other@s.whatsapp.net";

fn key() -> MessageKey {
    MessageKey::new().with_remote_jid("chat@s.whatsapp.net").with_from_me(false).with_id("ABC")
}
fn base_message(key: MessageKey, message: Option<Message>) -> WebMessageInfo {
    let content = message.unwrap_or_else(|| Message::new().with_conversation("hello"));
    WebMessageInfo::new().with_key(key).with_message(content).with_message_timestamp(1675888000u64)
}
fn reaction(key: MessageKey, text: &str) -> Message {
    Message::new().with_reaction_message(ReactionMessage::new().with_key(key).with_text(text))
}

#[test]
fn t_cleanmessage_jid_normalization_should_correctly_normalize_a_standard_phone_number_jid_with_a_device() {
    let mut message = base_message(key().with_remote_jid("1234567890:15@s.whatsapp.net").with_participant("9876543210:5@s.whatsapp.net"), None);
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    assert_eq!(message.key().unwrap().remote_jid().unwrap(), "1234567890@s.whatsapp.net");
    assert_eq!(message.key().unwrap().participant().unwrap(), "9876543210@s.whatsapp.net");
}
#[test]
fn t_cleanmessage_jid_normalization_should_not_modify_a_group_jid() {
    let mut message = base_message(key().with_remote_jid("123456-7890@g.us"), None);
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    assert_eq!(message.key().unwrap().remote_jid().unwrap(), "123456-7890@g.us");
}
#[test]
fn t_cleanmessage_jid_normalization_should_correctly_normalize_a_lid_with_a_device() {
    let mut message = base_message(key().with_participant("1234567890:12@lid"), None);
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    assert_eq!(message.key().unwrap().participant().unwrap(), "1234567890@lid");
}
#[test]
fn t_cleanmessage_hosted_jid_handling_should_correctly_normalize_a_hosted_pn_jid_back_to_pn_form() {
    let mut message = base_message(key().with_remote_jid("1234567890:99@hosted"), None);
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    assert_eq!(message.key().unwrap().remote_jid().unwrap(), "1234567890@s.whatsapp.net");
}
#[test]
fn t_cleanmessage_hosted_jid_handling_should_correctly_normalize_a_hosted_lid_jid_back_to_lid_form() {
    let mut message = base_message(key().with_participant("9876543210:99@hosted.lid"), None);
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    assert_eq!(message.key().unwrap().participant().unwrap(), "9876543210@lid");
}
#[test]
fn t_cleanmessage_reaction_message_perspective_should_correct_the_perspective_of_a_reaction_to_another_user_s_message() {
    let reacted = MessageKey::new().with_remote_jid("chat@s.whatsapp.net").with_from_me(false).with_id("MSG_THEY_SENT").with_participant(OTHER_USER_ID);
    let mut message = base_message(key().with_from_me(false).with_participant(OTHER_USER_ID), Some(reaction(reacted, "😂")));
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    let reaction_key = message.message().unwrap().reaction_message().unwrap().key().unwrap();
    assert_eq!(reaction_key.from_me(), Some(false));
}
#[test]
fn t_cleanmessage_reaction_message_perspective_should_not_modify_a_reaction_on_a_message_i_sent_from_another_device() {
    let reacted = MessageKey::new().with_remote_jid("chat@s.whatsapp.net").with_from_me(true).with_id("MSG_I_SENT");
    let mut message = base_message(key().with_from_me(true), Some(reaction(reacted, "❤️")));
    let original_reaction_key = message.message().unwrap().reaction_message().unwrap().key().unwrap().clone();
    clean_message(&mut message, ME_ID, ME_LID).unwrap();
    let reaction_key = message.message().unwrap().reaction_message().unwrap().key().unwrap();
    assert_eq!(*reaction_key, original_reaction_key);
}
#[test]
fn t_cleanmessage_edge_cases_should_not_crash_if_jids_are_undefined() {
    let mut message = base_message(MessageKey::new().with_from_me(false).with_id("ABC"), None);
    assert!(clean_message(&mut message, ME_ID, ME_LID).is_ok());
}
#[test]
fn t_cleanmessage_edge_cases_should_not_crash_on_an_empty_message_object() {
    let mut message = base_message(key(), Some(Message::new()));
    assert!(clean_message(&mut message, ME_ID, ME_LID).is_ok());
}
#[test]
fn t_getchatid_returns_remotejid_for_a_regular_1_1_chat() {
    let k = MessageKey::new().with_remote_jid("peer@s.whatsapp.net").with_from_me(false).with_id("X");
    assert_eq!(get_chat_id(&k).unwrap(), "peer@s.whatsapp.net");
}
#[test]
fn t_getchatid_returns_remotejid_for_a_group_chat_broadcast_check_is_false() {
    let k = MessageKey::new().with_remote_jid("120363@g.us").with_from_me(false).with_id("X");
    assert_eq!(get_chat_id(&k).unwrap(), "120363@g.us");
}
#[test]
fn t_getchatid_returns_remotejid_for_status_broadcast_status_is_special_cased_to_remotejid() {
    let k = MessageKey::new().with_remote_jid("status@broadcast").with_participant("someone@s.whatsapp.net").with_from_me(false).with_id("X");
    assert_eq!(get_chat_id(&k).unwrap(), "status@broadcast");
}
#[test]
fn t_getchatid_returns_participant_for_non_status_broadcast_received_from_peer() {
    let k = MessageKey::new().with_remote_jid("12345@broadcast").with_participant("sender@s.whatsapp.net").with_from_me(false).with_id("X");
    assert_eq!(get_chat_id(&k).unwrap(), "sender@s.whatsapp.net");
}
#[test]
fn t_getchatid_returns_remotejid_for_non_status_broadcast_sent_by_me() {
    let k = MessageKey::new().with_remote_jid("12345@broadcast").with_participant("me@s.whatsapp.net").with_from_me(true).with_id("X");
    assert_eq!(get_chat_id(&k).unwrap(), "12345@broadcast");
}
#[test]
fn t_getchatid_throws_when_remotejid_is_missing() {
    let k = MessageKey::new().with_from_me(false).with_id("X");
    assert!(get_chat_id(&k).unwrap_err().message.contains("missing remoteJid"));
}
#[test]
fn t_getchatid_throws_when_broadcast_key_has_no_participant() {
    let k = MessageKey::new().with_remote_jid("12345@broadcast").with_from_me(false).with_id("X");
    assert!(get_chat_id(&k).unwrap_err().message.contains("missing participant"));
}
