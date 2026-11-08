//! Port of Utils/reporting-utils.test.ts.
use baileys::crypto::random_bytes;
use baileys::proto::message::{AudioMessage, DocumentMessage, EncEventResponseMessage, EncReactionMessage, ExtendedTextMessage, ImageMessage, PollEncValue, PollUpdateMessage, ReactionMessage, StickerMessage, VideoMessage};
use baileys::proto::pb::PbMessage;
use baileys::proto::{Message, MessageContextInfo, MessageKey};
use baileys::utils::reporting_utils::{get_message_reporting_token, should_include_reporting_token};
use baileys::wabinary::{BinaryNode, Content};

fn key_with_id() -> MessageKey {
    MessageKey::new().with_id("id")
}
fn random_secret() -> Vec<u8> {
    let mut b = vec![0u8; 32];
    random_bytes(&mut b);
    b
}
fn create_key() -> MessageKey {
    MessageKey::new().with_id("test-id").with_from_me(true).with_remote_jid("123@s.whatsapp.net")
}
fn with_secret(content: Message, secret: Vec<u8>) -> Message {
    content.with_message_context_info(MessageContextInfo::new().with_message_secret(secret))
}
fn conversation(text: &str) -> Message {
    Message::new().with_conversation(text)
}
fn get_token(result: Option<BinaryNode>) -> Option<Vec<u8>> {
    match result?.content? {
        Content::Nodes(n) => match n.into_iter().next()?.content? {
            Content::Binary(b) => Some(b.to_vec()),
            _ => None,
        },
        _ => None,
    }
}
fn token_of(msg: &Message, key: &MessageKey) -> Option<Vec<u8>> {
    get_token(get_message_reporting_token(&msg.encode(), msg, key).unwrap())
}

#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_conversation() {
    assert!(should_include_reporting_token(&conversation("Hello")));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_extendedtextmessage() {
    assert!(should_include_reporting_token(&Message::new().with_extended_text_message(ExtendedTextMessage::new().with_text("Link"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_imagemessage() {
    assert!(should_include_reporting_token(&Message::new().with_image_message(ImageMessage::new().with_url("url").with_mimetype("image/jpeg"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_videomessage() {
    assert!(should_include_reporting_token(&Message::new().with_video_message(VideoMessage::new().with_url("url").with_mimetype("video/mp4"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_documentmessage() {
    assert!(should_include_reporting_token(&Message::new().with_document_message(DocumentMessage::new().with_url("url").with_mimetype("application/pdf"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_audiomessage() {
    assert!(should_include_reporting_token(&Message::new().with_audio_message(AudioMessage::new().with_url("url").with_mimetype("audio/ogg"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_true_for_stickermessage() {
    assert!(should_include_reporting_token(&Message::new().with_sticker_message(StickerMessage::new().with_url("url").with_mimetype("image/webp"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_false_for_reactionmessage() {
    assert!(!should_include_reporting_token(&Message::new().with_reaction_message(ReactionMessage::new().with_key(key_with_id()).with_text("👍"))));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_false_for_encreactionmessage() {
    let m = EncReactionMessage::new().with_target_message_key(key_with_id()).with_enc_payload(&b"x"[..]).with_enc_iv(&b"x"[..]);
    assert!(!should_include_reporting_token(&Message::new().with_enc_reaction_message(m)));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_false_for_pollupdatemessage() {
    let m = PollUpdateMessage::new().with_poll_creation_message_key(key_with_id()).with_vote(PollEncValue::new().with_enc_payload(&b"x"[..]).with_enc_iv(&b"x"[..]));
    assert!(!should_include_reporting_token(&Message::new().with_poll_update_message(m)));
}
#[test]
fn t_reporting_utils_shouldincludereportingtoken_should_return_false_for_enceventresponsemessage() {
    let m = EncEventResponseMessage::new().with_event_creation_message_key(key_with_id()).with_enc_payload(&b"x"[..]).with_enc_iv(&b"x"[..]);
    assert!(!should_include_reporting_token(&Message::new().with_enc_event_response_message(m)));
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_return_null_when_message_secret_is_missing() {
    let msg = conversation("Hello");
    assert_eq!(get_message_reporting_token(&msg.encode(), &msg, &create_key()).unwrap(), None);
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_return_null_when_message_key_id_is_missing() {
    let msg = with_secret(conversation("Hello"), random_secret());
    let key = create_key().with_id("");
    assert_eq!(get_message_reporting_token(&msg.encode(), &msg, &key).unwrap(), None);
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_return_valid_reporting_node_structure() {
    let msg = with_secret(conversation("Hello"), random_secret());
    let result = get_message_reporting_token(&msg.encode(), &msg, &create_key()).unwrap().unwrap();
    assert_eq!(result.tag, "reporting");
    assert!(result.attrs.is_empty());
    let Some(Content::Nodes(content)) = &result.content else { panic!("expected child nodes") };
    assert_eq!(content.len(), 1);
    assert_eq!(content[0].tag, "reporting_token");
    assert_eq!(content[0].attr("v"), Some("2"));
    let Some(Content::Binary(token)) = &content[0].content else { panic!("expected a token") };
    assert_eq!(token.len(), 16);
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_produce_consistent_tokens_for_the_same_input() {
    let msg = with_secret(conversation("Test"), random_secret());
    let key = create_key();
    let (t1, t2) = (token_of(&msg, &key), token_of(&msg, &key));
    assert_eq!(t1, t2);
    assert!(t1.is_some());
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_produce_different_tokens_for_different_secrets() {
    let msg1 = with_secret(conversation("Same"), random_secret());
    let msg2 = with_secret(conversation("Same"), random_secret());
    assert_ne!(token_of(&msg1, &create_key()), token_of(&msg2, &create_key()));
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_produce_different_tokens_for_different_message_ids() {
    let msg = with_secret(conversation("Same"), random_secret());
    assert_ne!(token_of(&msg, &create_key().with_id("id-1")), token_of(&msg, &create_key().with_id("id-2")));
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_produce_different_tokens_for_different_remotejids() {
    let msg = with_secret(conversation("Same"), random_secret());
    assert_ne!(token_of(&msg, &create_key().with_remote_jid("111@s.whatsapp.net")), token_of(&msg, &create_key().with_remote_jid("222@s.whatsapp.net")));
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_handle_group_messages() {
    let msg = with_secret(conversation("Test"), random_secret());
    let key = create_key().with_remote_jid("123@g.us").with_participant("456@s.whatsapp.net");
    assert_eq!(get_message_reporting_token(&msg.encode(), &msg, &key).unwrap().unwrap().tag, "reporting");
}
#[test]
fn t_reporting_utils_getmessagereportingtoken_should_handle_incoming_messages() {
    let msg = with_secret(conversation("Test"), random_secret());
    let key = create_key().with_from_me(false);
    assert_eq!(get_message_reporting_token(&msg.encode(), &msg, &key).unwrap().unwrap().tag, "reporting");
}
