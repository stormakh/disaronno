//! Port of Utils/history.test.ts.
use baileys::auth::LidMapping;
use baileys::proto::history_sync::HistorySyncType;
use baileys::proto::past_participant::LeaveReason;
use baileys::proto::{Conversation, HistorySync, HistorySyncMsg, MessageKey, PastParticipant, PastParticipants, PhoneNumberToLIDMapping, UserReceipt, WebMessageInfo};
use baileys::utils::history::process_history_message;

fn mapping(lid: &str, pn: &str) -> LidMapping {
    LidMapping { lid: lid.to_string(), pn: pn.to_string() }
}
fn wire_mapping(lid: &str, pn: &str) -> PhoneNumberToLIDMapping {
    PhoneNumberToLIDMapping::new().with_lid_jid(lid).with_pn_jid(pn)
}
fn sync(t: HistorySyncType, conversations: Vec<Conversation>) -> HistorySync {
    HistorySync::new().with_sync_type(t).with_conversations(conversations)
}
fn bootstrap(conversations: Vec<Conversation>) -> HistorySync {
    sync(HistorySyncType::INITIAL_BOOTSTRAP, conversations)
}
fn receipt_msg(from_me: bool, user_jid: &str) -> HistorySyncMsg {
    let key = MessageKey::new().with_remote_jid("211071956705386@lid").with_from_me(from_me).with_id("3EB052FF8D9D00646C9994");
    HistorySyncMsg::new().with_message(WebMessageInfo::new().with_key(key).with_user_receipt(vec![UserReceipt::new().with_user_jid(user_jid)]))
}
fn past(user: &str, reason: i32, ts: u64) -> PastParticipant {
    PastParticipant::new().with_user_jid(user).with_leave_reason(LeaveReason(reason)).with_leave_ts(ts)
}

#[test]
fn t_processhistorymessage_phonenumbertolidmappings_extraction_should_extract_lid_pn_mappings_from_history_sync_payload() {
    let h = bootstrap(vec![]).with_phone_number_to_lid_mappings(vec![wire_mapping("11111111111111@lid", "1234567890123@s.whatsapp.net"), wire_mapping("22222222222222@lid", "9876543210987@s.whatsapp.net")]);
    let result = process_history_message(h, None).unwrap();
    assert_eq!(result.lid_pn_mappings, vec![mapping("11111111111111@lid", "1234567890123@s.whatsapp.net"), mapping("22222222222222@lid", "9876543210987@s.whatsapp.net")]);
}
#[test]
fn t_processhistorymessage_phonenumbertolidmappings_extraction_should_skip_mappings_with_missing_lidjid_or_pnjid() {
    let h = sync(HistorySyncType::RECENT, vec![]).with_phone_number_to_lid_mappings(vec![
        PhoneNumberToLIDMapping::new().with_pn_jid("1234567890123@s.whatsapp.net"),
        PhoneNumberToLIDMapping::new().with_lid_jid("11111111111111@lid"),
        wire_mapping("22222222222222@lid", "9876543210987@s.whatsapp.net"),
    ]);
    let result = process_history_message(h, None).unwrap();
    assert_eq!(result.lid_pn_mappings, vec![mapping("22222222222222@lid", "9876543210987@s.whatsapp.net")]);
}
#[test]
fn t_processhistorymessage_phonenumbertolidmappings_extraction_should_return_empty_array_when_no_mappings_exist() {
    let result = process_history_message(bootstrap(vec![]), None).unwrap();
    assert_eq!(result.lid_pn_mappings, vec![]);
}
#[test]
fn t_processhistorymessage_phonenumbertolidmappings_extraction_should_process_mappings_regardless_of_sync_type() {
    for sync_type in [HistorySyncType::PUSH_NAME, HistorySyncType::ON_DEMAND] {
        let h = sync(sync_type, vec![]).with_pushnames(vec![]).with_phone_number_to_lid_mappings(vec![wire_mapping("11111111111111@lid", "1234567890123@s.whatsapp.net")]);
        let result = process_history_message(h, None).unwrap();
        assert_eq!(result.lid_pn_mappings, vec![mapping("11111111111111@lid", "1234567890123@s.whatsapp.net")]);
    }
}
#[test]
fn t_processhistorymessage_conversations_processing_should_extract_contacts_with_lid_and_pn_from_conversations() {
    let chat = Conversation::new().with_id("1234567890123@s.whatsapp.net").with_name("Test User").with_lid_jid("11111111111111@lid").with_pn_jid("1234567890123@s.whatsapp.net");
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert_eq!(result.contacts.len(), 1);
    let c = &result.contacts[0];
    assert_eq!(c.id, "1234567890123@s.whatsapp.net");
    assert_eq!(c.name.as_deref(), Some("Test User"));
    assert_eq!(c.lid.as_deref(), Some("11111111111111@lid"));
    assert_eq!(c.phone_number.as_deref(), Some("1234567890123@s.whatsapp.net"));
    assert_eq!(c.username, None);
    assert_eq!(c.notify, None);
    assert_eq!(c.verified_name, None);
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_extract_mapping_when_chat_id_is_lid_and_pnjid_exists() {
    let chat = Conversation::new().with_id("11111111111111@lid").with_pn_jid("1234567890123@s.whatsapp.net");
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert!(result.lid_pn_mappings.contains(&mapping("11111111111111@lid", "1234567890123@s.whatsapp.net")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_extract_mapping_when_chat_id_is_pn_and_lidjid_exists() {
    let chat = Conversation::new().with_id("1234567890123@s.whatsapp.net").with_lid_jid("11111111111111@lid");
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert!(result.lid_pn_mappings.contains(&mapping("11111111111111@lid", "1234567890123@s.whatsapp.net")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_not_extract_mapping_for_group_chats() {
    let chat = Conversation::new().with_id("123456789012345678@g.us").with_lid_jid("11111111111111@lid").with_pn_jid("1234567890123@s.whatsapp.net");
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert_eq!(result.lid_pn_mappings, vec![]);
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_combine_mappings_from_phonenumbertolidmappings_and_conversations() {
    let chat = Conversation::new().with_id("22222222222222@lid").with_pn_jid("2222222222222@s.whatsapp.net");
    let h = bootstrap(vec![chat]).with_phone_number_to_lid_mappings(vec![wire_mapping("11111111111111@lid", "1111111111111@s.whatsapp.net")]);
    let result = process_history_message(h, None).unwrap();
    assert_eq!(result.lid_pn_mappings.len(), 2);
    assert!(result.lid_pn_mappings.contains(&mapping("11111111111111@lid", "1111111111111@s.whatsapp.net")));
    assert!(result.lid_pn_mappings.contains(&mapping("22222222222222@lid", "2222222222222@s.whatsapp.net")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_extract_mapping_for_hosted_lid_users() {
    let chat = Conversation::new().with_id("11111111111111@hosted.lid").with_pn_jid("1234567890123@hosted");
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert!(result.lid_pn_mappings.contains(&mapping("11111111111111@hosted.lid", "1234567890123@hosted")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_extract_mapping_for_hosted_pn_users() {
    let chat = Conversation::new().with_id("1234567890123@hosted").with_lid_jid("11111111111111@hosted.lid");
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert!(result.lid_pn_mappings.contains(&mapping("11111111111111@hosted.lid", "1234567890123@hosted")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_extract_mapping_from_userreceipt_when_pnjid_is_missing_and_chat_id_is_lid() {
    let key = MessageKey::new().with_remote_jid("211071956705386@lid").with_from_me(true).with_id("3EB052FF8D9D00646C9994");
    let receipt = UserReceipt::new().with_user_jid("5518999991234@s.whatsapp.net").with_receipt_timestamp(1768320045i64).with_read_timestamp(1768327083i64);
    let msg = WebMessageInfo::new().with_key(key).with_message_timestamp(1768320044u64).with_user_receipt(vec![receipt]);
    let chat = Conversation::new().with_id("211071956705386@lid").with_messages(vec![HistorySyncMsg::new().with_message(msg)]);
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    assert!(result.lid_pn_mappings.contains(&mapping("211071956705386@lid", "5518999991234@s.whatsapp.net")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_not_extract_mapping_from_userreceipt_when_pnjid_already_exists() {
    let chat = Conversation::new().with_id("211071956705386@lid").with_pn_jid("5518888881234@s.whatsapp.net").with_messages(vec![receipt_msg(true, "5518999991234@s.whatsapp.net")]);
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    // Should use pnJid, not userReceipt
    assert!(result.lid_pn_mappings.contains(&mapping("211071956705386@lid", "5518888881234@s.whatsapp.net")));
    // Should NOT contain the userReceipt PN
    assert!(!result.lid_pn_mappings.contains(&mapping("211071956705386@lid", "5518999991234@s.whatsapp.net")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_not_extract_mapping_from_userreceipt_when_fromme_is_false() {
    let chat = Conversation::new().with_id("211071956705386@lid").with_messages(vec![receipt_msg(false, "5518999991234@s.whatsapp.net")]);
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    // Should not extract mapping when fromMe is false
    assert!(!result.lid_pn_mappings.contains(&mapping("211071956705386@lid", "5518999991234@s.whatsapp.net")));
}
#[test]
fn t_processhistorymessage_lid_pn_mapping_extraction_from_conversations_should_not_extract_mapping_from_userreceipt_when_userjid_is_also_a_lid() {
    let chat = Conversation::new().with_id("211071956705386@lid").with_messages(vec![receipt_msg(true, "152230971891797@lid")]);
    let result = process_history_message(bootstrap(vec![chat]), None).unwrap();
    // Should not create a LID->LID mapping
    assert_eq!(result.lid_pn_mappings.len(), 0);
}
#[test]
fn t_processhistorymessage_pastparticipants_extraction_should_pass_through_pastparticipants_from_history_sync_payload() {
    let past_participants = vec![PastParticipants::new().with_group_jid("123456789012345678@g.us").with_past_participants(vec![past("1234567890123@s.whatsapp.net", 1, 1700000000), past("9876543210987@s.whatsapp.net", 2, 1700000001)])];
    let h = bootstrap(vec![]).with_past_participants(past_participants.clone());
    let result = process_history_message(h, None).unwrap();
    assert_eq!(result.past_participants, Some(past_participants));
}
#[test]
fn t_processhistorymessage_pastparticipants_extraction_should_return_undefined_pastparticipants_when_not_present_in_payload() {
    let result = process_history_message(bootstrap(vec![]), None).unwrap();
    assert_eq!(result.past_participants, None);
}
#[test]
fn t_processhistorymessage_pastparticipants_extraction_should_pass_through_empty_pastparticipants_array() {
    let h = bootstrap(vec![]).with_past_participants(Vec::<PastParticipants>::new());
    let result = process_history_message(h, None).unwrap();
    assert_eq!(result.past_participants, Some(vec![]));
}
#[test]
fn t_processhistorymessage_pastparticipants_extraction_should_pass_through_pastparticipants_with_multiple_groups() {
    let past_participants = vec![
        PastParticipants::new().with_group_jid("111111111111111111@g.us").with_past_participants(vec![past("1111111111111@s.whatsapp.net", 1, 1700000000)]),
        PastParticipants::new().with_group_jid("222222222222222222@g.us").with_past_participants(vec![past("2222222222222@s.whatsapp.net", 2, 1700000001)]),
    ];
    let h = sync(HistorySyncType::RECENT, vec![]).with_past_participants(past_participants.clone());
    let result = process_history_message(h, None).unwrap();
    assert_eq!(result.past_participants, Some(past_participants));
}
