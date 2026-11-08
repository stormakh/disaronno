//! Port of src/__tests__/Utils/stanza-ack.test.ts.
use baileys::utils::stanza_ack::build_ack_stanza;
use baileys::wabinary::{Attrs, BinaryNode};

fn node<const N: usize>(tag: &str, attrs: [(&str, &str); N]) -> BinaryNode {
    BinaryNode::tag(tag, Attrs::from(attrs))
}

#[test]
fn t_buildackstanza_basic_stanza_construction_should_build_a_minimal_ack_stanza_from_a_message_node() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    let ack = build_ack_stanza(&n, None, None);
    assert_eq!(ack, node("ack", [("id", "msg-001"), ("to", "user@s.whatsapp.net"), ("class", "message")]));
}
#[test]
fn t_buildackstanza_basic_stanza_construction_should_build_ack_for_receipt_node() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("class"), Some("receipt"));
}
#[test]
fn t_buildackstanza_basic_stanza_construction_should_build_ack_for_notification_node() {
    let n = node("notification", [("id", "notif-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("class"), Some("notification"));
}
#[test]
fn t_buildackstanza_basic_stanza_construction_should_build_ack_for_call_node() {
    let n = node("call", [("id", "call-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("class"), Some("call"));
}

#[test]
fn t_buildackstanza_error_codes_nack_should_include_error_attribute_when_errorcode_is_provided_and_non_zero() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, Some(500), None).attr("error"), Some("500"));
}
#[test]
fn t_buildackstanza_error_codes_nack_should_include_error_for_all_known_nack_codes() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    for code in [487u32, 488, 491, 495, 496, 500, 552] {
        let ack = build_ack_stanza(&n, Some(code), None);
        assert_eq!(ack.attr("error"), Some(code.to_string().as_str()));
    }
}
#[test]
fn t_buildackstanza_error_codes_nack_should_not_include_error_when_errorcode_is_0() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, Some(0), None).attr("error"), None);
}
#[test]
fn t_buildackstanza_error_codes_nack_should_not_include_error_when_errorcode_is_undefined() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("error"), None);
}

#[test]
fn t_buildackstanza_participant_and_recipient_forwarding_should_include_participant_when_present_in_source_node() {
    let n = node("message", [("id", "msg-001"), ("from", "group@g.us"), ("participant", "sender@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("participant"), Some("sender@s.whatsapp.net"));
}
#[test]
fn t_buildackstanza_participant_and_recipient_forwarding_should_not_include_participant_when_absent() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("participant"), None);
}
#[test]
fn t_buildackstanza_participant_and_recipient_forwarding_should_include_recipient_when_present() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "user@s.whatsapp.net"), ("recipient", "me@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("recipient"), Some("me@s.whatsapp.net"));
}
#[test]
fn t_buildackstanza_participant_and_recipient_forwarding_should_not_include_recipient_when_absent() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("recipient"), None);
}
#[test]
fn t_buildackstanza_participant_and_recipient_forwarding_should_forward_both_participant_and_recipient_when_both_present() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "group@g.us"), ("participant", "sender@s.whatsapp.net"), ("recipient", "me@s.whatsapp.net")]);
    let ack = build_ack_stanza(&n, None, None);
    assert_eq!(ack.attr("participant"), Some("sender@s.whatsapp.net"));
    assert_eq!(ack.attr("recipient"), Some("me@s.whatsapp.net"));
}

#[test]
fn t_buildackstanza_type_attribute_handling_wa_web_n_type_drop_attr_should_include_type_for_non_message_tags() {
    let n = node("notification", [("id", "notif-001"), ("from", "user@s.whatsapp.net"), ("type", "encrypt")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("type"), Some("encrypt"));
}
#[test]
fn t_buildackstanza_type_attribute_handling_wa_web_n_type_drop_attr_should_always_include_type_for_message_tag_when_present() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net"), ("type", "text")]);
    // type is always included when present, regardless of errorCode
    assert_eq!(build_ack_stanza(&n, Some(0), None).attr("type"), Some("text"));
}
#[test]
fn t_buildackstanza_type_attribute_handling_wa_web_n_type_drop_attr_should_include_type_for_message_nack() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net"), ("type", "text")]);
    assert_eq!(build_ack_stanza(&n, Some(500), None).attr("type"), Some("text"));
}
#[test]
fn t_buildackstanza_type_attribute_handling_wa_web_n_type_drop_attr_should_not_include_type_when_source_node_has_no_type() {
    let n = node("notification", [("id", "notif-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("type"), None);
}
#[test]
fn t_buildackstanza_type_attribute_handling_wa_web_n_type_drop_attr_should_include_type_for_receipt_tag() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "user@s.whatsapp.net"), ("type", "read")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("type"), Some("read"));
}

#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_set_from_meid_for_message_ack_when_meid_provided() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, Some("me@s.whatsapp.net")).attr("from"), Some("me@s.whatsapp.net"));
}
#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_set_from_meid_for_message_nack_when_meid_provided() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, Some(500), Some("me@s.whatsapp.net")).attr("from"), Some("me@s.whatsapp.net"));
}
#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_set_from_meid_for_unavailable_message_with_meid() {
    let n = BinaryNode::with_nodes("message", Attrs::from([("id", "msg-001"), ("from", "user@s.whatsapp.net"), ("type", "text")]), vec![BinaryNode::tag("unavailable", Attrs::new())]);
    assert_eq!(build_ack_stanza(&n, Some(0), Some("me@s.whatsapp.net")).attr("from"), Some("me@s.whatsapp.net"));
}
#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_not_set_from_for_message_ack_without_meid() {
    let n = node("message", [("id", "msg-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, None).attr("from"), None);
}
#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_not_set_from_for_non_message_tags_even_with_meid() {
    let n = node("notification", [("id", "notif-001"), ("from", "user@s.whatsapp.net"), ("type", "encrypt")]);
    assert_eq!(build_ack_stanza(&n, Some(0), Some("me@s.whatsapp.net")).attr("from"), None);
}
#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_not_set_from_for_receipt_tag_even_with_meid() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, Some("me@s.whatsapp.net")).attr("from"), None);
}
#[test]
fn t_buildackstanza_from_field_for_message_acks_wa_web_sendack_sendnack_always_include_from_should_not_set_from_for_call_tag_even_with_meid() {
    let n = node("call", [("id", "call-001"), ("from", "user@s.whatsapp.net")]);
    assert_eq!(build_ack_stanza(&n, None, Some("me@s.whatsapp.net")).attr("from"), None);
}

#[test]
fn t_buildackstanza_full_stanza_construction_combined_attributes_should_handle_group_message_nack_with_all_attributes() {
    let n = node("message", [("id", "msg-001"), ("from", "group@g.us"), ("participant", "sender@s.whatsapp.net"), ("type", "text")]);
    let ack = build_ack_stanza(&n, Some(500), Some("me@s.whatsapp.net"));
    assert_eq!(ack, node("ack", [("id", "msg-001"), ("to", "group@g.us"), ("class", "message"), ("error", "500"), ("participant", "sender@s.whatsapp.net"), ("type", "text"), ("from", "me@s.whatsapp.net")]));
}
#[test]
fn t_buildackstanza_full_stanza_construction_combined_attributes_should_handle_group_message_ack_no_error_with_from() {
    let n = node("message", [("id", "msg-001"), ("from", "group@g.us"), ("participant", "sender@s.whatsapp.net"), ("type", "text")]);
    let ack = build_ack_stanza(&n, None, Some("me@s.whatsapp.net"));
    assert_eq!(ack, node("ack", [("id", "msg-001"), ("to", "group@g.us"), ("class", "message"), ("participant", "sender@s.whatsapp.net"), ("type", "text"), ("from", "me@s.whatsapp.net")]));
}
#[test]
fn t_buildackstanza_full_stanza_construction_combined_attributes_should_handle_receipt_with_participant_and_recipient_no_from() {
    let n = node("receipt", [("id", "rcpt-001"), ("from", "group@g.us"), ("participant", "sender@s.whatsapp.net"), ("recipient", "me@s.whatsapp.net"), ("type", "read")]);
    let ack = build_ack_stanza(&n, None, None);
    assert_eq!(ack, node("ack", [("id", "rcpt-001"), ("to", "group@g.us"), ("class", "receipt"), ("participant", "sender@s.whatsapp.net"), ("recipient", "me@s.whatsapp.net"), ("type", "read")]));
}
