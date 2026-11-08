//! Port of Signal/Group/sender-key-state-regression.test.ts.
use baileys::signal::group::{SenderMessageKey, state_from_json};
use waproto::pb::Json;

#[test]
fn t_senderkeystate_regression_missing_sendermessagekeys_array_should_initialize_sendermessagekeys_when_absent_in_provided_structure() {
    // adapted: the structure comes in as JSON, because the Rust state has no missing array
    let legacy_structure = Json::parse(
        r#"{"senderKeyId":42,"senderChainKey":{"iteration":0,"seed":{"type":"Buffer","data":[1,2,3]}},"senderSigningKey":{"public":{"type":"Buffer","data":[4,5,6]}}}"#,
    )
    .unwrap();
    let mut state = state_from_json(&legacy_structure).unwrap();
    let msg_key = SenderMessageKey::new(0, vec![7, 8, 9]);
    state.add_sender_message_key(&msg_key);
    assert_eq!(state.sender_message_keys.len(), 1);
    assert_eq!(state.sender_message_keys[0].iteration, 0);
}
