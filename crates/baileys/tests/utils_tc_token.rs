//! Port of Utils/tc-token.test.ts.
use baileys::auth::{KeyKind, KeyMap, KeyValue, KeyWrite, SignalKeyStore, TcTokenEntry};
use baileys::error::{Boom, Result};
use baileys::proto::pb::{Bytes, Json};
use baileys::utils::decode_wa_message::server_error_codes;
use baileys::utils::tc_token_utils::*;
use baileys::utils::time::now_ms;
use baileys::wabinary::{Attrs, BinaryNode, Content, PSA_WID, is_jid_bot, is_jid_meta_ai};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Mutex;

const BUCKET_DURATION: i64 = 604800;
const NUM_BUCKETS: i64 = 4;

fn now_seconds() -> i64 {
    now_ms().div_euclid(1000)
}
fn compute_cutoff() -> i64 {
    let current_bucket = now_seconds().div_euclid(BUCKET_DURATION);
    (current_bucket - (NUM_BUCKETS - 1)) * BUCKET_DURATION
}
fn expired(ts: i64) -> bool {
    is_tc_token_expired(Some(ts as f64))
}
fn should_send(ts: i64) -> bool {
    should_send_new_tc_token(Some(ts as f64))
}
/// The jest mock of the key store: `mockResolvedValue`, `mockResolvedValueOnce` and the calls of `set`.
#[derive(Default)]
struct MockKeys {
    get_once: Mutex<VecDeque<Result<KeyMap>>>,
    get_value: Mutex<KeyMap>,
    sets: Mutex<Vec<Vec<KeyWrite>>>,
}
impl SignalKeyStore for MockKeys {
    fn get(&self, _kind: KeyKind, _ids: &[String]) -> Result<KeyMap> {
        match self.get_once.lock().unwrap().pop_front() {
            Some(r) => r,
            None => Ok(self.get_value.lock().unwrap().clone()),
        }
    }
    fn set(&self, data: Vec<KeyWrite>) -> Result<()> {
        self.sets.lock().unwrap().push(data);
        Ok(())
    }
}
impl MockKeys {
    fn with(entries: &[(&str, TcTokenEntry)]) -> MockKeys {
        let m = MockKeys::default();
        *m.get_value.lock().unwrap() = map(entries);
        m
    }
    fn once(&self, entries: &[(&str, TcTokenEntry)]) {
        self.get_once.lock().unwrap().push_back(Ok(map(entries)));
    }
    fn reject_once(&self) {
        self.get_once.lock().unwrap().push_back(Err(Boom::new("database error")));
    }
    fn calls(&self) -> Vec<Vec<KeyWrite>> {
        self.sets.lock().unwrap().clone()
    }
    fn called_with_delete(&self, jid: &str) -> bool {
        self.calls().contains(&vec![(KeyKind::TcToken, jid.to_string(), None)])
    }
}
fn map(entries: &[(&str, TcTokenEntry)]) -> KeyMap {
    let mut m = KeyMap::default();
    for (k, v) in entries {
        m.insert(k.to_string(), KeyValue::TcToken(v.clone()));
    }
    m
}
fn entry(token: &[u8], ts: Option<&str>, sender: Option<i64>) -> TcTokenEntry {
    TcTokenEntry { token: Bytes::copy_from(token), timestamp: ts.map(str::to_string), sender_timestamp: sender.map(|s| s as f64) }
}
fn no_lid(_pn: &str) -> Result<Option<String>> {
    Ok(None)
}
fn write_for<'a>(call: &'a [KeyWrite], jid: &str) -> Option<&'a Option<KeyValue>> {
    call.iter().find(|(k, id, _)| *k == KeyKind::TcToken && id == jid).map(|(_, _, v)| v)
}
fn token_of(v: &Option<KeyValue>) -> Vec<u8> {
    match v {
        Some(KeyValue::TcToken(e)) => e.token.to_vec(),
        other => panic!("not a token: {other:?}"),
    }
}

const CONTACT_JID: &str = "contact@s.whatsapp.net";
const MY_DEVICE_JID: &str = "me@s.whatsapp.net";
const CONTACT_LID: &str = "contact@lid";
const TOKEN_BYTES: [u8; 5] = [4, 1, 33, 254, 110];
fn recent_ts() -> String {
    (now_seconds() - 86400).to_string()
}
fn make_notification_node(token_jid: Option<&str>, token_content: &[u8], timestamp: Option<&str>) -> BinaryNode {
    let mut attrs = Attrs::from([("type", "trusted_contact")]);
    if let Some(j) = token_jid {
        attrs.set("jid", j);
    }
    if let Some(t) = timestamp {
        attrs.set("t", t);
    }
    BinaryNode::with_nodes(
        "notification",
        Attrs::from([("from", CONTACT_JID), ("type", "privacy_token")]),
        vec![BinaryNode::with_nodes("tokens", Attrs::new(), vec![BinaryNode::with_bytes("token", attrs, token_content)])],
    )
}
fn skips_for(fallback_jid: &str) {
    let keys = MockKeys::default();
    let node = make_notification_node(Some(MY_DEVICE_JID), &TOKEN_BYTES, Some(&recent_ts()));
    store_tc_tokens_from_iq_result(&node, fallback_jid, &keys, &no_lid, None).unwrap();
    assert!(keys.calls().is_empty());
}

#[test]
fn t_storetctokensfromiqresult_stores_token_under_fallbackjid_even_when_token_node_has_a_different_jid_attr() {
    let keys = MockKeys::default();
    let node = make_notification_node(Some(MY_DEVICE_JID), &TOKEN_BYTES, Some(&recent_ts()));
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &no_lid, None).unwrap();
    let calls = keys.calls();
    assert_eq!(calls.len(), 1);
    assert!(write_for(&calls[0], CONTACT_JID).is_some());
    assert!(write_for(&calls[0], MY_DEVICE_JID).is_none());
    assert_eq!(token_of(write_for(&calls[0], CONTACT_JID).unwrap()), TOKEN_BYTES);
}
#[test]
fn t_storetctokensfromiqresult_multiple_notifications_from_different_contacts_do_not_overwrite_each_other() {
    let keys = MockKeys::default();
    let (contact_a, contact_b) = ("alice@s.whatsapp.net", "bob@s.whatsapp.net");
    let node_a = make_notification_node(Some(MY_DEVICE_JID), &[1, 2, 3], Some(&recent_ts()));
    let node_b = make_notification_node(Some(MY_DEVICE_JID), &[4, 5, 6], Some(&recent_ts()));
    store_tc_tokens_from_iq_result(&node_a, contact_a, &keys, &no_lid, None).unwrap();
    store_tc_tokens_from_iq_result(&node_b, contact_b, &keys, &no_lid, None).unwrap();
    let calls = keys.calls();
    assert_eq!(calls.len(), 2);
    assert!(write_for(&calls[0], contact_a).is_some());
    assert!(write_for(&calls[1], contact_b).is_some());
    assert!(write_for(&calls[0], MY_DEVICE_JID).is_none());
    assert!(write_for(&calls[1], MY_DEVICE_JID).is_none());
}
#[test]
fn t_storetctokensfromiqresult_uses_fallbackjid_when_token_node_has_no_jid_attr() {
    let keys = MockKeys::default();
    let node = make_notification_node(None, &TOKEN_BYTES, Some(&recent_ts()));
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &no_lid, None).unwrap();
    let calls = keys.calls();
    assert_eq!(calls.len(), 1);
    assert!(write_for(&calls[0], CONTACT_JID).is_some());
}
#[test]
fn t_storetctokensfromiqresult_resolves_fallbackjid_to_lid_via_getlidforpn() {
    let keys = MockKeys::default();
    let node = make_notification_node(Some(MY_DEVICE_JID), &TOKEN_BYTES, Some(&recent_ts()));
    let get_lid = |_: &str| -> Result<Option<String>> { Ok(Some(CONTACT_LID.to_string())) };
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &get_lid, None).unwrap();
    let calls = keys.calls();
    assert_eq!(calls.len(), 1);
    assert!(write_for(&calls[0], CONTACT_LID).is_some());
    assert!(write_for(&calls[0], CONTACT_JID).is_none());
    assert!(write_for(&calls[0], MY_DEVICE_JID).is_none());
}
#[test]
fn t_storetctokensfromiqresult_calls_onnewjidstored_with_the_resolved_storage_jid() {
    let keys = MockKeys::default();
    let node = make_notification_node(Some(MY_DEVICE_JID), &TOKEN_BYTES, Some(&recent_ts()));
    let stored = RefCell::new(Vec::new());
    let on_new = |jid: &str| stored.borrow_mut().push(jid.to_string());
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &no_lid, Some(&on_new)).unwrap();
    assert_eq!(*stored.borrow(), vec![CONTACT_JID.to_string()]);
}
#[test]
fn t_storetctokensfromiqresult_skips_storage_for_non_regular_user_psa() {
    skips_for("0@c.us");
}
#[test]
fn t_storetctokensfromiqresult_skips_storage_for_non_regular_user_bot() {
    skips_for("13135550001@c.us");
}
#[test]
fn t_storetctokensfromiqresult_skips_storage_for_non_regular_user_metaai() {
    skips_for("13135550002@bot");
}
#[test]
fn t_storetctokensfromiqresult_skips_storage_for_non_regular_user_group() {
    skips_for("abc-def@g.us");
}
#[test]
fn t_storetctokensfromiqresult_skips_token_nodes_with_non_trusted_contact_type() {
    let keys = MockKeys::default();
    let token = BinaryNode::with_bytes("token", Attrs::from([("type", "some_other_type"), ("jid", MY_DEVICE_JID)]), &TOKEN_BYTES[..]);
    let node = BinaryNode::with_nodes("notification", Attrs::from([("from", CONTACT_JID)]), vec![BinaryNode::with_nodes("tokens", Attrs::new(), vec![token])]);
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &no_lid, None).unwrap();
    assert!(keys.calls().is_empty());
}
#[test]
fn t_storetctokensfromiqresult_respects_timestamp_monotonicity_guard() {
    let older_ts = (now_seconds() - 2 * 86400).to_string();
    let newer_ts = (now_seconds() - 86400).to_string();
    let keys = MockKeys::with(&[(CONTACT_JID, entry(&[9, 9, 9], Some(&newer_ts), None))]);
    let node = make_notification_node(Some(MY_DEVICE_JID), &TOKEN_BYTES, Some(&older_ts));
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &no_lid, None).unwrap();
    assert!(keys.calls().is_empty());
}
#[test]
fn t_storetctokensfromiqresult_does_not_overwrite_timestamped_entry_with_timestamp_less_token() {
    let existing_ts = (now_seconds() - 86400).to_string();
    let keys = MockKeys::with(&[(CONTACT_JID, entry(&[9, 9, 9], Some(&existing_ts), None))]);
    // Incoming token has no timestamp
    let node = make_notification_node(Some(MY_DEVICE_JID), &TOKEN_BYTES, None);
    store_tc_tokens_from_iq_result(&node, CONTACT_JID, &keys, &no_lid, None).unwrap();
    assert!(keys.calls().is_empty());
}

#[test]
fn t_istctokenexpired_returns_true_for_undefined() {
    assert!(is_tc_token_expired(None));
}
#[test]
fn t_istctokenexpired_returns_true_for_null() {
    // adapted: `None` stands for both null and undefined
    assert!(is_tc_token_expired_str(None));
}
#[test]
fn t_istctokenexpired_returns_true_for_nan_string() {
    assert!(is_tc_token_expired_str(Some("not-a-number")));
}
#[test]
fn t_istctokenexpired_returns_true_for_empty_string() {
    assert!(is_tc_token_expired_str(Some("")));
}
#[test]
fn t_istctokenexpired_returns_true_for_timestamp_0() {
    assert!(expired(0));
}
#[test]
fn t_istctokenexpired_returns_false_for_recent_token_1_day_ago() {
    assert!(!expired(now_seconds() - 86400));
}
#[test]
fn t_istctokenexpired_returns_false_for_token_20_days_ago_within_28_day_window() {
    assert!(!expired(now_seconds() - 20 * 86400));
}
#[test]
fn t_istctokenexpired_returns_true_for_expired_token_30_days_ago() {
    assert!(expired(now_seconds() - 30 * 86400));
}
#[test]
fn t_istctokenexpired_handles_string_timestamp_recent() {
    assert!(!is_tc_token_expired_str(Some(&(now_seconds() - 86400).to_string())));
}
#[test]
fn t_istctokenexpired_handles_string_timestamp_expired() {
    assert!(is_tc_token_expired_str(Some(&(now_seconds() - 30 * 86400).to_string())));
}
#[test]
fn t_istctokenexpired_boundary_token_exactly_at_cutoff_is_not_expired() {
    assert!(!expired(compute_cutoff()));
}
#[test]
fn t_istctokenexpired_boundary_token_one_second_before_cutoff_is_expired() {
    assert!(expired(compute_cutoff() - 1));
}
#[test]
fn t_istctokenexpired_returns_true_for_very_old_timestamp_epoch() {
    assert!(expired(1));
}
#[test]
fn t_istctokenexpired_returns_false_for_token_issued_just_now() {
    assert!(!expired(now_seconds()));
}
#[test]
fn t_istctokenexpired_verifies_bucket_math_cutoff_currentbucket_3_bucketduration() {
    let cutoff = compute_cutoff();
    // Token at exactly cutoff is NOT expired (uses < not <=)
    assert!(!expired(cutoff));
    // Token one second before cutoff IS expired
    assert!(expired(cutoff - 1));
    // Token well past cutoff (e.g. 1 day ago) is valid
    assert!(!expired(now_seconds() - 86400));
    // Token well before cutoff (e.g. 35 days ago) is expired
    assert!(expired(now_seconds() - 35 * 86400));
}

#[test]
fn t_shouldsendnewtctoken_returns_true_for_undefined() {
    assert!(should_send_new_tc_token(None));
}
#[test]
fn t_shouldsendnewtctoken_returns_false_for_timestamp_in_current_bucket() {
    assert!(!should_send(now_seconds() - 100));
}
#[test]
fn t_shouldsendnewtctoken_returns_true_for_timestamp_in_previous_bucket() {
    assert!(should_send(now_seconds() - BUCKET_DURATION - 1));
}
#[test]
fn t_shouldsendnewtctoken_returns_false_for_timestamp_at_start_of_current_bucket() {
    let bucket_start = now_seconds().div_euclid(BUCKET_DURATION) * BUCKET_DURATION;
    assert!(!should_send(bucket_start));
}
#[test]
fn t_shouldsendnewtctoken_returns_true_for_timestamp_at_end_of_previous_bucket() {
    let bucket_start = now_seconds().div_euclid(BUCKET_DURATION) * BUCKET_DURATION;
    assert!(should_send(bucket_start - 1));
}
#[test]
fn t_shouldsendnewtctoken_returns_true_for_very_old_timestamp() {
    assert!(should_send(1000000));
}
#[test]
fn t_shouldsendnewtctoken_returns_false_for_timestamp_equal_to_now() {
    assert!(!should_send(now_seconds()));
}

const TEST_JID: &str = "user@s.whatsapp.net";
const VALID_TOKEN: [u8; 5] = [4, 1, 33, 254, 110];
fn expired_ts() -> String {
    (now_seconds() - 30 * 86400).to_string()
}
fn picture_node() -> BinaryNode {
    BinaryNode::tag("picture", Attrs::from([("type", "image")]))
}
fn assert_tctoken(node: &BinaryNode, ts: &str, token: &[u8]) {
    assert_eq!(node.tag, "tctoken");
    assert_eq!(node.attrs, Attrs::from([("t", ts)]));
    assert_eq!(node.content, Some(Content::Binary(Bytes::copy_from(token))));
}
#[test]
fn t_buildtctokenfromjid_returns_tctoken_node_for_valid_non_expired_token() {
    let ts = recent_ts();
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, Some(&ts), None))]);
    let result = build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid).unwrap();
    assert_eq!(result.len(), 1);
    // adapted: `toBe` compares the same Buffer object. Here the bytes must be equal.
    assert_tctoken(&result[0], &ts, &VALID_TOKEN);
}
#[test]
fn t_buildtctokenfromjid_returns_undefined_when_no_token_exists() {
    let keys = MockKeys::default();
    assert_eq!(build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid), None);
}
#[test]
fn t_buildtctokenfromjid_returns_undefined_for_expired_token() {
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, Some(&expired_ts()), None))]);
    assert_eq!(build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid), None);
}
#[test]
fn t_buildtctokenfromjid_deletes_expired_token_from_store_phase_5_opportunistic_cleanup() {
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, Some(&expired_ts()), None))]);
    build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid);
    assert!(keys.called_with_delete(TEST_JID));
}
#[test]
fn t_buildtctokenfromjid_preserves_sendertimestamp_when_clearing_an_expired_peer_token() {
    let sender_ts = now_seconds() - 100;
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, Some(&expired_ts()), Some(sender_ts)))]);
    build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid);
    let expected = vec![(KeyKind::TcToken, TEST_JID.to_string(), Some(KeyValue::TcToken(entry(&[], None, Some(sender_ts)))))];
    assert!(keys.calls().contains(&expected));
}
#[test]
fn t_buildtctokenfromjid_does_not_delete_when_token_is_simply_missing() {
    let keys = MockKeys::default();
    build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid);
    assert!(keys.calls().is_empty());
}
#[test]
fn t_buildtctokenfromjid_preserves_basecontent_when_no_token() {
    let keys = MockKeys::default();
    let result = build_tc_token_from_jid(TEST_JID, vec![picture_node()], &keys, &no_lid);
    assert_eq!(result, Some(vec![picture_node()]));
}
#[test]
fn t_buildtctokenfromjid_appends_tctoken_to_existing_basecontent() {
    let ts = recent_ts();
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, Some(&ts), None))]);
    let result = build_tc_token_from_jid(TEST_JID, vec![picture_node()], &keys, &no_lid).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], picture_node());
    assert_tctoken(&result[1], &ts, &VALID_TOKEN);
}
#[test]
fn t_buildtctokenfromjid_handles_key_store_errors_gracefully() {
    let keys = MockKeys::default();
    keys.reject_once();
    assert_eq!(build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid), None);
}
#[test]
fn t_buildtctokenfromjid_handles_key_store_errors_with_basecontent_fallback() {
    let keys = MockKeys::default();
    keys.reject_once();
    assert_eq!(build_tc_token_from_jid(TEST_JID, vec![picture_node()], &keys, &no_lid), Some(vec![picture_node()]));
}
#[test]
fn t_buildtctokenfromjid_returns_undefined_when_token_has_no_timestamp_treated_as_expired() {
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, None, None))]);
    assert_eq!(build_tc_token_from_jid(TEST_JID, vec![], &keys, &no_lid), None);
}
#[test]
fn t_buildtctokenfromjid_does_not_append_tctoken_to_basecontent_when_token_has_no_timestamp() {
    let keys = MockKeys::with(&[(TEST_JID, entry(&VALID_TOKEN, None, None))]);
    assert_eq!(build_tc_token_from_jid(TEST_JID, vec![picture_node()], &keys, &no_lid), Some(vec![picture_node()]));
    assert!(keys.called_with_delete(TEST_JID));
}

#[test]
fn t_server_error_codes_messageaccountrestriction_is_463() {
    assert_eq!(server_error_codes::MESSAGE_ACCOUNT_RESTRICTION, "463");
}
#[test]
fn t_server_error_codes_smaxinvalid_is_479() {
    assert_eq!(server_error_codes::SMAX_INVALID, "479");
}

const JID_A: &str = "alice@s.whatsapp.net";
const JID_B: &str = "bob@s.whatsapp.net";
const JID_C: &str = "charlie@s.whatsapp.net";
const TOKEN_A: [u8; 6] = [4, 1, 33, 254, 110, 59];
const TOKEN_B: [u8; 6] = [4, 2, 44, 128, 200, 12];

#[test]
fn t_tctoken_integration_scenarios_phase_1_token_fetch_and_store_flow_token_missing_fetch_stores_new_token_subsequent_read_finds_it() {
    let keys = MockKeys::default();
    let recent = now_seconds().to_string();
    // First read: no token
    keys.once(&[]);
    assert_eq!(build_tc_token_from_jid(JID_A, vec![], &keys, &no_lid), None);
    // Simulate: after fetch, token is stored
    let stored = entry(&TOKEN_A, Some(&recent), None);
    let write = vec![(KeyKind::TcToken, JID_A.to_string(), Some(KeyValue::TcToken(stored.clone())))];
    keys.set(write.clone()).unwrap();
    assert!(keys.calls().contains(&write));
    // Second read: token found
    keys.once(&[(JID_A, stored)]);
    let result = build_tc_token_from_jid(JID_A, vec![], &keys, &no_lid).unwrap();
    assert_tctoken(&result[0], &recent, &TOKEN_A);
}
#[test]
fn t_tctoken_integration_scenarios_phase_2_expired_token_triggers_re_fetch_expired_token_is_detected_and_deleted_then_re_fetch_stores_fresh_token() {
    let keys = MockKeys::default();
    let (expired_at, fresh) = (expired_ts(), now_seconds().to_string());
    // Read expired token: returns undefined, triggers cleanup
    keys.once(&[(JID_A, entry(&TOKEN_A, Some(&expired_at), None))]);
    assert_eq!(build_tc_token_from_jid(JID_A, vec![], &keys, &no_lid), None);
    assert!(is_tc_token_expired_str(Some(&expired_at)));
    // Verify expired entry deleted
    assert!(keys.called_with_delete(JID_A));
    // After re-fetch, fresh token stored and readable
    keys.once(&[(JID_A, entry(&TOKEN_B, Some(&fresh), None))]);
    let result = build_tc_token_from_jid(JID_A, vec![], &keys, &no_lid).unwrap();
    assert_tctoken(&result[0], &fresh, &TOKEN_B);
}
#[test]
fn t_tctoken_integration_scenarios_phase_2_shouldsendnewtctoken_gates_fire_and_forget_recent_sendertimestamp_prevents_re_issuance() {
    assert!(!should_send(now_seconds() - 100));
}
#[test]
fn t_tctoken_integration_scenarios_phase_2_shouldsendnewtctoken_gates_fire_and_forget_old_sendertimestamp_triggers_re_issuance() {
    assert!(should_send(now_seconds() - BUCKET_DURATION - 1));
}
#[test]
fn t_tctoken_integration_scenarios_phase_2_shouldsendnewtctoken_gates_fire_and_forget_sendertimestamp_update_prevents_next_issuance_in_same_bucket() {
    // Before update: should issue
    assert!(should_send_new_tc_token(None));
    // After update with current timestamp
    assert!(!should_send(now_seconds()));
}
#[test]
fn t_tctoken_integration_scenarios_sendertimestamp_preservation_on_token_update_simulates_notification_handler_preserving_sendertimestamp_via_spread() {
    // adapted: the object spread of upstream is struct update syntax here
    let existing = entry(&TOKEN_A, Some("1770912853"), Some(1770912855));
    let new_token = Bytes::copy_from(&[4, 1, 33, 99, 88]);
    let merged = TcTokenEntry { token: new_token.clone(), timestamp: Some("1770920492".to_string()), ..existing };
    assert_eq!(merged.token, new_token);
    assert_eq!(merged.timestamp.as_deref(), Some("1770920492"));
    assert_eq!(merged.sender_timestamp, Some(1770912855.0));
}
#[test]
fn t_tctoken_integration_scenarios_sendertimestamp_preservation_on_token_update_spread_with_undefined_existing_does_not_crash() {
    // adapted: an unknown JID gives no entry, so the update starts from an empty one
    let existing: Option<TcTokenEntry> = None;
    let new_token = Bytes::copy_from(&[4, 1, 33, 99, 88]);
    let merged = TcTokenEntry { token: new_token.clone(), timestamp: Some("1770920492".to_string()), ..existing.unwrap_or_default() };
    assert_eq!(merged.token, new_token);
    assert_eq!(merged.timestamp.as_deref(), Some("1770920492"));
    assert_eq!(merged.sender_timestamp, None);
}
fn sender_ts_from(keys: &MockKeys) -> Option<f64> {
    match keys.get(KeyKind::TcToken, &[JID_A.to_string()]).unwrap().remove(JID_A) {
        Some(KeyValue::TcToken(e)) => e.sender_timestamp,
        _ => None,
    }
}
#[test]
fn t_tctoken_integration_scenarios_phase_4_identity_change_re_issuance_decision_re_issues_when_sendertimestamp_is_recent_within_28_day_window() {
    let recent_sender_ts = now_seconds() - 5 * 86400; // 5 days ago
    let keys = MockKeys::with(&[(JID_A, entry(&TOKEN_A, Some(&recent_sender_ts.to_string()), Some(recent_sender_ts)))]);
    let sender_ts = sender_ts_from(&keys);
    // Valid senderTimestamp: should re-issue
    assert!(sender_ts.is_some());
    assert!(!is_tc_token_expired(sender_ts));
}
#[test]
fn t_tctoken_integration_scenarios_phase_4_identity_change_re_issuance_decision_does_not_re_issue_when_sendertimestamp_is_expired() {
    let expired_sender_ts = now_seconds() - 30 * 86400; // 30 days ago
    let keys = MockKeys::with(&[(JID_A, entry(&TOKEN_A, Some(&expired_sender_ts.to_string()), Some(expired_sender_ts)))]);
    let sender_ts = sender_ts_from(&keys);
    // Expired senderTimestamp: should NOT re-issue
    assert!(sender_ts.is_some());
    assert!(is_tc_token_expired(sender_ts));
}
#[test]
fn t_tctoken_integration_scenarios_phase_4_identity_change_re_issuance_decision_does_not_re_issue_when_no_sendertimestamp_exists() {
    let keys = MockKeys::with(&[(JID_A, entry(&TOKEN_A, Some(&now_seconds().to_string()), None))]);
    let sender_ts = sender_ts_from(&keys);
    // No senderTimestamp: isTcTokenExpired(undefined) = true, so don't re-issue
    assert_eq!(sender_ts, None);
    assert!(is_tc_token_expired(None));
}
fn ago(days: i64) -> String {
    (now_seconds() - days * 86400).to_string()
}
#[test]
fn t_tctoken_integration_scenarios_phase_5_token_pruning_prune_correctly_identifies_expired_vs_valid_tokens() {
    let entries = [(JID_A, ago(1)), (JID_B, ago(30)), (JID_C, ago(20))];
    let (mut expired_jids, mut valid_jids) = (Vec::new(), Vec::new());
    for (jid, ts) in &entries {
        if is_tc_token_expired_str(Some(ts)) {
            expired_jids.push(*jid);
        } else {
            valid_jids.push(*jid);
        }
    }
    assert_eq!(expired_jids, vec![JID_B]);
    assert!(valid_jids.contains(&JID_A));
    assert!(valid_jids.contains(&JID_C));
}
#[test]
fn t_tctoken_integration_scenarios_phase_5_token_pruning_prune_builds_correct_deletion_map() {
    let entries = [(JID_A, ago(1)), (JID_B, ago(30))];
    let deletions: Vec<&str> = entries.iter().filter(|(_, ts)| is_tc_token_expired_str(Some(ts))).map(|(j, _)| *j).collect();
    assert_eq!(deletions, vec![JID_B]);
    assert!(!deletions.contains(&JID_A)); // valid entry not in deletions
}
#[test]
fn t_tctoken_integration_scenarios_phase_5_token_pruning_prune_with_all_tokens_valid_results_in_no_deletions() {
    let entries = [(JID_A, ago(1)), (JID_B, ago(3))];
    assert_eq!(entries.iter().filter(|(_, ts)| is_tc_token_expired_str(Some(ts))).count(), 0);
}
#[test]
fn t_tctoken_integration_scenarios_phase_5_token_pruning_prune_with_all_tokens_expired_results_in_full_cleanup() {
    let entries = [(JID_A, ago(30)), (JID_B, ago(35))];
    let deletions: Vec<&str> = entries.iter().filter(|(_, ts)| is_tc_token_expired_str(Some(ts))).map(|(j, _)| *j).collect();
    assert_eq!(deletions.len(), 2);
    assert!(deletions.contains(&JID_A));
    assert!(deletions.contains(&JID_B));
}
#[test]
fn t_tctoken_integration_scenarios_phase_5_token_pruning_prune_handles_entries_with_missing_timestamp() {
    // no timestamp: treated as expired
    let e = entry(&TOKEN_A, None, None);
    assert!(is_tc_token_expired_str(e.timestamp.as_deref()));
}
#[test]
fn t_tctoken_integration_scenarios_full_lifecycle_simulation_token_goes_through_complete_lifecycle_missing_fetch_valid_bucket_cross_expired_prune() {
    let now = now_seconds();
    let bucket_start = now.div_euclid(BUCKET_DURATION) * BUCKET_DURATION;
    // Step 1: Token missing: isTcTokenExpired(undefined) triggers fetch
    assert!(is_tc_token_expired(None));
    assert!(should_send_new_tc_token(None));
    // Step 2: After fetch, token is fresh, no need to re-issue in same bucket
    let fetch_time = now;
    assert!(!expired(fetch_time));
    assert!(!should_send(fetch_time));
    // Step 3: Still in same bucket: token valid, no fire-and-forget
    assert!(!expired(fetch_time));
    assert!(!should_send(fetch_time));
    // Step 4: Next bucket boundary crossed: shouldSendNewTcToken triggers
    assert!(should_send(bucket_start - 1)); // timestamp from previous bucket
    // After re-issuing, senderTimestamp updated to current bucket
    assert!(!should_send(now));
    // Step 5: Token received long ago: expired
    let old_token = now - 30 * 86400;
    assert!(expired(old_token));
    // Step 6: Identity change: check senderTimestamp
    // Recent sender timestamp: re-issue
    assert!(!expired(now - 5 * 86400)); // still valid: re-issue
    // Expired sender timestamp: don't re-issue
    assert!(expired(now - 30 * 86400)); // expired: skip
    // Step 7: Prune: only old tokens cleaned
    assert!(!expired(fetch_time)); // fresh: keep
    assert!(expired(old_token)); // old: delete
}
#[test]
fn t_tctoken_integration_scenarios_full_lifecycle_simulation_sendertimestamp_and_received_timestamp_are_independent() {
    let now = now_seconds();
    let e = entry(&TOKEN_A, Some(&(now - 86400).to_string()), Some(now - 10 * 86400));
    // Received token is valid
    assert!(!is_tc_token_expired_str(e.timestamp.as_deref()));
    // But we should re-issue our token (crossed bucket boundary)
    assert!(should_send_new_tc_token(e.sender_timestamp));
}
#[test]
fn t_tctoken_integration_scenarios_full_lifecycle_simulation_multiple_contacts_have_independent_token_lifecycles() {
    let keys = MockKeys::with(&[(JID_A, entry(&TOKEN_A, Some(&ago(1)), None)), (JID_B, entry(&TOKEN_B, Some(&ago(30)), None))]);
    let data = keys.get(KeyKind::TcToken, &[JID_A.to_string(), JID_B.to_string()]).unwrap();
    let ts_of = |jid: &str| match data.get(jid) {
        Some(KeyValue::TcToken(e)) => e.timestamp.clone(),
        _ => None,
    };
    // A is valid
    assert!(!is_tc_token_expired_str(ts_of(JID_A).as_deref()));
    // B is expired
    assert!(is_tc_token_expired_str(ts_of(JID_B).as_deref()));
}
const INDEX_KEY: &str = "__index";
#[test]
fn t_tctoken_integration_scenarios_tctoken_index_persistence_index_round_trips_through_json_encoded_buffer() {
    let jids = vec![Json::Str(JID_A.to_string()), Json::Str(JID_B.to_string()), Json::Str("999@lid".to_string())];
    let token = Json::Arr(jids.clone()).stringify().into_bytes();
    let parsed = Json::parse(&String::from_utf8(token).unwrap()).unwrap();
    assert_eq!(parsed, Json::Arr(jids));
}
#[test]
fn t_tctoken_integration_scenarios_tctoken_index_persistence_index_ignores_sentinel_key_when_loading() {
    let jids = [Some(JID_A), Some(INDEX_KEY), Some(JID_B), Some(""), None];
    let mut loaded = std::collections::HashSet::new();
    for jid in jids.into_iter().flatten() {
        if !jid.is_empty() && jid != INDEX_KEY {
            loaded.insert(jid);
        }
    }
    assert!(loaded.contains(JID_A));
    assert!(loaded.contains(JID_B));
    assert!(!loaded.contains(INDEX_KEY));
    assert_eq!(loaded.len(), 2);
}
#[test]
fn t_tctoken_integration_scenarios_tctoken_index_persistence_index_enables_pruning_of_tokens_from_previous_sessions() {
    // Simulate: index loaded from store with 3 JIDs from previous session
    let mut known_jids = vec![JID_A.to_string(), JID_B.to_string(), "999@lid".to_string()];
    // Simulate token state: A valid, B expired, 999 missing
    let all_tokens = [(JID_A, ago(1)), (JID_B, ago(30))];
    let mut deletions = Vec::new();
    known_jids.retain(|jid| {
        let e = all_tokens.iter().find(|(k, _)| k == jid);
        if e.is_none_or(|(_, ts)| is_tc_token_expired_str(Some(ts))) {
            deletions.push(jid.clone());
            false
        } else {
            true
        }
    });
    // B (expired) and 999 (missing) should be pruned
    assert!(deletions.contains(&JID_B.to_string()));
    assert!(deletions.contains(&"999@lid".to_string()));
    // A should survive
    assert!(!deletions.contains(&JID_A.to_string()));
    assert!(known_jids.contains(&JID_A.to_string()));
    assert_eq!(known_jids.len(), 1);
    // Updated index should only contain A
    let text = Json::Arr(known_jids.into_iter().map(Json::Str).collect()).stringify();
    assert_eq!(Json::parse(&text).unwrap(), Json::Arr(vec![Json::Str(JID_A.to_string())]));
}
#[test]
fn t_tctoken_integration_scenarios_tctoken_index_persistence_only_schedules_index_save_when_jid_is_new() {
    let mut known_jids = std::collections::HashSet::new();
    let mut save_count = 0;
    // First add: triggers save
    if known_jids.insert(JID_A) {
        save_count += 1;
    }
    assert_eq!(save_count, 1);
    // Duplicate add: no save
    if known_jids.insert(JID_A) {
        save_count += 1;
    }
    assert_eq!(save_count, 1);
    // New JID: triggers save
    if known_jids.insert(JID_B) {
        save_count += 1;
    }
    assert_eq!(save_count, 2);
}

const PN_JID: &str = "user@s.whatsapp.net";
const LID_JID: &str = "user@lid";
fn gives(v: &'static str) -> impl Fn(&str) -> Result<Option<String>> {
    move |_| Ok(Some(v.to_string()))
}
fn gives_none(_: &str) -> Result<Option<String>> {
    Ok(None)
}
#[test]
fn t_resolveissuancejid_resolves_pn_to_lid_when_issuetolid_true() {
    assert_eq!(resolve_issuance_jid(PN_JID, true, &gives(LID_JID), None).unwrap(), LID_JID);
}
#[test]
fn t_resolveissuancejid_returns_original_jid_when_issuetolid_true_but_no_lid_mapping() {
    assert_eq!(resolve_issuance_jid(PN_JID, true, &gives_none, None).unwrap(), PN_JID);
}
#[test]
fn t_resolveissuancejid_returns_lid_as_is_when_issuetolid_true_and_already_a_lid() {
    let calls = RefCell::new(0);
    let get_lid = |_: &str| -> Result<Option<String>> {
        *calls.borrow_mut() += 1;
        Ok(None)
    };
    assert_eq!(resolve_issuance_jid(LID_JID, true, &get_lid, None).unwrap(), LID_JID);
    assert_eq!(*calls.borrow(), 0);
}
#[test]
fn t_resolveissuancejid_returns_pn_as_is_when_issuetolid_false_and_already_a_pn() {
    assert_eq!(resolve_issuance_jid(PN_JID, false, &gives_none, None).unwrap(), PN_JID);
}
#[test]
fn t_resolveissuancejid_resolves_lid_to_pn_when_issuetolid_false() {
    assert_eq!(resolve_issuance_jid(LID_JID, false, &gives_none, Some(&gives(PN_JID))).unwrap(), PN_JID);
}
#[test]
fn t_resolveissuancejid_returns_lid_when_issuetolid_false_but_no_pn_mapping() {
    assert_eq!(resolve_issuance_jid(LID_JID, false, &gives_none, Some(&gives_none)).unwrap(), LID_JID);
}

#[test]
fn t_psa_and_bot_jid_detection_psa_wid_is_0_c_us() {
    assert_eq!(PSA_WID, "0@c.us");
}
#[test]
fn t_psa_and_bot_jid_detection_isjidbot_detects_pn_bot_patterns() {
    assert!(is_jid_bot("13135550001@c.us"));
    assert!(is_jid_bot("13165550012@c.us"));
    assert!(!is_jid_bot("1234567890@c.us"));
    assert!(!is_jid_bot("alice@s.whatsapp.net"));
}
#[test]
fn t_psa_and_bot_jid_detection_isjidmetaai_detects_bot_suffix() {
    assert!(is_jid_meta_ai("13135550002@bot"));
    assert!(!is_jid_meta_ai("alice@s.whatsapp.net"));
}
#[test]
fn t_psa_and_bot_jid_detection_regular_user_jids_are_not_bot() {
    let jid = "alice@s.whatsapp.net";
    assert!(!is_jid_bot(jid));
    assert!(!is_jid_meta_ai(jid));
}

#[test]
fn t_tctoken_index_helpers_readtctokenindex_returns_empty_array_when_no_sentinel_exists() {
    let keys = MockKeys::default();
    assert_eq!(read_tc_token_index(&keys).unwrap(), Vec::<String>::new());
}
fn json_token(items: &[&str]) -> TcTokenEntry {
    let text = Json::Arr(items.iter().map(|s| Json::Str(s.to_string())).collect()).stringify();
    entry(text.as_bytes(), None, None)
}
#[test]
fn t_tctoken_index_helpers_readtctokenindex_parses_persisted_jids_and_drops_the_sentinel_itself() {
    let keys = MockKeys::with(&[(TC_TOKEN_INDEX_KEY, json_token(&["a@lid", "b@lid", TC_TOKEN_INDEX_KEY]))]);
    assert_eq!(read_tc_token_index(&keys).unwrap(), vec!["a@lid".to_string(), "b@lid".to_string()]);
}
#[test]
fn t_tctoken_index_helpers_readtctokenindex_tolerates_malformed_payloads() {
    let keys = MockKeys::with(&[(TC_TOKEN_INDEX_KEY, entry(b"not json", None, None))]);
    assert_eq!(read_tc_token_index(&keys).unwrap(), Vec::<String>::new());
}
#[test]
fn t_tctoken_index_helpers_buildmergedtctokenindexwrite_unions_persisted_and_added_jids() {
    let keys = MockKeys::with(&[(TC_TOKEN_INDEX_KEY, json_token(&["a@lid"]))]);
    let write = build_merged_tc_token_index_write(&keys, &["b@lid".to_string(), "a@lid".to_string()]).unwrap();
    let Json::Arr(merged) = Json::parse(&String::from_utf8(write.token.to_vec()).unwrap()).unwrap() else { panic!("not an array") };
    let set: std::collections::HashSet<&str> = merged.iter().filter_map(|j| j.as_str()).collect();
    assert_eq!(set, std::collections::HashSet::from(["a@lid", "b@lid"]));
}
#[test]
fn t_tctoken_index_helpers_buildmergedtctokenindexwrite_filters_out_the_sentinel_key_and_empty_strings() {
    let keys = MockKeys::default();
    let write = build_merged_tc_token_index_write(&keys, &[TC_TOKEN_INDEX_KEY.to_string(), String::new(), "a@lid".to_string()]).unwrap();
    let merged = Json::parse(&String::from_utf8(write.token.to_vec()).unwrap()).unwrap();
    assert_eq!(merged, Json::Arr(vec![Json::Str("a@lid".to_string())]));
}
