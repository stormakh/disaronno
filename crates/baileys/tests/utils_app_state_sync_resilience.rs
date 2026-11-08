//! Port of src/__tests__/Utils/app-state-sync-resilience.test.ts.
use baileys::error::{Boom, Result};
use baileys::proto::message::AppStateSyncKeyData;
use baileys::proto::pb::Json;
use baileys::proto::{KeyId, SyncdIndex, SyncdPatch, SyncdRecord, SyncdSnapshot, SyncdValue, SyncdVersion};
use baileys::types::chat::WAPatchName;
use baileys::utils::chat_utils::*;

fn missing_key_fn(_: &str) -> Result<Option<AppStateSyncKeyData>> {
    Ok(None)
}
fn missing_id() -> KeyId {
    KeyId::new().with_id(b"missing-key".to_vec())
}

#[test]
fn t_app_state_sync_missing_key_errors_are_marked_with_ismissingkey_blocked_in_wa_web_decodesyncdpatch_throws_with_ismissingkey_on_missing_key() {
    let msg = SyncdPatch::new().with_key_id(missing_id()).with_mutations(vec![]).with_version(SyncdVersion::new().with_version(1u64)).with_snapshot_mac(vec![0u8; 32]).with_patch_mac(vec![0u8; 32]);
    let error = decode_syncd_patch(&msg, WAPatchName::RegularLow, &new_lt_hash_state(), &missing_key_fn, &mut |_| {}, true).expect_err("should have thrown");
    assert!(is_missing_key_error(&error));
}

#[test]
fn t_app_state_sync_missing_key_errors_are_marked_with_ismissingkey_blocked_in_wa_web_decodesyncdsnapshot_throws_with_ismissingkey_on_missing_snapshot_key() {
    let snapshot = SyncdSnapshot::new().with_version(SyncdVersion::new().with_version(1u64)).with_records(vec![]).with_key_id(missing_id()).with_mac(vec![0u8; 32]);
    let error = decode_syncd_snapshot(WAPatchName::RegularLow, &snapshot, &missing_key_fn, None, true, None).expect_err("should have thrown");
    assert!(is_missing_key_error(&error));
}

#[test]
fn t_app_state_sync_missing_key_errors_are_marked_with_ismissingkey_blocked_in_wa_web_decodesyncdmutations_throws_with_ismissingkey_on_missing_mutation_key() {
    let records = vec![SyncdRecord::new().with_key_id(missing_id()).with_value(SyncdValue::new().with_blob(vec![0u8; 64])).with_index(SyncdIndex::new().with_blob(vec![0u8; 32]))];
    let error = decode_syncd_mutations(&records, &new_lt_hash_state(), &missing_key_fn, &mut |_| {}, true).expect_err("should have thrown");
    assert!(is_missing_key_error(&error));
}

#[test]
fn t_app_state_sync_missing_key_errors_are_marked_with_ismissingkey_blocked_in_wa_web_missing_key_errors_are_not_irrecoverable_on_first_attempt() {
    let error = Boom::with_data("missing key", Json::Obj(vec![("isMissingKey".to_string(), Json::Bool(true))]));
    assert!(is_missing_key_error(&error));
    assert!(!is_app_state_sync_irrecoverable(Some(&error), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_not_be_irrecoverable_for_status_400_dead_code_path_removed() {
    assert!(!is_app_state_sync_irrecoverable(Some(&Boom::status("test", 400)), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_not_be_irrecoverable_for_status_404_missing_key_is_blocked_not_fatal() {
    assert!(!is_app_state_sync_irrecoverable(Some(&Boom::status("test", 404)), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_not_be_irrecoverable_for_status_405() {
    assert!(!is_app_state_sync_irrecoverable(Some(&Boom::status("test", 405)), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_not_be_irrecoverable_for_status_406() {
    assert!(!is_app_state_sync_irrecoverable(Some(&Boom::status("test", 406)), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_be_irrecoverable_for_typeerror() {
    // adapted: Rust has no TypeError class. `Boom::type_error` is the same mark that `error.name` carries.
    assert!(is_app_state_sync_irrecoverable(Some(&Boom::type_error("WASM crash")), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_be_irrecoverable_when_attempts_max_sync_attempts() {
    assert!(is_app_state_sync_irrecoverable(Some(&Boom::new("generic")), MAX_SYNC_ATTEMPTS));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_not_be_irrecoverable_for_generic_error_below_max_attempts() {
    assert!(!is_app_state_sync_irrecoverable(Some(&Boom::new("generic")), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_not_be_irrecoverable_for_non_fatal_status_codes() {
    assert!(!is_app_state_sync_irrecoverable(Some(&Boom::status("server error", 500)), 1));
}

#[test]
fn t_app_state_sync_isappstatesyncirrecoverable_should_handle_null_undefined_error_gracefully() {
    assert!(is_app_state_sync_irrecoverable(None, MAX_SYNC_ATTEMPTS));
    assert!(!is_app_state_sync_irrecoverable(None, 1));
}
