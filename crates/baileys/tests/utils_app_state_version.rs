//! Port of src/__tests__/Utils/app-state-version.test.ts.
//!
//! adapted: `LtHashState.version` is a `u64`, so a bad version cannot exist in the typed state. A bad version can only
//! come from a stored state, so these tests give the same inputs to the check that reads a stored state as `Json`.
use baileys::auth::{KeyKind, KeyValue, LtHashState};
use baileys::proto::pb::{Json, js_number};
use baileys::utils::chat_utils::{ensure_lt_hash_state_version, ensure_lt_hash_state_version_json};
use baileys::utils::use_multi_file_auth_state::key_value_from_json;
use std::collections::HashMap;

/// `None` is a state where `version` is undefined.
fn make_state(version: Option<Json>) -> Json {
    let mut fields = vec![
        ("hash".to_string(), Json::Bytes(vec![0u8; 128])),
        ("indexValueMap".to_string(), Json::Obj(vec![("someKey".to_string(), Json::Obj(vec![("valueMac".to_string(), Json::Bytes(vec![1, 2, 3]))]))])),
    ];
    if let Some(v) = version {
        fields.insert(0, ("version".to_string(), v));
    }
    Json::Obj(fields)
}
fn version_of(state: &Json) -> f64 {
    state.get("version").and_then(Json::as_f64).expect("version must be a number")
}

#[test]
fn t_ensurelthashstateversion_should_return_state_unchanged_for_valid_numeric_version() {
    let mut state = make_state(Some(Json::Num(5.0)));
    let original = state.clone();
    let address: *const Json = &state;
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert!(std::ptr::eq(address, result));
    assert_eq!(version_of(result), 5.0);
    assert_eq!(*result, original);
    // the typed function also returns the same state
    let mut typed = LtHashState { version: 5, hash: vec![0u8; 128], index_value_map: HashMap::new() };
    let address: *const LtHashState = &typed;
    let result = ensure_lt_hash_state_version(&mut typed);
    assert!(std::ptr::eq(address, result));
    assert_eq!(result.version, 5);
}

#[test]
fn t_ensurelthashstateversion_should_fix_undefined_version_to_0() {
    let mut state = make_state(None);
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert_eq!(version_of(result), 0.0);
}

#[test]
fn t_ensurelthashstateversion_should_fix_null_version_to_0() {
    let mut state = make_state(Some(Json::Null));
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert_eq!(version_of(result), 0.0);
}

#[test]
fn t_ensurelthashstateversion_should_fix_nan_version_to_0() {
    let mut state = make_state(Some(Json::Num(f64::NAN)));
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert_eq!(version_of(result), 0.0);
}

#[test]
fn t_ensurelthashstateversion_should_fix_string_version_to_0() {
    let mut state = make_state(Some(Json::Str("3".to_string())));
    // the path a stored state takes into the library must apply the same rule
    let KeyValue::AppStateSyncVersion(read) = key_value_from_json(KeyKind::AppStateSyncVersion, &state).unwrap() else { panic!("wrong kind") };
    assert_eq!(read.version, 0);
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert_eq!(version_of(result), 0.0);
}

#[test]
fn t_ensurelthashstateversion_should_keep_version_0_as_is() {
    let mut state = make_state(Some(Json::Num(0.0)));
    let address: *const Json = &state;
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert!(std::ptr::eq(address, result));
    assert_eq!(version_of(result), 0.0);
}

#[test]
fn t_ensurelthashstateversion_should_preserve_other_state_fields() {
    let mut state = make_state(None);
    let original_hash = state.get("hash").cloned();
    let original_map = state.get("indexValueMap").cloned();
    let result = ensure_lt_hash_state_version_json(&mut state);
    assert_eq!(result.get("hash").cloned(), original_hash);
    assert_eq!(result.get("indexValueMap").cloned(), original_map);
}

#[test]
fn t_ensurelthashstateversion_should_allow_tostring_after_fix_without_throwing() {
    let mut state = make_state(None);
    ensure_lt_hash_state_version_json(&mut state);
    assert_eq!(js_number(version_of(&state)), "0");
}
