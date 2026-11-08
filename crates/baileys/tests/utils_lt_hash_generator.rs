//! Port of src/__tests__/Utils/lt-hash-generator.test.ts.
use baileys::auth::LtHashState;
use baileys::proto::pb::base64_encode;
use baileys::proto::syncd_mutation::SyncdOperation;
use baileys::utils::chat_utils::{Mac, make_lt_hash_generator};
use std::collections::HashMap;

const SET: SyncdOperation = SyncdOperation::SET;
const REMOVE: SyncdOperation = SyncdOperation::REMOVE;

fn make_index(id: &str) -> Vec<u8> {
    id.as_bytes().to_vec()
}
fn make_value(id: &str) -> Vec<u8> {
    format!("value-{id}").into_bytes()
}
fn state(index_value_map: HashMap<String, Vec<u8>>) -> LtHashState {
    LtHashState { version: 0, hash: vec![0u8; 128], index_value_map }
}
fn mac<'a>(index_mac: &'a [u8], value_mac: &'a [u8], operation: SyncdOperation) -> Mac<'a> {
    Mac { index_mac, value_mac, operation }
}

#[test]
fn t_makelthashgenerator_should_handle_set_operation_normally() {
    let mut generator = make_lt_hash_generator(&state(HashMap::new()));
    generator.mix(mac(&make_index("idx1"), &make_value("v1"), SET));
    let result = generator.finish();
    let key = base64_encode(&make_index("idx1"));
    assert_eq!(result.index_value_map.get(&key), Some(&make_value("v1")));
}

#[test]
fn t_makelthashgenerator_should_handle_remove_with_existing_previous_op() {
    let index_key = base64_encode(&make_index("idx1"));
    let mut generator = make_lt_hash_generator(&state(HashMap::from([(index_key.clone(), make_value("old-v1"))])));
    generator.mix(mac(&make_index("idx1"), &make_value("v1"), REMOVE));
    let result = generator.finish();
    assert!(!result.index_value_map.contains_key(&index_key));
}

#[test]
fn t_makelthashgenerator_should_not_throw_on_remove_without_previous_op_matches_wa_web() {
    let mut generator = make_lt_hash_generator(&state(HashMap::new()));
    // adapted: `mix` returns nothing, so reaching the next line is the "does not throw" check
    generator.mix(mac(&make_index("idx1"), &make_value("v1"), REMOVE));
    let result = generator.finish();
    assert_eq!(result.hash.len(), 128);
    assert!(result.index_value_map.is_empty());
}

#[test]
fn t_makelthashgenerator_should_continue_processing_after_remove_without_previous_op() {
    let mut generator = make_lt_hash_generator(&state(HashMap::new()));
    generator.mix(mac(&make_index("idx1"), &make_value("v1"), REMOVE));
    generator.mix(mac(&make_index("idx2"), &make_value("v2"), SET));
    let result = generator.finish();
    let key2 = base64_encode(&make_index("idx2"));
    assert_eq!(result.index_value_map.get(&key2), Some(&make_value("v2")));
}

#[test]
fn t_makelthashgenerator_should_not_add_missing_remove_to_indexvaluemap() {
    let mut generator = make_lt_hash_generator(&state(HashMap::new()));
    generator.mix(mac(&make_index("idx1"), &make_value("v1"), REMOVE));
    let result = generator.finish();
    let key = base64_encode(&make_index("idx1"));
    assert!(!result.index_value_map.contains_key(&key));
}

#[test]
fn t_makelthashgenerator_should_process_mix_of_set_remove_with_prev_and_remove_without_prev() {
    let existing_key = base64_encode(&make_index("existing"));
    let mut generator = make_lt_hash_generator(&state(HashMap::from([(existing_key.clone(), make_value("old"))])));
    generator.mix(mac(&make_index("new-entry"), &make_value("new"), SET));
    generator.mix(mac(&make_index("existing"), &make_value("existing"), REMOVE));
    generator.mix(mac(&make_index("ghost"), &make_value("ghost"), REMOVE));
    let result = generator.finish();
    let new_key = base64_encode(&make_index("new-entry"));
    let ghost_key = base64_encode(&make_index("ghost"));
    assert!(result.index_value_map.contains_key(&new_key));
    assert!(!result.index_value_map.contains_key(&existing_key));
    assert!(!result.index_value_map.contains_key(&ghost_key));
}
