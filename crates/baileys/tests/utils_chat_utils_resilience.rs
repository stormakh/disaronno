//! Port of src/__tests__/Utils/chat-utils-resilience.test.ts.
//!
//! Resilience tests for app-state-sync decode paths.
//!  - decodeSyncdMutations skips undecryptable records instead of aborting
//!    (key-not-found, HMAC mismatch, AES decrypt failure).
//!  - decodeSyncdSnapshot soft-fails the aggregate LTHash MAC verify when
//!    records were skipped, rather than throwing and losing the whole snapshot.
use baileys::auth::LtHashState;
use baileys::crypto::random_bytes;
use baileys::error::Result;
use baileys::proto::message::AppStateSyncKeyData;
use baileys::proto::pb::{Bytes, Json, base64_decode, base64_encode};
use baileys::proto::sync_action_value::ArchiveChatAction;
use baileys::proto::syncd_mutation::SyncdOperation;
use baileys::proto::{KeyId, SyncActionValue, SyncdIndex, SyncdPatch, SyncdRecord, SyncdSnapshot, SyncdValue, SyncdVersion};
use baileys::types::chat::{ChatMutation, WAPatchCreate, WAPatchName};
use baileys::utils::chat_utils::*;
use baileys::utils::logger::{LogLevel, Logger, SilentLogger};
use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock};

const NAME: WAPatchName = WAPatchName::Regular;

fn rand(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    random_bytes(&mut b);
    b
}
fn my_key_id() -> &'static str {
    static K: OnceLock<String> = OnceLock::new();
    K.get_or_init(|| base64_encode(&rand(16)))
}
/// 32-byte app-state-sync key — fed to expandAppStateKeys via mutationKeys().
fn app_state_key() -> &'static AppStateSyncKeyData {
    static K: OnceLock<AppStateSyncKeyData> = OnceLock::new();
    K.get_or_init(|| AppStateSyncKeyData::new().with_key_data(rand(32)))
}
fn get_app_state_sync_key(key_id: &str) -> Result<Option<AppStateSyncKeyData>> {
    Ok(if key_id == my_key_id() { Some(app_state_key().clone()) } else { None })
}
struct Encoded {
    record: SyncdRecord,
    new_state: LtHashState,
    patch: SyncdPatch,
}
/// Produce one valid encoded record by round-tripping through encodeSyncdPatch.
fn encode_valid_record(state: &LtHashState) -> Encoded {
    let create = WAPatchCreate {
        r#type: NAME,
        index: vec!["conversation".to_string(), format!("jid-{}", base64_encode(&rand(8))), "archive".to_string()],
        sync_action: SyncActionValue::new().with_archive_chat_action(ArchiveChatAction::new().with_archived(true)),
        api_version: 0,
        operation: SyncdOperation::SET,
    };
    let encoded = encode_syncd_patch(&create, my_key_id(), state, &get_app_state_sync_key).unwrap();
    let record = encoded.patch.mutations()[0].record().unwrap().clone();
    Encoded { record, new_state: encoded.state, patch: encoded.patch }
}
fn tamper_last_byte(blob: &Bytes) -> Vec<u8> {
    let mut b = blob.to_vec();
    let last = b.len() - 1;
    b[last] ^= 0xff;
    b
}

#[test]
fn t_decodesyncdmutations_resilience_skips_a_record_whose_content_hmac_does_not_verify_no_throw() {
    let initial = new_lt_hash_state();
    let Encoded { record, .. } = encode_valid_record(&initial);
    // Flip the trailing HMAC so the content HMAC compare fails.
    let blob = tamper_last_byte(record.value().unwrap().blob().unwrap());
    let tampered = record.clone().with_value(SyncdValue::new().with_blob(blob));
    let seen: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
    let mut on_mutation = |m: ChatMutation| seen.borrow_mut().push(m.index);
    let result = decode_syncd_mutations(&[tampered], &initial, &get_app_state_sync_key, &mut on_mutation, true);
    assert!(result.is_ok());
    assert_eq!(seen.borrow().len(), 0);
}

#[test]
fn t_decodesyncdmutations_resilience_skips_a_record_whose_aes_decrypt_fails_no_throw() {
    // Hand-craft a record whose ciphertext is garbage. validateMacs=false so the HMAC short-circuit doesn't fire first.
    let initial = new_lt_hash_state();
    let key_id = base64_decode(my_key_id());
    // Provide a non-AES-block-aligned ciphertext so the decrypt fails.
    let mut content = rand(17);
    content.extend_from_slice(&rand(32));
    let record = SyncdRecord::new().with_key_id(KeyId::new().with_id(key_id)).with_value(SyncdValue::new().with_blob(content)).with_index(SyncdIndex::new().with_blob(rand(32)));
    let seen: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
    let mut on_mutation = |m: ChatMutation| seen.borrow_mut().push(m.index);
    let result = decode_syncd_mutations(&[record], &initial, &get_app_state_sync_key, &mut on_mutation, false);
    assert!(result.is_ok());
    assert_eq!(seen.borrow().len(), 0);
}

#[test]
fn t_decodesyncdmutations_resilience_processes_good_records_alongside_a_bad_one_in_the_same_batch() {
    let initial = new_lt_hash_state();
    let Encoded { record: good1, new_state: s1, .. } = encode_valid_record(&initial);
    let Encoded { record: good2, .. } = encode_valid_record(&s1);
    // "Bad" record uses the right key but has a tampered HMAC blob — exercises
    // the record-level corruption skip path (NOT missing-key, which now propagates).
    let tampered_blob = tamper_last_byte(good1.value().unwrap().blob().unwrap());
    let bad = SyncdRecord::new().with_key_id(good1.key_id().unwrap().clone()).with_value(SyncdValue::new().with_blob(tampered_blob)).with_index(SyncdIndex::new().with_blob(rand(32)));
    let seen: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
    let mut on_mutation = |m: ChatMutation| seen.borrow_mut().push(m.index);
    let result = decode_syncd_mutations(&[good1, bad, good2], &initial, &get_app_state_sync_key, &mut on_mutation, true);
    assert!(result.is_ok());
    // Both valid records should have been emitted via onMutation.
    assert_eq!(seen.borrow().len(), 2);
}

#[derive(Default)]
struct WarnLogger {
    warns: Mutex<Vec<(Option<Json>, String)>>,
}
impl Logger for WarnLogger {
    fn level(&self) -> LogLevel {
        LogLevel::Trace
    }
    fn child(&self, _bindings: &[(&str, &str)]) -> Arc<dyn Logger> {
        Arc::new(SilentLogger)
    }
    fn log(&self, level: LogLevel, obj: Option<&Json>, msg: &str) {
        if level == LogLevel::Warn {
            self.warns.lock().unwrap().push((obj.cloned(), msg.to_string()));
        }
    }
}

#[test]
fn t_decodesyncdsnapshot_resilience_warns_and_returns_partial_state_when_aggregate_lthash_mac_verify_fails() {
    // Encode a valid record so we have a realistic snapshot shape, then
    // deliberately corrupt snapshot.mac so the aggregate LTHash verify fails.
    // Without the softening, this throws `failed to verify LTHash ... from snapshot`
    // and the whole syncd-state decode aborts (the primary user-visible symptom).
    let initial = new_lt_hash_state();
    let Encoded { record, patch, .. } = encode_valid_record(&initial);
    let mut corrupted_mac = patch.snapshot_mac().unwrap().to_vec();
    corrupted_mac[0] ^= 0xff;
    let key_id_bytes = base64_decode(my_key_id());
    let snapshot = SyncdSnapshot::new().with_version(SyncdVersion::new().with_version(1u64)).with_mac(corrupted_mac).with_key_id(KeyId::new().with_id(key_id_bytes)).with_records(vec![record]);
    let logger = WarnLogger::default();
    let decoded = decode_syncd_snapshot(NAME, &snapshot, &get_app_state_sync_key, None, true, Some(&logger)).unwrap();
    assert_eq!(decoded.state.version, 1);
    assert_eq!(decoded.state.hash.len(), 128);
    let warns = logger.warns.lock().unwrap();
    assert_eq!(warns.len(), 1);
    let (obj, msg) = &warns[0];
    assert_eq!(obj.as_ref().unwrap().get("name").and_then(Json::as_str), Some("regular"));
    assert!(msg.contains("LTHash verification failed"));
    // The valid record should still have been processed into the mutation map.
    assert_eq!(decoded.mutation_map.len(), 1);
}
