//! Same behavior as Utils/chat-utils.ts.
//!
//! Where JavaScript throws a TypeError because a required field is null, these functions return
//! `Boom::type_error`. Where upstream takes `RequestInit` to fetch an external blob, they take a `download` function.
use crate::auth::{AccountSettings, CredsUpdate, LidMapping, LtHashState};
use crate::crypto::{aes_decrypt, aes_encrypt, hkdf, hmac_sha256, hmac_sha512};
use crate::error::{Boom, Result};
use crate::events::{BaileysEvent, BaileysEventEmitter, BufferedEventData, MessagesDelete, SettingsUpdate};
use crate::types::chat::{Chat, ChatModification, ChatMutation, ChatUpdate, ChatUpdateConditional, InitialAppStateSyncOptions, LastMessageList, WAPatchCreate, WAPatchName};
use crate::types::contact::Contact;
use crate::types::label::{ChatLabelAssociation, Label, LabelAssociation, LabelAssociationType, MessageLabelAssociation};
use crate::types::message::{WAMessageKey, WAMessageUpdate};
use crate::events::ListUpdateType;
use crate::utils::generics::JsMap;
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::lt_hash::subtract_then_add;
use crate::utils::sync_action_utils::{emit_sync_action_results, process_contact_action};
use crate::utils::time::now_ms;
use crate::wabinary::{BinaryNode, Content, get_binary_node_child, get_binary_node_children, is_jid_group, jid_normalized_user};
use std::collections::HashMap;
use std::sync::Arc;
use waproto::message::AppStateSyncKeyData;
use waproto::pb::{Bytes, Json, PbMessage, Str, base64_decode, base64_encode, js_number};
use waproto::sync_action_value::*;
use waproto::syncd_mutation::SyncdOperation;
use waproto::{ExternalBlobReference, KeyId, MessageKey, SyncActionData, SyncActionValue, SyncdIndex, SyncdMutation, SyncdMutations, SyncdPatch, SyncdRecord, SyncdSnapshot, SyncdValue, WebMessageInfo};

/// `(keyId) => Promise<IAppStateSyncKeyData | null | undefined>`
pub type FetchAppStateSyncKey<'a> = dyn Fn(&str) -> Result<Option<AppStateSyncKeyData>> + 'a;
/// Fetches an external blob. In upstream this is `downloadContentFromMessage(blob, 'md-app-state', { options })`.
pub type DownloadExternalBlob<'a> = dyn Fn(&ExternalBlobReference) -> Result<Vec<u8>> + 'a;
pub type ChatMutationMap = JsMap<ChatMutation>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationKeys {
    pub index_key: [u8; 32],
    pub value_encryption_key: [u8; 32],
    pub value_mac_key: [u8; 32],
    pub snapshot_mac_key: [u8; 32],
    pub patch_mac_key: [u8; 32],
}
/// Same bytes as `expandAppStateKeys` in whatsapp-rust-bridge.
pub fn mutation_keys(keydata: &[u8]) -> MutationKeys {
    let k = hkdf(keydata, 160, None, b"WhatsApp Mutation Keys");
    let part = |i: usize| {
        let mut o = [0u8; 32];
        o.copy_from_slice(&k[i * 32..(i + 1) * 32]);
        o
    };
    MutationKeys { index_key: part(0), value_encryption_key: part(1), value_mac_key: part(2), snapshot_mac_key: part(3), patch_mac_key: part(4) }
}
fn keys_of(key: &AppStateSyncKeyData) -> Result<MutationKeys> {
    match key.key_data() {
        Some(d) => Ok(mutation_keys(d.as_slice())),
        None => Err(Boom::type_error("Cannot read properties of null (reading 'length')")),
    }
}
/// `operation` is `None` when a decoded mutation has no operation: as upstream, only an explicit SET gets 0x01.
fn generate_mac(operation: Option<SyncdOperation>, data: &[u8], key_id: &[u8], key: &[u8]) -> [u8; 32] {
    let op_byte = if operation == Some(SyncdOperation::SET) { 0x01 } else { 0x02 };
    let mut total = Vec::with_capacity(1 + key_id.len() + data.len() + 8);
    total.push(op_byte);
    total.extend_from_slice(key_id);
    total.extend_from_slice(data);
    total.extend_from_slice(&[0u8; 7]);
    total.push((1 + key_id.len()) as u8);
    let hmac = hmac_sha512(key, &total);
    let mut o = [0u8; 32];
    o.copy_from_slice(&hmac[..32]);
    o
}
/// `writeUint32BE` throws a RangeError above 32 bits, so this does too.
fn to_64_bit_network_order(e: u64) -> Result<[u8; 8]> {
    if e > u32::MAX as u64 {
        return Err(Boom::new(format!("The value of \"value\" is out of range. It must be >= 0 and <= 4294967295. Received {e}")));
    }
    let mut o = [0u8; 8];
    o[4..].copy_from_slice(&(e as u32).to_be_bytes());
    Ok(o)
}
pub struct Mac<'a> {
    pub index_mac: &'a [u8],
    pub value_mac: &'a [u8],
    pub operation: SyncdOperation,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct LtHashResult {
    pub hash: Vec<u8>,
    pub index_value_map: HashMap<String, Vec<u8>>,
}
pub struct LtHashGenerator {
    hash: Vec<u8>,
    index_value_map: HashMap<String, Vec<u8>>,
    add_buffs: Vec<Vec<u8>>,
    sub_buffs: Vec<Vec<u8>>,
}
pub fn make_lt_hash_generator(state: &LtHashState) -> LtHashGenerator {
    LtHashGenerator { hash: state.hash.clone(), index_value_map: state.index_value_map.clone(), add_buffs: Vec::new(), sub_buffs: Vec::new() }
}
impl LtHashGenerator {
    pub fn mix(&mut self, mac: Mac<'_>) {
        let index_mac_base64 = base64_encode(mac.index_mac);
        if mac.operation == SyncdOperation::REMOVE {
            // WA Web does not throw here — it logs a warning and skips the subtract.
            // The missing REMOVE will cause an LTHash mismatch, which is handled
            // by the MAC validation layer (snapshot recovery or retry).
            // Otherwise: remove from index value mac, since this mutation is erased.
            if let Some(prev) = self.index_value_map.remove(&index_mac_base64) {
                self.sub_buffs.push(prev);
            }
        } else {
            self.add_buffs.push(mac.value_mac.to_vec());
            // add this index into the history map
            if let Some(prev) = self.index_value_map.insert(index_mac_base64, mac.value_mac.to_vec()) {
                self.sub_buffs.push(prev);
            }
        }
    }
    pub fn finish(self) -> LtHashResult {
        let sub: Vec<&[u8]> = self.sub_buffs.iter().map(|b| b.as_slice()).collect();
        let add: Vec<&[u8]> = self.add_buffs.iter().map(|b| b.as_slice()).collect();
        LtHashResult { hash: subtract_then_add(&self.hash, &sub, &add), index_value_map: self.index_value_map }
    }
}
fn generate_snapshot_mac(lthash: &[u8], version: u64, name: &str, key: &[u8]) -> Result<[u8; 32]> {
    let mut total = Vec::with_capacity(lthash.len() + 8 + name.len());
    total.extend_from_slice(lthash);
    total.extend_from_slice(&to_64_bit_network_order(version)?);
    total.extend_from_slice(name.as_bytes());
    Ok(hmac_sha256(key, &total))
}
fn generate_patch_mac(snapshot_mac: &[u8], value_macs: &[&[u8]], version: u64, ty: &str, key: &[u8]) -> Result<[u8; 32]> {
    let mut total = Vec::with_capacity(snapshot_mac.len() + value_macs.len() * 32 + 8 + ty.len());
    total.extend_from_slice(snapshot_mac);
    for m in value_macs {
        total.extend_from_slice(m);
    }
    total.extend_from_slice(&to_64_bit_network_order(version)?);
    total.extend_from_slice(ty.as_bytes());
    Ok(hmac_sha256(key, &total))
}
pub fn new_lt_hash_state() -> LtHashState {
    LtHashState { version: 0, hash: vec![0u8; 128], index_value_map: HashMap::new() }
}
/// `version` is a `u64` here, so a typed state is always valid. A stored state that is not typed yet goes through
/// `ensure_lt_hash_state_version_json`.
pub fn ensure_lt_hash_state_version(state: &mut LtHashState) -> &mut LtHashState {
    state
}
/// Same check as `ensureLTHashStateVersion`, on a state as it comes from storage: a version that is missing,
/// null, not a number or NaN becomes 0.
pub fn ensure_lt_hash_state_version_json(state: &mut Json) -> &mut Json {
    if let Json::Obj(fields) = state {
        match fields.iter_mut().find(|(k, _)| k == "version") {
            Some((_, v)) => {
                if !matches!(v, Json::Num(n) if !n.is_nan()) {
                    *v = Json::Num(0.0);
                }
            }
            None => fields.push(("version".to_string(), Json::Num(0.0))),
        }
    }
    state
}
pub const MAX_SYNC_ATTEMPTS: u32 = 2;
/// Check if an error is a missing app state sync key.
/// WA Web treats these as "Blocked" (waits for key arrival), not fatal.
/// In Baileys we retry with a snapshot which may use a different key.
pub fn is_missing_key_error(error: &Boom) -> bool {
    error.is_missing_key || error.data.as_ref().and_then(|d| d.get("isMissingKey")).and_then(Json::as_bool) == Some(true)
}
/// Determines if an app state sync error is unrecoverable.
/// TypeError indicates a WASM crash; otherwise we give up after MAX_SYNC_ATTEMPTS.
/// Missing keys are NOT checked here — they are handled separately as "Blocked".
pub fn is_app_state_sync_irrecoverable(error: Option<&Boom>, attempts: u32) -> bool {
    attempts >= MAX_SYNC_ATTEMPTS || error.is_some_and(|e| e.is_type_error)
}
fn missing_key(message: String, extra: Option<(&str, Json)>) -> Boom {
    let mut data = vec![("isMissingKey".to_string(), Json::Bool(true))];
    if let Some((k, v)) = extra {
        data.push((k.to_string(), v));
    }
    Boom { is_missing_key: true, ..Boom::with_data(message, Json::Obj(data)) }
}
fn required<T>(v: Option<T>, field: &str) -> Result<T> {
    v.ok_or_else(|| Boom::type_error(format!("Cannot read properties of null (reading '{field}')")))
}
#[derive(Clone, Debug, PartialEq)]
pub struct EncodedSyncdPatch {
    pub patch: SyncdPatch,
    pub state: LtHashState,
}
pub fn encode_syncd_patch(create: &WAPatchCreate, my_app_state_key_id: &str, state: &LtHashState, get_app_state_sync_key: &FetchAppStateSyncKey<'_>) -> Result<EncodedSyncdPatch> {
    let key = if my_app_state_key_id.is_empty() { None } else { get_app_state_sync_key(my_app_state_key_id)? };
    let Some(key) = key else {
        return Err(missing_key(format!("myAppStateKey (\"{my_app_state_key_id}\") not present"), None));
    };
    let enc_key_id = Bytes::from_vec(base64_decode(my_app_state_key_id));
    let index = Json::Arr(create.index.iter().map(|s| Json::Str(s.clone())).collect()).stringify().into_bytes();
    let encoded = SyncActionData::new().with_index(index.clone()).with_value(create.sync_action.clone()).with_padding(Bytes::new()).with_version(create.api_version as i32).encode();
    let key_value = keys_of(&key)?;
    let enc_value = aes_encrypt(&encoded, &key_value.value_encryption_key)?;
    let value_mac = generate_mac(Some(create.operation), &enc_value, enc_key_id.as_slice(), &key_value.value_mac_key);
    let index_mac = hmac_sha256(&key_value.index_key, &index);
    // update LT hash
    let mut generator = make_lt_hash_generator(state);
    generator.mix(Mac { index_mac: &index_mac, value_mac: &value_mac, operation: create.operation });
    let LtHashResult { hash, mut index_value_map } = generator.finish();
    let version = state.version + 1;
    let name = create.r#type.as_str();
    let snapshot_mac = generate_snapshot_mac(&hash, version, name, &key_value.snapshot_mac_key)?;
    let patch_mac = generate_patch_mac(&snapshot_mac, &[&value_mac], version, name, &key_value.patch_mac_key)?;
    let mut blob = enc_value;
    blob.extend_from_slice(&value_mac);
    let record = SyncdRecord::new()
        .with_index(SyncdIndex::new().with_blob(index_mac.to_vec()))
        .with_value(SyncdValue::new().with_blob(blob))
        .with_key_id(KeyId::new().with_id(enc_key_id.clone()));
    let patch = SyncdPatch::new()
        .with_mutations(vec![SyncdMutation::new().with_operation(create.operation).with_record(record)])
        .with_snapshot_mac(snapshot_mac.to_vec())
        .with_patch_mac(patch_mac.to_vec())
        .with_key_id(KeyId::new().with_id(enc_key_id));
    index_value_map.insert(base64_encode(&index_mac), value_mac.to_vec());
    Ok(EncodedSyncdPatch { patch, state: LtHashState { version, hash, index_value_map } })
}
/// What `decodeSyncdMutations` reads from its `(ISyncdMutation | ISyncdRecord)[]` input.
pub trait SyncdMutationLike: PbMessage {
    /// If it's a syncdmutation, its operation. If it's only a record, it's a SET mutation.
    fn mutation_operation(&self) -> Option<SyncdOperation>;
    fn mutation_record(&self) -> Option<&SyncdRecord>;
}
impl SyncdMutationLike for SyncdMutation {
    fn mutation_operation(&self) -> Option<SyncdOperation> {
        self.operation()
    }
    fn mutation_record(&self) -> Option<&SyncdRecord> {
        self.record()
    }
}
impl SyncdMutationLike for SyncdRecord {
    fn mutation_operation(&self) -> Option<SyncdOperation> {
        Some(SyncdOperation::SET)
    }
    fn mutation_record(&self) -> Option<&SyncdRecord> {
        Some(self)
    }
}
fn parse_index(index: &[u8]) -> Result<Vec<String>> {
    let parsed = Json::parse(&String::from_utf8_lossy(index))?;
    // WhatsApp sends an array of strings. Another JSON value has no place in `ChatMutation.index`.
    let Json::Arr(items) = parsed else { return Ok(Vec::new()) };
    Ok(items
        .into_iter()
        .map(|v| match v {
            Json::Str(s) => s,
            other => other.stringify(),
        })
        .collect())
}
/// indexKey used to HMAC sign record.index.blob
/// valueEncryptionKey used to AES-256-CBC encrypt record.value.blob[0:-32]
/// the remaining record.value.blob[0:-32] is the mac, it the HMAC sign of key.keyId + decoded proto data + length of bytes in keyId
pub fn decode_syncd_mutations<M: SyncdMutationLike>(msg_mutations: &[M], initial_state: &LtHashState, get_app_state_sync_key: &FetchAppStateSyncKey<'_>, on_mutation: &mut dyn FnMut(ChatMutation), validate_macs: bool) -> Result<LtHashResult> {
    let mut lt_generator = make_lt_hash_generator(initial_state);
    let mut derived_key_cache: Vec<(Bytes, MutationKeys)> = Vec::new();
    for msg_mutation in msg_mutations {
        let operation = msg_mutation.mutation_operation();
        // A record or key id that is null is a TypeError inside the `try` of upstream: skip the record.
        let Some(record) = msg_mutation.mutation_record() else { continue };
        let Some(key_id) = record.key_id().and_then(|k| k.id()) else { continue };
        let cached = derived_key_cache.iter().position(|(id, _)| id.as_slice() == key_id.as_slice());
        let slot = match cached {
            Some(i) => i,
            None => {
                let base64_key = base64_encode(key_id.as_slice());
                match get_app_state_sync_key(&base64_key) {
                    Ok(Some(key_enc)) => match keys_of(&key_enc) {
                        Ok(keys) => {
                            derived_key_cache.push((key_id.clone(), keys));
                            derived_key_cache.len() - 1
                        }
                        Err(_) => continue,
                    },
                    Ok(None) => {
                        let list = Json::Arr(msg_mutations.iter().map(PbMessage::to_json).collect());
                        return Err(missing_key(format!("failed to find key \"{base64_key}\" to decode mutation"), Some(("msgMutations", list))));
                    }
                    // Missing-key errors must propagate so the orchestrator can park the
                    // collection (Blocked) and retry when APP_STATE_SYNC_KEY_SHARE arrives.
                    // Other errors → individual record corruption, skip and keep going.
                    Err(e) if is_missing_key_error(&e) => return Err(e),
                    Err(_) => continue,
                }
            }
        };
        let key = &derived_key_cache[slot].1;
        let content = required(record.value(), "blob")?;
        let content = required(content.blob(), "subarray")?.as_slice();
        let split = content.len().saturating_sub(32);
        let (enc_content, og_value_mac) = content.split_at(split);
        if validate_macs {
            let content_hmac = generate_mac(operation, enc_content, key_id.as_slice(), &key.value_mac_key);
            if content_hmac.as_slice() != og_value_mac {
                // HMAC verification failed — skip this record
                continue;
            }
        }
        // decrypt failed — skip this record instead of aborting
        let Ok(result) = aes_decrypt(enc_content, &key.value_encryption_key) else { continue };
        let sync_action = SyncActionData::decode_shared(Arc::new(result))?;
        let index = required(sync_action.index(), "index")?.clone();
        if validate_macs {
            let hmac = hmac_sha256(&key.index_key, index.as_slice());
            let blob = required(required(record.index(), "blob")?.blob(), "blob")?;
            if hmac.as_slice() != blob.as_slice() {
                return Err(Boom::new("HMAC index verification failed"));
            }
        }
        let parsed = parse_index(index.as_slice())?;
        on_mutation(ChatMutation { sync_action, index: parsed });
        let index_mac = required(required(record.index(), "blob")?.blob(), "blob")?;
        // a null operation is not REMOVE, so the generator takes it as SET
        lt_generator.mix(Mac { index_mac: index_mac.as_slice(), value_mac: og_value_mac, operation: operation.unwrap_or(SyncdOperation::SET) });
    }
    Ok(lt_generator.finish())
}
pub fn decode_syncd_patch(msg: &SyncdPatch, name: WAPatchName, initial_state: &LtHashState, get_app_state_sync_key: &FetchAppStateSyncKey<'_>, on_mutation: &mut dyn FnMut(ChatMutation), validate_macs: bool) -> Result<LtHashResult> {
    if validate_macs {
        let key_id = required(required(msg.key_id(), "id")?.id(), "id")?;
        let base64_key = base64_encode(key_id.as_slice());
        let Some(main_key_obj) = get_app_state_sync_key(&base64_key)? else {
            return Err(missing_key(format!("failed to find key \"{base64_key}\" to decode patch"), Some(("msg", msg.to_json()))));
        };
        let main_key = keys_of(&main_key_obj)?;
        let mut mutation_macs: Vec<&[u8]> = Vec::with_capacity(msg.mutations().len());
        for mutation in msg.mutations() {
            let value = required(required(mutation.record(), "value")?.value(), "blob")?;
            let blob = required(value.blob(), "slice")?.as_slice();
            mutation_macs.push(&blob[blob.len().saturating_sub(32)..]);
        }
        let version = required(msg.version(), "version")?.version().unwrap_or(0);
        let snapshot_mac = required(msg.snapshot_mac(), "snapshotMac")?;
        let patch_mac = generate_patch_mac(snapshot_mac.as_slice(), &mutation_macs, version, name.as_str(), &main_key.patch_mac_key)?;
        if patch_mac.as_slice() != required(msg.patch_mac(), "patchMac")?.as_slice() {
            return Err(Boom::new("Invalid patch mac"));
        }
    }
    decode_syncd_mutations(msg.mutations(), initial_state, get_app_state_sync_key, on_mutation, validate_macs)
}
/// One entry of the result of `extractSyncdPatches`.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SyncdCollection {
    pub patches: Vec<SyncdPatch>,
    pub has_more_patches: bool,
    pub snapshot: Option<SyncdSnapshot>,
}
/// `Buffer.from(Object.values(content))`, with `None` for content that JavaScript sees as false.
fn content_bytes(content: Option<&Content>) -> Option<Vec<u8>> {
    match content? {
        Content::Binary(b) => Some(b.to_vec()),
        Content::Nodes(n) => Some(vec![0u8; n.len()]),
        Content::Text(t) if t.as_str().is_empty() => None,
        Content::Text(t) => Some(t.as_str().chars().map(|c| c.to_digit(10).unwrap_or(0) as u8).collect()),
    }
}
/// `+attrs.version + 1`. A version that is not a number gives NaN, which writes as 0.
fn next_version(attr: Option<&str>) -> u64 {
    let Some(a) = attr else { return 0 };
    let t = a.trim();
    let n = if t.is_empty() { 0.0 } else { t.parse::<f64>().unwrap_or(f64::NAN) };
    (n + 1.0) as u64
}
pub fn extract_syncd_patches(result: &BinaryNode, download: &DownloadExternalBlob<'_>) -> Result<JsMap<SyncdCollection>> {
    let sync_node = get_binary_node_child(Some(result), "sync");
    let mut out = JsMap::new();
    for collection_node in get_binary_node_children(sync_node, "collection") {
        let patches_node = get_binary_node_child(Some(collection_node), "patches");
        let patches = get_binary_node_children(Some(patches_node.unwrap_or(collection_node)), "patch");
        let snapshot_node = get_binary_node_child(Some(collection_node), "snapshot");
        let name = collection_node.attr("name").unwrap_or("undefined");
        let has_more_patches = collection_node.attr("has_more_patches") == Some("true");
        let mut snapshot = None;
        if let Some(content) = content_bytes(snapshot_node.and_then(|n| n.content.as_ref())) {
            let blob_ref = ExternalBlobReference::decode(&content)?;
            let data = download_external_blob(&blob_ref, download)?;
            snapshot = Some(SyncdSnapshot::decode(&data)?);
        }
        let mut syncds = Vec::with_capacity(patches.len());
        for patch in patches {
            if let Some(content) = content_bytes(patch.content.as_ref()) {
                let mut syncd = SyncdPatch::decode(&content)?;
                if syncd.version().is_none() {
                    syncd.version_mut().set_version(next_version(collection_node.attr("version")));
                }
                syncds.push(syncd);
            }
        }
        out.insert(name, SyncdCollection { patches: syncds, has_more_patches, snapshot });
    }
    Ok(out)
}
pub fn download_external_blob(blob: &ExternalBlobReference, download: &DownloadExternalBlob<'_>) -> Result<Vec<u8>> {
    download(blob)
}
pub fn download_external_patch(blob: &ExternalBlobReference, download: &DownloadExternalBlob<'_>) -> Result<SyncdMutations> {
    let buffer = download_external_blob(blob, download)?;
    Ok(SyncdMutations::decode(&buffer)?)
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DecodedSyncd {
    pub state: LtHashState,
    pub mutation_map: ChatMutationMap,
}
fn mutation_key(mutation: &ChatMutation) -> String {
    String::from_utf8_lossy(mutation.sync_action.index().map_or(&[][..], |b| b.as_slice())).into_owned()
}
fn log_fields(name: WAPatchName, version: Json) -> Vec<(String, Json)> {
    vec![("name".to_string(), Json::Str(name.as_str().to_string())), ("version".to_string(), version)]
}
pub fn decode_syncd_snapshot(name: WAPatchName, snapshot: &SyncdSnapshot, get_app_state_sync_key: &FetchAppStateSyncKey<'_>, minimum_version_number: Option<u64>, validate_macs: bool, logger: Option<&dyn Logger>) -> Result<DecodedSyncd> {
    let mut new_state = new_lt_hash_state();
    new_state.version = required(snapshot.version(), "version")?.version().unwrap_or(0);
    let mut mutation_map = ChatMutationMap::new();
    let are_mutations_required = minimum_version_number.is_none_or(|m| new_state.version > m);
    let mut on_mutation = |mutation: ChatMutation| {
        if are_mutations_required {
            mutation_map.insert(mutation_key(&mutation), mutation);
        }
    };
    let result = decode_syncd_mutations(snapshot.records(), &new_state, get_app_state_sync_key, &mut on_mutation, validate_macs)?;
    new_state.hash = result.hash;
    new_state.index_value_map = result.index_value_map;
    if validate_macs {
        let key_id = required(required(snapshot.key_id(), "id")?.id(), "id")?;
        let base64_key = base64_encode(key_id.as_slice());
        let Some(key_enc) = get_app_state_sync_key(&base64_key)? else {
            return Err(missing_key(format!("failed to find key \"{base64_key}\" to decode mutation"), None));
        };
        let keys = keys_of(&key_enc)?;
        let computed_snapshot_mac = generate_snapshot_mac(&new_state.hash, new_state.version, name.as_str(), &keys.snapshot_mac_key)?;
        if required(snapshot.mac(), "mac")?.as_slice() != computed_snapshot_mac.as_slice() {
            // LTHash verification may fail when decodeSyncdMutations skipped undecryptable
            // records (poisoned server-side snapshot); the aggregate client hash diverges
            // from the server-computed mac. Fall through with a warning so the session stays
            // alive with partial state, symmetric to how decodePatches handles its own
            // LTHash mismatch a few lines below.
            if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Warn)) {
                l.warn_obj(&Json::Obj(log_fields(name, Json::Num(new_state.version as f64))), "LTHash verification failed on snapshot, continuing with partial state");
            }
        }
    }
    Ok(DecodedSyncd { state: new_state, mutation_map })
}
/// The `mutations` of a patch that was decoded are cleared, and external mutations are added to it, as upstream does.
#[allow(clippy::too_many_arguments)]
pub fn decode_patches(name: WAPatchName, syncds: &mut [SyncdPatch], initial: &LtHashState, get_app_state_sync_key: &FetchAppStateSyncKey<'_>, download: &DownloadExternalBlob<'_>, minimum_version_number: Option<u64>, logger: Option<&dyn Logger>, validate_macs: bool) -> Result<DecodedSyncd> {
    let mut new_state = initial.clone();
    let mut mutation_map = ChatMutationMap::new();
    for syncd in syncds.iter_mut() {
        let version_json = |p: &SyncdPatch| p.version().map_or(Json::Null, PbMessage::to_json);
        if let Some(external) = syncd.external_mutations().cloned() {
            if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Trace)) {
                l.trace_obj(&Json::Obj(log_fields(name, version_json(syncd))), "downloading external patch");
            }
            let downloaded = download_external_patch(&external, download)?;
            if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Debug)) {
                let mut fields = log_fields(name, version_json(syncd));
                fields.push(("mutations".to_string(), Json::Num(downloaded.mutations().len() as f64)));
                l.debug_obj(&Json::Obj(fields), "downloaded external patch");
            }
            syncd.mutations_mut().extend_from_slice(downloaded.mutations());
        }
        let patch_version = required(syncd.version(), "version")?.version().unwrap_or(0);
        new_state.version = patch_version;
        let should_mutate = minimum_version_number.is_none_or(|m| patch_version > m);
        let mut on_mutation = |mutation: ChatMutation| {
            if should_mutate {
                mutation_map.insert(mutation_key(&mutation), mutation);
            }
        };
        let decode_result = match decode_syncd_patch(syncd, name, &new_state, get_app_state_sync_key, &mut on_mutation, validate_macs) {
            Ok(r) => r,
            Err(err) => {
                if is_missing_key_error(&err) {
                    return Err(err);
                }
                if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Warn)) {
                    let mut fields = log_fields(name, Json::Num(patch_version as f64));
                    fields.push(("error".to_string(), Json::Str(err.message.clone())));
                    l.warn_obj(&Json::Obj(fields), "failed to decode patch, skipping");
                }
                continue;
            }
        };
        new_state.hash = decode_result.hash;
        new_state.index_value_map = decode_result.index_value_map;
        if validate_macs {
            let key_id = required(required(syncd.key_id(), "id")?.id(), "id")?;
            let base64_key = base64_encode(key_id.as_slice());
            let Some(key_enc) = get_app_state_sync_key(&base64_key)? else {
                return Err(missing_key(format!("failed to find key \"{base64_key}\" to decode mutation"), None));
            };
            let keys = keys_of(&key_enc)?;
            let computed_snapshot_mac = generate_snapshot_mac(&new_state.hash, new_state.version, name.as_str(), &keys.snapshot_mac_key)?;
            if required(syncd.snapshot_mac(), "snapshotMac")?.as_slice() != computed_snapshot_mac.as_slice() {
                if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Warn)) {
                    l.warn_obj(&Json::Obj(log_fields(name, Json::Num(new_state.version as f64))), "LTHash verification failed, skipping remaining patches");
                }
                break;
            }
        }
        // clear memory used up by the mutations
        syncd.clear_mutations();
    }
    Ok(DecodedSyncd { state: new_state, mutation_map })
}
fn bad_last_message(message: &str, key: &MessageKey, timestamp: Option<u64>) -> Boom {
    let data = Json::Obj(vec![("key".to_string(), key.to_json()), ("messageTimestamp".to_string(), timestamp.map_or(Json::Null, |t| Json::Num(t as f64)))]);
    Boom { status_code: Some(400), ..Boom::with_data(message, data) }
}
fn get_message_range(last_messages: &LastMessageList) -> Result<SyncActionMessageRange> {
    let list = match last_messages {
        LastMessageList::Range(r) => return Ok(r.clone()),
        LastMessageList::Messages(list) => list,
    };
    let mut range = SyncActionMessageRange::new();
    if let Some(t) = list.last().and_then(|m| m.message_timestamp) {
        range.set_last_message_timestamp(t as i64);
    }
    if list.is_empty() {
        return Ok(range);
    }
    let mut messages = Vec::with_capacity(list.len());
    for m in list {
        let filled = |s: Option<&Str>| s.is_some_and(|v| !v.as_str().is_empty());
        if !filled(m.key.id()) || !filled(m.key.remote_jid()) {
            return Err(bad_last_message("Incomplete key", &m.key, m.message_timestamp));
        }
        let group = m.key.remote_jid().is_some_and(|j| is_jid_group(j.as_str()));
        if group && !m.key.from_me().unwrap_or(false) && !filled(m.key.participant()) {
            return Err(bad_last_message("Expected not from me message to have participant", &m.key, m.message_timestamp));
        }
        if m.message_timestamp.unwrap_or(0) == 0 {
            return Err(bad_last_message("Missing timestamp in last message list", &m.key, m.message_timestamp));
        }
        let mut key = m.key.clone();
        if let Some(p) = m.key.participant().filter(|p| !p.as_str().is_empty()) {
            key.set_participant(jid_normalized_user(p.as_str()));
        }
        // upstream hands over `{ key, messageTimestamp }`. The proto field is `timestamp`, so only the key reaches the wire.
        messages.push(SyncActionMessage::new().with_key(key));
    }
    range.set_messages(messages);
    Ok(range)
}
fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}
pub fn chat_modification_to_app_patch(modification: &ChatModification, jid: &str) -> Result<WAPatchCreate> {
    use LabelAssociationType as L;
    let set = SyncdOperation::SET;
    let new = SyncActionValue::new;
    let (mut sync_action, index, ty, api_version, operation) = match modification {
        ChatModification::Mute(mute) => {
            let mut a = MuteAction::new().with_muted(mute.unwrap_or(0) != 0);
            if let Some(m) = mute.filter(|m| *m != 0) {
                a.set_mute_end_timestamp(m as i64);
            }
            (new().with_mute_action(a), strs(&["mute", jid]), WAPatchName::RegularHigh, 2, set)
        }
        ChatModification::Archive { archive, last_messages } => {
            let a = ArchiveChatAction::new().with_archived(*archive).with_message_range(get_message_range(last_messages)?);
            (new().with_archive_chat_action(a), strs(&["archive", jid]), WAPatchName::RegularLow, 3, set)
        }
        ChatModification::MarkRead { mark_read, last_messages } => {
            let a = MarkChatAsReadAction::new().with_read(*mark_read).with_message_range(get_message_range(last_messages)?);
            (new().with_mark_chat_as_read_action(a), strs(&["markChatAsRead", jid]), WAPatchName::RegularLow, 3, set)
        }
        ChatModification::DeleteForMe { delete_media, key, timestamp } => {
            let a = DeleteMessageForMeAction::new().with_delete_media(*delete_media).with_message_timestamp(*timestamp as i64);
            let id = key.id().map_or("", |s| s.as_str());
            let from_me = if key.from_me().unwrap_or(false) { "1" } else { "0" };
            (new().with_delete_message_for_me_action(a), strs(&["deleteMessageForMe", jid, id, from_me, "0"]), WAPatchName::RegularHigh, 3, set)
        }
        ChatModification::Clear { last_messages, .. } => {
            let a = ClearChatAction::new().with_message_range(get_message_range(last_messages)?);
            // the option here is 0 when keep starred messages is enabled
            (new().with_clear_chat_action(a), strs(&["clearChat", jid, "1", "0"]), WAPatchName::RegularHigh, 6, set)
        }
        ChatModification::Pin(pin) => (new().with_pin_action(PinAction::new().with_pinned(*pin)), strs(&["pin_v1", jid]), WAPatchName::RegularLow, 5, set),
        ChatModification::Contact(contact) => {
            let operation = if contact.is_some() { set } else { SyncdOperation::REMOVE };
            (new().with_contact_action(contact.clone().unwrap_or_default()), strs(&["contact", jid]), WAPatchName::CriticalUnblockLow, 2, operation)
        }
        ChatModification::DisableLinkPreviews(a) => (new().with_privacy_setting_disable_link_previews_action(a.clone()), strs(&["setting_disableLinkPreviews"]), WAPatchName::Regular, 8, set),
        ChatModification::Star { messages, star } => {
            let Some(key) = messages.first() else {
                return Err(Boom::type_error("Cannot read properties of undefined (reading 'id')"));
            };
            let from_me = if key.from_me.unwrap_or(false) { "1" } else { "0" };
            (new().with_star_action(StarAction::new().with_starred(*star)), strs(&["star", jid, &key.id, from_me, "0"]), WAPatchName::RegularLow, 2, set)
        }
        ChatModification::Delete { last_messages } => {
            let a = DeleteChatAction::new().with_message_range(get_message_range(last_messages)?);
            (new().with_delete_chat_action(a), strs(&["deleteChat", jid, "1"]), WAPatchName::RegularHigh, 6, set)
        }
        ChatModification::PushNameSetting(name) => (new().with_push_name_setting(PushNameSetting::new().with_name(name.as_str())), strs(&["setting_pushName"]), WAPatchName::CriticalBlock, 1, set),
        ChatModification::QuickReply(q) => {
            let text = |s: Option<&Str>| s.map_or(String::new(), |v| v.as_str().to_string());
            let a = QuickReplyAction::new()
                .with_count(0)
                .with_deleted(q.action.deleted().unwrap_or(false))
                .with_message(text(q.action.message()).as_str())
                .with_shortcut(text(q.action.shortcut()).as_str());
            let timestamp = match q.timestamp.as_deref().filter(|t| !t.is_empty()) {
                Some(t) => t.to_string(),
                None => js_number(now_ms().div_euclid(1000) as f64),
            };
            (new().with_quick_reply_action(a), strs(&["quick_reply", &timestamp]), WAPatchName::Regular, 2, set)
        }
        ChatModification::AddLabel(l) => {
            let mut a = LabelEditAction::new();
            if let Some(v) = &l.name {
                a.set_name(v.as_str());
            }
            if let Some(v) = l.color {
                a.set_color(v);
            }
            if let Some(v) = l.predefined_id {
                a.set_predefined_id(v);
            }
            if let Some(v) = l.deleted {
                a.set_deleted(v);
            }
            (new().with_label_edit_action(a), strs(&["label_edit", &l.id]), WAPatchName::Regular, 3, set)
        }
        ChatModification::AddChatLabel(l) => (new().with_label_association_action(LabelAssociationAction::new().with_labeled(true)), strs(&[L::Chat.as_str(), &l.label_id, jid]), WAPatchName::Regular, 3, set),
        ChatModification::RemoveChatLabel(l) => (new().with_label_association_action(LabelAssociationAction::new().with_labeled(false)), strs(&[L::Chat.as_str(), &l.label_id, jid]), WAPatchName::Regular, 3, set),
        ChatModification::AddMessageLabel(l) => (new().with_label_association_action(LabelAssociationAction::new().with_labeled(true)), strs(&[L::Message.as_str(), &l.label_id, jid, &l.message_id, "0", "0"]), WAPatchName::Regular, 3, set),
        ChatModification::RemoveMessageLabel(l) => (new().with_label_association_action(LabelAssociationAction::new().with_labeled(false)), strs(&[L::Message.as_str(), &l.label_id, jid, &l.message_id, "0", "0"]), WAPatchName::Regular, 3, set),
    };
    sync_action.set_timestamp(now_ms());
    Ok(WAPatchCreate { sync_action, index, r#type: ty, api_version, operation })
}
fn is_valid_patch_based_on_message_range(chat: &Chat, msg_range: &SyncActionMessageRange) -> bool {
    // a decoded int64 is a Long object, which JavaScript sees as true even when it is 0: only a null value falls through
    let last_msg_timestamp = msg_range.last_message_timestamp().or(msg_range.last_system_message_timestamp()).unwrap_or(0);
    let chat_last_msg_timestamp = chat.last_message_recv_timestamp().unwrap_or(0);
    last_msg_timestamp as f64 >= chat_last_msg_timestamp as f64
}
fn get_chat_update_conditional(is_initial_sync: bool, id: Option<&str>, msg_range: Option<&SyncActionMessageRange>) -> Option<ChatUpdateConditional> {
    if !is_initial_sync {
        return None;
    }
    let id = id.unwrap_or("undefined").to_string();
    let msg_range = msg_range.cloned();
    Some(Arc::new(move |data: &BufferedEventData| {
        let chat = data.history_sets.chats.get(&id).or_else(|| data.chat_upserts.get(&id))?;
        Some(match &msg_range {
            Some(r) => is_valid_patch_based_on_message_range(chat, r),
            None => true,
        })
    }))
}
fn chat_update(id: Option<&str>, conditional: Option<ChatUpdateConditional>) -> ChatUpdate {
    let mut update = ChatUpdate { chat: Chat::new(), conditional };
    if let Some(i) = id {
        update.set_id(i);
    }
    update
}
fn message_key(id: Option<&str>, msg_id: Option<&str>, from_me: Option<&str>) -> WAMessageKey {
    let mut key = WAMessageKey::new();
    if let Some(v) = id {
        key.set_remote_jid(v);
    }
    if let Some(v) = msg_id {
        key.set_id(v);
    }
    key.set_from_me(from_me == Some("1"));
    key
}
fn truthy(s: Option<&Str>) -> Option<&str> {
    s.map(|v| v.as_str()).filter(|v| !v.is_empty())
}
fn mutation_json(m: &ChatMutation) -> Json {
    Json::Obj(vec![("syncAction".to_string(), m.sync_action.to_json()), ("index".to_string(), Json::Arr(m.index.iter().map(|s| Json::Str(s.clone())).collect()))])
}
pub fn process_sync_action(sync_action: &ChatMutation, ev: &dyn BaileysEventEmitter, me: Option<&Contact>, initial_sync_opts: Option<&mut InitialAppStateSyncOptions>, logger: Option<&dyn Logger>) {
    let is_initial_sync = initial_sync_opts.is_some();
    if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Trace)) {
        let obj = Json::Obj(vec![("syncAction".to_string(), mutation_json(sync_action)), ("initialSync".to_string(), Json::Bool(is_initial_sync))]);
        l.trace_obj(&obj, "processing sync action");
    }
    let unarchive_chats = initial_sync_opts.as_ref().is_some_and(|o| o.account_settings.unarchive_chats);
    let action = sync_action.sync_action.value();
    let at = |i: usize| sync_action.index.get(i).map(String::as_str);
    let (ty, id, msg_id, from_me) = (at(0), at(1), at(2), at(3));
    let conditional = |msg_range: Option<&SyncActionMessageRange>| get_chat_update_conditional(is_initial_sync, id, msg_range);
    let emit_settings = |s: SettingsUpdate| {
        ev.emit(BaileysEvent::SettingsUpdate(s));
    };
    let id_or_empty = id.unwrap_or("").to_string();
    if let Some(mute) = action.and_then(|a| a.mute_action()) {
        let mut update = chat_update(id, conditional(None));
        if mute.muted().unwrap_or(false) {
            update.set_mute_end_time(mute.mute_end_timestamp().unwrap_or(0) as u64);
        } else {
            update.set_mute_end_time_null();
        }
        ev.emit(BaileysEvent::ChatsUpdate(vec![update]));
    } else if action.is_some_and(|a| a.archive_chat_action().is_some()) || ty == Some("archive") || ty == Some("unarchive") {
        // okay so we've to do some annoying computation here
        // when we're initially syncing the app state
        // there are a few cases we need to handle
        // 1. if the account unarchiveChats setting is true
        //   a. if the chat is archived, and no further messages have been received -- simple, keep archived
        //   b. if the chat was archived, and the user received messages from the other person afterwards
        //		then the chat should be marked unarchved --
        //		we compare the timestamp of latest message from the other person to determine this
        // 2. if the account unarchiveChats setting is false -- then it doesn't matter,
        //	it'll always take an app state action to mark in unarchived -- which we'll get anyway
        let archive_action = action.and_then(|a| a.archive_chat_action());
        let is_archived = match archive_action {
            Some(a) => a.archived(),
            None => Some(ty == Some("archive")),
        };
        let msg_range = if unarchive_chats { archive_action.and_then(|a| a.message_range()) } else { None };
        let mut update = chat_update(id, conditional(msg_range));
        match is_archived {
            Some(v) => update.set_archived(v),
            None => update.set_archived_null(),
        }
        ev.emit(BaileysEvent::ChatsUpdate(vec![update]));
    } else if let Some(mark_read_action) = action.and_then(|a| a.mark_chat_as_read_action()) {
        // basically we don't need to fire an "read" update if the chat is being marked as read
        // because the chat is read by default
        // this only applies for the initial sync
        let read = mark_read_action.read().unwrap_or(false);
        let mut update = chat_update(id, conditional(mark_read_action.message_range()));
        if is_initial_sync && read {
            update.set_unread_count_null();
        } else {
            update.set_unread_count(if read { 0 } else { -1 });
        }
        ev.emit(BaileysEvent::ChatsUpdate(vec![update]));
    } else if action.is_some_and(|a| a.delete_message_for_me_action().is_some()) || ty == Some("deleteMessageForMe") {
        ev.emit(BaileysEvent::MessagesDelete(MessagesDelete::Keys(vec![message_key(id, msg_id, from_me)])));
    } else if let Some(contact_action) = action.and_then(|a| a.contact_action()) {
        emit_sync_action_results(ev, process_contact_action(contact_action, id, logger));
    } else if let Some(push_name) = action.and_then(|a| a.push_name_setting()) {
        if let Some(name) = truthy(push_name.name()) {
            if me.and_then(|m| m.name.as_deref()) != Some(name) {
                let mut contact = me.cloned().unwrap_or_default();
                contact.name = Some(name.to_string());
                ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { me: Some(Some(contact)), ..CredsUpdate::default() })));
            }
        }
    } else if let Some(pin) = action.and_then(|a| a.pin_action()) {
        let mut update = chat_update(id, conditional(None));
        if pin.pinned().unwrap_or(false) {
            // adapted: `pinned` is a uint32 in the proto. A larger JavaScript number keeps its low bits, as it does on the wire.
            update.set_pinned(action.and_then(|a| a.timestamp()).unwrap_or(0) as u32);
        } else {
            update.set_pinned_null();
        }
        ev.emit(BaileysEvent::ChatsUpdate(vec![update]));
    } else if let Some(setting) = action.and_then(|a| a.unarchive_chats_setting()) {
        let unarchive = setting.unarchive_chats().unwrap_or(false);
        ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { account_settings: Some(AccountSettings { unarchive_chats: unarchive, default_disappearing_mode: None }), ..CredsUpdate::default() })));
        if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Info)) {
            let shown = setting.unarchive_chats().map_or("null", |v| if v { "true" } else { "false" });
            l.info(&format!("archive setting updated => '{shown}'"));
        }
        if let Some(opts) = initial_sync_opts {
            opts.account_settings.unarchive_chats = unarchive;
        }
    } else if action.is_some_and(|a| a.star_action().is_some()) || ty == Some("star") {
        let starred = action.and_then(|a| a.star_action()).and_then(|s| s.starred()).unwrap_or_else(|| sync_action.index.last().map(String::as_str) == Some("1"));
        ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key: message_key(id, msg_id, from_me), update: WebMessageInfo::new().with_starred(starred) }]));
    } else if action.is_some_and(|a| a.delete_chat_action().is_some()) || ty == Some("deleteChat") {
        if !is_initial_sync {
            ev.emit(BaileysEvent::ChatsDelete(vec![id_or_empty]));
        }
    } else if let Some(edit) = action.and_then(|a| a.label_edit_action()) {
        ev.emit(BaileysEvent::LabelsEdit(Label {
            id: id_or_empty,
            name: edit.name().map_or(String::new(), |n| n.as_str().to_string()),
            color: edit.color().unwrap_or(0),
            deleted: edit.deleted().unwrap_or(false),
            predefined_id: edit.predefined_id().filter(|p| *p != 0).map(|p| p.to_string()),
        }));
    } else if let Some(association) = action.and_then(|a| a.label_association_action()) {
        let owned = |i: usize| at(i).unwrap_or("").to_string();
        let value = if ty == Some(LabelAssociationType::Chat.as_str()) {
            LabelAssociation::Chat(ChatLabelAssociation { chat_id: owned(2), label_id: owned(1) })
        } else {
            LabelAssociation::Message(MessageLabelAssociation { chat_id: owned(2), message_id: owned(3), label_id: owned(1) })
        };
        let kind = if association.labeled().unwrap_or(false) { ListUpdateType::Add } else { ListUpdateType::Remove };
        ev.emit(BaileysEvent::LabelsAssociation { r#type: kind, association: value });
    } else if let Some(locale) = truthy(action.and_then(|a| a.locale_setting()).and_then(|l| l.locale())) {
        emit_settings(SettingsUpdate::Locale(locale.to_string()));
    } else if let Some(a) = action.and_then(|a| a.time_format_action()) {
        emit_settings(SettingsUpdate::TimeFormat(a.clone()));
    } else if let Some(a) = action.and_then(|a| a.pn_for_lid_chat_action()) {
        if let Some(pn) = truthy(a.pn_jid()) {
            ev.emit(BaileysEvent::LidMappingUpdate(LidMapping { lid: id_or_empty, pn: pn.to_string() }));
        }
    } else if let Some(a) = action.and_then(|a| a.privacy_setting_relay_all_calls()) {
        emit_settings(SettingsUpdate::PrivacySettingRelayAllCalls(a.clone()));
    } else if let Some(a) = action.and_then(|a| a.status_privacy()) {
        emit_settings(SettingsUpdate::StatusPrivacy(a.clone()));
    } else if let Some(a) = action.and_then(|a| a.lock_chat_action()) {
        ev.emit(BaileysEvent::ChatsLock { id: id_or_empty, locked: a.locked().unwrap_or(false) });
    } else if let Some(a) = action.and_then(|a| a.privacy_setting_disable_link_previews_action()) {
        emit_settings(SettingsUpdate::DisableLinkPreviews(a.clone()));
    } else if let Some(v) = action.and_then(|a| a.notification_activity_setting_action()).and_then(|a| a.notification_activity_setting()).filter(|v| v.0 != 0) {
        emit_settings(SettingsUpdate::NotificationActivitySetting(v));
    } else if let Some(a) = action.and_then(|a| a.lid_contact_action()) {
        let mut contact = Contact::new(id_or_empty.as_str());
        contact.name = truthy(a.full_name()).or(truthy(a.first_name())).or(truthy(a.username())).map(str::to_string);
        contact.username = truthy(a.username()).map(str::to_string);
        contact.lid = Some(id_or_empty);
        ev.emit(BaileysEvent::ContactsUpsert(vec![contact]));
    } else if let Some(a) = action.and_then(|a| a.privacy_setting_channels_personalised_recommendation_action()) {
        emit_settings(SettingsUpdate::ChannelsPersonalisedRecommendation(a.clone()));
    } else if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Debug)) {
        let obj = Json::Obj(vec![("syncAction".to_string(), mutation_json(sync_action)), ("id".to_string(), id.map_or(Json::Null, |v| Json::Str(v.to_string())))]);
        l.debug_obj(&obj, "unprocessable update");
    }
}
