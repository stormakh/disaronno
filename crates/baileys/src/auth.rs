//! Key store contract and credentials, same shape as Types/Auth.ts.
use crate::crypto::{KeyPair, SignedKeyPair};
use crate::error::Result;
use crate::signal::group::SenderKeyRecord;
use crate::signal::session::SessionRecord;
use crate::types::{Contact, MinimalMessage};
use crate::utils::generics::JsMap;
use rustc_hash::FxHashMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use waproto::ADVSignedDeviceIdentity;
use waproto::message::AppStateSyncKeyData;
use waproto::pb::{Bytes, Json};

#[derive(Clone, Debug, PartialEq, Default)]
pub struct LtHashState {
    pub version: u64,
    pub hash: Vec<u8>,
    pub index_value_map: HashMap<String, Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LidMapping {
    pub pn: String,
    pub lid: String,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TcTokenEntry {
    pub token: Bytes,
    pub timestamp: Option<String>,
    pub sender_timestamp: Option<f64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyKind {
    PreKey,
    Session,
    SenderKey,
    SenderKeyMemory,
    AppStateSyncKey,
    AppStateSyncVersion,
    LidMapping,
    DeviceList,
    TcToken,
    IdentityKey,
}
impl KeyKind {
    /// The name used for the data type in Baileys and in its files on disk.
    pub fn name(self) -> &'static str {
        match self {
            KeyKind::PreKey => "pre-key",
            KeyKind::Session => "session",
            KeyKind::SenderKey => "sender-key",
            KeyKind::SenderKeyMemory => "sender-key-memory",
            KeyKind::AppStateSyncKey => "app-state-sync-key",
            KeyKind::AppStateSyncVersion => "app-state-sync-version",
            KeyKind::LidMapping => "lid-mapping",
            KeyKind::DeviceList => "device-list",
            KeyKind::TcToken => "tctoken",
            KeyKind::IdentityKey => "identity-key",
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum KeyValue {
    PreKey(KeyPair),
    Session(Arc<SessionRecord>),
    SenderKey(Arc<SenderKeyRecord>),
    SenderKeyMemory(HashMap<String, bool>),
    AppStateSyncKey(AppStateSyncKeyData),
    AppStateSyncVersion(LtHashState),
    LidMapping(String),
    DeviceList(Vec<String>),
    TcToken(TcTokenEntry),
    IdentityKey(Bytes),
}
pub type KeyMap = FxHashMap<String, KeyValue>;
/// One write. `None` deletes the entry.
pub type KeyWrite = (KeyKind, String, Option<KeyValue>);

pub trait SignalKeyStore: Send + Sync {
    fn get(&self, kind: KeyKind, ids: &[String]) -> Result<KeyMap>;
    fn set(&self, data: Vec<KeyWrite>) -> Result<()>;
    fn get_one(&self, kind: KeyKind, id: &str) -> Result<Option<KeyValue>> {
        let ids = [id.to_string()];
        Ok(self.get(kind, &ids)?.remove(id))
    }
    fn set_one(&self, kind: KeyKind, id: &str, v: Option<KeyValue>) -> Result<()> {
        self.set(vec![(kind, id.to_string(), v)])
    }
    fn clear(&self) -> Result<()> {
        Ok(())
    }
    fn is_in_transaction(&self) -> bool {
        false
    }
    fn transaction(&self, work: &mut dyn FnMut() -> Result<()>, _key: &str) -> Result<()> {
        work()
    }
}

/// Simple in-memory store, for tests and short-lived clients.
#[derive(Default)]
pub struct MemoryKeyStore {
    data: Mutex<HashMap<KeyKind, FxHashMap<String, KeyValue>>>,
}
impl MemoryKeyStore {
    pub fn new() -> MemoryKeyStore {
        MemoryKeyStore::default()
    }
}
impl SignalKeyStore for MemoryKeyStore {
    fn get(&self, kind: KeyKind, ids: &[String]) -> Result<KeyMap> {
        let d = self.data.lock().unwrap();
        let mut o = KeyMap::default();
        if let Some(m) = d.get(&kind) {
            for id in ids {
                if let Some(v) = m.get(id) {
                    o.insert(id.clone(), v.clone());
                }
            }
        }
        Ok(o)
    }
    fn get_one(&self, kind: KeyKind, id: &str) -> Result<Option<KeyValue>> {
        Ok(self.data.lock().unwrap().get(&kind).and_then(|m| m.get(id).cloned()))
    }
    fn set(&self, data: Vec<KeyWrite>) -> Result<()> {
        let mut d = self.data.lock().unwrap();
        for (k, id, v) in data {
            let m = d.entry(k).or_default();
            match v {
                Some(v) => {
                    m.insert(id, v);
                }
                None => {
                    m.remove(&id);
                }
            }
        }
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        self.data.lock().unwrap().clear();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignalCreds {
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    pub registration_id: u32,
}
impl SignalCreds {
    pub fn from_auth(c: &AuthenticationCreds) -> SignalCreds {
        SignalCreds { signed_identity_key: c.signed_identity_key.clone(), signed_pre_key: c.signed_pre_key.clone(), registration_id: c.registration_id }
    }
}
/// `SignalDataSet`, grouped by kind. `None` deletes the entry.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct SignalDataSet(pub Vec<(KeyKind, JsMap<Option<KeyValue>>)>);
impl SignalDataSet {
    pub fn from_writes(data: Vec<KeyWrite>) -> SignalDataSet {
        let mut s = SignalDataSet::default();
        for (k, id, v) in data {
            s.entry(k).insert(id, v);
        }
        s
    }
    pub fn entry(&mut self, kind: KeyKind) -> &mut JsMap<Option<KeyValue>> {
        let i = match self.0.iter().position(|(k, _)| *k == kind) {
            Some(i) => i,
            None => {
                self.0.push((kind, JsMap::new()));
                self.0.len() - 1
            }
        };
        &mut self.0[i].1
    }
    pub fn get(&self, kind: KeyKind) -> Option<&JsMap<Option<KeyValue>>> {
        self.0.iter().find(|(k, _)| *k == kind).map(|(_, m)| m)
    }
    pub fn into_writes(self) -> Vec<KeyWrite> {
        let mut o = Vec::new();
        for (k, m) in self.0 {
            for (id, v) in m.into_pairs() {
                o.push((k, id, v));
            }
        }
        o
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionCapabilityOptions {
    pub max_commit_retries: u32,
    pub delay_between_tries_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProtocolAddress {
    /// jid
    pub name: String,
    pub device_id: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SignalIdentity {
    pub identifier: ProtocolAddress,
    pub identifier_key: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DefaultDisappearingMode {
    pub ephemeral_expiration: Option<u32>,
    pub ephemeral_setting_timestamp: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct AccountSettings {
    /// unarchive chats when a new message is received
    pub unarchive_chats: bool,
    /// the default mode to start new conversations with
    pub default_disappearing_mode: Option<DefaultDisappearingMode>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationCreds {
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedKeyPair,
    /// The optional `timestampS` of `signedPreKey`. Upstream only keeps it.
    pub signed_pre_key_timestamp_s: Option<u64>,
    pub registration_id: u32,
    pub noise_key: KeyPair,
    pub pairing_ephemeral_key_pair: KeyPair,
    pub adv_secret_key: String,
    pub me: Option<Contact>,
    pub account: Option<ADVSignedDeviceIdentity>,
    pub signal_identities: Option<Vec<SignalIdentity>>,
    pub my_app_state_key_id: Option<String>,
    pub first_unuploaded_pre_key_id: u32,
    pub next_pre_key_id: u32,
    pub last_account_sync_timestamp: Option<u64>,
    pub platform: Option<String>,
    pub processed_history_messages: Vec<MinimalMessage>,
    /// number of times history & app state has been synced
    pub account_sync_counter: u32,
    pub account_settings: AccountSettings,
    pub registered: bool,
    pub pairing_code: Option<String>,
    pub last_prop_hash: Option<String>,
    pub routing_info: Option<Bytes>,
    pub additional_data: Option<Json>,
}
/// `Partial<AuthenticationCreds>`. A field that is `None` is not in the update. The inner `Option`
/// of a field that can be undefined in the state uses `Some(None)` to clear the value.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CredsUpdate {
    pub signed_identity_key: Option<KeyPair>,
    pub signed_pre_key: Option<SignedKeyPair>,
    pub signed_pre_key_timestamp_s: Option<Option<u64>>,
    pub registration_id: Option<u32>,
    pub noise_key: Option<KeyPair>,
    pub pairing_ephemeral_key_pair: Option<KeyPair>,
    pub adv_secret_key: Option<String>,
    pub me: Option<Option<Contact>>,
    pub account: Option<Option<ADVSignedDeviceIdentity>>,
    pub signal_identities: Option<Option<Vec<SignalIdentity>>>,
    pub my_app_state_key_id: Option<Option<String>>,
    pub first_unuploaded_pre_key_id: Option<u32>,
    pub next_pre_key_id: Option<u32>,
    pub last_account_sync_timestamp: Option<Option<u64>>,
    pub platform: Option<Option<String>>,
    pub processed_history_messages: Option<Vec<MinimalMessage>>,
    pub account_sync_counter: Option<u32>,
    pub account_settings: Option<AccountSettings>,
    pub registered: Option<bool>,
    pub pairing_code: Option<Option<String>>,
    pub last_prop_hash: Option<Option<String>>,
    pub routing_info: Option<Option<Bytes>>,
    pub additional_data: Option<Option<Json>>,
}
impl AuthenticationCreds {
    /// Same as `Object.assign(creds, update)`.
    pub fn assign(&mut self, u: &CredsUpdate) {
        fn set<T: Clone>(a: &mut T, b: &Option<T>) {
            if let Some(v) = b {
                *a = v.clone();
            }
        }
        set(&mut self.signed_identity_key, &u.signed_identity_key);
        set(&mut self.signed_pre_key, &u.signed_pre_key);
        set(&mut self.signed_pre_key_timestamp_s, &u.signed_pre_key_timestamp_s);
        set(&mut self.registration_id, &u.registration_id);
        set(&mut self.noise_key, &u.noise_key);
        set(&mut self.pairing_ephemeral_key_pair, &u.pairing_ephemeral_key_pair);
        set(&mut self.adv_secret_key, &u.adv_secret_key);
        set(&mut self.me, &u.me);
        set(&mut self.account, &u.account);
        set(&mut self.signal_identities, &u.signal_identities);
        set(&mut self.my_app_state_key_id, &u.my_app_state_key_id);
        set(&mut self.first_unuploaded_pre_key_id, &u.first_unuploaded_pre_key_id);
        set(&mut self.next_pre_key_id, &u.next_pre_key_id);
        set(&mut self.last_account_sync_timestamp, &u.last_account_sync_timestamp);
        set(&mut self.platform, &u.platform);
        set(&mut self.processed_history_messages, &u.processed_history_messages);
        set(&mut self.account_sync_counter, &u.account_sync_counter);
        set(&mut self.account_settings, &u.account_settings);
        set(&mut self.registered, &u.registered);
        set(&mut self.pairing_code, &u.pairing_code);
        set(&mut self.last_prop_hash, &u.last_prop_hash);
        set(&mut self.routing_info, &u.routing_info);
        set(&mut self.additional_data, &u.additional_data);
    }
    /// All fields as an update, as `ev.emit('creds.update', creds)` passes the whole object.
    pub fn to_update(&self) -> CredsUpdate {
        CredsUpdate {
            signed_identity_key: Some(self.signed_identity_key.clone()),
            signed_pre_key: Some(self.signed_pre_key.clone()),
            signed_pre_key_timestamp_s: Some(self.signed_pre_key_timestamp_s),
            registration_id: Some(self.registration_id),
            noise_key: Some(self.noise_key.clone()),
            pairing_ephemeral_key_pair: Some(self.pairing_ephemeral_key_pair.clone()),
            adv_secret_key: Some(self.adv_secret_key.clone()),
            me: Some(self.me.clone()),
            account: Some(self.account.clone()),
            signal_identities: Some(self.signal_identities.clone()),
            my_app_state_key_id: Some(self.my_app_state_key_id.clone()),
            first_unuploaded_pre_key_id: Some(self.first_unuploaded_pre_key_id),
            next_pre_key_id: Some(self.next_pre_key_id),
            last_account_sync_timestamp: Some(self.last_account_sync_timestamp),
            platform: Some(self.platform.clone()),
            processed_history_messages: Some(self.processed_history_messages.clone()),
            account_sync_counter: Some(self.account_sync_counter),
            account_settings: Some(self.account_settings.clone()),
            registered: Some(self.registered),
            pairing_code: Some(self.pairing_code.clone()),
            last_prop_hash: Some(self.last_prop_hash.clone()),
            routing_info: Some(self.routing_info.clone()),
            additional_data: Some(self.additional_data.clone()),
        }
    }
}
/// The creds object that the socket and `saveCreds` share.
pub type SharedCreds = Arc<Mutex<AuthenticationCreds>>;
#[derive(Clone)]
pub struct SignalAuthState {
    pub creds: SignalCreds,
    pub keys: Arc<dyn SignalKeyStore>,
}
#[derive(Clone)]
pub struct AuthenticationState {
    pub creds: SharedCreds,
    pub keys: Arc<dyn SignalKeyStore>,
}
