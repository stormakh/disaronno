//! Same behavior as Utils/use-multi-file-auth-state.ts. The files stay readable by Baileys.
use crate::auth::*;
use crate::crypto::{KeyPair, SignedKeyPair};
use crate::error::{Boom, Result};
use crate::signal::group::SenderKeyRecord;
use crate::signal::session::SessionRecord;
use crate::types::{Contact, MinimalMessage};
use crate::utils::auth_utils::init_auth_creds;
use crate::utils::generics::buffer_json_parse;
use crate::utils::make_mutex::make_keyed_mutex;
use rustc_hash::FxHashMap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use waproto::pb::{Bytes, Json, PbMessage, bytes_from_json, js_number, u64_from_json};
use waproto::message::AppStateSyncKeyData;
use waproto::{ADVSignedDeviceIdentity, MessageKey};

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}
fn n(v: f64) -> Json {
    Json::Num(v)
}
fn b(v: &[u8]) -> Json {
    Json::Bytes(v.to_vec())
}
fn field(o: &mut Vec<(String, Json)>, k: &str, v: Json) {
    o.push((k.to_string(), v));
}
fn opt_str(o: &mut Vec<(String, Json)>, k: &str, v: Option<&str>) {
    if let Some(v) = v {
        field(o, k, s(v));
    }
}
fn str_of(j: &Json, k: &str) -> Option<String> {
    match j.get(k) {
        Some(Json::Str(v)) => Some(v.clone()),
        Some(Json::Num(v)) => Some(js_number(*v)),
        _ => None,
    }
}
fn num_of(j: &Json, k: &str) -> Option<f64> {
    j.get(k).and_then(|v| u64_or_f64(v))
}
fn u64_or_f64(v: &Json) -> Option<f64> {
    match v {
        Json::Num(n) => Some(*n),
        Json::Null => None,
        other => u64_from_json(other).ok().map(|x| x as f64),
    }
}
fn bytes_of(v: &Json) -> Result<Vec<u8>> {
    Ok(bytes_from_json(v)?.to_vec())
}
fn k32(v: &Json) -> Result<[u8; 32]> {
    bytes_of(v)?.as_slice().try_into().map_err(|_| Boom::new("invalid key length"))
}
pub fn key_pair_to_json(k: &KeyPair) -> Json {
    Json::Obj(vec![("private".to_string(), b(&k.private)), ("public".to_string(), b(&k.public))])
}
pub fn key_pair_from_json(j: &Json) -> Result<KeyPair> {
    let bad = || Boom::new("invalid key pair");
    Ok(KeyPair { private: k32(j.get("private").ok_or_else(bad)?)?, public: k32(j.get("public").ok_or_else(bad)?)? })
}
fn contact_to_json(c: &Contact) -> Json {
    let mut o = Vec::new();
    field(&mut o, "id", s(&c.id));
    opt_str(&mut o, "lid", c.lid.as_deref());
    opt_str(&mut o, "phoneNumber", c.phone_number.as_deref());
    opt_str(&mut o, "name", c.name.as_deref());
    opt_str(&mut o, "notify", c.notify.as_deref());
    opt_str(&mut o, "username", c.username.as_deref());
    opt_str(&mut o, "verifiedName", c.verified_name.as_deref());
    match &c.img_url {
        Some(Some(u)) => field(&mut o, "imgUrl", s(u)),
        Some(None) => field(&mut o, "imgUrl", Json::Null),
        None => {}
    }
    opt_str(&mut o, "status", c.status.as_deref());
    Json::Obj(o)
}
fn contact_from_json(j: &Json) -> Contact {
    Contact {
        id: str_of(j, "id").unwrap_or_default(),
        lid: str_of(j, "lid"),
        phone_number: str_of(j, "phoneNumber"),
        name: str_of(j, "name"),
        notify: str_of(j, "notify"),
        username: str_of(j, "username"),
        verified_name: str_of(j, "verifiedName"),
        img_url: match j.get("imgUrl") {
            Some(Json::Null) => Some(None),
            Some(Json::Str(u)) => Some(Some(u.clone())),
            _ => None,
        },
        status: str_of(j, "status"),
    }
}
/// A key in the JavaScript object form, with the fields that the proto form leaves out.
pub fn message_key_to_json(k: &MessageKey) -> Json {
    let Json::Obj(mut o) = k.to_json() else { return Json::Obj(Vec::new()) };
    opt_str(&mut o, "remoteJidAlt", k.remote_jid_alt().map(|v| v.as_str()));
    opt_str(&mut o, "remoteJidUsername", k.remote_jid_username().map(|v| v.as_str()));
    opt_str(&mut o, "participantAlt", k.participant_alt().map(|v| v.as_str()));
    opt_str(&mut o, "participantUsername", k.participant_username().map(|v| v.as_str()));
    opt_str(&mut o, "server_id", k.server_id().map(|v| v.as_str()));
    opt_str(&mut o, "addressingMode", k.addressing_mode().map(|v| v.as_str()));
    if let Some(v) = k.is_view_once() {
        field(&mut o, "isViewOnce", Json::Bool(v));
    }
    Json::Obj(o)
}
pub fn message_key_from_json(j: &Json) -> Result<MessageKey> {
    let mut k = MessageKey::from_json(j)?;
    if let Some(v) = str_of(j, "remoteJidAlt") {
        k.set_remote_jid_alt(v);
    }
    if let Some(v) = str_of(j, "remoteJidUsername") {
        k.set_remote_jid_username(v);
    }
    if let Some(v) = str_of(j, "participantAlt") {
        k.set_participant_alt(v);
    }
    if let Some(v) = str_of(j, "participantUsername") {
        k.set_participant_username(v);
    }
    if let Some(v) = str_of(j, "server_id") {
        k.set_server_id(v);
    }
    if let Some(v) = str_of(j, "addressingMode") {
        k.set_addressing_mode(v);
    }
    if let Some(v) = j.get("isViewOnce").and_then(Json::as_bool) {
        k.set_is_view_once(v);
    }
    Ok(k)
}
/// The field order is the one that `initAuthCreds` gives in Baileys.
pub fn creds_to_json(c: &AuthenticationCreds) -> Json {
    let mut o = Vec::new();
    field(&mut o, "noiseKey", key_pair_to_json(&c.noise_key));
    field(&mut o, "pairingEphemeralKeyPair", key_pair_to_json(&c.pairing_ephemeral_key_pair));
    field(&mut o, "signedIdentityKey", key_pair_to_json(&c.signed_identity_key));
    let mut spk = vec![("keyPair".to_string(), key_pair_to_json(&c.signed_pre_key.key_pair)), ("signature".to_string(), b(&c.signed_pre_key.signature)), ("keyId".to_string(), n(c.signed_pre_key.key_id as f64))];
    if let Some(t) = c.signed_pre_key_timestamp_s {
        field(&mut spk, "timestampS", n(t as f64));
    }
    field(&mut o, "signedPreKey", Json::Obj(spk));
    field(&mut o, "registrationId", n(c.registration_id as f64));
    field(&mut o, "advSecretKey", s(&c.adv_secret_key));
    field(
        &mut o,
        "processedHistoryMessages",
        Json::Arr(
            c.processed_history_messages
                .iter()
                .map(|m| {
                    let mut e = vec![("key".to_string(), message_key_to_json(&m.key))];
                    if let Some(t) = m.message_timestamp {
                        field(&mut e, "messageTimestamp", n(t as f64));
                    }
                    Json::Obj(e)
                })
                .collect(),
        ),
    );
    field(&mut o, "nextPreKeyId", n(c.next_pre_key_id as f64));
    field(&mut o, "firstUnuploadedPreKeyId", n(c.first_unuploaded_pre_key_id as f64));
    field(&mut o, "accountSyncCounter", n(c.account_sync_counter as f64));
    let mut settings = vec![("unarchiveChats".to_string(), Json::Bool(c.account_settings.unarchive_chats))];
    if let Some(d) = &c.account_settings.default_disappearing_mode {
        let mut m = Vec::new();
        if let Some(v) = d.ephemeral_expiration {
            field(&mut m, "ephemeralExpiration", n(v as f64));
        }
        if let Some(v) = d.ephemeral_setting_timestamp {
            field(&mut m, "ephemeralSettingTimestamp", n(v as f64));
        }
        field(&mut settings, "defaultDisappearingMode", Json::Obj(m));
    }
    field(&mut o, "accountSettings", Json::Obj(settings));
    field(&mut o, "registered", Json::Bool(c.registered));
    opt_str(&mut o, "pairingCode", c.pairing_code.as_deref());
    opt_str(&mut o, "lastPropHash", c.last_prop_hash.as_deref());
    if let Some(r) = &c.routing_info {
        field(&mut o, "routingInfo", b(r));
    }
    if let Some(d) = &c.additional_data {
        field(&mut o, "additionalData", d.clone());
    }
    if let Some(m) = &c.me {
        field(&mut o, "me", contact_to_json(m));
    }
    if let Some(a) = &c.account {
        field(&mut o, "account", a.to_json());
    }
    if let Some(ids) = &c.signal_identities {
        let list = ids
            .iter()
            .map(|i| {
                Json::Obj(vec![
                    ("identifier".to_string(), Json::Obj(vec![("name".to_string(), s(&i.identifier.name)), ("deviceId".to_string(), n(i.identifier.device_id as f64))])),
                    ("identifierKey".to_string(), b(&i.identifier_key)),
                ])
            })
            .collect();
        field(&mut o, "signalIdentities", Json::Arr(list));
    }
    opt_str(&mut o, "myAppStateKeyId", c.my_app_state_key_id.as_deref());
    if let Some(t) = c.last_account_sync_timestamp {
        field(&mut o, "lastAccountSyncTimestamp", n(t as f64));
    }
    opt_str(&mut o, "platform", c.platform.as_deref());
    Json::Obj(o)
}
pub fn creds_from_json(j: &Json) -> Result<AuthenticationCreds> {
    let bad = |k: &str| Boom::new(format!("invalid creds: {k}"));
    let req = |k: &'static str| j.get(k).ok_or_else(|| bad(k));
    let spk = req("signedPreKey")?;
    let signature: [u8; 64] = bytes_of(spk.get("signature").ok_or_else(|| bad("signature"))?)?.as_slice().try_into().map_err(|_| bad("signature"))?;
    let mut processed = Vec::new();
    if let Some(Json::Arr(a)) = j.get("processedHistoryMessages") {
        for m in a {
            let key = match m.get("key") {
                Some(k) => message_key_from_json(k)?,
                None => MessageKey::default(),
            };
            processed.push(MinimalMessage { key, message_timestamp: m.get("messageTimestamp").and_then(|t| u64_from_json(t).ok()) });
        }
    }
    let settings = j.get("accountSettings");
    let mut signal_identities = None;
    if let Some(Json::Arr(a)) = j.get("signalIdentities") {
        let mut list = Vec::new();
        for i in a {
            let id = i.get("identifier");
            list.push(SignalIdentity {
                identifier: ProtocolAddress { name: id.and_then(|v| str_of(v, "name")).unwrap_or_default(), device_id: id.and_then(|v| num_of(v, "deviceId")).unwrap_or(0.0) as u32 },
                identifier_key: match i.get("identifierKey") {
                    Some(k) => bytes_of(k)?,
                    None => Vec::new(),
                },
            });
        }
        signal_identities = Some(list);
    }
    Ok(AuthenticationCreds {
        noise_key: key_pair_from_json(req("noiseKey")?)?,
        pairing_ephemeral_key_pair: key_pair_from_json(req("pairingEphemeralKeyPair")?)?,
        signed_identity_key: key_pair_from_json(req("signedIdentityKey")?)?,
        signed_pre_key: SignedKeyPair { key_pair: key_pair_from_json(spk.get("keyPair").ok_or_else(|| bad("keyPair"))?)?, signature, key_id: num_of(spk, "keyId").unwrap_or(0.0) as u32 },
        signed_pre_key_timestamp_s: num_of(spk, "timestampS").map(|v| v as u64),
        registration_id: num_of(j, "registrationId").unwrap_or(0.0) as u32,
        adv_secret_key: str_of(j, "advSecretKey").unwrap_or_default(),
        me: j.get("me").filter(|m| !matches!(m, Json::Null)).map(contact_from_json),
        account: match j.get("account") {
            Some(a @ Json::Obj(_)) => Some(ADVSignedDeviceIdentity::from_json(a)?),
            _ => None,
        },
        signal_identities,
        my_app_state_key_id: str_of(j, "myAppStateKeyId"),
        first_unuploaded_pre_key_id: num_of(j, "firstUnuploadedPreKeyId").unwrap_or(0.0) as u32,
        next_pre_key_id: num_of(j, "nextPreKeyId").unwrap_or(0.0) as u32,
        last_account_sync_timestamp: num_of(j, "lastAccountSyncTimestamp").map(|v| v as u64),
        platform: str_of(j, "platform"),
        processed_history_messages: processed,
        account_sync_counter: num_of(j, "accountSyncCounter").unwrap_or(0.0) as u32,
        account_settings: AccountSettings {
            unarchive_chats: settings.and_then(|v| v.get("unarchiveChats")).and_then(Json::as_bool).unwrap_or(false),
            default_disappearing_mode: settings.and_then(|v| v.get("defaultDisappearingMode")).filter(|m| matches!(m, Json::Obj(_))).map(|m| DefaultDisappearingMode {
                ephemeral_expiration: num_of(m, "ephemeralExpiration").map(|v| v as u32),
                ephemeral_setting_timestamp: num_of(m, "ephemeralSettingTimestamp").map(|v| v as u64),
            }),
        },
        registered: j.get("registered").and_then(Json::as_bool).unwrap_or(false),
        pairing_code: str_of(j, "pairingCode"),
        last_prop_hash: str_of(j, "lastPropHash"),
        routing_info: match j.get("routingInfo") {
            Some(r) if !matches!(r, Json::Null) => Some(bytes_from_json(r)?),
            _ => None,
        },
        additional_data: j.get("additionalData").filter(|d| !matches!(d, Json::Null)).cloned(),
    })
}
/// The JSON that Baileys stores for each kind of key.
pub fn key_value_to_json(v: &KeyValue) -> Json {
    match v {
        KeyValue::PreKey(k) => key_pair_to_json(k),
        KeyValue::Session(r) => r.to_json(),
        // stored as the bytes of a JSON text
        KeyValue::SenderKey(r) => b(r.to_json().stringify().as_bytes()),
        KeyValue::SenderKeyMemory(m) => Json::Obj(m.iter().map(|(k, x)| (k.clone(), Json::Bool(*x))).collect()),
        KeyValue::AppStateSyncKey(k) => k.to_json(),
        KeyValue::AppStateSyncVersion(h) => Json::Obj(vec![
            ("version".to_string(), n(h.version as f64)),
            ("hash".to_string(), b(&h.hash)),
            ("indexValueMap".to_string(), Json::Obj(h.index_value_map.iter().map(|(k, x)| (k.clone(), Json::Obj(vec![("valueMac".to_string(), b(x))]))).collect())),
        ]),
        KeyValue::LidMapping(m) => s(m),
        KeyValue::DeviceList(l) => Json::Arr(l.iter().map(|d| s(d)).collect()),
        KeyValue::TcToken(t) => {
            let mut o = vec![("token".to_string(), b(&t.token))];
            opt_str(&mut o, "timestamp", t.timestamp.as_deref());
            if let Some(ts) = t.sender_timestamp {
                field(&mut o, "senderTimestamp", n(ts));
            }
            Json::Obj(o)
        }
        KeyValue::IdentityKey(k) => b(k),
    }
}
pub fn key_value_from_json(kind: KeyKind, j: &Json) -> Result<KeyValue> {
    let bad = || Boom::new(format!("invalid {} value", kind.name()));
    Ok(match kind {
        KeyKind::PreKey => KeyValue::PreKey(key_pair_from_json(j)?),
        KeyKind::Session => KeyValue::Session(Arc::new(SessionRecord::from_json(j)?)),
        KeyKind::SenderKey => {
            let text = bytes_of(j)?;
            let parsed = buffer_json_parse(std::str::from_utf8(&text).map_err(|_| bad())?)?;
            KeyValue::SenderKey(Arc::new(SenderKeyRecord::from_json(&parsed)?))
        }
        KeyKind::SenderKeyMemory => {
            let Json::Obj(o) = j else { return Err(bad()) };
            KeyValue::SenderKeyMemory(o.iter().map(|(k, v)| (k.clone(), v.as_bool().unwrap_or(false))).collect::<HashMap<_, _>>())
        }
        KeyKind::AppStateSyncKey => KeyValue::AppStateSyncKey(AppStateSyncKeyData::from_json(j)?),
        KeyKind::AppStateSyncVersion => {
            let mut index_value_map = HashMap::new();
            if let Some(Json::Obj(o)) = j.get("indexValueMap") {
                for (k, v) in o {
                    index_value_map.insert(k.clone(), bytes_of(v.get("valueMac").ok_or_else(bad)?)?);
                }
            }
            // ensureLTHashStateVersion: anything but a real number is 0, so a stored "3" does not become 3
            let version = match j.get("version") {
                Some(Json::Num(n)) if !n.is_nan() => *n as u64,
                _ => 0,
            };
            KeyValue::AppStateSyncVersion(LtHashState { version, hash: bytes_of(j.get("hash").ok_or_else(bad)?)?, index_value_map })
        }
        KeyKind::LidMapping => KeyValue::LidMapping(j.as_str().ok_or_else(bad)?.to_string()),
        KeyKind::DeviceList => {
            let Json::Arr(a) = j else { return Err(bad()) };
            KeyValue::DeviceList(a.iter().filter_map(|d| d.as_str().map(str::to_string)).collect())
        }
        KeyKind::TcToken => {
            let token: Bytes = bytes_from_json(j.get("token").ok_or_else(bad)?)?;
            KeyValue::TcToken(TcTokenEntry { token, timestamp: str_of(j, "timestamp"), sender_timestamp: num_of(j, "senderTimestamp") })
        }
        KeyKind::IdentityKey => KeyValue::IdentityKey(bytes_from_json(j)?),
    })
}
fn fix_file_name(file: &str) -> String {
    file.replace('/', "__").replace(':', "-")
}
/// Locks each file path, shared by all states in this process, as `fileLocks` is upstream.
fn file_locks() -> &'static crate::utils::make_mutex::KeyedMutex {
    static L: OnceLock<crate::utils::make_mutex::KeyedMutex> = OnceLock::new();
    L.get_or_init(make_keyed_mutex)
}
struct Files {
    folder: PathBuf,
}
impl Files {
    fn path(&self, file: &str) -> PathBuf {
        self.folder.join(fix_file_name(file))
    }
    fn write_data(&self, data: &Json, file: &str) -> Result<()> {
        let path = self.path(file);
        let text = data.stringify();
        file_locks().mutex(&path.to_string_lossy(), || std::fs::write(&path, text.as_bytes())).map_err(|e| Boom::new(e.to_string()))
    }
    fn read_data(&self, file: &str) -> Option<Json> {
        let path = self.path(file);
        let text = file_locks().mutex(&path.to_string_lossy(), || std::fs::read_to_string(&path)).ok()?;
        buffer_json_parse(&text).ok()
    }
    fn remove_data(&self, file: &str) {
        let path = self.path(file);
        let _ = file_locks().mutex(&path.to_string_lossy(), || std::fs::remove_file(&path));
    }
}
fn key_file(kind: KeyKind, id: &str) -> String {
    let name = kind.name();
    let mut f = String::with_capacity(name.len() + id.len() + 6);
    f.push_str(name);
    f.push('-');
    f.push_str(id);
    f.push_str(".json");
    f
}
impl SignalKeyStore for Files {
    fn get(&self, kind: KeyKind, ids: &[String]) -> Result<KeyMap> {
        let mut data = FxHashMap::default();
        for id in ids {
            // a file that cannot be read or parsed counts as missing, as upstream's null
            if let Some(v) = self.read_data(&key_file(kind, id)).and_then(|j| key_value_from_json(kind, &j).ok()) {
                data.insert(id.clone(), v);
            }
        }
        Ok(data)
    }
    fn set(&self, data: Vec<KeyWrite>) -> Result<()> {
        for (kind, id, value) in data {
            let file = key_file(kind, &id);
            match value {
                Some(v) => self.write_data(&key_value_to_json(&v), &file)?,
                None => self.remove_data(&file),
            }
        }
        Ok(())
    }
}
/// The result of `use_multi_file_auth_state`.
pub struct MultiFileAuthState {
    pub state: AuthenticationState,
    files: Arc<Files>,
}
impl MultiFileAuthState {
    pub fn save_creds(&self) -> Result<()> {
        let json = creds_to_json(&self.state.creds.lock().unwrap());
        self.files.write_data(&json, "creds.json")
    }
}
/// stores the full authentication state in a single folder.
/// Far more efficient than singlefileauthstate
///
/// Again, I wouldn't endorse this for any production level use other than perhaps a bot.
/// Would recommend writing an auth state for use with a proper SQL or No-SQL DB
pub fn use_multi_file_auth_state(folder: impl AsRef<Path>) -> Result<MultiFileAuthState> {
    let folder = folder.as_ref();
    match std::fs::metadata(folder) {
        Ok(info) if !info.is_dir() => return Err(Boom::new(format!("found something that is not a directory at {}, either delete it or specify a different location", folder.display()))),
        Ok(_) => {}
        Err(_) => std::fs::create_dir_all(folder).map_err(|e| Boom::new(e.to_string()))?,
    }
    let files = Arc::new(Files { folder: folder.to_path_buf() });
    let creds = files.read_data("creds.json").and_then(|j| creds_from_json(&j).ok()).unwrap_or_else(init_auth_creds);
    let keys: Arc<dyn SignalKeyStore> = files.clone();
    Ok(MultiFileAuthState { state: AuthenticationState { creds: Arc::new(Mutex::new(creds)), keys }, files })
}
