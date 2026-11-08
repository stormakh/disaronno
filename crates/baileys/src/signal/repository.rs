//! The signal repository, same behavior as Signal/libsignal.ts.
use super::group::*;
use super::lid_mapping::{LidMappingStore, PnToLidFn};
use super::session::*;
use crate::auth::*;
use crate::crypto::{self, KeyPair};
use crate::error::{Boom, Result};
use crate::wabinary::*;
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

pub struct E2ESession<'a> {
    pub registration_id: u32,
    pub identity_key: &'a [u8],
    pub signed_pre_key: SignedPreKeyPub<'a>,
    pub pre_key: Option<PreKeyPub<'a>>,
}
pub struct SignedPreKeyPub<'a> {
    pub key_id: u32,
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}
pub struct PreKeyPub<'a> {
    pub key_id: u32,
    pub public_key: &'a [u8],
}
pub struct EncryptedMessage {
    /// "pkmsg" or "msg".
    pub msg_type: &'static str,
    pub ciphertext: Vec<u8>,
}
pub struct GroupEncrypted {
    pub ciphertext: Vec<u8>,
    pub sender_key_distribution_message: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionValidation {
    pub exists: bool,
    pub reason: Option<&'static str>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MigrationResult {
    pub migrated: u32,
    pub skipped: u32,
    pub total: u32,
}
/// Same methods as `SignalRepositoryWithLIDStore` in Types/Signal.ts. Every method has a default
/// that returns an error, so a test mock implements only the methods that its code path calls.
pub trait SignalRepository: Send + Sync {
    fn decrypt_group_message(&self, _group: &str, _author_jid: &str, _msg: &[u8]) -> Result<Vec<u8>> {
        Err(not_mocked())
    }
    /// `group_id` and `axolotl_skdm` are the fields of `proto.Message.SenderKeyDistributionMessage`.
    fn process_sender_key_distribution_message(&self, _group_id: Option<&str>, _axolotl_skdm: &[u8], _author_jid: &str) -> Result<()> {
        Err(not_mocked())
    }
    fn decrypt_message(&self, _jid: &str, _msg_type: &str, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        Err(not_mocked())
    }
    fn encrypt_message(&self, _jid: &str, _data: &[u8]) -> Result<EncryptedMessage> {
        Err(not_mocked())
    }
    fn encrypt_group_message(&self, _group: &str, _me_id: &str, _data: &[u8]) -> Result<GroupEncrypted> {
        Err(not_mocked())
    }
    fn get_sender_key_distribution_message(&self, _group: &str, _me_id: &str) -> Result<Vec<u8>> {
        Err(not_mocked())
    }
    fn has_sender_key(&self, _group: &str, _me_id: &str) -> Result<bool> {
        Err(not_mocked())
    }
    /// The `base_key` and `registration_id` of the open session.
    fn get_session_info(&self, _jid: &str) -> Result<Option<(Vec<u8>, u32)>> {
        Err(not_mocked())
    }
    fn inject_e2e_session(&self, jid: &str, session: &E2ESession<'_>) -> Result<()>;
    fn validate_session(&self, _jid: &str) -> SessionValidation {
        SessionValidation { exists: false, reason: Some("validation error") }
    }
    fn jid_to_signal_protocol_address(&self, jid: &str) -> Result<String> {
        jid_to_signal_protocol_address(jid)
    }
    fn migrate_session(&self, _from_jid: &str, _to_jid: &str) -> Result<MigrationResult> {
        Err(not_mocked())
    }
    fn delete_session(&self, _jids: &[String]) -> Result<()> {
        Err(not_mocked())
    }
    /// The default is an empty store, for mocks that do not need mappings.
    fn lid_mapping(&self) -> Arc<LidMappingStore> {
        Arc::new(LidMappingStore::new(Arc::new(MemoryKeyStore::new()), None))
    }
    fn close(&self) {}
}
fn not_mocked() -> Boom {
    Boom::new("SignalRepository method not implemented")
}
pub struct LibSignalRepository {
    creds: SignalCreds,
    keys: Arc<dyn SignalKeyStore>,
    pub lid_mapping: Arc<LidMappingStore>,
    migrated: Mutex<FxHashMap<String, i64>>,
}
pub fn jid_to_signal_protocol_address(jid: &str) -> Result<String> {
    let d = jid_decode(jid).ok_or_else(|| Boom::new(format!("invalid jid: {jid}")))?;
    if d.user.is_empty() {
        return Err(Boom::new(format!("JID decoded but user is empty: \"{jid}\" -> user: \"{}\", server: \"{}\", device: {:?}", d.user, d.server, d.device)));
    }
    if d.device == Some(99) && d.server != "hosted" && d.server != "hosted.lid" {
        return Err(Boom::new(format!("Unexpected non-hosted device JID with device 99. This ID seems invalid. ID:{jid}")));
    }
    let device = d.device.unwrap_or(0);
    Ok(if d.domain_type != domains::WHATSAPP { format!("{}_{}.{}", d.user, d.domain_type, device) } else { format!("{}.{}", d.user, device) })
}
fn sender_key_name(group: &str, user: &str) -> Result<String> {
    let a = jid_to_signal_protocol_address(user)?;
    let (id, dev) = a.rsplit_once('.').unwrap_or((&a, "0"));
    Ok(format!("{group}::{id}::{dev}"))
}
struct Keys<'a>(&'a LibSignalRepository);
impl PreKeySource for Keys<'_> {
    fn load_pre_key(&self, id: u32) -> Result<Option<KeyPair>> {
        Ok(match self.0.keys.get_one(KeyKind::PreKey, &id.to_string())? {
            Some(KeyValue::PreKey(k)) => Some(k),
            _ => None,
        })
    }
    fn load_signed_pre_key(&self) -> KeyPair {
        self.0.creds.signed_pre_key.key_pair.clone()
    }
}
fn extract_identity_from_pkmsg(c: &[u8]) -> Option<&[u8]> {
    if c.len() < 2 || (c[0] & 0xf) != 3 {
        return None;
    }
    let m = parse_pre_key_message(&c[1..]).ok()?;
    if m.identity_key.len() == 33 { Some(m.identity_key) } else { None }
}
impl LibSignalRepository {
    pub fn new(creds: SignalCreds, keys: Arc<dyn SignalKeyStore>, pn_to_lid: Option<PnToLidFn>) -> LibSignalRepository {
        let lid_mapping = Arc::new(LidMappingStore::new(keys.clone(), pn_to_lid));
        LibSignalRepository { creds, keys, lid_mapping, migrated: Mutex::new(FxHashMap::default()) }
    }
    fn us(&self) -> OurIdentity {
        OurIdentity { pub_key: signal_pub(&self.creds.signed_identity_key), priv_key: self.creds.signed_identity_key.private }
    }
    /// Uses the LID address when the store knows a mapping for this PN address.
    fn resolve_lid_address(&self, id: &str) -> Result<String> {
        let Some((device_id, device)) = id.split_once('.') else { return Ok(id.to_string()) };
        let device = device.split('.').next().unwrap_or("");
        let mut it = device_id.split('_');
        let user = it.next().unwrap_or("");
        let domain = it.next().and_then(|d| d.parse::<u32>().ok()).unwrap_or(0);
        if domain == domains::LID || domain == domains::HOSTED_LID {
            return Ok(id.to_string());
        }
        let dev = if device != "0" { format!(":{device}") } else { String::new() };
        let pn = format!("{user}{dev}@{}", if domain == domains::HOSTED { "hosted" } else { "s.whatsapp.net" });
        match self.lid_mapping.get_lid_for_pn(&pn)? {
            Some(l) => jid_to_signal_protocol_address(&l),
            None => Ok(id.to_string()),
        }
    }
    fn load_session(&self, wire: &str) -> Result<Option<Arc<SessionRecord>>> {
        Ok(match self.keys.get_one(KeyKind::Session, wire) {
            Ok(Some(KeyValue::Session(s))) => Some(s),
            _ => None,
        })
    }
    fn store_session(&self, wire: &str, s: SessionRecord) -> Result<()> {
        self.keys.set_one(KeyKind::Session, wire, Some(KeyValue::Session(Arc::new(s))))
    }
    /// Returns true when the key is new, or changed. A changed key also clears the session.
    fn save_identity(&self, id: &str, key: &[u8]) -> Result<bool> {
        let wire = self.resolve_lid_address(id)?;
        let existing = match self.keys.get_one(KeyKind::IdentityKey, &wire)? {
            Some(KeyValue::IdentityKey(k)) => Some(k),
            _ => None,
        };
        let new_val = || Some(KeyValue::IdentityKey(key.into()));
        match existing {
            Some(k) if k.as_slice() == key => Ok(false),
            Some(_) => {
                self.keys.set(vec![(KeyKind::Session, wire.clone(), None), (KeyKind::IdentityKey, wire, new_val())])?;
                Ok(true)
            }
            None => {
                self.keys.set_one(KeyKind::IdentityKey, &wire, new_val())?;
                Ok(true)
            }
        }
    }
    fn load_sender_key(&self, name: &str) -> Result<SenderKeyRecord> {
        Ok(match self.keys.get_one(KeyKind::SenderKey, name)? {
            Some(KeyValue::SenderKey(k)) => (*k).clone(),
            _ => SenderKeyRecord::default(),
        })
    }
    fn store_sender_key(&self, name: &str, r: SenderKeyRecord) -> Result<()> {
        self.keys.set_one(KeyKind::SenderKey, name, Some(KeyValue::SenderKey(Arc::new(r))))
    }
    fn in_tx<T>(&self, key: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let slot: RefCell<Option<T>> = RefCell::new(None);
        let mut f = Some(f);
        self.keys.transaction(
            &mut || {
                if let Some(g) = f.take() {
                    *slot.borrow_mut() = Some(g()?);
                }
                Ok(())
            },
            key,
        )?;
        slot.into_inner().ok_or_else(|| Boom::new("transaction did not run"))
    }
    pub fn decrypt_group_message(&self, group: &str, author: &str, msg: &[u8]) -> Result<Vec<u8>> {
        let name = sender_key_name(group, author)?;
        self.in_tx(group, || {
            let mut r = self.load_sender_key(&name)?;
            let pt = group_decrypt(&mut r, msg)?;
            self.store_sender_key(&name, r)?;
            Ok(pt)
        })
    }
    pub fn process_sender_key_distribution_message(&self, group_id: Option<&str>, skdm: &[u8], author: &str) -> Result<()> {
        let group = group_id.ok_or_else(|| Boom::new("Group ID is required for sender key distribution message"))?;
        let name = sender_key_name(group, author)?;
        let m = skdm_parse(skdm)?;
        self.in_tx(group, || {
            let mut r = self.load_sender_key(&name)?;
            r.add_sender_key_state(m.id().unwrap_or(0), m.iteration().unwrap_or(0), m.chain_key().map_or(&[][..], |b| b.as_slice()), m.signing_key().map_or(&[][..], |b| b.as_slice()));
            self.store_sender_key(&name, r)
        })
    }
    pub fn decrypt_message(&self, jid: &str, msg_type: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let addr = jid_to_signal_protocol_address(jid)?;
        if msg_type == "pkmsg" {
            if let Some(k) = extract_identity_from_pkmsg(ciphertext) {
                self.save_identity(&addr, k)?;
            }
        }
        self.in_tx(jid, || {
            let wire = self.resolve_lid_address(&addr)?;
            let cur = self.load_session(&wire)?;
            let us = self.us();
            if msg_type == "pkmsg" {
                let mut r = cur.map(|c| (*c).clone()).unwrap_or_default();
                let (pt, pk) = decrypt_pre_key(&mut r, ciphertext, &Keys(self), &us)?;
                self.store_session(&wire, r)?;
                if let Some(id) = pk {
                    self.keys.set_one(KeyKind::PreKey, &id.to_string(), None)?;
                }
                Ok(pt)
            } else {
                let c = cur.ok_or_else(|| Boom::new("No session record"))?;
                let mut r = (*c).clone();
                let pt = decrypt_whisper(&mut r, ciphertext, &us)?;
                self.store_session(&wire, r)?;
                Ok(pt)
            }
        })
    }
    pub fn encrypt_message(&self, jid: &str, data: &[u8]) -> Result<EncryptedMessage> {
        let addr = jid_to_signal_protocol_address(jid)?;
        self.in_tx(jid, || {
            let wire = self.resolve_lid_address(&addr)?;
            let c = self.load_session(&wire)?.ok_or_else(|| Boom::new("No sessions"))?;
            let mut r = (*c).clone();
            let e = encrypt(&mut r, data, &self.us(), self.creds.registration_id)?;
            self.store_session(&wire, r)?;
            Ok(EncryptedMessage { msg_type: if e.msg_type == 3 { "pkmsg" } else { "msg" }, ciphertext: e.body })
        })
    }
    fn ensure_sender_key(&self, name: &str) -> Result<(SenderKeyRecord, Vec<u8>)> {
        let mut r = self.load_sender_key(name)?;
        if r.is_empty() {
            let mut idb = [0u8; 4];
            crypto::random_bytes(&mut idb);
            let id = u32::from_be_bytes(idb) & 0x7fff_ffff;
            let mut seed = [0u8; 32];
            crypto::random_bytes(&mut seed);
            let k = crypto::generate_key_pair();
            r.set_sender_key_state(id, 0, &seed, &crypto::generate_signal_pub_key(&k.public), &k.private);
            self.store_sender_key(name, r.clone())?;
        }
        let st = r.states.last().ok_or_else(|| Boom::new("No session state available"))?;
        let skdm = skdm_serialize(st.sender_key_id, st.chain_iteration, &st.chain_seed, &st.signing_key_public());
        Ok((r, skdm))
    }
    pub fn encrypt_group_message(&self, group: &str, me_id: &str, data: &[u8]) -> Result<GroupEncrypted> {
        let name = sender_key_name(group, me_id)?;
        self.in_tx(group, || {
            let (mut r, skdm) = self.ensure_sender_key(&name)?;
            let ciphertext = group_encrypt(&mut r, data)?;
            self.store_sender_key(&name, r)?;
            Ok(GroupEncrypted { ciphertext, sender_key_distribution_message: skdm })
        })
    }
    pub fn get_sender_key_distribution_message(&self, group: &str, me_id: &str) -> Result<Vec<u8>> {
        let name = sender_key_name(group, me_id)?;
        self.in_tx(group, || Ok(self.ensure_sender_key(&name)?.1))
    }
    pub fn has_sender_key(&self, group: &str, me_id: &str) -> Result<bool> {
        Ok(self.keys.get_one(KeyKind::SenderKey, &sender_key_name(group, me_id)?)?.is_some())
    }
    pub fn get_session_info(&self, jid: &str) -> Result<Option<(Vec<u8>, u32)>> {
        let wire = self.resolve_lid_address(&jid_to_signal_protocol_address(jid)?)?;
        let Some(r) = self.load_session(&wire)? else { return Ok(None) };
        let Some(i) = r.open_session() else { return Ok(None) };
        let s = &r.sessions[i];
        Ok(s.registration_id.map(|id| (s.base_key.to_vec(), id)))
    }
    pub fn validate_session(&self, jid: &str) -> SessionValidation {
        let res = jid_to_signal_protocol_address(jid).and_then(|a| self.resolve_lid_address(&a)).and_then(|w| self.load_session(&w));
        match res {
            Err(_) => SessionValidation { exists: false, reason: Some("validation error") },
            Ok(None) => SessionValidation { exists: false, reason: Some("no session") },
            Ok(Some(s)) if !s.have_open_session() => SessionValidation { exists: false, reason: Some("no open session") },
            Ok(Some(_)) => SessionValidation { exists: true, reason: None },
        }
    }
    pub fn delete_session(&self, jids: &[String]) -> Result<()> {
        if jids.is_empty() {
            return Ok(());
        }
        let mut w = Vec::with_capacity(jids.len());
        for j in jids {
            w.push((KeyKind::Session, jid_to_signal_protocol_address(j)?, None));
        }
        self.in_tx(&format!("delete-{}-sessions", jids.len()), || self.keys.set(std::mem::take(&mut w)))
    }
    pub fn migrate_session(&self, from: &str, to: &str) -> Result<MigrationResult> {
        if from.is_empty() || (!is_lid_user(to) && !is_hosted_lid_user(to)) {
            return Ok(MigrationResult::default());
        }
        if !is_pn_user(from) && !is_hosted_pn_user(from) {
            return Ok(MigrationResult { migrated: 0, skipped: 0, total: 1 });
        }
        let d = jid_decode(from).ok_or_else(|| Boom::new("invalid jid"))?;
        let user = d.user.to_string();
        let Some(KeyValue::DeviceList(mut devices)) = self.keys.get_one(KeyKind::DeviceList, &user)? else {
            return Ok(MigrationResult::default());
        };
        let from_dev = d.device.unwrap_or(0).to_string();
        if !devices.contains(&from_dev) {
            devices.push(from_dev);
        }
        let now = crate::utils::time::now_ms();
        let session_keys: Vec<String> = {
            let m = self.migrated.lock().unwrap();
            devices.iter().map(|x| format!("{user}.{x}")).filter(|k| m.get(k).is_none_or(|e| *e <= now)).collect()
        };
        let existing = self.keys.get(KeyKind::Session, &session_keys)?;
        let mut device_jids = Vec::new();
        for k in &session_keys {
            if !existing.contains_key(k) {
                continue;
            }
            let Some(ds) = k.split('.').nth(1) else { continue };
            let n: u32 = ds.parse().unwrap_or(0);
            device_jids.push(if n == 0 {
                format!("{user}@s.whatsapp.net")
            } else if n == 99 {
                format!("{user}:99@hosted")
            } else {
                format!("{user}:{n}@s.whatsapp.net")
            });
        }
        let to_user = jid_decode(to).map(|t| t.user).unwrap_or("");
        self.in_tx(&format!("migrate-{}-sessions-{to_user}", device_jids.len()), || {
            let mut ops = Vec::new();
            for j in &device_jids {
                let lid = transfer_device(j, to).ok_or_else(|| Boom::new("invalid jid"))?;
                let dev = jid_decode(j).and_then(|f| f.device).unwrap_or(0);
                ops.push((jid_to_signal_protocol_address(j)?, jid_to_signal_protocol_address(&lid)?, dev));
            }
            let total = ops.len() as u32;
            let mut migrated = 0;
            let mut writes = Vec::new();
            let mut done = Vec::new();
            for (pn_addr, lid_addr, dev) in &ops {
                if let Some(KeyValue::Session(s)) = self.keys.get_one(KeyKind::Session, pn_addr)? {
                    if s.have_open_session() {
                        writes.push((KeyKind::Session, lid_addr.clone(), Some(KeyValue::Session(s))));
                        writes.push((KeyKind::Session, pn_addr.clone(), None));
                        done.push(format!("{user}.{dev}"));
                        migrated += 1;
                    }
                }
            }
            if !writes.is_empty() {
                self.keys.set(writes)?;
                let now = crate::utils::time::now_ms();
                let exp = now + 3 * 24 * 60 * 60 * 1000;
                let mut m = self.migrated.lock().unwrap();
                // same job as `ttlAutopurge` of upstream, without a timer
                if m.len() >= 1024 {
                    let mut expired = Vec::new();
                    for (k, e) in m.iter() {
                        if *e <= now {
                            expired.push(k.clone());
                        }
                    }
                    for k in &expired {
                        m.remove(k);
                    }
                }
                for k in done {
                    m.insert(k, exp);
                }
            }
            Ok(MigrationResult { migrated, skipped: total - migrated, total })
        })
    }
    pub fn close(&self) {
        self.migrated.lock().unwrap().clear();
        self.lid_mapping.close();
    }
}
impl SignalRepository for LibSignalRepository {
    fn decrypt_group_message(&self, group: &str, author_jid: &str, msg: &[u8]) -> Result<Vec<u8>> {
        LibSignalRepository::decrypt_group_message(self, group, author_jid, msg)
    }
    fn process_sender_key_distribution_message(&self, group_id: Option<&str>, axolotl_skdm: &[u8], author_jid: &str) -> Result<()> {
        LibSignalRepository::process_sender_key_distribution_message(self, group_id, axolotl_skdm, author_jid)
    }
    fn decrypt_message(&self, jid: &str, msg_type: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        LibSignalRepository::decrypt_message(self, jid, msg_type, ciphertext)
    }
    fn encrypt_message(&self, jid: &str, data: &[u8]) -> Result<EncryptedMessage> {
        LibSignalRepository::encrypt_message(self, jid, data)
    }
    fn encrypt_group_message(&self, group: &str, me_id: &str, data: &[u8]) -> Result<GroupEncrypted> {
        LibSignalRepository::encrypt_group_message(self, group, me_id, data)
    }
    fn get_sender_key_distribution_message(&self, group: &str, me_id: &str) -> Result<Vec<u8>> {
        LibSignalRepository::get_sender_key_distribution_message(self, group, me_id)
    }
    fn has_sender_key(&self, group: &str, me_id: &str) -> Result<bool> {
        LibSignalRepository::has_sender_key(self, group, me_id)
    }
    fn get_session_info(&self, jid: &str) -> Result<Option<(Vec<u8>, u32)>> {
        LibSignalRepository::get_session_info(self, jid)
    }
    fn validate_session(&self, jid: &str) -> SessionValidation {
        LibSignalRepository::validate_session(self, jid)
    }
    fn migrate_session(&self, from_jid: &str, to_jid: &str) -> Result<MigrationResult> {
        LibSignalRepository::migrate_session(self, from_jid, to_jid)
    }
    fn delete_session(&self, jids: &[String]) -> Result<()> {
        LibSignalRepository::delete_session(self, jids)
    }
    fn lid_mapping(&self) -> Arc<LidMappingStore> {
        self.lid_mapping.clone()
    }
    fn close(&self) {
        LibSignalRepository::close(self)
    }
    fn inject_e2e_session(&self, jid: &str, session: &E2ESession<'_>) -> Result<()> {
        let addr = jid_to_signal_protocol_address(jid)?;
        self.in_tx(jid, || {
            let wire = self.resolve_lid_address(&addr)?;
            let mut r = self.load_session(&wire)?.map(|c| (*c).clone()).unwrap_or_default();
            let b = PreKeyBundle {
                registration_id: session.registration_id,
                identity_key: session.identity_key,
                signed_key_id: session.signed_pre_key.key_id,
                signed_public: session.signed_pre_key.public_key,
                signature: session.signed_pre_key.signature,
                pre_key: session.pre_key.as_ref().map(|p| (p.key_id, p.public_key)),
            };
            init_outgoing(&mut r, &b, &self.us())?;
            self.store_session(&wire, r)
        })
    }
}
