//! Signal sessions, same behavior and JSON format as libsignal-node.
use crate::crypto::{self, KeyPair};
use crate::error::{Boom, Result};
use crate::utils::time::now_ms;
use waproto::pb::{Json, base64_decode, base64_encode};

pub type PubKey = [u8; 33];
const CLOSED_SESSIONS_MAX: usize = 40;
const VERSION: u8 = 3;
const TUPLE: u8 = (VERSION << 4) | VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Chain {
    pub id: PubKeyOwned,
    pub counter: i32,
    /// `None` once the chain is closed.
    pub key: Option<[u8; 32]>,
    pub sending: bool,
    pub message_keys: Vec<(u32, [u8; 32])>,
}
/// A public key of up to 33 bytes, stored in place, so that a session needs no allocation for each key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubKeyOwned {
    len: u8,
    bytes: [u8; 33],
}
impl PubKeyOwned {
    /// A longer key is an error: every key here passed `crypto::shared_key`, or came from a stored session.
    pub fn new(k: &[u8]) -> Result<PubKeyOwned> {
        let mut bytes = [0u8; 33];
        bytes.get_mut(..k.len()).ok_or_else(|| Boom::new("Invalid public key"))?.copy_from_slice(k);
        Ok(PubKeyOwned { len: k.len() as u8, bytes })
    }
}
impl Default for PubKeyOwned {
    fn default() -> PubKeyOwned {
        PubKeyOwned { len: 0, bytes: [0; 33] }
    }
}
impl std::ops::Deref for PubKeyOwned {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingPreKey {
    pub signed_key_id: u32,
    pub base_key: PubKeyOwned,
    pub pre_key_id: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SessionEntry {
    pub registration_id: Option<u32>,
    pub eph_pub: PubKeyOwned,
    pub eph_priv: [u8; 32],
    pub last_remote_ephemeral_key: PubKeyOwned,
    pub previous_counter: i32,
    pub root_key: [u8; 32],
    pub base_key: PubKeyOwned,
    pub base_key_ours: bool,
    pub closed: i64,
    pub used: i64,
    pub created: i64,
    pub remote_identity_key: PubKeyOwned,
    pub chains: Vec<Chain>,
    pub pending_pre_key: Option<PendingPreKey>,
}
impl SessionEntry {
    fn chain(&self, k: &[u8]) -> Option<usize> {
        self.chains.iter().position(|c| *c.id == *k)
    }
    pub fn is_closed(&self) -> bool {
        self.closed != -1
    }
    fn add_chain(&mut self, c: Chain) -> Result<()> {
        if self.chain(&c.id).is_some() {
            return Err(Boom::new("Overwrite attempt"));
        }
        // most sessions hold one or two chains, and four slots would cost 352 bytes
        self.chains.reserve_exact(1);
        self.chains.push(c);
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SessionRecord {
    pub sessions: Vec<SessionEntry>,
}
impl SessionRecord {
    pub fn have_open_session(&self) -> bool {
        self.open_session().is_some_and(|s| self.sessions[s].registration_id.is_some())
    }
    pub fn open_session(&self) -> Option<usize> {
        self.sessions.iter().position(|s| !s.is_closed())
    }
    /// Errors when the key names one of our own base keys.
    pub fn session_by_base(&self, k: &[u8]) -> Result<Option<usize>> {
        match self.sessions.iter().position(|s| *s.base_key == *k) {
            Some(i) if self.sessions[i].base_key_ours => Err(Boom::new("Tried to lookup a session using our basekey")),
            r => Ok(r),
        }
    }
    pub fn set_session(&mut self, s: SessionEntry) {
        match self.sessions.iter().position(|e| e.base_key == s.base_key) {
            Some(i) => self.sessions[i] = s,
            None => {
                // most records hold one session, and a spare entry would cost 264 bytes
                self.sessions.reserve_exact(1);
                self.sessions.push(s);
            }
        }
    }
    pub fn close_session(&mut self, i: usize) {
        if !self.sessions[i].is_closed() {
            self.sessions[i].closed = now_ms();
        }
    }
    pub fn remove_old_sessions(&mut self) -> Result<()> {
        while self.sessions.len() > CLOSED_SESSIONS_MAX {
            let mut oldest: Option<usize> = None;
            for (i, s) in self.sessions.iter().enumerate() {
                if s.closed != -1 && oldest.is_none_or(|o| s.closed < self.sessions[o].closed) {
                    oldest = Some(i);
                }
            }
            match oldest {
                Some(i) => {
                    self.sessions.remove(i);
                }
                None => return Err(Boom::new("Corrupt sessions object")),
            }
        }
        Ok(())
    }
    pub fn to_json(&self) -> Json {
        let b = |v: &[u8]| Json::Str(base64_encode(v));
        let n = |v: i64| Json::Num(v as f64);
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for s in &self.sessions {
            let mut chains = Vec::new();
            for c in &s.chains {
                let mut ck = vec![("counter".to_string(), n(c.counter as i64))];
                if let Some(k) = &c.key {
                    ck.push(("key".to_string(), b(k)));
                }
                let mk = c.message_keys.iter().map(|(i, k)| (i.to_string(), b(k))).collect();
                chains.push((
                    base64_encode(&c.id),
                    Json::Obj(vec![("chainKey".to_string(), Json::Obj(ck)), ("chainType".to_string(), n(if c.sending { 1 } else { 2 })), ("messageKeys".to_string(), Json::Obj(mk))]),
                ));
            }
            let mut e = vec![];
            if let Some(r) = s.registration_id {
                e.push(("registrationId".to_string(), n(r as i64)));
            }
            e.push((
                "currentRatchet".to_string(),
                Json::Obj(vec![
                    ("ephemeralKeyPair".to_string(), Json::Obj(vec![("pubKey".to_string(), b(&s.eph_pub)), ("privKey".to_string(), b(&s.eph_priv))])),
                    ("lastRemoteEphemeralKey".to_string(), b(&s.last_remote_ephemeral_key)),
                    ("previousCounter".to_string(), n(s.previous_counter as i64)),
                    ("rootKey".to_string(), b(&s.root_key)),
                ]),
            ));
            e.push((
                "indexInfo".to_string(),
                Json::Obj(vec![
                    ("baseKey".to_string(), b(&s.base_key)),
                    ("baseKeyType".to_string(), n(if s.base_key_ours { 1 } else { 2 })),
                    ("closed".to_string(), n(s.closed)),
                    ("used".to_string(), n(s.used)),
                    ("created".to_string(), n(s.created)),
                    ("remoteIdentityKey".to_string(), b(&s.remote_identity_key)),
                ]),
            ));
            e.push(("_chains".to_string(), Json::Obj(chains)));
            if let Some(p) = &s.pending_pre_key {
                let mut pj = vec![("signedKeyId".to_string(), n(p.signed_key_id as i64)), ("baseKey".to_string(), b(&p.base_key))];
                if let Some(i) = p.pre_key_id {
                    pj.push(("preKeyId".to_string(), n(i as i64)));
                }
                e.push(("pendingPreKey".to_string(), Json::Obj(pj)));
            }
            sessions.push((base64_encode(&s.base_key), Json::Obj(e)));
        }
        Json::Obj(vec![("_sessions".to_string(), Json::Obj(sessions)), ("version".to_string(), Json::Str("v1".to_string()))])
    }
    pub fn from_json(j: &Json) -> Result<SessionRecord> {
        let bad = || Boom::new("invalid session record");
        let bytes = |v: Option<&Json>| -> Result<Vec<u8>> { Ok(base64_decode(v.and_then(Json::as_str).ok_or_else(bad)?)) };
        let pk = |v: Option<&Json>| -> Result<PubKeyOwned> { PubKeyOwned::new(&bytes(v)?).map_err(|_| bad()) };
        let k32 = |v: Option<&Json>| -> Result<[u8; 32]> {
            let b = bytes(v)?;
            b.as_slice().try_into().map_err(|_| bad())
        };
        let num = |v: Option<&Json>| -> Result<i64> { Ok(v.and_then(Json::as_f64).ok_or_else(bad)? as i64) };
        let mut r = SessionRecord::default();
        let Some(Json::Obj(ss)) = j.get("_sessions") else { return Ok(r) };
        for (_, e) in ss {
            let cr = e.get("currentRatchet").ok_or_else(bad)?;
            let kp = cr.get("ephemeralKeyPair").ok_or_else(bad)?;
            let ii = e.get("indexInfo").ok_or_else(bad)?;
            let mut chains = Vec::new();
            if let Some(Json::Obj(cs)) = e.get("_chains") {
                for (id, c) in cs {
                    let ck = c.get("chainKey").ok_or_else(bad)?;
                    let key = match ck.get("key") {
                        Some(Json::Str(_)) => Some(k32(ck.get("key"))?),
                        _ => None,
                    };
                    let mut message_keys = Vec::new();
                    if let Some(Json::Obj(ms)) = c.get("messageKeys") {
                        for (i, m) in ms {
                            message_keys.push((i.parse::<u32>().map_err(|_| bad())?, k32(Some(m))?));
                        }
                    }
                    message_keys.sort_by_key(|(i, _)| *i);
                    chains.push(Chain { id: PubKeyOwned::new(&base64_decode(id)).map_err(|_| bad())?, counter: num(ck.get("counter"))? as i32, key, sending: num(c.get("chainType"))? == 1, message_keys });
                }
            }
            let pending_pre_key = match e.get("pendingPreKey") {
                Some(p @ Json::Obj(_)) => Some(PendingPreKey { signed_key_id: num(p.get("signedKeyId"))? as u32, base_key: pk(p.get("baseKey"))?, pre_key_id: p.get("preKeyId").and_then(Json::as_f64).map(|v| v as u32) }),
                _ => None,
            };
            r.sessions.push(SessionEntry {
                registration_id: e.get("registrationId").and_then(Json::as_f64).map(|v| v as u32),
                eph_pub: pk(kp.get("pubKey"))?,
                eph_priv: k32(kp.get("privKey"))?,
                last_remote_ephemeral_key: pk(cr.get("lastRemoteEphemeralKey"))?,
                previous_counter: num(cr.get("previousCounter"))? as i32,
                root_key: k32(cr.get("rootKey"))?,
                base_key: pk(ii.get("baseKey"))?,
                base_key_ours: num(ii.get("baseKeyType"))? == 1,
                closed: num(ii.get("closed"))?,
                used: num(ii.get("used")).unwrap_or(0),
                created: num(ii.get("created")).unwrap_or(0),
                remote_identity_key: pk(ii.get("remoteIdentityKey"))?,
                chains,
                pending_pre_key,
            });
        }
        Ok(r)
    }
}

pub fn signal_pub(k: &KeyPair) -> Vec<u8> {
    crypto::generate_signal_pub_key(&k.public)
}
fn gen_eph() -> (Vec<u8>, [u8; 32]) {
    let k = crypto::generate_key_pair();
    (signal_pub(&k), k.private)
}

// libsignal's WhisperTextProtocol messages
fn put_varint(o: &mut Vec<u8>, mut v: u64) {
    while v > 127 {
        o.push((v as u8 & 127) | 128);
        v >>= 7;
    }
    o.push(v as u8);
}
fn put_bytes(o: &mut Vec<u8>, tag: u8, b: &[u8]) {
    o.push(tag);
    put_varint(o, b.len() as u64);
    o.extend_from_slice(b);
}
fn put_u32(o: &mut Vec<u8>, tag: u8, v: u32) {
    o.push(tag);
    put_varint(o, v as u64);
}
/// Reads a protobuf message field by field, with no allocation.
struct PbFields<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> PbFields<'a> {
    fn varint(&mut self) -> Result<u64> {
        let (mut v, mut s) = (0u64, 0);
        loop {
            let c = *self.b.get(self.i).ok_or_else(|| Boom::new("index out of range"))?;
            self.i += 1;
            if s < 64 {
                v |= ((c & 127) as u64) << s;
            }
            if c < 128 {
                return Ok(v);
            }
            s += 7;
            if s > 70 {
                return Err(Boom::new("invalid varint encoding"));
            }
        }
    }
    /// Returns (field, varint value, length-delimited bytes), skipping fixed-size fields.
    fn next(&mut self) -> Result<Option<(u32, u64, &'a [u8])>> {
        while self.i < self.b.len() {
            let t = self.varint()? as u32;
            match t & 7 {
                0 => {
                    let v = self.varint()?;
                    return Ok(Some((t >> 3, v, &[])));
                }
                1 => self.i += 8,
                2 => {
                    let n = self.varint()? as usize;
                    if n > self.b.len() - self.i {
                        return Err(Boom::new("index out of range"));
                    }
                    let d = &self.b[self.i..self.i + n];
                    self.i += n;
                    return Ok(Some((t >> 3, 0, d)));
                }
                5 => self.i += 4,
                w => return Err(Boom::new(format!("invalid wire type {w} at offset {}", self.i))),
            }
            if self.i > self.b.len() {
                return Err(Boom::new("index out of range"));
            }
        }
        Ok(None)
    }
}
#[derive(Default)]
pub struct PreKeyWhisperMessage<'a> {
    pub pre_key_id: Option<u32>,
    pub base_key: &'a [u8],
    pub identity_key: &'a [u8],
    pub message: &'a [u8],
    pub registration_id: Option<u32>,
    pub signed_pre_key_id: u32,
}
pub fn parse_pre_key_message(b: &[u8]) -> Result<PreKeyWhisperMessage<'_>> {
    let mut m = PreKeyWhisperMessage::default();
    let mut p = PbFields { b, i: 0 };
    while let Some((f, v, d)) = p.next()? {
        match f {
            1 => m.pre_key_id = Some(v as u32),
            2 => m.base_key = d,
            3 => m.identity_key = d,
            4 => m.message = d,
            5 => m.registration_id = Some(v as u32),
            6 => m.signed_pre_key_id = v as u32,
            _ => {}
        }
    }
    Ok(m)
}

/// The keys of the local user, as `getOurIdentity` gives them.
pub struct OurIdentity {
    pub pub_key: Vec<u8>,
    pub priv_key: [u8; 32],
}
pub struct PreKeyBundle<'a> {
    pub registration_id: u32,
    pub identity_key: &'a [u8],
    pub signed_key_id: u32,
    pub signed_public: &'a [u8],
    pub signature: &'a [u8],
    pub pre_key: Option<(u32, &'a [u8])>,
}

fn master(secret: &[u8], salt: &[u8; 32], info: &[u8], n: usize) -> Vec<[u8; 32]> {
    crypto::derive_secrets(secret, salt, info, n)
}
const ZERO32: [u8; 32] = [0u8; 32];

fn init_session(is_initiator: bool, our_ephemeral: Option<&(Vec<u8>, [u8; 32])>, our_signed: Option<&(Vec<u8>, [u8; 32])>, their_identity: &[u8], their_ephemeral: Option<&[u8]>, their_signed: Option<&[u8]>, registration_id: Option<u32>, us: &OurIdentity) -> Result<SessionEntry> {
    let our_signed_k = if is_initiator { our_ephemeral } else { our_signed }.ok_or_else(|| Boom::new("Invalid call to initSession"))?;
    let their_signed_k = if is_initiator { their_signed } else { their_ephemeral }.ok_or_else(|| Boom::new("Invalid call to initSession"))?;
    let has4 = our_ephemeral.is_some() && their_ephemeral.is_some();
    let mut secret = vec![0xffu8; 32];
    secret.resize(if has4 { 32 * 5 } else { 32 * 4 }, 0);
    let a1 = crypto::shared_key(&us.priv_key, their_signed_k)?;
    let a2 = crypto::shared_key(&our_signed_k.1, their_identity)?;
    let a3 = crypto::shared_key(&our_signed_k.1, their_signed_k)?;
    let (s1, s2) = if is_initiator { (&a1, &a2) } else { (&a2, &a1) };
    secret[32..64].copy_from_slice(s1);
    secret[64..96].copy_from_slice(s2);
    secret[96..128].copy_from_slice(&a3);
    if has4 {
        let a4 = crypto::shared_key(&our_ephemeral.unwrap().1, their_ephemeral.unwrap())?;
        secret[128..160].copy_from_slice(&a4);
    }
    let mk = master(&secret, &ZERO32, b"WhisperText", 3);
    let (eph_pub, eph_priv) = if is_initiator { gen_eph() } else { our_signed_k.clone() };
    let now = now_ms();
    let mut s = SessionEntry {
        registration_id,
        eph_pub: PubKeyOwned::new(&eph_pub)?,
        eph_priv,
        last_remote_ephemeral_key: PubKeyOwned::new(their_signed_k)?,
        previous_counter: 0,
        root_key: mk[0],
        base_key: PubKeyOwned::new(if is_initiator { &our_ephemeral.unwrap().0 } else { their_ephemeral.unwrap() })?,
        base_key_ours: is_initiator,
        closed: -1,
        used: now,
        created: now,
        remote_identity_key: PubKeyOwned::new(their_identity)?,
        chains: Vec::new(),
        pending_pre_key: None,
    };
    if is_initiator {
        let shared = crypto::shared_key(&s.eph_priv, their_signed_k)?;
        let m = master(&shared, &s.root_key, b"WhisperRatchet", 3);
        s.add_chain(Chain { id: s.eph_pub, counter: -1, key: Some(m[1]), sending: true, message_keys: Vec::new() })?;
        s.root_key = m[0];
    }
    Ok(s)
}

/// SessionBuilder.initOutgoing. The signature check is skipped, as libsignal does with `isInit`.
pub fn init_outgoing(record: &mut SessionRecord, device: &PreKeyBundle<'_>, us: &OurIdentity) -> Result<()> {
    if device.signature.len() != 64 {
        return Err(Boom::new("Invalid signature"));
    }
    let base = gen_eph();
    let mut s = init_session(true, Some(&base), None, device.identity_key, device.pre_key.map(|p| p.1), Some(device.signed_public), Some(device.registration_id), us)?;
    s.pending_pre_key = Some(PendingPreKey { signed_key_id: device.signed_key_id, base_key: PubKeyOwned::new(&base.0)?, pre_key_id: device.pre_key.map(|p| p.0) });
    if let Some(i) = record.open_session() {
        record.close_session(i);
    }
    record.set_session(s);
    Ok(())
}

/// Finds the stored keys for an incoming prekey message.
pub trait PreKeySource {
    fn load_pre_key(&self, id: u32) -> Result<Option<KeyPair>>;
    fn load_signed_pre_key(&self) -> KeyPair;
}
fn init_incoming(record: &mut SessionRecord, m: &PreKeyWhisperMessage<'_>, src: &dyn PreKeySource, us: &OurIdentity) -> Result<Option<u32>> {
    if record.session_by_base(m.base_key)?.is_some() {
        return Ok(None);
    }
    let pre = match m.pre_key_id {
        Some(id) => src.load_pre_key(id)?,
        None => None,
    };
    if m.pre_key_id.is_some_and(|i| i != 0) && pre.is_none() {
        return Err(Boom::new("Invalid PreKey ID"));
    }
    let signed = src.load_signed_pre_key();
    if let Some(i) = record.open_session() {
        record.close_session(i);
    }
    let our_eph = pre.map(|k| (signal_pub(&k), k.private));
    let our_signed = (signal_pub(&signed), signed.private);
    let s = init_session(false, our_eph.as_ref(), Some(&our_signed), m.identity_key, Some(m.base_key), None, m.registration_id, us)?;
    record.set_session(s);
    Ok(m.pre_key_id)
}

fn fill_message_keys(chain: &mut Chain, counter: i32) -> Result<()> {
    if chain.counter >= counter {
        return Ok(());
    }
    if counter - chain.counter > 2000 {
        return Err(Boom::new("Over 2000 messages into the future!"));
    }
    let Some(mut key) = chain.key else { return Err(Boom::new("Chain closed")) };
    while chain.counter < counter {
        chain.counter += 1;
        chain.message_keys.push((chain.counter as u32, crypto::hmac_sha256(&key, &[1])));
        key = crypto::hmac_sha256(&key, &[2]);
    }
    chain.key = Some(key);
    Ok(())
}
fn calculate_ratchet(s: &mut SessionEntry, remote: &[u8], sending: bool) -> Result<()> {
    let shared = crypto::shared_key(&s.eph_priv, remote)?;
    let m = master(&shared, &s.root_key, b"WhisperRatchet", 2);
    let id = if sending { s.eph_pub } else { PubKeyOwned::new(remote)? };
    s.add_chain(Chain { id, counter: -1, key: Some(m[1]), sending, message_keys: Vec::new() })?;
    s.root_key = m[0];
    Ok(())
}
fn maybe_step_ratchet(s: &mut SessionEntry, remote: &[u8], prev_counter: u32) -> Result<()> {
    if s.chain(remote).is_some() {
        return Ok(());
    }
    if let Some(p) = s.chain(&s.last_remote_ephemeral_key) {
        fill_message_keys(&mut s.chains[p], prev_counter as i32)?;
        s.chains[p].key = None;
    }
    calculate_ratchet(s, remote, false)?;
    if let Some(p) = s.chain(&s.eph_pub) {
        s.previous_counter = s.chains[p].counter;
        s.chains.remove(p);
    }
    let (p, k) = gen_eph();
    s.eph_pub = PubKeyOwned::new(&p)?;
    s.eph_priv = k;
    calculate_ratchet(s, remote, true)?;
    s.last_remote_ephemeral_key = PubKeyOwned::new(remote)?;
    Ok(())
}

pub struct Encrypted {
    /// 3 is a prekey message, 1 is a normal message.
    pub msg_type: u8,
    pub body: Vec<u8>,
}
pub fn encrypt(record: &mut SessionRecord, data: &[u8], us: &OurIdentity, our_reg_id: u32) -> Result<Encrypted> {
    let i = record.open_session().ok_or_else(|| Boom::new("No open session"))?;
    let s = &mut record.sessions[i];
    let c = s.chain(&s.eph_pub).ok_or_else(|| Boom::new("Cannot read properties of undefined (reading 'chainType')"))?;
    if !s.chains[c].sending {
        return Err(Boom::new("Tried to encrypt on a receiving chain"));
    }
    let next = s.chains[c].counter + 1;
    fill_message_keys(&mut s.chains[c], next)?;
    let counter = s.chains[c].counter;
    let mk_idx = s.chains[c].message_keys.iter().position(|(n, _)| *n == counter as u32).ok_or_else(|| Boom::new("message key missing"))?;
    let (_, mk) = s.chains[c].message_keys.remove(mk_idx);
    let keys = crypto::derive_secrets(&mk, &ZERO32, b"WhisperMessageKeys", 3);
    let ct = crypto::aes_encrypt_with_iv(data, &keys[0], &keys[2][..16])?;
    let mut msg = Vec::with_capacity(ct.len() + 48);
    put_bytes(&mut msg, 0x0a, &s.eph_pub);
    put_u32(&mut msg, 0x10, counter as u32);
    put_u32(&mut msg, 0x18, s.previous_counter as u32);
    put_bytes(&mut msg, 0x22, &ct);
    let mut mac_in = Vec::with_capacity(msg.len() + 67);
    mac_in.extend_from_slice(&us.pub_key);
    mac_in.extend_from_slice(&s.remote_identity_key);
    mac_in.push(TUPLE);
    mac_in.extend_from_slice(&msg);
    let mac = crypto::hmac_sha256(&keys[1], &mac_in);
    let mut result = Vec::with_capacity(msg.len() + 9);
    result.push(TUPLE);
    result.extend_from_slice(&msg);
    result.extend_from_slice(&mac[..8]);
    let pending = s.pending_pre_key.clone();
    record.remove_old_sessions()?;
    match pending {
        Some(p) => {
            let mut o = Vec::with_capacity(result.len() + 90);
            o.push(TUPLE);
            if let Some(id) = p.pre_key_id.filter(|v| *v != 0) {
                put_u32(&mut o, 0x08, id);
            }
            put_bytes(&mut o, 0x12, &p.base_key);
            put_bytes(&mut o, 0x1a, &us.pub_key);
            put_bytes(&mut o, 0x22, &result);
            put_u32(&mut o, 0x28, our_reg_id);
            put_u32(&mut o, 0x30, p.signed_key_id);
            Ok(Encrypted { msg_type: 3, body: o })
        }
        None => Ok(Encrypted { msg_type: 1, body: result }),
    }
}
fn do_decrypt(s: &mut SessionEntry, buf: &[u8], us: &OurIdentity) -> Result<Vec<u8>> {
    if buf.len() < 9 {
        return Err(Boom::new("Incompatible version number on WhisperMessage"));
    }
    let (v1, v2) = (buf[0] >> 4, buf[0] & 15);
    if v2 > 3 || v1 < 3 {
        return Err(Boom::new("Incompatible version number on WhisperMessage"));
    }
    let proto = &buf[1..buf.len() - 8];
    let (mut eph, mut counter, mut prev, mut ct): (&[u8], u32, u32, &[u8]) = (&[], 0, 0, &[]);
    let mut p = PbFields { b: proto, i: 0 };
    while let Some((f, v, d)) = p.next()? {
        match f {
            1 => eph = d,
            2 => counter = v as u32,
            3 => prev = v as u32,
            4 => ct = d,
            _ => {}
        }
    }
    maybe_step_ratchet(s, eph, prev)?;
    let c = s.chain(eph).ok_or_else(|| Boom::new("chain missing"))?;
    if s.chains[c].sending {
        return Err(Boom::new("Tried to decrypt on a sending chain"));
    }
    fill_message_keys(&mut s.chains[c], counter as i32)?;
    let Some(p) = s.chains[c].message_keys.iter().position(|(n, _)| *n == counter) else {
        return Err(Boom::new("Key used already or never filled"));
    };
    let (_, mk) = s.chains[c].message_keys.remove(p);
    let keys = crypto::derive_secrets(&mk, &ZERO32, b"WhisperMessageKeys", 3);
    let mut mac_in = Vec::with_capacity(proto.len() + 67);
    mac_in.extend_from_slice(&s.remote_identity_key);
    mac_in.extend_from_slice(&us.pub_key);
    mac_in.push(TUPLE);
    mac_in.extend_from_slice(proto);
    let mac = crypto::hmac_sha256(&keys[1], &mac_in);
    if mac[..8] != buf[buf.len() - 8..] {
        return Err(Boom::new("Bad MAC"));
    }
    let pt = crypto::aes_decrypt_with_iv(ct, &keys[0], &keys[2][..16])?;
    s.pending_pre_key = None;
    Ok(pt)
}
pub fn decrypt_whisper(record: &mut SessionRecord, data: &[u8], us: &OurIdentity) -> Result<Vec<u8>> {
    if record.sessions.is_empty() {
        return Err(Boom::new("No sessions available"));
    }
    let mut order: Vec<usize> = (0..record.sessions.len()).collect();
    order.sort_by(|a, b| record.sessions[*b].used.cmp(&record.sessions[*a].used));
    for i in order {
        if let Ok(pt) = do_decrypt(&mut record.sessions[i], data, us) {
            record.sessions[i].used = now_ms();
            record.remove_old_sessions()?;
            return Ok(pt);
        }
    }
    Err(Boom::new("No matching sessions found for message"))
}
/// Returns the plaintext and the prekey id that the caller must now remove.
pub fn decrypt_pre_key(record: &mut SessionRecord, data: &[u8], src: &dyn PreKeySource, us: &OurIdentity) -> Result<(Vec<u8>, Option<u32>)> {
    if data.is_empty() || (data[0] & 15) > 3 || (data[0] >> 4) < 3 {
        return Err(Boom::new("Incompatible version number on PreKeyWhisperMessage"));
    }
    let m = parse_pre_key_message(&data[1..])?;
    if record.sessions.is_empty() && m.registration_id.is_none() {
        return Err(Boom::new("No registrationId"));
    }
    let pk = init_incoming(record, &m, src, us)?;
    let i = record.session_by_base(m.base_key)?.ok_or_else(|| Boom::new("session required"))?;
    let pt = do_decrypt(&mut record.sessions[i], m.message, us)?;
    record.remove_old_sessions()?;
    Ok((pt, pk))
}
