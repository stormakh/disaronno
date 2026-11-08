//! Sender keys for group messages, same behavior as src/Signal/Group.
use crate::crypto;
use crate::error::{Boom, Result};
use waproto::pb::{Json, PbMessage, base64_decode, base64_encode};

const MAX_MESSAGE_KEYS: usize = 2000;
const MAX_STATES: usize = 5;
const SIGNATURE_LENGTH: usize = 64;
const CURRENT_VERSION: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SenderMessageKeyEntry {
    pub iteration: u32,
    pub seed: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SenderKeyState {
    pub sender_key_id: u32,
    pub chain_iteration: u32,
    pub chain_seed: Vec<u8>,
    pub signing_public: Vec<u8>,
    pub signing_private: Vec<u8>,
    pub sender_message_keys: Vec<SenderMessageKeyEntry>,
}
pub struct SenderMessageKey {
    pub iteration: u32,
    pub iv: Vec<u8>,
    pub cipher_key: Vec<u8>,
    pub seed: Vec<u8>,
}
impl SenderMessageKey {
    pub fn new(iteration: u32, seed: Vec<u8>) -> SenderMessageKey {
        let d = crypto::derive_secrets(&seed, &[0u8; 32], b"WhisperGroup", 3);
        let mut k = Vec::with_capacity(32);
        k.extend_from_slice(&d[0][16..]);
        k.extend_from_slice(&d[1][..16]);
        SenderMessageKey { iteration, iv: d[0][..16].to_vec(), cipher_key: k, seed }
    }
}
fn chain_msg_key(iteration: u32, seed: &[u8]) -> SenderMessageKey {
    SenderMessageKey::new(iteration, crypto::hmac_sha256(seed, &[1]).to_vec())
}
impl SenderKeyState {
    pub fn signing_key_public(&self) -> Vec<u8> {
        if self.signing_public.len() == 32 {
            return crypto::generate_signal_pub_key(&self.signing_public);
        }
        self.signing_public.clone()
    }
    pub fn has_sender_message_key(&self, iteration: u32) -> bool {
        self.sender_message_keys.iter().any(|k| k.iteration == iteration)
    }
    pub fn add_sender_message_key(&mut self, k: &SenderMessageKey) {
        self.sender_message_keys.push(SenderMessageKeyEntry { iteration: k.iteration, seed: k.seed.clone() });
        if self.sender_message_keys.len() > MAX_MESSAGE_KEYS {
            self.sender_message_keys.remove(0);
        }
    }
    pub fn remove_sender_message_key(&mut self, iteration: u32) -> Option<SenderMessageKey> {
        let i = self.sender_message_keys.iter().position(|k| k.iteration == iteration)?;
        let k = self.sender_message_keys.remove(i);
        Some(SenderMessageKey::new(k.iteration, k.seed))
    }
    fn sender_key(&mut self, iteration: u32) -> Result<SenderMessageKey> {
        if self.chain_iteration > iteration {
            if self.has_sender_message_key(iteration) {
                return self.remove_sender_message_key(iteration).ok_or_else(|| Boom::new("No sender message key found for iteration"));
            }
            return Err(Boom::new(format!("Received message with old counter: {}, {}", self.chain_iteration, iteration)));
        }
        if iteration - self.chain_iteration > 2000 {
            return Err(Boom::new("Over 2000 messages into the future!"));
        }
        let mut it = self.chain_iteration;
        let mut seed = self.chain_seed.clone();
        while it < iteration {
            let k = chain_msg_key(it, &seed);
            self.add_sender_message_key(&k);
            seed = crypto::hmac_sha256(&seed, &[2]).to_vec();
            it += 1;
        }
        self.chain_seed = crypto::hmac_sha256(&seed, &[2]).to_vec();
        self.chain_iteration = it + 1;
        Ok(chain_msg_key(it, &seed))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SenderKeyRecord {
    pub states: Vec<SenderKeyState>,
}
impl SenderKeyRecord {
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
    pub fn state_mut(&mut self, key_id: Option<u32>) -> Option<&mut SenderKeyState> {
        match key_id {
            None => self.states.last_mut(),
            Some(id) => self.states.iter_mut().find(|s| s.sender_key_id == id),
        }
    }
    pub fn add_sender_key_state(&mut self, id: u32, iteration: u32, chain_key: &[u8], signature_key: &[u8]) {
        self.states.push(SenderKeyState { sender_key_id: id, chain_iteration: iteration, chain_seed: chain_key.to_vec(), signing_public: signature_key.to_vec(), signing_private: Vec::new(), sender_message_keys: Vec::new() });
        if self.states.len() > MAX_STATES {
            self.states.remove(0);
        }
    }
    pub fn set_sender_key_state(&mut self, id: u32, iteration: u32, chain_key: &[u8], public: &[u8], private: &[u8]) {
        self.states.clear();
        self.states.push(SenderKeyState { sender_key_id: id, chain_iteration: iteration, chain_seed: chain_key.to_vec(), signing_public: public.to_vec(), signing_private: private.to_vec(), sender_message_keys: Vec::new() });
    }
    /// Same text as `JSON.stringify(record.serialize())`, where a Buffer has the `{type, data}` form.
    pub fn to_json(&self) -> Json {
        let b = |v: &[u8]| Json::Obj(vec![("type".to_string(), Json::Str("Buffer".to_string())), ("data".to_string(), Json::Arr(v.iter().map(|x| Json::Num(*x as f64)).collect()))]);
        let n = |v: u32| Json::Num(v as f64);
        Json::Arr(
            self.states
                .iter()
                .map(|s| {
                    Json::Obj(vec![
                        ("senderKeyId".to_string(), n(s.sender_key_id)),
                        ("senderChainKey".to_string(), Json::Obj(vec![("iteration".to_string(), n(s.chain_iteration)), ("seed".to_string(), b(&s.chain_seed))])),
                        ("senderSigningKey".to_string(), Json::Obj(vec![("public".to_string(), b(&s.signing_public)), ("private".to_string(), b(&s.signing_private))])),
                        ("senderMessageKeys".to_string(), Json::Arr(s.sender_message_keys.iter().map(|k| Json::Obj(vec![("iteration".to_string(), n(k.iteration)), ("seed".to_string(), b(&k.seed))])).collect())),
                    ])
                })
                .collect(),
        )
    }
    pub fn from_json(j: &Json) -> Result<SenderKeyRecord> {
        let mut r = SenderKeyRecord::default();
        let Json::Arr(a) = j else { return Err(Boom::new("invalid sender key record")) };
        for s in a {
            r.states.push(state_from_json(s)?);
        }
        Ok(r)
    }
}
/// A missing `senderMessageKeys` array gives an empty list. Old records do not have it.
pub fn state_from_json(s: &Json) -> Result<SenderKeyState> {
    let num = |v: Option<&Json>| v.and_then(Json::as_f64).unwrap_or(0.0) as u32;
    let ck = s.get("senderChainKey");
    let sk = s.get("senderSigningKey");
    let mut keys = Vec::new();
    if let Some(Json::Arr(a)) = s.get("senderMessageKeys") {
        for k in a {
            keys.push(SenderMessageKeyEntry { iteration: num(k.get("iteration")), seed: json_bytes(k.get("seed")) });
        }
    }
    Ok(SenderKeyState {
        sender_key_id: num(s.get("senderKeyId")),
        chain_iteration: num(ck.and_then(|c| c.get("iteration"))),
        chain_seed: json_bytes(ck.and_then(|c| c.get("seed"))),
        signing_public: json_bytes(sk.and_then(|c| c.get("public"))),
        signing_private: json_bytes(sk.and_then(|c| c.get("private"))),
        sender_message_keys: keys,
    })
}
/// Reads the three Buffer forms that BufferJSON accepts.
fn json_bytes(v: Option<&Json>) -> Vec<u8> {
    match v {
        Some(Json::Bytes(b)) => b.clone(),
        Some(Json::Str(s)) => base64_decode(s),
        Some(Json::Obj(o)) => match v.and_then(|x| x.get("data")) {
            Some(Json::Str(s)) => base64_decode(s),
            Some(Json::Arr(a)) => a.iter().map(|x| x.as_f64().unwrap_or(0.0) as u8).collect(),
            _ => o.iter().map(|(_, x)| x.as_f64().unwrap_or(0.0) as u8).collect(),
        },
        Some(Json::Arr(a)) => a.iter().map(|x| x.as_f64().unwrap_or(0.0) as u8).collect(),
        _ => Vec::new(),
    }
}
#[allow(dead_code)]
fn _b64(v: &[u8]) -> String {
    base64_encode(v)
}

/// `iteration == 0` stays 0 and others use the next one, as group_cipher.ts does.
pub fn group_encrypt(record: &mut SenderKeyRecord, plaintext: &[u8]) -> Result<Vec<u8>> {
    let st = record.state_mut(None).ok_or_else(|| Boom::new("No session to encrypt message"))?;
    let it = st.chain_iteration;
    let k = st.sender_key(if it == 0 { 0 } else { it + 1 })?;
    let ct = crypto::aes_encrypt_with_iv(plaintext, &k.cipher_key, &k.iv).map_err(|_| Boom::new("InvalidMessageException"))?;
    let m = waproto::SenderKeyMessage::new().with_id(st.sender_key_id).with_iteration(k.iteration).with_ciphertext(ct);
    let version = (CURRENT_VERSION << 4) | CURRENT_VERSION;
    let body = m.encode();
    let mut out = Vec::with_capacity(1 + body.len() + SIGNATURE_LENGTH);
    out.push(version);
    out.extend_from_slice(&body);
    let private: &[u8] = &st.signing_private;
    let pk: [u8; 32] = private.try_into().map_err(|_| Boom::new(format!("Incorrect private key length: {}", private.len())))?;
    let sig = crypto::sign(&pk, &out);
    out.extend_from_slice(&sig);
    Ok(out)
}
pub fn group_decrypt(record: &mut SenderKeyRecord, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < SIGNATURE_LENGTH + 1 {
        return Err(Boom::new("Invalid signature"));
    }
    let split = bytes.len() - SIGNATURE_LENGTH;
    let m = waproto::SenderKeyMessage::decode(&bytes[1..split])?;
    let st = record.state_mut(Some(m.id().unwrap_or(0))).ok_or_else(|| Boom::new("No session found to decrypt message"))?;
    if !crypto::verify(&st.signing_key_public(), &bytes[..split], &bytes[split..]) {
        return Err(Boom::new("Invalid signature!"));
    }
    let k = st.sender_key(m.iteration().unwrap_or(0))?;
    crypto::aes_decrypt_with_iv(m.ciphertext().map_or(&[][..], |b| b.as_slice()), &k.cipher_key, &k.iv).map_err(|_| Boom::new("InvalidMessageException"))
}
/// A serialized SenderKeyDistributionMessage.
pub fn skdm_serialize(id: u32, iteration: u32, chain_key: &[u8], signing_key: &[u8]) -> Vec<u8> {
    let m = waproto::SenderKeyDistributionMessage::new().with_id(id).with_iteration(iteration).with_chain_key(chain_key).with_signing_key(signing_key);
    let b = m.encode();
    let mut o = Vec::with_capacity(1 + b.len());
    o.push((CURRENT_VERSION << 4) | CURRENT_VERSION);
    o.extend_from_slice(&b);
    o
}
pub fn skdm_parse(b: &[u8]) -> Result<waproto::SenderKeyDistributionMessage> {
    if b.is_empty() {
        return Err(Boom::new("empty distribution message"));
    }
    Ok(waproto::SenderKeyDistributionMessage::decode(&b[1..])?)
}
