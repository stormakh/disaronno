//! Same behavior as Utils/signal.ts.
use crate::auth::*;
use crate::crypto::{self, KeyPair, SignedKeyPair, generate_signal_pub_key};
use crate::defaults::KEY_BUNDLE_TYPE;
use crate::error::{Boom, Result};
use crate::signal::repository::{E2ESession, PreKeyPub, SignalRepository, SignedPreKeyPub};
use crate::types::USyncQueryResultList;
use crate::utils::generics::encode_big_endian;
use crate::wabinary::*;
use waproto::pb::Bytes;

pub fn create_signal_identity(wid: &str, account_signature_key: &[u8]) -> SignalIdentity {
    SignalIdentity { identifier: ProtocolAddress { name: wid.to_string(), device_id: 0 }, identifier_key: generate_signal_pub_key(account_signature_key) }
}
pub fn get_pre_keys(keys: &dyn SignalKeyStore, min: u32, limit: u32) -> Result<KeyMap> {
    let ids: Vec<String> = (min..limit).map(|id| id.to_string()).collect();
    keys.get(KeyKind::PreKey, &ids)
}
#[derive(Clone, Debug, PartialEq)]
pub struct GeneratedPreKeys {
    pub new_pre_keys: Vec<(u32, KeyPair)>,
    /// Can be below `next_pre_key_id`, and below zero, when enough keys exist already.
    pub last_pre_key_id: i64,
    /// The first id and the count.
    pub pre_keys_range: (u32, u32),
}
pub fn generate_or_get_pre_keys(creds: &AuthenticationCreds, range: u32) -> GeneratedPreKeys {
    let avaliable = creds.next_pre_key_id as i64 - creds.first_unuploaded_pre_key_id as i64;
    let remaining = range as i64 - avaliable;
    let last_pre_key_id = creds.next_pre_key_id as i64 + remaining - 1;
    let mut new_pre_keys = Vec::new();
    if remaining > 0 {
        for i in creds.next_pre_key_id as i64..=last_pre_key_id {
            new_pre_keys.push((i as u32, crypto::generate_key_pair()));
        }
    }
    GeneratedPreKeys { new_pre_keys, last_pre_key_id, pre_keys_range: (creds.first_unuploaded_pre_key_id, range) }
}
fn bytes_child(tag: &str, b: impl Into<Bytes>) -> BinaryNode {
    BinaryNode::with_bytes(tag, Attrs::new(), b)
}
pub fn xmpp_signed_pre_key(key: &SignedKeyPair) -> BinaryNode {
    BinaryNode::with_nodes("skey", Attrs::new(), vec![bytes_child("id", encode_big_endian(key.key_id, 3)), bytes_child("value", key.key_pair.public), bytes_child("signature", key.signature)])
}
pub fn xmpp_pre_key(pair: &KeyPair, id: u32) -> BinaryNode {
    BinaryNode::with_nodes("key", Attrs::new(), vec![bytes_child("id", encode_big_endian(id, 3)), bytes_child("value", pair.public)])
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedSignedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}
/// The owned form of `E2ESession`. `as_session` lends it to `inject_e2e_session`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedE2ESession {
    pub registration_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_pre_key: OwnedSignedPreKey,
    pub pre_key: Option<OwnedPreKey>,
}
impl OwnedE2ESession {
    pub fn as_session(&self) -> E2ESession<'_> {
        E2ESession {
            registration_id: self.registration_id,
            identity_key: &self.identity_key,
            signed_pre_key: SignedPreKeyPub { key_id: self.signed_pre_key.key_id, public_key: &self.signed_pre_key.public_key, signature: &self.signed_pre_key.signature },
            pre_key: self.pre_key.as_ref().map(|p| PreKeyPub { key_id: p.key_id, public_key: &p.public_key }),
        }
    }
}
pub fn extract_e2e_session_from_retry_receipt(receipt: &BinaryNode) -> Option<OwnedE2ESession> {
    let keys_node = get_binary_node_child(Some(receipt), "keys")?;
    let type_buf = get_binary_node_child_buffer(Some(keys_node), "type")?;
    if type_buf.len() != 1 || type_buf[0] != KEY_BUNDLE_TYPE[0] {
        return None;
    }
    let identity = get_binary_node_child_buffer(Some(keys_node), "identity").filter(|b| b.len() == 32)?;
    let skey = get_binary_node_child(Some(keys_node), "skey")?;
    let registration_id = get_binary_node_child_uint(Some(receipt), "registration", 4)?;
    let signed_pub_key = get_binary_node_child_buffer(Some(skey), "value").filter(|b| b.len() == 32)?;
    let signed_sig = get_binary_node_child_buffer(Some(skey), "signature")?;
    let signed_key_id = get_binary_node_child_uint(Some(skey), "id", 3)?;
    let pre_key = match get_binary_node_child(Some(keys_node), "key") {
        Some(n) => {
            let pre_key_pub = get_binary_node_child_buffer(Some(n), "value").filter(|b| b.len() == 32)?;
            let key_id = get_binary_node_child_uint(Some(n), "id", 3)?;
            Some(OwnedPreKey { key_id, public_key: generate_signal_pub_key(pre_key_pub) })
        }
        None => None,
    };
    Some(OwnedE2ESession {
        registration_id,
        identity_key: generate_signal_pub_key(identity),
        signed_pre_key: OwnedSignedPreKey { key_id: signed_key_id, public_key: generate_signal_pub_key(signed_pub_key), signature: signed_sig.to_vec() },
        pre_key,
    })
}
fn parse_user_session(node: &BinaryNode) -> Result<OwnedE2ESession> {
    let bad = |what: &str| Boom::new(format!("invalid e2e session node: missing {what}"));
    let extract = |key: &BinaryNode| -> Result<(u32, Vec<u8>)> {
        let key_id = get_binary_node_child_uint(Some(key), "id", 3).ok_or_else(|| bad("id"))?;
        let value = get_binary_node_child_buffer(Some(key), "value").ok_or_else(|| bad("value"))?;
        Ok((key_id, generate_signal_pub_key(value)))
    };
    let signed_key = get_binary_node_child(Some(node), "skey").ok_or_else(|| bad("skey"))?;
    let identity = get_binary_node_child_buffer(Some(node), "identity").ok_or_else(|| bad("identity"))?;
    let registration_id = get_binary_node_child_uint(Some(node), "registration", 4).ok_or_else(|| bad("registration"))?;
    let (key_id, public_key) = extract(signed_key)?;
    let signature = get_binary_node_child_buffer(Some(signed_key), "signature").ok_or_else(|| bad("signature"))?.to_vec();
    let pre_key = match get_binary_node_child(Some(node), "key") {
        Some(k) => {
            let (key_id, public_key) = extract(k)?;
            Some(OwnedPreKey { key_id, public_key })
        }
        None => None,
    };
    Ok(OwnedE2ESession { registration_id, identity_key: generate_signal_pub_key(identity), signed_pre_key: OwnedSignedPreKey { key_id, public_key, signature }, pre_key })
}
pub fn parse_and_inject_e2e_sessions(node: &BinaryNode, repository: &dyn SignalRepository) -> Result<()> {
    let nodes = get_binary_node_children(get_binary_node_child(Some(node), "list"), "user");
    for n in &nodes {
        assert_node_error_free(n)?;
    }
    for n in &nodes {
        let session = parse_user_session(n)?;
        repository.inject_e2e_session(n.attr("jid").unwrap_or(""), &session.as_session())?;
    }
    Ok(())
}
/// The owned form of `FullJid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceJid {
    pub user: String,
    pub device: Option<u32>,
    pub domain_type: u32,
    pub server: String,
}
pub fn extract_device_jids(result: &[USyncQueryResultList], my_jid: &str, my_lid: &str, exclude_zero_devices: bool) -> Result<Vec<DeviceJid>> {
    let me = jid_decode(my_jid).ok_or_else(|| Boom::new(format!("invalid jid: {my_jid}")))?;
    let mut extracted = Vec::new();
    for user_result in result {
        let decoded = jid_decode(&user_result.id).ok_or_else(|| Boom::new(format!("invalid jid: {}", user_result.id)))?;
        let (user, server) = (decoded.user, decoded.server);
        // upstream keeps this value across the devices of one user
        let mut domain_type = decoded.domain_type;
        let Some(device_list) = user_result.devices.as_ref().and_then(|d| d.device_list.as_ref()) else { continue };
        for d in device_list {
            // if zero devices are not-excluded, or device is non zero
            let wanted = !exclude_zero_devices || d.id != 0;
            // either different user or if me user, not this device
            let not_me = (me.user != user && my_lid != user) || me.device != Some(d.id);
            // ensure that "key-index" is specified for "non-zero" devices, produces a bad req otherwise
            let keyed = d.id == 0 || d.key_index.is_some_and(|k| k != 0);
            if wanted && not_me && keyed {
                if d.is_hosted == Some(true) {
                    domain_type = if domain_type == domains::LID { domains::HOSTED_LID } else { domains::HOSTED };
                }
                extracted.push(DeviceJid { user: user.to_string(), device: Some(d.id), domain_type, server: get_server_from_domain_type(server, Some(domain_type)) });
            }
        }
    }
    Ok(extracted)
}
/// The ids and values in id order, as `Object.keys` lists integer keys.
fn sorted_pre_keys(pre_keys: KeyMap) -> Vec<(u32, KeyPair)> {
    let mut o: Vec<(u32, KeyPair)> = pre_keys
        .into_iter()
        .filter_map(|(k, v)| match (k.parse::<u32>(), v) {
            (Ok(id), KeyValue::PreKey(p)) => Some((id, p)),
            _ => None,
        })
        .collect();
    o.sort_by_key(|(id, _)| *id);
    o
}
/// get the next N keys for upload or processing
fn next_pre_key_ids(creds: &AuthenticationCreds, g: &GeneratedPreKeys) -> CredsUpdate {
    let next = (g.last_pre_key_id + 1).max(creds.next_pre_key_id as i64) as u32;
    let first = (g.last_pre_key_id + 1).max(creds.first_unuploaded_pre_key_id as i64) as u32;
    CredsUpdate { next_pre_key_id: Some(next), first_unuploaded_pre_key_id: Some(first), ..CredsUpdate::default() }
}
pub fn get_next_pre_keys(creds: &AuthenticationCreds, keys: &dyn SignalKeyStore, count: u32) -> Result<(CredsUpdate, Vec<(u32, KeyPair)>)> {
    let g = generate_or_get_pre_keys(creds, count);
    let update = next_pre_key_ids(creds, &g);
    keys.set(g.new_pre_keys.into_iter().map(|(id, p)| (KeyKind::PreKey, id.to_string(), Some(KeyValue::PreKey(p)))).collect())?;
    let pre_keys = get_pre_keys(keys, g.pre_keys_range.0, g.pre_keys_range.0 + g.pre_keys_range.1)?;
    Ok((update, sorted_pre_keys(pre_keys)))
}
/// `getNextPreKeysNode`, as the bytes of the stanza with the given `id`. A first upload has 812 keys,
/// so this does not hold the stanza tree and the copies of the keys in the key store at one time.
pub fn get_next_pre_keys_stanza(state: &AuthenticationState, count: u32, id: &str) -> Result<(CredsUpdate, Vec<u8>)> {
    let creds = state.creds.lock().unwrap().clone();
    let g = generate_or_get_pre_keys(&creds, count);
    let (start, len) = g.pre_keys_range;
    let all_new = g.new_pre_keys.len() as u32 == len && g.new_pre_keys.first().is_some_and(|(i, _)| *i == start);
    if !all_new {
        // some keys are in the store from an upload that failed
        let (update, pre_keys) = get_next_pre_keys(&creds, state.keys.as_ref(), count)?;
        return Ok((update, encode_pre_keys_stanza(&creds, &pre_keys, id)?));
    }
    let update = next_pre_key_ids(&creds, &g);
    let bytes = encode_pre_keys_stanza(&creds, &g.new_pre_keys, id)?;
    state.keys.set(g.new_pre_keys.into_iter().map(|(i, p)| (KeyKind::PreKey, i.to_string(), Some(KeyValue::PreKey(p)))).collect())?;
    Ok((update, bytes))
}
fn encode_pre_keys_stanza(creds: &AuthenticationCreds, pre_keys: &[(u32, KeyPair)], id: &str) -> Result<Vec<u8>> {
    let mut node = pre_keys_node(creds, pre_keys);
    node.attrs.set("id", id);
    encode_binary_node(&node)
}
pub fn get_next_pre_keys_node(state: &AuthenticationState, count: u32) -> Result<(CredsUpdate, BinaryNode)> {
    let creds = state.creds.lock().unwrap().clone();
    let (update, pre_keys) = get_next_pre_keys(&creds, state.keys.as_ref(), count)?;
    Ok((update, pre_keys_node(&creds, &pre_keys)))
}
fn pre_keys_node(creds: &AuthenticationCreds, pre_keys: &[(u32, KeyPair)]) -> BinaryNode {
    let list = pre_keys.iter().map(|(id, p)| xmpp_pre_key(p, *id)).collect();
    BinaryNode::with_nodes(
        "iq",
        Attrs::from([("xmlns", "encrypt"), ("type", "set"), ("to", S_WHATSAPP_NET)]),
        vec![
            bytes_child("registration", encode_big_endian(creds.registration_id, 4)),
            bytes_child("type", KEY_BUNDLE_TYPE),
            bytes_child("identity", creds.signed_identity_key.public),
            BinaryNode::with_nodes("list", Attrs::new(), list),
            xmpp_signed_pre_key(&creds.signed_pre_key),
        ],
    )
}
