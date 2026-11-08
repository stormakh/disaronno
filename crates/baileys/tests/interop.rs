//! Reads vectors made by the real Baileys build (scripts/interop.mjs) and writes replies for it to read.
use baileys::auth::*;
use baileys::crypto::{self, KeyPair};
use baileys::proto::pb::{Json, PbMessage};
use baileys::signal::repository::*;
use baileys::utils::lt_hash::subtract_then_add;
use baileys::wabinary::*;
use std::sync::Arc;

const ALICE: &str = "1111@s.whatsapp.net";
const GROUP: &str = "1203630@g.us";
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    let mut o = String::with_capacity(b.len() * 2);
    for x in b {
        o.push_str(&format!("{x:02x}"));
    }
    o
}
fn vectors() -> Json {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests-data/interop.json");
    Json::parse(&std::fs::read_to_string(p).expect("run scripts/interop.mjs gen")).unwrap()
}
fn h(v: &Json, k: &str) -> Vec<u8> {
    unhex(v.get(k).and_then(Json::as_str).unwrap_or_else(|| panic!("missing {k}")))
}
fn k32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}
#[test]
fn crypto_matches_baileys() {
    let v = vectors();
    let (key, iv16, iv12, aad, data) = (h(&v, "key"), h(&v, "iv16"), h(&v, "iv12"), h(&v, "aad"), h(&v, "data"));
    assert_eq!(crypto::sha256(&data).to_vec(), h(&v, "sha256"));
    assert_eq!(crypto::md5(&data).to_vec(), h(&v, "md5"));
    assert_eq!(crypto::hmac_sha256(&key, &data).to_vec(), h(&v, "hmac256"));
    assert_eq!(crypto::hmac_sha512(&key, &data).to_vec(), h(&v, "hmac512"));
    assert_eq!(crypto::hkdf(&data, 112, None, b"WhatsApp Image Keys"), h(&v, "hkdf"));
    assert_eq!(crypto::hkdf(&data, 64, Some(&key), b""), h(&v, "hkdf_salt"));
    assert_eq!(crypto::aes_encrypt_gcm(&data, &key, &iv12, &aad).unwrap(), h(&v, "gcm"));
    assert_eq!(crypto::aes_decrypt_gcm(&h(&v, "gcm"), &key, &iv12, &aad).unwrap(), data);
    assert!(crypto::aes_decrypt_gcm(&h(&v, "gcm"), &key, &iv12, b"other").is_err());
    assert_eq!(crypto::aes_encrypt_ctr(&data, &key, &iv16).unwrap(), h(&v, "ctr"));
    assert_eq!(crypto::aes_encrypt_with_iv(&data, &key, &iv16).unwrap(), h(&v, "cbc"));
    assert_eq!(crypto::aes_decrypt_with_iv(&h(&v, "cbc"), &key, &iv16).unwrap(), data);
    assert_eq!(crypto::derive_pairing_code_key("ABCD1234", &key).to_vec(), h(&v, "pbkdf"));
    let a = k32(&h(&v, "x_a_priv"));
    assert_eq!(crypto::key_from_private(a).public.to_vec(), h(&v, "x_a_pub"));
    assert_eq!(crypto::shared_key(&a, &h(&v, "x_b_pub")).unwrap().to_vec(), h(&v, "x_shared"));
    assert_eq!(crypto::sign(&a, &h(&v, "sig_msg")).to_vec(), h(&v, "sig"), "signature bytes must match curve25519-js");
    assert!(crypto::verify(&h(&v, "x_a_pub"), &h(&v, "sig_msg"), &h(&v, "sig")));
    assert!(!crypto::verify(&h(&v, "x_a_pub"), b"other", &h(&v, "sig")));
    let base = vec![5u8; 128];
    let (i1, i2, i3) = (vec![1u8; 32], vec![2u8; 20], vec![3u8; 32]);
    assert_eq!(subtract_then_add(&base, &[&i1, &i2], &[&i3]), h(&v, "lt"));
}
#[test]
fn binary_nodes_match_baileys() {
    let v = vectors();
    for n in v.get("nodes").unwrap().as_arr().unwrap() {
        let b = unhex(n.as_str().unwrap());
        let node = decode_binary_node(&b).unwrap();
        assert_eq!(encode_binary_node(&node).unwrap(), b);
    }
}
#[test]
fn proto_matches_baileys() {
    let v = vectors();
    let p = v.get("proto").unwrap();
    let b = h(p, "wmi");
    let m = baileys::proto::WebMessageInfo::decode(&b).unwrap();
    assert_eq!(m.encode(), b);
    let want = Json::parse(p.get("wmi_json").unwrap().as_str().unwrap()).unwrap();
    assert_eq!(m.to_json().get("message"), want.get("message"));
    assert_eq!(m.to_json().get("messageTimestamp"), want.get("messageTimestamp"));
    let back = baileys::proto::WebMessageInfo::from_json(&want).unwrap();
    assert_eq!(back.encode(), b);
}
fn repo_for(reg: u32, id: KeyPair, spk: KeyPair, sig: [u8; 64], keys: Arc<MemoryKeyStore>) -> LibSignalRepository {
    let creds = SignalCreds { signed_identity_key: id, signed_pre_key: crypto::SignedKeyPair { key_pair: spk, signature: sig, key_id: 1 }, registration_id: reg };
    LibSignalRepository::new(creds, keys, None)
}
#[test]
fn signal_talks_to_baileys() {
    let v = vectors();
    let s = v.get("signal").unwrap();
    let b = s.get("bob").unwrap();
    let keys = Arc::new(MemoryKeyStore::new());
    keys.set_one(KeyKind::PreKey, "1", Some(KeyValue::PreKey(KeyPair { private: k32(&h(b, "pk_priv")), public: k32(&h(b, "pk_pub")) }))).unwrap();
    let repo = repo_for(b.get("reg").unwrap().as_f64().unwrap() as u32, KeyPair { private: k32(&h(b, "id_priv")), public: k32(&h(b, "id_pub")) }, KeyPair { private: k32(&h(b, "spk_priv")), public: k32(&h(b, "spk_pub")) }, h(b, "spk_sig").try_into().unwrap(), keys.clone());
    for m in s.get("msgs").unwrap().as_arr().unwrap() {
        let pt = repo.decrypt_message(ALICE, m.get("type").unwrap().as_str().unwrap(), &h(m, "c")).unwrap();
        assert_eq!(pt, m.get("p").unwrap().as_str().unwrap().as_bytes());
    }
    assert!(keys.get_one(KeyKind::PreKey, "1").unwrap().is_none(), "used prekey must be removed");
    repo.process_sender_key_distribution_message(Some(GROUP), &h(s, "skdm"), ALICE).unwrap();
    for m in s.get("groupMsgs").unwrap().as_arr().unwrap() {
        let pt = repo.decrypt_group_message(GROUP, ALICE, &h(m, "c")).unwrap();
        assert_eq!(pt, m.get("p").unwrap().as_str().unwrap().as_bytes());
    }
    // session records survive the JSON format that Baileys stores
    let KeyValue::Session(rec) = keys.get_one(KeyKind::Session, "1111.0").unwrap().unwrap() else { panic!() };
    let rt = baileys::signal::session::SessionRecord::from_json(&Json::parse(&rec.to_json().stringify()).unwrap()).unwrap();
    assert_eq!(rt, *rec);
    // replies for Node
    let mut to_alice = Vec::new();
    for t in ["reply one", "reply two", "reply three"] {
        let e = repo.encrypt_message(ALICE, t.as_bytes()).unwrap();
        to_alice.push(format!("{{\"type\":\"{}\",\"c\":\"{}\",\"p\":\"{t}\"}}", e.msg_type, hex(&e.ciphertext)));
    }
    // a new session that Rust starts, and group messages that Rust signs
    let (id, spk, pk) = (crypto::generate_key_pair(), crypto::generate_key_pair(), crypto::generate_key_pair());
    let sig = crypto::sign(&id.private, &crypto::generate_signal_pub_key(&spk.public));
    let (aid, aspk) = (crypto::generate_key_pair(), crypto::generate_key_pair());
    let akeys = Arc::new(MemoryKeyStore::new());
    let asig = crypto::sign(&aid.private, &crypto::generate_signal_pub_key(&aspk.public));
    let a = repo_for(777, aid, aspk, asig, akeys);
    let (idp, spkp, pkp) = (crypto::generate_signal_pub_key(&id.public), crypto::generate_signal_pub_key(&spk.public), crypto::generate_signal_pub_key(&pk.public));
    let bob = "2222@s.whatsapp.net";
    a.inject_e2e_session(bob, &E2ESession { registration_id: 555, identity_key: &idp, signed_pre_key: SignedPreKeyPub { key_id: 1, public_key: &spkp, signature: &sig }, pre_key: Some(PreKeyPub { key_id: 1, public_key: &pkp }) }).unwrap();
    let mut fresh = Vec::new();
    for t in ["fresh one", "fresh two"] {
        let e = a.encrypt_message(bob, t.as_bytes()).unwrap();
        fresh.push(format!("{{\"type\":\"{}\",\"c\":\"{}\",\"p\":\"{t}\"}}", e.msg_type, hex(&e.ciphertext)));
    }
    let skdm = a.get_sender_key_distribution_message(GROUP, ALICE).unwrap();
    let mut group = Vec::new();
    for t in ["group one", "group two", "group three"] {
        let e = a.encrypt_group_message(GROUP, ALICE, t.as_bytes()).unwrap();
        group.push(format!("{{\"c\":\"{}\",\"p\":\"{t}\"}}", hex(&e.ciphertext)));
    }
    let sign_k = crypto::generate_key_pair();
    let rsig = crypto::sign(&sign_k.private, b"rust signed");
    let out = format!(
        "{{\"to_alice\":[{}],\"fresh\":{{\"reg\":555,\"id_priv\":\"{}\",\"id_pub\":\"{}\",\"spk_priv\":\"{}\",\"spk_pub\":\"{}\",\"spk_sig\":\"{}\",\"pk_priv\":\"{}\",\"pk_pub\":\"{}\",\"msgs\":[{}],\"skdm\":\"{}\",\"group\":[{}]}},\"sig\":{{\"pub\":\"{}\",\"msg\":\"{}\",\"sig\":\"{}\"}}}}",
        to_alice.join(","), hex(&id.private), hex(&id.public), hex(&spk.private), hex(&spk.public), hex(&sig), hex(&pk.private), hex(&pk.public), fresh.join(","), hex(&skdm), group.join(","), hex(&sign_k.public), hex(b"rust signed"), hex(&rsig)
    );
    std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests-data/interop-rust.json"), out).unwrap();
}
