//! Crypto primitives, same results as Utils/crypto.ts and libsignal/src/crypto.js.
#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
use native as backend;
#[cfg(all(feature = "native", target_arch = "x86_64"))]
pub mod hkdf_x8;
#[cfg(any(test, not(feature = "native")))]
pub mod soft;
#[cfg(not(feature = "native"))]
use soft as backend;

use crate::error::{Boom, Result};
use std::sync::OnceLock;

pub use backend::{CbcDecryptor, CbcEncryptor, HmacKey, HmacSha256Stream, Sha256Stream, hmac_sha256, hmac_sha512, md5, pbkdf2_sha256, random_bytes, sha256, sha512};

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

const KEY_BUNDLE_TYPE: u8 = 5;

/// Adds the version byte that signal functions need on public keys.
pub fn generate_signal_pub_key(k: &[u8]) -> Vec<u8> {
    if k.len() == 33 {
        return k.to_vec();
    }
    let mut v = Vec::with_capacity(33);
    v.push(KEY_BUNDLE_TYPE);
    v.extend_from_slice(k);
    v
}

/// Accepts a 32-byte key, or a 33-byte key with the version byte.
fn scrub(k: &[u8]) -> Result<[u8; 32]> {
    let s = match k.len() {
        33 if k[0] == KEY_BUNDLE_TYPE => &k[1..],
        32 => k,
        _ => return Err(Boom::new("Invalid public key")),
    };
    let mut o = [0u8; 32];
    o.copy_from_slice(s);
    Ok(o)
}

pub fn key_from_private(private: [u8; 32]) -> KeyPair {
    KeyPair { private, public: backend::x25519_base(&private) }
}
pub fn generate_key_pair() -> KeyPair {
    let mut p = [0u8; 32];
    random_bytes(&mut p);
    // the same clamp that a generated X25519 key has on disk in Baileys
    p[0] &= 248;
    p[31] &= 127;
    p[31] |= 64;
    key_from_private(p)
}
pub fn shared_key(private: &[u8; 32], public: &[u8]) -> Result<[u8; 32]> {
    Ok(backend::x25519(private, &scrub(public)?))
}
/// XEdDSA signature, same bytes as curve25519-js without random input.
pub fn sign(private: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    backend::xeddsa_sign(private, msg)
}
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let Ok(k) = scrub(public) else { return false };
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    backend::xeddsa_verify(&k, msg, &s)
}
pub fn signed_key_pair(identity: &KeyPair, key_id: u32) -> SignedKeyPair {
    let key_pair = generate_key_pair();
    let signature = sign(&identity.private, &generate_signal_pub_key(&key_pair.public));
    SignedKeyPair { key_pair, signature, key_id }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedKeyPair {
    pub key_pair: KeyPair,
    pub signature: [u8; 64],
    pub key_id: u32,
}

fn zero_salt_key() -> &'static HmacKey {
    static K: OnceLock<HmacKey> = OnceLock::new();
    K.get_or_init(|| HmacKey::new(&[0u8; 32]))
}
/// RFC 5869. A missing salt means 32 zero bytes.
pub fn hkdf(input: &[u8], len: usize, salt: Option<&[u8]>, info: &[u8]) -> Vec<u8> {
    let prk = match salt.filter(|s| !s.is_empty()) {
        Some(s) => hmac_sha256(s, input),
        None => zero_salt_key().sign(input),
    };
    let key = HmacKey::new(&prk);
    let mut out = Vec::with_capacity(len + 32);
    let mut t: Vec<u8> = Vec::with_capacity(32 + info.len() + 1);
    let mut i = 1u8;
    while out.len() < len {
        t.extend_from_slice(info);
        t.push(i);
        let h = key.sign(&t);
        out.extend_from_slice(&h);
        t.clear();
        t.extend_from_slice(&h);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// libsignal deriveSecrets: HKDF that returns 32-byte chunks, with an empty-key salt of 32 bytes.
pub fn derive_secrets(input: &[u8], salt: &[u8; 32], info: &[u8], chunks: usize) -> Vec<[u8; 32]> {
    let prk = if *salt == [0u8; 32] { zero_salt_key().sign(input) } else { hmac_sha256(salt, input) };
    let key = HmacKey::new(&prk);
    let mut res: Vec<[u8; 32]> = Vec::with_capacity(chunks);
    let mut buf: Vec<u8> = Vec::with_capacity(32 + info.len() + 1);
    for i in 0..chunks {
        buf.clear();
        if let Some(p) = res.last() {
            buf.extend_from_slice(p);
        }
        buf.extend_from_slice(info);
        buf.push(i as u8 + 1);
        res.push(key.sign(&buf));
    }
    res
}

/// Tag is appended to the ciphertext.
pub fn aes_encrypt_gcm(plaintext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    backend::aes_gcm_encrypt(plaintext, key, iv, aad)
}
pub fn aes_decrypt_gcm(ciphertext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    backend::aes_gcm_decrypt(ciphertext, key, iv, aad)
}
pub fn aes_encrypt_ctr(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    backend::aes_ctr(data, key, iv)
}
pub fn aes_decrypt_ctr(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    backend::aes_ctr(data, key, iv)
}
pub fn aes_encrypt_with_iv(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    backend::aes_cbc_encrypt(data, key, iv)
}
pub fn aes_decrypt_with_iv(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    backend::aes_cbc_decrypt(data, key, iv)
}
/// CBC with a random IV in front of the ciphertext.
pub fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    random_bytes(&mut iv);
    let ct = backend::aes_cbc_encrypt(data, key, &iv)?;
    let mut o = Vec::with_capacity(16 + ct.len());
    o.extend_from_slice(&iv);
    o.extend_from_slice(&ct);
    Ok(o)
}
/// CBC where the IV is in front of the ciphertext.
pub fn aes_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(Boom::new("Invalid initialization vector"));
    }
    backend::aes_cbc_decrypt(&data[16..], key, &data[..16])
}
pub fn derive_pairing_code_key(code: &str, salt: &[u8]) -> [u8; 32] {
    pbkdf2_sha256(code.as_bytes(), salt, 2 << 16)
}

#[cfg(test)]
mod backend_agreement {
    use super::*;
    /// The dev-only fallback must give the same result as the release backend.
    #[test]
    fn soft_matches_native() {
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let iv12 = [3u8; 12];
        for n in [0usize, 1, 15, 16, 17, 55, 56, 64, 111, 112, 1000] {
            let d: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
            assert_eq!(sha256(&d), soft::sha256(&d));
            assert_eq!(sha512(&d), soft::sha512(&d));
            assert_eq!(md5(&d), soft::md5(&d));
            assert_eq!(hmac_sha256(&key, &d), soft::hmac_sha256(&key, &d));
            assert_eq!(hmac_sha512(&key, &d), soft::hmac_sha512(&key, &d));
            let cbc = aes_encrypt_with_iv(&d, &key, &iv).unwrap();
            assert_eq!(cbc, soft::aes_cbc_encrypt(&d, &key, &iv).unwrap());
            assert_eq!(soft::aes_cbc_decrypt(&cbc, &key, &iv).unwrap(), d);
            assert_eq!(aes_encrypt_ctr(&d, &key, &iv).unwrap(), soft::aes_ctr(&d, &key, &iv).unwrap());
            let gcm = aes_encrypt_gcm(&d, &key, &iv12, b"a").unwrap();
            assert_eq!(gcm, soft::aes_gcm_encrypt(&d, &key, &iv12, b"a").unwrap());
            assert_eq!(soft::aes_gcm_decrypt(&gcm, &key, &iv12, b"a").unwrap(), d);
        }
        assert_eq!(pbkdf2_sha256(b"p", b"s", 10), soft::pbkdf2_sha256(b"p", b"s", 10));
        for _ in 0..8 {
            let (a, b) = (generate_key_pair(), generate_key_pair());
            assert_eq!(a.public, soft::x25519_base(&a.private));
            assert_eq!(shared_key(&a.private, &b.public).unwrap(), soft::x25519(&a.private, &b.public));
            let sig = sign(&a.private, b"message");
            assert_eq!(sig, soft::xeddsa_sign(&a.private, b"message"));
            assert!(soft::xeddsa_verify(&a.public, b"message", &sig));
            assert!(!soft::xeddsa_verify(&a.public, b"massage", &sig));
        }
        // a public key with the top bit set, and keys of small order that give an all-zero result
        let k = generate_key_pair();
        let mut high = generate_key_pair().public;
        high[31] |= 128;
        let mut one = [0u8; 32];
        one[0] = 1;
        for p in [high, [0u8; 32], one] {
            assert_eq!(shared_key(&k.private, &p).unwrap(), soft::x25519(&k.private, &p));
        }
    }
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn hkdf_x8_matches_both_backends() {
        const INFO: &[u8; 24] = b"WhatsApp Patch Integrity";
        for round in 0..64u8 {
            let mut items = [[0u8; 32]; 8];
            for it in &mut items {
                random_bytes(it);
            }
            if round == 0 {
                items = [[0u8; 32]; 8];
            }
            let refs: [&[u8; 32]; 8] = std::array::from_fn(|i| &items[i]);
            let got = hkdf_x8::hkdf_128_x8(&refs, INFO).expect("this test needs AVX2");
            for (o, it) in got.iter().zip(&items) {
                assert_eq!(o.as_slice(), hkdf(it, 128, None, INFO));
                let prk = soft::hmac_sha256(&[0u8; 32], it);
                let mut expected = Vec::new();
                let mut t = Vec::new();
                for n in 1..=4u8 {
                    t.extend_from_slice(INFO);
                    t.push(n);
                    let h = soft::hmac_sha256(&prk, &t);
                    expected.extend_from_slice(&h);
                    t = h.to_vec();
                }
                assert_eq!(o.as_slice(), expected);
            }
        }
    }
}
