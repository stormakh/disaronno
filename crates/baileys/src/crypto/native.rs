//! Audited crypto crates, used by every release build.
use crate::error::{Boom, Result};
use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher, block_padding::Pkcs7, inout::InOutBuf};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use md5::{Digest, Md5};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::{digest, hmac, pbkdf2};
use std::num::NonZeroU32;

pub fn sha256(d: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(digest::digest(&digest::SHA256, d).as_ref());
    o
}
pub fn sha512(d: &[u8]) -> [u8; 64] {
    let mut o = [0u8; 64];
    o.copy_from_slice(digest::digest(&digest::SHA512, d).as_ref());
    o
}
pub fn md5(d: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(&Md5::digest(d));
    o
}
pub fn hmac_sha256(key: &[u8], d: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), d).as_ref());
    o
}
/// A prepared HMAC key. Later signs reuse the hashed pads.
pub struct HmacKey(hmac::Key);
impl HmacKey {
    pub fn new(key: &[u8]) -> HmacKey {
        HmacKey(hmac::Key::new(hmac::HMAC_SHA256, key))
    }
    pub fn sign(&self, d: &[u8]) -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(hmac::sign(&self.0, d).as_ref());
        o
    }
}
pub fn hmac_sha512(key: &[u8], d: &[u8]) -> [u8; 64] {
    let mut o = [0u8; 64];
    o.copy_from_slice(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, key), d).as_ref());
    o
}
pub fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut o = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, NonZeroU32::new(iters).unwrap(), salt, pw, &mut o);
    o
}
pub fn random_bytes(o: &mut [u8]) {
    getrandom::fill(o).expect("system random source failed");
}
pub fn x25519_base(sk: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*sk).to_bytes()
}
pub fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    // SAFETY: each pointer is to 32 bytes. The return value only reports an all-zero result, which the other backend also returns as it is.
    unsafe { aws_lc_sys::X25519(o.as_mut_ptr(), sk.as_ptr(), pk.as_ptr()) };
    o
}
pub fn xeddsa_sign(sk: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let mut a_bytes = *sk;
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a_bytes);
    let big_a = EdwardsPoint::mul_base(&a).compress().to_bytes();
    let sign_bit = big_a[31] & 128;
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&a_bytes);
    buf.extend_from_slice(msg);
    let r = Scalar::from_bytes_mod_order_wide(&sha512(&buf));
    let big_r = (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    buf.clear();
    buf.extend_from_slice(&big_r);
    buf.extend_from_slice(&big_a);
    buf.extend_from_slice(msg);
    let h = Scalar::from_bytes_mod_order_wide(&sha512(&buf));
    let s = h * a + r;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&big_r);
    out[32..].copy_from_slice(s.as_bytes());
    out[63] |= sign_bit;
    out
}
pub fn xeddsa_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let sign = sig[63] >> 7;
    let Some(big_a) = MontgomeryPoint(*pk).to_edwards(sign) else { return false };
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    s_bytes[31] &= 127;
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&r_bytes);
    buf.extend_from_slice(big_a.compress().as_bytes());
    buf.extend_from_slice(msg);
    let h = Scalar::from_bytes_mod_order_wide(&sha512(&buf));
    // curve25519-js reduces nothing here: it multiplies the raw S bytes, so a non-canonical S still verifies
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-big_a, &s);
    let _ = CompressedEdwardsY(r_bytes);
    check.compress().as_bytes() == &r_bytes
}
fn gcm_key(key: &[u8]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, key).map(LessSafeKey::new).map_err(|_| Boom::new("Invalid key length"))
}
fn nonce(iv: &[u8]) -> Result<Nonce> {
    Nonce::try_assume_unique_for_key(iv).map_err(|_| Boom::new("Invalid IV length"))
}
pub fn aes_gcm_encrypt(p: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut o = Vec::with_capacity(p.len() + 16);
    o.extend_from_slice(p);
    gcm_key(key)?.seal_in_place_append_tag(nonce(iv)?, Aad::from(aad), &mut o).map_err(|_| Boom::new("encrypt failed"))?;
    Ok(o)
}
pub fn aes_gcm_decrypt(c: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut o = c.to_vec();
    let n = gcm_key(key)?
        .open_in_place(nonce(iv)?, Aad::from(aad), &mut o)
        .map_err(|_| Boom::new("Unsupported state or unable to authenticate data"))?
        .len();
    o.truncate(n);
    Ok(o)
}
pub fn aes_ctr(d: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let mut o = d.to_vec();
    let mut c = ctr::Ctr128BE::<Aes256>::new_from_slices(key, iv).map_err(|_| Boom::new("Invalid key or IV length"))?;
    c.apply_keystream(&mut o);
    Ok(o)
}
pub fn aes_cbc_encrypt(d: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let c = cbc::Encryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| Boom::new("Invalid key or IV length"))?;
    Ok(c.encrypt_padded_vec_mut::<Pkcs7>(d))
}
pub fn aes_cbc_decrypt(d: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let c = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| Boom::new("Invalid key or IV length"))?;
    c.decrypt_padded_vec_mut::<Pkcs7>(d).map_err(|_| Boom::new("bad decrypt"))
}
/// SHA-256 over data that arrives in parts.
pub struct Sha256Stream(digest::Context);
impl Sha256Stream {
    pub fn new() -> Sha256Stream {
        Sha256Stream(digest::Context::new(&digest::SHA256))
    }
    pub fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    pub fn finish(self) -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(self.0.finish().as_ref());
        o
    }
}
/// HMAC-SHA256 over data that arrives in parts.
pub struct HmacSha256Stream(hmac::Context);
impl HmacSha256Stream {
    pub fn new(key: &[u8]) -> HmacSha256Stream {
        HmacSha256Stream(hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key)))
    }
    pub fn update(&mut self, d: &[u8]) {
        self.0.update(d);
    }
    pub fn finish(self) -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(self.0.sign().as_ref());
        o
    }
}
/// AES-256-CBC encryption of whole blocks. The caller handles padding.
pub struct CbcEncryptor(cbc::Encryptor<Aes256>);
impl CbcEncryptor {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<CbcEncryptor> {
        cbc::Encryptor::<Aes256>::new_from_slices(key, iv).map(CbcEncryptor).map_err(|_| Boom::new("Invalid key or IV length"))
    }
    /// `d.len()` must be a multiple of 16.
    pub fn encrypt_blocks(&mut self, d: &mut [u8]) {
        let (blocks, _) = InOutBuf::from(d).into_chunks();
        self.0.encrypt_blocks_inout_mut(blocks);
    }
}
/// AES-256-CBC decryption of whole blocks. The caller handles padding.
pub struct CbcDecryptor(cbc::Decryptor<Aes256>);
impl CbcDecryptor {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<CbcDecryptor> {
        cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map(CbcDecryptor).map_err(|_| Boom::new("Invalid key or IV length"))
    }
    /// `d.len()` must be a multiple of 16.
    pub fn decrypt_blocks(&mut self, d: &mut [u8]) {
        let (blocks, _) = InOutBuf::from(d).into_chunks();
        self.0.decrypt_blocks_inout_mut(blocks);
    }
}
