//! Eight SHA-256 streams in one AVX2 register set, for `hkdf(item, 128, None, info)` over many 32-byte items.
//! It has no branch or table lookup on the data, the same as the single-stream code in `ring`.
use std::arch::x86_64::*;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
/// SHA-256 state after the 64-byte HMAC pad of an empty key, inner and outer.
const ZERO_KEY_INNER: [u32; 8] = [0xf454dead, 0x9725214f, 0x90daf2a0, 0xdf1228ea, 0x64e5750f, 0xa3924181, 0x824a932b, 0xf8e04e32];
const ZERO_KEY_OUTER: [u32; 8] = [0xd385480f, 0x7abb6477, 0x37c9c538, 0x5dd82467, 0x8e043a72, 0x753434b0, 0xdeb82818, 0x361d45a6];
const PAD_END: u32 = 0x80000000;
/// The bit length of an HMAC tail: one pad block and 32 bytes.
const BITS_PAD_DIGEST: u32 = (64 + 32) * 8;

type V = __m256i;
type State = [V; 8];
type Words = [V; 16];

#[inline]
#[target_feature(enable = "avx2")]
fn rotr<const R: i32, const L: i32>(x: V) -> V {
    _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x))
}
#[inline]
#[target_feature(enable = "avx2")]
fn add(a: V, b: V) -> V {
    _mm256_add_epi32(a, b)
}
#[inline]
#[target_feature(enable = "avx2")]
fn xor(a: V, b: V) -> V {
    _mm256_xor_si256(a, b)
}
#[inline]
#[target_feature(enable = "avx2")]
fn all(v: u32) -> V {
    _mm256_set1_epi32(v as i32)
}
#[target_feature(enable = "avx2")]
fn compress(state: &mut State, mut w: Words) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (i, k) in K.iter().enumerate() {
        if i >= 16 {
            let (x, y) = (w[(i + 1) & 15], w[(i + 14) & 15]);
            let s0 = xor(xor(rotr::<7, 25>(x), rotr::<18, 14>(x)), _mm256_srli_epi32::<3>(x));
            let s1 = xor(xor(rotr::<17, 15>(y), rotr::<19, 13>(y)), _mm256_srli_epi32::<10>(y));
            w[i & 15] = add(add(w[i & 15], s0), add(w[(i + 9) & 15], s1));
        }
        let s1 = xor(xor(rotr::<6, 26>(e), rotr::<11, 21>(e)), rotr::<25, 7>(e));
        let ch = xor(g, _mm256_and_si256(e, xor(f, g)));
        let t1 = add(add(add(h, s1), add(ch, all(*k))), w[i & 15]);
        let s0 = xor(xor(rotr::<2, 30>(a), rotr::<13, 19>(a)), rotr::<22, 10>(a));
        let maj = _mm256_or_si256(_mm256_and_si256(a, b), _mm256_and_si256(c, _mm256_or_si256(a, b)));
        (h, g, f, e, d, c, b, a) = (g, f, e, add(d, t1), c, b, a, add(t1, add(s0, maj)));
    }
    for (s, x) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = add(*s, x);
    }
}
/// Finishes HMAC: the outer hash of the inner digest.
#[inline]
#[target_feature(enable = "avx2")]
fn outer(mut st: State, inner: State) -> State {
    let z = all(0);
    let w = [inner[0], inner[1], inner[2], inner[3], inner[4], inner[5], inner[6], inner[7], all(PAD_END), z, z, z, z, z, z, all(BITS_PAD_DIGEST)];
    compress(&mut st, w);
    st
}
#[inline]
#[target_feature(enable = "avx2")]
fn all_state(s: &[u32; 8]) -> State {
    [all(s[0]), all(s[1]), all(s[2]), all(s[3]), all(s[4]), all(s[5]), all(s[6]), all(s[7])]
}
#[target_feature(enable = "avx2")]
fn expand(items: &[&[u8; 32]; 8], info: &[u8; 24]) -> [[u8; 128]; 8] {
    let z = all(0);
    let word = |b: &[u8], i: usize| u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]) as i32;
    let lanes = |i: usize| _mm256_set_epi32(word(items[7], i), word(items[6], i), word(items[5], i), word(items[4], i), word(items[3], i), word(items[2], i), word(items[1], i), word(items[0], i));
    let info: [V; 6] = std::array::from_fn(|i| all(word(info, i) as u32));

    // extract: HMAC(zero key, item)
    let mut inner = all_state(&ZERO_KEY_INNER);
    compress(&mut inner, [lanes(0), lanes(1), lanes(2), lanes(3), lanes(4), lanes(5), lanes(6), lanes(7), all(PAD_END), z, z, z, z, z, z, all(BITS_PAD_DIGEST)]);
    let prk = outer(all_state(&ZERO_KEY_OUTER), inner);

    // the HMAC pads of the extracted key
    let pad_state = |pad: u32| {
        let p = all(pad);
        let mut st = all_state(&IV);
        compress(&mut st, [xor(prk[0], p), xor(prk[1], p), xor(prk[2], p), xor(prk[3], p), xor(prk[4], p), xor(prk[5], p), xor(prk[6], p), xor(prk[7], p), p, p, p, p, p, p, p, p]);
        st
    };
    let (key_inner, key_outer) = (pad_state(0x36363636), pad_state(0x5c5c5c5c));

    // expand: T(1) is HMAC(info | 1), and T(n) is HMAC(T(n-1) | info | n). Each of them is 32 bytes
    let mut out = [[0u8; 128]; 8];
    let mut t = key_inner;
    for n in 1..=4u32 {
        let mut st = key_inner;
        let end = all((n << 24) | 0x800000);
        if n == 1 {
            compress(&mut st, [info[0], info[1], info[2], info[3], info[4], info[5], end, z, z, z, z, z, z, z, z, all((64 + 25) * 8)]);
        } else {
            compress(&mut st, [t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], info[0], info[1], info[2], info[3], info[4], info[5], end, z]);
            compress(&mut st, [z, z, z, z, z, z, z, z, z, z, z, z, z, z, z, all((64 + 57) * 8)]);
        }
        t = outer(key_outer, st);
        for (i, v) in t.iter().enumerate() {
            let mut w = [0u32; 8];
            // SAFETY: `w` is 32 bytes, and this store has no alignment need.
            unsafe { _mm256_storeu_si256(w.as_mut_ptr().cast(), *v) };
            for (o, x) in out.iter_mut().zip(w) {
                let at = (n as usize - 1) * 32 + i * 4;
                o[at..at + 4].copy_from_slice(&x.to_be_bytes());
            }
        }
    }
    out
}
/// Same result as `hkdf(item, 128, None, info)` for each item. `None` when this CPU has no AVX2.
pub fn hkdf_128_x8(items: &[&[u8; 32]; 8], info: &[u8; 24]) -> Option<[[u8; 128]; 8]> {
    if !is_x86_feature_detected!("avx2") {
        return None;
    }
    // SAFETY: AVX2 was detected above.
    Some(unsafe { expand(items, info) })
}
