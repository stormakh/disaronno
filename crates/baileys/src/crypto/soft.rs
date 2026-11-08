//! Safe Rust crypto for lust dev builds only. Release builds use native.rs. Curve code follows TweetNaCl.
use crate::error::{Boom, Result};

fn rotr32(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
fn pad(d: &[u8], block: usize, lenb: usize, be: bool) -> Vec<u8> {
    let mut m = d.to_vec();
    m.push(0x80);
    while m.len() % block != block - lenb {
        m.push(0);
    }
    let bits = (d.len() as u128) * 8;
    if be {
        m.extend_from_slice(&bits.to_be_bytes()[16 - lenb..]);
    } else {
        m.extend_from_slice(&bits.to_le_bytes()[..lenb]);
    }
    m
}
pub fn sha256(d: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for c in pad(d, 64, 8, true).chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([c[i * 4], c[i * 4 + 1], c[i * 4 + 2], c[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = rotr32(v[4], 6) ^ rotr32(v[4], 11) ^ rotr32(v[4], 25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
            let s0 = rotr32(v[0], 2) ^ rotr32(v[0], 13) ^ rotr32(v[0], 22);
            let mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(mj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut o = [0u8; 32];
    for i in 0..8 {
        o[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    o
}
const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];
pub fn sha512(d: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
    for c in pad(d, 128, 16, true).chunks(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let mut t = [0u8; 8];
            t.copy_from_slice(&c[i * 8..i * 8 + 8]);
            w[i] = u64::from_be_bytes(t);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..80 {
            let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
            let mj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(mj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut o = [0u8; 64];
    for i in 0..8 {
        o[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    o
}
pub fn md5(d: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    for c in pad(d, 64, 8, false).chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([c[i * 4], c[i * 4 + 1], c[i * 4 + 2], c[i * 4 + 3]]);
        }
        let [mut a, mut b, mut cc, mut dd] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & cc) | (!b & dd), i),
                1 => ((dd & b) | (!dd & cc), (5 * i + 1) % 16),
                2 => (b ^ cc ^ dd, (3 * i + 5) % 16),
                _ => (cc ^ (b | !dd), (7 * i) % 16),
            };
            let t = dd;
            dd = cc;
            cc = b;
            b = b.wrapping_add(a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]));
            a = t;
        }
        h = [h[0].wrapping_add(a), h[1].wrapping_add(b), h[2].wrapping_add(cc), h[3].wrapping_add(dd)];
    }
    let mut o = [0u8; 16];
    for i in 0..4 {
        o[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    o
}
fn hmac_with(key: &[u8], d: &[u8], block: usize, hash: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut k = if key.len() > block { hash(key) } else { key.to_vec() };
    k.resize(block, 0);
    let mut i: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    i.extend_from_slice(d);
    let inner = hash(&i);
    let mut o: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    o.extend_from_slice(&inner);
    hash(&o)
}
pub fn hmac_sha256(key: &[u8], d: &[u8]) -> [u8; 32] {
    let r = hmac_with(key, d, 64, &|b: &[u8]| sha256(b).to_vec());
    let mut o = [0u8; 32];
    o.copy_from_slice(&r);
    o
}
pub struct HmacKey(Vec<u8>);
impl HmacKey {
    pub fn new(key: &[u8]) -> HmacKey {
        HmacKey(key.to_vec())
    }
    pub fn sign(&self, d: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.0, d)
    }
}
pub fn hmac_sha512(key: &[u8], d: &[u8]) -> [u8; 64] {
    let r = hmac_with(key, d, 128, &|b: &[u8]| sha512(b).to_vec());
    let mut o = [0u8; 64];
    o.copy_from_slice(&r);
    o
}
pub fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut s = salt.to_vec();
    s.extend_from_slice(&[0, 0, 0, 1]);
    let mut u = hmac_sha256(pw, &s);
    let mut t = u;
    for _ in 1..iters {
        u = hmac_sha256(pw, &u);
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    t
}
pub fn random_bytes(o: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("no /dev/urandom");
    f.read_exact(o).expect("short read from /dev/urandom");
}

// AES-256
fn sbox() -> ([u8; 256], [u8; 256]) {
    let (mut s, mut inv) = ([0u8; 256], [0u8; 256]);
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        s[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    for i in 0..256 {
        inv[s[i] as usize] = i as u8;
    }
    (s, inv)
}
struct Aes {
    rk: [[u8; 16]; 15],
    s: [u8; 256],
    inv: [u8; 256],
}
fn xt(a: u8) -> u8 {
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}
fn mul(a: u8, b: u8) -> u8 {
    let (mut a, mut b, mut r) = (a, b, 0u8);
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xt(a);
        b >>= 1;
    }
    r
}
impl Aes {
    fn new(key: &[u8]) -> Result<Aes> {
        if key.len() != 32 {
            return Err(Boom::new("Invalid key length"));
        }
        let (s, inv) = sbox();
        let mut w = [0u8; 240];
        w[..32].copy_from_slice(key);
        let mut rc = 1u8;
        let mut i = 32;
        while i < 240 {
            let mut t = [w[i - 4], w[i - 3], w[i - 2], w[i - 1]];
            if i % 32 == 0 {
                t = [s[t[1] as usize] ^ rc, s[t[2] as usize], s[t[3] as usize], s[t[0] as usize]];
                rc = xt(rc);
            } else if i % 32 == 16 {
                t = [s[t[0] as usize], s[t[1] as usize], s[t[2] as usize], s[t[3] as usize]];
            }
            for j in 0..4 {
                w[i + j] = w[i + j - 32] ^ t[j];
            }
            i += 4;
        }
        let mut rk = [[0u8; 16]; 15];
        for r in 0..15 {
            rk[r].copy_from_slice(&w[r * 16..r * 16 + 16]);
        }
        Ok(Aes { rk, s, inv })
    }
    fn enc(&self, b: &mut [u8; 16]) {
        for j in 0..16 {
            b[j] ^= self.rk[0][j];
        }
        for r in 1..15 {
            let mut t = [0u8; 16];
            for c in 0..4 {
                for j in 0..4 {
                    t[c * 4 + j] = self.s[b[((c + j) % 4) * 4 + j] as usize];
                }
            }
            if r != 14 {
                for c in 0..4 {
                    let x = [t[c * 4], t[c * 4 + 1], t[c * 4 + 2], t[c * 4 + 3]];
                    for j in 0..4 {
                        t[c * 4 + j] = xt(x[j]) ^ (xt(x[(j + 1) % 4]) ^ x[(j + 1) % 4]) ^ x[(j + 2) % 4] ^ x[(j + 3) % 4];
                    }
                }
            }
            for j in 0..16 {
                b[j] = t[j] ^ self.rk[r][j];
            }
        }
    }
    fn dec(&self, b: &mut [u8; 16]) {
        for j in 0..16 {
            b[j] ^= self.rk[14][j];
        }
        for r in (0..14).rev() {
            let mut t = [0u8; 16];
            for c in 0..4 {
                for j in 0..4 {
                    t[((c + j) % 4) * 4 + j] = self.inv[b[c * 4 + j] as usize];
                }
            }
            for j in 0..16 {
                t[j] ^= self.rk[r][j];
            }
            if r != 0 {
                for c in 0..4 {
                    let x = [t[c * 4], t[c * 4 + 1], t[c * 4 + 2], t[c * 4 + 3]];
                    for j in 0..4 {
                        t[c * 4 + j] = mul(x[j], 14) ^ mul(x[(j + 1) % 4], 11) ^ mul(x[(j + 2) % 4], 13) ^ mul(x[(j + 3) % 4], 9);
                    }
                }
            }
            *b = t;
        }
    }
}
fn iv16(iv: &[u8]) -> Result<[u8; 16]> {
    if iv.len() != 16 {
        return Err(Boom::new("Invalid initialization vector"));
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(iv);
    Ok(o)
}
pub fn aes_cbc_encrypt(d: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let a = Aes::new(key)?;
    let mut prev = iv16(iv)?;
    let pad_n = 16 - d.len() % 16;
    let mut m = d.to_vec();
    m.resize(d.len() + pad_n, pad_n as u8);
    let mut o = Vec::with_capacity(m.len());
    for c in m.chunks(16) {
        for j in 0..16 {
            prev[j] ^= c[j];
        }
        a.enc(&mut prev);
        o.extend_from_slice(&prev);
    }
    Ok(o)
}
pub fn aes_cbc_decrypt(d: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let a = Aes::new(key)?;
    let mut prev = iv16(iv)?;
    if d.is_empty() || d.len() % 16 != 0 {
        return Err(Boom::new("wrong final block length"));
    }
    let mut o = Vec::with_capacity(d.len());
    for c in d.chunks(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(c);
        let cur = b;
        a.dec(&mut b);
        for j in 0..16 {
            b[j] ^= prev[j];
        }
        o.extend_from_slice(&b);
        prev = cur;
    }
    let n = o[o.len() - 1] as usize;
    if n == 0 || n > 16 || o[o.len() - n..].iter().any(|v| *v as usize != n) {
        return Err(Boom::new("bad decrypt"));
    }
    o.truncate(o.len() - n);
    Ok(o)
}
pub fn aes_ctr(d: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let a = Aes::new(key)?;
    let mut ctr = iv16(iv)?;
    let mut o = Vec::with_capacity(d.len());
    for c in d.chunks(16) {
        let mut k = ctr;
        a.enc(&mut k);
        for (i, v) in c.iter().enumerate() {
            o.push(v ^ k[i]);
        }
        for j in (0..16).rev() {
            ctr[j] = ctr[j].wrapping_add(1);
            if ctr[j] != 0 {
                break;
            }
        }
    }
    Ok(o)
}
fn gmul(x: u128, y: u128) -> u128 {
    let (mut z, mut v) = (0u128, y);
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ (0xe1u128 << 120) } else { v >> 1 };
    }
    z
}
fn ghash(h: u128, aad: &[u8], c: &[u8]) -> u128 {
    let mut y = 0u128;
    for part in [aad, c] {
        for b in part.chunks(16) {
            let mut t = [0u8; 16];
            t[..b.len()].copy_from_slice(b);
            y = gmul(y ^ u128::from_be_bytes(t), h);
        }
    }
    let l = (((aad.len() as u128) * 8) << 64) | ((c.len() as u128) * 8);
    gmul(y ^ l, h)
}
fn gcm_core(d: &[u8], key: &[u8], iv: &[u8]) -> Result<(Vec<u8>, [u8; 16], u128)> {
    if iv.len() != 12 {
        return Err(Boom::new("Invalid IV length"));
    }
    let a = Aes::new(key)?;
    let mut hb = [0u8; 16];
    a.enc(&mut hb);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut e0 = j0;
    a.enc(&mut e0);
    let mut o = Vec::with_capacity(d.len());
    let mut n = 1u32;
    for c in d.chunks(16) {
        n = n.wrapping_add(1);
        let mut k = j0;
        k[12..].copy_from_slice(&n.to_be_bytes());
        a.enc(&mut k);
        for (i, v) in c.iter().enumerate() {
            o.push(v ^ k[i]);
        }
    }
    Ok((o, e0, u128::from_be_bytes(hb)))
}
pub fn aes_gcm_encrypt(p: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let (mut o, e0, h) = gcm_core(p, key, iv)?;
    let t = ghash(h, aad, &o).to_be_bytes();
    for i in 0..16 {
        o.push(t[i] ^ e0[i]);
    }
    Ok(o)
}
pub fn aes_gcm_decrypt(c: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if c.len() < 16 {
        return Err(Boom::new("Unsupported state or unable to authenticate data"));
    }
    let (ct, tag) = c.split_at(c.len() - 16);
    let (o, e0, h) = gcm_core(ct, key, iv)?;
    let t = ghash(h, aad, ct).to_be_bytes();
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= t[i] ^ e0[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Boom::new("Unsupported state or unable to authenticate data"));
    }
    Ok(o)
}

// Curve25519 and Ed25519, in TweetNaCl form
type Gf = [i64; 16];
const GF0: Gf = [0; 16];
const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const D: Gf = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
const D2: Gf = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
const X: Gf = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
const Y: Gf = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
const I: Gf = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];
const L: [i64; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
fn car(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        o[if i < 15 { i + 1 } else { 0 }] += c - 1 + (if i == 15 { 37 * (c - 1) } else { 0 });
        o[i] -= c << 16;
    }
}
fn sel(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}
fn pack25519(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    car(&mut t);
    car(&mut t);
    car(&mut t);
    let mut m = GF0;
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}
fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = GF0;
    for i in 0..16 {
        o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}
fn add(a: &Gf, b: &Gf) -> Gf {
    let mut o = GF0;
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
    o
}
fn sub(a: &Gf, b: &Gf) -> Gf {
    let mut o = GF0;
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
    o
}
fn gmulf(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o = GF0;
    o.copy_from_slice(&t[..16]);
    car(&mut o);
    car(&mut o);
    o
}
fn inv25519(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = gmulf(&c, &c);
        if a != 2 && a != 4 {
            c = gmulf(&c, i);
        }
    }
    c
}
fn pow2523(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=250).rev() {
        c = gmulf(&c, &c);
        if a != 1 {
            c = gmulf(&c, i);
        }
    }
    c
}
pub fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    let mut z = *sk;
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
    let x = unpack25519(pk);
    let (mut a, mut b, mut c, mut d) = (GF1, x, GF0, GF1);
    let c121665: Gf = [0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for i in (0..=254).rev() {
        let r = ((z[i >> 3] >> (i & 7)) & 1) as i64;
        sel(&mut a, &mut b, r);
        sel(&mut c, &mut d, r);
        let e = add(&a, &c);
        a = sub(&a, &c);
        c = add(&b, &d);
        b = sub(&b, &d);
        d = gmulf(&e, &e);
        let f = gmulf(&a, &a);
        a = gmulf(&c, &a);
        c = gmulf(&b, &e);
        let e2 = add(&a, &c);
        a = sub(&a, &c);
        b = gmulf(&a, &a);
        c = sub(&d, &f);
        a = gmulf(&c, &c121665);
        a = add(&a, &d);
        c = gmulf(&c, &a);
        a = gmulf(&d, &f);
        d = gmulf(&b, &x);
        b = gmulf(&e2, &e2);
        sel(&mut a, &mut b, r);
        sel(&mut c, &mut d, r);
    }
    let i = inv25519(&c);
    pack25519(&gmulf(&a, &i))
}
pub fn x25519_base(sk: &[u8; 32]) -> [u8; 32] {
    let mut nine = [0u8; 32];
    nine[0] = 9;
    x25519(sk, &nine)
}
type P = [Gf; 4];
fn padd(p: &mut P, q: &P) {
    let a = gmulf(&sub(&p[1], &p[0]), &sub(&q[1], &q[0]));
    let b = gmulf(&add(&p[0], &p[1]), &add(&q[0], &q[1]));
    let c = gmulf(&gmulf(&p[3], &q[3]), &D2);
    let d0 = gmulf(&p[2], &q[2]);
    let d = add(&d0, &d0);
    let e = sub(&b, &a);
    let f = sub(&d, &c);
    let g = add(&d, &c);
    let h = add(&b, &a);
    p[0] = gmulf(&e, &f);
    p[1] = gmulf(&h, &g);
    p[2] = gmulf(&g, &f);
    p[3] = gmulf(&e, &h);
}
fn cswap(p: &mut P, q: &mut P, b: i64) {
    for i in 0..4 {
        sel(&mut p[i], &mut q[i], b);
    }
}
fn par25519(a: &Gf) -> u8 {
    pack25519(a)[0] & 1
}
fn pack(p: &P) -> [u8; 32] {
    let zi = inv25519(&p[2]);
    let tx = gmulf(&p[0], &zi);
    let ty = gmulf(&p[1], &zi);
    let mut r = pack25519(&ty);
    r[31] ^= par25519(&tx) << 7;
    r
}
fn scalarmult(q: &P, s: &[u8; 32]) -> P {
    let mut p: P = [GF0, GF1, GF1, GF0];
    let mut q = *q;
    for i in (0..=255).rev() {
        let b = ((s[i / 8] >> (i & 7)) & 1) as i64;
        cswap(&mut p, &mut q, b);
        let qc = q;
        padd(&mut q, &p);
        let pc = p;
        padd(&mut p, &pc);
        let _ = qc;
        cswap(&mut p, &mut q, b);
    }
    p
}
fn scalarbase(s: &[u8; 32]) -> P {
    let q: P = [X, Y, GF1, gmulf(&X, &Y)];
    scalarmult(&q, s)
}
fn mod_l(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..=63).rev() {
        let mut carry = 0i64;
        for j in (i - 32)..(i - 12) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    let mut carry = 0i64;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    let mut r = [0u8; 32];
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
    r
}
fn reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut x = [0i64; 64];
    for i in 0..64 {
        x[i] = h[i] as i64;
    }
    mod_l(&mut x)
}
pub fn xeddsa_sign(sk: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let mut a = *sk;
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let big_a = pack(&scalarbase(&a));
    let sign_bit = big_a[31] & 128;
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&a);
    buf.extend_from_slice(msg);
    let r = reduce(&sha512(&buf));
    let big_r = pack(&scalarbase(&r));
    buf.clear();
    buf.extend_from_slice(&big_r);
    buf.extend_from_slice(&big_a);
    buf.extend_from_slice(msg);
    let h = reduce(&sha512(&buf));
    let mut x = [0i64; 64];
    for i in 0..32 {
        x[i] = r[i] as i64;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += h[i] as i64 * a[j] as i64;
        }
    }
    let s = mod_l(&mut x);
    let mut o = [0u8; 64];
    o[..32].copy_from_slice(&big_r);
    o[32..].copy_from_slice(&s);
    o[63] |= sign_bit;
    o
}
fn neq(a: &Gf, b: &Gf) -> bool {
    pack25519(a) != pack25519(b)
}
fn unpackneg(p: &[u8; 32]) -> Option<P> {
    let y = unpack25519(p);
    let num0 = gmulf(&y, &y);
    let den0 = gmulf(&num0, &D);
    let num = sub(&num0, &GF1);
    let den = add(&den0, &GF1);
    let den2 = gmulf(&den, &den);
    let den4 = gmulf(&den2, &den2);
    let den6 = gmulf(&den4, &den2);
    let mut t = gmulf(&den6, &num);
    t = gmulf(&t, &den);
    t = pow2523(&t);
    t = gmulf(&t, &num);
    t = gmulf(&t, &den);
    t = gmulf(&t, &den);
    let mut x = gmulf(&t, &den);
    let chk = gmulf(&gmulf(&x, &x), &den);
    if neq(&chk, &num) {
        x = gmulf(&x, &I);
    }
    let chk = gmulf(&gmulf(&x, &x), &den);
    if neq(&chk, &num) {
        return None;
    }
    if par25519(&x) == (p[31] >> 7) {
        x = sub(&GF0, &x);
    }
    Some([x, y, GF1, gmulf(&x, &y)])
}
pub fn xeddsa_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    // convert the Montgomery u to Edwards y = (u-1)/(u+1), sign bit comes from the signature
    let u = unpack25519(pk);
    let y = gmulf(&sub(&u, &GF1), &inv25519(&add(&u, &GF1)));
    let mut edpk = pack25519(&y);
    edpk[31] |= sig[63] & 128;
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    s[31] &= 127;
    let Some(q) = unpackneg(&edpk) else { return false };
    let mut buf = Vec::with_capacity(64 + msg.len());
    buf.extend_from_slice(&sig[..32]);
    buf.extend_from_slice(&edpk);
    buf.extend_from_slice(msg);
    let h = reduce(&sha512(&buf));
    let mut p = scalarmult(&q, &h);
    let sb = scalarbase(&s);
    padd(&mut p, &sb);
    pack(&p)[..] == sig[..32]
}
/// SHA-256 over data that arrives in parts. This dev-only version keeps the data until `finish`.
pub struct Sha256Stream(Vec<u8>);
impl Sha256Stream {
    pub fn new() -> Sha256Stream {
        Sha256Stream(Vec::new())
    }
    pub fn update(&mut self, d: &[u8]) {
        self.0.extend_from_slice(d);
    }
    pub fn finish(self) -> [u8; 32] {
        sha256(&self.0)
    }
}
/// HMAC-SHA256 over data that arrives in parts. This dev-only version keeps the data until `finish`.
pub struct HmacSha256Stream(Vec<u8>, Vec<u8>);
impl HmacSha256Stream {
    pub fn new(key: &[u8]) -> HmacSha256Stream {
        HmacSha256Stream(key.to_vec(), Vec::new())
    }
    pub fn update(&mut self, d: &[u8]) {
        self.1.extend_from_slice(d);
    }
    pub fn finish(self) -> [u8; 32] {
        hmac_sha256(&self.0, &self.1)
    }
}
/// AES-256-CBC encryption of whole blocks. The caller handles padding.
pub struct CbcEncryptor {
    aes: Aes,
    prev: [u8; 16],
}
impl CbcEncryptor {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<CbcEncryptor> {
        Ok(CbcEncryptor { aes: Aes::new(key)?, prev: iv16(iv)? })
    }
    /// `d.len()` must be a multiple of 16.
    pub fn encrypt_blocks(&mut self, d: &mut [u8]) {
        for c in d.chunks_exact_mut(16) {
            for j in 0..16 {
                self.prev[j] ^= c[j];
            }
            self.aes.enc(&mut self.prev);
            c.copy_from_slice(&self.prev);
        }
    }
}
/// AES-256-CBC decryption of whole blocks. The caller handles padding.
pub struct CbcDecryptor {
    aes: Aes,
    prev: [u8; 16],
}
impl CbcDecryptor {
    pub fn new(key: &[u8], iv: &[u8]) -> Result<CbcDecryptor> {
        Ok(CbcDecryptor { aes: Aes::new(key)?, prev: iv16(iv)? })
    }
    /// `d.len()` must be a multiple of 16.
    pub fn decrypt_blocks(&mut self, d: &mut [u8]) {
        for c in d.chunks_exact_mut(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(c);
            let cur = b;
            self.aes.dec(&mut b);
            for j in 0..16 {
                c[j] = b[j] ^ self.prev[j];
            }
            self.prev = cur;
        }
    }
}
