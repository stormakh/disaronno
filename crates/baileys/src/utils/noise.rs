//! Noise XX handshake and transport, same frames as Utils/noise-handler.ts.
use crate::crypto::{self, KeyPair};
use crate::error::{Boom, Result};
use crate::utils::logger::{LogLevel, Logger};
use crate::wabinary::{BinaryNode, decode_binary_node_owned};
use std::sync::Arc;
use waproto::cert_chain::noise_certificate::Details;
use waproto::pb::{Json, PbMessage};
use waproto::{CertChain, HandshakeMessage};

pub const NOISE_MODE: &[u8; 32] = b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0";
pub const WA_CERT_SERIAL: u32 = 0;
pub const WA_CERT_PUBLIC_KEY: [u8; 32] = [0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b];

const IN_BYTES_KEEP: usize = 16 * 1024;
fn iv_of(c: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&c.to_be_bytes());
    iv
}
struct Transport {
    enc: Vec<u8>,
    dec: Vec<u8>,
    read: u32,
    write: u32,
}
pub struct NoiseHandler {
    private: [u8; 32],
    hash: [u8; 32],
    salt: Vec<u8>,
    enc_key: Vec<u8>,
    dec_key: Vec<u8>,
    counter: u32,
    sent_intro: bool,
    in_bytes: Vec<u8>,
    transport: Option<Transport>,
    intro_header: Vec<u8>,
    root_public_key: [u8; 32],
    logger: Option<Arc<dyn Logger>>,
}
/// A received frame: raw bytes during the handshake, a decoded node after it.
#[derive(Debug, PartialEq)]
pub enum Frame {
    Raw(Vec<u8>),
    Node(BinaryNode),
}
fn trace_frame(l: &dyn Logger, id: Option<&str>) {
    if l.is_enabled(LogLevel::Trace) {
        let msg = id.map_or(Json::Null, |i| Json::Str(i.to_string()));
        l.trace_obj(&Json::Obj(vec![("msg".to_string(), msg)]), "recv frame");
    }
}
impl NoiseHandler {
    pub fn new(key_pair: &KeyPair, noise_header: &[u8], routing_info: Option<&[u8]>) -> NoiseHandler {
        NoiseHandler::with_logger(key_pair, noise_header, routing_info, None)
    }
    /// `logger` gets the trace records of upstream, on a child with `class: ns`.
    pub fn with_logger(key_pair: &KeyPair, noise_header: &[u8], routing_info: Option<&[u8]>, logger: Option<Arc<dyn Logger>>) -> NoiseHandler {
        let mut intro_header = Vec::new();
        if let Some(r) = routing_info {
            // same limit as `writeUint8`, which throws when the high byte does not fit
            assert!(r.len() >> 16 <= 255, "routing info is too long");
            intro_header.extend_from_slice(b"ED\x00\x01");
            intro_header.push((r.len() >> 16) as u8);
            intro_header.extend_from_slice(&((r.len() & 65535) as u16).to_be_bytes());
            intro_header.extend_from_slice(r);
        }
        intro_header.extend_from_slice(noise_header);
        let mut n = NoiseHandler {
            private: key_pair.private,
            hash: *NOISE_MODE,
            salt: NOISE_MODE.to_vec(),
            enc_key: NOISE_MODE.to_vec(),
            dec_key: NOISE_MODE.to_vec(),
            counter: 0,
            sent_intro: false,
            in_bytes: Vec::new(),
            transport: None,
            intro_header,
            root_public_key: WA_CERT_PUBLIC_KEY,
            logger: logger.map(|l| l.child(&[("class", "ns")])),
        };
        n.authenticate(noise_header);
        n.authenticate(&key_pair.public);
        n
    }
    /// The key that must sign the intermediate certificate. Only for a test root of a mock server.
    pub fn set_root_public_key(&mut self, key: [u8; 32]) {
        self.root_public_key = key;
    }
    pub fn authenticate(&mut self, d: &[u8]) {
        if self.transport.is_none() {
            let mut b = Vec::with_capacity(32 + d.len());
            b.extend_from_slice(&self.hash);
            b.extend_from_slice(d);
            self.hash = crypto::sha256(&b);
        }
    }
    pub fn encrypt(&mut self, p: &[u8]) -> Result<Vec<u8>> {
        if let Some(t) = &mut self.transport {
            let iv = iv_of(t.write);
            t.write = t.write.wrapping_add(1);
            return crypto::aes_encrypt_gcm(p, &t.enc, &iv, &[]);
        }
        // `counter++` runs before the call in upstream, so a failure also uses up the counter
        let iv = iv_of(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let r = crypto::aes_encrypt_gcm(p, &self.enc_key, &iv, &self.hash)?;
        self.authenticate(&r);
        Ok(r)
    }
    pub fn decrypt(&mut self, c: &[u8]) -> Result<Vec<u8>> {
        if let Some(t) = &mut self.transport {
            let iv = iv_of(t.read);
            t.read = t.read.wrapping_add(1);
            return crypto::aes_decrypt_gcm(c, &t.dec, &iv, &[]);
        }
        let iv = iv_of(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let r = crypto::aes_decrypt_gcm(c, &self.dec_key, &iv, &self.hash)?;
        self.authenticate(c);
        Ok(r)
    }
    fn local_hkdf(&self, d: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let k = crypto::hkdf(d, 64, Some(&self.salt), b"");
        (k[..32].to_vec(), k[32..].to_vec())
    }
    pub fn mix_into_key(&mut self, d: &[u8]) {
        let (w, r) = self.local_hkdf(d);
        self.salt = w;
        self.enc_key = r.clone();
        self.dec_key = r;
        self.counter = 0;
    }
    /// Moves to the transport state. Upstream has a buffer for frames that arrive during this call,
    /// but its flag is set and cleared with no `await` between, so that buffer can never fill.
    /// Here `&mut self` gives the same guarantee, so there is no buffer. A partial frame stays in
    /// `in_bytes` and is decrypted by the next `decode_frame`.
    ///
    /// With a reader thread, encode the client finish frame and call this before you write the frame.
    /// Otherwise the first server frame can reach `decode_frame` before the keys are ready.
    pub fn finish_init(&mut self) {
        let (w, r) = self.local_hkdf(&[]);
        self.transport = Some(Transport { enc: w, dec: r, read: 0, write: 0 });
        if let Some(l) = &self.logger {
            l.trace("Noise handler transitioned to Transport state");
        }
    }
    pub fn is_transport(&self) -> bool {
        self.transport.is_some()
    }
    /// Checks the server certificates and returns the encrypted static key to send back.
    pub fn process_handshake(&mut self, msg: &HandshakeMessage, noise_key: &KeyPair) -> Result<Vec<u8>> {
        let hello = msg.server_hello().ok_or_else(|| Boom::new("server hello missing"))?;
        let eph = hello.ephemeral().cloned().unwrap_or_default();
        self.authenticate(&eph);
        let s = crypto::shared_key(&self.private, &eph)?;
        self.mix_into_key(&s);
        let stat = self.decrypt(hello.r#static().map_or(&[][..], |b| b.as_slice()))?;
        let s = crypto::shared_key(&self.private, &stat)?;
        self.mix_into_key(&s);
        let cert = self.decrypt(hello.payload().map_or(&[][..], |b| b.as_slice()))?;
        let chain = CertChain::decode(&cert)?;
        let leaf = chain.leaf().filter(|l| l.details().is_some() && l.signature().is_some()).ok_or_else(|| Boom::status("invalid noise leaf certificate", 400))?;
        let inter = chain.intermediate().filter(|l| l.details().is_some() && l.signature().is_some()).ok_or_else(|| Boom::status("invalid noise intermediate certificate", 400))?;
        let inter_details = inter.details().map_or(&[][..], |b| b.as_slice());
        let details = Details::decode(inter_details)?;
        // Upstream `Curve.verify` ignores the result of the signature check, so it accepts any
        // signature of the right length. This port checks the signatures on purpose.
        let ok_leaf = crypto::verify(details.key().map_or(&[][..], |b| b.as_slice()), leaf.details().map_or(&[][..], |b| b.as_slice()), leaf.signature().map_or(&[][..], |b| b.as_slice()));
        let ok_inter = crypto::verify(&self.root_public_key, inter_details, inter.signature().map_or(&[][..], |b| b.as_slice()));
        if !ok_leaf {
            return Err(Boom::status("noise certificate signature invalid", 400));
        }
        if !ok_inter {
            return Err(Boom::status("noise intermediate certificate signature invalid", 400));
        }
        // a missing serial is null in upstream, which is not the expected 0
        if details.issuer_serial() != Some(WA_CERT_SERIAL) {
            return Err(Boom::status("certification match failed", 400));
        }
        let key_enc = self.encrypt(&noise_key.public)?;
        let s = crypto::shared_key(&noise_key.private, &eph)?;
        self.mix_into_key(&s);
        Ok(key_enc)
    }
    pub fn encode_frame(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let enc;
        let d: &[u8] = if self.transport.is_some() {
            enc = self.encrypt(data)?;
            &enc
        } else {
            data
        };
        let intro: &[u8] = if self.sent_intro { &[] } else { &self.intro_header };
        let mut f = Vec::with_capacity(intro.len() + 3 + d.len());
        f.extend_from_slice(intro);
        f.extend_from_slice(&(d.len() as u32).to_be_bytes()[1..]);
        f.extend_from_slice(d);
        self.sent_intro = true;
        Ok(f)
    }
    /// Adds received bytes. Calls `on_frame` once for each complete frame.
    pub fn decode_frame(&mut self, data: &[u8], on_frame: &mut dyn FnMut(Frame)) -> Result<()> {
        self.in_bytes.extend_from_slice(data);
        let mut off = 0;
        let mut res = Ok(());
        while self.in_bytes.len() - off >= 3 {
            let b = &self.in_bytes[off..];
            let size = ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize;
            if b.len() < size + 3 {
                break;
            }
            let start = off + 3;
            off += size + 3;
            if self.transport.is_some() {
                let frame = &self.in_bytes[start..start + size];
                let t = self.transport.as_mut().unwrap();
                let iv = iv_of(t.read);
                t.read = t.read.wrapping_add(1);
                let r = crypto::aes_decrypt_gcm(frame, &t.dec, &iv, &[]).and_then(decode_binary_node_owned);
                match r {
                    Ok(n) => {
                        if let Some(l) = &self.logger {
                            trace_frame(l.as_ref(), n.attr("id"));
                        }
                        on_frame(Frame::Node(n))
                    }
                    Err(e) => {
                        res = Err(e);
                        break;
                    }
                }
            } else {
                if let Some(l) = &self.logger {
                    trace_frame(l.as_ref(), None);
                }
                on_frame(Frame::Raw(self.in_bytes[start..start + size].to_vec()));
            }
        }
        self.in_bytes.drain(..off);
        // one large frame must not keep its buffer for the life of the connection
        if self.in_bytes.capacity() > IN_BYTES_KEEP && self.in_bytes.len() <= IN_BYTES_KEEP {
            self.in_bytes.shrink_to(IN_BYTES_KEEP);
        }
        res
    }
}
