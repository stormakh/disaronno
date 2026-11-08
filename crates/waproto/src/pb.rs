//! Protobuf wire runtime for the generated types. Strings and byte fields share the decoded buffer.
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Boxed so that `Result<u64, DecodeError>` and the like are returned in registers.
pub struct DecodeError(pub Box<String>);
impl DecodeError {
    #[cold]
    pub fn new(s: &str) -> DecodeError {
        DecodeError(Box::new(s.to_string()))
    }
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for DecodeError {}

const INLINE: usize = 22;
#[derive(Clone)]
enum Repr {
    Static(&'static [u8]),
    Inline(u8, [u8; INLINE]),
    Owned(Arc<[u8]>),
    Shared(Arc<Vec<u8>>, u32, u32),
}
/// Bytes that are cheap to clone. Short values are stored inline and do not allocate.
#[derive(Clone)]
pub struct Bytes(Repr);
impl Bytes {
    pub fn new() -> Bytes {
        Bytes(Repr::Inline(0, [0; INLINE]))
    }
    pub const fn from_static(b: &'static [u8]) -> Bytes {
        Bytes(Repr::Static(b))
    }
    #[inline]
    pub fn copy_from(v: &[u8]) -> Bytes {
        if v.len() <= INLINE {
            let mut d = [0u8; INLINE];
            d[..v.len()].copy_from_slice(v);
            return Bytes(Repr::Inline(v.len() as u8, d));
        }
        Bytes(Repr::Owned(Arc::from(v)))
    }
    pub fn from_vec(v: Vec<u8>) -> Bytes {
        Bytes::copy_from(&v)
    }
    /// Shares part of `buf`. Short ranges are copied so they do not keep `buf` alive.
    #[inline]
    pub fn shared(buf: &Arc<Vec<u8>>, from: usize, to: usize) -> Bytes {
        if to - from <= INLINE {
            return Bytes::copy_from(&buf[from..to]);
        }
        Bytes(Repr::Shared(buf.clone(), from as u32, to as u32))
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            Repr::Static(b) => b,
            Repr::Inline(n, d) => &d[..*n as usize],
            Repr::Owned(a) => a,
            Repr::Shared(b, f, t) => &b[*f as usize..*t as usize],
        }
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
    pub fn slice(&self, from: usize, to: usize) -> Bytes {
        Bytes::copy_from(&self.as_slice()[from..to])
    }
}
impl Default for Bytes {
    fn default() -> Bytes {
        Bytes::new()
    }
}
impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl PartialEq for Bytes {
    fn eq(&self, o: &Bytes) -> bool {
        self.as_slice() == o.as_slice()
    }
}
impl Eq for Bytes {}
impl PartialEq<[u8]> for Bytes {
    fn eq(&self, o: &[u8]) -> bool {
        self.as_slice() == o
    }
}
impl PartialEq<Vec<u8>> for Bytes {
    fn eq(&self, o: &Vec<u8>) -> bool {
        self.as_slice() == o.as_slice()
    }
}
impl Hash for Bytes {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.as_slice().hash(h)
    }
}
impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({})", base64_encode(self.as_slice()))
    }
}
impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Bytes {
        Bytes::from_vec(v)
    }
}
impl From<&[u8]> for Bytes {
    fn from(v: &[u8]) -> Bytes {
        Bytes::from_vec(v.to_vec())
    }
}
impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(v: [u8; N]) -> Bytes {
        Bytes::from_vec(v.to_vec())
    }
}

/// A UTF-8 string that is cheap to clone. Tokens use no memory and short strings are inline.
#[derive(Clone, Default)]
pub struct Str(Bytes);
impl Str {
    #[inline]
    pub fn new(s: &str) -> Str {
        Str(Bytes::copy_from(s.as_bytes()))
    }
    pub const fn from_static(s: &'static str) -> Str {
        Str(Bytes::from_static(s.as_bytes()))
    }
    /// Every constructor checks the bytes first, so they are valid UTF-8.
    #[cfg(feature = "native")]
    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.0.as_slice()) }
    }
    #[cfg(not(feature = "native"))]
    #[inline]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.0.as_slice()).unwrap_or("")
    }
    /// Same as `String::from_utf8_lossy`. ASCII, the usual case, takes a cheap check.
    #[inline]
    pub fn from_utf8_lossy(b: &[u8]) -> Str {
        if b.is_ascii() || std::str::from_utf8(b).is_ok() {
            return Str(Bytes::copy_from(b));
        }
        Str::from(String::from_utf8_lossy(b).into_owned())
    }
    /// Joins parts without building a `String` first, so a short result does not allocate.
    pub fn concat(parts: &[&str]) -> Str {
        let mut d = [0u8; 64];
        let mut n = 0;
        for p in parts {
            if n + p.len() > d.len() {
                return Str::new(&parts.concat());
            }
            d[n..n + p.len()].copy_from_slice(p.as_bytes());
            n += p.len();
        }
        Str(Bytes::copy_from(&d[..n]))
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn raw(&self) -> &Bytes {
        &self.0
    }
}
impl std::ops::Deref for Str {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for Str {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl PartialEq for Str {
    fn eq(&self, o: &Str) -> bool {
        self.0 == o.0
    }
}
impl Eq for Str {}
impl PartialEq<str> for Str {
    fn eq(&self, o: &str) -> bool {
        self.as_bytes() == o.as_bytes()
    }
}
impl PartialEq<&str> for Str {
    fn eq(&self, o: &&str) -> bool {
        self.as_bytes() == o.as_bytes()
    }
}
impl PartialEq<String> for Str {
    fn eq(&self, o: &String) -> bool {
        self.as_bytes() == o.as_bytes()
    }
}
impl Hash for Str {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self.as_str().hash(h)
    }
}
impl fmt::Debug for Str {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}
impl fmt::Display for Str {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl From<&str> for Str {
    fn from(s: &str) -> Str {
        Str::new(s)
    }
}
impl From<&String> for Str {
    fn from(s: &String) -> Str {
        Str::new(s)
    }
}
impl From<String> for Str {
    fn from(s: String) -> Str {
        Str::new(&s)
    }
}
impl PartialOrd for Str {
    fn partial_cmp(&self, o: &Str) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Str {
    fn cmp(&self, o: &Str) -> std::cmp::Ordering {
        self.as_bytes().cmp(o.as_bytes())
    }
}

pub struct Writer {
    pub buf: Vec<u8>,
}
impl Writer {
    pub fn new() -> Writer {
        Writer { buf: Vec::with_capacity(256) }
    }
    #[inline]
    pub fn tag(&mut self, t: &[u8]) {
        self.buf.extend_from_slice(t);
    }
    #[inline]
    fn varint(&mut self, mut v: u64) {
        while v > 127 {
            self.buf.push((v as u8 & 127) | 128);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }
    #[inline]
    pub fn uint32(&mut self, v: u32) {
        self.varint(v as u64)
    }
    #[inline]
    pub fn uint64(&mut self, v: u64) {
        self.varint(v)
    }
    /// A signed Rust value on a uint32 wire field: `-1` writes as 4294967295, as protobufjs does.
    #[inline]
    pub fn uint32_i32(&mut self, v: i32) {
        self.varint(v as u32 as u64)
    }
    #[inline]
    pub fn int32(&mut self, v: i32) {
        self.varint(v as i64 as u64)
    }
    #[inline]
    pub fn int64(&mut self, v: i64) {
        self.varint(v as u64)
    }
    pub fn sint32(&mut self, v: i32) {
        self.varint((((v << 1) ^ (v >> 31)) as u32) as u64)
    }
    pub fn sint64(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64)
    }
    pub fn fixed32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes())
    }
    pub fn fixed64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes())
    }
    pub fn sfixed32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes())
    }
    pub fn sfixed64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes())
    }
    pub fn float(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes())
    }
    pub fn double(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes())
    }
    #[inline]
    pub fn bool(&mut self, v: bool) {
        self.buf.push(v as u8)
    }
    #[inline]
    pub fn str(&mut self, v: &Str) {
        self.bytes(v.raw())
    }
    #[inline]
    pub fn bytes(&mut self, v: &Bytes) {
        self.varint(v.len() as u64);
        self.buf.extend_from_slice(v.as_slice());
    }
    /// Starts a length-delimited body. One length byte is reserved and `end` widens it when needed.
    #[inline]
    pub fn begin(&mut self) -> usize {
        self.buf.push(0);
        self.buf.len()
    }
    #[inline]
    pub fn end(&mut self, start: usize) {
        let len = self.buf.len() - start;
        if len < 128 {
            self.buf[start - 1] = len as u8;
            return;
        }
        let mut lb = [0u8; 10];
        let mut n = 0;
        let mut v = len as u64;
        while v > 127 {
            lb[n] = (v as u8 & 127) | 128;
            v >>= 7;
            n += 1;
        }
        lb[n] = v as u8;
        n += 1;
        self.buf.resize(self.buf.len() + n - 1, 0);
        self.buf.copy_within(start..start + len, start + n - 1);
        self.buf[start - 1..start - 1 + n].copy_from_slice(&lb[..n]);
    }
    #[inline]
    pub fn nested<M: PbMessage>(&mut self, m: &M) {
        let st = self.begin();
        m.encode_to(self);
        self.end(st);
    }
}

pub struct Reader<'a> {
    /// Ends at the limit of the message being read. Offsets are from the start of the whole buffer.
    buf: &'a [u8],
    /// The owned input of `decode_shared`, which long fields point into. Without it, each long field copies only its own bytes.
    shared: Option<Arc<Vec<u8>>>,
    pos: usize,
    /// How many nested messages and groups are open now.
    depth: u32,
}
const EOF: &str = "index out of range";
/// A message from a peer can nest without end, and a stack overflow ends the whole process. The
/// stack of a socket thread (`THREAD_STACK` in `utils::time`) must hold this many levels.
pub const MAX_DEPTH: u32 = 64;
impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], shared: Option<Arc<Vec<u8>>>) -> Reader<'a> {
        Reader { buf, shared, pos: 0, depth: 0 }
    }
    #[inline]
    fn enter(&mut self) -> Result<(), DecodeError> {
        if self.depth >= MAX_DEPTH {
            return Err(DecodeError(Box::new("max depth exceeded".to_string())));
        }
        self.depth += 1;
        Ok(())
    }
    #[inline(always)]
    fn varint(&mut self) -> Result<u64, DecodeError> {
        match self.buf.get(self.pos) {
            Some(&b) if b < 128 => {
                self.pos += 1;
                Ok(b as u64)
            }
            _ => self.varint_long(),
        }
    }
    fn varint_long(&mut self) -> Result<u64, DecodeError> {
        let mut v = 0u64;
        let mut s = 0;
        loop {
            let Some(&b) = self.buf.get(self.pos) else { return Err(DecodeError::new(EOF)) };
            self.pos += 1;
            if s < 64 {
                v |= ((b & 127) as u64) << s;
            }
            if b < 128 {
                return Ok(v);
            }
            s += 7;
            if s > 70 {
                return Err(DecodeError::new("invalid varint encoding"));
            }
        }
    }
    #[inline]
    pub fn next_field(&mut self) -> Result<Option<(u32, u32)>, DecodeError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let t = self.varint()? as u32;
        Ok(Some((t >> 3, t & 7)))
    }
    pub fn next_field_until(&mut self, e: usize) -> Result<Option<(u32, u32)>, DecodeError> {
        if self.pos >= e {
            return Ok(None);
        }
        self.next_field()
    }
    /// How many fields are left in this message, with a run of one repeated field counted once.
    /// It gives the field list its exact size, with no growth and no spare slots. Bad data ends the count: the real read reports it.
    pub fn count_fields(&self) -> usize {
        fn varint(b: &[u8], p: &mut usize) -> usize {
            let mut v = 0usize;
            let mut s = 0;
            while let Some(&c) = b.get(*p) {
                *p += 1;
                v |= ((c & 127) as usize) << (s & 63);
                if c < 128 {
                    break;
                }
                s += 7;
            }
            v
        }
        let b = self.buf;
        let mut p = self.pos;
        let (mut n, mut last) = (0, 0);
        while p < b.len() {
            let t = varint(b, &mut p);
            match t & 7 {
                0 => {
                    varint(b, &mut p);
                }
                1 => p += 8,
                2 => {
                    let l = varint(b, &mut p);
                    p = p.saturating_add(l);
                }
                5 => p += 4,
                _ => break,
            }
            if t != last {
                n += 1;
                last = t;
            }
        }
        n
    }
    #[inline]
    pub fn pos_before(&self, e: usize) -> bool {
        self.pos < e
    }
    #[inline]
    fn len_delim(&mut self) -> Result<(usize, usize), DecodeError> {
        let n = self.varint()? as usize;
        if n > self.buf.len() - self.pos {
            return Err(DecodeError::new(EOF));
        }
        let s = self.pos;
        self.pos += n;
        Ok((s, s + n))
    }
    pub fn begin_packed(&mut self) -> Result<usize, DecodeError> {
        let (s, e) = self.len_delim()?;
        self.pos = s;
        Ok(e)
    }
    #[inline]
    pub fn uint32(&mut self) -> Result<u32, DecodeError> {
        Ok(self.varint()? as u32)
    }
    #[inline]
    pub fn uint32_i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.varint()? as u32 as i32)
    }
    #[inline]
    pub fn uint64(&mut self) -> Result<u64, DecodeError> {
        self.varint()
    }
    #[inline]
    pub fn int32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.varint()? as i32)
    }
    #[inline]
    pub fn int64(&mut self) -> Result<i64, DecodeError> {
        Ok(self.varint()? as i64)
    }
    pub fn sint32(&mut self) -> Result<i32, DecodeError> {
        let v = self.varint()? as u32;
        Ok(((v >> 1) as i32) ^ -((v & 1) as i32))
    }
    pub fn sint64(&mut self) -> Result<i64, DecodeError> {
        let v = self.varint()?;
        Ok(((v >> 1) as i64) ^ -((v & 1) as i64))
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        if self.buf.len() - self.pos < N {
            return Err(DecodeError::new(EOF));
        }
        let mut b = [0u8; N];
        b.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(b)
    }
    pub fn fixed32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    pub fn fixed64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    pub fn sfixed32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.fixed()?))
    }
    pub fn sfixed64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.fixed()?))
    }
    pub fn float(&mut self) -> Result<f32, DecodeError> {
        Ok(f32::from_bits(u32::from_le_bytes(self.fixed()?)))
    }
    pub fn double(&mut self) -> Result<f64, DecodeError> {
        Ok(f64::from_bits(u64::from_le_bytes(self.fixed()?)))
    }
    #[inline]
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.varint()? != 0)
    }
    #[inline]
    pub fn bytes(&mut self) -> Result<Bytes, DecodeError> {
        let (s, e) = self.len_delim()?;
        Ok(self.range(s, e))
    }
    #[inline]
    fn range(&mut self, s: usize, e: usize) -> Bytes {
        if e - s <= INLINE {
            // a fixed-size copy is much cheaper than a copy of variable length. `as_slice` reads only the first `e - s` bytes
            if let Some(c) = self.buf.get(s..s + INLINE) {
                let mut d = [0u8; INLINE];
                d.copy_from_slice(c);
                return Bytes(Repr::Inline((e - s) as u8, d));
            }
            return Bytes::copy_from(&self.buf[s..e]);
        }
        match &self.shared {
            Some(a) => Bytes(Repr::Shared(a.clone(), s as u32, e as u32)),
            None => Bytes(Repr::Owned(Arc::from(&self.buf[s..e]))),
        }
    }
    /// Invalid UTF-8 is replaced, as protobufjs does when it reads a string.
    #[inline]
    pub fn str(&mut self) -> Result<Str, DecodeError> {
        let (s, e) = self.len_delim()?;
        let raw = &self.buf[s..e];
        if raw.is_ascii() || std::str::from_utf8(raw).is_ok() {
            return Ok(Str(self.range(s, e)));
        }
        Ok(Str::from(String::from_utf8_lossy(raw).into_owned()))
    }
    #[inline]
    pub fn merge_nested<M: PbMessage>(&mut self, m: &mut M) -> Result<(), DecodeError> {
        self.enter()?;
        let (s, e) = self.len_delim()?;
        let outer = self.buf;
        self.pos = s;
        self.buf = &outer[..e];
        let r = m.merge_from(self);
        self.pos = e;
        self.buf = outer;
        self.depth -= 1;
        r
    }
    #[inline]
    pub fn message<M: PbMessage>(&mut self) -> Result<M, DecodeError> {
        let mut m = M::default();
        self.merge_nested(&mut m)?;
        Ok(m)
    }
    /// Builds the message in its box, so a large struct is not copied.
    #[inline]
    pub fn boxed<M: PbMessage>(&mut self) -> Result<Box<M>, DecodeError> {
        let mut m = Box::<M>::default();
        self.merge_nested(&mut *m)?;
        Ok(m)
    }
    pub fn skip(&mut self, wt: u32) -> Result<(), DecodeError> {
        match wt {
            0 => {
                self.varint()?;
            }
            1 => {
                self.fixed::<8>()?;
            }
            2 => {
                self.len_delim()?;
            }
            3 => {
                self.enter()?;
                loop {
                    let t = self.varint()? as u32;
                    if t & 7 == 4 {
                        break;
                    }
                    self.skip(t & 7)?;
                }
                self.depth -= 1;
            }
            5 => {
                self.fixed::<4>()?;
            }
            _ => return Err(DecodeError(Box::new(format!("invalid wire type {wt} at offset {}", self.pos)))),
        }
        Ok(())
    }
}

pub trait PbMessage: Default {
    fn encode_to(&self, w: &mut Writer);
    fn merge_from(&mut self, r: &mut Reader<'_>) -> Result<(), DecodeError>;
    fn to_json(&self) -> Json;
    fn from_json(j: &Json) -> Result<Self, DecodeError>;
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_to(&mut w);
        w.buf
    }
    fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(b, None);
        let mut m = Self::default();
        m.merge_from(&mut r)?;
        Ok(m)
    }
    /// Decodes an owned buffer. Long fields share it and do not copy.
    fn decode_shared(b: Arc<Vec<u8>>) -> Result<Self, DecodeError> {
        let mut r = Reader::new(&b, Some(b.clone()));
        let mut m = Self::default();
        m.merge_from(&mut r)?;
        Ok(m)
    }
}

/// JSON value with insertion-ordered objects, as JavaScript objects keep string keys.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
    /// A Buffer, as `BufferJSON.reviver` gives. It stringifies in the BufferJSON form.
    Bytes(Vec<u8>),
}
impl Json {
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(o) => o.iter().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Json::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn stringify(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }
    fn write(&self, s: &mut String) {
        match self {
            Json::Null => s.push_str("null"),
            Json::Bool(b) => s.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => s.push_str(&js_number(*n)),
            Json::Str(v) => write_json_str(v, s),
            Json::Bytes(b) => {
                s.push_str("{\"type\":\"Buffer\",\"data\":\"");
                s.push_str(&base64_encode(b));
                s.push_str("\"}");
            }
            Json::Arr(a) => {
                s.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    v.write(s);
                }
                s.push(']');
            }
            Json::Obj(o) => {
                s.push('{');
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    write_json_str(k, s);
                    s.push(':');
                    v.write(s);
                }
                s.push('}');
            }
        }
    }
    pub fn parse(t: &str) -> Result<Json, DecodeError> {
        let b = t.as_bytes();
        let mut p = 0;
        let v = parse_value(b, &mut p)?;
        skip_ws(b, &mut p);
        if p != b.len() {
            return Err(DecodeError::new("trailing JSON data"));
        }
        Ok(v)
    }
}
/// Formats a number as JavaScript `String(n)` does, for the range this library uses.
pub fn js_number(n: f64) -> String {
    if n.is_nan() || n.is_infinite() {
        return "null".to_string();
    }
    if n == n.trunc() && n.abs() < 9007199254740992.0 {
        return format!("{}", n as i64);
    }
    // the shortest digits that read back as the same value, then the layout from the JavaScript spec
    let e = format!("{:e}", n.abs());
    let (mantissa, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let point = exp.parse::<i32>().unwrap_or(0) + 1;
    let mut o = String::with_capacity(32);
    if n < 0.0 {
        o.push('-');
    }
    if k <= point && point <= 21 {
        o.push_str(&digits);
        o.push_str(&"0".repeat((point - k) as usize));
    } else if 0 < point && point <= 21 {
        o.push_str(&digits[..point as usize]);
        o.push('.');
        o.push_str(&digits[point as usize..]);
    } else if -6 < point && point <= 0 {
        o.push_str("0.");
        o.push_str(&"0".repeat(-point as usize));
        o.push_str(&digits);
    } else {
        o.push_str(&digits[..1]);
        if k > 1 {
            o.push('.');
            o.push_str(&digits[1..]);
        }
        o.push('e');
        o.push(if point > 0 { '+' } else { '-' });
        o.push_str(&(point - 1).abs().to_string());
    }
    o
}
fn write_json_str(v: &str, s: &mut String) {
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '\u{8}' => s.push_str("\\b"),
            '\u{c}' => s.push_str("\\f"),
            c if (c as u32) < 32 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
}
fn skip_ws(b: &[u8], p: &mut usize) {
    while *p < b.len() && matches!(b[*p], b' ' | b'\n' | b'\r' | b'\t') {
        *p += 1;
    }
}
fn parse_value(b: &[u8], p: &mut usize) -> Result<Json, DecodeError> {
    skip_ws(b, p);
    if *p >= b.len() {
        return Err(DecodeError::new("unexpected end of JSON"));
    }
    match b[*p] {
        b'{' => {
            *p += 1;
            let mut o: Vec<(String, Json)> = Vec::new();
            skip_ws(b, p);
            if *p < b.len() && b[*p] == b'}' {
                *p += 1;
                return Ok(Json::Obj(o));
            }
            loop {
                skip_ws(b, p);
                let k = parse_str(b, p)?;
                skip_ws(b, p);
                if *p >= b.len() || b[*p] != b':' {
                    return Err(DecodeError::new("expected ':' in JSON"));
                }
                *p += 1;
                let v = parse_value(b, p)?;
                // a repeated key keeps its first position and takes the last value, as JSON.parse does
                match o.iter().position(|(n, _)| *n == k) {
                    Some(i) => o[i].1 = v,
                    None => o.push((k, v)),
                }
                skip_ws(b, p);
                if *p < b.len() && b[*p] == b',' {
                    *p += 1;
                    continue;
                }
                if *p < b.len() && b[*p] == b'}' {
                    *p += 1;
                    return Ok(Json::Obj(o));
                }
                return Err(DecodeError::new("expected ',' or '}' in JSON"));
            }
        }
        b'[' => {
            *p += 1;
            let mut a = Vec::new();
            skip_ws(b, p);
            if *p < b.len() && b[*p] == b']' {
                *p += 1;
                return Ok(Json::Arr(a));
            }
            loop {
                a.push(parse_value(b, p)?);
                skip_ws(b, p);
                if *p < b.len() && b[*p] == b',' {
                    *p += 1;
                    continue;
                }
                if *p < b.len() && b[*p] == b']' {
                    *p += 1;
                    return Ok(Json::Arr(a));
                }
                return Err(DecodeError::new("expected ',' or ']' in JSON"));
            }
        }
        b'"' => Ok(Json::Str(parse_str(b, p)?)),
        b't' if b[*p..].starts_with(b"true") => {
            *p += 4;
            Ok(Json::Bool(true))
        }
        b'f' if b[*p..].starts_with(b"false") => {
            *p += 5;
            Ok(Json::Bool(false))
        }
        b'n' if b[*p..].starts_with(b"null") => {
            *p += 4;
            Ok(Json::Null)
        }
        _ => {
            let s = *p;
            while *p < b.len() && matches!(b[*p], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                *p += 1;
            }
            let t = std::str::from_utf8(&b[s..*p]).map_err(|_| DecodeError::new("bad JSON number"))?;
            t.parse::<f64>().map(Json::Num).map_err(|_| DecodeError::new("bad JSON value"))
        }
    }
}
fn hex4(b: &[u8], p: &mut usize) -> Result<u32, DecodeError> {
    if *p + 4 > b.len() {
        return Err(DecodeError::new("bad \\u escape"));
    }
    let t = std::str::from_utf8(&b[*p..*p + 4]).map_err(|_| DecodeError::new("bad \\u escape"))?;
    let v = u32::from_str_radix(t, 16).map_err(|_| DecodeError::new("bad \\u escape"))?;
    *p += 4;
    Ok(v)
}
fn parse_str(b: &[u8], p: &mut usize) -> Result<String, DecodeError> {
    if *p >= b.len() || b[*p] != b'"' {
        return Err(DecodeError::new("expected string in JSON"));
    }
    *p += 1;
    let mut out: Vec<u8> = Vec::new();
    loop {
        if *p >= b.len() {
            return Err(DecodeError::new("unterminated JSON string"));
        }
        let c = b[*p];
        *p += 1;
        match c {
            b'"' => break,
            b'\\' => {
                if *p >= b.len() {
                    return Err(DecodeError::new("bad JSON escape"));
                }
                let e = b[*p];
                *p += 1;
                match e {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let mut v = hex4(b, p)?;
                        if (0xd800..0xdc00).contains(&v) && b[*p..].starts_with(b"\\u") {
                            *p += 2;
                            let lo = hex4(b, p)?;
                            v = 0x10000 + ((v - 0xd800) << 10) + (lo.wrapping_sub(0xdc00) & 0x3ff);
                        }
                        let ch = char::from_u32(v).unwrap_or('\u{fffd}');
                        let mut t = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut t).as_bytes());
                    }
                    _ => return Err(DecodeError::new("bad JSON escape")),
                }
            }
            c => out.push(c),
        }
    }
    String::from_utf8(out).map_err(|_| DecodeError::new("invalid UTF-8 in JSON"))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn base64_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = ((c[0] as u32) << 16) | ((*c.get(1).unwrap_or(&0) as u32) << 8) | (*c.get(2).unwrap_or(&0) as u32);
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    s
}
/// Lenient as Node's `Buffer.from(s, 'base64')`: skips other characters and accepts the URL alphabet.
pub fn base64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut n, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        n = (n << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((n >> bits) as u8);
            n &= (1 << bits) - 1;
        }
    }
    out
}

pub fn enum_json(name: Option<&'static str>, v: i32) -> Json {
    match name {
        Some(n) => Json::Str(n.to_string()),
        None => Json::Num(v as f64),
    }
}
pub fn float_json(v: f64) -> Json {
    if v.is_finite() { Json::Num(v) } else { Json::Str(if v.is_nan() { "NaN".into() } else if v > 0.0 { "Infinity".into() } else { "-Infinity".into() }) }
}
pub fn enum_from_json<T: Into<i32Wrap>>(j: &Json, by_name: fn(&str) -> Option<T>) -> Result<i32, DecodeError> {
    match j {
        Json::Num(n) => Ok(*n as i32),
        Json::Str(s) => by_name(s).map(|v| v.into().0).ok_or_else(|| DecodeError(Box::new(format!("unknown enum value {s}")))),
        _ => Err(DecodeError::new("enum value expected")),
    }
}
/// Carrier so `enum_from_json` works for every generated enum.
pub struct i32Wrap(pub i32);
pub fn str_from_json(j: &Json) -> Result<Str, DecodeError> {
    match j {
        Json::Str(s) => Ok(Str::new(s)),
        Json::Num(n) => Ok(Str::from(js_number(*n))),
        Json::Bool(b) => Ok(Str::new(if *b { "true" } else { "false" })),
        _ => Err(DecodeError::new("string expected")),
    }
}
pub fn bytes_from_json(j: &Json) -> Result<Bytes, DecodeError> {
    match j {
        Json::Bytes(b) => Ok(Bytes::copy_from(b)),
        Json::Str(s) => Ok(Bytes::from_vec(base64_decode(s))),
        Json::Arr(a) => Ok(Bytes::from_vec(a.iter().map(|v| v.as_f64().unwrap_or(0.0) as u8).collect())),
        Json::Obj(_) => {
            // BufferJSON and Buffer.toJSON forms
            if let Some(Json::Str(s)) = j.get("data") {
                return Ok(Bytes::from_vec(base64_decode(s)));
            }
            if let Some(a @ Json::Arr(_)) = j.get("data") {
                return bytes_from_json(a);
            }
            Err(DecodeError::new("bytes expected"))
        }
        _ => Err(DecodeError::new("bytes expected")),
    }
}
pub fn i64_from_json(j: &Json) -> Result<i64, DecodeError> {
    match j {
        Json::Num(n) => Ok(*n as i64),
        Json::Str(s) => s.parse::<i64>().or_else(|_| s.parse::<u64>().map(|v| v as i64)).map_err(|_| DecodeError(Box::new(format!("invalid integer {s}")))),
        Json::Obj(_) => long_parts(j).map(|v| v as i64),
        Json::Bool(b) => Ok(*b as i64),
        _ => Err(DecodeError::new("integer expected")),
    }
}
pub fn u64_from_json(j: &Json) -> Result<u64, DecodeError> {
    match j {
        Json::Num(n) => Ok(*n as u64),
        Json::Str(s) => s.parse::<u64>().or_else(|_| s.parse::<i64>().map(|v| v as u64)).map_err(|_| DecodeError(Box::new(format!("invalid integer {s}")))),
        Json::Obj(_) => long_parts(j),
        Json::Bool(b) => Ok(*b as u64),
        _ => Err(DecodeError::new("integer expected")),
    }
}
/// A protobufjs Long in JSON form: `{ low, high, unsigned }`.
fn long_parts(j: &Json) -> Result<u64, DecodeError> {
    let lo = j.get("low").and_then(Json::as_f64).ok_or_else(|| DecodeError::new("long expected"))? as i64 as u32;
    let hi = j.get("high").and_then(Json::as_f64).ok_or_else(|| DecodeError::new("long expected"))? as i64 as u32;
    Ok(((hi as u64) << 32) | lo as u64)
}
pub fn f64_from_json(j: &Json) -> Result<f64, DecodeError> {
    match j {
        Json::Num(n) => Ok(*n),
        Json::Str(s) => s.parse::<f64>().map_err(|_| DecodeError::new("number expected")),
        _ => Err(DecodeError::new("number expected")),
    }
}
pub fn bool_from_json(j: &Json) -> Result<bool, DecodeError> {
    Ok(match j {
        Json::Bool(b) => *b,
        Json::Num(n) => *n != 0.0,
        Json::Str(s) => !s.is_empty(),
        _ => false,
    })
}
/// Map keys arrive as JSON strings. Each key type this schema uses converts through this trait.
pub trait MapKey: Sized {
    fn from_key(s: &str) -> Result<Self, DecodeError>;
}
impl MapKey for Str {
    fn from_key(s: &str) -> Result<Str, DecodeError> {
        Ok(Str::new(s))
    }
}
impl MapKey for i32 {
    fn from_key(s: &str) -> Result<i32, DecodeError> {
        s.parse().map_err(|_| DecodeError::new("integer map key expected"))
    }
}
impl MapKey for u32 {
    fn from_key(s: &str) -> Result<u32, DecodeError> {
        s.parse().map_err(|_| DecodeError::new("integer map key expected"))
    }
}
pub fn map_key_from_json<K: MapKey>(s: &str) -> Result<K, DecodeError> {
    K::from_key(s)
}
/// Generated code uses this name because the schema has a message called `Option`.
pub type Opt<T> = std::option::Option<T>;
