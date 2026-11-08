//! Binary node format, same bytes as WABinary/encode.ts and decode.ts.
pub mod jid;
mod tokens;
pub use jid::*;
pub use tokens::{DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS};
use crate::error::{Boom, Result};
use rustc_hash::FxHashMap;
use std::io::Read;
use std::sync::{Arc, OnceLock};
use waproto::pb::{Bytes, Str};

pub mod tags {
    pub const LIST_EMPTY: u8 = 0;
    pub const DICTIONARY_0: u8 = 236;
    pub const DICTIONARY_3: u8 = 239;
    pub const INTEROP_JID: u8 = 245;
    pub const FB_JID: u8 = 246;
    pub const AD_JID: u8 = 247;
    pub const LIST_8: u8 = 248;
    pub const LIST_16: u8 = 249;
    pub const JID_PAIR: u8 = 250;
    pub const HEX_8: u8 = 251;
    pub const BINARY_8: u8 = 252;
    pub const BINARY_20: u8 = 253;
    pub const BINARY_32: u8 = 254;
    pub const NIBBLE_8: u8 = 255;
    pub const PACKED_MAX: usize = 127;
}
use tags::*;

/// Strings are often dictionary tokens, so most nodes do not allocate for them.
pub type NodeStr = Str;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct Attrs(pub Vec<(NodeStr, NodeStr)>);
impl Attrs {
    pub fn new() -> Attrs {
        Attrs(Vec::new())
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n.as_str() == k).map(|(_, v)| v.as_str())
    }
    /// A repeated key keeps its first position and takes the new value, like a JS object.
    pub fn set(&mut self, k: impl Into<NodeStr>, v: impl Into<NodeStr>) {
        let k = k.into();
        let v = v.into();
        match self.0.iter_mut().find(|(n, _)| *n == k) {
            Some(e) => e.1 = v,
            None => self.0.push((k, v)),
        }
    }
    pub fn remove(&mut self, k: &str) {
        while let Some(i) = self.0.iter().position(|(n, _)| n.as_str() == k) {
            self.0.remove(i);
        }
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}
impl<K: Into<NodeStr>, V: Into<NodeStr>, const N: usize> From<[(K, V); N]> for Attrs {
    fn from(a: [(K, V); N]) -> Attrs {
        let mut o = Attrs(Vec::with_capacity(N));
        for (k, v) in a {
            o.set(k, v);
        }
        o
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Content {
    Nodes(Vec<BinaryNode>),
    Binary(Bytes),
    Text(NodeStr),
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct BinaryNode {
    pub tag: NodeStr,
    pub attrs: Attrs,
    pub content: Option<Content>,
}
impl BinaryNode {
    pub fn new(tag: impl Into<NodeStr>, attrs: Attrs, content: Option<Content>) -> BinaryNode {
        BinaryNode { tag: tag.into(), attrs, content }
    }
    pub fn tag(tag: impl Into<NodeStr>, attrs: Attrs) -> BinaryNode {
        BinaryNode { tag: tag.into(), attrs, content: None }
    }
    pub fn with_nodes(tag: impl Into<NodeStr>, attrs: Attrs, nodes: Vec<BinaryNode>) -> BinaryNode {
        BinaryNode { tag: tag.into(), attrs, content: Some(Content::Nodes(nodes)) }
    }
    pub fn with_bytes(tag: impl Into<NodeStr>, attrs: Attrs, b: impl Into<Bytes>) -> BinaryNode {
        BinaryNode { tag: tag.into(), attrs, content: Some(Content::Binary(b.into())) }
    }
    pub fn with_text(tag: impl Into<NodeStr>, attrs: Attrs, t: impl Into<NodeStr>) -> BinaryNode {
        BinaryNode { tag: tag.into(), attrs, content: Some(Content::Text(t.into())) }
    }
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.get(k)
    }
}

fn token_map() -> &'static FxHashMap<&'static str, (Option<u8>, u8)> {
    static MAP: OnceLock<FxHashMap<&'static str, (Option<u8>, u8)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = FxHashMap::default();
        // the same order as constants.ts: single-byte entries, then double-byte entries overwrite
        for (i, t) in SINGLE_BYTE_TOKENS.iter().enumerate() {
            m.insert(*t, (None, i as u8));
        }
        for (d, ts) in DOUBLE_BYTE_TOKENS.iter().enumerate() {
            for (i, t) in ts.iter().enumerate() {
                m.insert(*t, (Some(d as u8), i as u8));
            }
        }
        m
    })
}

struct Enc {
    b: Vec<u8>,
}
impl Enc {
    fn byte_len(&mut self, n: usize) -> Result<()> {
        if n >= 4294967296 {
            return Err(Boom::new(format!("string too large to encode: {n}")));
        }
        if n >= 1 << 20 {
            self.b.push(BINARY_32);
            self.b.extend_from_slice(&(n as u32).to_be_bytes());
        } else if n >= 256 {
            self.b.extend_from_slice(&[BINARY_20, ((n >> 16) & 0x0f) as u8, (n >> 8) as u8, n as u8]);
        } else {
            self.b.extend_from_slice(&[BINARY_8, n as u8]);
        }
        Ok(())
    }
    fn raw(&mut self, s: &str) -> Result<()> {
        self.byte_len(s.len())?;
        self.b.extend_from_slice(s.as_bytes());
        Ok(())
    }
    fn packed(&mut self, s: &[u8], tag: u8) -> Result<()> {
        self.b.push(tag);
        let mut rounded = s.len().div_ceil(2) as u8;
        if s.len() % 2 != 0 {
            rounded |= 128;
        }
        self.b.push(rounded);
        let f: fn(u8) -> u8 = if tag == NIBBLE_8 { pack_nibble } else { pack_hex };
        for p in s.chunks(2) {
            let hi = f(p[0]);
            let lo = if p.len() == 2 { f(p[1]) } else { f(0) };
            self.b.push((hi << 4) | lo);
        }
        Ok(())
    }
    fn jid(&mut self, j: &FullJid<'_>) -> Result<()> {
        if let Some(d) = j.device {
            self.b.extend_from_slice(&[AD_JID, j.domain_type as u8, d as u8]);
            self.string(j.user)
        } else {
            self.b.push(JID_PAIR);
            if j.user.is_empty() {
                self.b.push(LIST_EMPTY);
            } else {
                self.string(j.user)?;
            }
            self.string(j.server)
        }
    }
    fn string(&mut self, s: &str) -> Result<()> {
        if s.is_empty() {
            return self.raw(s);
        }
        if let Some((d, i)) = token_map().get(s) {
            if let Some(d) = d {
                self.b.push(DICTIONARY_0 + d);
            }
            self.b.push(*i);
            return Ok(());
        }
        let b = s.as_bytes();
        if b.len() <= PACKED_MAX {
            if b.iter().all(|c| c.is_ascii_digit() || *c == b'-' || *c == b'.') {
                return self.packed(b, NIBBLE_8);
            }
            if b.iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c)) {
                return self.packed(b, HEX_8);
            }
        }
        if let Some(j) = jid_decode(s) {
            return self.jid(&j);
        }
        self.raw(s)
    }
    fn list(&mut self, n: usize) {
        if n == 0 {
            self.b.push(LIST_EMPTY);
        } else if n < 256 {
            self.b.extend_from_slice(&[LIST_8, n as u8]);
        } else {
            self.b.extend_from_slice(&[LIST_16, (n >> 8) as u8, n as u8]);
        }
    }
    fn node(&mut self, n: &BinaryNode) -> Result<()> {
        if n.tag.is_empty() {
            return Err(Boom::new("Invalid node: tag cannot be undefined"));
        }
        self.list(2 * n.attrs.len() + 1 + usize::from(n.content.is_some()));
        self.string(&n.tag)?;
        for (k, v) in &n.attrs.0 {
            self.string(k)?;
            self.string(v)?;
        }
        match &n.content {
            Some(Content::Text(t)) => self.string(t)?,
            Some(Content::Binary(b)) => {
                self.byte_len(b.len())?;
                self.b.extend_from_slice(b.as_slice());
            }
            Some(Content::Nodes(c)) => {
                self.list(c.len());
                for i in c {
                    self.node(i)?;
                }
            }
            None => {}
        }
        Ok(())
    }
}
fn pack_nibble(c: u8) -> u8 {
    match c {
        b'-' => 10,
        b'.' => 11,
        0 => 15,
        _ => c - b'0',
    }
}
fn pack_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'A'..=b'F' => 10 + c - b'A',
        b'a'..=b'f' => 10 + c - b'a',
        _ => 15,
    }
}

/// Encodes with the leading zero byte that marks "not compressed".
pub fn encode_binary_node(n: &BinaryNode) -> Result<Vec<u8>> {
    let mut e = Enc { b: Vec::with_capacity(512) };
    e.b.push(0);
    e.node(n)?;
    Ok(e.b)
}

/// Removes the compression byte. Inflates when bit 2 is set.
pub fn decompressing_if_required(b: &[u8]) -> Result<Vec<u8>> {
    if b.is_empty() {
        return Err(Boom::new("end of stream"));
    }
    if b[0] & 2 != 0 {
        let mut o = Vec::new();
        flate2::read::ZlibDecoder::new(&b[1..]).read_to_end(&mut o).map_err(|e| Boom::new(e.to_string()))?;
        return Ok(o);
    }
    Ok(b[1..].to_vec())
}

struct Dec {
    b: Arc<Vec<u8>>,
    i: usize,
}
const EOS: &str = "end of stream";
/// Boxed, so that a result is small and `?` moves little on this hot path.
type DecResult<T> = std::result::Result<T, Box<Boom>>;
#[cold]
fn dec_err(m: impl Into<String>) -> Box<Boom> {
    Box::new(Boom::new(m))
}
impl Dec {
    #[inline]
    fn byte(&mut self) -> DecResult<u8> {
        let v = *self.b.get(self.i).ok_or_else(|| dec_err(EOS))?;
        self.i += 1;
        Ok(v)
    }
    #[inline]
    fn take(&mut self, n: usize) -> DecResult<(usize, usize)> {
        if self.i + n > self.b.len() {
            return Err(dec_err(EOS));
        }
        let s = self.i;
        self.i += n;
        Ok((s, s + n))
    }
    fn int(&mut self, n: usize) -> DecResult<usize> {
        let mut v = 0usize;
        for _ in 0..n {
            v = (v << 8) | self.byte()? as usize;
        }
        Ok(v)
    }
    fn int20(&mut self) -> DecResult<usize> {
        let (a, b, c) = (self.byte()? as usize, self.byte()? as usize, self.byte()? as usize);
        Ok(((a & 15) << 16) + (b << 8) + c)
    }
    fn chars(&mut self, n: usize) -> DecResult<NodeStr> {
        let (s, e) = self.take(n)?;
        Ok(Str::from_utf8_lossy(&self.b[s..e]))
    }
    fn packed(&mut self, tag: u8) -> DecResult<NodeStr> {
        let start = self.byte()?;
        let n = (start & 127) as usize * 2;
        let mut v = [0u8; 254];
        for i in (0..n).step_by(2) {
            let c = self.byte()?;
            v[i] = unpack(tag, c >> 4)?;
            v[i + 1] = unpack(tag, c & 15)?;
        }
        Ok(Str::from_utf8_lossy(&v[..n.saturating_sub((start >> 7) as usize)]))
    }
    fn list_size(&mut self, tag: u8) -> DecResult<usize> {
        match tag {
            LIST_EMPTY => Ok(0),
            LIST_8 => Ok(self.byte()? as usize),
            LIST_16 => self.int(2),
            _ => Err(dec_err(format!("invalid tag for list size: {tag}"))),
        }
    }
    fn string(&mut self, tag: u8) -> DecResult<NodeStr> {
        if tag >= 1 && (tag as usize) < SINGLE_BYTE_TOKENS.len() {
            return Ok(Str::from_static(SINGLE_BYTE_TOKENS[tag as usize]));
        }
        match tag {
            DICTIONARY_0..=DICTIONARY_3 => {
                let i = self.byte()? as usize;
                let d = DOUBLE_BYTE_TOKENS.get((tag - DICTIONARY_0) as usize).ok_or_else(|| dec_err(format!("Invalid double token dict ({})", tag - DICTIONARY_0)))?;
                d.get(i).map(|s| Str::from_static(s)).ok_or_else(|| dec_err(format!("Invalid double token ({i})")))
            }
            LIST_EMPTY => Ok(Str::default()),
            BINARY_8 => {
                let n = self.byte()? as usize;
                self.chars(n)
            }
            BINARY_20 => {
                let n = self.int20()?;
                self.chars(n)
            }
            BINARY_32 => {
                let n = self.int(4)?;
                self.chars(n)
            }
            JID_PAIR => {
                let t = self.byte()?;
                let i = self.string(t)?;
                let t = self.byte()?;
                let j = self.string(t)?;
                if j.is_empty() {
                    return Err(dec_err(format!("invalid jid pair: {i}, {j}")));
                }
                Ok(Str::concat(&[&i, "@", &j]))
            }
            FB_JID => {
                let t = self.byte()?;
                let u = self.string(t)?;
                let d = self.int(2)?;
                let t = self.byte()?;
                let s = self.string(t)?;
                Ok(Str::from(format!("{u}:{d}@{s}")))
            }
            INTEROP_JID => {
                let t = self.byte()?;
                let u = self.string(t)?;
                let d = self.int(2)?;
                let integ = self.int(2)?;
                let before = self.i;
                let server = match self.byte().and_then(|t| self.string(t)) {
                    Ok(s) => s,
                    Err(_) => {
                        self.i = before;
                        Str::from_static("interop")
                    }
                };
                Ok(Str::from(format!("{integ}-{u}:{d}@{server}")))
            }
            AD_JID => {
                let domain = self.byte()? as u32;
                let device = self.byte()? as u32;
                let t = self.byte()?;
                let u = self.string(t)?;
                let server = match domain {
                    domains::LID => "lid",
                    domains::HOSTED => "hosted",
                    domains::HOSTED_LID => "hosted.lid",
                    _ => "s.whatsapp.net",
                };
                Ok(Str::from(jid_encode(&u, server, Some(device), None)))
            }
            HEX_8 | NIBBLE_8 => self.packed(tag),
            _ => Err(dec_err(format!("invalid string with tag: {tag}"))),
        }
    }
    fn node(&mut self, depth: u32) -> DecResult<BinaryNode> {
        // a frame can nest without end, and a stack overflow ends the whole process
        if depth >= 64 {
            return Err(dec_err("max depth exceeded"));
        }
        let t = self.byte()?;
        let size = self.list_size(t)?;
        let t = self.byte()?;
        let header = self.string(t)?;
        if size == 0 || header.is_empty() {
            return Err(dec_err("invalid node"));
        }
        let n_attrs = (size - 1) >> 1;
        let mut attrs = Attrs(Vec::with_capacity(n_attrs));
        for _ in 0..n_attrs {
            let t = self.byte()?;
            let k = self.string(t)?;
            let t = self.byte()?;
            let v = self.string(t)?;
            attrs.set(k, v);
        }
        let mut content = None;
        if size % 2 == 0 {
            let t = self.byte()?;
            content = Some(match t {
                LIST_EMPTY | LIST_8 | LIST_16 => {
                    let n = self.list_size(t)?;
                    // a hostile length must not reserve memory that the input cannot fill
                    let mut v = Vec::with_capacity(n.min(self.b.len() - self.i.min(self.b.len())));
                    for _ in 0..n {
                        v.push(self.node(depth + 1)?);
                    }
                    Content::Nodes(v)
                }
                BINARY_8 => {
                    let n = self.byte()? as usize;
                    self.binary(n)?
                }
                BINARY_20 => {
                    let n = self.int20()?;
                    self.binary(n)?
                }
                BINARY_32 => {
                    let n = self.int(4)?;
                    self.binary(n)?
                }
                _ => Content::Text(self.string(t)?),
            });
        }
        Ok(BinaryNode { tag: header, attrs, content })
    }
    fn binary(&mut self, n: usize) -> DecResult<Content> {
        let (s, e) = self.take(n)?;
        Ok(Content::Binary(Bytes::shared(&self.b, s, e)))
    }
}
#[inline]
fn unpack(tag: u8, v: u8) -> DecResult<u8> {
    if tag == NIBBLE_8 {
        return match v {
            0..=9 => Ok(b'0' + v),
            10 => Ok(b'-'),
            11 => Ok(b'.'),
            15 => Ok(0),
            _ => Err(dec_err(format!("invalid nibble: {v}"))),
        };
    }
    Ok(if v < 10 { b'0' + v } else { b'A' + v - 10 })
}

/// Decodes a node that has no compression byte. Binary content shares `b`.
pub fn decode_decompressed_binary_node(b: Arc<Vec<u8>>) -> Result<BinaryNode> {
    let mut d = Dec { b, i: 0 };
    d.node(0).map_err(|e| *e)
}
pub fn decode_binary_node(buff: &[u8]) -> Result<BinaryNode> {
    decode_decompressed_binary_node(Arc::new(decompressing_if_required(buff)?))
}
/// Same as `decode_binary_node` for a buffer the caller no longer needs. It does not copy.
pub fn decode_binary_node_owned(mut buff: Vec<u8>) -> Result<BinaryNode> {
    if buff.first().is_some_and(|f| f & 2 != 0) {
        return decode_binary_node(&buff);
    }
    if buff.is_empty() {
        return Err(Boom::new(EOS));
    }
    let mut d = Dec { b: Arc::new(std::mem::take(&mut buff)), i: 1 };
    d.node(0).map_err(|e| *e)
}

// generic-utils.ts helpers
pub fn get_binary_node_children<'a>(n: Option<&'a BinaryNode>, tag: &str) -> Vec<&'a BinaryNode> {
    match n.and_then(|n| n.content.as_ref()) {
        Some(Content::Nodes(c)) => c.iter().filter(|i| i.tag.as_str() == tag).collect(),
        _ => Vec::new(),
    }
}
pub fn get_all_binary_node_children(n: &BinaryNode) -> &[BinaryNode] {
    match &n.content {
        Some(Content::Nodes(c)) => c,
        _ => &[],
    }
}
pub fn get_binary_node_child<'a>(n: Option<&'a BinaryNode>, tag: &str) -> Option<&'a BinaryNode> {
    match n.and_then(|n| n.content.as_ref()) {
        Some(Content::Nodes(c)) => c.iter().find(|i| i.tag.as_str() == tag),
        _ => None,
    }
}
pub fn get_binary_node_child_buffer<'a>(n: Option<&'a BinaryNode>, tag: &str) -> Option<&'a Bytes> {
    match get_binary_node_child(n, tag).and_then(|c| c.content.as_ref()) {
        Some(Content::Binary(b)) => Some(b),
        _ => None,
    }
}
/// Reads a binary child as text. Text content is returned as it is.
pub fn get_binary_node_child_string(n: Option<&BinaryNode>, tag: &str) -> Option<String> {
    match get_binary_node_child(n, tag).and_then(|c| c.content.as_ref()) {
        Some(Content::Binary(b)) => Some(String::from_utf8_lossy(b.as_slice()).into_owned()),
        Some(Content::Text(t)) => Some(t.as_str().to_string()),
        _ => None,
    }
}
/// `None` also stands for the NaN that upstream gets from a buffer shorter than `length`.
pub fn get_binary_node_child_uint(n: Option<&BinaryNode>, tag: &str, length: usize) -> Option<u32> {
    let b = get_binary_node_child_buffer(n, tag)?;
    if b.len() < length {
        return None;
    }
    let mut v = 0u32;
    for x in b.as_slice().iter().take(length) {
        v = (v << 8) | *x as u32;
    }
    Some(v)
}
pub fn assert_node_error_free(node: &BinaryNode) -> Result<()> {
    if let Some(e) = get_binary_node_child(Some(node), "error") {
        let code = e.attr("code").and_then(|c| c.trim().parse::<f64>().ok()).unwrap_or(f64::NAN);
        return Err(Boom::with_data(e.attr("text").filter(|t| !t.is_empty()).unwrap_or("Unknown error"), waproto::pb::Json::Num(code)));
    }
    Ok(())
}
/// Keys come from `name` or else `config_code`, and values from `value` or else `config_value`.
pub fn reduce_binary_node_to_dictionary(node: &BinaryNode, tag: &str) -> Attrs {
    let mut dict = Attrs::new();
    for c in get_binary_node_children(Some(node), tag) {
        let key = c.attr("name").or_else(|| c.attr("config_code")).unwrap_or("undefined");
        match c.attr("value").filter(|v| !v.is_empty()).or_else(|| c.attr("config_value")) {
            Some(v) => dict.set(key, v),
            None => dict.remove(key),
        }
    }
    dict
}
pub fn get_binary_node_messages(node: &BinaryNode) -> Result<Vec<waproto::WebMessageInfo>> {
    let mut msgs = Vec::new();
    for item in get_all_binary_node_children(node) {
        if item.tag.as_str() == "message" {
            let body = match &item.content {
                Some(Content::Binary(b)) => b.as_slice(),
                _ => &[],
            };
            msgs.push(<waproto::WebMessageInfo as waproto::pb::PbMessage>::decode(body)?);
        }
    }
    Ok(msgs)
}
fn tabs(n: usize) -> String {
    "\t".repeat(n)
}
fn content_to_string(c: Option<&Content>, i: usize) -> String {
    match c {
        None => String::new(),
        Some(Content::Text(t)) if t.is_empty() => String::new(),
        Some(Content::Text(t)) => tabs(i) + t.as_str(),
        Some(Content::Binary(b)) => {
            let mut s = tabs(i);
            for x in b.as_slice() {
                s.push(char::from_digit((*x >> 4) as u32, 16).unwrap_or('0'));
                s.push(char::from_digit((*x & 15) as u32, 16).unwrap_or('0'));
            }
            s
        }
        Some(Content::Nodes(n)) => n.iter().map(|x| tabs(i + 1) + &binary_node_to_string(x, i + 1)).collect::<Vec<_>>().join("\n"),
    }
}
pub fn binary_node_to_string(node: &BinaryNode, i: usize) -> String {
    let children = content_to_string(node.content.as_ref(), i + 1);
    let attrs: Vec<String> = node.attrs.iter().map(|(k, v)| format!("{k}='{v}'")).collect();
    let tag = format!("<{} {}", node.tag, attrs.join(" "));
    if children.is_empty() {
        return tag + "/>";
    }
    format!("{tag}>\n{children}\n{}</{}>", tabs(i), node.tag)
}
