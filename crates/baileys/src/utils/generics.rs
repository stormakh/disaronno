//! Same behavior as Utils/generics.ts. `Promise` helpers block the calling thread.
//! `trimUndefined` has no port: a Rust `Option` field that is `None` is already absent.
use crate::crypto;
use crate::error::{Boom, Result};
use crate::events::{BaileysEvent, BaileysEventEmitter, EventKind, ListenerId};
use crate::types::{DisconnectReason, RequestInit, WACallUpdateType, WAVersion};
use crate::utils::time::{Timeout, now_ms, set_timeout};
use crate::wabinary::{BinaryNode, get_all_binary_node_children, jid_decode};
use rustc_hash::FxHashMap;
use std::sync::{Arc, Condvar, Mutex};
use waproto::pb::{Json, PbMessage, base64_decode, base64_encode, js_number};
use waproto::web_message_info::Status;
use waproto::{Message, MessageKey};

const BAILEYS_VERSION: WAVersion = [2, 3000, 1043857760];

/// An object map that keeps insertion order, as a JavaScript object does for non-numeric keys.
/// A deleted key gets a new position when it is set again.
#[derive(Clone, Debug)]
pub struct JsMap<V> {
    slots: Vec<Option<(String, V)>>,
    index: FxHashMap<String, usize>,
}
impl<V> Default for JsMap<V> {
    fn default() -> JsMap<V> {
        JsMap { slots: Vec::new(), index: FxHashMap::default() }
    }
}
impl<V: PartialEq> PartialEq for JsMap<V> {
    fn eq(&self, o: &JsMap<V>) -> bool {
        self.len() == o.len() && self.iter().zip(o.iter()).all(|(a, b)| a == b)
    }
}
impl<V> JsMap<V> {
    pub fn new() -> JsMap<V> {
        JsMap::default()
    }
    pub fn len(&self) -> usize {
        self.index.len()
    }
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
    pub fn contains_key(&self, k: &str) -> bool {
        self.index.contains_key(k)
    }
    pub fn get(&self, k: &str) -> Option<&V> {
        let i = *self.index.get(k)?;
        self.slots[i].as_ref().map(|e| &e.1)
    }
    pub fn get_mut(&mut self, k: &str) -> Option<&mut V> {
        let i = *self.index.get(k)?;
        self.slots[i].as_mut().map(|e| &mut e.1)
    }
    /// Replaces the value in place when the key exists. Otherwise it adds the key at the end.
    pub fn insert(&mut self, k: impl Into<String>, v: V) {
        let k = k.into();
        match self.index.get(&k) {
            Some(i) => self.slots[*i] = Some((k, v)),
            None => {
                self.index.insert(k.clone(), self.slots.len());
                self.slots.push(Some((k, v)));
            }
        }
    }
    pub fn remove(&mut self, k: &str) -> Option<V> {
        let i = self.index.remove(k)?;
        self.slots[i].take().map(|e| e.1)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.slots.iter().flatten().map(|(k, v)| (k.as_str(), v))
    }
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.slots.iter().flatten().map(|(_, v)| v)
    }
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.slots.iter_mut().flatten().map(|(_, v)| v)
    }
    pub fn into_values(self) -> Vec<V> {
        self.slots.into_iter().flatten().map(|(_, v)| v).collect()
    }
    pub fn into_pairs(self) -> Vec<(String, V)> {
        self.slots.into_iter().flatten().collect()
    }
}

/// `value?.type === 'Buffer'` nodes become the base64 form. `Json::Bytes` already stringifies that way.
pub fn buffer_json_replacer(value: &Json) -> Json {
    if value.get("type").and_then(Json::as_str) == Some("Buffer") {
        let bytes = match value.get("data") {
            Some(Json::Arr(a)) => a.iter().map(|v| to_uint8(v.as_f64().unwrap_or(0.0))).collect(),
            Some(Json::Str(s)) => s.as_bytes().to_vec(),
            Some(Json::Bytes(b)) => b.clone(),
            _ => Vec::new(),
        };
        return Json::Obj(vec![("type".to_string(), Json::Str("Buffer".to_string())), ("data".to_string(), Json::Str(base64_encode(&bytes)))]);
    }
    value.clone()
}
fn to_uint8(n: f64) -> u8 {
    if !n.is_finite() {
        return 0;
    }
    let r = n.trunc() % 256.0;
    (if r < 0.0 { r + 256.0 } else { r }) as u8
}
/// `parseInt(k, 10)` is not NaN: optional spaces and sign, then at least one digit.
fn parses_as_int(k: &str) -> bool {
    let t = k.trim_start();
    let t = t.strip_prefix(['+', '-']).unwrap_or(t);
    t.as_bytes().first().is_some_and(u8::is_ascii_digit)
}
/// A canonical array index. JavaScript lists such keys first, in number order.
fn array_index(k: &str) -> Option<u32> {
    if k.len() > 1 && k.starts_with('0') {
        return None;
    }
    k.parse::<u32>().ok().filter(|n| *n != u32::MAX && k.bytes().all(|c| c.is_ascii_digit()))
}
/// One node of `BufferJSON.reviver`. Its children must be revived already.
pub fn buffer_json_reviver(value: Json) -> Json {
    let Json::Obj(o) = &value else { return value };
    if value.get("type").and_then(Json::as_str) == Some("Buffer") {
        if let Some(Json::Str(d)) = value.get("data") {
            return Json::Bytes(base64_decode(d));
        }
    }
    if !o.is_empty() && o.iter().all(|(k, v)| parses_as_int(k) && matches!(v, Json::Num(_))) {
        let mut indexed: Vec<(u32, u8)> = Vec::new();
        let mut others = Vec::new();
        for (k, v) in o {
            let b = to_uint8(v.as_f64().unwrap_or(0.0));
            match array_index(k) {
                Some(i) => indexed.push((i, b)),
                None => others.push(b),
            }
        }
        indexed.sort_by_key(|(i, _)| *i);
        let mut bytes: Vec<u8> = indexed.into_iter().map(|(_, b)| b).collect();
        bytes.extend(others);
        return Json::Bytes(bytes);
    }
    value
}
fn revive_deep(value: Json) -> Json {
    let v = match value {
        Json::Arr(a) => Json::Arr(a.into_iter().map(revive_deep).collect()),
        Json::Obj(o) => Json::Obj(o.into_iter().map(|(k, x)| (k, revive_deep(x))).collect()),
        other => other,
    };
    buffer_json_reviver(v)
}
fn replace_deep(value: &Json) -> Json {
    match buffer_json_replacer(value) {
        Json::Arr(a) => Json::Arr(a.iter().map(replace_deep).collect()),
        Json::Obj(o) => Json::Obj(o.iter().map(|(k, x)| (k.clone(), if k == "data" && value.get("type").and_then(Json::as_str) == Some("Buffer") { x.clone() } else { replace_deep(x) })).collect()),
        other => other,
    }
}
/// Same as `JSON.stringify(value, BufferJSON.replacer)`.
pub fn buffer_json_stringify(value: &Json) -> String {
    replace_deep(value).stringify()
}
/// Same as `JSON.parse(text, BufferJSON.reviver)`. Buffers come back as `Json::Bytes`.
pub fn buffer_json_parse(text: &str) -> Result<Json> {
    Ok(revive_deep(Json::parse(text)?))
}

pub fn get_key_author<'a>(key: Option<&'a MessageKey>, me_id: &'a str) -> &'a str {
    let Some(k) = key else { return "" };
    if k.from_me() == Some(true) {
        return me_id;
    }
    [k.participant_alt(), k.remote_jid_alt(), k.participant(), k.remote_jid()].into_iter().flatten().map(|s| s.as_str()).find(|s| !s.is_empty()).unwrap_or("")
}
pub fn is_string_null_or_empty(value: Option<&str>) -> bool {
    value.is_none_or(str::is_empty)
}
pub fn write_random_pad_max16(msg: &[u8]) -> Vec<u8> {
    let mut pad = [0u8; 1];
    crypto::random_bytes(&mut pad);
    let n = (pad[0] & 0x0f) + 1;
    let mut o = Vec::with_capacity(msg.len() + n as usize);
    o.extend_from_slice(msg);
    o.resize(msg.len() + n as usize, n);
    o
}
pub fn unpad_random_max16(t: &[u8]) -> Result<&[u8]> {
    let Some(r) = t.last() else { return Err(Boom::new("unpadPkcs7 given empty bytes")) };
    if *r as usize > t.len() {
        return Err(Boom::new(format!("unpad given {} bytes, but pad is {r}", t.len())));
    }
    Ok(&t[..t.len() - *r as usize])
}
/// Sorts `participants` in place, by UTF-16 code unit as `Array.sort` does.
pub fn generate_participant_hash_v2(participants: &mut [String]) -> String {
    participants.sort_by_key(|p| p.encode_utf16().collect::<Vec<u16>>());
    let hash = base64_encode(&crypto::sha256(participants.concat().as_bytes()));
    let mut s = String::with_capacity(8);
    s.push_str("2:");
    s.push_str(&hash[..6]);
    s
}
pub fn encode_wa_message(message: &Message) -> Vec<u8> {
    write_random_pad_max16(&message.encode())
}
/// Upstream reads `Uint16Array.from(bytes)[0]`, which is the first byte alone.
pub fn generate_registration_id() -> u32 {
    let mut b = [0u8; 2];
    crypto::random_bytes(&mut b);
    b[0] as u32 & 16383
}
pub fn encode_big_endian(e: u32, t: usize) -> Vec<u8> {
    let mut a = vec![0u8; t];
    let mut r = e;
    for i in (0..t).rev() {
        a[i] = (r & 255) as u8;
        r = r.checked_shr(8).unwrap_or(0);
    }
    a
}

/// The fields of a `Long` from the `long` package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Long {
    pub low: i32,
    pub high: i32,
    pub unsigned: bool,
}
impl Long {
    pub fn from_bits(low: i32, high: i32, unsigned: bool) -> Long {
        Long { low, high, unsigned }
    }
    fn bits(self) -> u64 {
        ((self.high as u32 as u64) << 32) | self.low as u32 as u64
    }
}
/// The values that the upstream long helpers accept. `Object` is any other object.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LongValue<'a> {
    Str(&'a str),
    Num(f64),
    Long(Long),
    Null,
    Undefined,
    Object,
}
/// `longToString` from WAProto/fix-imports.js.
pub fn long_to_string(value: LongValue<'_>, unsigned: bool) -> String {
    match value {
        LongValue::Str(s) => s.to_string(),
        LongValue::Num(n) => js_number(n),
        LongValue::Long(l) if !unsigned && l.high < 0 => (l.bits() as i64).to_string(),
        LongValue::Long(l) => l.bits().to_string(),
        LongValue::Null => "null".to_string(),
        LongValue::Undefined => "undefined".to_string(),
        LongValue::Object => "[object Object]".to_string(),
    }
}
/// Same as `Number(string)`.
fn js_string_to_number(s: &str) -> f64 {
    let t = s.trim();
    match t {
        "" => return 0.0,
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(d) = t.strip_prefix(prefix) {
            return u64::from_str_radix(d, radix).map_or(f64::NAN, |v| v as f64);
        }
    }
    if t.bytes().any(|c| !(c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))) {
        return f64::NAN;
    }
    t.parse().unwrap_or(f64::NAN)
}
/// `longToNumber` from WAProto/fix-imports.js.
pub fn long_to_number(value: LongValue<'_>, unsigned: bool) -> f64 {
    match value {
        LongValue::Num(n) => n,
        LongValue::Str(s) => js_string_to_number(s),
        LongValue::Long(l) if !unsigned && l.high < 0 => l.bits() as i64 as f64,
        LongValue::Long(l) => l.bits() as f64,
        LongValue::Null => 0.0,
        LongValue::Undefined | LongValue::Object => f64::NAN,
    }
}
/// Types that `toNumber` can read.
pub trait ToJsNumber {
    fn to_js_number(self) -> f64;
}
macro_rules! to_js_number {
    ($($t:ty),*) => { $(impl ToJsNumber for $t { fn to_js_number(self) -> f64 { self as f64 } })* };
}
to_js_number!(u64, i64, u32, i32, f64);
impl ToJsNumber for Long {
    fn to_js_number(self) -> f64 {
        if self.unsigned { self.bits() as f64 } else { self.bits() as i64 as f64 }
    }
}
pub fn to_number<T: ToJsNumber>(t: Option<T>) -> f64 {
    t.map_or(0.0, T::to_js_number)
}

/// `Math.floor(date.getTime() / 1000)` of a time in milliseconds.
pub fn unix_timestamp_seconds(date_ms: Option<i64>) -> i64 {
    date_ms.unwrap_or_else(now_ms).div_euclid(1000)
}
pub type DebouncedTask = Arc<dyn Fn() + Send + Sync>;
struct DebouncedState {
    interval_ms: u64,
    task: Option<DebouncedTask>,
    timeout: Option<Timeout>,
}
/// From `debounced_timeout`. `start` replaces the pending timer.
pub struct DebouncedTimeout(Mutex<DebouncedState>);
pub fn debounced_timeout(interval_ms: u64, task: Option<DebouncedTask>) -> DebouncedTimeout {
    DebouncedTimeout(Mutex::new(DebouncedState { interval_ms, task, timeout: None }))
}
impl DebouncedTimeout {
    pub fn start(&self, new_interval_ms: Option<u64>, new_task: Option<DebouncedTask>) {
        let mut s = self.0.lock().unwrap();
        if new_task.is_some() {
            s.task = new_task;
        }
        if let Some(i) = new_interval_ms.filter(|i| *i != 0) {
            s.interval_ms = i;
        }
        if let Some(t) = s.timeout.take() {
            t.cancel();
        }
        let task = s.task.clone();
        let ms = s.interval_ms;
        s.timeout = Some(set_timeout(ms, move || {
            if let Some(t) = task {
                t();
            }
        }));
    }
    pub fn cancel(&self) {
        if let Some(t) = self.0.lock().unwrap().timeout.take() {
            t.cancel();
        }
    }
    pub fn set_task(&self, new_task: DebouncedTask) {
        self.0.lock().unwrap().task = Some(new_task);
    }
    pub fn set_interval(&self, new_interval_ms: u64) {
        self.0.lock().unwrap().interval_ms = new_interval_ms;
    }
}
pub fn delay(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}
/// A one-shot result that any thread can complete. This is what a `Promise` becomes.
pub struct Resolver<T>(Arc<(Mutex<Option<Result<T>>>, Condvar)>);
impl<T> Clone for Resolver<T> {
    fn clone(&self) -> Resolver<T> {
        Resolver(self.0.clone())
    }
}
impl<T> Default for Resolver<T> {
    fn default() -> Resolver<T> {
        Resolver(Arc::new((Mutex::new(None), Condvar::new())))
    }
}
impl<T> Resolver<T> {
    pub fn new() -> Resolver<T> {
        Resolver::default()
    }
    fn settle(&self, r: Result<T>) {
        let mut g = self.0.0.lock().unwrap();
        if g.is_none() {
            *g = Some(r);
            self.0.1.notify_all();
        }
    }
    /// Only the first `resolve` or `reject` has an effect.
    pub fn resolve(&self, v: T) {
        self.settle(Ok(v))
    }
    pub fn reject(&self, e: Boom) {
        self.settle(Err(e))
    }
    /// Blocks until the result is ready, or until `ms` milliseconds pass (then `None`).
    pub fn wait(&self, ms: Option<u64>) -> Option<Result<T>> {
        let mut g = self.0.0.lock().unwrap();
        match ms {
            None => loop {
                if let Some(r) = g.take() {
                    return Some(r);
                }
                g = self.0.1.wait(g).unwrap();
            },
            Some(ms) => {
                let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
                loop {
                    if let Some(r) = g.take() {
                        return Some(r);
                    }
                    let now = std::time::Instant::now();
                    if now >= end {
                        return None;
                    }
                    g = self.0.1.wait_timeout(g, end - now).unwrap().0;
                }
            }
        }
    }
}
/// From `delay_cancellable`. `cancel` makes `wait` return the `Cancelled` error.
#[derive(Clone)]
pub struct DelayCancellable {
    done: Resolver<()>,
}
pub fn delay_cancellable(ms: u64) -> DelayCancellable {
    let done = Resolver::new();
    let d = done.clone();
    set_timeout(ms, move || d.resolve(()));
    DelayCancellable { done }
}
impl DelayCancellable {
    pub fn wait(&self) -> Result<()> {
        self.done.wait(None).unwrap_or(Ok(()))
    }
    pub fn cancel(&self) {
        self.done.reject(Boom::status("Cancelled", 500));
    }
}
/// `promise` gets a resolver and may complete it from any thread. No time limit when `ms` is
/// `None` or 0. Otherwise the result is the `Timed Out` error when the time passes first.
pub fn promise_timeout<T>(ms: Option<u64>, promise: impl FnOnce(Resolver<T>)) -> Result<T> {
    let r = Resolver::new();
    promise(r.clone());
    match r.wait(ms.filter(|m| *m != 0)) {
        Some(v) => v,
        None => Err(Boom::status("Timed Out", DisconnectReason::TIMED_OUT.0)),
    }
}

// inspired from whatsmeow code
pub fn generate_message_id_v2(user_id: Option<&str>) -> String {
    let mut data = [0u8; 8 + 20 + 16];
    data[..8].copy_from_slice(&((now_ms() / 1000) as u64).to_be_bytes());
    let mut write = |at: usize, s: &[u8]| {
        if at < data.len() {
            let n = s.len().min(data.len() - at);
            data[at..at + n].copy_from_slice(&s[..n]);
        }
    };
    if let Some(id) = user_id.and_then(jid_decode).filter(|d| !d.user.is_empty()) {
        write(8, id.user.as_bytes());
        write(8 + id.user.encode_utf16().count(), b"@c.us");
    }
    let mut random = [0u8; 16];
    crypto::random_bytes(&mut random);
    data[28..].copy_from_slice(&random);
    let hash = crypto::sha256(&data);
    let mut id = String::with_capacity(22);
    id.push_str("3EB0");
    id.push_str(&hex_upper(&hash)[..18]);
    id
}
fn hex_upper(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(*x >> 4) as usize] as char);
        s.push(H[(*x & 15) as usize] as char);
    }
    s
}
pub fn generate_message_id() -> String {
    let mut b = [0u8; 18];
    crypto::random_bytes(&mut b);
    let mut id = String::with_capacity(40);
    id.push_str("3EB0");
    id.push_str(&hex_upper(&b));
    id
}
/// Blocks until `check` returns true for `event`. A close of the connection rejects with its
/// error. Same as the function that `bindWaitForEvent` returns, called with the emitter.
pub fn bind_wait_for_event(ev: &dyn BaileysEventEmitter, event: EventKind, check: Arc<dyn Fn(&BaileysEvent) -> bool + Send + Sync>, timeout_ms: Option<u64>) -> Result<()> {
    let ids: Mutex<Vec<(EventKind, ListenerId)>> = Mutex::new(Vec::new());
    let res = promise_timeout(timeout_ms, |r: Resolver<()>| {
        let close = r.clone();
        let a = ev.on(
            EventKind::ConnectionUpdate,
            Arc::new(move |e: &BaileysEvent| {
                if let BaileysEvent::ConnectionUpdate(u) = e {
                    if u.connection == Some(crate::types::WAConnectionState::Close) {
                        let err = u.last_disconnect.as_ref().and_then(|d| d.error.clone());
                        close.reject(err.unwrap_or_else(|| Boom::status("Connection Closed", DisconnectReason::CONNECTION_CLOSED.0)));
                    }
                }
            }),
        );
        let done = r.clone();
        let b = ev.on(
            event,
            Arc::new(move |e: &BaileysEvent| {
                if check(e) {
                    done.resolve(());
                }
            }),
        );
        let mut g = ids.lock().unwrap();
        g.push((EventKind::ConnectionUpdate, a));
        g.push((event, b));
    });
    for (k, id) in ids.lock().unwrap().iter() {
        ev.off(*k, *id);
    }
    res
}
pub fn bind_wait_for_connection_update(ev: &dyn BaileysEventEmitter, check: Arc<dyn Fn(&BaileysEvent) -> bool + Send + Sync>, timeout_ms: Option<u64>) -> Result<()> {
    bind_wait_for_event(ev, EventKind::ConnectionUpdate, check, timeout_ms)
}

/// Result of a version lookup. On a failure `version` is the built-in one and `error` is set.
#[derive(Clone, Debug, PartialEq)]
pub struct FetchedVersion {
    pub version: WAVersion,
    pub is_latest: bool,
    pub error: Option<Boom>,
}
fn digits_at(s: &str) -> (&str, &str) {
    let n = s.bytes().position(|c| !c.is_ascii_digit()).unwrap_or(s.len());
    s.split_at(n)
}
/// Reads the regex `const version = \[(\d+),\s*(\d+),\s*(\d+)\]` from one line.
fn parse_version_line(line: &str) -> Option<WAVersion> {
    const PRE: &str = "const version = [";
    for (at, _) in line.match_indices(PRE) {
        let mut rest = &line[at + PRE.len()..];
        let mut v = [0u32; 3];
        let mut ok = true;
        for i in 0..3 {
            let (d, r) = digits_at(rest);
            if d.is_empty() {
                ok = false;
                break;
            }
            v[i] = d.parse().unwrap_or(u32::MAX);
            rest = r;
            if i < 2 {
                match rest.strip_prefix(',') {
                    Some(r) => rest = r.trim_start(),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
        }
        if ok && rest.starts_with(']') {
            return Some(v);
        }
    }
    None
}
/// The parsing step of `fetchLatestBaileysVersion`: the version is on line 7 of Defaults/index.ts.
pub fn parse_baileys_version(text: &str) -> Result<WAVersion> {
    text.split('\n').nth(6).and_then(parse_version_line).ok_or_else(|| Boom::new("Could not parse version from Defaults/index.ts"))
}
/// Reads the regex `\\?"client_revision\\?":\s*(\d+)` from sw.js.
pub fn parse_client_revision(data: &str) -> Option<u32> {
    const KEY: &str = "\"client_revision";
    for (at, _) in data.match_indices(KEY) {
        let r = &data[at + KEY.len()..];
        let r = r.strip_prefix('\\').unwrap_or(r);
        let Some(r) = r.strip_prefix("\":") else { continue };
        let (d, _) = digits_at(r.trim_start());
        if !d.is_empty() {
            return d.parse().ok();
        }
    }
    None
}
/// Uses the HTTP client in `options`. Without one this gives the same result as a network failure.
pub fn fetch_latest_baileys_version(options: &RequestInit) -> FetchedVersion {
    const URL: &str = "https://raw.githubusercontent.com/WhiskeySockets/Baileys/master/src/Defaults/index.ts";
    let got = options.get(URL, &[]).and_then(|res| {
        if !res.ok() {
            return Err(Boom::status(format!("Failed to fetch latest Baileys version: {}", res.status_text), res.status));
        }
        parse_baileys_version(&String::from_utf8_lossy(&res.body))
    });
    match got {
        Ok(version) => FetchedVersion { version, is_latest: true, error: None },
        Err(e) => FetchedVersion { version: BAILEYS_VERSION, is_latest: false, error: Some(e) },
    }
}
pub fn fetch_latest_wa_web_version(options: &RequestInit) -> FetchedVersion {
    // Absolute minimal headers required to bypass anti-bot detection
    let mut headers = vec![("sec-fetch-site".to_string(), "none".to_string()), ("user-agent".to_string(), "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string())];
    for (k, v) in &options.headers {
        match headers.iter_mut().find(|(n, _)| n == k) {
            Some(e) => e.1 = v.clone(),
            None => headers.push((k.clone(), v.clone())),
        }
    }
    let got = options.get("https://web.whatsapp.com/sw.js", &headers).and_then(|res| {
        if !res.ok() {
            return Err(Boom::status(format!("Failed to fetch sw.js: {}", res.status_text), res.status));
        }
        parse_client_revision(&String::from_utf8_lossy(&res.body)).ok_or_else(|| Boom::new("Could not find client revision in the fetched content"))
    });
    match got {
        Ok(rev) => FetchedVersion { version: [2, 3000, rev], is_latest: true, error: None },
        Err(e) => FetchedVersion { version: BAILEYS_VERSION, is_latest: false, error: Some(e) },
    }
}
/// unique message tag prefix for MD clients
pub fn generate_md_tag_prefix() -> String {
    let mut b = [0u8; 4];
    crypto::random_bytes(&mut b);
    format!("{}.{}-", u16::from_be_bytes([b[0], b[1]]), u16::from_be_bytes([b[2], b[3]]))
}
/// `None` as input is `undefined` and gives DELIVERY_ACK. An unknown type gives `None`.
pub fn get_status_from_receipt_type(ty: Option<&str>) -> Option<Status> {
    match ty {
        None => Some(Status::DELIVERY_ACK),
        Some("sender") => Some(Status::SERVER_ACK),
        Some("played") => Some(Status::PLAYED),
        Some("read") | Some("read-self") => Some(Status::READ),
        Some(_) => None,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamErrorInfo {
    pub reason: String,
    /// 0 stands for the NaN that upstream gets from a `code` that is not a number.
    pub status_code: u16,
}
/// Stream errors generally provide a reason, map that to a baileys DisconnectReason
pub fn get_error_code_from_stream_error(node: &BinaryNode) -> StreamErrorInfo {
    let mut reason = get_all_binary_node_children(node).first().map_or("unknown", |c| c.tag.as_str()).to_string();
    let status_code = match node.attr("code").filter(|c| !c.is_empty()) {
        Some(c) => c.trim().parse().unwrap_or(0),
        None if reason == "conflict" => DisconnectReason::CONNECTION_REPLACED.0,
        None => DisconnectReason::BAD_SESSION.0,
    };
    if status_code == DisconnectReason::RESTART_REQUIRED.0 {
        reason = "restart required".to_string();
    }
    StreamErrorInfo { reason, status_code }
}
pub fn get_call_status_from_node(node: &BinaryNode) -> WACallUpdateType {
    match node.tag.as_str() {
        "offer" | "offer_notice" => WACallUpdateType::Offer,
        "terminate" if node.attr("reason") == Some("timeout") => WACallUpdateType::Timeout,
        //fired when accepted/rejected/timeout/caller hangs up
        "terminate" => WACallUpdateType::Terminate,
        "preaccept" => WACallUpdateType::Preaccept,
        "transport" => WACallUpdateType::Transport,
        "relaylatency" => WACallUpdateType::Relaylatency,
        "reject" => WACallUpdateType::Reject,
        "accept" => WACallUpdateType::Accept,
        _ => WACallUpdateType::Ringing,
    }
}
const UNEXPECTED_SERVER_CODE_TEXT: &str = "Unexpected server response: ";
/// `code` is the `code` field of a socket error, such as `ETIMEDOUT`.
pub fn get_code_from_ws_error(message: &str, code: Option<&str>) -> u16 {
    if message.contains(UNEXPECTED_SERVER_CODE_TEXT) {
        let n = message.get(UNEXPECTED_SERVER_CODE_TEXT.len()..).and_then(|t| t.trim().parse::<f64>().ok());
        return match n {
            Some(c) if c >= 400.0 => c as u16,
            _ => 500,
        };
    }
    if code.is_some_and(|c| c.starts_with('E')) || message.contains("timed out") {
        return 408;
    }
    500
}
/// Is the given platform WA business
pub fn is_wa_business_platform(platform: &str) -> bool {
    platform == "smbi" || platform == "smba"
}
const CROCKFORD_CHARACTERS: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";
pub fn bytes_to_crockford(buffer: &[u8]) -> String {
    let mut value = 0u32;
    let mut bit_count = 0u32;
    let mut s = String::with_capacity(buffer.len() * 8 / 5 + 1);
    for e in buffer {
        value = (value << 8) | *e as u32;
        bit_count += 8;
        while bit_count >= 5 {
            s.push(CROCKFORD_CHARACTERS[((value >> (bit_count - 5)) & 31) as usize] as char);
            bit_count -= 5;
        }
    }
    if bit_count > 0 {
        s.push(CROCKFORD_CHARACTERS[((value << (5 - bit_count)) & 31) as usize] as char);
    }
    s
}
pub fn encode_newsletter_message(message: &Message) -> Vec<u8> {
    message.encode()
}
