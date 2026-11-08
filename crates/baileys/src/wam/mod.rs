//! Same as src/WAM: the telemetry event tables and their binary encoding.
//!
//! `WEB_EVENTS` and `WEB_GLOBALS` of upstream are `web_events` and `web_globals` here. The tables are
//! text in the binary, and a value is parsed only when something asks for it.
pub mod constants;
pub mod encode;
use constants::{WEB_EVENTS_TEXT, WEB_GLOBALS_TEXT};
pub use encode::encode_wam;

/// The type of a prop or a global. `E` is an enum, with its names and numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropType {
    I,
    B,
    S,
    T,
    N,
    E(Vec<(&'static str, i64)>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prop {
    pub name: &'static str,
    pub id: u32,
    pub r#type: PropType,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub name: &'static str,
    pub id: u32,
    pub weight: i32,
    pub wam_channel: &'static str,
    pub private_stats_id_int: Option<i64>,
    pub props: Vec<Prop>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Global {
    pub name: &'static str,
    pub id: u32,
    pub r#type: PropType,
    pub validator: Option<&'static str>,
    pub channels: Vec<&'static str>,
}
fn parse_type(t: &'static str) -> PropType {
    match t {
        "i" => PropType::I,
        "b" => PropType::B,
        "s" => PropType::S,
        "t" => PropType::T,
        "n" => PropType::N,
        _ => PropType::E(t.split(',').skip(1).filter_map(|e| e.split_once('=')).map(|(k, v)| (k, v.parse().unwrap_or(0))).collect()),
    }
}
fn parse_event(line: &'static str) -> Option<Event> {
    let mut f = line.split('\t');
    let name = f.next()?;
    let id = f.next()?.parse().ok()?;
    let weight = f.next()?.parse().ok()?;
    let wam_channel = f.next()?;
    let private_stats_id_int = f.next()?.parse().ok();
    let mut props = Vec::new();
    for p in f {
        let mut parts = p.splitn(3, '|');
        props.push(Prop { name: parts.next()?, id: parts.next()?.parse().ok()?, r#type: parse_type(parts.next()?) });
    }
    Some(Event { name, id, weight, wam_channel, private_stats_id_int, props })
}
fn parse_global(line: &'static str) -> Option<Global> {
    let mut f = line.split('\t');
    let name = f.next()?;
    let id = f.next()?.parse().ok()?;
    let r#type = parse_type(f.next()?);
    let validator = f.next().filter(|v| !v.is_empty());
    let channels = f.next()?.split(',').collect();
    Some(Global { name, id, r#type, validator, channels })
}
/// The line of a table whose first field is `name`.
fn find_line(text: &'static str, name: &str) -> Option<&'static str> {
    text.lines().find(|l| l.split('\t').next() == Some(name))
}
/// `WEB_EVENTS.find(a => a.name === name)`.
pub fn find_event(name: &str) -> Option<Event> {
    parse_event(find_line(WEB_EVENTS_TEXT, name)?)
}
/// `WEB_GLOBALS.find(a => a.name === name)`.
pub fn find_global(name: &str) -> Option<Global> {
    parse_global(find_line(WEB_GLOBALS_TEXT, name)?)
}
/// `WEB_EVENTS`.
pub fn web_events() -> Vec<Event> {
    WEB_EVENTS_TEXT.lines().filter_map(parse_event).collect()
}
/// `WEB_GLOBALS`.
pub fn web_globals() -> Vec<Global> {
    WEB_GLOBALS_TEXT.lines().filter_map(parse_global).collect()
}
/// `Value` of upstream. A boolean is written as 0 or 1.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
}
/// One entry of `BinaryInfo.events`: `{ [name]: { props, globals } }`.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct EventInput {
    pub name: String,
    pub props: Vec<(String, Value)>,
    pub globals: Vec<(String, Value)>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryInfo {
    pub protocol_version: u8,
    pub sequence: u16,
    pub events: Vec<EventInput>,
    pub buffer: Vec<Vec<u8>>,
}
impl Default for BinaryInfo {
    fn default() -> BinaryInfo {
        BinaryInfo { protocol_version: 5, sequence: 0, events: Vec::new(), buffer: Vec::new() }
    }
}
impl BinaryInfo {
    pub fn new() -> BinaryInfo {
        BinaryInfo::default()
    }
}
