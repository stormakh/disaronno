//! Port of proto-tojson-long.test.ts.
use waproto::WebMessageInfo;
use waproto::pb::{Json, PbMessage};

fn file_length_of(json: &Json) -> Option<&Json> {
    json.get("message")?.get("imageMessage")?.get("fileLength")
}
fn message(ts: Json, file_length: Json) -> WebMessageInfo {
    let j = Json::Obj(vec![
        ("key".to_string(), Json::Obj(vec![("remoteJid".to_string(), Json::Str("123@s.whatsapp.net".to_string())), ("id".to_string(), Json::Str("ABC123".to_string())), ("fromMe".to_string(), Json::Bool(false))])),
        ("messageTimestamp".to_string(), ts),
        ("message".to_string(), Json::Obj(vec![("imageMessage".to_string(), Json::Obj(vec![("fileLength".to_string(), file_length)]))])),
    ]);
    WebMessageInfo::from_json(&j).unwrap()
}
/// A `Long` as protobufjs `fromObject` reads it, with the same bits as `Long.fromString(s, true)`.
fn long(low: i32, high: i32) -> Json {
    Json::Obj(vec![("low".to_string(), Json::Num(low as f64)), ("high".to_string(), Json::Num(high as f64)), ("unsigned".to_string(), Json::Bool(true))])
}
#[test]
fn t_proto_serialization_handles_string_values_in_long_fields_gracefully() {
    // adapted: Rust fields are typed, so the string value enters through `fromObject` input
    let m = message(Json::Num(1.0), Json::Str("1234567890123456789".to_string()));
    let json = m.to_json();
    assert!(!json.stringify().is_empty());
    assert_eq!(file_length_of(&json), Some(&Json::Str("1234567890123456789".to_string())));
}
#[test]
fn t_proto_serialization_converts_long_objects_to_strings_correctly_via_bigint_fast_path() {
    // Long.fromNumber(1700000000, true) and Long.fromString('9876543210', true)
    let m = message(long(1700000000, 0), long(1286608618, 2));
    let json = m.to_json();
    assert_eq!(json.get("messageTimestamp"), Some(&Json::Str("1700000000".to_string())));
    assert_eq!(file_length_of(&json), Some(&Json::Str("9876543210".to_string())));
}
#[test]
fn t_proto_serialization_handles_large_unsigned_long_values_max_safe_integer() {
    // Long.fromString('18446744073709551615', true) and Long.fromString('9999999999999999999', true)
    let m = message(long(-1, -1), long(-1981284353, -1966660860));
    let json = m.to_json();
    assert_eq!(json.get("messageTimestamp"), Some(&Json::Str("18446744073709551615".to_string())));
    assert_eq!(file_length_of(&json), Some(&Json::Str("9999999999999999999".to_string())));
}
#[test]
fn t_proto_serialization_handles_zero_and_small_long_values() {
    let m = message(long(0, 0), long(1, 0));
    let json = m.to_json();
    assert_eq!(json.get("messageTimestamp"), Some(&Json::Str("0".to_string())));
    assert_eq!(file_length_of(&json), Some(&Json::Str("1".to_string())));
}
#[test]
fn t_proto_serialization_roundtrips_encode_decode_with_long_fields_preserving_values() {
    let original = message(Json::Num(1700000000.0), Json::Num(123456789.0));
    let encoded = original.encode();
    let decoded = WebMessageInfo::decode(&encoded).unwrap();
    let json = decoded.to_json();
    assert_eq!(json.get("messageTimestamp"), Some(&Json::Str("1700000000".to_string())));
    assert_eq!(file_length_of(&json), Some(&Json::Str("123456789".to_string())));
}
