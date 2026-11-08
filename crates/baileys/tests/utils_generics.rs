//! Port of Utils/generics.test.ts.
use baileys::utils::generics::{buffer_json_parse, buffer_json_stringify};
use waproto::pb::Json;

fn obj(v: Vec<(&str, Json)>) -> Json {
    Json::Obj(v.into_iter().map(|(k, x)| (k.to_string(), x)).collect())
}
fn original_object() -> Json {
    obj(vec![("id", Json::Num(1.0)), ("key", Json::Bytes(vec![1, 2, 3, 4, 5])), ("nested", obj(vec![("data", Json::Bytes(vec![6, 7, 8]))]))])
}
const LEGACY_JSON_STRING: &str = "{\"id\":1,\"key\":{\"0\":1,\"1\":2,\"2\":3,\"3\":4,\"4\":5},\"nested\":{\"data\":{\"0\":6,\"1\":7,\"2\":8}}}";

#[test]
fn t_bufferjson_should_correctly_perform_a_round_trip_stringify_with_replacer_parse_with_reviver() {
    let original = original_object();
    let serialized = buffer_json_stringify(&original);
    assert!(serialized.contains("\"type\":\"Buffer\""));
    assert!(!serialized.contains("\"data\":[1,2,3,4,5]"));
    let revived = buffer_json_parse(&serialized).unwrap();
    assert!(matches!(revived.get("key"), Some(Json::Bytes(_))));
    assert!(matches!(revived.get("nested").and_then(|n| n.get("data")), Some(Json::Bytes(_))));
    assert_eq!(revived.get("key"), original.get("key"));
    assert_eq!(revived, original);
}
#[test]
fn t_bufferjson_should_correctly_revive_a_legacy_json_string_with_object_like_buffers() {
    let original = original_object();
    let revived = buffer_json_parse(LEGACY_JSON_STRING).unwrap();
    assert!(matches!(revived.get("key"), Some(Json::Bytes(_))));
    assert!(matches!(revived.get("nested").and_then(|n| n.get("data")), Some(Json::Bytes(_))));
    assert_eq!(revived.get("key"), original.get("key"));
    assert_eq!(revived.get("nested").and_then(|n| n.get("data")), original.get("nested").and_then(|n| n.get("data")));
    assert_eq!(revived.get("id"), original.get("id"));
}
#[test]
fn t_bufferjson_should_not_corrupt_legitimate_objects_that_are_not_buffers() {
    let legitimate_proto_object = obj(vec![("0", Json::Str("some-value".to_string())), ("1", Json::Str("another-value".to_string()))]);
    let json_string = legitimate_proto_object.stringify();
    let revived = buffer_json_parse(&json_string).unwrap();
    assert!(!matches!(revived, Json::Bytes(_)));
    assert_eq!(revived, legitimate_proto_object);
}
#[test]
fn t_bufferjson_should_not_convert_other_objects_or_null_values() {
    let other_object = obj(vec![("a", Json::Num(1.0)), ("b", Json::Num(2.0)), ("c", Json::Null), ("d", obj(vec![("0", Json::Num(1.0)), ("foo", Json::Str("bar".to_string()))]))]);
    let json_string = other_object.stringify();
    let revived = buffer_json_parse(&json_string).unwrap();
    assert!(!matches!(revived.get("a"), Some(Json::Bytes(_))));
    assert_eq!(revived.get("c"), Some(&Json::Null));
    assert!(!matches!(revived.get("d"), Some(Json::Bytes(_))));
    assert_eq!(revived, other_object);
}
#[test]
fn t_bufferjson_should_correctly_handle_an_empty_object() {
    let revived = buffer_json_parse("{}").unwrap();
    assert_eq!(revived, Json::Obj(Vec::new()));
}
