//! Port of src/__tests__/Socket/groups.test.ts.
use baileys::socket::extract_group_metadata;
use baileys::wabinary::{Attrs, BinaryNode};

fn minimal_group_node(overrides: &[(&str, &str)]) -> BinaryNode {
    let mut attrs = Attrs::from([("id", "120363000000000000"), ("creation", "1700000000"), ("s_t", "1700000000"), ("subject", "Test Group")]);
    for (k, v) in overrides {
        attrs.set(*k, *v);
    }
    BinaryNode::with_nodes("group", attrs, Vec::new())
}
#[test]
fn t_extractgroupmetadata_parses_a_valid_group_node() {
    let result = BinaryNode::with_nodes("iq", Attrs::from([("type", "result")]), vec![minimal_group_node(&[])]);
    let meta = extract_group_metadata(&result).unwrap();
    assert_eq!(meta.id, "120363000000000000@g.us");
    assert_eq!(meta.subject, "Test Group");
}
#[test]
fn t_extractgroupmetadata_keeps_the_suffix_when_group_id_already_contains_it() {
    let result = BinaryNode::with_nodes("iq", Attrs::from([("type", "result")]), vec![minimal_group_node(&[("id", "120363000000000000@g.us")])]);
    assert_eq!(extract_group_metadata(&result).unwrap().id, "120363000000000000@g.us");
}
#[test]
fn t_extractgroupmetadata_throws_boom_with_the_server_error_code_text_when_no_group_is_present() {
    let result = BinaryNode::with_nodes("iq", Attrs::from([("type", "error")]), vec![BinaryNode::tag("error", Attrs::from([("code", "403"), ("text", "forbidden")]))]);
    let captured = extract_group_metadata(&result).unwrap_err();
    assert_eq!(captured.output_status_code(), 403);
    assert_eq!(captured.message, "forbidden");
}
#[test]
fn t_extractgroupmetadata_falls_back_to_a_generic_boom_when_neither_group_nor_error_is_present() {
    let result = BinaryNode::with_nodes("iq", Attrs::from([("type", "result")]), Vec::new());
    assert!(extract_group_metadata(&result).unwrap_err().message.contains("missing <group>"));
}
#[test]
fn t_extractgroupmetadata_throws_when_the_group_node_lacks_an_id() {
    let mut group = minimal_group_node(&[]);
    group.attrs.remove("id");
    let result = BinaryNode::with_nodes("iq", Attrs::from([("type", "result")]), vec![group]);
    assert!(extract_group_metadata(&result).unwrap_err().message.contains("missing group id"));
}
#[test]
fn t_extractgroupmetadata_uses_default_code_500_when_error_has_no_code_attribute() {
    let result = BinaryNode::with_nodes("iq", Attrs::from([("type", "error")]), vec![BinaryNode::tag("error", Attrs::new())]);
    assert_eq!(extract_group_metadata(&result).unwrap_err().output_status_code(), 500);
}
