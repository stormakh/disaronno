//! Port of src/__tests__/Socket/chats.test.ts.
use baileys::socket::build_profile_picture_query_content;
use baileys::wabinary::{Attrs, BinaryNode, Content};

#[test]
fn t_buildprofilepicturequerycontent_builds_a_profile_picture_query_without_tctoken_content() {
    assert_eq!(build_profile_picture_query_content("preview", None), vec![BinaryNode::tag("picture", Attrs::from([("type", "preview"), ("query", "url")]))]);
}
#[test]
fn t_buildprofilepicturequerycontent_nests_tctoken_under_the_picture_node() {
    let tc_token = BinaryNode::with_bytes("tctoken", Attrs::from([("t", "1770000000")]), &[4u8, 1, 33][..]);
    let got = build_profile_picture_query_content("image", Some(vec![tc_token.clone()]));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].tag.as_str(), "picture");
    assert_eq!(got[0].attrs, Attrs::from([("type", "image"), ("query", "url")]));
    assert_eq!(got[0].content, Some(Content::Nodes(vec![tc_token])));
}
