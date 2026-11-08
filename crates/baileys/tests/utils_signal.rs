//! Port of Utils/signal.test.ts.
use baileys::error::Result;
use baileys::signal::repository::{E2ESession, SignalRepository};
use baileys::utils::signal::parse_and_inject_e2e_sessions;
use baileys::wabinary::{Attrs, BinaryNode};
use std::sync::Mutex;

#[derive(Default)]
struct MockRepository {
    jids: Mutex<Vec<String>>,
}
impl SignalRepository for MockRepository {
    fn inject_e2e_session(&self, jid: &str, _session: &E2ESession<'_>) -> Result<()> {
        self.jids.lock().unwrap().push(jid.to_string());
        Ok(())
    }
}
fn bytes(tag: &str, b: Vec<u8>) -> BinaryNode {
    BinaryNode::with_bytes(tag, Attrs::new(), b)
}
fn create_user_node(jid: &str) -> BinaryNode {
    BinaryNode::with_nodes(
        "user",
        Attrs::from([("jid", jid)]),
        vec![
            BinaryNode::with_nodes("skey", Attrs::new(), vec![bytes("id", vec![0, 0, 1]), bytes("value", vec![0; 33]), bytes("signature", vec![0; 64])]),
            BinaryNode::with_nodes("key", Attrs::new(), vec![bytes("id", vec![0, 0, 2]), bytes("value", vec![0; 33])]),
            bytes("identity", vec![0; 32]),
            bytes("registration", vec![0; 4]),
        ],
    )
}
#[test]
fn t_parseandinjecte2esessions_should_process_all_user_node() {
    let mock_repository = MockRepository::default();
    let mock_node = BinaryNode::with_nodes(
        "iq",
        Attrs::new(),
        vec![BinaryNode::with_nodes("list", Attrs::new(), vec![create_user_node("user1@s.whatsapp.net"), create_user_node("user2@s.whatsapp.net"), create_user_node("user3@s.whatsapp.net")])],
    );
    parse_and_inject_e2e_sessions(&mock_node, &mock_repository).unwrap();
    let jids = mock_repository.jids.lock().unwrap();
    assert_eq!(jids.len(), 3);
    assert!(jids.iter().any(|j| j == "user1@s.whatsapp.net"));
    assert!(jids.iter().any(|j| j == "user2@s.whatsapp.net"));
    assert!(jids.iter().any(|j| j == "user3@s.whatsapp.net"));
}
