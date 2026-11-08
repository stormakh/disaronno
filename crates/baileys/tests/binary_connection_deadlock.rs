//! Port of src/__tests__/binary/connection-deadlock.test.ts.
use baileys::defaults::default_connection_config;
use baileys::error::{Boom, Result};
use baileys::events::{BaileysEvent, BaileysEventEmitter, EventKind};
use baileys::socket::{Transport, make_wa_socket};
use baileys::types::*;
use baileys::utils::use_multi_file_auth_state::use_multi_file_auth_state;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use waproto::Message;

/// Same as `mockWebSocket`: it accepts every call and never sends a frame.
#[derive(Default)]
struct MockTransport {
    closed: Mutex<bool>,
    wake: Condvar,
}
impl Transport for MockTransport {
    fn connect(&self) -> Result<()> {
        Ok(())
    }
    fn send(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    fn recv(&self) -> Result<Option<Vec<u8>>> {
        let mut closed = self.closed.lock().unwrap();
        while !*closed {
            closed = self.wake.wait(closed).unwrap();
        }
        Ok(None)
    }
    fn close(&self) {
        *self.closed.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
fn mock_config() -> SocketConfig {
    let mut config = default_connection_config();
    config.make_transport = Some(Arc::new(|_: &SocketConfig| Ok(Arc::new(MockTransport::default()) as Arc<dyn Transport>)));
    config
}
#[test]
fn t_connection_deadlock_test_should_not_deadlock_when_history_sync_is_disabled() {
    let dir = std::env::temp_dir().join(format!("baileys-test-session-deadlock-{}", std::process::id()));
    let auth = use_multi_file_auth_state(&dir).unwrap();
    auth.state.creds.lock().unwrap().me = Some(Contact { id: "1234567890:1@s.whatsapp.net".to_string(), name: Some("Test User".to_string()), ..Contact::default() });
    let mut config = mock_config();
    config.auth = Some(auth.state.clone());
    config.should_sync_history_message = Arc::new(|_| false);
    let sock = make_wa_socket(config).unwrap();
    let calls: Arc<Mutex<Vec<MessagesUpsert>>> = Arc::default();
    let recorded = calls.clone();
    sock.ev.on(
        EventKind::MessagesUpsert,
        Arc::new(move |e: &BaileysEvent| {
            if let BaileysEvent::MessagesUpsert(u) = e {
                recorded.lock().unwrap().push(u.clone());
            }
        }),
    );
    sock.connect();
    // 1. Simulate receiving pending notifications. This activates the buffer.
    sock.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { received_pending_notifications: Some(true), ..ConnectionState::default() }));
    // 2. Now, emit a regular message. Because the previous step should have
    // flushed the buffer, this message should be processed immediately.
    let key = WAMessageKey::default().with_remote_jid("1234567890@s.whatsapp.net").with_from_me(false).with_id("REGULAR_MSG_1");
    let regular_message = WAMessage::default().with_key(key.clone()).with_message_timestamp(baileys::utils::time::unix_timestamp_seconds() as u64).with_message(Message::default().with_conversation("Hello, world!"));
    sock.ev.emit(BaileysEvent::MessagesUpsert(MessagesUpsert { messages: vec![regular_message], r#type: MessageUpsertType::Notify, request_id: None }));
    // Wait for the event loop to process any final events.
    std::thread::sleep(Duration::from_millis(50));
    // 3. Check if the regular message listener was called.
    let got = calls.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].r#type, MessageUpsertType::Notify);
    assert!(got[0].messages.iter().any(|m| m.key() == Some(&key)));
    sock.end(Some(Boom::new("Test completed")));
    std::fs::remove_dir_all(&dir).unwrap();
}
