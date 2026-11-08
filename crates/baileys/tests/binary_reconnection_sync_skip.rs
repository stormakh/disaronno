//! Port of src/__tests__/binary/reconnection-sync-skip.test.ts.
use baileys::defaults::default_connection_config;
use baileys::error::{Boom, Result};
use baileys::events::{BaileysEvent, BaileysEventEmitter, EventKind};
use baileys::socket::{Socket, Transport, make_wa_socket};
use baileys::types::*;
use baileys::utils::use_multi_file_auth_state::{MultiFileAuthState, use_multi_file_auth_state};
use std::path::PathBuf;
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
struct Session {
    dir: PathBuf,
    auth: MultiFileAuthState,
}
fn make_session(name: &str) -> Session {
    let dir = std::env::temp_dir().join(format!("baileys-test-session-{name}-{}", std::process::id()));
    let auth = use_multi_file_auth_state(&dir).unwrap();
    Session { dir, auth }
}
type Calls = Arc<Mutex<Vec<MessagesUpsert>>>;
fn start_socket(session: &Session) -> (Socket, Calls) {
    let mut config = default_connection_config();
    config.auth = Some(session.auth.state.clone());
    config.make_transport = Some(Arc::new(|_: &SocketConfig| Ok(Arc::new(MockTransport::default()) as Arc<dyn Transport>)));
    let sock = make_wa_socket(config).unwrap();
    let calls: Calls = Arc::default();
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
    (sock, calls)
}
fn emit_pending_then_message(sock: &Socket, id: &str, text: &str) -> WAMessageKey {
    // Simulate receiving pending notifications (triggers AwaitingInitialSync)
    sock.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { received_pending_notifications: Some(true), ..ConnectionState::default() }));
    let key = WAMessageKey::default().with_remote_jid("1234567890@s.whatsapp.net").with_from_me(false).with_id(id);
    let msg = WAMessage::default().with_key(key.clone()).with_message_timestamp(baileys::utils::time::unix_timestamp_seconds() as u64).with_message(Message::default().with_conversation(text));
    sock.ev.emit(BaileysEvent::MessagesUpsert(MessagesUpsert { messages: vec![msg], r#type: MessageUpsertType::Notify, request_id: None }));
    key
}
#[test]
fn t_reconnection_sync_skip_should_skip_20s_history_sync_wait_on_reconnection_accountsynccounter_0() {
    let session = make_session("reconnect");
    {
        let mut c = session.auth.state.creds.lock().unwrap();
        c.me = Some(Contact { id: "1234567890:1@s.whatsapp.net".to_string(), name: Some("Test User".to_string()), ..Contact::default() });
        // Simulate a session that has already synced before
        c.account_sync_counter = 1;
    }
    let (sock, calls) = start_socket(&session);
    // Emit a message immediately after — if the 20s wait is skipped,
    // the buffer should already be flushed and this message should be delivered.
    let key = emit_pending_then_message(&sock, "MSG_AFTER_RECONNECT", "Hello after reconnect");
    std::thread::sleep(Duration::from_millis(50));
    // Message should be delivered immediately, NOT buffered for 20s
    let got = calls.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].r#type, MessageUpsertType::Notify);
    assert!(got[0].messages.iter().any(|m| m.key() == Some(&key)));
    sock.end(Some(Boom::new("Test completed")));
    std::fs::remove_dir_all(&session.dir).unwrap();
}
#[test]
fn t_reconnection_sync_skip_should_still_wait_for_history_sync_on_fresh_pairing_accountsynccounter_0() {
    let session = make_session("fresh");
    {
        let mut c = session.auth.state.creds.lock().unwrap();
        c.me = Some(Contact { id: "1234567890:1@s.whatsapp.net".to_string(), name: Some("Test User".to_string()), ..Contact::default() });
        // Fresh pairing — accountSyncCounter is 0 (default)
        c.account_sync_counter = 0;
    }
    let (sock, calls) = start_socket(&session);
    // Emit a message immediately
    emit_pending_then_message(&sock, "MSG_DURING_INITIAL_SYNC", "Hello during initial sync");
    std::thread::sleep(Duration::from_millis(50));
    // Message should be BUFFERED (not delivered) because we're waiting for history sync
    assert_eq!(calls.lock().unwrap().len(), 0);
    sock.end(Some(Boom::new("Test completed")));
    std::fs::remove_dir_all(&session.dir).unwrap();
}
