//! Connects, prints the QR, and keeps the login with `use_multi_file_auth_state`.
//!
//! `cargo run -p baileys --example connect -- <auth folder>`
//!
//! By default this connects to the real WhatsApp servers. Set `WA_URL` and `WA_ROOT_KEY` (hex) to
//! use a test server, such as `scripts/mock-server.mjs`.
use baileys::defaults::default_connection_config;
use baileys::events::{BaileysEvent, BaileysEventEmitter, EventKind};
use baileys::socket::make_wa_socket;
use baileys::types::{DisconnectReason, WAConnectionState};
use baileys::utils::use_multi_file_auth_state::{MultiFileAuthState, use_multi_file_auth_state};
use std::sync::{Arc, mpsc};

fn main() {
    let folder = std::env::args().nth(1).unwrap_or_else(|| "baileys_auth_info".to_string());
    let auth = Arc::new(use_multi_file_auth_state(folder).expect("the auth folder must be usable"));
    loop {
        let code = run_once(&auth);
        println!("connection closed: {code:?}");
        // the server asks for this restart after a new login. A logout needs a new login.
        if code != Some(DisconnectReason::RESTART_REQUIRED.0) {
            return;
        }
    }
}

fn run_once(auth: &Arc<MultiFileAuthState>) -> Option<u16> {
    let mut config = default_connection_config();
    config.auth = Some(auth.state.clone());
    if let Ok(url) = std::env::var("WA_URL") {
        config.wa_web_socket_url = url;
    }
    if let Ok(hex) = std::env::var("WA_ROOT_KEY") {
        for (i, b) in config.wa_cert_public_key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("WA_ROOT_KEY must be hex");
        }
    }
    let sock = make_wa_socket(config).expect("the config must be valid");

    let saver = auth.clone();
    sock.ev.on(EventKind::CredsUpdate, Arc::new(move |_: &BaileysEvent| saver.save_creds().expect("creds must save")));

    let (closed, wait) = mpsc::channel();
    sock.ev.on(
        EventKind::ConnectionUpdate,
        Arc::new(move |e: &BaileysEvent| {
            let BaileysEvent::ConnectionUpdate(u) = e else { return };
            if let Some(Some(qr)) = &u.qr {
                println!("QR: {qr}");
            }
            match u.connection {
                Some(WAConnectionState::Open) => println!("connected"),
                Some(WAConnectionState::Close) => {
                    let code = u.last_disconnect.as_ref().and_then(|d| d.error.as_ref()).and_then(|err| err.status_code);
                    let _ = closed.send(code);
                }
                _ => {}
            }
        }),
    );
    sock.ev.on(
        EventKind::MessagesUpsert,
        Arc::new(|e: &BaileysEvent| {
            if let BaileysEvent::MessagesUpsert(u) = e {
                println!("got {} message(s), type {}", u.messages.len(), u.r#type.as_str());
            }
        }),
    );
    sock.connect();
    let code = wait.recv().unwrap_or(None);
    sock.end(None);
    code
}
