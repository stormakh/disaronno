//! Tool for `scripts/live-test.mjs`: runs one socket against the real server and prints counts on stdout, one JSON
//! object per line. It never prints message text, names or numbers. `stop` on stdin logs out, which unlinks the device.
use baileys::defaults::default_connection_config;
use baileys::events::{BaileysEvent, BaileysEventEmitter, EventKind};
use baileys::socket::{Socket, make_wa_socket};
use baileys::types::DisconnectReason;
use baileys::utils::use_multi_file_auth_state::{MultiFileAuthState, use_multi_file_auth_state};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use waproto::pb::Json;

fn out(fields: Vec<(&str, Json)>) {
    let line = Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect()).stringify();
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(line.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}
fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}
fn n(v: usize) -> Json {
    Json::Num(v as f64)
}
#[repr(C)]
struct MallInfo2 {
    arena: usize,
    ordblks: usize,
    smblks: usize,
    hblks: usize,
    hblkhd: usize,
    usmblks: usize,
    fsmblks: usize,
    uordblks: usize,
    fordblks: usize,
    keepcost: usize,
}
unsafe extern "C" {
    fn mallinfo2() -> MallInfo2;
    fn malloc_trim(pad: usize) -> i32;
}
/// `mem` on stdin: the allocator's own counts, so that memory in use can be told from free memory it keeps.
fn mem(step: &str) {
    // SAFETY: reads the allocator's counters only
    let m = unsafe { mallinfo2() };
    let kb = |v: usize| n(v / 1024);
    out(vec![("ev", s("mem")), ("step", s(step)), ("heapKb", kb(m.arena)), ("usedKb", kb(m.uordblks)), ("freeKb", kb(m.fordblks)), ("mmapKb", kb(m.hblkhd)), ("mmaps", n(m.hblks))]);
}
fn trim() {
    // SAFETY: gives free heap pages back to the system, no other effect
    unsafe { malloc_trim(0) };
}
fn run_once(auth: &Arc<MultiFileAuthState>, current: &Arc<Mutex<Option<Socket>>>) -> Option<u16> {
    let mut config = default_connection_config();
    config.auth = Some(auth.state.clone());
    config.mark_online_on_connect = false;
    config.sync_full_history = true;
    config.should_sync_history_message = Arc::new(|_| true);
    let sock = make_wa_socket(config).expect("the config must be valid");
    let saver = auth.clone();
    sock.ev.on(EventKind::CredsUpdate, Arc::new(move |_: &BaileysEvent| saver.save_creds().expect("creds must save")));
    let (closed, wait) = mpsc::channel();
    sock.ev.on(
        EventKind::ConnectionUpdate,
        Arc::new(move |e: &BaileysEvent| {
            let BaileysEvent::ConnectionUpdate(u) = e else { return };
            if let Some(Some(qr)) = &u.qr {
                out(vec![("ev", s("qr")), ("qr", s(qr))]);
            }
            if let Some(c) = u.connection {
                out(vec![("ev", s("conn")), ("state", s(c.as_str()))]);
                if c.as_str() == "close" {
                    let code = u.last_disconnect.as_ref().and_then(|d| d.error.as_ref()).map(|err| err.output_status_code());
                    let _ = closed.send(code);
                }
            }
        }),
    );
    sock.ev.on(
        EventKind::MessagingHistorySet,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::MessagingHistorySet(h) = e else { return };
            let mut f = vec![("ev", s("history")), ("chats", n(h.chats.len())), ("contacts", n(h.contacts.len())), ("messages", n(h.messages.len()))];
            if let Some(Some(p)) = h.progress {
                f.push(("progress", Json::Num(p)));
            }
            if let Some(l) = h.is_latest {
                f.push(("isLatest", Json::Bool(l)));
            }
            if let Some(Some(t)) = &h.sync_type {
                f.push(("syncType", Json::Num(t.0 as f64)));
            }
            out(f);
        }),
    );
    sock.ev.on(
        EventKind::MessagesUpsert,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::MessagesUpsert(u) = e else { return };
            out(vec![("ev", s("upsert")), ("messages", n(u.messages.len()))]);
        }),
    );
    *current.lock().unwrap() = Some(sock.clone());
    sock.connect();
    let code = wait.recv().unwrap_or(None);
    sock.end(None);
    code
}
fn main() {
    let folder = std::env::args().nth(1).expect("an auth folder");
    let auth = Arc::new(use_multi_file_auth_state(folder).expect("the auth folder must be usable"));
    let current: Arc<Mutex<Option<Socket>>> = Arc::new(Mutex::new(None));
    let stopper = current.clone();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap_or_default();
            match line.trim() {
                "mem" => mem("now"),
                "trim" => {
                    trim();
                    mem("trimmed");
                }
                "stop" => {
                    let sock = stopper.lock().unwrap().clone();
                    let logged_out = sock.is_some_and(|sock| sock.logout(None).is_ok());
                    out(vec![("ev", s("stopped")), ("loggedOut", Json::Bool(logged_out))]);
                    // with the socket gone, what is left belongs to the auth state or is not freed
                    std::thread::sleep(Duration::from_secs(2));
                    stopper.lock().unwrap().take();
                    std::thread::sleep(Duration::from_secs(1));
                    trim();
                    mem("no socket");
                    // time for the runner to read this process's memory
                    std::thread::sleep(Duration::from_millis(500));
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    });
    for _ in 0..50 {
        let code = run_once(&auth, &current);
        out(vec![("ev", s("closed")), ("code", code.map_or(Json::Null, |c| Json::Num(c as f64)))]);
        // a new login asks for this restart, and a QR that was not scanned or a lost connection connects again
        if [DisconnectReason::LOGGED_OUT.0, DisconnectReason::FORBIDDEN.0, DisconnectReason::CONNECTION_REPLACED.0].iter().any(|c| Some(*c) == code) {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    // the `stop` thread reports the logout, which closes this socket first
    std::thread::sleep(Duration::from_secs(6));
    std::process::exit(1);
}
