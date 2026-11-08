//! Rust side of the frozen benchmark. Does the same work as bench/node/bench.mjs. Run from the repo root.
use baileys::auth::*;
use baileys::crypto;
use baileys::defaults::MediaType;
use baileys::proto::pb::PbMessage;
use baileys::proto::sync_action_value::MuteAction;
use baileys::proto::syncd_mutation::SyncdOperation;
use baileys::proto::{SyncActionValue, SyncdVersion};
use baileys::signal::repository::*;
use baileys::types::chat::{WAPatchCreate, WAPatchName};
use baileys::utils::chat_utils::{decode_syncd_patch, encode_syncd_patch, new_lt_hash_state};
use baileys::types::WAMediaUpload;
use baileys::utils::held_message::HeldMessage;
use baileys::utils::lt_hash::subtract_then_add;
use baileys::utils::messages_media::{EncryptedStreamOptions, encrypted_stream};
use baileys::utils::noise::{Frame, NoiseHandler};
use baileys::wabinary::*;
use std::sync::Arc;
use std::time::Instant;


/// Two process settings, for peak memory and speed. Any binary that links this library can do the same.
/// Transparent huge pages add about 20% to RSS, in steps of 2 MB that depend on how much free memory the system has,
/// and give no measurable speed here. Without a high trim threshold, malloc gives the heap back after each large
/// free, and history_decode takes twice as long. This runs before the first allocation.
#[cfg(all(feature = "native", target_os = "linux"))]
#[used]
#[unsafe(link_section = ".preinit_array")]
static PROCESS_SETTINGS: extern "C" fn() = {
    const PR_SET_THP_DISABLE: i32 = 41;
    const M_TRIM_THRESHOLD: i32 = -1;
    unsafe extern "C" {
        fn prctl(option: i32, ...) -> i32;
        fn mallopt(param: i32, value: i32) -> i32;
    }
    extern "C" fn set() {
        // SAFETY: prctl takes four more integer arguments for this option, and both calls touch only this process.
        unsafe {
            prctl(PR_SET_THP_DISABLE, 1u64, 0u64, 0u64, 0u64);
            mallopt(M_TRIM_THRESHOLD, 64 << 20);
        }
    }
    set
};

fn fixture(n: &str) -> Vec<u8> {
    std::fs::read(format!("bench/fixtures/{n}")).expect("run bench/node/bench.mjs first")
}
fn prng(seed: &str, n: usize) -> Vec<u8> {
    let mut o = Vec::with_capacity(n + 32);
    let mut h = crypto::sha256(seed.as_bytes());
    while o.len() < n {
        o.extend_from_slice(&h);
        h = crypto::sha256(&h);
    }
    o.truncate(n);
    o
}
fn timed(name: &str, f: &mut dyn FnMut()) {
    let mut samples = Vec::new();
    for b in 0..6 {
        let t = Instant::now();
        let mut ops = 0u64;
        loop {
            f();
            ops += 1;
            if ops % 16 == 0 && t.elapsed().as_secs_f64() >= 1.0 {
                break;
            }
        }
        if b > 0 {
            samples.push(ops as f64 / t.elapsed().as_secs_f64());
        }
    }
    samples.sort_by(|a, b| a.total_cmp(b));
    println!("{name} {:.1}", samples[samples.len() / 2]);
}
const ALICE: &str = "1111@s.whatsapp.net";
const BOB: &str = "2222@s.whatsapp.net";
const GROUP: &str = "1203630@g.us";
struct Party {
    creds: SignalCreds,
    keys: Arc<MemoryKeyStore>,
    repo: LibSignalRepository,
}
fn party() -> Party {
    let id = crypto::generate_key_pair();
    let creds = SignalCreds { signed_pre_key: crypto::signed_key_pair(&id, 1), signed_identity_key: id, registration_id: 1234 };
    let keys = Arc::new(MemoryKeyStore::new());
    let repo = LibSignalRepository::new(creds.clone(), keys.clone(), None);
    Party { creds, keys, repo }
}
fn pair() -> (Party, Party) {
    let (a, b) = (party(), party());
    let pk = crypto::generate_key_pair();
    b.keys.set_one(KeyKind::PreKey, "1", Some(KeyValue::PreKey(pk.clone()))).unwrap();
    inject(&a, &b, BOB, &pk);
    (a, b)
}
fn inject(a: &Party, b: &Party, jid: &str, pk: &crypto::KeyPair) {
    let id = crypto::generate_signal_pub_key(&b.creds.signed_identity_key.public);
    let spk = crypto::generate_signal_pub_key(&b.creds.signed_pre_key.key_pair.public);
    let ppk = crypto::generate_signal_pub_key(&pk.public);
    a.repo
        .inject_e2e_session(
            jid,
            &E2ESession {
                registration_id: b.creds.registration_id,
                identity_key: &id,
                signed_pre_key: SignedPreKeyPub { key_id: b.creds.signed_pre_key.key_id, public_key: &spk, signature: &b.creds.signed_pre_key.signature },
                pre_key: Some(PreKeyPub { key_id: 1, public_key: &ppk }),
            },
        )
        .unwrap();
}
fn pad(m: &[u8]) -> Vec<u8> {
    let mut o = m.to_vec();
    o.push(1);
    o
}
fn vm_status() -> String {
    let st = std::fs::read_to_string("/proc/self/status").unwrap();
    let get = |k: &str| st.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).unwrap().to_string();
    format!("\"VmHWM_kB\":{},\"VmRSS_kB\":{}", get("VmHWM"), get("VmRSS"))
}
fn memory() {
    let (a, b) = (party(), party());
    let pk = crypto::generate_key_pair();
    for i in 0..1000 {
        inject(&a, &b, &format!("{}@s.whatsapp.net", 10000 + i), &pk);
    }
    let wmi = fixture("wmi.bin");
    let mut held = Vec::with_capacity(10000);
    for _ in 0..10000 {
        // each message owns its copy, as Node's decode does
        held.push(baileys::proto::WebMessageInfo::decode(&wmi).unwrap());
    }
    println!("{{{},\"held\":{}}}", vm_status(), held.len());
    std::process::exit(0);
}
/// A separate measure from `memory`: the same sessions, with each message held as its own checked bytes.
fn memory_compact() {
    let (a, b) = (party(), party());
    let pk = crypto::generate_key_pair();
    for i in 0..1000 {
        inject(&a, &b, &format!("{}@s.whatsapp.net", 10000 + i), &pk);
    }
    let wmi = fixture("wmi.bin");
    let mut held = Vec::with_capacity(10000);
    for _ in 0..10000 {
        held.push(HeldMessage::new(&wmi).unwrap());
    }
    println!("{{{},\"held\":{}}}", vm_status(), held.len());
    assert!(held.iter().all(|m| m.read().unwrap().encode() == wmi));
    std::process::exit(0);
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("speed");
    if mode == "startup" {
        return;
    }
    if mode == "idle" {
        // the library is linked in, and this touches it so that the linker keeps it
        std::hint::black_box(crypto::generate_key_pair());
        println!("{{{}}}", vm_status());
        return;
    }
    if mode == "memory" {
        memory();
    }
    if mode == "memory-compact" {
        memory_compact();
    }
    let only = args.get(2).cloned();
    let on = |n: &str| only.as_deref().is_none_or(|o| o == n);
    let stanza_bytes = fixture("stanza.bin");
    let stanza = decode_binary_node(&stanza_bytes).unwrap();
    assert_eq!(encode_binary_node(&stanza).unwrap(), stanza_bytes, "node codec must match Baileys bytes");
    if on("binary_encode") {
        timed("binary_encode", &mut || {
            std::hint::black_box(encode_binary_node(&stanza).unwrap());
        });
    }
    if on("binary_decode") {
        timed("binary_decode", &mut || {
            std::hint::black_box(decode_binary_node(&stanza_bytes).unwrap());
        });
    }
    let wmi_bytes = fixture("wmi.bin");
    let wmi = baileys::proto::WebMessageInfo::decode(&wmi_bytes).unwrap();
    assert_eq!(wmi.encode(), wmi_bytes, "proto codec must match Baileys bytes");
    if on("proto_encode") {
        timed("proto_encode", &mut || {
            std::hint::black_box(wmi.encode());
        });
    }
    if on("proto_decode") {
        timed("proto_decode", &mut || {
            std::hint::black_box(baileys::proto::WebMessageInfo::decode(&wmi_bytes).unwrap());
        });
    }
    let hist_z = fixture("history.bin");
    let hist_raw = {
        use std::io::Read;
        let mut o = Vec::new();
        flate2::read::ZlibDecoder::new(&hist_z[..]).read_to_end(&mut o).unwrap();
        o
    };
    if on("history_decode") {
        timed("history_decode", &mut || {
            std::hint::black_box(baileys::proto::HistorySync::decode(&hist_raw).unwrap());
        });
    }
    let lt: Vec<Vec<u8>> = (0..64).map(|i| prng(&format!("lt{i}"), 32)).collect();
    let lt_refs: Vec<&[u8]> = lt.iter().map(|v| v.as_slice()).collect();
    let base = vec![0u8; 128];
    if on("lthash_64") {
        timed("lthash_64", &mut || {
            std::hint::black_box(subtract_then_add(&base, &lt_refs, &[]));
        });
    }
    if on("media_encrypt_1mb") {
        let media = WAMediaUpload::Buffer(prng("media", 1 << 20).into());
        let options = EncryptedStreamOptions::default();
        timed("media_encrypt_1mb", &mut || {
            let r = encrypted_stream(&media, MediaType::Image, &options).unwrap();
            let _ = std::fs::remove_file(&r.enc_file_path);
        });
    }
    if on("curve_sign") {
        let k = crypto::generate_key_pair();
        timed("curve_sign", &mut || {
            std::hint::black_box(crypto::sign(&k.private, lt_refs[0]));
        });
    }
    if on("curve_agree") {
        let (a, b) = (crypto::generate_key_pair(), crypto::generate_key_pair());
        timed("curve_agree", &mut || {
            std::hint::black_box(crypto::shared_key(&a.private, &b.public).unwrap());
        });
    }
    if on("signal_roundtrip") {
        let (a, b) = pair();
        let data = pad("hello world".repeat(10).as_bytes());
        timed("signal_roundtrip", &mut || {
            let e = a.repo.encrypt_message(BOB, &data).unwrap();
            std::hint::black_box(b.repo.decrypt_message(ALICE, e.msg_type, &e.ciphertext).unwrap());
        });
    }
    if on("group_roundtrip") {
        let (a, b) = (party(), party());
        let skdm = a.repo.get_sender_key_distribution_message(GROUP, ALICE).unwrap();
        b.repo.process_sender_key_distribution_message(Some(GROUP), &skdm, ALICE).unwrap();
        let data = pad("hello world".repeat(10).as_bytes());
        timed("group_roundtrip", &mut || {
            let e = a.repo.encrypt_group_message(GROUP, ALICE, &data).unwrap();
            std::hint::black_box(b.repo.decrypt_group_message(GROUP, ALICE, &e.ciphertext).unwrap());
        });
    }
    if on("appstate_roundtrip") {
        let key_data = prng("appstate", 32);
        let key_id = baileys::proto::pb::base64_encode(&prng("keyid", 6));
        let key = baileys::proto::message::AppStateSyncKeyData::new().with_key_data(key_data);
        let get = |_: &str| Ok(Some(key.clone()));
        let create = WAPatchCreate {
            r#type: WAPatchName::Regular,
            index: vec!["mute".to_string(), "1555@s.whatsapp.net".to_string()],
            api_version: 2,
            operation: SyncdOperation::SET,
            sync_action: SyncActionValue::new().with_timestamp(1700000000i64).with_mute_action(MuteAction::new().with_muted(true).with_mute_end_timestamp(1700000100i64)),
        };
        let mut state = new_lt_hash_state();
        timed("appstate_roundtrip", &mut || {
            let encoded = encode_syncd_patch(&create, &key_id, &state, &get).unwrap();
            state = encoded.state;
            let version = state.version;
            state.index_value_map.clear();
            let patch = encoded.patch.with_version(SyncdVersion::new().with_version(version));
            std::hint::black_box(decode_syncd_patch(&patch, WAPatchName::Regular, &new_lt_hash_state(), &get, &mut |_| {}, false).unwrap());
        });
    }
    if on("receive_pipeline") {
        let (a, b) = pair();
        let k = crypto::generate_key_pair();
        let mut noise = NoiseHandler::new(&k, &[87, 65, 6, 3], None);
        noise.finish_init();
        let dec = crypto::hkdf(&[], 64, Some(baileys::utils::noise::NOISE_MODE), b"")[32..].to_vec();
        let msg = baileys::proto::Message::new().with_extended_text_message(baileys::proto::message::ExtendedTextMessage::new().with_text("x".repeat(200))).encode();
        let mut wc = 0u32;
        let mut samples = Vec::new();
        for batch in 0..6 {
            let mut q = Vec::with_capacity(20000);
            for i in 0..20000 {
                let e = a.repo.encrypt_message(BOB, &pad(&msg)).unwrap();
                let node = BinaryNode::with_nodes("message", Attrs::from([("from", ALICE.to_string()), ("id", format!("M{i}")), ("t", "1700000000".to_string()), ("type", "text".to_string())]), vec![BinaryNode::with_bytes("enc", Attrs::from([("v", "2"), ("type", e.msg_type)]), e.ciphertext)]);
                let plain = encode_binary_node(&node).unwrap();
                let mut iv = [0u8; 12];
                iv[8..].copy_from_slice(&wc.to_be_bytes());
                wc += 1;
                let ct = crypto::aes_encrypt_gcm(&plain, &dec, &iv, &[]).unwrap();
                let mut fr = (ct.len() as u32).to_be_bytes()[1..].to_vec();
                fr.extend_from_slice(&ct);
                q.push(fr);
            }
            let t = Instant::now();
            for fr in &q {
                let mut node = None;
                noise.decode_frame(fr, &mut |f| {
                    if let Frame::Node(n) = f {
                        node = Some(n);
                    }
                })
                .unwrap();
                let node = node.unwrap();
                let enc = &get_all_binary_node_children(&node)[0];
                let Some(Content::Binary(c)) = &enc.content else { panic!("no ciphertext") };
                let pt = b.repo.decrypt_message(node.attr("from").unwrap(), enc.attr("type").unwrap(), c.as_slice()).unwrap();
                let n = pt.len() - pt[pt.len() - 1] as usize;
                std::hint::black_box(baileys::proto::Message::decode(&pt[..n]).unwrap());
            }
            if batch > 0 {
                samples.push(q.len() as f64 / t.elapsed().as_secs_f64());
            }
        }
        samples.sort_by(|a, b| a.total_cmp(b));
        println!("receive_pipeline {:.1}", samples[samples.len() / 2]);
    }
    // not part of the 13 frozen workloads: the cost of the compact form of `memory-compact`
    if on("compact_hold") {
        timed("compact_hold", &mut || {
            std::hint::black_box(HeldMessage::new(&wmi_bytes).unwrap());
        });
    }
    if on("compact_read") {
        let held = HeldMessage::new(&wmi_bytes).unwrap();
        timed("compact_read", &mut || {
            std::hint::black_box(held.read().unwrap());
        });
    }
}
