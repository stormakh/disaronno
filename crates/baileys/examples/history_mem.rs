//! Local copy of a full history sync, for memory: runs the history chunks in target/tmp/hist through the same
//! inflate and process code as the socket, on short-lived threads like the lanes, and prints memory after each step.
//! `history_mem [nothp] [trim]`
use baileys::utils::history::download_and_process_history_sync_notification;
use baileys::types::RequestInit;
use waproto::message::HistorySyncNotification;

#[repr(C)]
#[derive(Default)]
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
    fn prctl(option: i32, ...) -> i32;
}
fn status(k: &str, file: &str) -> usize {
    let s = std::fs::read_to_string(file).unwrap();
    s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).unwrap_or(0)
}
fn report(step: &str) {
    // SAFETY: reads the allocator's counters only
    let m = unsafe { mallinfo2() };
    println!(
        "{step:<14} rss {:>6} kB anon {:>6} kB hugepages {:>6} kB | malloc in use {:>6} kB free {:>6} kB mmap {:>6} kB",
        status("VmRSS:", "/proc/self/status"),
        status("RssAnon:", "/proc/self/status"),
        status("AnonHugePages:", "/proc/self/smaps_rollup"),
        m.uordblks / 1024,
        m.fordblks / 1024,
        m.hblkhd / 1024
    );
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "nothp") {
        // SAFETY: changes only this process
        unsafe { prctl(41, 1u64, 0u64, 0u64, 0u64) };
    }
    let trim = args.iter().any(|a| a == "trim");
    report("start");
    let mut files: Vec<_> = std::fs::read_dir("target/tmp/hist").unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    if let Some(mode) = args.iter().find(|a| *a == "lane" || *a == "split").cloned() {
        // one long-lived lane for the whole sync, which keeps small copies, as the stores of the socket do
        std::thread::spawn(move || {
            let mut kept: Vec<String> = Vec::new();
            for f in &files {
                let note = HistorySyncNotification::default().with_initial_hist_bootstrap_inline_payload(std::fs::read(f).unwrap());
                let work = || download_and_process_history_sync_notification(&note, &RequestInit::default(), None).unwrap();
                let data = if mode == "split" { std::thread::scope(|s| s.spawn(work).join().unwrap()) } else { work() };
                for c in &data.chats {
                    kept.push(c.id().map_or("", |s| s.as_str()).to_string());
                }
                for m in data.messages.iter().step_by(64) {
                    kept.push(m.key().and_then(|k| k.id()).map_or("", |s| s.as_str()).to_string());
                }
            }
            report(&format!("{mode} end"));
            // SAFETY: gives free heap pages back, no other effect
            unsafe { malloc_trim(0) };
            report(&format!("{mode} trimmed"));
            println!("kept {} strings", kept.len());
        })
        .join()
        .unwrap();
        return;
    }
    let mut messages = 0;
    for (i, f) in files.iter().enumerate() {
        let payload = std::fs::read(f).unwrap();
        let n = std::thread::spawn(move || {
            let note = HistorySyncNotification::default().with_initial_hist_bootstrap_inline_payload(payload);
            let data = download_and_process_history_sync_notification(&note, &RequestInit::default(), None).unwrap();
            data.messages.len()
        })
        .join()
        .unwrap();
        messages += n;
        if trim {
            // SAFETY: gives free heap pages back, no other effect
            unsafe { malloc_trim(0) };
        }
        if i % 10 == 0 || i == files.len() - 1 {
            report(&format!("chunk {i}"));
        }
    }
    println!("{messages} messages");
    report("end");
    std::thread::sleep(std::time::Duration::from_secs(20));
    report("after 20 s");
    // SAFETY: gives free heap pages back, no other effect
    unsafe { malloc_trim(0) };
    report("after trim");
}
