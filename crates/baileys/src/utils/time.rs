//! Clock helpers and `setTimeout`.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
pub fn unix_timestamp_seconds() -> i64 {
    now_ms() / 1000
}
/// Same text as `new Date(ms).toJSON()`.
pub fn iso_time(ms: i64) -> String {
    let (secs, millis) = (ms.div_euclid(1000), ms.rem_euclid(1000));
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

struct Entry {
    cancelled: Arc<AtomicBool>,
    task: Box<dyn FnOnce() + Send>,
}
#[derive(Default)]
struct Queue {
    next_seq: u64,
    /// Sorted by due time. The sequence number keeps equal times apart.
    entries: BTreeMap<(Instant, u64), Entry>,
}
struct Timers {
    queue: Mutex<Queue>,
    wake: Condvar,
}
fn timers() -> &'static Timers {
    static T: OnceLock<&'static Timers> = OnceLock::new();
    T.get_or_init(|| {
        let t: &'static Timers = Box::leak(Box::new(Timers { queue: Mutex::new(Queue::default()), wake: Condvar::new() }));
        // the timer thread only waits, and runs no task itself
        let _ = std::thread::Builder::new().name("wa-timers".to_string()).stack_size(TIMER_STACK).spawn(move || timer_loop(t));
        t
    })
}
/// Each task runs on its own thread, so a slow listener does not delay other timers.
fn timer_loop(t: &'static Timers) {
    let mut q = t.queue.lock().unwrap();
    loop {
        let now = Instant::now();
        match q.entries.keys().next().copied() {
            None => q = t.wake.wait(q).unwrap(),
            Some((at, _)) if at > now => q = t.wake.wait_timeout(q, at - now).unwrap().0,
            Some(k) => {
                if let Some(e) = q.entries.remove(&k) {
                    if !e.cancelled.load(Ordering::Acquire) {
                        let _ = std::thread::Builder::new().name("wa-timer-task".to_string()).stack_size(THREAD_STACK).spawn(e.task);
                    }
                }
            }
        }
    }
}
/// Handle from `set_timeout`. Dropping it does not cancel the timer.
#[derive(Clone)]
pub struct Timeout(Arc<AtomicBool>);
impl Timeout {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}
/// Stack of a thread that runs handlers and listeners. Only the pages in use count as memory, so
/// this limits address space, not resident memory. The whole end-to-end flow passes in a release
/// build with half of this. A debug build has much larger stack frames.
pub const THREAD_STACK: usize = if cfg!(debug_assertions) { 1024 * 1024 } else { 128 * 1024 };
const TIMER_STACK: usize = 64 * 1024;
/// Runs `task` once on a background thread after `ms` milliseconds.
pub fn set_timeout(ms: u64, task: impl FnOnce() + Send + 'static) -> Timeout {
    let cancelled = Arc::new(AtomicBool::new(false));
    let t = timers();
    let mut q = t.queue.lock().unwrap();
    q.next_seq += 1;
    let key = (Instant::now() + Duration::from_millis(ms), q.next_seq);
    q.entries.insert(key, Entry { cancelled: cancelled.clone(), task: Box::new(task) });
    drop(q);
    t.wake.notify_one();
    Timeout(cancelled)
}
