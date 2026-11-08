//! Same behavior as Utils/make-mutex.ts: tasks run one at a time, first come first served.
use rustc_hash::FxHashMap;
use std::sync::{Arc, Condvar, Mutex as StdMutex};

#[derive(Default)]
struct Tickets {
    next: u64,
    serving: u64,
}
/// A ticket lock, so waiters run in arrival order. It is not reentrant, as `async-mutex` is not.
#[derive(Default)]
pub struct FifoMutex {
    tickets: StdMutex<Tickets>,
    released: Condvar,
}
struct Release<'a>(&'a FifoMutex);
impl Drop for Release<'_> {
    fn drop(&mut self) {
        let mut t = match self.0.tickets.lock() {
            Ok(t) => t,
            Err(e) => e.into_inner(),
        };
        t.serving += 1;
        drop(t);
        self.0.released.notify_all();
    }
}
impl FifoMutex {
    pub fn new() -> FifoMutex {
        FifoMutex::default()
    }
    pub fn is_locked(&self) -> bool {
        let t = self.tickets.lock().unwrap();
        t.next != t.serving
    }
    pub fn run_exclusive<T>(&self, code: impl FnOnce() -> T) -> T {
        let mut t = self.tickets.lock().unwrap();
        let ticket = t.next;
        t.next += 1;
        while t.serving != ticket {
            t = self.released.wait(t).unwrap();
        }
        drop(t);
        let _release = Release(self);
        code()
    }
}
#[derive(Default)]
pub struct Mutex(FifoMutex);
impl Mutex {
    pub fn mutex<T>(&self, code: impl FnOnce() -> T) -> T {
        self.0.run_exclusive(code)
    }
}
pub fn make_mutex() -> Mutex {
    Mutex::default()
}
struct KeyedEntry {
    mutex: Arc<FifoMutex>,
    ref_count: u32,
}
/// One FIFO queue per key. A key's entry is removed when nobody uses it.
#[derive(Default)]
pub struct KeyedMutex {
    map: StdMutex<FxHashMap<String, KeyedEntry>>,
}
impl KeyedMutex {
    pub fn mutex<T>(&self, key: &str, task: impl FnOnce() -> T) -> T {
        let mutex = {
            let mut map = self.map.lock().unwrap();
            let entry = map.entry(key.to_string()).or_insert_with(|| KeyedEntry { mutex: Arc::new(FifoMutex::new()), ref_count: 0 });
            entry.ref_count += 1;
            entry.mutex.clone()
        };
        let _unref = KeyedUnref(self, key);
        mutex.run_exclusive(task)
    }
    /// Number of keys in use, for checks that entries do not leak.
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
struct KeyedUnref<'a>(&'a KeyedMutex, &'a str);
impl Drop for KeyedUnref<'_> {
    fn drop(&mut self) {
        let mut map = match self.0.map.lock() {
            Ok(m) => m,
            Err(e) => e.into_inner(),
        };
        if let Some(e) = map.get_mut(self.1) {
            e.ref_count -= 1;
            if e.ref_count == 0 {
                map.remove(self.1);
            }
        }
    }
}
pub fn make_keyed_mutex() -> KeyedMutex {
    KeyedMutex::default()
}
