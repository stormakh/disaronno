//! Small TTL cache in place of `@cacheable/node-cache`, with `useClones: false`.
use crate::types::{CacheStore, CacheValue};
use crate::utils::time::now_ms;
use rustc_hash::FxHashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

/// How often a `set` also removes the entries that have expired.
const PURGE_INTERVAL_MS: i64 = 60_000;
pub struct NodeCache {
    std_ttl_ms: i64,
    /// An expiry of 0 means the entry does not expire.
    map: Mutex<FxHashMap<String, (CacheValue, i64)>>,
    next_purge_ms: AtomicI64,
}
impl NodeCache {
    /// `std_ttl_s` is the `stdTTL` option in seconds. 0 keeps entries until they are deleted.
    pub fn new(std_ttl_s: u64) -> NodeCache {
        NodeCache { std_ttl_ms: std_ttl_s as i64 * 1000, map: Mutex::new(FxHashMap::default()), next_purge_ms: AtomicI64::new(0) }
    }
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl CacheStore for NodeCache {
    fn get(&self, key: &str) -> Option<CacheValue> {
        let mut m = self.map.lock().unwrap();
        match m.get(key) {
            Some((_, exp)) if *exp != 0 && *exp <= now_ms() => {
                m.remove(key);
                None
            }
            Some((v, _)) => Some(v.clone()),
            None => None,
        }
    }
    fn set(&self, key: &str, value: CacheValue) {
        let now = now_ms();
        let exp = if self.std_ttl_ms == 0 { 0 } else { now + self.std_ttl_ms };
        let mut m = self.map.lock().unwrap();
        // a key that is set and never read again must not stay for ever
        if self.std_ttl_ms != 0 && now >= self.next_purge_ms.load(Ordering::Relaxed) {
            self.next_purge_ms.store(now + PURGE_INTERVAL_MS, Ordering::Relaxed);
            let mut expired = Vec::new();
            for (k, (_, e)) in m.iter() {
                if *e != 0 && *e <= now {
                    expired.push(k.clone());
                }
            }
            for k in &expired {
                m.remove(k);
            }
        }
        m.insert(key.to_string(), (value, exp));
    }
    fn del(&self, key: &str) {
        self.map.lock().unwrap().remove(key);
    }
    fn flush_all(&self) {
        self.map.lock().unwrap().clear();
    }
}
