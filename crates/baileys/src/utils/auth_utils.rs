//! Same behavior as Utils/auth-utils.ts. The transaction context is per thread, in place of
//! `AsyncLocalStorage`: a thread that a transaction starts does not join that transaction.
use crate::auth::*;
use crate::crypto;
use crate::defaults::default_cache_ttls;
use crate::error::{Boom, Result};
use crate::types::{CacheStore, cache_get, cache_set};
use crate::utils::generics::{delay, generate_registration_id};
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::make_mutex::FifoMutex;
use crate::utils::node_cache::NodeCache;
use crate::utils::pre_key_manager::{KindData, PreKeyManager};
use rustc_hash::FxHashMap;
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use waproto::pb::{Json, base64_encode};

fn unique_id(kind: KeyKind, id: &str) -> String {
    let name = kind.name();
    let mut s = String::with_capacity(name.len() + 1 + id.len());
    s.push_str(name);
    s.push('.');
    s.push_str(id);
    s
}
/// Adds caching capability to a SignalKeyStore
pub struct CacheableSignalKeyStore {
    store: Arc<dyn SignalKeyStore>,
    logger: Option<Arc<dyn Logger>>,
    cache: Arc<dyn CacheStore>,
    /// Mutex for protecting cache operations
    cache_mutex: FifoMutex,
}
pub fn make_cacheable_signal_key_store(store: Arc<dyn SignalKeyStore>, logger: Option<Arc<dyn Logger>>, cache: Option<Arc<dyn CacheStore>>) -> Arc<CacheableSignalKeyStore> {
    let cache = cache.unwrap_or_else(|| Arc::new(NodeCache::new(default_cache_ttls::SIGNAL_STORE)));
    Arc::new(CacheableSignalKeyStore { store, logger, cache, cache_mutex: FifoMutex::new() })
}
impl SignalKeyStore for CacheableSignalKeyStore {
    fn get(&self, kind: KeyKind, ids: &[String]) -> Result<KeyMap> {
        self.cache_mutex.run_exclusive(|| {
            let mut data = KeyMap::default();
            let mut ids_to_fetch = Vec::new();
            for id in ids {
                match cache_get::<Option<KeyValue>>(self.cache.as_ref(), &unique_id(kind, id)) {
                    Some(item) => {
                        // a cached null counts as a hit, and the result has no value for it
                        if let Some(v) = item.as_ref() {
                            data.insert(id.clone(), v.clone());
                        }
                    }
                    None => ids_to_fetch.push(id.clone()),
                }
            }
            if !ids_to_fetch.is_empty() {
                if let Some(l) = self.logger.as_ref().filter(|l| l.is_enabled(LogLevel::Trace)) {
                    l.trace_obj(&Json::Obj(vec![("items".to_string(), Json::Num(ids_to_fetch.len() as f64))]), "loading from store");
                }
                let mut fetched = self.store.get(kind, &ids_to_fetch)?;
                for id in &ids_to_fetch {
                    if let Some(item) = fetched.remove(id) {
                        cache_set::<Option<KeyValue>>(self.cache.as_ref(), &unique_id(kind, id), Some(item.clone()));
                        data.insert(id.clone(), item);
                    }
                }
            }
            Ok(data)
        })
    }
    fn set(&self, data: Vec<KeyWrite>) -> Result<()> {
        self.cache_mutex.run_exclusive(|| {
            for (kind, id, v) in &data {
                cache_set::<Option<KeyValue>>(self.cache.as_ref(), &unique_id(*kind, id), v.clone());
            }
            if let Some(l) = self.logger.as_ref().filter(|l| l.is_enabled(LogLevel::Trace)) {
                l.trace_obj(&Json::Obj(vec![("keys".to_string(), Json::Num(data.len() as f64))]), "updated cache");
            }
            self.store.set(data)
        })
    }
    fn clear(&self) -> Result<()> {
        self.cache.flush_all();
        self.store.clear()
    }
}

#[derive(Default)]
struct TransactionContext {
    cache: FxHashMap<KeyKind, KindData>,
    mutations: SignalDataSet,
    db_queries: u32,
}
struct TxMutexEntry {
    mutex: Arc<FifoMutex>,
    ref_count: i64,
}
/// Adds DB-like transaction capability to the SignalKeyStore
pub struct TransactionalKeyStore {
    state: Arc<dyn SignalKeyStore>,
    logger: Arc<dyn Logger>,
    max_commit_retries: u32,
    delay_between_tries_ms: u64,
    /// One entry per thread that is in a transaction, so a short list.
    contexts: Mutex<Vec<(ThreadId, TransactionContext)>>,
    /// Queues for concurrency control (keyed by signal data type - bounded set)
    key_queues: Mutex<FxHashMap<KeyKind, Arc<FifoMutex>>>,
    /// Transaction mutexes with reference counting for cleanup
    tx_mutexes: Mutex<FxHashMap<String, TxMutexEntry>>,
    /// Pre-key manager for specialized operations
    pre_key_manager: PreKeyManager,
}
pub fn add_transaction_capability(state: Arc<dyn SignalKeyStore>, logger: Arc<dyn Logger>, opts: TransactionCapabilityOptions) -> Arc<TransactionalKeyStore> {
    Arc::new(TransactionalKeyStore {
        pre_key_manager: PreKeyManager::new(state.clone(), logger.clone()),
        state,
        logger,
        max_commit_retries: opts.max_commit_retries,
        delay_between_tries_ms: opts.delay_between_tries_ms,
        contexts: Mutex::new(Vec::new()),
        key_queues: Mutex::new(FxHashMap::default()),
        tx_mutexes: Mutex::new(FxHashMap::default()),
    })
}
fn me() -> ThreadId {
    std::thread::current().id()
}
fn context_mut(c: &mut [(ThreadId, TransactionContext)], thread: ThreadId) -> Option<&mut TransactionContext> {
    c.iter_mut().find(|(t, _)| *t == thread).map(|(_, x)| x)
}
fn take_context(c: &mut Vec<(ThreadId, TransactionContext)>, thread: ThreadId) -> Option<TransactionContext> {
    let i = c.iter().position(|(t, _)| *t == thread)?;
    Some(c.swap_remove(i).1)
}
/// Removes the context of this thread, also when the work panics.
struct ContextGuard<'a>(&'a TransactionalKeyStore);
impl Drop for ContextGuard<'_> {
    fn drop(&mut self) {
        let mut c = match self.0.contexts.lock() {
            Ok(c) => c,
            Err(e) => e.into_inner(),
        };
        take_context(&mut c, me());
    }
}
struct MutexRef<'a>(&'a TransactionalKeyStore, &'a str);
impl Drop for MutexRef<'_> {
    fn drop(&mut self) {
        self.0.release_tx_mutex_ref(self.1);
    }
}
impl TransactionalKeyStore {
    fn get_queue(&self, kind: KeyKind) -> Arc<FifoMutex> {
        self.key_queues.lock().unwrap().entry(kind).or_default().clone()
    }
    /// Get or create a transaction mutex
    fn get_tx_mutex(&self, key: &str) -> Arc<FifoMutex> {
        let mut m = self.tx_mutexes.lock().unwrap();
        if let Some(e) = m.get(key) {
            return e.mutex.clone();
        }
        let mutex = Arc::new(FifoMutex::new());
        m.insert(key.to_string(), TxMutexEntry { mutex: mutex.clone(), ref_count: 0 });
        mutex
    }
    /// Acquire a reference to a transaction mutex
    fn acquire_tx_mutex_ref(&self, key: &str) {
        if let Some(e) = self.tx_mutexes.lock().unwrap().get_mut(key) {
            e.ref_count += 1;
        }
    }
    /// Release a reference to a transaction mutex and cleanup if no longer needed
    fn release_tx_mutex_ref(&self, key: &str) {
        let mut m = match self.tx_mutexes.lock() {
            Ok(m) => m,
            Err(e) => e.into_inner(),
        };
        if let Some(e) = m.get_mut(key) {
            e.ref_count -= 1;
            // Cleanup if no more references and mutex is not locked
            if e.ref_count <= 0 && !e.mutex.is_locked() {
                m.remove(key);
            }
        }
    }
    /// Commit transaction with retries
    fn commit_with_retry(&self, mutations: SignalDataSet) -> Result<()> {
        if mutations.is_empty() {
            self.logger.trace("no mutations in transaction");
            return Ok(());
        }
        self.logger.trace("committing transaction");
        let count = mutations.0.len();
        let writes = mutations.into_writes();
        for attempt in 0..self.max_commit_retries {
            match self.state.set(writes.clone()) {
                Ok(()) => {
                    if self.logger.is_enabled(LogLevel::Trace) {
                        self.logger.trace_obj(&Json::Obj(vec![("mutationCount".to_string(), Json::Num(count as f64))]), "committed transaction");
                    }
                    return Ok(());
                }
                Err(error) => {
                    let retries_left = self.max_commit_retries - attempt - 1;
                    self.logger.warn(&format!("failed to commit mutations, retries left={retries_left}"));
                    if retries_left == 0 {
                        return Err(error);
                    }
                    delay(self.delay_between_tries_ms);
                }
            }
        }
        Ok(())
    }
}
impl SignalKeyStore for TransactionalKeyStore {
    fn get(&self, kind: KeyKind, ids: &[String]) -> Result<KeyMap> {
        let thread = me();
        let missing: Vec<String> = {
            let mut c = self.contexts.lock().unwrap();
            let Some(ctx) = context_mut(&mut c, thread) else {
                drop(c);
                // No transaction - direct read without exclusive lock for concurrency
                return self.state.get(kind, ids);
            };
            // In transaction - check what it wrote and read first
            let cached = ctx.cache.get(&kind);
            let written = ctx.mutations.get(kind);
            ids.iter().filter(|id| !written.is_some_and(|m| m.contains_key(id)) && !cached.is_some_and(|m| m.contains_key(id))).cloned().collect()
        };
        if !missing.is_empty() {
            if self.logger.is_enabled(LogLevel::Trace) {
                self.logger.trace_obj(&Json::Obj(vec![("type".to_string(), Json::Str(kind.name().to_string())), ("count".to_string(), Json::Num(missing.len() as f64))]), "fetching missing keys in transaction");
            }
            let fetched = self.get_tx_mutex(kind.name()).run_exclusive(|| self.state.get(kind, &missing))?;
            let mut c = self.contexts.lock().unwrap();
            if let Some(ctx) = context_mut(&mut c, thread) {
                ctx.db_queries += 1;
                let cache = ctx.cache.entry(kind).or_default();
                for (id, v) in fetched {
                    cache.insert(id, Some(v));
                }
            }
        }
        // Return requested ids. A write of the transaction hides what the cache read before it.
        let mut c = self.contexts.lock().unwrap();
        let mut result = KeyMap::default();
        if let Some(ctx) = context_mut(&mut c, thread) {
            let (cached, written) = (ctx.cache.get(&kind), ctx.mutations.get(kind));
            for id in ids {
                let value = written.and_then(|m| m.get(id)).or_else(|| cached.and_then(|m| m.get(id)));
                if let Some(Some(v)) = value {
                    result.insert(id.clone(), v.clone());
                }
            }
        }
        Ok(result)
    }
    fn set(&self, data: Vec<KeyWrite>) -> Result<()> {
        let thread = me();
        let mut set = SignalDataSet::from_writes(data);
        let in_tx = context_mut(&mut self.contexts.lock().unwrap(), thread).is_some();
        if !in_tx {
            // No transaction - direct write with queue protection
            // Process pre-keys with validation
            for (kind, values) in &mut set.0 {
                if *kind == KeyKind::PreKey {
                    self.pre_key_manager.validate_deletions(values, *kind)?;
                }
            }
            for (kind, values) in set.0 {
                let writes = SignalDataSet(vec![(kind, values)]).into_writes();
                self.get_queue(kind).run_exclusive(|| self.state.set(writes))?;
            }
            return Ok(());
        }
        // In transaction - only the mutations hold a write, so a large write is not stored twice
        if self.logger.is_enabled(LogLevel::Trace) {
            let types = set.0.iter().map(|(k, _)| Json::Str(k.name().to_string())).collect();
            self.logger.trace_obj(&Json::Obj(vec![("types".to_string(), Json::Arr(types))]), "caching in transaction");
        }
        for (kind, values) in set.0 {
            let mut c = self.contexts.lock().unwrap();
            let Some(ctx) = context_mut(&mut c, thread) else { break };
            let mutations = ctx.mutations.entry(kind);
            // Special handling for pre-keys
            if kind == KeyKind::PreKey {
                self.pre_key_manager.process_operations(values, kind, ctx.cache.get(&kind), mutations, true)?;
            } else {
                // Normal key types
                for (id, v) in values.into_pairs() {
                    mutations.insert(id, v);
                }
            }
        }
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        self.state.clear()
    }
    fn is_in_transaction(&self) -> bool {
        context_mut(&mut self.contexts.lock().unwrap(), me()).is_some()
    }
    fn transaction(&self, work: &mut dyn FnMut() -> Result<()>, key: &str) -> Result<()> {
        // Nested transaction - reuse existing context
        if self.is_in_transaction() {
            self.logger.trace("reusing existing transaction context");
            return work();
        }
        // New transaction - acquire mutex and create context
        let mutex = self.get_tx_mutex(key);
        self.acquire_tx_mutex_ref(key);
        let _release = MutexRef(self, key);
        mutex.run_exclusive(|| {
            self.contexts.lock().unwrap().push((me(), TransactionContext::default()));
            let guard = ContextGuard(self);
            self.logger.trace("entering transaction");
            let result = work();
            let ctx = take_context(&mut self.contexts.lock().unwrap(), me());
            drop(guard);
            let result = match (result, ctx) {
                // Commit mutations
                (Ok(()), Some(ctx)) => {
                    let TransactionContext { cache, mutations, db_queries: queries } = ctx;
                    // a large commit should not hold the read cache as well
                    drop(cache);
                    self.commit_with_retry(mutations).inspect(|_| {
                        if self.logger.is_enabled(LogLevel::Trace) {
                            self.logger.trace_obj(&Json::Obj(vec![("dbQueries".to_string(), Json::Num(queries as f64))]), "transaction completed");
                        }
                    })
                }
                (other, _) => other,
            };
            if let Err(error) = &result {
                if self.logger.is_enabled(LogLevel::Error) {
                    self.logger.error_obj(&Json::Obj(vec![("error".to_string(), Json::Str(error.message.clone()))]), "transaction failed, rolling back");
                }
            }
            result
        })
    }
}
/// Returns the authenticated user's JID, or a Boom-401 if creds are not yet authenticated.
pub fn assert_me_id(creds: &AuthenticationCreds) -> Result<&str> {
    match creds.me.as_ref().map(|m| m.id.as_str()) {
        Some(id) if !id.is_empty() => Ok(id),
        _ => Err(Boom::status("Cannot proceed: socket is not authenticated yet (creds.me.id is missing)", 401)),
    }
}
pub fn init_auth_creds() -> AuthenticationCreds {
    let identity_key = crypto::generate_key_pair();
    let mut adv = [0u8; 32];
    crypto::random_bytes(&mut adv);
    AuthenticationCreds {
        noise_key: crypto::generate_key_pair(),
        pairing_ephemeral_key_pair: crypto::generate_key_pair(),
        signed_pre_key: crypto::signed_key_pair(&identity_key, 1),
        signed_pre_key_timestamp_s: None,
        signed_identity_key: identity_key,
        registration_id: generate_registration_id(),
        adv_secret_key: base64_encode(&adv),
        processed_history_messages: Vec::new(),
        next_pre_key_id: 1,
        first_unuploaded_pre_key_id: 1,
        account_sync_counter: 0,
        account_settings: AccountSettings { unarchive_chats: false, default_disappearing_mode: None },
        registered: false,
        pairing_code: None,
        last_prop_hash: None,
        routing_info: None,
        additional_data: None,
        me: None,
        account: None,
        signal_identities: None,
        my_app_state_key_id: None,
        last_account_sync_timestamp: None,
        platform: None,
    }
}
