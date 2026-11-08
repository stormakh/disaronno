//! Same behavior as Utils/pre-key-manager.ts.
use crate::auth::{KeyKind, KeyValue, SignalKeyStore};
use crate::error::Result;
use crate::utils::generics::JsMap;
use crate::utils::logger::Logger;
use crate::utils::make_mutex::FifoMutex;
use rustc_hash::FxHashMap;
use std::sync::{Arc, Mutex};

/// A value of the transaction cache or the mutations. `None` is a deleted key.
pub type KindData = JsMap<Option<KeyValue>>;
/// Manages pre-key operations with proper concurrency control
pub struct PreKeyManager {
    queues: Mutex<FxHashMap<KeyKind, Arc<FifoMutex>>>,
    store: Arc<dyn SignalKeyStore>,
    logger: Arc<dyn Logger>,
}
impl PreKeyManager {
    pub fn new(store: Arc<dyn SignalKeyStore>, logger: Arc<dyn Logger>) -> PreKeyManager {
        PreKeyManager { queues: Mutex::new(FxHashMap::default()), store, logger }
    }
    /// Get or create a queue for a specific key type
    fn get_queue(&self, kind: KeyKind) -> Arc<FifoMutex> {
        self.queues.lock().unwrap().entry(kind).or_default().clone()
    }
    /// Process pre-key operations (updates and deletions)
    /// `cache` is what the transaction has read. It holds no writes: they are all in `mutations`.
    pub fn process_operations(&self, data: KindData, kind: KeyKind, cache: Option<&KindData>, mutations: &mut KindData, is_in_transaction: bool) -> Result<()> {
        let queue = self.get_queue(kind);
        queue.run_exclusive(|| {
            // Separate deletions from updates
            let mut deletions = Vec::new();
            for (id, v) in data.into_pairs() {
                match v {
                    None => deletions.push(id),
                    // Process updates (no validation needed)
                    Some(_) => mutations.insert(id, v),
                }
            }
            // Process deletions with validation
            if !deletions.is_empty() {
                return self.process_deletions(kind, &deletions, cache, mutations, is_in_transaction);
            }
            Ok(())
        })
    }
    /// Process deletions with validation
    fn process_deletions(&self, kind: KeyKind, ids: &[String], cache: Option<&KindData>, mutations: &mut KindData, is_in_transaction: bool) -> Result<()> {
        if is_in_transaction {
            // In transaction, only allow deletion if key exists in cache
            for id in ids {
                let current = mutations.get(id).or_else(|| cache.and_then(|c| c.get(id)));
                if matches!(current, Some(Some(_))) {
                    mutations.insert(id.as_str(), None);
                } else {
                    self.logger.warn(&format!("Skipping deletion of non-existent {} in transaction: {id}", kind.name()));
                }
            }
        } else {
            // Outside transaction, validate against store
            let existing = self.store.get(kind, ids)?;
            for id in ids {
                if existing.contains_key(id) {
                    mutations.insert(id.as_str(), None);
                } else {
                    self.logger.warn(&format!("Skipping deletion of non-existent {}: {id}", kind.name()));
                }
            }
        }
        Ok(())
    }
    /// Validate and process pre-key deletions outside transactions
    pub fn validate_deletions(&self, data: &mut KindData, kind: KeyKind) -> Result<()> {
        let queue = self.get_queue(kind);
        queue.run_exclusive(|| {
            // Find all deletion requests
            let ids: Vec<String> = data.iter().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_string()).collect();
            if ids.is_empty() {
                return Ok(());
            }
            // Validate deletions
            let existing = self.store.get(kind, &ids)?;
            for id in &ids {
                if !existing.contains_key(id) {
                    self.logger.warn(&format!("Skipping deletion of non-existent {}: {id}", kind.name()));
                    data.remove(id);
                }
            }
            Ok(())
        })
    }
}
