//! Same behavior as Utils/event-buffer.ts: consolidates buffered events into one batch,
//! so the data can be processed in a single transaction.
//!
//! Dispatch rules for threads, which upstream does not have: the listeners of one buffer run on one
//! thread at a time, in order. A nested `emit` from a listener runs at once, as in Node. An `emit`
//! from another thread during a dispatch is queued, runs on the dispatching thread, and returns
//! without waiting, so a listener that waits for another thread cannot deadlock.
use crate::types::*;
use crate::utils::generics::JsMap;
use crate::utils::logger::{LogLevel, Logger};
use crate::utils::messages::{update_message_with_reaction, update_message_with_receipt};
use crate::utils::process_message::{is_real_message, should_increment_chat_unread};
use crate::utils::time::{Timeout, set_timeout};
use rustc_hash::FxHashSet;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::ThreadId;
use waproto::PastParticipants;
use waproto::pb::{Json, PbMessage};

/// Limit the history cache size to prevent memory bloat
const MAX_HISTORY_CACHE_SIZE: usize = 10000;
const BUFFER_TIMEOUT_MS: u64 = 30000;
const FLUSH_DELAY_MS: u64 = 100;

pub type ProcessHandler = Arc<dyn Fn(&BaileysEventData) + Send + Sync>;
pub const fn is_bufferable(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::MessagingHistorySet
            | EventKind::ChatsUpsert
            | EventKind::ChatsUpdate
            | EventKind::ChatsDelete
            | EventKind::ContactsUpsert
            | EventKind::ContactsUpdate
            | EventKind::MessagesUpsert
            | EventKind::MessagesUpdate
            | EventKind::MessagesDelete
            | EventKind::MessagesReaction
            | EventKind::MessageReceiptUpdate
            | EventKind::GroupsUpdate
    )
}
struct State {
    data: BufferedEventData,
    history_cache: FxHashSet<String>,
    is_buffering: bool,
    buffer_timeout: Option<Timeout>,
    /// A specific timer for the debounced flush to prevent leak
    flush_pending_timeout: Option<Timeout>,
    buffer_count: u32,
}
#[derive(Default)]
struct Listeners {
    next_id: u64,
    named: Vec<(u64, EventKind, Listener)>,
    process: Vec<(u64, ProcessHandler)>,
    /// `ev.on('event', ...)` that fires the named listeners. `destroy` removes it.
    forwards: bool,
    on_emit: Vec<(u64, EventKind, Listener)>,
}
#[derive(Default)]
struct Dispatch {
    owner: Option<ThreadId>,
    queue: VecDeque<BaileysEventData>,
    /// `destroy_after_dispatch` found another thread busy: that thread does it when its queue is empty.
    destroy_pending: bool,
}
struct Inner {
    logger: Arc<dyn Logger>,
    state: Mutex<State>,
    listeners: Mutex<Listeners>,
    dispatch: Mutex<Dispatch>,
}
/// The buffered emitter. Clones share the same buffer.
#[derive(Clone)]
pub struct EventBuffer(Arc<Inner>);
pub fn make_event_buffer(logger: Arc<dyn Logger>) -> EventBuffer {
    EventBuffer(Arc::new(Inner {
        logger,
        state: Mutex::new(State { data: make_buffer_data(), history_cache: FxHashSet::default(), is_buffering: false, buffer_timeout: None, flush_pending_timeout: None, buffer_count: 0 }),
        listeners: Mutex::new(Listeners { forwards: true, ..Listeners::default() }),
        dispatch: Mutex::new(Dispatch::default()),
    }))
}
pub fn make_buffer_data() -> BufferedEventData {
    let mut d = BufferedEventData::default();
    d.history_sets.empty = true;
    d
}
fn object1(k: &str, v: Json) -> Json {
    Json::Obj(vec![(k.to_string(), v)])
}
impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
    fn has_event_listeners(&self) -> bool {
        let l = self.listeners.lock().unwrap();
        l.forwards || !l.process.is_empty()
    }
    fn run_listeners(&self, map: &BaileysEventData) {
        // a snapshot, as Node copies the listener array before it emits
        let (named, process) = {
            let l = self.listeners.lock().unwrap();
            let named: Vec<(EventKind, Listener)> = if l.forwards { l.named.iter().filter(|(_, k, _)| map.iter().any(|e| e.kind() == *k)).map(|(_, k, f)| (*k, f.clone())).collect() } else { Vec::new() };
            let process: Vec<ProcessHandler> = l.process.iter().map(|(_, f)| f.clone()).collect();
            (named, process)
        };
        for e in map.iter() {
            for (k, f) in &named {
                if *k == e.kind() {
                    f(e);
                }
            }
        }
        for f in &process {
            f(map);
        }
    }
    /// Same as `ev.emit('event', map)`, with the thread rules at the top of this file.
    fn dispatch(&self, map: BaileysEventData) -> bool {
        let has_listeners = self.has_event_listeners();
        let me = std::thread::current().id();
        {
            let mut d = self.dispatch.lock().unwrap();
            match d.owner {
                Some(o) if o == me => {
                    drop(d);
                    self.run_listeners(&map);
                    return has_listeners;
                }
                Some(_) => {
                    d.queue.push_back(map);
                    return has_listeners;
                }
                None => d.owner = Some(me),
            }
        }
        let _owner = DispatchOwner(self);
        self.run_listeners(&map);
        loop {
            let next = {
                let mut d = self.dispatch.lock().unwrap();
                match d.queue.pop_front() {
                    Some(n) => n,
                    None => {
                        d.owner = None;
                        let destroy = std::mem::take(&mut d.destroy_pending);
                        drop(d);
                        if destroy {
                            self.destroy();
                        }
                        return has_listeners;
                    }
                }
            };
            self.run_listeners(&next);
        }
    }
    fn buffer(self: &Arc<Inner>) {
        let mut s = self.state();
        if !s.is_buffering {
            self.logger.debug("Event buffer activated");
            s.is_buffering = true;
            s.buffer_count = 0;
            if let Some(t) = s.buffer_timeout.take() {
                t.cancel();
            }
            let weak = Arc::downgrade(self);
            s.buffer_timeout = Some(set_timeout(BUFFER_TIMEOUT_MS, move || {
                if let Some(me) = weak.upgrade() {
                    if me.state().is_buffering {
                        me.logger.warn("Buffer timeout reached, auto-flushing");
                        me.flush();
                    }
                }
            }));
        }
        // Always increment count when requested
        s.buffer_count += 1;
    }
    fn flush(&self) -> bool {
        let mut s = self.state();
        if !s.is_buffering {
            return false;
        }
        if self.logger.is_enabled(LogLevel::Debug) {
            self.logger.debug_obj(&object1("bufferCount", Json::Num(s.buffer_count as f64)), "Flushing event buffer");
        }
        s.is_buffering = false;
        s.buffer_count = 0;
        // Clear timeout
        if let Some(t) = s.buffer_timeout.take() {
            t.cancel();
        }
        if let Some(t) = s.flush_pending_timeout.take() {
            t.cancel();
        }
        // Clear history cache if it exceeds the max size
        if s.history_cache.len() > MAX_HISTORY_CACHE_SIZE {
            if self.logger.is_enabled(LogLevel::Debug) {
                self.logger.debug_obj(&object1("cacheSize", Json::Num(s.history_cache.len() as f64)), "Clearing history cache");
            }
            s.history_cache.clear();
        }
        let mut new_data = make_buffer_data();
        let mut data = std::mem::replace(&mut s.data, make_buffer_data());
        let conditional: Vec<String> = data.chat_updates.iter().filter(|(_, u)| u.conditional.is_some()).map(|(k, _)| k.to_string()).collect();
        let conditional_chat_updates_left = conditional.len();
        for id in conditional {
            if let Some(u) = data.chat_updates.remove(&id) {
                // upstream keys the new map by `update.id`
                let key = u.id().map_or(String::new(), |i| i.to_string());
                new_data.chat_updates.insert(key, u);
            }
        }
        s.data = new_data;
        drop(s);
        let consolidated = consolidate_events(data);
        if !consolidated.is_empty() {
            self.dispatch(consolidated);
        }
        if self.logger.is_enabled(LogLevel::Trace) {
            self.logger.trace_obj(&object1("conditionalChatUpdatesLeft", Json::Num(conditional_chat_updates_left as f64)), "released buffered events");
        }
        true
    }
    fn destroy(&self) {
        {
            let mut s = self.state();
            // Clear buffer timeout
            if let Some(t) = s.buffer_timeout.take() {
                t.cancel();
            }
            if let Some(t) = s.flush_pending_timeout.take() {
                t.cancel();
            }
            // Clear history cache
            s.history_cache.clear();
            // Reset buffer data
            s.data = make_buffer_data();
            s.is_buffering = false;
            s.buffer_count = 0;
        }
        // Remove all listeners
        let mut l = self.listeners.lock().unwrap();
        l.named.clear();
        l.process.clear();
        l.on_emit.clear();
        l.forwards = false;
        drop(l);
        self.logger.debug("Event buffer destroyed");
    }
}
struct DispatchOwner<'a>(&'a Inner);
impl Drop for DispatchOwner<'_> {
    /// A panicking listener must not block the other threads for good.
    fn drop(&mut self) {
        let mut d = match self.0.dispatch.lock() {
            Ok(d) => d,
            Err(e) => e.into_inner(),
        };
        if d.owner == Some(std::thread::current().id()) {
            d.owner = None;
        }
    }
}
impl EventBuffer {
    /// Use to process events in a batch. The returned id goes to `off_process`.
    pub fn process(&self, handler: ProcessHandler) -> ListenerId {
        let mut l = self.0.listeners.lock().unwrap();
        l.next_id += 1;
        let id = l.next_id;
        l.process.push((id, handler));
        ListenerId(id)
    }
    pub fn off_process(&self, id: ListenerId) {
        self.0.listeners.lock().unwrap().process.retain(|(i, _)| *i != id.0);
    }
    /// starts buffering events, call flush() to release them
    pub fn buffer(&self) {
        self.0.buffer()
    }
    /// flushes all buffered events
    /// returns true if the flush actually happened, otherwise false
    pub fn flush(&self) -> bool {
        self.0.flush()
    }
    /// Runs `listener` on the emitting thread at the moment of the `emit`, before any buffering or
    /// queueing. The socket uses this so that `creds.update` changes the creds at once, as a
    /// synchronous emit does upstream, also when another thread dispatches a slow listener.
    /// A wait inside a listener also needs this, because a queued event would wait for that listener.
    pub fn on_emit(&self, event: EventKind, listener: Listener) -> ListenerId {
        let mut l = self.0.listeners.lock().unwrap();
        l.next_id += 1;
        let id = l.next_id;
        l.on_emit.push((id, event, listener));
        ListenerId(id)
    }
    pub fn off_emit(&self, id: ListenerId) {
        self.0.listeners.lock().unwrap().on_emit.retain(|(i, _, _)| *i != id.0);
    }
    /// Blocks until no other thread dispatches listeners, for at most `ms` milliseconds.
    pub fn wait_dispatch_idle(&self, ms: u64) {
        let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        let me = std::thread::current().id();
        loop {
            let busy = self.0.dispatch.lock().unwrap().owner.is_some_and(|o| o != me);
            if !busy || std::time::Instant::now() >= end {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    /// is there an ongoing buffer
    pub fn is_buffering(&self) -> bool {
        self.0.state().is_buffering
    }
    /// Buffers all events till `work` completes. Nested calls share one buffer.
    pub fn run_buffered<T>(&self, work: impl FnOnce() -> T) -> T {
        self.0.buffer();
        let _end = BufferedEnd(&self.0);
        let result = work();
        // If this is the only buffer, flush after a small delay
        if self.0.state().buffer_count == 1 {
            let weak: Weak<Inner> = Arc::downgrade(&self.0);
            set_timeout(FLUSH_DELAY_MS, move || {
                if let Some(me) = weak.upgrade() {
                    let only = {
                        let s = me.state();
                        s.is_buffering && s.buffer_count == 1
                    };
                    if only {
                        me.flush();
                    }
                }
            });
        }
        result
    }
    /// buffers all events till the function completes
    pub fn create_buffered_function<A: 'static, T: 'static>(&self, work: Arc<dyn Fn(A) -> T + Send + Sync>) -> Arc<dyn Fn(A) -> T + Send + Sync> {
        let ev = self.clone();
        Arc::new(move |args: A| ev.run_buffered(|| work(args)))
    }
    /// destroy the event buffer, clearing all resources
    pub fn destroy(&self) {
        self.0.destroy();
    }
    /// `destroy`, but events that another thread still dispatches reach their listeners first.
    pub fn destroy_after_dispatch(&self) {
        let me = std::thread::current().id();
        let mut d = self.0.dispatch.lock().unwrap();
        if d.owner.is_some_and(|o| o != me) {
            d.destroy_pending = true;
            return;
        }
        drop(d);
        self.0.destroy();
    }
}
struct BufferedEnd<'a>(&'a Arc<Inner>);
impl Drop for BufferedEnd<'_> {
    fn drop(&mut self) {
        let mut s = match self.0.state.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };
        s.buffer_count = s.buffer_count.saturating_sub(1);
        // Only schedule ONE timeout, not 10,000
        if s.buffer_count == 0 && s.flush_pending_timeout.is_none() {
            let weak = Arc::downgrade(self.0);
            s.flush_pending_timeout = Some(set_timeout(FLUSH_DELAY_MS, move || {
                if let Some(me) = weak.upgrade() {
                    me.flush();
                }
            }));
        }
    }
}
impl BaileysEventEmitter for EventBuffer {
    fn on(&self, event: EventKind, listener: Listener) -> ListenerId {
        let mut l = self.0.listeners.lock().unwrap();
        l.next_id += 1;
        let id = l.next_id;
        l.named.push((id, event, listener));
        ListenerId(id)
    }
    fn off(&self, event: EventKind, listener: ListenerId) {
        self.0.listeners.lock().unwrap().named.retain(|(i, k, _)| !(*i == listener.0 && *k == event));
    }
    fn remove_all_listeners(&self, event: EventKind) {
        self.0.listeners.lock().unwrap().named.retain(|(_, k, _)| *k != event);
    }
    fn emit(&self, event: BaileysEvent) -> bool {
        let inner = &self.0;
        let on_emit: Vec<Listener> = {
            let l = inner.listeners.lock().unwrap();
            if l.on_emit.is_empty() { Vec::new() } else { l.on_emit.iter().filter(|(_, k, _)| *k == event.kind()).map(|(_, _, f)| f.clone()).collect() }
        };
        for f in &on_emit {
            f(&event);
        }
        let mut s = inner.state();
        // Check if this is a messages.upsert with a different type than what's buffered
        // If so, flush the buffered messages first to avoid type overshadowing
        if let BaileysEvent::MessagesUpsert(u) = &event {
            let buffered_type = s.data.message_upserts.values().next().map(|m| m.r#type);
            if let Some(buffered_type) = buffered_type.filter(|b| *b != u.r#type) {
                if inner.logger.is_enabled(LogLevel::Debug) {
                    inner.logger.debug_obj(&Json::Obj(vec![("bufferedType".to_string(), Json::Str(buffered_type.as_str().to_string())), ("newType".to_string(), Json::Str(u.r#type.as_str().to_string()))]), "messages.upsert type mismatch, emitting buffered messages");
                }
                // Emit the buffered messages with their correct type
                let upserts = std::mem::take(&mut s.data.message_upserts);
                let messages = upserts.into_values().into_iter().map(|m| m.message).collect();
                drop(s);
                inner.dispatch(BaileysEventData(vec![BaileysEvent::MessagesUpsert(MessagesUpsert { messages, r#type: buffered_type, request_id: None })]));
                s = inner.state();
            }
        }
        if s.is_buffering && is_bufferable(event.kind()) {
            let st = &mut *s;
            append(&mut st.data, &mut st.history_cache, event, inner.logger.as_ref());
            return true;
        }
        drop(s);
        inner.dispatch(BaileysEventData(vec![event]))
    }
}
#[derive(Clone, Copy, PartialEq)]
enum ChatSlot {
    History,
    Upsert,
}
fn slot_mut<'a>(data: &'a mut BufferedEventData, slot: ChatSlot, id: &str) -> Option<&'a mut Chat> {
    match slot {
        ChatSlot::History => data.history_sets.chats.get_mut(id),
        ChatSlot::Upsert => data.chat_upserts.get_mut(id),
    }
}
/// The update takes the fields of `existing`, and `existing` then takes the result.
fn absorbing_chat_update(data: &mut BufferedEventData, slot: ChatSlot, id: &str, logger: &dyn Logger) {
    let Some(update) = data.chat_updates.get(id) else { return };
    let condition_matches = match update.conditional.clone() {
        Some(c) => c(data),
        None => Some(true),
    };
    match condition_matches {
        Some(true) => {
            debug_chat(logger, id, "absorbed chat update in existing chat");
            if let Some(mut update) = data.chat_updates.remove(id) {
                update.conditional = None;
                if let Some(existing) = slot_mut(data, slot, id) {
                    let mut b = existing.clone();
                    concat_chats(&mut update.chat, &mut b);
                    existing.assign_from(&update.chat);
                    clear_unread_if_marked(existing, &update.chat);
                }
            }
        }
        Some(false) => {
            debug_chat(logger, id, "chat update condition fail, removing");
            data.chat_updates.remove(id);
        }
        None => {}
    }
}
/// `Object.assign` copies an `undefined` unread count too, which `assign_from` cannot see.
fn clear_unread_if_marked(existing: &mut Chat, merged: &Chat) {
    if merged.unread_count().is_none() && !merged.unread_count_is_null() {
        existing.clear_unread_count();
    }
}
fn debug_chat(logger: &dyn Logger, id: &str, msg: &str) {
    if logger.is_enabled(LogLevel::Debug) {
        logger.debug_obj(&object1("chatId", Json::Str(id.to_string())), msg);
    }
}
/// Same as upstream `concatChats(a, b)`, which also writes to `b`: `a` takes the fields of `b`.
fn concat_chats(a: &mut Chat, b: &mut Chat) {
    // neutralize unread counter
    if b.unread_count_is_null() && a.unread_count().is_some_and(|c| c < 0) {
        a.clear_unread_count();
        b.clear_unread_count();
    }
    if let (Some(ac), Some(bc)) = (a.unread_count(), b.unread_count()) {
        if bc >= 0 {
            // `b = { ...b }` keeps this sum out of the caller's copy, which nothing reads after
            b.set_unread_count(bc.max(0) + ac.max(0));
        }
    }
    a.assign_from(b);
}
fn stringify_message_key(key: &WAMessageKey) -> String {
    let remote = key.remote_jid().map_or("undefined", |s| s.as_str());
    let id = key.id().map_or("undefined", |s| s.as_str());
    let mut s = String::with_capacity(remote.len() + id.len() + 3);
    s.push_str(remote);
    s.push(',');
    s.push_str(id);
    s.push(',');
    s.push(if key.from_me() == Some(true) { '1' } else { '0' });
    s
}
fn message_key_of(m: &WAMessage) -> String {
    match m.key() {
        Some(k) => stringify_message_key(k),
        None => stringify_message_key(&WAMessageKey::default()),
    }
}
fn sig_of(p: &waproto::PastParticipant) -> String {
    let ts = p.leave_ts().filter(|t| *t != 0).map_or(String::new(), |t| t.to_string());
    let reason = p.leave_reason().filter(|r| r.0 != 0).map_or(String::new(), |r| r.0.to_string());
    format!("{}:{ts}:{reason}", p.user_jid().map_or("", |s| s.as_str()))
}
fn merge_past_participants(existing: Option<Vec<PastParticipants>>, incoming: Vec<PastParticipants>) -> Vec<PastParticipants> {
    let mut merged: JsMap<PastParticipants> = JsMap::new();
    let mut ingest = |entry: PastParticipants| {
        let key = match entry.group_jid() {
            Some(g) => g.to_string(),
            None => entry.to_json().stringify(),
        };
        let Some(cur) = merged.get_mut(&key) else {
            merged.insert(key, entry);
            return;
        };
        let mut seen: FxHashSet<String> = cur.past_participants().iter().map(sig_of).collect();
        for p in entry.past_participants() {
            if seen.insert(sig_of(p)) {
                cur.past_participants_mut().push(p.clone());
            }
        }
    };
    for e in existing.unwrap_or_default() {
        ingest(e);
    }
    for e in incoming {
        ingest(e);
    }
    merged.into_values()
}
fn append(data: &mut BufferedEventData, history_cache: &mut FxHashSet<String>, event: BaileysEvent, logger: &dyn Logger) {
    match event {
        BaileysEvent::MessagingHistorySet(ev) => {
            for chat in ev.chats {
                let id = chat.id().map_or(String::new(), |s| s.to_string());
                if let Some(existing) = data.history_sets.chats.get_mut(&id) {
                    match chat.end_of_history_transfer_type() {
                        Some(t) => existing.set_end_of_history_transfer_type(t),
                        None => existing.clear_end_of_history_transfer_type(),
                    }
                } else if !history_cache.contains(&id) {
                    data.history_sets.chats.insert(id.as_str(), chat);
                    history_cache.insert(id.clone());
                    absorbing_chat_update(data, ChatSlot::History, &id, logger);
                }
            }
            for contact in ev.contacts {
                if let Some(existing) = data.history_sets.contacts.get_mut(&contact.id) {
                    existing.assign(&contact);
                } else {
                    let mut history_contact_id = String::with_capacity(contact.id.len() + 2);
                    history_contact_id.push_str("c:");
                    history_contact_id.push_str(&contact.id);
                    let non_empty = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.is_empty());
                    let has_any_name = non_empty(&contact.notify) || non_empty(&contact.name) || non_empty(&contact.verified_name);
                    if !history_cache.contains(&history_contact_id) || has_any_name {
                        data.history_sets.contacts.insert(contact.id.clone(), contact);
                        history_cache.insert(history_contact_id);
                    }
                }
            }
            for message in ev.messages {
                let key = message_key_of(&message);
                if !data.history_sets.messages.contains_key(&key) && !history_cache.contains(&key) {
                    history_cache.insert(key.clone());
                    data.history_sets.messages.insert(key, message);
                }
            }
            data.history_sets.empty = false;
            data.history_sets.sync_type = ev.sync_type;
            if let Some(Some(past)) = ev.past_participants.filter(|p| p.as_ref().is_some_and(|v| !v.is_empty())) {
                data.history_sets.past_participants = Some(merge_past_participants(data.history_sets.past_participants.take(), past));
            }
            data.history_sets.progress = ev.progress;
            data.history_sets.chunk_order = ev.chunk_order;
            data.history_sets.peer_data_request_session_id = ev.peer_data_request_session_id;
            data.history_sets.is_latest = ev.is_latest.unwrap_or(false) || data.history_sets.is_latest;
        }
        BaileysEvent::ChatsUpsert(chats) => {
            for mut chat in chats {
                let id = chat.id().map_or(String::new(), |s| s.to_string());
                let slot = if data.chat_upserts.contains_key(&id) {
                    Some(ChatSlot::Upsert)
                } else if !id.is_empty() && data.history_sets.chats.contains_key(&id) {
                    debug_chat(logger, &id, "absorbed chat upsert in chat set");
                    Some(ChatSlot::History)
                } else {
                    None
                };
                let slot = match slot {
                    Some(slot) => {
                        if let Some(upsert) = slot_mut(data, slot, &id) {
                            concat_chats(upsert, &mut chat);
                        }
                        slot
                    }
                    None => {
                        data.chat_upserts.insert(id.as_str(), chat);
                        ChatSlot::Upsert
                    }
                };
                absorbing_chat_update(data, slot, &id, logger);
                data.chat_deletes.remove(&id);
            }
        }
        BaileysEvent::ChatsUpdate(updates) => {
            for mut update in updates {
                let chat_id = update.id().map_or("undefined".to_string(), |s| s.to_string());
                let condition_matches = match update.conditional.clone() {
                    Some(c) => c(data),
                    None => Some(true),
                };
                match condition_matches {
                    Some(true) => {
                        update.conditional = None;
                        // if there is an existing upsert, merge the update into it
                        if let Some(upsert) = data.history_sets.chats.get_mut(&chat_id) {
                            concat_chats(upsert, &mut update.chat);
                        } else if let Some(upsert) = data.chat_upserts.get_mut(&chat_id) {
                            concat_chats(upsert, &mut update.chat);
                        } else {
                            // merge the update into the existing update
                            if !data.chat_updates.contains_key(&chat_id) {
                                data.chat_updates.insert(chat_id.as_str(), ChatUpdate::default());
                            }
                            if let Some(chat_update) = data.chat_updates.get_mut(&chat_id) {
                                concat_chats(&mut chat_update.chat, &mut update.chat);
                            }
                        }
                    }
                    // condition yet to be fulfilled
                    None => data.chat_updates.insert(chat_id.as_str(), update),
                    // otherwise -- condition not met, update is invalid
                    Some(false) => {}
                }
                // if the chat has been updated
                // ignore any existing chat delete
                data.chat_deletes.remove(&chat_id);
            }
        }
        BaileysEvent::ChatsDelete(ids) => {
            for chat_id in ids {
                if !data.chat_deletes.contains_key(&chat_id) {
                    data.chat_deletes.insert(chat_id.as_str(), ());
                }
                // remove any prior updates & upserts
                data.chat_updates.remove(&chat_id);
                data.chat_upserts.remove(&chat_id);
                data.history_sets.chats.remove(&chat_id);
            }
        }
        BaileysEvent::ContactsUpsert(contacts) => {
            for contact in contacts {
                let id = contact.id.clone();
                if let Some(upsert) = data.contact_upserts.get_mut(&id) {
                    upsert.assign(&contact);
                } else if let Some(upsert) = data.history_sets.contacts.get_mut(&id) {
                    if logger.is_enabled(LogLevel::Debug) {
                        logger.debug_obj(&object1("contactId", Json::Str(id.clone())), "absorbed contact upsert in contact set");
                    }
                    upsert.assign(&contact);
                } else {
                    data.contact_upserts.insert(id.as_str(), contact);
                }
                // upstream merges the contact into this update and then drops the result
                data.contact_updates.remove(&id);
            }
        }
        BaileysEvent::ContactsUpdate(updates) => {
            for update in updates {
                let id = update.contact.id.clone();
                // merge into prior upsert
                if let Some(upsert) = data.history_sets.contacts.get_mut(&id) {
                    upsert.apply_update(&update);
                } else if let Some(upsert) = data.contact_upserts.get_mut(&id) {
                    upsert.apply_update(&update);
                } else if let Some(contact_update) = data.contact_updates.get_mut(&id) {
                    // merge into prior update
                    contact_update.assign(&update);
                } else {
                    data.contact_updates.insert(id, update);
                }
            }
        }
        BaileysEvent::MessagesUpsert(MessagesUpsert { messages, r#type, .. }) => {
            for mut message in messages {
                let key = message_key_of(&message);
                let existing_ts = match data.message_upserts.get(&key) {
                    Some(e) => Some(e.message.message_timestamp()),
                    None => match data.history_sets.messages.get(&key) {
                        Some(e) => {
                            if logger.is_enabled(LogLevel::Debug) {
                                logger.debug_obj(&object1("messageId", Json::Str(key.clone())), "absorbed message upsert in message set");
                            }
                            Some(e.message_timestamp())
                        }
                        None => None,
                    },
                };
                if let Some(ts) = existing_ts {
                    match ts {
                        Some(t) => message.set_message_timestamp(t),
                        None => message.clear_message_timestamp(),
                    }
                }
                if let Some(u) = data.message_updates.remove(&key) {
                    logger.debug("absorbed prior message update in message upsert");
                    message.assign_from(&u.update);
                }
                if data.history_sets.messages.contains_key(&key) {
                    data.history_sets.messages.insert(key, message);
                } else {
                    let was_notify = data.message_upserts.get(&key).is_some_and(|m| m.r#type == MessageUpsertType::Notify);
                    let t = if r#type == MessageUpsertType::Notify || was_notify { MessageUpsertType::Notify } else { r#type };
                    data.message_upserts.insert(key, BufferedMessageUpsert { message, r#type: t });
                }
            }
        }
        BaileysEvent::MessagesUpdate(updates) => {
            for WAMessageUpdate { key, update } in updates {
                let key_str = stringify_message_key(&key);
                let existing = match data.history_sets.messages.get_mut(&key_str) {
                    Some(m) => Some(m),
                    None => data.message_upserts.get_mut(&key_str).map(|e| &mut e.message),
                };
                if let Some(existing) = existing {
                    existing.assign_from(&update);
                    // if the message was received & read by us
                    // the chat counter must have been incremented
                    // so we need to decrement it
                    if update.status() == Some(WAMessageStatus::READ) && key.from_me() != Some(true) {
                        let message = existing.clone();
                        decrement_chat_read_counter_if_msg_did_unread(data, &message, logger);
                    }
                } else if let Some(msg_update) = data.message_updates.get_mut(&key_str) {
                    msg_update.update.assign_from(&update);
                } else {
                    data.message_updates.insert(key_str, WAMessageUpdate { key, update });
                }
            }
        }
        BaileysEvent::MessagesDelete(MessagesDelete::Keys(keys)) => {
            for key in keys {
                let key_str = stringify_message_key(&key);
                if !data.message_deletes.contains_key(&key_str) {
                    data.message_deletes.insert(key_str.as_str(), key);
                }
                data.message_upserts.remove(&key_str);
                data.message_updates.remove(&key_str);
            }
        }
        // TODO: add support, as upstream says
        BaileysEvent::MessagesDelete(MessagesDelete::All { .. }) => {}
        BaileysEvent::MessagesReaction(reactions) => {
            for MessageReaction { key, reaction } in reactions {
                let key_str = stringify_message_key(&key);
                if let Some(existing) = data.message_upserts.get_mut(&key_str) {
                    update_message_with_reaction(existing.message.reactions_mut(), reaction);
                } else {
                    if !data.message_reactions.contains_key(&key_str) {
                        data.message_reactions.insert(key_str.as_str(), BufferedReactions { key, reactions: Vec::new() });
                    }
                    if let Some(e) = data.message_reactions.get_mut(&key_str) {
                        update_message_with_reaction(&mut e.reactions, reaction);
                    }
                }
            }
        }
        BaileysEvent::MessageReceiptUpdate(receipts) => {
            for MessageUserReceiptUpdate { key, receipt } in receipts {
                let key_str = stringify_message_key(&key);
                if let Some(existing) = data.message_upserts.get_mut(&key_str) {
                    update_message_with_receipt(existing.message.user_receipt_mut(), receipt);
                } else {
                    if !data.message_receipts.contains_key(&key_str) {
                        data.message_receipts.insert(key_str.as_str(), BufferedReceipts { key, user_receipt: Vec::new() });
                    }
                    if let Some(e) = data.message_receipts.get_mut(&key_str) {
                        update_message_with_receipt(&mut e.user_receipt, receipt);
                    }
                }
            }
        }
        BaileysEvent::GroupsUpdate(updates) => {
            for update in updates {
                let id = update.id.clone().unwrap_or_else(|| "undefined".to_string());
                if !data.group_updates.contains_key(&id) {
                    data.group_updates.insert(id, update);
                }
            }
        }
        // `emit` only appends bufferable events
        other => panic!("\"{}\" cannot be buffered", other.kind().name()),
    }
}
/// decrement chat unread counter
/// if the message has already been marked read by us
fn decrement_chat_read_counter_if_msg_did_unread(data: &mut BufferedEventData, message: &WAMessage, logger: &dyn Logger) {
    let Some(chat_id) = message.key().and_then(|k| k.remote_jid()) else { return };
    if !is_real_message(message) || !should_increment_chat_unread(message) {
        return;
    }
    let chat = match data.chat_updates.get_mut(chat_id.as_str()) {
        Some(u) => Some(&mut u.chat),
        None => data.chat_upserts.get_mut(chat_id.as_str()),
    };
    let Some(chat) = chat else { return };
    if let Some(c) = chat.unread_count().filter(|c| *c > 0) {
        if logger.is_enabled(LogLevel::Debug) {
            logger.debug_obj(&object1("chatId", Json::Str(chat.id().map_or("", |i| i.as_str()).to_string())), "decrementing chat counter");
        }
        if c == 1 {
            chat.clear_unread_count();
        } else {
            chat.set_unread_count(c - 1);
        }
    }
}
fn consolidate_events(data: BufferedEventData) -> BaileysEventData {
    let mut map = Vec::new();
    let h = data.history_sets;
    if !h.empty {
        map.push(BaileysEvent::MessagingHistorySet(MessagingHistorySet {
            chats: h.chats.into_values(),
            messages: h.messages.into_values(),
            contacts: h.contacts.into_values(),
            past_participants: h.past_participants.map(Some),
            sync_type: h.sync_type,
            progress: h.progress,
            is_latest: Some(h.is_latest),
            chunk_order: h.chunk_order,
            peer_data_request_session_id: h.peer_data_request_session_id,
            lid_pn_mappings: None,
        }));
    }
    if !data.chat_upserts.is_empty() {
        map.push(BaileysEvent::ChatsUpsert(data.chat_upserts.into_values()));
    }
    if !data.chat_updates.is_empty() {
        map.push(BaileysEvent::ChatsUpdate(data.chat_updates.into_values()));
    }
    if !data.chat_deletes.is_empty() {
        map.push(BaileysEvent::ChatsDelete(data.chat_deletes.into_pairs().into_iter().map(|(k, _)| k).collect()));
    }
    if !data.message_upserts.is_empty() {
        let upserts = data.message_upserts.into_values();
        let r#type = upserts[0].r#type;
        map.push(BaileysEvent::MessagesUpsert(MessagesUpsert { messages: upserts.into_iter().map(|m| m.message).collect(), r#type, request_id: None }));
    }
    if !data.message_updates.is_empty() {
        map.push(BaileysEvent::MessagesUpdate(data.message_updates.into_values()));
    }
    if !data.message_deletes.is_empty() {
        map.push(BaileysEvent::MessagesDelete(MessagesDelete::Keys(data.message_deletes.into_values())));
    }
    let mut reactions = Vec::new();
    for e in data.message_reactions.into_values() {
        for reaction in e.reactions {
            reactions.push(MessageReaction { key: e.key.clone(), reaction });
        }
    }
    if !reactions.is_empty() {
        map.push(BaileysEvent::MessagesReaction(reactions));
    }
    let mut receipts = Vec::new();
    for e in data.message_receipts.into_values() {
        for receipt in e.user_receipt {
            receipts.push(MessageUserReceiptUpdate { key: e.key.clone(), receipt });
        }
    }
    if !receipts.is_empty() {
        map.push(BaileysEvent::MessageReceiptUpdate(receipts));
    }
    if !data.contact_upserts.is_empty() {
        map.push(BaileysEvent::ContactsUpsert(data.contact_upserts.into_values()));
    }
    if !data.contact_updates.is_empty() {
        map.push(BaileysEvent::ContactsUpdate(data.contact_updates.into_values()));
    }
    if !data.group_updates.is_empty() {
        map.push(BaileysEvent::GroupsUpdate(data.group_updates.into_values()));
    }
    BaileysEventData(map)
}
