//! Same job as Utils/offline-node-processor.ts: queues offline stanza nodes and processes them in
//! order, one at a time, and a handler error does not stop the queue.
//!
//! Upstream runs the handlers on the event loop and awaits each one. A sync port cannot run them on
//! the caller's thread: `enqueue` is called by the socket reader, and a handler that waits for a
//! query reply would then block the thread that must read the reply. So the first `enqueue` starts
//! one worker thread. Like the upstream loop, the worker ends when the queue is empty or the socket
//! is closed, and the next `enqueue` starts a new one. An idle processor has no thread to stop.
use crate::error::{Boom, Result};
use crate::wabinary::BinaryNode;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    Message,
    Call,
    Receipt,
    Notification,
}
impl MessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageType::Message => "message",
            MessageType::Call => "call",
            MessageType::Receipt => "receipt",
            MessageType::Notification => "notification",
        }
    }
}

pub type NodeProcessor = Box<dyn Fn(&BinaryNode) -> Result<()> + Send + Sync>;
pub type NodeProcessorMap = FxHashMap<MessageType, NodeProcessor>;

pub struct OfflineNodeProcessorDeps {
    /// Runs with the queue locked, so it must be fast and must not call `enqueue`.
    pub is_ws_open: Box<dyn Fn() -> bool + Send + Sync>,
    pub on_unexpected_error: Box<dyn Fn(&Boom, &str) + Send + Sync>,
    /// Called after each batch. The worker blocks no event loop, so `std::thread::yield_now` is enough.
    pub yield_to_event_loop: Box<dyn Fn() + Send + Sync>,
}

struct State {
    nodes: VecDeque<(MessageType, BinaryNode)>,
    is_processing: bool,
    /// Kept here and not on the worker, because whether a fast worker ends between two `enqueue`
    /// calls depends on timing. Upstream starts each burst at 0. This count carries on.
    processed_in_batch: usize,
}
struct Shared {
    map: NodeProcessorMap,
    deps: OfflineNodeProcessorDeps,
    batch_size: usize,
    state: Mutex<State>,
    idle: Condvar,
}

/// From `make_offline_node_processor`.
#[derive(Clone)]
pub struct OfflineNodeProcessor(Arc<Shared>);

/// `batch_size` is 10 when `None`, as upstream.
pub fn make_offline_node_processor(node_processor_map: NodeProcessorMap, deps: OfflineNodeProcessorDeps, batch_size: Option<usize>) -> OfflineNodeProcessor {
    OfflineNodeProcessor(Arc::new(Shared {
        map: node_processor_map,
        deps,
        batch_size: batch_size.unwrap_or(10),
        state: Mutex::new(State { nodes: VecDeque::new(), is_processing: false, processed_in_batch: 0 }),
        idle: Condvar::new(),
    }))
}

impl OfflineNodeProcessor {
    pub fn enqueue(&self, ty: MessageType, node: BinaryNode) {
        let s = &self.0;
        let mut st = s.state.lock().unwrap();
        st.nodes.push_back((ty, node));
        if st.is_processing {
            return;
        }
        st.is_processing = true;
        drop(st);

        let worker = s.clone();
        if let Err(e) = std::thread::Builder::new().name("offline-nodes".to_string()).stack_size(crate::utils::time::THREAD_STACK).spawn(move || run(&worker)) {
            finish(&mut s.state.lock().unwrap(), &s.idle);
            (s.deps.on_unexpected_error)(&Boom::new(e.to_string()), "processing offline nodes");
        }
    }
    /// Blocks until no worker runs. This has no upstream version: there, a timer or an await does
    /// this job. Nodes can still be in the queue when the socket is closed.
    /// Do not call this from a handler, because the worker would wait for itself.
    pub fn wait_idle(&self) {
        let mut st = self.0.state.lock().unwrap();
        while st.is_processing {
            st = self.0.idle.wait(st).unwrap();
        }
    }
}

fn finish(st: &mut State, idle: &Condvar) {
    st.is_processing = false;
    idle.notify_all();
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    match (p.downcast_ref::<&str>(), p.downcast_ref::<String>()) {
        (Some(m), _) => m.to_string(),
        (_, Some(m)) => m.clone(),
        _ => "handler panicked".to_string(),
    }
}

fn run(s: &Shared) {
    loop {
        let (ty, node) = {
            let mut st = s.state.lock().unwrap();
            // The empty check, the socket check, and the flag change share one lock. So an
            // `enqueue` either sees this worker still running, or starts a new one.
            let next = if !st.nodes.is_empty() && (s.deps.is_ws_open)() { st.nodes.pop_front() } else { None };
            match next {
                Some(n) => n,
                None => {
                    finish(&mut st, &s.idle);
                    return;
                }
            }
        };

        let Some(node_processor) = s.map.get(&ty) else {
            let msg = format!("unknown offline node type: {}", ty.as_str());
            (s.deps.on_unexpected_error)(&Boom::new(msg), "processing offline node");
            continue;
        };

        // A throw in an upstream handler becomes a report. A panic is the closest thing to a throw.
        let error = match catch_unwind(AssertUnwindSafe(|| node_processor(&node))) {
            Ok(r) => r.err(),
            Err(p) => Some(Boom::new(panic_message(p.as_ref()))),
        };
        if let Some(e) = error {
            (s.deps.on_unexpected_error)(&e, &format!("processing offline {}", ty.as_str()));
        }

        let batch_done = {
            let mut st = s.state.lock().unwrap();
            st.processed_in_batch += 1;
            let done = st.processed_in_batch >= s.batch_size;
            if done {
                st.processed_in_batch = 0;
            }
            done
        };
        if batch_done {
            (s.deps.yield_to_event_loop)();
        }
    }
}
