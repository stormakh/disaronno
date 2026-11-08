//! Port of src/__tests__/Utils/offline-node-processor.test.ts.
//!
//! Upstream waits with `setTimeout(r, 10)`. A timed wait would be a race with the worker thread here,
//! so these tests use `wait_idle`, which returns only when the worker has ended.
use baileys::error::{Boom, Result};
use baileys::utils::offline_node_processor::{MessageType, NodeProcessorMap, OfflineNodeProcessor, OfflineNodeProcessorDeps, make_offline_node_processor};
use baileys::wabinary::{Attrs, BinaryNode};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

fn make_node(id: &str, tag: &str) -> BinaryNode {
    BinaryNode::tag(tag, Attrs::from([("id", id), ("from", "user@s.whatsapp.net"), ("offline", "1")]))
}
fn msg(id: &str) -> BinaryNode {
    make_node(id, "message")
}
#[derive(Clone, Default)]
struct Env {
    is_ws_open: Arc<AtomicBool>,
    errors: Arc<Mutex<Vec<(String, String)>>>,
    yield_calls: Arc<AtomicUsize>,
}
impl Env {
    fn new() -> Env {
        let e = Env::default();
        e.is_ws_open.store(true, Ordering::SeqCst);
        e
    }
    fn processor(&self, handlers: NodeProcessorMap, batch_size: usize) -> OfflineNodeProcessor {
        let (open, errors, yields) = (self.is_ws_open.clone(), self.errors.clone(), self.yield_calls.clone());
        make_offline_node_processor(
            handlers,
            OfflineNodeProcessorDeps {
                is_ws_open: Box::new(move || open.load(Ordering::SeqCst)),
                on_unexpected_error: Box::new(move |e: &Boom, m: &str| errors.lock().unwrap().push((e.message.clone(), m.to_string()))),
                yield_to_event_loop: Box::new(move || {
                    yields.fetch_add(1, Ordering::SeqCst);
                }),
            },
            Some(batch_size),
        )
    }
    fn error_count(&self) -> usize {
        self.errors.lock().unwrap().len()
    }
}
type Ids = Arc<Mutex<Vec<String>>>;
fn ids(v: &Ids) -> Vec<String> {
    v.lock().unwrap().clone()
}
fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}
fn id_of(n: &BinaryNode) -> String {
    n.attr("id").unwrap().to_string()
}
fn recording(processed: &Ids, fail: &'static [&'static str]) -> NodeProcessorMap {
    let p = processed.clone();
    let mut m = NodeProcessorMap::default();
    m.insert(
        MessageType::Message,
        Box::new(move |n: &BinaryNode| -> Result<()> {
            if fail.contains(&n.attr("id").unwrap()) {
                return Err(Boom::new("handler crash"));
            }
            p.lock().unwrap().push(id_of(n));
            Ok(())
        }),
    );
    m
}
fn counting(count: &Arc<AtomicUsize>) -> NodeProcessorMap {
    let c = count.clone();
    let mut m = NodeProcessorMap::default();
    m.insert(
        MessageType::Message,
        Box::new(move |_: &BinaryNode| -> Result<()> {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    );
    m
}

#[test]
fn t_makeofflinenodeprocessor_basic_processing_should_process_a_single_enqueued_node() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let p = env.processor(recording(&processed, &[]), 10);
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.wait_idle();
    // the handler records each call, so this also checks that it ran once
    assert_eq!(ids(&processed), strs(&["msg-1"]));
}
#[test]
fn t_makeofflinenodeprocessor_basic_processing_should_process_multiple_nodes_in_fifo_order() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let p = env.processor(recording(&processed, &[]), 10);
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.enqueue(MessageType::Message, msg("msg-2"));
    p.enqueue(MessageType::Message, msg("msg-3"));
    p.wait_idle();
    assert_eq!(ids(&processed), strs(&["msg-1", "msg-2", "msg-3"]));
}
#[test]
fn t_makeofflinenodeprocessor_basic_processing_should_dispatch_nodes_to_correct_handler_by_type() {
    let env = Env::new();
    let (message_ids, call_ids, receipt_ids, notification_ids): (Ids, Ids, Ids, Ids) = Default::default();
    let mut m = NodeProcessorMap::default();
    for (ty, list) in [(MessageType::Message, &message_ids), (MessageType::Call, &call_ids), (MessageType::Receipt, &receipt_ids), (MessageType::Notification, &notification_ids)] {
        let l = list.clone();
        m.insert(
            ty,
            Box::new(move |n: &BinaryNode| -> Result<()> {
                l.lock().unwrap().push(id_of(n));
                Ok(())
            }),
        );
    }
    let p = env.processor(m, 10);
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.enqueue(MessageType::Call, make_node("call-1", "call"));
    p.enqueue(MessageType::Receipt, make_node("rcpt-1", "receipt"));
    p.enqueue(MessageType::Notification, make_node("notif-1", "notification"));
    p.wait_idle();
    assert_eq!(ids(&message_ids), strs(&["msg-1"]));
    assert_eq!(ids(&call_ids), strs(&["call-1"]));
    assert_eq!(ids(&receipt_ids), strs(&["rcpt-1"]));
    assert_eq!(ids(&notification_ids), strs(&["notif-1"]));
}

#[test]
fn t_makeofflinenodeprocessor_error_resilience_should_continue_processing_after_a_handler_throws() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let p = env.processor(recording(&processed, &["msg-2"]), 10);
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.enqueue(MessageType::Message, msg("msg-2"));
    p.enqueue(MessageType::Message, msg("msg-3"));
    p.wait_idle();
    // msg-1 and msg-3 should be processed, msg-2 error should be caught
    assert_eq!(ids(&processed), strs(&["msg-1", "msg-3"]));
    assert_eq!(env.error_count(), 1);
    assert_eq!(env.errors.lock().unwrap()[0].1, "processing offline message");
}
#[test]
fn t_makeofflinenodeprocessor_error_resilience_should_continue_processing_after_multiple_handler_errors() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let p = env.processor(recording(&processed, &["msg-1", "msg-3"]), 10);
    for i in 1..=5 {
        p.enqueue(MessageType::Message, msg(&format!("msg-{i}")));
    }
    p.wait_idle();
    assert_eq!(ids(&processed), strs(&["msg-2", "msg-4", "msg-5"]));
    assert_eq!(env.error_count(), 2);
}
#[test]
fn t_makeofflinenodeprocessor_error_resilience_should_report_unknown_node_type_and_continue() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let p = env.processor(recording(&processed, &[]), 10);
    // adapted: `'unknown-type' as MessageType` cannot exist in the Rust enum. A type with no handler
    // takes the same branch, which is the only way upstream reaches it through its own types.
    p.enqueue(MessageType::Call, make_node("unknown-1", "call"));
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.wait_idle();
    assert_eq!(ids(&processed), strs(&["msg-1"]));
    let errors = env.errors.lock().unwrap();
    assert!(errors.iter().any(|(m, c)| m.contains("unknown offline node type") && c == "processing offline node"), "{errors:?}");
}

#[test]
fn t_makeofflinenodeprocessor_connection_awareness_should_stop_processing_when_connection_closes() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let (pr, open) = (processed.clone(), env.is_ws_open.clone());
    let mut m = NodeProcessorMap::default();
    m.insert(
        MessageType::Message,
        Box::new(move |n: &BinaryNode| -> Result<()> {
            pr.lock().unwrap().push(id_of(n));
            if n.attr("id") == Some("msg-2") {
                open.store(false, Ordering::SeqCst);
            }
            Ok(())
        }),
    );
    let p = env.processor(m, 10);
    for i in 1..=5 {
        p.enqueue(MessageType::Message, msg(&format!("msg-{i}")));
    }
    p.wait_idle();
    // Should stop after msg-2 closes the connection
    assert_eq!(ids(&processed), strs(&["msg-1", "msg-2"]));
}
#[test]
fn t_makeofflinenodeprocessor_connection_awareness_should_resume_processing_when_new_nodes_are_enqueued_after_connection_reopens() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    // Start with closed connection
    env.is_ws_open.store(false, Ordering::SeqCst);
    let p = env.processor(recording(&processed, &[]), 10);
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.wait_idle();
    assert_eq!(ids(&processed), Vec::<String>::new());

    // Reopen connection and enqueue new node
    env.is_ws_open.store(true, Ordering::SeqCst);
    p.enqueue(MessageType::Message, msg("msg-2"));
    p.wait_idle();
    // Both nodes should now be processed (msg-1 was still in queue)
    assert_eq!(ids(&processed), strs(&["msg-1", "msg-2"]));
}

#[test]
fn t_makeofflinenodeprocessor_batch_yielding_should_yield_to_event_loop_after_batchsize_nodes() {
    let env = Env::new();
    let count: Arc<AtomicUsize> = Arc::default();
    let p = env.processor(counting(&count), 3);
    for i in 1..=7 {
        p.enqueue(MessageType::Message, msg(&format!("msg-{i}")));
    }
    p.wait_idle();
    assert_eq!(count.load(Ordering::SeqCst), 7);
    // 7 nodes with batchSize 3 => yields after 3rd and 6th = 2 yields
    assert_eq!(env.yield_calls.load(Ordering::SeqCst), 2);
}
#[test]
fn t_makeofflinenodeprocessor_batch_yielding_should_not_yield_for_fewer_nodes_than_batchsize() {
    let env = Env::new();
    let count: Arc<AtomicUsize> = Arc::default();
    let p = env.processor(counting(&count), 10);
    for i in 1..=5 {
        p.enqueue(MessageType::Message, msg(&format!("msg-{i}")));
    }
    p.wait_idle();
    assert_eq!(count.load(Ordering::SeqCst), 5);
    assert_eq!(env.yield_calls.load(Ordering::SeqCst), 0);
}
#[test]
fn t_makeofflinenodeprocessor_batch_yielding_should_yield_exactly_at_batchsize_boundary() {
    let env = Env::new();
    let count: Arc<AtomicUsize> = Arc::default();
    let p = env.processor(counting(&count), 3);
    for i in 1..=3 {
        p.enqueue(MessageType::Message, msg(&format!("msg-{i}")));
    }
    p.wait_idle();
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(env.yield_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn t_makeofflinenodeprocessor_isprocessing_guard_should_not_start_a_second_processing_loop_for_concurrent_enqueues() {
    let env = Env::new();
    let call_count: Arc<AtomicUsize> = Arc::default();
    let (started_tx, started_rx) = channel::<()>();
    let (release_tx, release_rx) = channel::<()>();
    let (started_tx, release_rx) = (Mutex::new(started_tx), Mutex::new(release_rx));
    let c = call_count.clone();
    let mut m = NodeProcessorMap::default();
    m.insert(
        MessageType::Message,
        Box::new(move |_: &BinaryNode| -> Result<()> {
            // Block on first node to simulate slow processing
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                started_tx.lock().unwrap().send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
            }
            Ok(())
        }),
    );
    let p = env.processor(m, 10);
    p.enqueue(MessageType::Message, msg("msg-1"));

    // Wait for first processing to start
    started_rx.recv().unwrap();

    // Enqueue while first is still processing
    p.enqueue(MessageType::Message, msg("msg-2"));
    p.enqueue(MessageType::Message, msg("msg-3"));
    // adapted: a stronger check that threads make possible. A second loop would run these now.
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    // Release the first handler
    release_tx.send(()).unwrap();
    p.wait_idle();
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
}

#[test]
fn t_makeofflinenodeprocessor_mixed_error_types_should_handle_both_handler_errors_and_unknown_types_in_sequence() {
    let env = Env::new();
    let processed: Ids = Arc::default();
    let p = env.processor(recording(&processed, &["msg-2"]), 10);
    p.enqueue(MessageType::Message, msg("msg-1"));
    p.enqueue(MessageType::Message, msg("msg-2")); // will throw
    // adapted: a type with no handler in place of `'bogus' as MessageType`, as above
    p.enqueue(MessageType::Receipt, make_node("x", "receipt")); // unknown type
    p.enqueue(MessageType::Message, msg("msg-3"));
    p.wait_idle();
    assert_eq!(ids(&processed), strs(&["msg-1", "msg-3"]));
    assert_eq!(env.error_count(), 2);
}
