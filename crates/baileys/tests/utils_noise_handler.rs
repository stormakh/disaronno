//! Port of src/__tests__/Utils/noise-handler.test.ts.
use baileys::crypto::generate_key_pair;
use baileys::defaults::NOISE_WA_HEADER;
use baileys::utils::noise::{Frame, NoiseHandler};
use std::sync::{Arc, Mutex};

/// Helper to create a frame with length prefix
fn create_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![(payload.len() >> 16) as u8];
    frame.extend_from_slice(&((payload.len() & 0xffff) as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn handler() -> NoiseHandler {
    NoiseHandler::new(&generate_key_pair(), &NOISE_WA_HEADER, None)
}
fn raw(f: Frame) -> Vec<u8> {
    match f {
        Frame::Raw(b) => b,
        Frame::Node(n) => panic!("expected raw bytes, got {n:?}"),
    }
}

#[test]
fn t_noise_handler_decodeframe_with_multiple_frames_in_buffer_should_process_multiple_unencrypted_frames_in_single_buffer() {
    let mut h = handler();
    let payload1 = [1u8, 2, 3, 4, 5];
    let payload2 = [6u8, 7, 8, 9, 10];
    let combined = [create_frame(&payload1), create_frame(&payload2)].concat();
    let mut received = Vec::new();
    h.decode_frame(&combined, &mut |f| received.push(raw(f))).unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0], payload1);
    assert_eq!(received[1], payload2);
}
#[test]
fn t_noise_handler_decodeframe_with_multiple_frames_in_buffer_should_handle_frames_split_across_multiple_decodeframe_calls() {
    let mut h = handler();
    let payload = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let frame = create_frame(&payload);
    let mut received = Vec::new();
    // Split the frame across two calls
    h.decode_frame(&frame[..5], &mut |f| received.push(raw(f))).unwrap();
    assert_eq!(received.len(), 0);
    h.decode_frame(&frame[5..], &mut |f| received.push(raw(f))).unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], payload);
}
#[test]
fn t_noise_handler_decodeframe_with_multiple_frames_in_buffer_should_correctly_process_frames_when_callback_triggers_async_operations() {
    let mut h = handler();
    let payload1 = [1u8, 2, 3];
    let payload2 = [4u8, 5, 6];
    let combined = [create_frame(&payload1), create_frame(&payload2)].concat();
    let mut received: Vec<Vec<u8>> = Vec::new();
    let mut callback_order = Vec::new();
    h.decode_frame(&combined, &mut |f| {
        callback_order.push(received.len() + 1);
        received.push(raw(f));
    })
    .unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(callback_order, [1, 2]);
    assert_eq!(received[0], payload1);
    assert_eq!(received[1], payload2);
}

#[test]
fn t_noise_handler_encrypted_frame_handling_should_encrypt_and_verify_frame_structure() {
    let mut h = handler();
    h.finish_init();
    let payload = b"test payload";
    let encoded = h.encode_frame(payload).unwrap();
    assert!(encoded.len() > payload.len() + 3);
    let encoded2 = h.encode_frame(b"second payload").unwrap();
    assert_eq!(encoded2[..3], [0, 0, (encoded2.len() - 3) as u8]);
}
#[test]
fn t_noise_handler_encrypted_frame_handling_should_produce_different_ciphertext_for_same_plaintext_due_to_counter() {
    let mut h = handler();
    h.finish_init();
    let payload = b"same payload";
    let encrypted1 = h.encrypt(payload).unwrap();
    let encrypted2 = h.encrypt(payload).unwrap();
    let encrypted3 = h.encrypt(payload).unwrap();
    assert_ne!(encrypted1, encrypted2);
    assert_ne!(encrypted2, encrypted3);
    assert_ne!(encrypted1, encrypted3);
}

#[test]
fn t_noise_handler_race_condition_scenario_concurrent_decodeframe_calls_should_handle_concurrent_decodeframe_calls_without_corrupting_inbytes_buffer() {
    // adapted: `Promise.all` over `decodeFrame`. `decode_frame` takes `&mut self`, so concurrent calls
    // can only come through a lock. These threads do that, as a socket with several readers would.
    let h = Arc::new(Mutex::new(handler()));
    let payloads: Vec<String> = (0..5).map(|i| format!("payload-{i}")).collect();
    let received: Arc<Mutex<Vec<String>>> = Arc::default();
    let threads: Vec<_> = payloads
        .iter()
        .map(|p| {
            let (h, received, frame) = (h.clone(), received.clone(), create_frame(p.as_bytes()));
            std::thread::spawn(move || {
                h.lock().unwrap().decode_frame(&frame, &mut |f| received.lock().unwrap().push(String::from_utf8(raw(f)).unwrap())).unwrap();
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    // All frames should be received
    let received = received.lock().unwrap();
    assert_eq!(received.len(), 5);
    // Verify all payloads are present (order may vary due to concurrency)
    for p in &payloads {
        assert!(received.contains(p));
    }
}
#[test]
fn t_noise_handler_race_condition_scenario_concurrent_decodeframe_calls_should_maintain_counter_integrity_with_many_frames_in_single_buffer() {
    let mut h = handler();
    // Create 10 frames to stress test the while loop
    let payloads: Vec<String> = (0..10).map(|i| format!("frame-{i}-payload-data")).collect();
    let combined: Vec<u8> = payloads.iter().flat_map(|p| create_frame(p.as_bytes())).collect();
    let mut received = Vec::new();
    h.decode_frame(&combined, &mut |f| received.push(raw(f))).unwrap();
    assert_eq!(received.len(), 10);
    for (i, p) in payloads.iter().enumerate() {
        assert_eq!(received[i], p.as_bytes());
    }
}

#[test]
fn t_noise_handler_encrypted_frame_race_condition_should_produce_different_ciphertext_for_same_plaintext_due_to_counter() {
    // Verify that encryption uses incrementing counters
    let mut h = handler();
    h.finish_init();
    let payload1 = b"message-1";
    let payload2 = b"message-2";
    let encrypted1 = h.encrypt(payload1).unwrap();
    let encrypted2 = h.encrypt(payload2).unwrap();
    assert_eq!(encrypted1.len(), payload1.len() + 16); // +16 for GCM tag
    assert_eq!(encrypted2.len(), payload2.len() + 16);
    // The encrypted data should be different (different counters used)
    assert_ne!(encrypted1, encrypted2);
}
#[test]
fn t_noise_handler_encrypted_frame_race_condition_should_serialize_concurrent_decodeframe_calls_fix_for_race_condition() {
    // adapted: `&mut self` serializes these calls, which is the lock this test checks. They run in
    // the order they are made, so the three calls are consecutive.
    let mut h = handler();
    let mut received_order = Vec::new();
    for p in ["first", "second", "third"] {
        h.decode_frame(&create_frame(p.as_bytes()), &mut |f| received_order.push(String::from_utf8(raw(f)).unwrap())).unwrap();
    }
    // With serialization, frames should be received in the order
    // the decodeFrame calls were made
    assert_eq!(received_order.len(), 3);
    assert_eq!(received_order[0], "first");
    assert_eq!(received_order[1], "second");
    assert_eq!(received_order[2], "third");
}
#[test]
fn t_noise_handler_encrypted_frame_race_condition_should_maintain_frame_order_with_interleaved_partial_frames_after_fix() {
    let mut h = handler();
    // Create a single frame split into parts
    let payload = b"complete-message-content";
    let frame = create_frame(payload);
    let mut received = Vec::new();
    // With serialization, these should be processed in order
    // and the frame should be correctly reassembled
    h.decode_frame(&frame[..10], &mut |f| received.push(raw(f))).unwrap();
    assert_eq!(received.len(), 0); // Not complete yet
    h.decode_frame(&frame[10..], &mut |f| received.push(raw(f))).unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], payload);
}
