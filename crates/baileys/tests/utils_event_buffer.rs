//! Port of Utils/event-buffer.test.ts.
use baileys::events::*;
use baileys::utils::event_buffer::{EventBuffer, make_event_buffer};
use baileys::utils::logger::SilentLogger;
use std::sync::{Arc, Mutex};
use waproto::history_sync::HistorySyncType;
use waproto::past_participant::LeaveReason;
use waproto::{PastParticipant, PastParticipants};

fn make_ev() -> (EventBuffer, Arc<Mutex<Vec<MessagingHistorySet>>>) {
    let ev = make_event_buffer(Arc::new(SilentLogger));
    let received = Arc::new(Mutex::new(Vec::new()));
    let r = received.clone();
    ev.on(
        EventKind::MessagingHistorySet,
        Arc::new(move |e: &BaileysEvent| {
            if let BaileysEvent::MessagingHistorySet(d) = e {
                r.lock().unwrap().push(d.clone());
            }
        }),
    );
    (ev, received)
}
fn entry(group: &str, user: &str, reason: i32, ts: u64) -> PastParticipants {
    PastParticipants::new().with_group_jid(group).with_past_participants(vec![PastParticipant::new().with_user_jid(user).with_leave_reason(LeaveReason(reason)).with_leave_ts(ts)])
}
fn history(past_participants: Option<Vec<PastParticipants>>, progress: f64) -> BaileysEvent {
    BaileysEvent::MessagingHistorySet(MessagingHistorySet {
        chats: Vec::new(),
        contacts: Vec::new(),
        messages: Vec::new(),
        past_participants: past_participants.map(Some),
        sync_type: Some(Some(HistorySyncType(0))),
        progress: Some(Some(progress)),
        is_latest: Some(false),
        peer_data_request_session_id: Some(None),
        ..MessagingHistorySet::default()
    })
}
#[test]
fn t_event_buffer_messaging_history_set_pastparticipants_buffering_should_include_pastparticipants_in_flushed_event() {
    let (ev, received) = make_ev();
    let past_participants = vec![entry("123456789012345678@g.us", "1234567890123@s.whatsapp.net", 1, 1700000000)];
    ev.buffer();
    ev.emit(history(Some(past_participants.clone()), 50.0));
    ev.flush();
    let r = received.lock().unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].past_participants, Some(Some(past_participants)));
}
#[test]
fn t_event_buffer_messaging_history_set_pastparticipants_buffering_should_accumulate_pastparticipants_across_multiple_buffered_events() {
    let (ev, received) = make_ev();
    let batch1 = vec![entry("111111111111111111@g.us", "1111111111111@s.whatsapp.net", 1, 1700000000)];
    let batch2 = vec![entry("222222222222222222@g.us", "2222222222222@s.whatsapp.net", 2, 1700000001)];
    ev.buffer();
    ev.emit(history(Some(batch1.clone()), 25.0));
    ev.emit(history(Some(batch2.clone()), 50.0));
    ev.flush();
    let r = received.lock().unwrap();
    assert_eq!(r.len(), 1);
    let got = r[0].past_participants.clone().unwrap().unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.contains(&batch1[0]));
    assert!(got.contains(&batch2[0]));
}
#[test]
fn t_event_buffer_messaging_history_set_pastparticipants_buffering_should_not_lose_pastparticipants_when_later_event_has_none() {
    let (ev, received) = make_ev();
    let batch1 = vec![entry("111111111111111111@g.us", "1111111111111@s.whatsapp.net", 1, 1700000000)];
    ev.buffer();
    ev.emit(history(Some(batch1.clone()), 25.0));
    // Second event has no pastParticipants
    ev.emit(history(None, 50.0));
    ev.flush();
    let r = received.lock().unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].past_participants, Some(Some(batch1)));
}
