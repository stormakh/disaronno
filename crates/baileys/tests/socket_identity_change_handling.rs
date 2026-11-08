//! Port of src/__tests__/Socket/identity-change-handling.test.ts.
use baileys::error::{Boom, Result};
use baileys::signal::repository::SessionValidation;
use baileys::utils::identity_change_handler::{IdentityChangeContext, handle_identity_change};
use baileys::utils::logger::SilentLogger;
use baileys::utils::node_cache::NodeCache;
use baileys::wabinary::{Attrs, BinaryNode};
use std::sync::{Arc, Mutex};

const ME_ID: &str = "myuser@s.whatsapp.net";
const ME_LID: &str = "mylid@lid";

/// In place of the Jest mocks: the return value can change, and the calls are recorded.
struct Mocks {
    validate: Arc<Mutex<Result<SessionValidation>>>,
    validate_calls: Arc<Mutex<Vec<String>>>,
    assert: Arc<Mutex<Result<bool>>>,
    assert_calls: Arc<Mutex<Vec<(Vec<String>, bool)>>>,
    order: Arc<Mutex<Vec<String>>>,
    cache: Arc<NodeCache>,
}
fn exists(v: bool) -> Result<SessionValidation> {
    Ok(SessionValidation { exists: v, reason: None })
}
impl Mocks {
    fn new() -> Mocks {
        Mocks {
            // an unset jest.fn() returns undefined, so a test that reaches it would fail
            validate: Arc::new(Mutex::new(Err(Boom::new("validateSession has no mock value")))),
            validate_calls: Arc::default(),
            assert: Arc::new(Mutex::new(Err(Boom::new("assertSessions has no mock value")))),
            assert_calls: Arc::default(),
            order: Arc::default(),
            cache: Arc::new(NodeCache::new(5)),
        }
    }
    fn set_validate(&self, v: Result<SessionValidation>) {
        *self.validate.lock().unwrap() = v;
    }
    fn set_assert(&self, v: Result<bool>) {
        *self.assert.lock().unwrap() = v;
    }
    fn ctx(&self) -> IdentityChangeContext {
        let (validate, validate_calls) = (self.validate.clone(), self.validate_calls.clone());
        let (assert, assert_calls, order) = (self.assert.clone(), self.assert_calls.clone(), self.order.clone());
        IdentityChangeContext {
            me_id: Some(ME_ID.to_string()),
            me_lid: Some(ME_LID.to_string()),
            validate_session: Arc::new(move |jid| {
                validate_calls.lock().unwrap().push(jid.to_string());
                validate.lock().unwrap().clone()
            }),
            assert_sessions: Arc::new(move |jids, force| {
                assert_calls.lock().unwrap().push((jids.to_vec(), force));
                order.lock().unwrap().push("assertSessions".to_string());
                assert.lock().unwrap().clone()
            }),
            debounce_cache: self.cache.clone(),
            logger: Arc::new(SilentLogger),
            on_before_session_refresh: None,
        }
    }
    fn validate_count(&self) -> usize {
        self.validate_calls.lock().unwrap().len()
    }
    fn assert_count(&self) -> usize {
        self.assert_calls.lock().unwrap().len()
    }
}
fn identity_change_node(from: &str, offline: Option<&str>) -> BinaryNode {
    let mut attrs = Attrs::from([("from", from), ("type", "encrypt")]);
    if let Some(o) = offline {
        attrs.set("offline", o);
    }
    BinaryNode::with_nodes("notification", attrs, vec![BinaryNode::with_bytes("identity", Attrs::new(), b"test-identity-key".to_vec())])
}

#[test]
fn t_identity_change_handling_core_checks_should_skip_companion_devices_device_0() {
    let m = Mocks::new();
    let r = handle_identity_change(&identity_change_node("user:5@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(m.validate_count(), 0);
    assert_eq!(r.action(), "skipped_companion_device");
}
#[test]
fn t_identity_change_handling_core_checks_should_process_primary_device_device_0_or_undefined() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    m.set_assert(Ok(true));
    let r = handle_identity_change(&identity_change_node("user@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(r.action(), "session_refreshed");
}
#[test]
fn t_identity_change_handling_core_checks_should_skip_self_primary_identity_pn_match() {
    let m = Mocks::new();
    let r = handle_identity_change(&identity_change_node("myuser@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(m.validate_count(), 0);
    assert_eq!(r.action(), "skipped_self_primary");
}
#[test]
fn t_identity_change_handling_core_checks_should_skip_self_primary_identity_lid_match() {
    let m = Mocks::new();
    let r = handle_identity_change(&identity_change_node("mylid@lid", None), &m.ctx()).unwrap();
    assert_eq!(m.validate_count(), 0);
    assert_eq!(r.action(), "skipped_self_primary");
}
#[test]
fn t_identity_change_handling_core_checks_should_skip_when_no_existing_session() {
    let m = Mocks::new();
    m.set_validate(exists(false));
    let r = handle_identity_change(&identity_change_node("user@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(m.assert_count(), 0);
    assert_eq!(r.action(), "skipped_no_session");
}
#[test]
fn t_identity_change_handling_core_checks_should_skip_session_refresh_during_offline_processing() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    let r = handle_identity_change(&identity_change_node("user@s.whatsapp.net", Some("0")), &m.ctx()).unwrap();
    assert_eq!(m.assert_count(), 0);
    assert_eq!(r.action(), "skipped_offline");
}
#[test]
fn t_identity_change_handling_core_checks_should_refresh_session_when_online_with_existing_session() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    m.set_assert(Ok(true));
    let r = handle_identity_change(&identity_change_node("user@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(m.assert_calls.lock().unwrap().as_slice(), &[(vec!["user@s.whatsapp.net".to_string()], true)]);
    assert_eq!(r.action(), "session_refreshed");
}

#[test]
fn t_identity_change_handling_debounce_should_debounce_multiple_identity_changes_for_the_same_jid() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    m.set_assert(Ok(true));
    let node = identity_change_node("user@s.whatsapp.net", None);
    let r1 = handle_identity_change(&node, &m.ctx()).unwrap();
    assert_eq!(r1.action(), "session_refreshed");
    let r2 = handle_identity_change(&node, &m.ctx()).unwrap();
    assert_eq!(r2.action(), "debounced");
    assert_eq!(m.assert_count(), 1);
}
#[test]
fn t_identity_change_handling_debounce_should_allow_different_jids_to_process_independently() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    m.set_assert(Ok(true));
    let r1 = handle_identity_change(&identity_change_node("user1@s.whatsapp.net", None), &m.ctx()).unwrap();
    let r2 = handle_identity_change(&identity_change_node("user2@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(r1.action(), "session_refreshed");
    assert_eq!(r2.action(), "session_refreshed");
    assert_eq!(m.assert_count(), 2);
}

#[test]
fn t_identity_change_handling_error_handling_should_handle_assertsessions_failure_gracefully() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    let test_error = Boom::new("Session assertion failed");
    m.set_assert(Err(test_error.clone()));
    let r = handle_identity_change(&identity_change_node("user@s.whatsapp.net", None), &m.ctx()).unwrap();
    assert_eq!(r.action(), "session_refresh_failed");
    match r {
        baileys::utils::identity_change_handler::IdentityChangeResult::SessionRefreshFailed { error } => assert_eq!(error, test_error),
        other => panic!("unexpected result {other:?}"),
    }
}
#[test]
fn t_identity_change_handling_error_handling_should_propagate_validatesession_errors() {
    let m = Mocks::new();
    m.set_validate(Err(Boom::new("Database error")));
    let e = handle_identity_change(&identity_change_node("user@s.whatsapp.net", None), &m.ctx()).unwrap_err();
    assert!(e.message.contains("Database error"));
}

#[test]
fn t_identity_change_handling_edge_cases_should_return_invalid_notification_when_from_is_missing() {
    let m = Mocks::new();
    let node = BinaryNode::with_nodes("notification", Attrs::from([("type", "encrypt")]), vec![BinaryNode::with_bytes("identity", Attrs::new(), b"key".to_vec())]);
    let r = handle_identity_change(&node, &m.ctx()).unwrap();
    assert_eq!(r.action(), "invalid_notification");
}
#[test]
fn t_identity_change_handling_edge_cases_should_return_no_identity_node_when_identity_child_is_missing() {
    let m = Mocks::new();
    let node = BinaryNode::with_nodes("notification", Attrs::from([("from", "user@s.whatsapp.net"), ("type", "encrypt")]), vec![]);
    let r = handle_identity_change(&node, &m.ctx()).unwrap();
    assert_eq!(r.action(), "no_identity_node");
}
#[test]
fn t_identity_change_handling_edge_cases_should_handle_lid_jids_correctly() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    m.set_assert(Ok(true));
    let r = handle_identity_change(&identity_change_node("12345@lid", None), &m.ctx()).unwrap();
    assert_eq!(m.validate_calls.lock().unwrap().as_slice(), &["12345@lid".to_string()]);
    assert_eq!(r.action(), "session_refreshed");
}

#[test]
fn t_identity_change_handling_onbeforesessionrefresh_callback_fires_before_assertsessions_when_a_session_refresh_is_about_to_run() {
    let m = Mocks::new();
    m.set_validate(exists(true));
    m.set_assert(Ok(true));
    let order = m.order.clone();
    let mut ctx = m.ctx();
    ctx.on_before_session_refresh = Some(Arc::new(move |jid| order.lock().unwrap().push(format!("before:{jid}"))));
    let r = handle_identity_change(&identity_change_node("user@s.whatsapp.net", None), &ctx).unwrap();
    assert_eq!(r.action(), "session_refreshed");
    assert_eq!(m.order.lock().unwrap().as_slice(), &["before:user@s.whatsapp.net".to_string(), "assertSessions".to_string()]);
}
#[test]
fn t_identity_change_handling_onbeforesessionrefresh_callback_does_not_fire_when_the_refresh_is_skipped_no_session_offline_self() {
    let m = Mocks::new();
    let calls: Arc<Mutex<u32>> = Arc::default();
    let with_callback = || {
        let c = calls.clone();
        let mut ctx = m.ctx();
        ctx.on_before_session_refresh = Some(Arc::new(move |_| *c.lock().unwrap() += 1));
        ctx
    };
    // no session
    m.set_validate(exists(false));
    handle_identity_change(&identity_change_node("a@s.whatsapp.net", None), &with_callback()).unwrap();
    // offline
    m.set_validate(exists(true));
    handle_identity_change(&identity_change_node("b@s.whatsapp.net", Some("0")), &with_callback()).unwrap();
    // self-primary
    handle_identity_change(&identity_change_node(ME_ID, None), &with_callback()).unwrap();

    assert_eq!(*calls.lock().unwrap(), 0);
}
