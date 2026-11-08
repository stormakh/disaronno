//! Port of src/__tests__/Utils/sync-action-utils.test.ts.
use baileys::auth::LidMapping;
use baileys::proto::pb::Json;
use baileys::proto::sync_action_value::ContactAction;
use baileys::types::contact::Contact;
use baileys::utils::logger::{LogLevel, Logger, SilentLogger};
use baileys::utils::sync_action_utils::{SyncActionResult, process_contact_action};
use std::sync::{Arc, Mutex};

fn action(full_name: Option<&str>, lid_jid: Option<&str>, pn_jid: Option<&str>) -> ContactAction {
    let mut a = ContactAction::new();
    if let Some(v) = full_name {
        a.set_full_name(v);
    }
    if let Some(v) = lid_jid {
        a.set_lid_jid(v);
    }
    if let Some(v) = pn_jid {
        a.set_pn_jid(v);
    }
    a
}
fn contact(results: &[SyncActionResult]) -> &Contact {
    results
        .iter()
        .find_map(|r| match r {
            SyncActionResult::ContactsUpsert(d) => Some(&d[0]),
            _ => None,
        })
        .unwrap()
}
fn mapping(results: &[SyncActionResult]) -> Option<&LidMapping> {
    results.iter().find_map(|r| match r {
        SyncActionResult::LidMappingUpdate(d) => Some(d),
        _ => None,
    })
}
fn lid_mapping(lid: &str, pn: &str) -> SyncActionResult {
    SyncActionResult::LidMappingUpdate(LidMapping { lid: lid.to_string(), pn: pn.to_string() })
}
#[derive(Default)]
struct WarnLogger {
    warns: Mutex<Vec<(Option<Json>, String)>>,
}
impl Logger for WarnLogger {
    fn level(&self) -> LogLevel {
        LogLevel::Trace
    }
    fn child(&self, _bindings: &[(&str, &str)]) -> Arc<dyn Logger> {
        Arc::new(SilentLogger)
    }
    fn log(&self, level: LogLevel, obj: Option<&Json>, msg: &str) {
        if level == LogLevel::Warn {
            self.warns.lock().unwrap().push((obj.cloned(), msg.to_string()));
        }
    }
}

#[test]
fn t_processcontactaction_contacts_upsert_emits_with_phonenumber_from_id_when_id_is_pn_user() {
    let results = process_contact_action(&action(Some("John Doe"), Some("123456789@lid"), None), Some("5511999999999@s.whatsapp.net"), None);
    let mut expected = Contact::new("5511999999999@s.whatsapp.net");
    expected.name = Some("John Doe".to_string());
    expected.lid = Some("123456789@lid".to_string());
    expected.phone_number = Some("5511999999999@s.whatsapp.net".to_string());
    assert!(results.contains(&SyncActionResult::ContactsUpsert(vec![expected])));
}

#[test]
fn t_processcontactaction_contacts_upsert_uses_pnjid_as_phonenumber_fallback_when_id_is_lid_user() {
    let results = process_contact_action(&action(Some("John Doe"), None, Some("5511888888888@s.whatsapp.net")), Some("123456789@lid"), None);
    let mut expected = Contact::new("123456789@lid");
    expected.name = Some("John Doe".to_string());
    expected.phone_number = Some("5511888888888@s.whatsapp.net".to_string());
    assert!(results.contains(&SyncActionResult::ContactsUpsert(vec![expected])));
}

#[test]
fn t_processcontactaction_contacts_upsert_handles_undefined_fullname() {
    let results = process_contact_action(&action(None, Some("123456789@lid"), None), Some("5511999999999@s.whatsapp.net"), None);
    assert_eq!(contact(&results).name, None);
}

#[test]
fn t_processcontactaction_lid_mapping_update_emits_when_lid_and_pn_are_valid() {
    let results = process_contact_action(&action(Some("John Doe"), Some("123456789@lid"), None), Some("5511999999999@s.whatsapp.net"), None);
    assert!(results.contains(&lid_mapping("123456789@lid", "5511999999999@s.whatsapp.net")));
}

#[test]
fn t_processcontactaction_lid_mapping_update_handles_lid_with_device_id_suffix() {
    let results = process_contact_action(&action(Some("Contact"), Some("173233882013816:99@lid"), None), Some("5511999999999@s.whatsapp.net"), None);
    assert!(results.contains(&lid_mapping("173233882013816:99@lid", "5511999999999@s.whatsapp.net")));
}

#[test]
fn t_processcontactaction_lid_mapping_update_does_not_emit_when_lidjid_is_missing() {
    let results = process_contact_action(&action(Some("John Doe"), None, None), Some("5511999999999@s.whatsapp.net"), None);
    assert!(mapping(&results).is_none());
}

#[test]
fn t_processcontactaction_lid_mapping_update_does_not_emit_when_id_is_lid_user_not_pn() {
    let results = process_contact_action(&action(Some("John Doe"), Some("123456789@lid"), None), Some("987654321@lid"), None);
    assert!(mapping(&results).is_none());
}

#[test]
fn t_processcontactaction_lid_mapping_update_does_not_emit_when_lidjid_is_invalid_format() {
    let results = process_contact_action(&action(Some("John Doe"), Some("invalid-lid-format"), None), Some("5511999999999@s.whatsapp.net"), None);
    assert!(mapping(&results).is_none());
}

#[test]
fn t_processcontactaction_lid_mapping_update_does_not_emit_for_group_jids() {
    let results = process_contact_action(&action(Some("Group"), Some("123456789@lid"), None), Some("123456789012345678@g.us"), None);
    assert!(mapping(&results).is_none());
}

#[test]
fn t_processcontactaction_missing_id_returns_empty_array_and_logs_warning_when_id_is_undefined() {
    let logger = WarnLogger::default();
    let results = process_contact_action(&action(Some("John Doe"), Some("123456789@lid"), None), None, Some(&logger));
    assert!(results.is_empty());
    let warns = logger.warns.lock().unwrap();
    assert_eq!(warns.len(), 1);
    let expected = Json::Obj(vec![("hasFullName".to_string(), Json::Bool(true)), ("hasLidJid".to_string(), Json::Bool(true)), ("hasPnJid".to_string(), Json::Bool(false))]);
    assert_eq!(warns[0].0.as_ref(), Some(&expected));
    assert_eq!(warns[0].1, "contactAction sync: missing id in index");
}

#[test]
fn t_processcontactaction_missing_id_returns_empty_array_when_id_is_empty_string() {
    let logger = WarnLogger::default();
    let results = process_contact_action(&action(Some("John Doe"), Some("123456789@lid"), None), Some(""), Some(&logger));
    assert!(results.is_empty());
}

#[test]
fn t_processcontactaction_pn_extraction_from_index_1_pnjid_is_always_null_extracts_pn_from_id_when_pnjid_is_null() {
    // In real WhatsApp data, pnJid is ALWAYS null - PN comes from index[1]
    let results = process_contact_action(&action(Some("Test Contact"), Some("111222333@lid"), None), Some("5599887766@s.whatsapp.net"), None);
    let c = contact(&results);
    assert_eq!(c.phone_number.as_deref(), Some("5599887766@s.whatsapp.net"));
    assert_eq!(c.lid.as_deref(), Some("111222333@lid"));
    assert_eq!(mapping(&results), Some(&LidMapping { lid: "111222333@lid".to_string(), pn: "5599887766@s.whatsapp.net".to_string() }));
}

#[test]
fn t_processcontactaction_pn_extraction_from_index_1_pnjid_is_always_null_prefers_id_over_pnjid_when_id_is_pn_user() {
    let results = process_contact_action(&action(Some("Test"), Some("111222333@lid"), Some("1111111111@s.whatsapp.net")), Some("9999999999@s.whatsapp.net"), None);
    assert_eq!(contact(&results).phone_number.as_deref(), Some("9999999999@s.whatsapp.net"));
    assert_eq!(mapping(&results).unwrap().pn, "9999999999@s.whatsapp.net");
}
