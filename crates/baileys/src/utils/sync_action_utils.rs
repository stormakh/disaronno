//! Same behavior as Utils/sync-action-utils.ts.
use crate::auth::LidMapping;
use crate::events::{BaileysEvent, BaileysEventEmitter};
use crate::types::contact::Contact;
use crate::utils::logger::{LogLevel, Logger};
use crate::wabinary::{is_lid_user, is_pn_user};
use waproto::pb::{Json, Str};
use waproto::sync_action_value::ContactAction;

#[derive(Clone, Debug, PartialEq)]
pub enum SyncActionResult {
    ContactsUpsert(Vec<Contact>),
    LidMappingUpdate(LidMapping),
}
fn truthy(s: Option<&Str>) -> Option<&str> {
    s.map(|v| v.as_str()).filter(|v| !v.is_empty())
}
/// Process contactAction and return events to emit.
/// Pure function - no side effects.
pub fn process_contact_action(action: &ContactAction, id: Option<&str>, logger: Option<&dyn Logger>) -> Vec<SyncActionResult> {
    let Some(id) = id.filter(|i| !i.is_empty()) else {
        if let Some(l) = logger.filter(|l| l.is_enabled(LogLevel::Warn)) {
            let obj = Json::Obj(vec![
                ("hasFullName".to_string(), Json::Bool(truthy(action.full_name()).is_some())),
                ("hasLidJid".to_string(), Json::Bool(truthy(action.lid_jid()).is_some())),
                ("hasPnJid".to_string(), Json::Bool(truthy(action.pn_jid()).is_some())),
            ]);
            l.warn_obj(&obj, "contactAction sync: missing id in index");
        }
        return Vec::new();
    };
    let lid_jid = truthy(action.lid_jid());
    let id_is_pn = is_pn_user(id);
    // PN is in index[1], not in contactAction.pnJid which is usually null
    let phone_number = if id_is_pn { Some(id) } else { truthy(action.pn_jid()) };
    let mut contact = Contact::new(id);
    contact.name = truthy(action.full_name()).or(truthy(action.first_name())).or(truthy(action.username())).map(str::to_string);
    contact.username = truthy(action.username()).map(str::to_string);
    contact.lid = lid_jid.map(str::to_string);
    contact.phone_number = phone_number.map(str::to_string);
    // Always emit contacts.upsert
    let mut results = vec![SyncActionResult::ContactsUpsert(vec![contact])];
    // Emit lid-mapping.update if we have valid LID-PN pair
    if let Some(lid) = lid_jid.filter(|l| is_lid_user(l) && id_is_pn) {
        results.push(SyncActionResult::LidMappingUpdate(LidMapping { lid: lid.to_string(), pn: id.to_string() }));
    }
    results
}
pub fn emit_sync_action_results(ev: &dyn BaileysEventEmitter, results: Vec<SyncActionResult>) {
    for result in results {
        match result {
            SyncActionResult::ContactsUpsert(data) => ev.emit(BaileysEvent::ContactsUpsert(data)),
            SyncActionResult::LidMappingUpdate(data) => ev.emit(BaileysEvent::LidMappingUpdate(data)),
        };
    }
}
