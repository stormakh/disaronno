//! Port of src/__tests__/Utils/process-sync-action.test.ts.
use baileys::auth::{AccountSettings, CredsUpdate, LidMapping};
use baileys::events::*;
use baileys::proto::pb::{Json, PbMessage};
use baileys::proto::sync_action_value::*;
use baileys::proto::{MessageKey, SyncActionData, SyncActionValue, WebMessageInfo};
use baileys::types::chat::{ChatMutation, ChatUpdate, InitialAppStateSyncOptions};
use baileys::types::contact::Contact;
use baileys::types::label::{ChatLabelAssociation, Label, LabelAssociation, LabelAssociationType, MessageLabelAssociation};
use baileys::types::message::WAMessageUpdate;
use baileys::utils::chat_utils::process_sync_action;
use baileys::utils::logger::{LogLevel, Logger, SilentLogger};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MockEmitter {
    emitted: Mutex<Vec<BaileysEvent>>,
}
impl BaileysEventEmitter for MockEmitter {
    fn on(&self, _event: EventKind, _listener: Listener) -> ListenerId {
        ListenerId(0)
    }
    fn off(&self, _event: EventKind, _listener: ListenerId) {}
    fn remove_all_listeners(&self, _event: EventKind) {}
    fn emit(&self, event: BaileysEvent) -> bool {
        self.emitted.lock().unwrap().push(event);
        true
    }
}
impl MockEmitter {
    fn events(&self) -> Vec<BaileysEvent> {
        self.emitted.lock().unwrap().clone()
    }
    fn chat_update(&self) -> ChatUpdate {
        let events = self.events();
        let found = events.iter().find_map(|e| match e {
            BaileysEvent::ChatsUpdate(u) => Some(u[0].clone()),
            _ => None,
        });
        found.expect("chats.update must be emitted")
    }
}
#[derive(Default)]
struct MockLogger {
    debugs: Mutex<Vec<(Option<Json>, String)>>,
}
impl Logger for MockLogger {
    fn level(&self) -> LogLevel {
        LogLevel::Trace
    }
    fn child(&self, _bindings: &[(&str, &str)]) -> Arc<dyn Logger> {
        Arc::new(SilentLogger)
    }
    fn log(&self, level: LogLevel, obj: Option<&Json>, msg: &str) {
        if level == LogLevel::Debug {
            self.debugs.lock().unwrap().push((obj.cloned(), msg.to_string()));
        }
    }
}
fn create_sync_action(action: SyncActionValue, index: &[&str]) -> ChatMutation {
    ChatMutation { sync_action: SyncActionData::new().with_value(action), index: index.iter().map(|s| s.to_string()).collect() }
}
fn value() -> SyncActionValue {
    SyncActionValue::new()
}
fn mock_me() -> Contact {
    let mut c = Contact::new("me@s.whatsapp.net");
    c.name = Some("Test User".to_string());
    c
}
fn initial_sync() -> InitialAppStateSyncOptions {
    InitialAppStateSyncOptions { account_settings: AccountSettings { unarchive_chats: false, default_disappearing_mode: None } }
}
/// Runs the action with `processSyncAction(syncAction, ev, mockMe, undefined, logger)`.
fn run(action: SyncActionValue, index: &[&str]) -> MockEmitter {
    let ev = MockEmitter::default();
    let logger = MockLogger::default();
    process_sync_action(&create_sync_action(action, index), &ev, Some(&mock_me()), None, Some(&logger));
    ev
}
fn run_initial(action: SyncActionValue, index: &[&str]) -> MockEmitter {
    let ev = MockEmitter::default();
    let logger = MockLogger::default();
    let mut opts = initial_sync();
    process_sync_action(&create_sync_action(action, index), &ev, Some(&mock_me()), Some(&mut opts), Some(&logger));
    ev
}
fn key(remote_jid: &str, id: &str, from_me: bool) -> MessageKey {
    MessageKey::new().with_remote_jid(remote_jid).with_id(id).with_from_me(from_me)
}

#[test]
fn t_processsyncaction_muteaction_emits_chats_update_with_muteendtime_when_muted() {
    let ev = run(value().with_mute_action(MuteAction::new().with_muted(true).with_mute_end_timestamp(1700000000i64)), &["mute", "chat123@s.whatsapp.net"]);
    let u = ev.chat_update();
    assert_eq!(u.id().map(|s| s.as_str()), Some("chat123@s.whatsapp.net"));
    assert_eq!(u.mute_end_time(), Some(1700000000));
}

#[test]
fn t_processsyncaction_muteaction_emits_null_muteendtime_when_unmuted() {
    let ev = run(value().with_mute_action(MuteAction::new().with_muted(false).with_mute_end_timestamp(0i64)), &["mute", "chat123@s.whatsapp.net"]);
    assert!(ev.chat_update().mute_end_time_is_null());
}

#[test]
fn t_processsyncaction_archivechataction_emits_chats_update_with_archived_true_false() {
    let ev = run(value().with_archive_chat_action(ArchiveChatAction::new().with_archived(true)), &["archive", "chat@s.whatsapp.net"]);
    assert_eq!(ev.chat_update().archived(), Some(true));
}

#[test]
fn t_processsyncaction_archivechataction_handles_type_fallback_without_archivechataction() {
    let ev = run(value(), &["archive", "chat@s.whatsapp.net"]);
    assert_eq!(ev.chat_update().archived(), Some(true));
}

#[test]
fn t_processsyncaction_markchatasreadaction_emits_unreadcount_0_when_read_is_true() {
    let ev = run(value().with_mark_chat_as_read_action(MarkChatAsReadAction::new().with_read(true)), &["markRead", "chat@s.whatsapp.net"]);
    assert_eq!(ev.chat_update().unread_count(), Some(0));
}

#[test]
fn t_processsyncaction_markchatasreadaction_emits_unreadcount_1_when_read_is_false() {
    let ev = run(value().with_mark_chat_as_read_action(MarkChatAsReadAction::new().with_read(false)), &["markRead", "chat@s.whatsapp.net"]);
    assert_eq!(ev.chat_update().unread_count(), Some(-1));
}

#[test]
fn t_processsyncaction_markchatasreadaction_emits_null_unreadcount_during_initial_sync_when_already_read() {
    let ev = run_initial(value().with_mark_chat_as_read_action(MarkChatAsReadAction::new().with_read(true)), &["markRead", "chat@s.whatsapp.net"]);
    assert!(ev.chat_update().unread_count_is_null());
}

#[test]
fn t_processsyncaction_deletemessageformeaction_emits_messages_delete_with_correct_key() {
    let ev = run(value().with_delete_message_for_me_action(DeleteMessageForMeAction::new().with_delete_media(false)), &["deleteMessageForMe", "chat@s.whatsapp.net", "msg456", "1"]);
    assert!(ev.events().contains(&BaileysEvent::MessagesDelete(MessagesDelete::Keys(vec![key("chat@s.whatsapp.net", "msg456", true)]))));
}

#[test]
fn t_processsyncaction_contactaction_emits_contacts_upsert_and_lid_mapping_update_for_pn_user_with_lid() {
    let ev = run(value().with_contact_action(ContactAction::new().with_full_name("John").with_lid_jid("123@lid")), &["contact", "5511999@s.whatsapp.net"]);
    let mut c = Contact::new("5511999@s.whatsapp.net");
    c.name = Some("John".to_string());
    c.lid = Some("123@lid".to_string());
    c.phone_number = Some("5511999@s.whatsapp.net".to_string());
    assert!(ev.events().contains(&BaileysEvent::ContactsUpsert(vec![c])));
    assert!(ev.events().contains(&BaileysEvent::LidMappingUpdate(LidMapping { lid: "123@lid".to_string(), pn: "5511999@s.whatsapp.net".to_string() })));
}

#[test]
fn t_processsyncaction_contactaction_does_not_emit_events_when_id_is_missing() {
    let ev = run(value().with_contact_action(ContactAction::new().with_full_name("John").with_lid_jid("123@lid")), &["contact", ""]);
    assert_eq!(ev.events().iter().filter(|e| e.kind() == EventKind::ContactsUpsert).count(), 0);
}

#[test]
fn t_processsyncaction_pushnamesetting_emits_creds_update_when_name_differs() {
    let ev = run(value().with_push_name_setting(PushNameSetting::new().with_name("New")), &["pushName"]);
    let mut me = mock_me();
    me.name = Some("New".to_string());
    assert!(ev.events().contains(&BaileysEvent::CredsUpdate(Box::new(CredsUpdate { me: Some(Some(me)), ..CredsUpdate::default() }))));
}

#[test]
fn t_processsyncaction_pushnamesetting_does_not_emit_when_name_is_same_or_empty() {
    let ev = run(value().with_push_name_setting(PushNameSetting::new().with_name("Test User")), &["pushName"]);
    assert!(ev.events().is_empty());
}

#[test]
fn t_processsyncaction_pinaction_emits_chats_update_with_pinned_timestamp_or_null() {
    let ev = run(value().with_pin_action(PinAction::new().with_pinned(true)).with_timestamp(1700000000i64), &["pin", "chat@s.whatsapp.net"]);
    assert_eq!(ev.chat_update().pinned(), Some(1700000000));
}

#[test]
fn t_processsyncaction_staraction_emits_messages_update_with_starred_value() {
    let ev = run(value().with_star_action(StarAction::new().with_starred(true)), &["star", "chat@s.whatsapp.net", "msg", "1"]);
    let expected = WAMessageUpdate { key: key("chat@s.whatsapp.net", "msg", true), update: WebMessageInfo::new().with_starred(true) };
    assert!(ev.events().contains(&BaileysEvent::MessagesUpdate(vec![expected])));
}

#[test]
fn t_processsyncaction_deletechataction_emits_chats_delete_when_not_initial_sync() {
    let ev = run(value().with_delete_chat_action(DeleteChatAction::new()), &["deleteChat", "chat@s.whatsapp.net"]);
    assert!(ev.events().contains(&BaileysEvent::ChatsDelete(vec!["chat@s.whatsapp.net".to_string()])));
}

#[test]
fn t_processsyncaction_deletechataction_does_not_emit_during_initial_sync() {
    let ev = run_initial(value().with_delete_chat_action(DeleteChatAction::new()), &["deleteChat", "chat@s.whatsapp.net"]);
    assert!(ev.events().is_empty());
}

#[test]
fn t_processsyncaction_labeleditaction_emits_labels_edit() {
    let ev = run(value().with_label_edit_action(LabelEditAction::new().with_name("Important").with_color(1).with_deleted(false).with_predefined_id(5)), &["label", "label123"]);
    let expected = Label { id: "label123".to_string(), name: "Important".to_string(), color: 1, deleted: false, predefined_id: Some("5".to_string()) };
    assert!(ev.events().contains(&BaileysEvent::LabelsEdit(expected)));
}

#[test]
fn t_processsyncaction_labelassociationaction_emits_labels_association_for_chat_label() {
    let ev = run(value().with_label_association_action(LabelAssociationAction::new().with_labeled(true)), &[LabelAssociationType::Chat.as_str(), "label123", "chat@s.whatsapp.net"]);
    let association = LabelAssociation::Chat(ChatLabelAssociation { chat_id: "chat@s.whatsapp.net".to_string(), label_id: "label123".to_string() });
    assert!(ev.events().contains(&BaileysEvent::LabelsAssociation { association, r#type: ListUpdateType::Add }));
}

#[test]
fn t_processsyncaction_labelassociationaction_emits_labels_association_for_message_label() {
    let ev = run(value().with_label_association_action(LabelAssociationAction::new().with_labeled(true)), &[LabelAssociationType::Message.as_str(), "label123", "chat@s.whatsapp.net", "msg789"]);
    let association = LabelAssociation::Message(MessageLabelAssociation { chat_id: "chat@s.whatsapp.net".to_string(), message_id: "msg789".to_string(), label_id: "label123".to_string() });
    assert!(ev.events().contains(&BaileysEvent::LabelsAssociation { association, r#type: ListUpdateType::Add }));
}

#[test]
fn t_processsyncaction_pnforlidchataction_emits_lid_mapping_update_when_pnjid_is_present() {
    let ev = run(value().with_pn_for_lid_chat_action(PnForLidChatAction::new().with_pn_jid("5511999@s.whatsapp.net")), &["pnForLid", "123@lid"]);
    assert!(ev.events().contains(&BaileysEvent::LidMappingUpdate(LidMapping { lid: "123@lid".to_string(), pn: "5511999@s.whatsapp.net".to_string() })));
}

#[test]
fn t_processsyncaction_pnforlidchataction_does_not_emit_when_pnjid_is_missing() {
    let ev = run(value().with_pn_for_lid_chat_action(PnForLidChatAction::new().with_pn_jid("")), &["pnForLid", "123@lid"]);
    assert!(ev.events().is_empty());
}

#[test]
fn t_processsyncaction_lockchataction_emits_chats_lock() {
    let ev = run(value().with_lock_chat_action(LockChatAction::new().with_locked(true)), &["lockChat", "chat@s.whatsapp.net"]);
    assert!(ev.events().contains(&BaileysEvent::ChatsLock { id: "chat@s.whatsapp.net".to_string(), locked: true }));
}

#[test]
fn t_processsyncaction_lidcontactaction_emits_contacts_upsert_with_lid_contact() {
    let ev = run(value().with_lid_contact_action(LidContactAction::new().with_full_name("LID Contact")), &["lidContact", "123@lid"]);
    let mut c = Contact::new("123@lid");
    c.name = Some("LID Contact".to_string());
    c.lid = Some("123@lid".to_string());
    assert!(ev.events().contains(&BaileysEvent::ContactsUpsert(vec![c])));
}

#[test]
fn t_processsyncaction_settings_actions_localesetting_emits_settings_update() {
    let ev = run(value().with_locale_setting(LocaleSetting::new().with_locale("en-US")), &["locale"]);
    assert!(ev.events().contains(&BaileysEvent::SettingsUpdate(SettingsUpdate::Locale("en-US".to_string()))));
}

#[test]
fn t_processsyncaction_settings_actions_unarchivechatssetting_emits_creds_update() {
    let ev = run(value().with_unarchive_chats_setting(UnarchiveChatsSetting::new().with_unarchive_chats(true)), &["unarchiveChats"]);
    let update = CredsUpdate { account_settings: Some(AccountSettings { unarchive_chats: true, default_disappearing_mode: None }), ..CredsUpdate::default() };
    assert!(ev.events().contains(&BaileysEvent::CredsUpdate(Box::new(update))));
}

#[test]
fn t_processsyncaction_unprocessable_actions_logs_debug_for_unknown_action() {
    // adapted: `unknownAction` is not a proto field, and the decoder drops unknown fields, so the value has no known action
    let sync_action = create_sync_action(value(), &["unknown", "id123"]);
    let ev = MockEmitter::default();
    let logger = MockLogger::default();
    process_sync_action(&sync_action, &ev, Some(&mock_me()), None, Some(&logger));
    let debugs = logger.debugs.lock().unwrap();
    assert_eq!(debugs.len(), 1);
    let index = Json::Arr(sync_action.index.iter().map(|s| Json::Str(s.clone())).collect());
    let mutation = Json::Obj(vec![("syncAction".to_string(), sync_action.sync_action.to_json()), ("index".to_string(), index)]);
    let expected = Json::Obj(vec![("syncAction".to_string(), mutation), ("id".to_string(), Json::Str("id123".to_string()))]);
    assert_eq!(debugs[0].0.as_ref(), Some(&expected));
    assert_eq!(debugs[0].1, "unprocessable update");
    assert!(ev.events().is_empty());
}
