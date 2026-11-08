//! Tool for `scripts/e2e.mjs`: runs one socket and takes JSON commands on stdin, one per line.
//! Each event and reply goes to stdout as one line of JSON. It is not part of the library.
use baileys::auth::{KeyKind, KeyValue};
use baileys::defaults::default_connection_config;
use baileys::events::{BaileysEvent, BaileysEventEmitter, EventKind};
use baileys::socket::{Socket, make_wa_socket};
use baileys::types::*;
use baileys::utils::logger::SilentLogger;
use baileys::utils::use_multi_file_auth_state::{MultiFileAuthState, use_multi_file_auth_state};
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};
use waproto::message::AppStateSyncKeyData;
use waproto::pb::{Json, base64_decode};

fn out(fields: Vec<(&str, Json)>) {
    let line = Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect()).stringify();
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(line.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}
fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}
fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, |d| d.count())
}
fn text_of(m: &WAMessage) -> Option<String> {
    let c = m.message()?;
    let c = baileys::utils::messages::normalize_message_content(Some(c))?;
    c.conversation().map(|t| t.as_str().to_string()).or_else(|| c.extended_text_message().and_then(|e| e.text()).map(|t| t.as_str().to_string()))
}
/// What the owner of a client keeps in a store: the sent messages, for `get_message`.
fn sent() -> &'static Mutex<Vec<(String, waproto::Message)>> {
    static SENT: Mutex<Vec<(String, waproto::Message)>> = Mutex::new(Vec::new());
    &SENT
}
fn start(cmd: &Json, auth: &Arc<MultiFileAuthState>) -> Socket {
    let text = |k: &str| cmd.get(k).and_then(Json::as_str).unwrap_or_default().to_string();
    let mut config = default_connection_config();
    config.logger = Arc::new(SilentLogger);
    config.auth = Some(auth.state.clone());
    config.wa_web_socket_url = text("url");
    let root = text("root");
    for (i, b) in config.wa_cert_public_key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&root[i * 2..i * 2 + 2], 16).expect("hex root key");
    }
    config.should_sync_history_message = Arc::new(|_| false);
    config.get_message = Arc::new(|k: &WAMessageKey| {
        let id = k.id()?.as_str().to_string();
        sent().lock().unwrap().iter().find(|(i, _)| *i == id).map(|(_, m)| m.clone())
    });
    config.app_state_mac_verification = AppStateMacVerification { patch: true, snapshot: true };
    config.keep_alive_interval_ms = cmd.get("keepalive").and_then(Json::as_f64).unwrap_or(30000.0) as u64;
    config.push_name = cmd.get("push_name").and_then(Json::as_str).map(str::to_string);
    let sock = make_wa_socket(config).expect("config");
    let saver = auth.clone();
    sock.ev.on(EventKind::CredsUpdate, Arc::new(move |_: &BaileysEvent| saver.save_creds().expect("save creds")));
    sock.ev.on(
        EventKind::ConnectionUpdate,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::ConnectionUpdate(u) = e else { return };
            if let Some(Some(qr)) = &u.qr {
                out(vec![("ev", s("qr")), ("qr", s(qr))]);
            }
            if let Some(c) = u.connection {
                let mut f = vec![("ev", s("conn")), ("state", s(c.as_str()))];
                if let Some(err) = u.last_disconnect.as_ref().and_then(|d| d.error.as_ref()) {
                    f.push(("code", Json::Num(err.output_status_code() as f64)));
                    f.push(("error", s(&err.message)));
                }
                out(f);
            }
            if u.received_pending_notifications == Some(true) {
                out(vec![("ev", s("pending"))]);
            }
        }),
    );
    sock.ev.on(
        EventKind::MessagesUpsert,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::MessagesUpsert(u) = e else { return };
            for m in &u.messages {
                let k = m.key();
                let mut f = vec![
                    ("ev", s("msg")),
                    ("type", s(u.r#type.as_str())),
                    ("id", s(k.and_then(|k| k.id()).map_or("", |v| v.as_str()))),
                    ("jid", s(k.and_then(|k| k.remote_jid()).map_or("", |v| v.as_str()))),
                    ("fromMe", Json::Bool(k.and_then(|k| k.from_me()) == Some(true))),
                ];
                if let Some(p) = k.and_then(|k| k.participant()) {
                    f.push(("participant", s(p.as_str())));
                }
                if let Some(t) = text_of(m) {
                    f.push(("text", Json::Str(t)));
                }
                if let Some(st) = m.message_stub_type() {
                    f.push(("stub", s(st.name().unwrap_or("?"))));
                    f.push(("stubParams", Json::Arr(m.message_stub_parameters().iter().map(|p| s(p.as_str())).collect())));
                }
                out(f);
            }
        }),
    );
    sock.ev.on(
        EventKind::MessagesUpdate,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::MessagesUpdate(list) = e else { return };
            for u in list {
                if let Some(st) = u.update.status() {
                    out(vec![("ev", s("status")), ("id", s(u.key.id().map_or("", |v| v.as_str()))), ("status", Json::Num(st.0 as f64))]);
                }
            }
        }),
    );
    sock.ev.on(
        EventKind::MessageReceiptUpdate,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::MessageReceiptUpdate(list) = e else { return };
            for u in list {
                out(vec![("ev", s("receipt")), ("id", s(u.key.id().map_or("", |v| v.as_str())))]);
            }
        }),
    );
    sock.ev.on(
        EventKind::ChatsUpdate,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::ChatsUpdate(list) = e else { return };
            for u in list {
                if let Some(mute) = u.mute_end_time() {
                    out(vec![("ev", s("chat_mute")), ("id", s(u.id().map_or("", |v| v.as_str()))), ("mute", Json::Num(mute as f64))]);
                }
            }
        }),
    );
    sock.ev.on(
        EventKind::GroupsUpsert,
        Arc::new(|e: &BaileysEvent| {
            let BaileysEvent::GroupsUpsert(list) = e else { return };
            for g in list {
                out(vec![("ev", s("group_upsert")), ("id", s(&g.id)), ("subject", s(&g.subject))]);
            }
        }),
    );
    sock.connect();
    sock
}
/// Runs one public method by its upstream name, for the stanza compare of `scripts/e2e.mjs`.
/// A result does not matter: the mock gives an empty reply, and only the stanza is compared.
fn api(sock: &Socket, name: &str, a: &[Json]) -> baileys::error::Result<()> {
    let t = |i: usize| a.get(i).and_then(Json::as_str).unwrap_or_default();
    let n = |i: usize| a.get(i).and_then(Json::as_f64).unwrap_or(0.0) as u32;
    let list = |i: usize| -> Vec<String> { a.get(i).and_then(Json::as_arr).map_or_else(Vec::new, |v| v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()) };
    let key = |i: usize| -> WAMessageKey {
        let k = a.get(i);
        let f = |n: &str| k.and_then(|k| k.get(n)).and_then(Json::as_str).unwrap_or_default().to_string();
        let mut out = WAMessageKey::default().with_remote_jid(f("remoteJid")).with_id(f("id")).with_from_me(k.and_then(|k| k.get("fromMe")).and_then(Json::as_bool) == Some(true));
        if !f("participant").is_empty() {
            out.set_participant(f("participant"));
        }
        out
    };
    let action = |s: &str| match s {
        "add" => ParticipantAction::Add,
        "remove" => ParticipantAction::Remove,
        "promote" => ParticipantAction::Promote,
        _ => ParticipantAction::Demote,
    };
    match name {
        "updateMessagesPrivacy" => sock.update_messages_privacy(WAPrivacyMessagesValue::parse(t(0)).unwrap())?,
        "updateCallPrivacy" => sock.update_call_privacy(WAPrivacyCallValue::parse(t(0)).unwrap())?,
        "updateLastSeenPrivacy" => sock.update_last_seen_privacy(WAPrivacyValue::parse(t(0)).unwrap())?,
        "updateOnlinePrivacy" => sock.update_online_privacy(WAPrivacyOnlineValue::parse(t(0)).unwrap())?,
        "updateProfilePicturePrivacy" => sock.update_profile_picture_privacy(WAPrivacyValue::parse(t(0)).unwrap())?,
        "updateStatusPrivacy" => sock.update_status_privacy(WAPrivacyValue::parse(t(0)).unwrap())?,
        "updateReadReceiptsPrivacy" => sock.update_read_receipts_privacy(WAReadReceiptsValue::parse(t(0)).unwrap())?,
        "updateGroupsAddPrivacy" => sock.update_groups_add_privacy(WAPrivacyGroupAddValue::parse(t(0)).unwrap())?,
        "updateDefaultDisappearingMode" => sock.update_default_disappearing_mode(n(0))?,
        "getBotListV2" => drop(sock.get_bot_list_v2()?),
        "fetchStatus" => drop(sock.fetch_status(&[t(0).to_string()])?),
        "fetchDisappearingDuration" => drop(sock.fetch_disappearing_duration(&[t(0).to_string()])?),
        "removeProfilePicture" => sock.remove_profile_picture(t(0))?,
        "updateProfileStatus" => sock.update_profile_status(t(0))?,
        "fetchBlocklist" => drop(sock.fetch_blocklist()?),
        "updateBlockStatus" => sock.update_block_status(t(0), t(1))?,
        "getBusinessProfile" => drop(sock.get_business_profile(t(0))?),
        "cleanDirtyBits" => sock.clean_dirty_bits(t(0), a.get(1).and_then(Json::as_str))?,
        "profilePictureUrl" => drop(sock.profile_picture_url(t(0), t(1), None)?),
        "createCallLink" => drop(sock.create_call_link(if t(0) == "audio" { CallType::Audio } else { CallType::Video }, a.get(1).and_then(|v| v.get("startTime")).and_then(Json::as_f64).map(|v| v as u64), None)?),
        "sendPresenceUpdate" => sock.send_presence_update(WAPresence::parse(t(0)).unwrap(), a.get(1).and_then(Json::as_str))?,
        "presenceSubscribe" => sock.presence_subscribe(t(0))?,
        "digestKeyBundle" => sock.digest_key_bundle()?,
        "rotateSignedPreKey" => sock.rotate_signed_pre_key()?,
        "sendWAMBuffer" => drop(sock.send_wam_buffer(b"WAM-test")?),
        "fetchAccountReachoutTimelock" => drop(sock.fetch_account_reachout_timelock()?),
        "fetchNewChatMessageCap" => drop(sock.fetch_new_chat_message_cap()?),
        "groupMetadata" => drop(sock.group_metadata(t(0))?),
        "groupCreate" => drop(sock.group_create(t(0), &list(1))?),
        "groupLeave" => sock.group_leave(t(0))?,
        "groupUpdateSubject" => sock.group_update_subject(t(0), t(1))?,
        "groupRequestParticipantsList" => drop(sock.group_request_participants_list(t(0))?),
        "groupRequestParticipantsUpdate" => drop(sock.group_request_participants_update(t(0), &list(1), t(2))?),
        "groupParticipantsUpdate" => drop(sock.group_participants_update(t(0), &list(1), action(t(2)))?),
        "groupUpdateDescription" => sock.group_update_description(t(0), a.get(1).and_then(Json::as_str))?,
        "groupInviteCode" => drop(sock.group_invite_code(t(0))?),
        "groupRevokeInvite" => drop(sock.group_revoke_invite(t(0))?),
        "groupAcceptInvite" => drop(sock.group_accept_invite(t(0))?),
        "groupRevokeInviteV4" => drop(sock.group_revoke_invite_v4(t(0), t(1))?),
        "groupGetInviteInfo" => drop(sock.group_get_invite_info(t(0))?),
        "groupToggleEphemeral" => sock.group_toggle_ephemeral(t(0), n(1))?,
        "groupSettingUpdate" => sock.group_setting_update(t(0), t(1))?,
        "groupMemberAddMode" => sock.group_member_add_mode(t(0), t(1))?,
        "groupJoinApprovalMode" => sock.group_join_approval_mode(t(0), t(1))?,
        "groupFetchAllParticipating" => drop(sock.group_fetch_all_participating()?),
        "newsletterCreate" => drop(sock.newsletter_create(t(0), a.get(1).and_then(Json::as_str))?),
        "newsletterSubscribers" => drop(sock.newsletter_subscribers(t(0))?),
        "newsletterMetadata" => drop(sock.newsletter_metadata(t(0), t(1))?),
        "newsletterFollow" => drop(sock.newsletter_follow(t(0))?),
        "newsletterUnfollow" => drop(sock.newsletter_unfollow(t(0))?),
        "newsletterMute" => drop(sock.newsletter_mute(t(0))?),
        "newsletterUnmute" => drop(sock.newsletter_unmute(t(0))?),
        "newsletterUpdateName" => drop(sock.newsletter_update_name(t(0), t(1))?),
        "newsletterUpdateDescription" => drop(sock.newsletter_update_description(t(0), t(1))?),
        "newsletterRemovePicture" => drop(sock.newsletter_remove_picture(t(0))?),
        "newsletterReactMessage" => sock.newsletter_react_message(t(0), t(1), a.get(2).and_then(Json::as_str))?,
        "newsletterFetchMessages" => drop(sock.newsletter_fetch_messages(t(0), n(1), Some(n(2) as u64), Some(n(3) as u64))?),
        "subscribeNewsletterUpdates" => drop(sock.subscribe_newsletter_updates(t(0))?),
        "newsletterAdminCount" => drop(sock.newsletter_admin_count(t(0))?),
        "newsletterChangeOwner" => sock.newsletter_change_owner(t(0), t(1))?,
        "newsletterDemote" => sock.newsletter_demote(t(0), t(1))?,
        "newsletterDelete" => sock.newsletter_delete(t(0))?,
        "communityMetadata" => drop(sock.community_metadata(t(0))?),
        "communityCreate" => drop(sock.community_create(t(0), t(1))?),
        "communityCreateGroup" => drop(sock.community_create_group(t(0), &list(1), t(2))?),
        "communityLeave" => sock.community_leave(t(0))?,
        "communityUpdateSubject" => sock.community_update_subject(t(0), t(1))?,
        "communityLinkGroup" => sock.community_link_group(t(0), t(1))?,
        "communityUnlinkGroup" => sock.community_unlink_group(t(0), t(1))?,
        "communityFetchLinkedGroups" => drop(sock.community_fetch_linked_groups(t(0))?),
        "communityRequestParticipantsList" => drop(sock.community_request_participants_list(t(0))?),
        "communityRequestParticipantsUpdate" => drop(sock.community_request_participants_update(t(0), &list(1), t(2))?),
        "communityParticipantsUpdate" => drop(sock.community_participants_update(t(0), &list(1), action(t(2)))?),
        "communityUpdateDescription" => sock.community_update_description(t(0), a.get(1).and_then(Json::as_str))?,
        "communityInviteCode" => drop(sock.community_invite_code(t(0))?),
        "communityRevokeInvite" => drop(sock.community_revoke_invite(t(0))?),
        "communityAcceptInvite" => drop(sock.community_accept_invite(t(0))?),
        "communityRevokeInviteV4" => drop(sock.community_revoke_invite_v4(t(0), t(1))?),
        "communityGetInviteInfo" => drop(sock.community_get_invite_info(t(0))?),
        "communityToggleEphemeral" => sock.community_toggle_ephemeral(t(0), n(1))?,
        "communitySettingUpdate" => sock.community_setting_update(t(0), t(1))?,
        "communityMemberAddMode" => sock.community_member_add_mode(t(0), t(1))?,
        "communityJoinApprovalMode" => sock.community_join_approval_mode(t(0), t(1))?,
        "communityFetchAllParticipating" => drop(sock.community_fetch_all_participating()?),
        "updateBussinesProfile" => {
            let args = a.first();
            let f = |k: &str| args.and_then(|x| x.get(k)).and_then(Json::as_str).map(str::to_string);
            let hours = BusinessHours { timezone: "UTC".to_string(), days: vec![HoursDay::SpecificHours { day: DayOfWeekBussines::Mon, open_time_in_minutes: "60".to_string(), close_time_in_minutes: "120".to_string() }, HoursDay::Open24h { day: DayOfWeekBussines::Tue }] };
            let websites = args.and_then(|x| x.get("websites")).and_then(Json::as_arr).map(|v| v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect());
            drop(sock.update_bussines_profile(&UpdateBussinesProfileProps { address: f("address"), email: f("email"), description: f("description"), websites, hours: Some(hours) })?);
        }
        "removeCoverPhoto" => drop(sock.remove_cover_photo(t(0))?),
        "getCatalog" => drop(sock.get_catalog(&GetCatalogOptions { jid: Some(t(0).to_string()), limit: Some(n(1)), cursor: Some(t(2).to_string()) })?),
        "getCollections" => drop(sock.get_collections(Some(t(0)), Some(n(1)))?),
        "getOrderDetails" => drop(sock.get_order_details(t(0), t(1))?),
        "productDelete" => drop(sock.product_delete(&list(0))?),
        "sendReceipt" => sock.send_receipt(t(0), a.get(1).and_then(Json::as_str), &list(2), a.get(3).and_then(Json::as_str))?,
        "sendReceipts" => sock.send_receipts(&[key(0)], a.get(1).and_then(Json::as_str))?,
        "readMessages" => sock.read_messages(&[key(0)])?,
        "refreshMediaConn" => drop(sock.refresh_media_conn(true)?),
        "assertSessions" => drop(sock.assert_sessions(&list(0), true)?),
        "getUSyncDevices" => drop(sock.get_usync_devices(&list(0), false, false)?),
        "updateMemberLabel" => drop(sock.update_member_label(t(0), t(1))?),
        "fetchMessageHistory" => drop(sock.fetch_message_history(n(0), &key(1), n(2) as i64)?),
        "rejectCall" => sock.reject_call(t(0), t(1))?,
        "issuePrivacyTokens" => drop(sock.issue_privacy_tokens(&list(0), Some(n(1) as i64))?),
        "star" => sock.star(t(0), vec![StarredMessage { id: t(1).to_string(), from_me: Some(true) }], true)?,
        "addLabel" => sock.add_label(t(0), LabelActionBody { id: t(1).to_string(), name: Some(t(2).to_string()), color: Some(1), deleted: Some(false), predefined_id: None })?,
        "addChatLabel" => sock.add_chat_label(t(0), t(1))?,
        "removeChatLabel" => sock.remove_chat_label(t(0), t(1))?,
        "addMessageLabel" => sock.add_message_label(t(0), t(1), t(2))?,
        "removeMessageLabel" => sock.remove_message_label(t(0), t(1), t(2))?,
        "removeContact" => sock.remove_contact(t(0))?,
        "updateDisableLinkPreviewsPrivacy" => sock.update_disable_link_previews_privacy(true)?,
        "removeQuickReply" => sock.remove_quick_reply(t(0))?,
        "updateProfileName" => sock.update_profile_name(t(0))?,
        "addOrEditContact" => sock.add_or_edit_contact(t(0), waproto::sync_action_value::ContactAction::default().with_full_name(t(1)).with_first_name(t(2)))?,
        "addOrEditQuickReply" => sock.add_or_edit_quick_reply(QuickReplyAction { action: waproto::sync_action_value::QuickReplyAction::default().with_shortcut(t(0)).with_message(t(1)), timestamp: Some(t(2).to_string()) })?,
        "groupAcceptInviteV4" => drop(sock.group_accept_invite_v4(&key(0), &waproto::message::GroupInviteMessage::default().with_group_jid(t(1)).with_invite_code(t(2)).with_invite_expiration(n(3) as i64))?),
        "communityAcceptInviteV4" => drop(sock.community_accept_invite_v4(&key(0), &waproto::message::GroupInviteMessage::default().with_group_jid(t(1)).with_invite_code(t(2)).with_invite_expiration(n(3) as i64))?),
        "requestPairingCode" => drop(sock.request_pairing_code(t(0), Some(t(1)))?),
        "logout" => sock.logout(None)?,
        "sendMessage" => {
            let content = match t(1) {
                "text" => AnyMessageContent::Regular(Box::new(RegularContent::Text { text: t(2).to_string(), link_preview: Some(None), mentions: Mentionable::default(), context_info: None, edit: None }.into())),
                "edit" => AnyMessageContent::Regular(Box::new(RegularContent::Text { text: t(2).to_string(), link_preview: Some(None), mentions: Mentionable::default(), context_info: None, edit: Some(key(3)) }.into())),
                "delete" => AnyMessageContent::Delete(key(3)),
                "react" => AnyMessageContent::Regular(Box::new(RegularContent::React(waproto::message::ReactionMessage::default().with_text(t(2)).with_key(key(3))).into())),
                "pin" => AnyMessageContent::Regular(Box::new(RegularContent::Pin { pin: key(3), r#type: waproto::pin_in_chat::Type::PIN_FOR_ALL, time: Some(86400) }.into())),
                "location" => AnyMessageContent::Regular(Box::new(RegularContent::Location(waproto::message::LocationMessage::default().with_degrees_latitude(1.5).with_degrees_longitude(2.5)).into())),
                "poll" => AnyMessageContent::Regular(Box::new(RegularContent::Poll { poll: PollMessageOptions { name: t(2).to_string(), selectable_count: Some(1), values: vec!["a".to_string(), "b".to_string()], message_secret: None, to_announcement_group: None }, mentions: Mentionable::default(), context_info: None, edit: None }.into())),
                "disappearing" => AnyMessageContent::DisappearingMessagesInChat(DisappearingMessages::Enabled(true)),
                other => return Err(baileys::error::Boom::new(format!("unknown content {other}"))),
            };
            sock.send_message(t(0), &content, MiscMessageGenerationOptions::default())?;
        }
        other => return Err(baileys::error::Boom::new(format!("unknown api {other}"))),
    }
    Ok(())
}
fn main() {
    let sock: Arc<Mutex<Option<Socket>>> = Arc::default();
    let mut auth: Option<Arc<MultiFileAuthState>> = None;
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let cmd = Json::parse(&line).expect("json command");
        let id = cmd.get("req").cloned().unwrap_or(Json::Null);
        let name = cmd.get("cmd").and_then(Json::as_str).unwrap_or_default().to_string();
        let text = |k: &str| cmd.get(k).and_then(Json::as_str).unwrap_or_default().to_string();
        let current = sock.lock().unwrap().clone();
        if name == "start" {
            let a = auth.get_or_insert_with(|| Arc::new(use_multi_file_auth_state(text("dir")).expect("auth dir"))).clone();
            *sock.lock().unwrap() = Some(start(&cmd, &a));
            out(vec![("ev", s("reply")), ("req", id)]);
            continue;
        }
        if name == "wam" {
            let mut info = baileys::wam::BinaryInfo::new();
            info.sequence = 7;
            info.events = vec![
                baileys::wam::EventInput {
                    name: "WamDroppedEvent".to_string(),
                    props: vec![("droppedEventCode".to_string(), baileys::wam::Value::Number(300.0)), ("droppedEventCount".to_string(), baileys::wam::Value::Number(70000.0)), ("isFromWamsys".to_string(), baileys::wam::Value::Bool(true))],
                    globals: vec![("abKey2".to_string(), baileys::wam::Value::Str("ab-key".to_string()))],
                },
                baileys::wam::EventInput { name: "WamDroppedEvent".to_string(), props: vec![("droppedEventCode".to_string(), baileys::wam::Value::Number(1.5)), ("droppedEventCount".to_string(), baileys::wam::Value::Number(5e10))], globals: vec![] },
            ];
            let bytes = baileys::wam::encode_wam(&mut info).expect("wam");
            out(vec![("ev", s("reply")), ("req", id), ("wam", s(&waproto::pb::base64_encode(&bytes)))]);
            continue;
        }
        if name == "threads" {
            out(vec![("ev", s("reply")), ("req", id), ("threads", Json::Num(thread_count() as f64))]);
            continue;
        }
        if name == "quit" {
            out(vec![("ev", s("reply")), ("req", id)]);
            return;
        }
        // a command can block for a reply from the server, so each one has its own thread
        let reply_id = id;
        let _ = std::thread::Builder::new().stack_size(baileys::utils::time::THREAD_STACK).spawn({
            let cmd = cmd.clone();
            move || {
                let text = |k: &str| cmd.get(k).and_then(Json::as_str).unwrap_or_default().to_string();
                let r: baileys::error::Result<Vec<(&str, Json)>> = (|| {
                    let sock = current.ok_or_else(|| baileys::error::Boom::new("no socket"))?;
                    match name.as_str() {
                        "send" => {
                            let content = AnyMessageContent::Regular(Box::new(RegularContent::Text { text: text("text"), link_preview: Some(None), mentions: Mentionable::default(), context_info: None, edit: None }.into()));
                            let m = sock.send_message(&text("jid"), &content, MiscMessageGenerationOptions::default())?;
                            let id = m.as_ref().and_then(|m| m.key().and_then(|k| k.id()).map(|i| i.as_str().to_string())).unwrap_or_default();
                            if let Some(c) = m.as_ref().and_then(|m| m.message()) {
                                let mut store = sent().lock().unwrap();
                                // a retry asks only for a recent message, and a long run must not measure this store
                                if store.len() >= 1000 {
                                    store.remove(0);
                                }
                                store.push((id.clone(), c.clone()));
                            }
                            Ok(vec![("id", s(&id))])
                        }
                        "group_create" => {
                            let parts: Vec<String> = cmd.get("participants").and_then(Json::as_arr).map_or_else(Vec::new, |a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect());
                            let g = sock.group_create(&text("subject"), &parts)?;
                            Ok(vec![("id", s(&g.id)), ("participants", Json::Num(g.participants.len() as f64))])
                        }
                        "group_metadata" => {
                            let g = sock.group_metadata(&text("jid"))?;
                            Ok(vec![("subject", s(&g.subject))])
                        }
                        "set_app_key" => {
                            let key = text("id");
                            let data = AppStateSyncKeyData::default().with_key_data(base64_decode(&text("key")));
                            sock.keys.set_one(KeyKind::AppStateSyncKey, &key, Some(KeyValue::AppStateSyncKey(data)))?;
                            sock.ev.emit(BaileysEvent::CredsUpdate(Box::new(baileys::auth::CredsUpdate { my_app_state_key_id: Some(Some(key)), ..baileys::auth::CredsUpdate::default() })));
                            Ok(vec![])
                        }
                        "mute" => {
                            sock.chat_modify(&ChatModification::Mute(cmd.get("until").and_then(Json::as_f64).map(|u| u as u64)), &text("jid"))?;
                            Ok(vec![])
                        }
                        "api" => {
                            let args = cmd.get("args").and_then(Json::as_arr).cloned().unwrap_or_default();
                            match api(&sock, &text("name"), &args) {
                                Ok(()) => Ok(vec![("ok", Json::Bool(true))]),
                                Err(e) => Ok(vec![("ok", Json::Bool(false)), ("message", s(&e.message))]),
                            }
                        }
                        "drop_session" => {
                            let addr = sock.signal_repository.jid_to_signal_protocol_address(&text("jid"))?;
                            sock.keys.set_one(KeyKind::Session, &addr, None)?;
                            Ok(vec![("addr", s(&addr))])
                        }
                        "resync" => {
                            sock.resync_app_state(&ALL_WA_PATCH_NAMES, false)?;
                            Ok(vec![])
                        }
                        "on_whatsapp" => {
                            let r = sock.on_whats_app(&[text("jid")])?.unwrap_or_default();
                            Ok(vec![("exists", Json::Bool(r.iter().any(|x| x.exists)))])
                        }
                        "fetch_status" => {
                            let r = sock.fetch_status(&[text("jid")])?.unwrap_or_default();
                            let st = r.first().and_then(|e| e.get::<baileys::wausync::StatusData>("status")).and_then(|d| d.status.clone());
                            Ok(vec![("status", st.map_or(Json::Null, Json::Str))])
                        }
                        "end" => {
                            sock.end(None);
                            Ok(vec![])
                        }
                        other => Err(baileys::error::Boom::new(format!("unknown command {other}"))),
                    }
                })();
                match r {
                    Ok(mut f) => {
                        f.insert(0, ("ev", s("reply")));
                        f.push(("req", reply_id));
                        out(f);
                    }
                    Err(e) => out(vec![("ev", s("reply")), ("req", reply_id), ("error", s(&e.message))]),
                }
            }
        });
    }
}
