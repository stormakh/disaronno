//! Same as Socket/groups.ts.
use super::socket::SocketInner;
use crate::error::{Boom, Result};
use crate::events::{BaileysEvent, BaileysEventEmitter};
use crate::types::*;
use crate::utils::generics::{JsMap, generate_message_id_v2, unix_timestamp_seconds};
use crate::utils::validate_connection::node_to_json;
use crate::wabinary::*;
use waproto::message::GroupInviteMessage;
use waproto::pb::{Json, Str};
use waproto::web_message_info::StubType;

/// One entry of the results of `group_participants_update`.
#[derive(Clone, Debug, PartialEq)]
pub struct ParticipantUpdateResult {
    pub status: String,
    pub jid: Option<String>,
    pub content: Option<BinaryNode>,
}
/// `+attr` of a whole number. Text that is not a number gives `None`.
fn num<T: TryFrom<u64>>(a: Option<&str>) -> Option<T> {
    a.and_then(|v| v.trim().parse::<f64>().ok()).filter(|v| *v >= 0.0).and_then(|v| T::try_from(v as u64).ok())
}
fn participant_nodes(participants: &[String]) -> Vec<BinaryNode> {
    participants.iter().map(|jid| BinaryNode::tag("participant", Attrs::from([("jid", jid.as_str())]))).collect()
}
pub(crate) fn participants_result(node: Option<&BinaryNode>, with_content: bool) -> Vec<ParticipantUpdateResult> {
    get_binary_node_children(node, "participant")
        .into_iter()
        .map(|p| ParticipantUpdateResult { status: p.attr("error").filter(|e| !e.is_empty()).unwrap_or("200").to_string(), jid: p.attr("jid").map(str::to_string), content: with_content.then(|| p.clone()) })
        .collect()
}
impl SocketInner {
    fn group_query(&self, jid: &str, r#type: &str, content: Vec<BinaryNode>) -> Result<Option<BinaryNode>> {
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("type", r#type), ("xmlns", "w:g2"), ("to", jid)]), content), None)
    }
    pub fn group_metadata(&self, jid: &str) -> Result<GroupMetadata> {
        let result = self.group_query(jid, "get", vec![BinaryNode::tag("query", Attrs::from([("request", "interactive")]))])?;
        extract_group_metadata(result.as_ref().ok_or_else(missing_result)?)
    }
    pub fn group_fetch_all_participating(&self) -> Result<JsMap<GroupMetadata>> {
        let sub = vec![BinaryNode::tag("participants", Attrs::new()), BinaryNode::tag("description", Attrs::new())];
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", "@g.us"), ("xmlns", "w:g2"), ("type", "get")]), vec![BinaryNode::with_nodes("participating", Attrs::new(), sub)]), None)?;
        let mut data = JsMap::new();
        let groups_child = get_binary_node_child(result.as_ref(), "groups");
        for group_node in get_binary_node_children(groups_child, "group") {
            let meta = extract_group_metadata(&BinaryNode::with_nodes("result", Attrs::new(), vec![group_node.clone()]))?;
            data.insert(meta.id.clone(), meta);
        }
        // TODO: properly parse LID / PN DATA
        self.ev.emit(BaileysEvent::GroupsUpdate(data.values().map(group_metadata_to_update).collect()));
        Ok(data)
    }
    pub(crate) fn on_dirty_groups(&self, dirty: &BinaryNode) {
        if dirty.attr("type") != Some("groups") {
            return;
        }
        let run = || -> Result<()> {
            self.group_fetch_all_participating()?;
            self.clean_dirty_bits("groups", None)
        };
        if let Err(e) = run() {
            self.on_unexpected_error(&e, "dirty groups");
        }
    }
    pub fn group_create(&self, subject: &str, participants: &[String]) -> Result<GroupMetadata> {
        let key = generate_message_id_v2(None);
        let result = self.group_query("@g.us", "set", vec![BinaryNode::with_nodes("create", Attrs::from([("subject", subject), ("key", key.as_str())]), participant_nodes(participants))])?;
        extract_group_metadata(result.as_ref().ok_or_else(missing_result)?)
    }
    pub fn group_leave(&self, id: &str) -> Result<()> {
        self.group_query("@g.us", "set", vec![BinaryNode::with_nodes("leave", Attrs::new(), vec![BinaryNode::tag("group", Attrs::from([("id", id)]))])])?;
        Ok(())
    }
    pub fn group_update_subject(&self, jid: &str, subject: &str) -> Result<()> {
        self.group_query(jid, "set", vec![BinaryNode::with_bytes("subject", Attrs::new(), subject.as_bytes())])?;
        Ok(())
    }
    pub fn group_request_participants_list(&self, jid: &str) -> Result<Vec<Attrs>> {
        let result = self.group_query(jid, "get", vec![BinaryNode::tag("membership_approval_requests", Attrs::new())])?;
        let node = get_binary_node_child(result.as_ref(), "membership_approval_requests");
        Ok(get_binary_node_children(node, "membership_approval_request").into_iter().map(|v| v.attrs.clone()).collect())
    }
    /// `action` is `approve` or `reject`.
    pub fn group_request_participants_update(&self, jid: &str, participants: &[String], action: &str) -> Result<Vec<ParticipantUpdateResult>> {
        let result = self.group_query(jid, "set", vec![BinaryNode::with_nodes("membership_requests_action", Attrs::new(), vec![BinaryNode::with_nodes(action, Attrs::new(), participant_nodes(participants))])])?;
        let node = get_binary_node_child(result.as_ref(), "membership_requests_action");
        Ok(participants_result(get_binary_node_child(node, action), false))
    }
    pub fn group_participants_update(&self, jid: &str, participants: &[String], action: ParticipantAction) -> Result<Vec<ParticipantUpdateResult>> {
        let result = self.group_query(jid, "set", vec![BinaryNode::with_nodes(action.as_str(), Attrs::new(), participant_nodes(participants))])?;
        Ok(participants_result(get_binary_node_child(result.as_ref(), action.as_str()), true))
    }
    pub fn group_update_description(&self, jid: &str, description: Option<&str>) -> Result<()> {
        let metadata = self.group_metadata(jid)?;
        let description = description.filter(|d| !d.is_empty());
        let mut attrs = Attrs::new();
        match description {
            Some(_) => attrs.set("id", generate_message_id_v2(None)),
            None => attrs.set("delete", "true"),
        }
        if let Some(prev) = metadata.desc_id.as_deref().filter(|p| !p.is_empty()) {
            attrs.set("prev", prev);
        }
        let node = match description {
            Some(d) => BinaryNode::with_nodes("description", attrs, vec![BinaryNode::with_bytes("body", Attrs::new(), d.as_bytes())]),
            None => BinaryNode::tag("description", attrs),
        };
        self.group_query(jid, "set", vec![node])?;
        Ok(())
    }
    pub fn group_invite_code(&self, jid: &str) -> Result<Option<String>> {
        let result = self.group_query(jid, "get", vec![BinaryNode::tag("invite", Attrs::new())])?;
        Ok(get_binary_node_child(result.as_ref(), "invite").and_then(|n| n.attr("code")).map(str::to_string))
    }
    pub fn group_revoke_invite(&self, jid: &str) -> Result<Option<String>> {
        let result = self.group_query(jid, "set", vec![BinaryNode::tag("invite", Attrs::new())])?;
        Ok(get_binary_node_child(result.as_ref(), "invite").and_then(|n| n.attr("code")).map(str::to_string))
    }
    pub fn group_accept_invite(&self, code: &str) -> Result<Option<String>> {
        let results = self.group_query("@g.us", "set", vec![BinaryNode::tag("invite", Attrs::from([("code", code)]))])?;
        Ok(get_binary_node_child(results.as_ref(), "group").and_then(|n| n.attr("jid")).map(str::to_string))
    }
    /// revoke a v4 invite for someone. Returns true if successful
    pub fn group_revoke_invite_v4(&self, group_jid: &str, invited_jid: &str) -> Result<bool> {
        let result = self.group_query(group_jid, "set", vec![BinaryNode::with_nodes("revoke", Attrs::new(), vec![BinaryNode::tag("participant", Attrs::from([("jid", invited_jid)]))])])?;
        Ok(result.is_some())
    }
    /// accept a GroupInviteMessage. `key` is the key of the invite message,
    /// or only the `remote_jid` of the person who sent the invite
    pub fn group_accept_invite_v4(&self, key: &WAMessageKey, invite_message: &GroupInviteMessage) -> Result<Option<String>> {
        self.ev.run_buffered(|| self.accept_invite_v4(key, invite_message))
    }
    /// The body of `groupAcceptInviteV4`, which `communityAcceptInviteV4` repeats upstream.
    pub(crate) fn accept_invite_v4(&self, key: &WAMessageKey, invite_message: &GroupInviteMessage) -> Result<Option<String>> {
        let group_jid = invite_message.group_jid().map_or("", |s| s.as_str());
        let remote_jid = key.remote_jid().map_or("", |s| s.as_str());
        let expiration = invite_message.invite_expiration().ok_or_else(|| Boom::type_error("Cannot read properties of null (reading 'toString')"))?.to_string();
        let attrs = Attrs::from([("code", invite_message.invite_code().map_or("", |s| s.as_str())), ("expiration", expiration.as_str()), ("admin", remote_jid)]);
        let results = self.group_query(group_jid, "set", vec![BinaryNode::tag("accept", attrs)])?;
        // if we have the full message key
        // update the invite message to be expired
        if key.id().is_some_and(|i| !i.as_str().is_empty()) {
            // create new invite message that is expired
            let expired = invite_message.clone().with_invite_expiration(0i64).with_invite_code("");
            let update = WAMessage::default().with_message(waproto::Message::default().with_group_invite_message(expired));
            self.ev.emit(BaileysEvent::MessagesUpdate(vec![WAMessageUpdate { key: key.clone(), update }]));
        }
        // generate the group add message
        let mut stub_key = WAMessageKey::default().with_remote_jid(group_jid).with_from_me(false).with_participant(remote_jid);
        stub_key.set_id(generate_message_id_v2(self.me_id().as_deref()));
        let me_json = self.user().map_or(Json::Null, |c| contact_to_json(&c));
        let msg = WAMessage::default()
            .with_key(stub_key)
            .with_message_stub_type(StubType::GROUP_PARTICIPANT_ADD)
            .with_message_stub_parameters(vec![Str::from(me_json.stringify().as_str())])
            .with_participant(remote_jid)
            .with_message_timestamp(unix_timestamp_seconds(None) as u64);
        self.upsert_message(msg, MessageUpsertType::Notify)?;
        Ok(results.as_ref().and_then(|r| r.attr("from")).map(str::to_string))
    }
    pub fn group_get_invite_info(&self, code: &str) -> Result<GroupMetadata> {
        let results = self.group_query("@g.us", "get", vec![BinaryNode::tag("invite", Attrs::from([("code", code)]))])?;
        extract_group_metadata(results.as_ref().ok_or_else(missing_result)?)
    }
    pub fn group_toggle_ephemeral(&self, jid: &str, ephemeral_expiration: u32) -> Result<()> {
        let content = if ephemeral_expiration != 0 { BinaryNode::tag("ephemeral", Attrs::from([("expiration", ephemeral_expiration.to_string())])) } else { BinaryNode::tag("not_ephemeral", Attrs::new()) };
        self.group_query(jid, "set", vec![content])?;
        Ok(())
    }
    /// `setting` is `announcement`, `not_announcement`, `locked` or `unlocked`.
    pub fn group_setting_update(&self, jid: &str, setting: &str) -> Result<()> {
        self.group_query(jid, "set", vec![BinaryNode::tag(setting, Attrs::new())])?;
        Ok(())
    }
    /// `mode` is `admin_add` or `all_member_add`.
    pub fn group_member_add_mode(&self, jid: &str, mode: &str) -> Result<()> {
        self.group_query(jid, "set", vec![BinaryNode::with_text("member_add_mode", Attrs::new(), mode)])?;
        Ok(())
    }
    /// `mode` is `on` or `off`.
    pub fn group_join_approval_mode(&self, jid: &str, mode: &str) -> Result<()> {
        self.group_query(jid, "set", vec![BinaryNode::with_nodes("membership_approval_mode", Attrs::new(), vec![BinaryNode::tag("group_join", Attrs::from([("state", mode)]))])])?;
        Ok(())
    }
}
fn missing_result() -> Boom {
    Boom::type_error("Cannot read properties of undefined (reading 'content')")
}
/// `JSON.stringify` of a contact, with the fields that are set.
pub(crate) fn contact_to_json(c: &Contact) -> Json {
    let mut o = vec![("id".to_string(), Json::Str(c.id.clone()))];
    let mut put = |k: &str, v: &Option<String>| {
        if let Some(v) = v {
            o.push((k.to_string(), Json::Str(v.clone())));
        }
    };
    put("lid", &c.lid);
    put("phoneNumber", &c.phone_number);
    put("name", &c.name);
    put("notify", &c.notify);
    put("username", &c.username);
    put("verifiedName", &c.verified_name);
    put("status", &c.status);
    Json::Obj(o)
}
pub(crate) fn group_metadata_to_update(m: &GroupMetadata) -> GroupMetadataUpdate {
    GroupMetadataUpdate {
        id: Some(m.id.clone()),
        notify: m.notify.clone(),
        addressing_mode: m.addressing_mode,
        owner: m.owner.clone(),
        owner_pn: m.owner_pn.clone(),
        owner_username: m.owner_username.clone(),
        owner_country_code: m.owner_country_code.clone(),
        subject: Some(m.subject.clone()),
        subject_owner: m.subject_owner.clone(),
        subject_owner_pn: m.subject_owner_pn.clone(),
        subject_owner_username: m.subject_owner_username.clone(),
        subject_time: m.subject_time,
        creation: m.creation,
        desc: m.desc.clone(),
        desc_owner: m.desc_owner.clone(),
        desc_owner_pn: m.desc_owner_pn.clone(),
        desc_owner_username: m.desc_owner_username.clone(),
        desc_id: m.desc_id.clone(),
        desc_time: m.desc_time,
        linked_parent: m.linked_parent.clone(),
        restrict: m.restrict,
        announce: m.announce,
        member_add_mode: m.member_add_mode,
        join_approval_mode: m.join_approval_mode,
        is_community: m.is_community,
        is_community_announce: m.is_community_announce,
        size: m.size,
        participants: Some(m.participants.clone()),
        ephemeral_duration: m.ephemeral_duration,
        invite_code: m.invite_code.clone(),
        author: m.author.clone(),
        author_pn: m.author_pn.clone(),
        author_username: m.author_username.clone(),
    }
}
pub(crate) fn parse_group_participant(node: &BinaryNode) -> GroupParticipant {
    let jid = node.attr("jid");
    let phone = node.attr("phone_number");
    let lid = node.attr("lid");
    let mut contact = Contact::new(jid.unwrap_or_default());
    contact.phone_number = jid.filter(|j| is_lid_user(j)).and(phone).filter(|p| is_pn_user(p)).map(str::to_string);
    contact.lid = jid.filter(|j| is_pn_user(j)).and(lid).filter(|l| is_lid_user(l)).map(str::to_string);
    contact.username = node.attr("participant_username").filter(|u| !u.is_empty()).or_else(|| node.attr("username").filter(|u| !u.is_empty())).map(str::to_string);
    let admin = match node.attr("type") {
        Some("admin") => Some(GroupAdmin::Admin),
        Some("superadmin") => Some(GroupAdmin::Superadmin),
        _ => None,
    };
    GroupParticipant { contact, is_admin: None, is_super_admin: None, admin: Some(admin) }
}
fn normalized(a: Option<&str>) -> Option<String> {
    a.filter(|v| !v.is_empty()).map(jid_normalized_user)
}
fn owned(a: Option<&str>) -> Option<String> {
    a.map(str::to_string)
}
pub fn extract_group_metadata(result: &BinaryNode) -> Result<GroupMetadata> {
    let Some(group) = get_binary_node_child(Some(result), "group") else {
        // Mirror WAWeb: surface server/client errors with their code+text instead of crashing.
        if let Some(error_node) = get_binary_node_child(Some(result), "error") {
            let code = error_node.attr("code").filter(|c| !c.is_empty()).map_or(500, |c| num::<u16>(Some(c)).unwrap_or(0));
            let text = error_node.attr("text").filter(|t| !t.is_empty()).unwrap_or("group metadata query failed");
            let mut e = Boom::with_data(text, node_to_json(error_node));
            e.status_code = Some(code);
            return Err(e);
        }
        return Err(Boom::with_data("Invalid group metadata response: missing <group> node", node_to_json(result)));
    };
    let Some(id) = group.attr("id").filter(|i| !i.is_empty()) else {
        return Err(Boom::with_data("Invalid group metadata response: missing group id", node_to_json(group)));
    };
    let desc_child = get_binary_node_child(Some(group), "description");
    let (mut desc, mut desc_id, mut desc_owner, mut desc_owner_pn, mut desc_owner_username, mut desc_time) = (None, None, None, None, None, None);
    if let Some(d) = desc_child {
        desc = get_binary_node_child_string(Some(d), "body");
        desc_owner = normalized(d.attr("participant"));
        desc_owner_pn = normalized(d.attr("participant_pn"));
        desc_owner_username = d.attr("participant_username").filter(|u| !u.is_empty()).map(str::to_string);
        desc_time = num(d.attr("t"));
        desc_id = owned(d.attr("id"));
    }
    let group_id = if id.contains('@') { id.to_string() } else { jid_encode(id, "g.us", None, None) };
    let eph = get_binary_node_child(Some(group), "ephemeral").and_then(|e| e.attr("expiration")).filter(|e| !e.is_empty());
    let member_add_mode = get_binary_node_child_string(Some(group), "member_add_mode").as_deref() == Some("all_member_add");
    let has = |t: &str| get_binary_node_child(Some(group), t).is_some();
    let participants = get_binary_node_children(Some(group), "participant");
    Ok(GroupMetadata {
        id: group_id,
        notify: owned(group.attr("notify")),
        addressing_mode: Some(if group.attr("addressing_mode") == Some("lid") { WAMessageAddressingMode::Lid } else { WAMessageAddressingMode::Pn }),
        subject: group.attr("subject").unwrap_or_default().to_string(),
        subject_owner: owned(group.attr("s_o")),
        subject_owner_pn: owned(group.attr("s_o_pn")),
        subject_owner_username: owned(group.attr("s_o_username")),
        subject_time: num(group.attr("s_t")),
        size: match group.attr("size").filter(|s| !s.is_empty()) {
            Some(s) => num(Some(s)),
            None => Some(participants.len() as u32),
        },
        creation: num(group.attr("creation")),
        owner: normalized(group.attr("creator")),
        owner_pn: normalized(group.attr("creator_pn")),
        owner_username: group.attr("creator_username").filter(|u| !u.is_empty()).map(str::to_string),
        owner_country_code: owned(group.attr("creator_country_code")),
        desc,
        desc_id,
        desc_owner,
        desc_owner_pn,
        desc_owner_username,
        desc_time,
        linked_parent: get_binary_node_child(Some(group), "linked_parent").and_then(|l| l.attr("jid")).filter(|j| !j.is_empty()).map(str::to_string),
        restrict: Some(has("locked")),
        announce: Some(has("announcement")),
        is_community: Some(has("parent")),
        is_community_announce: Some(has("default_sub_group")),
        join_approval_mode: Some(has("membership_approval_mode")),
        member_add_mode: Some(member_add_mode),
        participants: participants.into_iter().map(parse_group_participant).collect(),
        ephemeral_duration: eph.and_then(|e| num(Some(e))),
        invite_code: None,
        author: None,
        author_pn: None,
        author_username: None,
    })
}
