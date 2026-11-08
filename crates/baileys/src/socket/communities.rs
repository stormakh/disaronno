//! Same as Socket/communities.ts.
use super::groups::{ParticipantUpdateResult, group_metadata_to_update, participants_result};
use super::socket::SocketInner;
use crate::error::{Boom, Result};
use crate::events::{BaileysEvent, BaileysEventEmitter};
use crate::types::*;
use crate::utils::generics::{JsMap, generate_message_id, generate_message_id_v2};
use crate::wabinary::*;
use waproto::message::GroupInviteMessage;

/// One entry of `CommunityLinkedGroups.linked_groups`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinkedGroup {
    pub id: Option<String>,
    pub subject: String,
    pub creation: Option<u64>,
    pub owner: Option<String>,
    pub size: Option<u32>,
}
/// The result of `community_fetch_linked_groups`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommunityLinkedGroups {
    pub community_jid: String,
    pub is_community: bool,
    pub linked_groups: Vec<LinkedGroup>,
}
fn participant_nodes(participants: &[String]) -> Vec<BinaryNode> {
    participants.iter().map(|jid| BinaryNode::tag("participant", Attrs::from([("jid", jid.as_str())]))).collect()
}
fn missing_result() -> Boom {
    Boom::type_error("Cannot read properties of undefined (reading 'content')")
}
fn num<T: TryFrom<u64>>(a: Option<&str>) -> Option<T> {
    a.and_then(|v| v.trim().parse::<f64>().ok()).filter(|v| *v >= 0.0).and_then(|v| T::try_from(v as u64).ok())
}
impl SocketInner {
    fn community_query(&self, jid: &str, r#type: &str, content: Vec<BinaryNode>) -> Result<Option<BinaryNode>> {
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("type", r#type), ("xmlns", "w:g2"), ("to", jid)]), content), None)
    }
    pub fn community_metadata(&self, jid: &str) -> Result<GroupMetadata> {
        let result = self.community_query(jid, "get", vec![BinaryNode::tag("query", Attrs::from([("request", "interactive")]))])?;
        extract_community_metadata(result.as_ref().ok_or_else(missing_result)?)
    }
    pub fn community_fetch_all_participating(&self) -> Result<JsMap<GroupMetadata>> {
        let sub = vec![BinaryNode::tag("participants", Attrs::new()), BinaryNode::tag("description", Attrs::new())];
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", "@g.us"), ("xmlns", "w:g2"), ("type", "get")]), vec![BinaryNode::with_nodes("participating", Attrs::new(), sub)]), None)?;
        let mut data = JsMap::new();
        let communities_child = get_binary_node_child(result.as_ref(), "communities");
        for community_node in get_binary_node_children(communities_child, "community") {
            let meta = extract_community_metadata(&BinaryNode::with_nodes("result", Attrs::new(), vec![community_node.clone()]))?;
            data.insert(meta.id.clone(), meta);
        }
        self.ev.emit(BaileysEvent::GroupsUpdate(data.values().map(group_metadata_to_update).collect()));
        Ok(data)
    }
    fn parse_group_result(&self, node: Option<&BinaryNode>) -> Option<GroupMetadata> {
        let id = get_binary_node_child(node, "group")?.attr("id").unwrap_or_default();
        let mut jid = String::with_capacity(id.len() + 5);
        jid.push_str(id);
        jid.push_str("@g.us");
        match self.group_metadata(&jid) {
            Ok(m) => Some(m),
            Err(error) => {
                self.logger.error(&format!("Error parsing group metadata: {error}"));
                None
            }
        }
    }
    pub(crate) fn on_dirty_communities(&self, dirty: &BinaryNode) {
        if dirty.attr("type") != Some("communities") {
            return;
        }
        let run = || -> Result<()> {
            self.community_fetch_all_participating()?;
            self.clean_dirty_bits("groups", None)
        };
        if let Err(e) = run() {
            self.on_unexpected_error(&e, "dirty communities");
        }
    }
    pub fn community_create(&self, subject: &str, body: &str) -> Result<Option<GroupMetadata>> {
        let description_id: String = generate_message_id().chars().take(12).collect();
        let description = BinaryNode::with_nodes("description", Attrs::from([("id", description_id.as_str())]), vec![BinaryNode::with_bytes("body", Attrs::new(), body.as_bytes())]);
        let content = vec![description, BinaryNode::tag("parent", Attrs::from([("default_membership_approval_mode", "request_required")])), BinaryNode::tag("allow_non_admin_sub_group_creation", Attrs::new()), BinaryNode::tag("create_general_chat", Attrs::new())];
        let result = self.community_query("@g.us", "set", vec![BinaryNode::with_nodes("create", Attrs::from([("subject", subject)]), content)])?;
        Ok(self.parse_group_result(result.as_ref()))
    }
    pub fn community_create_group(&self, subject: &str, participants: &[String], parent_community_jid: &str) -> Result<Option<GroupMetadata>> {
        let key = generate_message_id_v2(None);
        let mut content = participant_nodes(participants);
        content.push(BinaryNode::tag("linked_parent", Attrs::from([("jid", parent_community_jid)])));
        let result = self.community_query("@g.us", "set", vec![BinaryNode::with_nodes("create", Attrs::from([("subject", subject), ("key", key.as_str())]), content)])?;
        Ok(self.parse_group_result(result.as_ref()))
    }
    pub fn community_leave(&self, id: &str) -> Result<()> {
        self.community_query("@g.us", "set", vec![BinaryNode::with_nodes("leave", Attrs::new(), vec![BinaryNode::tag("community", Attrs::from([("id", id)]))])])?;
        Ok(())
    }
    pub fn community_update_subject(&self, jid: &str, subject: &str) -> Result<()> {
        self.community_query(jid, "set", vec![BinaryNode::with_bytes("subject", Attrs::new(), subject.as_bytes())])?;
        Ok(())
    }
    pub fn community_link_group(&self, group_jid: &str, parent_community_jid: &str) -> Result<()> {
        let link = BinaryNode::with_nodes("link", Attrs::from([("link_type", "sub_group")]), vec![BinaryNode::tag("group", Attrs::from([("jid", group_jid)]))]);
        self.community_query(parent_community_jid, "set", vec![BinaryNode::with_nodes("links", Attrs::new(), vec![link])])?;
        Ok(())
    }
    pub fn community_unlink_group(&self, group_jid: &str, parent_community_jid: &str) -> Result<()> {
        self.community_query(parent_community_jid, "set", vec![BinaryNode::with_nodes("unlink", Attrs::from([("unlink_type", "sub_group")]), vec![BinaryNode::tag("group", Attrs::from([("jid", group_jid)]))])])?;
        Ok(())
    }
    pub fn community_fetch_linked_groups(&self, jid: &str) -> Result<CommunityLinkedGroups> {
        // Try to determine if it is a subgroup or a community
        let metadata = self.group_metadata(jid)?;
        // It is a subgroup when it has a parent: get the community jid
        let (community_jid, is_community) = match metadata.linked_parent.filter(|p| !p.is_empty()) {
            Some(parent) => (parent, false),
            None => (jid.to_string(), true),
        };
        // Fetch all subgroups of the community
        let result = self.community_query(&community_jid, "get", vec![BinaryNode::tag("sub_groups", Attrs::new())])?;
        let sub_groups_node = get_binary_node_child(result.as_ref(), "sub_groups");
        let linked_groups = get_binary_node_children(sub_groups_node, "group")
            .into_iter()
            .map(|g| LinkedGroup {
                id: g.attr("id").filter(|i| !i.is_empty()).map(|i| jid_encode(i, "g.us", None, None)),
                subject: g.attr("subject").unwrap_or_default().to_string(),
                creation: num(g.attr("creation")),
                owner: g.attr("creator").filter(|c| !c.is_empty()).map(jid_normalized_user),
                size: num(g.attr("size")),
            })
            .collect();
        Ok(CommunityLinkedGroups { community_jid, is_community, linked_groups })
    }
    pub fn community_request_participants_list(&self, jid: &str) -> Result<Vec<Attrs>> {
        let result = self.community_query(jid, "get", vec![BinaryNode::tag("membership_approval_requests", Attrs::new())])?;
        let node = get_binary_node_child(result.as_ref(), "membership_approval_requests");
        Ok(get_binary_node_children(node, "membership_approval_request").into_iter().map(|v| v.attrs.clone()).collect())
    }
    /// `action` is `approve` or `reject`.
    pub fn community_request_participants_update(&self, jid: &str, participants: &[String], action: &str) -> Result<Vec<ParticipantUpdateResult>> {
        let result = self.community_query(jid, "set", vec![BinaryNode::with_nodes("membership_requests_action", Attrs::new(), vec![BinaryNode::with_nodes(action, Attrs::new(), participant_nodes(participants))])])?;
        let node = get_binary_node_child(result.as_ref(), "membership_requests_action");
        Ok(participants_result(get_binary_node_child(node, action), false))
    }
    pub fn community_participants_update(&self, jid: &str, participants: &[String], action: ParticipantAction) -> Result<Vec<ParticipantUpdateResult>> {
        let attrs = if action == ParticipantAction::Remove { Attrs::from([("linked_groups", "true")]) } else { Attrs::new() };
        let result = self.community_query(jid, "set", vec![BinaryNode::with_nodes(action.as_str(), attrs, participant_nodes(participants))])?;
        Ok(participants_result(get_binary_node_child(result.as_ref(), action.as_str()), true))
    }
    pub fn community_update_description(&self, jid: &str, description: Option<&str>) -> Result<()> {
        let metadata = self.community_metadata(jid)?;
        let description = description.filter(|d| !d.is_empty());
        let mut attrs = Attrs::new();
        match description {
            Some(_) => attrs.set("id", generate_message_id()),
            None => attrs.set("delete", "true"),
        }
        if let Some(prev) = metadata.desc_id.as_deref().filter(|p| !p.is_empty()) {
            attrs.set("prev", prev);
        }
        let node = match description {
            Some(d) => BinaryNode::with_nodes("description", attrs, vec![BinaryNode::with_bytes("body", Attrs::new(), d.as_bytes())]),
            None => BinaryNode::tag("description", attrs),
        };
        self.community_query(jid, "set", vec![node])?;
        Ok(())
    }
    pub fn community_invite_code(&self, jid: &str) -> Result<Option<String>> {
        let result = self.community_query(jid, "get", vec![BinaryNode::tag("invite", Attrs::new())])?;
        Ok(get_binary_node_child(result.as_ref(), "invite").and_then(|n| n.attr("code")).map(str::to_string))
    }
    pub fn community_revoke_invite(&self, jid: &str) -> Result<Option<String>> {
        let result = self.community_query(jid, "set", vec![BinaryNode::tag("invite", Attrs::new())])?;
        Ok(get_binary_node_child(result.as_ref(), "invite").and_then(|n| n.attr("code")).map(str::to_string))
    }
    pub fn community_accept_invite(&self, code: &str) -> Result<Option<String>> {
        let results = self.community_query("@g.us", "set", vec![BinaryNode::tag("invite", Attrs::from([("code", code)]))])?;
        Ok(get_binary_node_child(results.as_ref(), "community").and_then(|n| n.attr("jid")).map(str::to_string))
    }
    /// revoke a v4 invite for someone. Returns true if successful
    pub fn community_revoke_invite_v4(&self, community_jid: &str, invited_jid: &str) -> Result<bool> {
        let result = self.community_query(community_jid, "set", vec![BinaryNode::with_nodes("revoke", Attrs::new(), vec![BinaryNode::tag("participant", Attrs::from([("jid", invited_jid)]))])])?;
        Ok(result.is_some())
    }
    /// accept a CommunityInviteMessage. `key` is the key of the invite message,
    /// or only the `remote_jid` of the person who sent the invite
    pub fn community_accept_invite_v4(&self, key: &WAMessageKey, invite_message: &GroupInviteMessage) -> Result<Option<String>> {
        self.ev.run_buffered(|| self.accept_invite_v4(key, invite_message))
    }
    pub fn community_get_invite_info(&self, code: &str) -> Result<GroupMetadata> {
        let results = self.community_query("@g.us", "get", vec![BinaryNode::tag("invite", Attrs::from([("code", code)]))])?;
        extract_community_metadata(results.as_ref().ok_or_else(missing_result)?)
    }
    pub fn community_toggle_ephemeral(&self, jid: &str, ephemeral_expiration: u32) -> Result<()> {
        let content = if ephemeral_expiration != 0 { BinaryNode::tag("ephemeral", Attrs::from([("expiration", ephemeral_expiration.to_string())])) } else { BinaryNode::tag("not_ephemeral", Attrs::new()) };
        self.community_query(jid, "set", vec![content])?;
        Ok(())
    }
    /// `setting` is `announcement`, `not_announcement`, `locked` or `unlocked`.
    pub fn community_setting_update(&self, jid: &str, setting: &str) -> Result<()> {
        self.community_query(jid, "set", vec![BinaryNode::tag(setting, Attrs::new())])?;
        Ok(())
    }
    /// `mode` is `admin_add` or `all_member_add`.
    pub fn community_member_add_mode(&self, jid: &str, mode: &str) -> Result<()> {
        self.community_query(jid, "set", vec![BinaryNode::with_text("member_add_mode", Attrs::new(), mode)])?;
        Ok(())
    }
    /// `mode` is `on` or `off`.
    pub fn community_join_approval_mode(&self, jid: &str, mode: &str) -> Result<()> {
        self.community_query(jid, "set", vec![BinaryNode::with_nodes("membership_approval_mode", Attrs::new(), vec![BinaryNode::tag("community_join", Attrs::from([("state", mode)]))])])?;
        Ok(())
    }
}
pub fn extract_community_metadata(result: &BinaryNode) -> Result<GroupMetadata> {
    let community = get_binary_node_child(Some(result), "community").ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'attrs')"))?;
    let desc_child = get_binary_node_child(Some(community), "description");
    let (mut desc, mut desc_id) = (None, None);
    if let Some(d) = desc_child {
        desc = get_binary_node_child_string(Some(d), "body");
        desc_id = d.attr("id").map(str::to_string);
    }
    let raw_id = community.attr("id").unwrap_or("");
    let community_id = if raw_id.contains('@') { raw_id.to_string() } else { jid_encode(raw_id, "g.us", None, None) };
    let eph = get_binary_node_child(Some(community), "ephemeral").and_then(|e| e.attr("expiration")).filter(|e| !e.is_empty());
    let member_add_mode = get_binary_node_child_string(Some(community), "member_add_mode").as_deref() == Some("all_member_add");
    let has = |t: &str| get_binary_node_child(Some(community), t).is_some();
    let participants = get_binary_node_children(Some(community), "participant");
    let addressing = get_binary_node_child_string(Some(community), "addressing_mode");
    Ok(GroupMetadata {
        id: community_id,
        subject: community.attr("subject").unwrap_or_default().to_string(),
        subject_owner: community.attr("s_o").map(str::to_string),
        subject_time: Some(num(community.attr("s_t")).unwrap_or(0)),
        size: Some(participants.len() as u32),
        creation: Some(num(community.attr("creation")).unwrap_or(0)),
        owner: community.attr("creator").filter(|c| !c.is_empty()).map(jid_normalized_user),
        desc,
        desc_id,
        linked_parent: get_binary_node_child(Some(community), "linked_parent").and_then(|l| l.attr("jid")).filter(|j| !j.is_empty()).map(str::to_string),
        restrict: Some(has("locked")),
        announce: Some(has("announcement")),
        is_community: Some(has("parent")),
        is_community_announce: Some(has("default_sub_community")),
        join_approval_mode: Some(has("membership_approval_mode")),
        member_add_mode: Some(member_add_mode),
        participants: participants
            .into_iter()
            .map(|p| {
                // TODO: IMPLEMENT THE PN/LID FIELDS HERE!!
                let admin = match p.attr("type") {
                    Some("admin") => Some(GroupAdmin::Admin),
                    Some("superadmin") => Some(GroupAdmin::Superadmin),
                    _ => None,
                };
                GroupParticipant { contact: Contact::new(p.attr("jid").unwrap_or_default()), is_admin: None, is_super_admin: None, admin: Some(admin) }
            })
            .collect(),
        ephemeral_duration: eph.and_then(|e| num(Some(e))),
        addressing_mode: match addressing.as_deref() {
            Some("lid") => Some(WAMessageAddressingMode::Lid),
            Some("pn") => Some(WAMessageAddressingMode::Pn),
            _ => None,
        },
        ..GroupMetadata::default()
    })
}
