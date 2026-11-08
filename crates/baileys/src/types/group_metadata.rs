//! Same types as Types/GroupMetadata.ts.
use super::contact::Contact;
use super::message::WAMessageAddressingMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GroupAdmin {
    Admin,
    Superadmin,
}
impl GroupAdmin {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupAdmin::Admin => "admin",
            GroupAdmin::Superadmin => "superadmin",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct GroupParticipant {
    pub contact: Contact,
    pub is_admin: Option<bool>,
    pub is_super_admin: Option<bool>,
    /// `Some(None)` is null.
    pub admin: Option<Option<GroupAdmin>>,
}
impl std::ops::Deref for GroupParticipant {
    type Target = Contact;
    fn deref(&self) -> &Contact {
        &self.contact
    }
}
impl std::ops::DerefMut for GroupParticipant {
    fn deref_mut(&mut self) -> &mut Contact {
        &mut self.contact
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParticipantAction {
    Add,
    Remove,
    Promote,
    Demote,
    Modify,
}
impl ParticipantAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ParticipantAction::Add => "add",
            ParticipantAction::Remove => "remove",
            ParticipantAction::Promote => "promote",
            ParticipantAction::Demote => "demote",
            ParticipantAction::Modify => "modify",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestJoinAction {
    Created,
    Revoked,
    Rejected,
}
impl RequestJoinAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestJoinAction::Created => "created",
            RequestJoinAction::Revoked => "revoked",
            RequestJoinAction::Rejected => "rejected",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestJoinMethod {
    InviteLink,
    LinkedGroupJoin,
    NonAdminAdd,
}
impl RequestJoinMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestJoinMethod::InviteLink => "invite_link",
            RequestJoinMethod::LinkedGroupJoin => "linked_group_join",
            RequestJoinMethod::NonAdminAdd => "non_admin_add",
        }
    }
    pub fn parse(s: &str) -> Option<RequestJoinMethod> {
        match s {
            "invite_link" => Some(RequestJoinMethod::InviteLink),
            "linked_group_join" => Some(RequestJoinMethod::LinkedGroupJoin),
            "non_admin_add" => Some(RequestJoinMethod::NonAdminAdd),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct GroupMetadata {
    pub id: String,
    pub notify: Option<String>,
    /// group uses 'lid' or 'pn' to send messages
    pub addressing_mode: Option<WAMessageAddressingMode>,
    pub owner: Option<String>,
    pub owner_pn: Option<String>,
    pub owner_username: Option<String>,
    pub owner_country_code: Option<String>,
    pub subject: String,
    /// group subject owner
    pub subject_owner: Option<String>,
    pub subject_owner_pn: Option<String>,
    pub subject_owner_username: Option<String>,
    /// group subject modification date
    pub subject_time: Option<u64>,
    pub creation: Option<u64>,
    pub desc: Option<String>,
    pub desc_owner: Option<String>,
    pub desc_owner_pn: Option<String>,
    pub desc_owner_username: Option<String>,
    pub desc_id: Option<String>,
    pub desc_time: Option<u64>,
    /// if this group is part of a community, it returns the jid of the community to which it belongs
    pub linked_parent: Option<String>,
    /// is set when the group only allows admins to change group settings
    pub restrict: Option<bool>,
    /// is set when the group only allows admins to write messages
    pub announce: Option<bool>,
    /// is set when the group also allows members to add participants
    pub member_add_mode: Option<bool>,
    /// Request approval to join the group
    pub join_approval_mode: Option<bool>,
    /// is this a community
    pub is_community: Option<bool>,
    /// is this the announce of a community
    pub is_community_announce: Option<bool>,
    /// number of group participants
    pub size: Option<u32>,
    pub participants: Vec<GroupParticipant>,
    pub ephemeral_duration: Option<u32>,
    pub invite_code: Option<String>,
    /// the person who added you to group or changed some setting in group
    pub author: Option<String>,
    pub author_pn: Option<String>,
    pub author_username: Option<String>,
}
/// `Partial<GroupMetadata>`.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct GroupMetadataUpdate {
    pub id: Option<String>,
    pub notify: Option<String>,
    pub addressing_mode: Option<WAMessageAddressingMode>,
    pub owner: Option<String>,
    pub owner_pn: Option<String>,
    pub owner_username: Option<String>,
    pub owner_country_code: Option<String>,
    pub subject: Option<String>,
    pub subject_owner: Option<String>,
    pub subject_owner_pn: Option<String>,
    pub subject_owner_username: Option<String>,
    pub subject_time: Option<u64>,
    pub creation: Option<u64>,
    pub desc: Option<String>,
    pub desc_owner: Option<String>,
    pub desc_owner_pn: Option<String>,
    pub desc_owner_username: Option<String>,
    pub desc_id: Option<String>,
    pub desc_time: Option<u64>,
    pub linked_parent: Option<String>,
    pub restrict: Option<bool>,
    pub announce: Option<bool>,
    pub member_add_mode: Option<bool>,
    pub join_approval_mode: Option<bool>,
    pub is_community: Option<bool>,
    pub is_community_announce: Option<bool>,
    pub size: Option<u32>,
    pub participants: Option<Vec<GroupParticipant>>,
    pub ephemeral_duration: Option<u32>,
    pub invite_code: Option<String>,
    pub author: Option<String>,
    pub author_pn: Option<String>,
    pub author_username: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct WAGroupCreateResponse {
    pub status: u32,
    pub gid: Option<String>,
    pub participants: Option<Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct GroupModificationResponse {
    pub status: u32,
    pub participants: Option<Vec<String>>,
}
