//! Same as WAUSync/Protocols.
use crate::error::Result;
use crate::types::usync::{DeviceListData, KeyIndexData, ParsedDeviceInfo, USyncParsed, USyncQueryProtocol, USyncUser};
use crate::wabinary::{Attrs, BinaryNode, Content, assert_node_error_free, get_binary_node_child, get_binary_node_child_string, get_binary_node_children};
use std::sync::Arc;

fn simple(tag: &str) -> BinaryNode {
    BinaryNode::tag(tag, Attrs::new())
}
/// `content?.toString()`.
pub(crate) fn content_text(c: Option<&Content>) -> Option<String> {
    match c? {
        Content::Binary(b) => Some(String::from_utf8_lossy(b.as_slice()).into_owned()),
        Content::Text(t) => Some(t.as_str().to_string()),
        Content::Nodes(_) => None,
    }
}
/// `+attr` of a number with an upper limit of 2^53. Text that is not a number gives `None`.
fn number(a: Option<&str>) -> Option<u64> {
    a.and_then(|v| v.trim().parse::<f64>().ok()).filter(|n| *n >= 0.0).map(|n| n as u64)
}
fn parsed<T: std::any::Any + Send + Sync>(v: T) -> Result<Option<USyncParsed>> {
    Ok(Some(Arc::new(v)))
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BotProfileCommand {
    pub name: String,
    pub description: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BotProfileInfo {
    pub jid: String,
    pub name: String,
    pub attributes: String,
    pub description: String,
    pub category: String,
    pub is_default: bool,
    pub prompts: Vec<String>,
    pub persona_id: String,
    pub commands: Vec<BotProfileCommand>,
    pub commands_description: String,
}
pub struct USyncBotProfileProtocol;
impl USyncQueryProtocol for USyncBotProfileProtocol {
    fn name(&self) -> &str {
        "bot"
    }
    fn get_query_element(&self) -> BinaryNode {
        BinaryNode::with_nodes("bot", Attrs::new(), vec![BinaryNode::tag("profile", Attrs::from([("v", "1")]))])
    }
    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode> {
        let mut attrs = Attrs::new();
        if let Some(p) = &user.persona_id {
            attrs.set("persona_id", p.as_str());
        }
        Some(BinaryNode::with_nodes("bot", Attrs::new(), vec![BinaryNode::tag("profile", attrs)]))
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        let bot_node = get_binary_node_child(Some(node), "bot");
        let profile = get_binary_node_child(bot_node, "profile");
        let commands_node = get_binary_node_child(profile, "commands");
        let prompts_node = get_binary_node_child(profile, "prompts");
        let text = |n: Option<&BinaryNode>, t: &str| get_binary_node_child_string(n, t).unwrap_or_default();
        let commands = get_binary_node_children(commands_node, "command").into_iter().map(|c| BotProfileCommand { name: text(Some(c), "name"), description: text(Some(c), "description") }).collect();
        let prompts = get_binary_node_children(prompts_node, "prompt")
            .into_iter()
            .map(|p| {
                let mut s = text(Some(p), "emoji");
                s.push(' ');
                s.push_str(&text(Some(p), "text"));
                s
            })
            .collect();
        parsed(BotProfileInfo {
            is_default: get_binary_node_child(profile, "default").is_some(),
            jid: node.attr("jid").unwrap_or_default().to_string(),
            name: text(profile, "name"),
            attributes: text(profile, "attributes"),
            description: text(profile, "description"),
            category: text(profile, "category"),
            persona_id: profile.and_then(|p| p.attr("persona_id")).unwrap_or_default().to_string(),
            commands_description: text(commands_node, "description"),
            commands,
            prompts,
        })
    }
}
pub struct USyncContactProtocol;
impl USyncQueryProtocol for USyncContactProtocol {
    fn name(&self) -> &str {
        "contact"
    }
    fn get_query_element(&self) -> BinaryNode {
        simple("contact")
    }
    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode> {
        if let Some(phone) = user.phone.as_deref().filter(|p| !p.is_empty()) {
            return Some(BinaryNode::with_text("contact", Attrs::new(), phone));
        }
        if let Some(username) = user.username.as_deref().filter(|p| !p.is_empty()) {
            let mut attrs = Attrs::from([("username", username)]);
            if let Some(k) = user.username_key.as_deref().filter(|p| !p.is_empty()) {
                attrs.set("pin", k);
            }
            if let Some(l) = user.lid.as_deref().filter(|p| !p.is_empty()) {
                attrs.set("lid", l);
            }
            return Some(BinaryNode::tag("contact", attrs));
        }
        if let Some(t) = user.r#type.as_deref().filter(|p| !p.is_empty()) {
            return Some(BinaryNode::tag("contact", Attrs::from([("type", t)])));
        }
        Some(simple("contact"))
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        if node.tag.as_str() == "contact" {
            assert_node_error_free(node)?;
            return parsed(node.attr("type") == Some("in"));
        }
        parsed(false)
    }
}
pub struct USyncDeviceProtocol;
impl USyncQueryProtocol for USyncDeviceProtocol {
    fn name(&self) -> &str {
        "devices"
    }
    fn get_query_element(&self) -> BinaryNode {
        BinaryNode::tag("devices", Attrs::from([("version", "2")]))
    }
    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        let mut device_list = Vec::new();
        let mut key_index = None;
        if node.tag.as_str() == "devices" {
            assert_node_error_free(node)?;
            let device_list_node = get_binary_node_child(Some(node), "device-list");
            let key_index_node = get_binary_node_child(Some(node), "key-index-list");
            if let Some(Content::Nodes(content)) = device_list_node.and_then(|n| n.content.as_ref()) {
                for d in content {
                    if d.tag.as_str() == "device" {
                        device_list.push(DeviceListData {
                            id: number(d.attr("id")).unwrap_or(0) as u32,
                            key_index: number(d.attr("key-index")).map(|k| k as u32).filter(|k| *k != 0),
                            is_hosted: Some(d.attr("is_hosted") == Some("true")),
                        });
                    }
                }
            }
            if let Some(k) = key_index_node {
                let signed_key_index = match &k.content {
                    Some(Content::Binary(b)) => Some(b.as_slice().to_vec()),
                    _ => None,
                };
                key_index = Some(KeyIndexData { timestamp: number(k.attr("ts")).unwrap_or(0), signed_key_index, expected_timestamp: number(k.attr("expected_ts")) });
            }
        }
        parsed(ParsedDeviceInfo { device_list: Some(device_list), key_index })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DisappearingModeData {
    pub duration: u64,
    pub set_at_ms: Option<i64>,
}
pub struct USyncDisappearingModeProtocol;
impl USyncQueryProtocol for USyncDisappearingModeProtocol {
    fn name(&self) -> &str {
        "disappearing_mode"
    }
    fn get_query_element(&self) -> BinaryNode {
        simple("disappearing_mode")
    }
    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        if node.tag.as_str() == "disappearing_mode" {
            assert_node_error_free(node)?;
            return parsed(DisappearingModeData { duration: number(node.attr("duration")).unwrap_or(0), set_at_ms: Some(number(node.attr("t")).unwrap_or(0) as i64 * 1000) });
        }
        Ok(None)
    }
}
pub struct USyncLIDProtocol;
impl USyncQueryProtocol for USyncLIDProtocol {
    fn name(&self) -> &str {
        "lid"
    }
    fn get_query_element(&self) -> BinaryNode {
        simple("lid")
    }
    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode> {
        user.lid.as_deref().filter(|l| !l.is_empty()).map(|l| BinaryNode::tag("lid", Attrs::from([("jid", l)])))
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        if node.tag.as_str() == "lid" {
            return parsed(node.attr("val").unwrap_or_default().to_string());
        }
        Ok(None)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StatusData {
    /// `None` is null.
    pub status: Option<String>,
    pub set_at_ms: Option<i64>,
}
pub struct USyncStatusProtocol;
impl USyncQueryProtocol for USyncStatusProtocol {
    fn name(&self) -> &str {
        "status"
    }
    fn get_query_element(&self) -> BinaryNode {
        simple("status")
    }
    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        if node.tag.as_str() == "status" {
            assert_node_error_free(node)?;
            let mut status = content_text(node.content.as_ref()).filter(|s| !s.is_empty());
            let set_at_ms = Some(number(node.attr("t")).unwrap_or(0) as i64 * 1000);
            if status.is_none() && number(node.attr("code")) == Some(401) {
                status = Some(String::new());
            }
            return parsed(StatusData { status, set_at_ms });
        }
        Ok(None)
    }
}
pub struct USyncUsernameProtocol;
impl USyncQueryProtocol for USyncUsernameProtocol {
    fn name(&self) -> &str {
        "username"
    }
    fn get_query_element(&self) -> BinaryNode {
        simple("username")
    }
    fn get_user_element(&self, _user: &USyncUser) -> Option<BinaryNode> {
        None
    }
    fn parser(&self, node: &BinaryNode) -> Result<Option<USyncParsed>> {
        if node.tag.as_str() == "username" {
            assert_node_error_free(node)?;
            if let Some(Content::Text(t)) = &node.content {
                return parsed(t.as_str().to_string());
            }
        }
        Ok(None)
    }
}
