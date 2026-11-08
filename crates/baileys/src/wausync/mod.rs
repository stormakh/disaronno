//! Same as src/WAUSync: USync queries and their protocols.
pub mod protocols;
pub use crate::types::usync::{USyncQueryResult, USyncQueryResultList, USyncUser};
pub use protocols::*;

use crate::error::Result;
use crate::types::usync::USyncQueryProtocol;
use crate::wabinary::{BinaryNode, Content, get_binary_node_child};
use std::sync::Arc;

#[derive(Clone)]
pub struct USyncQuery {
    pub protocols: Vec<Arc<dyn USyncQueryProtocol>>,
    pub users: Vec<USyncUser>,
    pub context: String,
    pub mode: String,
}
impl Default for USyncQuery {
    fn default() -> USyncQuery {
        USyncQuery { protocols: Vec::new(), users: Vec::new(), context: "interactive".to_string(), mode: "query".to_string() }
    }
}
impl USyncQuery {
    pub fn new() -> USyncQuery {
        USyncQuery::default()
    }
    pub fn with_mode(mut self, mode: &str) -> USyncQuery {
        self.mode = mode.to_string();
        self
    }
    pub fn with_context(mut self, context: &str) -> USyncQuery {
        self.context = context.to_string();
        self
    }
    pub fn with_user(mut self, user: USyncUser) -> USyncQuery {
        self.users.push(user);
        self
    }
    pub fn add_user(&mut self, user: USyncUser) {
        self.users.push(user);
    }
    pub fn parse_usync_query_result(&self, result: Option<&BinaryNode>) -> Result<Option<USyncQueryResult>> {
        let Some(result) = result.filter(|r| r.attr("type") == Some("result")) else {
            return Ok(None);
        };
        let mut query_result = USyncQueryResult::default();
        let usync_node = get_binary_node_child(Some(result), "usync");
        let list_node = get_binary_node_child(usync_node, "list");
        if let Some(Content::Nodes(nodes)) = list_node.and_then(|l| l.content.as_ref()) {
            for node in nodes {
                let Some(id) = node.attr("jid") else { continue };
                let mut entry = USyncQueryResultList { id: id.to_string(), ..USyncQueryResultList::default() };
                if let Some(Content::Nodes(content)) = &node.content {
                    for c in content {
                        let protocol = c.tag.as_str();
                        let Some(p) = self.protocols.iter().find(|p| p.name() == protocol) else { continue };
                        let Some(parsed) = p.parser(c)? else { continue };
                        if protocol == "devices" {
                            entry.devices = parsed.downcast_ref::<crate::types::usync::ParsedDeviceInfo>().cloned();
                        }
                        entry.protocols.push((protocol.to_string(), parsed));
                    }
                }
                query_result.list.push(entry);
            }
        }
        Ok(Some(query_result))
    }
    pub fn with_device_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncDeviceProtocol));
        self
    }
    pub fn with_contact_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncContactProtocol));
        self
    }
    pub fn with_status_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncStatusProtocol));
        self
    }
    pub fn with_disappearing_mode_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncDisappearingModeProtocol));
        self
    }
    pub fn with_bot_profile_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncBotProfileProtocol));
        self
    }
    pub fn with_lid_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncLIDProtocol));
        self
    }
    pub fn with_username_protocol(mut self) -> USyncQuery {
        self.protocols.push(Arc::new(USyncUsernameProtocol));
        self
    }
}
