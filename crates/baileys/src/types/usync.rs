//! Same types as Types/USync.ts, with the result types that Utils/signal.ts reads from WAUSync.
use crate::error::Result;
use crate::wabinary::BinaryNode;
use std::any::Any;
use std::sync::Arc;

/// Same fields as WAUSync/USyncUser.ts. Use the fields or the builder methods.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct USyncUser {
    pub id: Option<String>,
    pub lid: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub username_key: Option<String>,
    pub r#type: Option<String>,
    pub persona_id: Option<String>,
}
impl USyncUser {
    pub fn new() -> USyncUser {
        USyncUser::default()
    }
    pub fn with_id(mut self, v: impl Into<String>) -> USyncUser {
        self.id = Some(v.into());
        self
    }
    pub fn with_lid(mut self, v: impl Into<String>) -> USyncUser {
        self.lid = Some(v.into());
        self
    }
    pub fn with_phone(mut self, v: impl Into<String>) -> USyncUser {
        self.phone = Some(v.into());
        self
    }
    pub fn with_username(mut self, v: impl Into<String>) -> USyncUser {
        self.username = Some(v.into());
        self
    }
    pub fn with_username_key(mut self, v: impl Into<String>) -> USyncUser {
        self.username_key = Some(v.into());
        self
    }
    pub fn with_type(mut self, v: impl Into<String>) -> USyncUser {
        self.r#type = Some(v.into());
        self
    }
    pub fn with_persona_id(mut self, v: impl Into<String>) -> USyncUser {
        self.persona_id = Some(v.into());
        self
    }
}
/// What a protocol parser returns. `parser` results are protocol specific, as `unknown` is upstream.
pub type USyncParsed = Arc<dyn Any + Send + Sync>;
/// Defines the interface for a USyncQuery protocol
pub trait USyncQueryProtocol: Send + Sync {
    /// The name of the protocol
    fn name(&self) -> &str;
    /// Defines what goes inside the query part of a USyncQuery
    fn get_query_element(&self) -> BinaryNode;
    /// Defines what goes inside the user part of a USyncQuery
    fn get_user_element(&self, user: &USyncUser) -> Option<BinaryNode>;
    /// Parse the result of the query. `None` is a null result, which the query leaves out of the list.
    fn parser(&self, data: &BinaryNode) -> Result<Option<USyncParsed>>;
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct KeyIndexData {
    pub timestamp: u64,
    pub signed_key_index: Option<Vec<u8>>,
    pub expected_timestamp: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DeviceListData {
    pub id: u32,
    /// `None` also stands for a `key-index` of 0 or NaN, which upstream treats as falsy.
    pub key_index: Option<u32>,
    pub is_hosted: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ParsedDeviceInfo {
    pub device_list: Option<Vec<DeviceListData>>,
    pub key_index: Option<KeyIndexData>,
}
/// One entry of a USync result list. A protocol value goes in `protocols`, by protocol name.
#[derive(Clone, Default)]
pub struct USyncQueryResultList {
    pub id: String,
    /// The value of the `devices` protocol.
    pub devices: Option<ParsedDeviceInfo>,
    pub protocols: Vec<(String, USyncParsed)>,
}
impl USyncQueryResultList {
    /// The value of a protocol, with the type that its parser returns.
    pub fn get<T: Any + Send + Sync>(&self, protocol: &str) -> Option<Arc<T>> {
        self.protocols.iter().find(|(n, _)| n == protocol).and_then(|(_, v)| v.clone().downcast::<T>().ok())
    }
    /// The value of the `lid` protocol. An empty value is falsy upstream.
    pub fn lid(&self) -> Option<Arc<String>> {
        self.get::<String>("lid").filter(|l| !l.is_empty())
    }
    /// The value of the `contact` protocol.
    pub fn contact(&self) -> bool {
        self.get::<bool>("contact").is_some_and(|c| *c)
    }
}
#[derive(Clone, Default)]
pub struct USyncQueryResult {
    pub list: Vec<USyncQueryResultList>,
    pub side_list: Vec<USyncQueryResultList>,
}
