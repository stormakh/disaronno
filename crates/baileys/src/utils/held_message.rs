//! A stored message in its smallest form: its own encoded bytes, checked once when it is created.
use crate::error::Result;
use waproto::WebMessageInfo;
use waproto::pb::PbMessage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldMessage(Box<[u8]>);
impl HeldMessage {
    /// Does a full decode, so it rejects every input that `WebMessageInfo::decode` rejects.
    pub fn new(encoded: &[u8]) -> Result<HeldMessage> {
        WebMessageInfo::decode(encoded)?;
        Ok(HeldMessage(encoded.into()))
    }
    /// Decodes again on each call.
    pub fn read(&self) -> Result<WebMessageInfo> {
        Ok(WebMessageInfo::decode(&self.0)?)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
