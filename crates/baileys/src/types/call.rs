//! Same types as Types/Call.ts. Dates are milliseconds since the epoch.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WACallUpdateType {
    Offer,
    Ringing,
    Preaccept,
    Transport,
    Relaylatency,
    Timeout,
    Reject,
    Accept,
    Terminate,
}
impl WACallUpdateType {
    pub fn as_str(self) -> &'static str {
        match self {
            WACallUpdateType::Offer => "offer",
            WACallUpdateType::Ringing => "ringing",
            WACallUpdateType::Preaccept => "preaccept",
            WACallUpdateType::Transport => "transport",
            WACallUpdateType::Relaylatency => "relaylatency",
            WACallUpdateType::Timeout => "timeout",
            WACallUpdateType::Reject => "reject",
            WACallUpdateType::Accept => "accept",
            WACallUpdateType::Terminate => "terminate",
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct WACallEvent {
    pub chat_id: String,
    pub from: String,
    pub caller_pn: Option<String>,
    pub is_group: Option<bool>,
    pub group_jid: Option<String>,
    pub id: String,
    pub date_ms: i64,
    pub is_video: Option<bool>,
    pub status: WACallUpdateType,
    pub offline: bool,
    pub latency_ms: Option<u32>,
}
