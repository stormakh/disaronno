//! Same types as Types/Bussines.ts and the business types of Types/index.ts.
use waproto::sync_action_value::QuickReplyAction as ProtoQuickReplyAction;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DayOfWeekBussines {
    Sun,
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
}
impl DayOfWeekBussines {
    pub fn as_str(self) -> &'static str {
        match self {
            DayOfWeekBussines::Sun => "sun",
            DayOfWeekBussines::Mon => "mon",
            DayOfWeekBussines::Tue => "tue",
            DayOfWeekBussines::Wed => "wed",
            DayOfWeekBussines::Thu => "thu",
            DayOfWeekBussines::Fri => "fri",
            DayOfWeekBussines::Sat => "sat",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HoursDay {
    SpecificHours { day: DayOfWeekBussines, open_time_in_minutes: String, close_time_in_minutes: String },
    Open24h { day: DayOfWeekBussines },
    AppointmentOnly { day: DayOfWeekBussines },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessHours {
    pub timezone: String,
    pub days: Vec<HoursDay>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UpdateBussinesProfileProps {
    pub address: Option<String>,
    pub websites: Option<Vec<String>>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub hours: Option<BusinessHours>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct QuickReplyAction {
    pub action: ProtoQuickReplyAction,
    pub timestamp: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WABusinessHoursConfig {
    pub day_of_week: String,
    pub mode: String,
    pub open_time: Option<u32>,
    pub close_time: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WABusinessHours {
    pub timezone: Option<String>,
    pub config: Option<Vec<WABusinessHoursConfig>>,
    pub business_config: Option<Vec<WABusinessHoursConfig>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WABusinessProfile {
    pub description: String,
    pub email: Option<String>,
    pub business_hours: WABusinessHours,
    pub website: Vec<String>,
    pub category: Option<String>,
    pub wid: Option<String>,
    pub address: Option<String>,
}
