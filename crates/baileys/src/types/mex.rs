//! Same types as Types/Mex.ts.

/// `XWAPaths` values, by upstream name.
pub mod xwa_paths {
    pub const XWA2_NEWSLETTER_CREATE: &str = "xwa2_newsletter_create";
    pub const XWA2_NEWSLETTER_SUBSCRIBERS: &str = "xwa2_newsletter_subscribers";
    pub const XWA2_NEWSLETTER_VIEW: &str = "xwa2_newsletter_view";
    pub const XWA2_NEWSLETTER_METADATA: &str = "xwa2_newsletter";
    pub const XWA2_NEWSLETTER_ADMIN_COUNT: &str = "xwa2_newsletter_admin";
    pub const XWA2_NEWSLETTER_MUTE_V2: &str = "xwa2_newsletter_mute_v2";
    pub const XWA2_NEWSLETTER_UNMUTE_V2: &str = "xwa2_newsletter_unmute_v2";
    pub const XWA2_NEWSLETTER_FOLLOW: &str = "xwa2_newsletter_follow";
    pub const XWA2_NEWSLETTER_UNFOLLOW: &str = "xwa2_newsletter_unfollow";
    pub const XWA2_NEWSLETTER_JOIN_V2: &str = "xwa2_newsletter_join_v2";
    pub const XWA2_NEWSLETTER_LEAVE_V2: &str = "xwa2_newsletter_leave_v2";
    pub const XWA2_NEWSLETTER_CHANGE_OWNER: &str = "xwa2_newsletter_change_owner";
    pub const XWA2_NEWSLETTER_DEMOTE: &str = "xwa2_newsletter_demote";
    pub const XWA2_NEWSLETTER_DELETE_V2: &str = "xwa2_newsletter_delete_v2";
    pub const XWA2_FETCH_ACCOUNT_REACHOUT_TIMELOCK: &str = "xwa2_fetch_account_reachout_timelock";
    pub const XWA2_MESSAGE_CAPPING_INFO: &str = "xwa2_message_capping_info";
}
/// `QueryIds` values, by upstream name.
pub mod query_ids {
    pub const CREATE: &str = "8823471724422422";
    pub const UPDATE_METADATA: &str = "24250201037901610";
    pub const METADATA: &str = "6563316087068696";
    pub const SUBSCRIBERS: &str = "9783111038412085";
    pub const FOLLOW: &str = "24404358912487870";
    pub const UNFOLLOW: &str = "9767147403369991";
    pub const MUTE: &str = "29766401636284406";
    pub const UNMUTE: &str = "9864994326891137";
    pub const ADMIN_COUNT: &str = "7130823597031706";
    pub const CHANGE_OWNER: &str = "7341777602580933";
    pub const DEMOTE: &str = "6551828931592903";
    pub const DELETE: &str = "30062808666639665";
    pub const REACHOUT_TIMELOCK: &str = "23983697327930364";
    pub const MESSAGE_CAPPING_INFO: &str = "24503548349331633";
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub picture: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterTextField {
    pub id: String,
    pub text: String,
    pub update_time: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterPictureField {
    pub direct_path: String,
    pub id: String,
    pub r#type: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterThreadMetadataResponse {
    pub creation_time: String,
    pub description: NewsletterTextField,
    pub handle: Option<String>,
    pub invite: String,
    pub name: NewsletterTextField,
    pub picture: NewsletterPictureField,
    pub preview: NewsletterPictureField,
    pub subscribers_count: String,
    /// `VERIFIED` or `UNVERIFIED`.
    pub verification: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterViewerMetadata {
    /// `ON` or `OFF`.
    pub mute: String,
    /// `ADMIN`, `GUEST`, `OWNER` or `SUBSCRIBER`.
    pub role: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterCreateResponse {
    pub id: String,
    /// The `state.type` field.
    pub state_type: String,
    pub thread_metadata: NewsletterThreadMetadataResponse,
    pub viewer_metadata: NewsletterViewerMetadata,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterPicture {
    pub url: Option<String>,
    pub direct_path: Option<String>,
    pub media_key: Option<String>,
    pub id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterReactionCode {
    pub code: String,
    pub count: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterThreadMetadata {
    pub creation_time: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NewsletterMetadata {
    pub id: String,
    pub owner: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub invite: Option<String>,
    pub creation_time: Option<u64>,
    pub subscribers: Option<u64>,
    pub picture: Option<NewsletterPicture>,
    pub verification: Option<String>,
    pub reaction_codes: Option<Vec<NewsletterReactionCode>>,
    pub mute_state: Option<String>,
    pub thread_metadata: Option<NewsletterThreadMetadata>,
}
