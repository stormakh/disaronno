//! JID helpers, same behavior as WABinary/jid-utils.ts.
pub const S_WHATSAPP_NET: &str = "@s.whatsapp.net";
pub const OFFICIAL_BIZ_JID: &str = "16505361212@c.us";
pub const SERVER_JID: &str = "server@c.us";
pub const PSA_WID: &str = "0@c.us";
pub const STORIES_JID: &str = "status@broadcast";
pub const META_AI_JID: &str = "13135550002@c.us";

pub mod domains {
    pub const WHATSAPP: u32 = 0;
    pub const LID: u32 = 1;
    pub const HOSTED: u32 = 128;
    pub const HOSTED_LID: u32 = 129;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullJid<'a> {
    pub user: &'a str,
    pub server: &'a str,
    pub domain_type: u32,
    /// `Some(0)` when the JID has a device part that is not a number, as `+device || 0` does.
    pub device: Option<u32>,
}

pub fn get_server_from_domain_type(initial: &str, domain: Option<u32>) -> String {
    match domain {
        Some(domains::LID) => "lid".to_string(),
        Some(domains::HOSTED) => "hosted".to_string(),
        Some(domains::HOSTED_LID) => "hosted.lid".to_string(),
        _ => initial.to_string(),
    }
}

pub fn jid_encode(user: &str, server: &str, device: Option<u32>, agent: Option<u32>) -> String {
    let mut s = String::with_capacity(user.len() + server.len() + 12);
    s.push_str(user);
    if let Some(a) = agent.filter(|a| *a != 0) {
        s.push('_');
        s.push_str(&a.to_string());
    }
    if let Some(d) = device.filter(|d| *d != 0) {
        s.push(':');
        s.push_str(&d.to_string());
    }
    s.push('@');
    s.push_str(server);
    s
}

pub fn jid_decode(jid: &str) -> Option<FullJid<'_>> {
    let sep = jid.find('@')?;
    let server = &jid[sep + 1..];
    let combined = &jid[..sep];
    let mut colon = combined.split(':');
    let user_agent = colon.next().unwrap_or("");
    let device = colon.next();
    let mut us = user_agent.split('_');
    let user = us.next().unwrap_or("");
    let agent = us.next();
    let domain_type = match server {
        "lid" => domains::LID,
        "hosted" => domains::HOSTED,
        "hosted.lid" => domains::HOSTED_LID,
        _ => match agent {
            Some(a) if !a.is_empty() => parse_int_prefix(a).unwrap_or(0),
            _ => domains::WHATSAPP,
        },
    };
    let device = match device {
        Some(d) if !d.is_empty() => Some(d.parse::<u32>().unwrap_or(0)),
        _ => None,
    };
    Some(FullJid { server, user, domain_type, device })
}
/// JavaScript `parseInt`: reads leading digits.
fn parse_int_prefix(a: &str) -> Option<u32> {
    let end = a.bytes().position(|c| !c.is_ascii_digit()).unwrap_or(a.len());
    a[..end].parse().ok()
}

pub fn are_jids_same_user(a: Option<&str>, b: Option<&str>) -> bool {
    a.and_then(jid_decode).map(|j| j.user) == b.and_then(jid_decode).map(|j| j.user)
}
pub fn is_jid_meta_ai(j: &str) -> bool {
    j.ends_with("@bot")
}
pub fn is_pn_user(j: &str) -> bool {
    j.ends_with("@s.whatsapp.net")
}
pub fn is_lid_user(j: &str) -> bool {
    j.ends_with("@lid")
}
pub fn is_jid_broadcast(j: &str) -> bool {
    j.ends_with("@broadcast")
}
pub fn is_jid_group(j: &str) -> bool {
    j.ends_with("@g.us")
}
pub fn is_jid_status_broadcast(j: &str) -> bool {
    j == "status@broadcast"
}
pub fn is_jid_newsletter(j: &str) -> bool {
    j.ends_with("@newsletter")
}
pub fn is_hosted_pn_user(j: &str) -> bool {
    j.ends_with("@hosted")
}
pub fn is_hosted_lid_user(j: &str) -> bool {
    j.ends_with("@hosted.lid")
}
/// Matches `^1313555\d{4}$|^131655500\d{2}$` on the user part, and the `@c.us` server.
pub fn is_jid_bot(j: &str) -> bool {
    if !j.ends_with("@c.us") {
        return false;
    }
    let u = j.split('@').next().unwrap_or("");
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|c| c.is_ascii_digit());
    u.strip_prefix("1313555").is_some_and(|r| digits(r, 4)) || u.strip_prefix("131655500").is_some_and(|r| digits(r, 2))
}
pub fn jid_normalized_user(j: &str) -> String {
    let Some(r) = jid_decode(j) else { return String::new() };
    jid_encode(r.user, if r.server == "c.us" { "s.whatsapp.net" } else { r.server }, None, None)
}
pub fn transfer_device(from: &str, to: &str) -> Option<String> {
    let device = jid_decode(from).and_then(|f| f.device).unwrap_or(0);
    let t = jid_decode(to)?;
    Some(jid_encode(t.user, t.server, Some(device), None))
}
