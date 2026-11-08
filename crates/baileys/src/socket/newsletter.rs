//! Same as Socket/newsletter.ts.
use super::mex::execute_wmex_query;
use super::socket::{SocketInner, jstr};
use crate::error::Result;
use crate::types::*;
use crate::utils::messages_media::generate_profile_picture;
use crate::wabinary::*;
use waproto::pb::{Json, base64_encode};

fn obj(fields: Vec<(&str, Json)>) -> Json {
    Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn text_at<'a>(j: &'a Json, a: &str, b: &str) -> Option<&'a str> {
    j.get(a).and_then(|x| x.get(b)).and_then(Json::as_str)
}
fn int_of(j: Option<&Json>) -> Option<u64> {
    match j? {
        Json::Str(s) => s.parse().ok(),
        Json::Num(n) => Some(*n as u64),
        _ => None,
    }
}
fn parse_newsletter_create_response(response: &Json) -> NewsletterMetadata {
    let thread = response.get("thread_metadata");
    let t = thread.unwrap_or(&Json::Null);
    NewsletterMetadata {
        id: response.get("id").and_then(Json::as_str).unwrap_or_default().to_string(),
        owner: None,
        name: text_at(t, "name", "text").unwrap_or_default().to_string(),
        creation_time: int_of(t.get("creation_time")),
        description: text_at(t, "description", "text").map(str::to_string),
        invite: t.get("invite").and_then(Json::as_str).map(str::to_string),
        subscribers: int_of(t.get("subscribers_count")),
        verification: t.get("verification").and_then(Json::as_str).map(str::to_string),
        picture: Some(NewsletterPicture { id: text_at(t, "picture", "id").map(str::to_string), direct_path: text_at(t, "picture", "direct_path").map(str::to_string), ..NewsletterPicture::default() }),
        mute_state: text_at(response, "viewer_metadata", "mute").map(str::to_string),
        ..NewsletterMetadata::default()
    }
}
fn metadata_from_json(r: &Json) -> NewsletterMetadata {
    let text = |k: &str| r.get(k).and_then(Json::as_str).map(str::to_string);
    let thread_metadata = r.get("thread_metadata").map(|t| NewsletterThreadMetadata { creation_time: int_of(t.get("creation_time")), name: t.get("name").and_then(Json::as_str).map(str::to_string), description: t.get("description").and_then(Json::as_str).map(str::to_string) });
    NewsletterMetadata {
        id: text("id").unwrap_or_default(),
        owner: text("owner"),
        name: text("name").unwrap_or_default(),
        description: text("description"),
        invite: text("invite"),
        creation_time: int_of(r.get("creation_time")),
        subscribers: int_of(r.get("subscribers")),
        picture: r.get("picture").map(|p| NewsletterPicture {
            url: p.get("url").and_then(Json::as_str).map(str::to_string),
            direct_path: p.get("directPath").and_then(Json::as_str).map(str::to_string),
            media_key: p.get("mediaKey").and_then(Json::as_str).map(str::to_string),
            id: p.get("id").and_then(Json::as_str).map(str::to_string),
        }),
        verification: text("verification"),
        reaction_codes: r.get("reaction_codes").and_then(Json::as_arr).map(|a| a.iter().map(|c| NewsletterReactionCode { code: c.get("code").and_then(Json::as_str).unwrap_or_default().to_string(), count: int_of(c.get("count")).unwrap_or(0) }).collect()),
        mute_state: text("mute_state"),
        thread_metadata,
    }
}
fn parse_newsletter_metadata(result: &Json) -> Option<NewsletterMetadata> {
    if !matches!(result, Json::Obj(_)) {
        return None;
    }
    if result.get("id").and_then(Json::as_str).is_some() {
        return Some(metadata_from_json(result));
    }
    let inner = result.get("result")?;
    if matches!(inner, Json::Obj(_)) && inner.get("id").is_some() {
        return Some(metadata_from_json(inner));
    }
    None
}
fn newsletter_id(jid: &str) -> Json {
    obj(vec![("newsletter_id", jstr(jid))])
}
impl SocketInner {
    pub fn newsletter_create(&self, name: &str, description: Option<&str>) -> Result<NewsletterMetadata> {
        let variables = obj(vec![("input", obj(vec![("name", jstr(name)), ("description", description.map_or(Json::Null, jstr))]))]);
        let raw = execute_wmex_query(self, variables, query_ids::CREATE, xwa_paths::XWA2_NEWSLETTER_CREATE)?;
        Ok(parse_newsletter_create_response(&raw))
    }
    pub fn newsletter_update(&self, jid: &str, updates: &NewsletterUpdate) -> Result<Json> {
        let mut u = Vec::new();
        for (k, v) in [("name", &updates.name), ("description", &updates.description), ("picture", &updates.picture)] {
            if let Some(v) = v {
                u.push((k, jstr(v)));
            }
        }
        u.push(("settings", Json::Null));
        let variables = obj(vec![("newsletter_id", jstr(jid)), ("updates", obj(u))]);
        execute_wmex_query(self, variables, query_ids::UPDATE_METADATA, "xwa2_newsletter_update")
    }
    pub fn newsletter_subscribers(&self, jid: &str) -> Result<Json> {
        execute_wmex_query(self, newsletter_id(jid), query_ids::SUBSCRIBERS, xwa_paths::XWA2_NEWSLETTER_SUBSCRIBERS)
    }
    /// `type` is `invite` or `jid`.
    pub fn newsletter_metadata(&self, r#type: &str, key: &str) -> Result<Option<NewsletterMetadata>> {
        let variables = obj(vec![("fetch_creation_time", Json::Bool(true)), ("fetch_full_image", Json::Bool(true)), ("fetch_viewer_metadata", Json::Bool(true)), ("input", obj(vec![("key", jstr(key)), ("type", jstr(&r#type.to_uppercase()))]))]);
        let result = execute_wmex_query(self, variables, query_ids::METADATA, xwa_paths::XWA2_NEWSLETTER_METADATA)?;
        Ok(parse_newsletter_metadata(&result))
    }
    pub fn newsletter_follow(&self, jid: &str) -> Result<Json> {
        execute_wmex_query(self, newsletter_id(jid), query_ids::FOLLOW, xwa_paths::XWA2_NEWSLETTER_JOIN_V2)
    }
    pub fn newsletter_unfollow(&self, jid: &str) -> Result<Json> {
        execute_wmex_query(self, newsletter_id(jid), query_ids::UNFOLLOW, xwa_paths::XWA2_NEWSLETTER_LEAVE_V2)
    }
    pub fn newsletter_mute(&self, jid: &str) -> Result<Json> {
        execute_wmex_query(self, newsletter_id(jid), query_ids::MUTE, xwa_paths::XWA2_NEWSLETTER_MUTE_V2)
    }
    pub fn newsletter_unmute(&self, jid: &str) -> Result<Json> {
        execute_wmex_query(self, newsletter_id(jid), query_ids::UNMUTE, xwa_paths::XWA2_NEWSLETTER_UNMUTE_V2)
    }
    pub fn newsletter_update_name(&self, jid: &str, name: &str) -> Result<Json> {
        self.newsletter_update(jid, &NewsletterUpdate { name: Some(name.to_string()), ..NewsletterUpdate::default() })
    }
    pub fn newsletter_update_description(&self, jid: &str, description: &str) -> Result<Json> {
        self.newsletter_update(jid, &NewsletterUpdate { description: Some(description.to_string()), ..NewsletterUpdate::default() })
    }
    pub fn newsletter_update_picture(&self, jid: &str, content: &WAMediaUpload) -> Result<Json> {
        let img = generate_profile_picture(content, None)?;
        self.newsletter_update(jid, &NewsletterUpdate { picture: Some(base64_encode(&img)), ..NewsletterUpdate::default() })
    }
    pub fn newsletter_remove_picture(&self, jid: &str) -> Result<Json> {
        self.newsletter_update(jid, &NewsletterUpdate { picture: Some(String::new()), ..NewsletterUpdate::default() })
    }
    pub fn newsletter_react_message(&self, jid: &str, server_id: &str, reaction: Option<&str>) -> Result<()> {
        let reaction = reaction.filter(|r| !r.is_empty());
        let mut attrs = Attrs::from([("to", jid)]);
        if reaction.is_none() {
            attrs.set("edit", "7");
        }
        attrs.set("type", "reaction");
        attrs.set("server_id", server_id);
        attrs.set("id", self.generate_message_tag());
        let reaction_attrs = reaction.map_or_else(Attrs::new, |r| Attrs::from([("code", r)]));
        self.query(BinaryNode::with_nodes("message", attrs, vec![BinaryNode::tag("reaction", reaction_attrs)]), None)?;
        Ok(())
    }
    pub fn newsletter_fetch_messages(&self, jid: &str, count: u32, since: Option<u64>, after: Option<u64>) -> Result<Option<BinaryNode>> {
        let mut update_attrs = Attrs::from([("count", count.to_string())]);
        if let Some(s) = since {
            update_attrs.set("since", s.to_string());
        }
        if let Some(a) = after.filter(|a| *a != 0) {
            update_attrs.set("after", a.to_string());
        }
        let mut attrs = Attrs::new();
        attrs.set("id", self.generate_message_tag());
        attrs.set("type", "get");
        attrs.set("xmlns", "newsletter");
        attrs.set("to", jid);
        self.query(BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::tag("message_updates", update_attrs)]), None)
    }
    /// The value is the `duration` of the updates.
    pub fn subscribe_newsletter_updates(&self, jid: &str) -> Result<Option<String>> {
        let mut attrs = Attrs::new();
        attrs.set("id", self.generate_message_tag());
        attrs.set("type", "set");
        attrs.set("xmlns", "newsletter");
        attrs.set("to", jid);
        let result = self.query(BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::with_nodes("live_updates", Attrs::new(), Vec::new())]), None)?;
        Ok(get_binary_node_child(result.as_ref(), "live_updates").and_then(|n| n.attr("duration")).filter(|d| !d.is_empty()).map(str::to_string))
    }
    pub fn newsletter_admin_count(&self, jid: &str) -> Result<Option<u64>> {
        let response = execute_wmex_query(self, newsletter_id(jid), query_ids::ADMIN_COUNT, xwa_paths::XWA2_NEWSLETTER_ADMIN_COUNT)?;
        Ok(int_of(response.get("admin_count")))
    }
    pub fn newsletter_change_owner(&self, jid: &str, new_owner_jid: &str) -> Result<()> {
        execute_wmex_query(self, obj(vec![("newsletter_id", jstr(jid)), ("user_id", jstr(new_owner_jid))]), query_ids::CHANGE_OWNER, xwa_paths::XWA2_NEWSLETTER_CHANGE_OWNER)?;
        Ok(())
    }
    pub fn newsletter_demote(&self, jid: &str, user_jid: &str) -> Result<()> {
        execute_wmex_query(self, obj(vec![("newsletter_id", jstr(jid)), ("user_id", jstr(user_jid))]), query_ids::DEMOTE, xwa_paths::XWA2_NEWSLETTER_DEMOTE)?;
        Ok(())
    }
    pub fn newsletter_delete(&self, jid: &str) -> Result<()> {
        execute_wmex_query(self, newsletter_id(jid), query_ids::DELETE, xwa_paths::XWA2_NEWSLETTER_DELETE_V2)?;
        Ok(())
    }
}
