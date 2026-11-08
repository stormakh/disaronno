//! Same as Socket/chats.ts.
use super::socket::{Socket, SocketInner, attr_num, content_string, upgrade};
use crate::auth::*;
use crate::defaults::*;
use crate::error::{Boom, Result};
use crate::events::*;
use crate::types::*;
use crate::utils::chat_utils::*;
use crate::utils::history::get_history_msg;
use crate::utils::make_mutex::{Mutex as FifoLock, make_mutex};
use crate::utils::messages_media::{DecryptedMediaStream, MediaDownloadOptions, download_content_from_message, generate_profile_picture, to_buffer};
use crate::utils::node_cache::NodeCache;
use crate::utils::process_message::{ProcessMessageContext, process_message};
use crate::utils::tc_token_utils::build_tc_token_from_jid;
use crate::utils::time::{Timeout, set_timeout};
use crate::wabinary::*;
use crate::wausync::{USyncQuery, USyncQueryResultList, USyncUser};
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use waproto::history_sync::HistorySyncType;
use waproto::message::{AppStateSyncKeyData, HistorySyncNotification};
use waproto::pb::PbMessage;
use waproto::sync_action_value::{ContactAction, PrivacySettingDisableLinkPreviewsAction, QuickReplyAction as ProtoQuickReplyAction};
use waproto::{ExternalBlobReference, SyncdVersion};

pub fn build_profile_picture_query_content(r#type: &str, tc_token_content: Option<Vec<BinaryNode>>) -> Vec<BinaryNode> {
    let attrs = Attrs::from([("type", r#type), ("query", "url")]);
    match tc_token_content.filter(|c| !c.is_empty()) {
        Some(c) => vec![BinaryNode::with_nodes("picture", attrs, c)],
        None => vec![BinaryNode::tag("picture", attrs)],
    }
}
/// Server-assigned AB props for protocol behavior.
pub struct ServerProps {
    /// AB prop 10518: gate tctoken on 1:1 messages. Default true (safe: avoids 463).
    pub privacy_token_on_1to1: AtomicBool,
    /// AB prop 9666: gate tctoken on profile picture IQs. WA Web default: true.
    pub profile_pic_privacy_token: AtomicBool,
    /// AB prop 14303: issue tctokens to LID instead of PN. WA Web default: false.
    pub lid_trusted_token_issue_to_lid: AtomicBool,
}
#[derive(Default)]
struct HistorySyncCompletion {
    initial_bootstrap_complete: bool,
    recent_sync_complete: bool,
}
pub struct ChatsState {
    privacy_settings: Mutex<Option<Attrs>>,
    pub server_props: ServerProps,
    sync_state: Mutex<SyncState>,
    /// this mutex ensures that messages are processed in order
    pub message_mutex: FifoLock,
    /// this mutex ensures that receipts are processed in order
    pub receipt_mutex: FifoLock,
    /// this mutex ensures that app state patches are processed in order
    pub app_state_patch_mutex: FifoLock,
    /// this mutex ensures that notifications are processed in order
    pub notification_mutex: FifoLock,
    /// Timeout for AwaitingInitialSync state
    awaiting_sync_timeout: Mutex<Option<Timeout>>,
    /// In-memory history sync completion tracking (resets on reconnection)
    history_sync_status: Mutex<HistorySyncCompletion>,
    history_sync_paused_timeout: Mutex<Option<Timeout>>,
    /// Collections blocked on missing app state sync keys (mirrors WA Web's "Blocked" state).
    /// When a key arrives via APP_STATE_SYNC_KEY_SHARE, these are re-synced.
    blocked_collections: Mutex<Vec<WAPatchName>>,
    pub placeholder_resend_cache: Arc<dyn CacheStore>,
}
impl ChatsState {
    pub fn new(config: &SocketConfig) -> ChatsState {
        ChatsState {
            privacy_settings: Mutex::new(None),
            server_props: ServerProps { privacy_token_on_1to1: AtomicBool::new(true), profile_pic_privacy_token: AtomicBool::new(true), lid_trusted_token_issue_to_lid: AtomicBool::new(false) },
            sync_state: Mutex::new(SyncState::Connecting),
            message_mutex: make_mutex(),
            receipt_mutex: make_mutex(),
            app_state_patch_mutex: make_mutex(),
            notification_mutex: make_mutex(),
            awaiting_sync_timeout: Mutex::new(None),
            history_sync_status: Mutex::new(HistorySyncCompletion::default()),
            history_sync_paused_timeout: Mutex::new(None),
            blocked_collections: Mutex::new(Vec::new()),
            placeholder_resend_cache: config.placeholder_resend_cache.clone().unwrap_or_else(|| Arc::new(NodeCache::new(default_cache_ttls::MSG_RETRY))),
        }
    }
}
fn cancel(t: &Mutex<Option<Timeout>>) {
    if let Some(t) = t.lock().unwrap().take() {
        t.cancel();
    }
}
fn prop_true(v: &str) -> bool {
    v == "true" || v == "1"
}
/// Downloads an app state blob with `messages_media`.
pub(crate) fn download_app_state_blob(blob: &ExternalBlobReference, options: &RequestInit) -> Result<Vec<u8>> {
    let msg = DownloadableMessage { media_key: blob.media_key().cloned(), direct_path: blob.direct_path().map(|d| d.as_str().to_string()), url: None };
    let stream: DecryptedMediaStream = download_content_from_message(&msg, MediaType::MdAppState, &MediaDownloadOptions { options: Some(options.clone()), ..MediaDownloadOptions::default() })?;
    to_buffer(&stream)
}
impl SocketInner {
    /// helper function to fetch the given app state sync key
    fn get_app_state_sync_key(&self, key_id: &str) -> Result<Option<AppStateSyncKeyData>> {
        Ok(match self.keys.get_one(KeyKind::AppStateSyncKey, key_id)? {
            Some(KeyValue::AppStateSyncKey(k)) => Some(k),
            _ => None,
        })
    }
    pub fn fetch_privacy_settings(&self, force: bool) -> Result<Attrs> {
        if !force {
            if let Some(p) = self.chats.privacy_settings.lock().unwrap().as_ref() {
                return Ok(p.clone());
            }
        }
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("xmlns", "privacy"), ("to", S_WHATSAPP_NET), ("type", "get")]), vec![BinaryNode::tag("privacy", Attrs::new())]), None)?;
        let result = result.ok_or_else(|| Boom::type_error("Cannot destructure property 'content' of undefined"))?;
        let first = get_all_binary_node_children(&result).first().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'content')"))?;
        let settings = reduce_binary_node_to_dictionary(first, "category");
        *self.chats.privacy_settings.lock().unwrap() = Some(settings.clone());
        Ok(settings)
    }
    /// helper function to run a privacy IQ query
    fn privacy_query(&self, name: &str, value: &str) -> Result<()> {
        let category = BinaryNode::tag("category", Attrs::from([("name", name), ("value", value)]));
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("xmlns", "privacy"), ("to", S_WHATSAPP_NET), ("type", "set")]), vec![BinaryNode::with_nodes("privacy", Attrs::new(), vec![category])]), None)?;
        Ok(())
    }
    pub fn update_messages_privacy(&self, value: WAPrivacyMessagesValue) -> Result<()> {
        self.privacy_query("messages", value.as_str())
    }
    pub fn update_call_privacy(&self, value: WAPrivacyCallValue) -> Result<()> {
        self.privacy_query("calladd", value.as_str())
    }
    pub fn update_last_seen_privacy(&self, value: WAPrivacyValue) -> Result<()> {
        self.privacy_query("last", value.as_str())
    }
    pub fn update_online_privacy(&self, value: WAPrivacyOnlineValue) -> Result<()> {
        self.privacy_query("online", value.as_str())
    }
    pub fn update_profile_picture_privacy(&self, value: WAPrivacyValue) -> Result<()> {
        self.privacy_query("profile", value.as_str())
    }
    pub fn update_status_privacy(&self, value: WAPrivacyValue) -> Result<()> {
        self.privacy_query("status", value.as_str())
    }
    pub fn update_read_receipts_privacy(&self, value: WAReadReceiptsValue) -> Result<()> {
        self.privacy_query("readreceipts", value.as_str())
    }
    pub fn update_groups_add_privacy(&self, value: WAPrivacyGroupAddValue) -> Result<()> {
        self.privacy_query("groupadd", value.as_str())
    }
    pub fn update_default_disappearing_mode(&self, duration: u32) -> Result<()> {
        let mode = BinaryNode::tag("disappearing_mode", Attrs::from([("duration", duration.to_string())]));
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("xmlns", "disappearing_mode"), ("to", S_WHATSAPP_NET), ("type", "set")]), vec![mode]), None)?;
        Ok(())
    }
    pub fn get_bot_list_v2(&self) -> Result<Vec<BotListInfo>> {
        let resp = self.query(BinaryNode::with_nodes("iq", Attrs::from([("xmlns", "bot"), ("to", S_WHATSAPP_NET), ("type", "get")]), vec![BinaryNode::tag("bot", Attrs::from([("v", "2")]))]), None)?;
        let bot_node = get_binary_node_child(resp.as_ref(), "bot");
        let mut bot_list = Vec::new();
        for section in get_binary_node_children(bot_node, "section") {
            if section.attr("type") == Some("all") {
                for bot in get_binary_node_children(Some(section), "bot") {
                    bot_list.push(BotListInfo { jid: bot.attr("jid").unwrap_or_default().to_string(), persona_id: bot.attr("persona_id").unwrap_or_default().to_string() });
                }
            }
        }
        Ok(bot_list)
    }
    pub fn fetch_status(&self, jids: &[String]) -> Result<Option<Vec<USyncQueryResultList>>> {
        let mut usync_query = USyncQuery::new().with_status_protocol();
        for jid in jids {
            usync_query.add_user(USyncUser::new().with_id(jid.as_str()));
        }
        Ok(self.execute_usync_query(&usync_query)?.map(|r| r.list))
    }
    pub fn fetch_disappearing_duration(&self, jids: &[String]) -> Result<Option<Vec<USyncQueryResultList>>> {
        let mut usync_query = USyncQuery::new().with_disappearing_mode_protocol();
        for jid in jids {
            usync_query.add_user(USyncUser::new().with_id(jid.as_str()));
        }
        Ok(self.execute_usync_query(&usync_query)?.map(|r| r.list))
    }
    fn profile_picture_attrs(&self, jid: &str) -> Result<Attrs> {
        if jid.is_empty() {
            return Err(Boom::new("Illegal no-jid profile update. Please specify either your ID or the ID of the chat you wish to update"));
        }
        let me = self.me_id().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'id')"))?;
        let mut attrs = Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "w:profile:picture")]);
        let normalized = jid_normalized_user(jid);
        if normalized != jid_normalized_user(&me) {
            attrs.set("target", normalized); // in case it is someone other than us
        }
        Ok(attrs)
    }
    /// update the profile picture for yourself or a group
    pub fn update_profile_picture(&self, jid: &str, content: &WAMediaUpload, dimensions: Option<crate::utils::messages_media::Dimensions>) -> Result<()> {
        let attrs = self.profile_picture_attrs(jid)?;
        let img = generate_profile_picture(content, dimensions)?;
        self.query(BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::with_bytes("picture", Attrs::from([("type", "image")]), img)]), None)?;
        Ok(())
    }
    /// remove the profile picture for yourself or a group
    pub fn remove_profile_picture(&self, jid: &str) -> Result<()> {
        let attrs = self.profile_picture_attrs(jid)?;
        self.query(BinaryNode::tag("iq", attrs), None)?;
        Ok(())
    }
    /// update the profile status for yourself
    pub fn update_profile_status(&self, status: &str) -> Result<()> {
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "status")]), vec![BinaryNode::with_bytes("status", Attrs::new(), status.as_bytes())]), None)?;
        Ok(())
    }
    pub fn fetch_blocklist(&self) -> Result<Vec<Option<String>>> {
        let result = self.query(BinaryNode::tag("iq", Attrs::from([("xmlns", "blocklist"), ("to", S_WHATSAPP_NET), ("type", "get")])), None)?;
        let list_node = get_binary_node_child(result.as_ref(), "list");
        Ok(get_binary_node_children(list_node, "item").into_iter().map(|n| n.attr("jid").map(str::to_string)).collect())
    }
    /// `action` is `block` or `unblock`.
    pub fn update_block_status(&self, jid: &str, action: &str) -> Result<()> {
        let normalized_jid = jid_normalized_user(jid);
        let lid_mapping = self.signal_repository.lid_mapping();
        let lid;
        let mut pn_jid = None;
        if is_lid_user(&normalized_jid) || is_hosted_lid_user(&normalized_jid) {
            lid = normalized_jid.clone();
            if action == "block" {
                let pn = lid_mapping.get_pn_for_lid(&normalized_jid)?.ok_or_else(|| Boom::status(format!("Unable to resolve PN JID for LID: {jid}"), 400))?;
                pn_jid = Some(jid_normalized_user(&pn));
            }
        } else if is_pn_user(&normalized_jid) || is_hosted_pn_user(&normalized_jid) {
            lid = lid_mapping.get_lid_for_pn(&normalized_jid)?.ok_or_else(|| Boom::status(format!("Unable to resolve LID for PN JID: {jid}"), 400))?;
            if action == "block" {
                pn_jid = Some(jid_normalized_user(&normalized_jid));
            }
        } else {
            return Err(Boom::status(format!("Invalid jid: {jid}"), 400));
        }
        let mut item_attrs = Attrs::from([("action", action), ("jid", lid.as_str())]);
        if action == "block" {
            let pn = pn_jid.ok_or_else(|| Boom::status(format!("pn_jid required for block: {jid}"), 400))?;
            item_attrs.set("pn_jid", pn);
        }
        self.query(BinaryNode::with_nodes("iq", Attrs::from([("xmlns", "blocklist"), ("to", S_WHATSAPP_NET), ("type", "set")]), vec![BinaryNode::tag("item", item_attrs)]), None)?;
        Ok(())
    }
    pub fn get_business_profile(&self, jid: &str) -> Result<Option<WABusinessProfile>> {
        let profile = BinaryNode::tag("profile", Attrs::from([("jid", jid)]));
        let results = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", "s.whatsapp.net"), ("xmlns", "w:biz"), ("type", "get")]), vec![BinaryNode::with_nodes("business_profile", Attrs::from([("v", "244")]), vec![profile])]), None)?;
        let profile_node = get_binary_node_child(results.as_ref(), "business_profile");
        let Some(profiles) = get_binary_node_child(profile_node, "profile") else { return Ok(None) };
        let child_text = |tag: &str| content_string(get_binary_node_child(Some(profiles), tag));
        let category = content_string(get_binary_node_child(get_binary_node_child(Some(profiles), "categories"), "category"));
        let business_hours = get_binary_node_child(Some(profiles), "business_hours");
        let business_config = business_hours.map(|b| {
            get_binary_node_children(Some(b), "business_hours_config")
                .into_iter()
                .map(|c| WABusinessHoursConfig {
                    day_of_week: c.attr("day_of_week").unwrap_or_default().to_string(),
                    mode: c.attr("mode").unwrap_or_default().to_string(),
                    open_time: c.attr("open_time").and_then(|v| v.parse().ok()),
                    close_time: c.attr("close_time").and_then(|v| v.parse().ok()),
                })
                .collect()
        });
        Ok(Some(WABusinessProfile {
            wid: profiles.attr("jid").map(str::to_string),
            address: child_text("address"),
            description: child_text("description").unwrap_or_default(),
            website: child_text("website").filter(|w| !w.is_empty()).into_iter().collect(),
            email: child_text("email"),
            category,
            business_hours: WABusinessHours { timezone: business_hours.and_then(|b| b.attr("timezone")).map(str::to_string), config: None, business_config },
        }))
    }
    /// `type` is `account_sync` or `groups`.
    pub fn clean_dirty_bits(&self, r#type: &str, from_timestamp: Option<&str>) -> Result<()> {
        self.logger.info(&format!("clean dirty bits {}", r#type));
        let mut clean_attrs = Attrs::from([("type", r#type)]);
        if let Some(t) = from_timestamp.filter(|t| !t.is_empty() && *t != "0") {
            clean_attrs.set("timestamp", t);
        }
        let mut attrs = Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "urn:xmpp:whatsapp:dirty")]);
        attrs.set("id", self.generate_message_tag());
        self.send_node(&BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::tag("clean", clean_attrs)]))
    }
    fn on_mutation(&self, mutation: &ChatMutation, initial: Option<&mut InitialAppStateSyncOptions>) {
        let me = self.creds.lock().unwrap().me.clone();
        process_sync_action(mutation, &self.ev, me.as_ref(), initial, Some(self.logger.as_ref()));
    }
    /// `is_initial_sync` makes processing use and change the account settings of the creds.
    fn apply_mutations(&self, map: ChatMutationMap, is_initial_sync: bool) {
        let mut initial = is_initial_sync.then(|| InitialAppStateSyncOptions { account_settings: self.creds.lock().unwrap().account_settings.clone() });
        for (_, mutation) in map.into_pairs() {
            self.on_mutation(&mutation, initial.as_mut());
        }
        if let Some(i) = initial {
            // upstream changes the object of the creds in place
            self.creds.lock().unwrap().account_settings = i.account_settings;
        }
    }
    fn tx_key(&self, fallback: &str) -> String {
        self.me_id().filter(|i| !i.is_empty()).unwrap_or_else(|| fallback.to_string())
    }
    pub fn resync_app_state(&self, collections: &[WAPatchName], is_initial_sync: bool) -> Result<()> {
        self.ev.run_buffered(|| self.resync_app_state_inner(collections, is_initial_sync))
    }
    fn resync_app_state_inner(&self, collections: &[WAPatchName], is_initial_sync: bool) -> Result<()> {
        let app_state_sync_key_cache: RefCell<FxHashMap<String, Option<AppStateSyncKeyData>>> = RefCell::new(FxHashMap::default());
        let get_cached_app_state_sync_key = |key_id: &str| -> Result<Option<AppStateSyncKeyData>> {
            if let Some(k) = app_state_sync_key_cache.borrow().get(key_id) {
                return Ok(k.clone());
            }
            let key = self.get_app_state_sync_key(key_id)?;
            app_state_sync_key_cache.borrow_mut().insert(key_id.to_string(), key.clone());
            Ok(key)
        };
        let options = self.config.options.clone();
        let download = |blob: &ExternalBlobReference| download_app_state_blob(blob, &options);
        // we use this to determine which events to fire
        // otherwise when we resync from scratch -- all notifications will fire
        let mut initial_version_map: FxHashMap<WAPatchName, u64> = FxHashMap::default();
        let mut global_mutation_map = ChatMutationMap::new();
        let validate = self.config.app_state_mac_verification;
        let logger = self.logger.as_ref();

        self.transaction(&self.tx_key("resync-app-state"), || {
            let mut collections_to_handle: Vec<WAPatchName> = Vec::with_capacity(collections.len());
            for c in collections {
                if !collections_to_handle.contains(c) {
                    collections_to_handle.push(*c);
                }
            }
            // in case something goes wrong -- ensure we don't enter a loop that cannot be exited from
            let mut attempts_map: FxHashMap<WAPatchName, u32> = FxHashMap::default();
            // collections that failed and need a full snapshot on retry
            // mirrors WA Web's ErrorFatal -> force snapshot behavior
            let mut force_snapshot_collections: Vec<WAPatchName> = Vec::new();
            // keep executing till all collections are done
            // sometimes a single patch request will not return all the patches (God knows why)
            // so we fetch till they're all done (this is determined by the "has_more_patches" flag)
            while !collections_to_handle.is_empty() {
                let mut states: FxHashMap<WAPatchName, LtHashState> = FxHashMap::default();
                let mut nodes = Vec::with_capacity(collections_to_handle.len());
                for name in &collections_to_handle {
                    let name = *name;
                    let state = match self.keys.get_one(KeyKind::AppStateSyncVersion, name.as_str())? {
                        Some(KeyValue::AppStateSyncVersion(mut s)) => {
                            ensure_lt_hash_state_version(&mut s);
                            initial_version_map.entry(name).or_insert(s.version);
                            s
                        }
                        _ => new_lt_hash_state(),
                    };
                    let should_force_snapshot = force_snapshot_collections.contains(&name);
                    if should_force_snapshot {
                        force_snapshot_collections.retain(|c| *c != name);
                    }
                    if logger.is_enabled(crate::utils::logger::LogLevel::Info) {
                        logger.info(&format!("resyncing {} from v{}{}", name.as_str(), state.version, if should_force_snapshot { " (forcing snapshot)" } else { "" }));
                    }
                    // return snapshot if syncing from scratch or forcing after a failed attempt
                    let return_snapshot = if should_force_snapshot || state.version == 0 { "true" } else { "false" };
                    let mut attrs = Attrs::from([("name", name.as_str())]);
                    attrs.set("version", state.version.to_string());
                    attrs.set("return_snapshot", return_snapshot);
                    nodes.push(BinaryNode::tag("collection", attrs));
                    states.insert(name, state);
                }
                let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("xmlns", "w:sync:app:state"), ("type", "set")]), vec![BinaryNode::with_nodes("sync", Attrs::new(), nodes)]), None)?;
                // extract from binary node
                let empty = BinaryNode::tag("iq", Attrs::new());
                let decoded = extract_syncd_patches(result.as_ref().unwrap_or(&empty), &download)?;
                for (key, collection) in decoded.into_pairs() {
                    let Some(name) = WAPatchName::parse(&key) else { continue };
                    let SyncdCollection { mut patches, has_more_patches, snapshot } = collection;
                    let mut work = || -> Result<()> {
                        if let Some(snapshot) = &snapshot {
                            let DecodedSyncd { state: new_state, mutation_map } = decode_syncd_snapshot(name, snapshot, &get_cached_app_state_sync_key, initial_version_map.get(&name).copied(), validate.snapshot, Some(logger))?;
                            for (k, v) in mutation_map.into_pairs() {
                                global_mutation_map.insert(k, v);
                            }
                            self.keys.set_one(KeyKind::AppStateSyncVersion, name.as_str(), Some(KeyValue::AppStateSyncVersion(new_state.clone())))?;
                            states.insert(name, new_state);
                        }
                        // only process if there are syncd patches
                        if !patches.is_empty() {
                            let initial = states.get(&name).cloned().unwrap_or_else(new_lt_hash_state);
                            let DecodedSyncd { state: new_state, mutation_map } = decode_patches(name, &mut patches, &initial, &get_cached_app_state_sync_key, &download, initial_version_map.get(&name).copied(), Some(logger), validate.patch)?;
                            let version = new_state.version;
                            self.keys.set_one(KeyKind::AppStateSyncVersion, name.as_str(), Some(KeyValue::AppStateSyncVersion(new_state)))?;
                            initial_version_map.insert(name, version);
                            for (k, v) in mutation_map.into_pairs() {
                                global_mutation_map.insert(k, v);
                            }
                        }
                        if has_more_patches {
                            logger.info(&format!("{} has more patches...", name.as_str()));
                        } else {
                            // collection is done with sync
                            collections_to_handle.retain(|c| *c != name);
                        }
                        Ok(())
                    };
                    if let Err(error) = work() {
                        let attempts = attempts_map.entry(name).or_insert(0);
                        *attempts += 1;
                        let attempts = *attempts;
                        let version = states.get(&name).map_or(0, |s| s.version);
                        if is_missing_key_error(&error) && attempts >= MAX_SYNC_ATTEMPTS {
                            // WA Web treats missing keys as "Blocked" — park the collection
                            // until the key arrives via APP_STATE_SYNC_KEY_SHARE.
                            logger.warn(&format!("{} blocked on missing key from v{version}, parking after {attempts} attempts", name.as_str()));
                            let mut blocked = self.chats.blocked_collections.lock().unwrap();
                            if !blocked.contains(&name) {
                                blocked.push(name);
                            }
                            drop(blocked);
                            collections_to_handle.retain(|c| *c != name);
                        } else if is_missing_key_error(&error) {
                            // Retry with a snapshot which may use a different key.
                            logger.info(&format!("{} blocked on missing key from v{version}, retrying with snapshot", name.as_str()));
                            force_snapshot_collections.push(name);
                        } else if is_app_state_sync_irrecoverable(Some(&error), attempts) {
                            logger.warn(&format!("failed to sync {} from v{version}, giving up: {error}", name.as_str()));
                            collections_to_handle.retain(|c| *c != name);
                        } else {
                            logger.info(&format!("failed to sync {} from v{version}, forcing snapshot retry: {error}", name.as_str()));
                            // force a full snapshot on retry to recover from
                            // corrupted local state (e.g. LTHash MAC mismatch)
                            force_snapshot_collections.push(name);
                        }
                    }
                }
            }
            Ok(())
        })?;
        self.apply_mutations(global_mutation_map, is_initial_sync);
        Ok(())
    }
    /// fetch the profile picture of a user/group
    /// `type` is `preview` for a low res picture, and `image` for the high res picture
    pub fn profile_picture_url(&self, jid: &str, r#type: &str, timeout_ms: Option<u64>) -> Result<Option<String>> {
        // WA Web only includes tctoken for user JIDs (not groups/newsletters)
        // and never for own profile pic (Chat model for self has no tcToken).
        // Including tctoken for own JID causes the server to never respond.
        let normalized_jid = jid_normalized_user(jid);
        let is_user_jid = is_pn_user(&normalized_jid) || is_lid_user(&normalized_jid);
        let me = self.user();
        let is_self = me.as_ref().is_some_and(|m| normalized_jid == jid_normalized_user(&m.id) || m.lid.as_ref().is_some_and(|l| !l.is_empty() && normalized_jid == jid_normalized_user(l)));
        let mut tc_token_content = None;
        if self.chats.server_props.profile_pic_privacy_token.load(Ordering::Relaxed) && is_user_jid && !is_self {
            let lid_mapping = self.signal_repository.lid_mapping();
            let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);
            tc_token_content = build_tc_token_from_jid(&normalized_jid, Vec::new(), self.keys.as_ref(), &get_lid);
        }
        let mut attrs = Attrs::from([("target", normalized_jid.as_str())]);
        attrs.set("to", S_WHATSAPP_NET);
        attrs.set("type", "get");
        attrs.set("xmlns", "w:profile:picture");
        let result = self.query(BinaryNode::with_nodes("iq", attrs, build_profile_picture_query_content(r#type, tc_token_content)), timeout_ms)?;
        Ok(get_binary_node_child(result.as_ref(), "picture").and_then(|c| c.attr("url")).map(str::to_string))
    }
    pub fn create_call_link(&self, r#type: CallType, start_time: Option<u64>, timeout_ms: Option<u64>) -> Result<Option<String>> {
        let attrs = Attrs::from([("media", r#type.as_str())]);
        let link = match start_time {
            Some(t) => BinaryNode::with_nodes("link_create", attrs, vec![BinaryNode::tag("event", Attrs::from([("start_time", t.to_string())]))]),
            None => BinaryNode::tag("link_create", attrs),
        };
        let mut call_attrs = Attrs::new();
        call_attrs.set("id", self.generate_message_tag());
        call_attrs.set("to", "@call");
        let result = self.query(BinaryNode::with_nodes("call", call_attrs, vec![link]), timeout_ms)?;
        Ok(get_binary_node_child(result.as_ref(), "link_create").and_then(|c| c.attr("token")).map(str::to_string))
    }
    pub fn send_presence_update(&self, r#type: WAPresence, to_jid: Option<&str>) -> Result<()> {
        let me = self.user().ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'name')"))?;
        let is_available_type = r#type == WAPresence::Available;
        if is_available_type || r#type == WAPresence::Unavailable {
            let Some(name) = me.name.as_deref().filter(|n| !n.is_empty()) else {
                self.logger.warn("no name present, ignoring presence update request...");
                return Ok(());
            };
            self.ev.emit(BaileysEvent::ConnectionUpdate(ConnectionState { is_online: Some(is_available_type), ..ConnectionState::default() }));
            if is_available_type {
                self.send_unified_session();
            }
            self.send_node(&BinaryNode::tag("presence", Attrs::from([("name", name.replace('@', "").as_str()), ("type", r#type.as_str())])))
        } else {
            let to_jid = to_jid.ok_or_else(|| Boom::type_error("Cannot destructure property 'server' of undefined"))?;
            let is_lid = jid_decode(to_jid).ok_or_else(|| Boom::type_error("Cannot destructure property 'server' of undefined"))?.server == "lid";
            let from = if is_lid { me.lid.clone().unwrap_or_default() } else { me.id.clone() };
            let child = match r#type {
                WAPresence::Recording => BinaryNode::tag("composing", Attrs::from([("media", "audio")])),
                t => BinaryNode::tag(t.as_str(), Attrs::new()),
            };
            self.send_node(&BinaryNode::with_nodes("chatstate", Attrs::from([("from", from.as_str()), ("to", to_jid)]), vec![child]))
        }
    }
    /// `to_jid` is the jid to subscribe to
    pub fn presence_subscribe(&self, to_jid: &str) -> Result<()> {
        // Only include tctoken for user JIDs — groups/newsletters don't use tctokens
        let normalized_to_jid = jid_normalized_user(to_jid);
        let is_user_jid = is_pn_user(&normalized_to_jid) || is_lid_user(&normalized_to_jid);
        let lid_mapping = self.signal_repository.lid_mapping();
        let get_lid = |pn: &str| lid_mapping.get_lid_for_pn(pn);
        let tc_token_content = if is_user_jid { build_tc_token_from_jid(&normalized_to_jid, Vec::new(), self.keys.as_ref(), &get_lid) } else { None };
        let mut attrs = Attrs::from([("to", to_jid)]);
        attrs.set("id", self.generate_message_tag());
        attrs.set("type", "subscribe");
        let node = match tc_token_content {
            Some(c) => BinaryNode::with_nodes("presence", attrs, c),
            None => BinaryNode::tag("presence", attrs),
        };
        self.send_node(&node)
    }
    pub(crate) fn handle_presence_update(&self, node: &BinaryNode) {
        let jid = node.attr("from").unwrap_or_default();
        let participant = node.attr("participant").filter(|p| !p.is_empty()).unwrap_or(jid);
        if (self.config.should_ignore_jid)(jid) == Some(true) && jid != S_WHATSAPP_NET {
            return;
        }
        let mut presence = None;
        if node.tag.as_str() == "presence" {
            presence = Some(PresenceData {
                last_known_presence: if node.attr("type") == Some("unavailable") { WAPresence::Unavailable } else { WAPresence::Available },
                last_seen: node.attr("last").filter(|l| !l.is_empty() && *l != "deny").map(|l| attr_num(Some(l)) as u64),
                group_online_count: node.attr("count").filter(|c| !c.is_empty()).map(|c| attr_num(Some(c)) as u32),
            });
        } else if let Some(Content::Nodes(content)) = &node.content {
            if let Some(first_child) = content.first() {
                let mut r#type = match first_child.tag.as_str() {
                    "paused" => WAPresence::Available,
                    other => WAPresence::parse(other).unwrap_or(WAPresence::Composing),
                };
                if first_child.attr("media") == Some("audio") {
                    r#type = WAPresence::Recording;
                }
                presence = Some(PresenceData { last_known_presence: r#type, last_seen: None, group_online_count: None });
            }
        } else {
            self.logger.error("recv invalid presence node");
        }
        if let Some(p) = presence {
            self.ev.emit(BaileysEvent::PresenceUpdate(PresenceUpdate { id: jid.to_string(), presences: vec![(participant.to_string(), p)] }));
        }
    }
    pub fn app_patch(&self, patch_create: &WAPatchCreate) -> Result<()> {
        let name = patch_create.r#type;
        let my_app_state_key_id = self.creds.lock().unwrap().my_app_state_key_id.clone().filter(|k| !k.is_empty()).ok_or_else(|| Boom::status("App state key not present!", 400))?;
        let get_key = |key_id: &str| self.get_app_state_sync_key(key_id);
        let (initial, encode_result) = self.chats.app_state_patch_mutex.mutex(|| {
            self.transaction(&self.tx_key("app-patch"), || {
                self.logger.debug("applying app patch");
                self.resync_app_state(&[name], false)?;
                let initial = match self.keys.get_one(KeyKind::AppStateSyncVersion, name.as_str())? {
                    Some(KeyValue::AppStateSyncVersion(mut s)) => {
                        ensure_lt_hash_state_version(&mut s);
                        s
                    }
                    _ => new_lt_hash_state(),
                };
                let encode_result = encode_syncd_patch(patch_create, &my_app_state_key_id, &initial, &get_key)?;
                let mut attrs = Attrs::from([("name", name.as_str())]);
                attrs.set("version", (encode_result.state.version - 1).to_string());
                attrs.set("return_snapshot", "false");
                let patch = BinaryNode::with_bytes("patch", Attrs::new(), encode_result.patch.encode());
                let node = BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "w:sync:app:state")]), vec![BinaryNode::with_nodes("sync", Attrs::new(), vec![BinaryNode::with_nodes("collection", attrs, vec![patch])])]);
                self.query(node, None)?;
                self.keys.set_one(KeyKind::AppStateSyncVersion, name.as_str(), Some(KeyValue::AppStateSyncVersion(encode_result.state.clone())))?;
                Ok((initial, encode_result.clone()))
            })
        })?;
        if self.config.emit_own_events {
            let mut patch = encode_result.patch.clone();
            patch.set_version(SyncdVersion::default().with_version(encode_result.state.version));
            let options = self.config.options.clone();
            let download = |blob: &ExternalBlobReference| download_app_state_blob(blob, &options);
            let decoded = decode_patches(name, std::slice::from_mut(&mut patch), &initial, &get_key, &download, None, Some(self.logger.as_ref()), false)?;
            self.apply_mutations(decoded.mutation_map, false);
        }
        Ok(())
    }
    /// fetch AB props
    pub fn fetch_props(&self) -> Result<Attrs> {
        let mut props_attrs = Attrs::from([("protocol", "1")]);
        if let Some(h) = self.creds.lock().unwrap().last_prop_hash.as_deref().filter(|h| !h.is_empty()) {
            props_attrs.set("hash", h);
        }
        let result_node = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("xmlns", "abt"), ("type", "get")]), vec![BinaryNode::tag("props", props_attrs)]), None)?;
        let props_node = get_binary_node_child(result_node.as_ref(), "props");
        let mut props = Attrs::new();
        if let Some(p) = props_node {
            if let Some(hash) = p.attr("hash").filter(|h| !h.is_empty()) {
                // on some clients, the hash is returning as undefined
                self.emit_creds_fields(CredsUpdate { last_prop_hash: Some(Some(hash.to_string())), ..CredsUpdate::default() });
            }
            props = reduce_binary_node_to_dictionary(p, "prop");
        }
        // Extract protocol-relevant AB props (only the ones we need)
        let sp = &self.chats.server_props;
        if let Some(v) = props.get("10518").or_else(|| props.get("privacy_token_sending_on_all_1_on_1_messages")) {
            sp.privacy_token_on_1to1.store(prop_true(v), Ordering::Relaxed);
        }
        if let Some(v) = props.get("9666").or_else(|| props.get("profile_scraping_privacy_token_in_photo_iq")) {
            sp.profile_pic_privacy_token.store(prop_true(v), Ordering::Relaxed);
        }
        if let Some(v) = props.get("14303").or_else(|| props.get("lid_trusted_token_issue_to_lid")) {
            sp.lid_trusted_token_issue_to_lid.store(prop_true(v), Ordering::Relaxed);
        }
        self.logger.debug("fetched props");
        Ok(props)
    }
    /// modify a chat -- mark unread, read etc.
    /// last_messages must be sorted in reverse chronologically
    /// requires the last messages till the last message received; required for archive & unread
    pub fn chat_modify(&self, modification: &ChatModification, jid: &str) -> Result<()> {
        let patch = chat_modification_to_app_patch(modification, jid)?;
        self.app_patch(&patch)
    }
    pub fn update_profile_name(&self, name: &str) -> Result<()> {
        self.chat_modify(&ChatModification::PushNameSetting(name.to_string()), "")
    }
    /// Enable/Disable link preview privacy, not related to baileys link preview generation
    pub fn update_disable_link_previews_privacy(&self, is_previews_disabled: bool) -> Result<()> {
        self.chat_modify(&ChatModification::DisableLinkPreviews(PrivacySettingDisableLinkPreviewsAction::default().with_is_previews_disabled(is_previews_disabled)), "")
    }
    /// Star or Unstar a message
    pub fn star(&self, jid: &str, messages: Vec<StarredMessage>, star: bool) -> Result<()> {
        self.chat_modify(&ChatModification::Star { messages, star }, jid)
    }
    /// Add or Edit Contact
    pub fn add_or_edit_contact(&self, jid: &str, contact: ContactAction) -> Result<()> {
        self.chat_modify(&ChatModification::Contact(Some(contact)), jid)
    }
    /// Remove Contact
    pub fn remove_contact(&self, jid: &str) -> Result<()> {
        self.chat_modify(&ChatModification::Contact(None), jid)
    }
    /// Adds label
    pub fn add_label(&self, jid: &str, labels: LabelActionBody) -> Result<()> {
        self.chat_modify(&ChatModification::AddLabel(labels), jid)
    }
    /// Adds label for the chats
    pub fn add_chat_label(&self, jid: &str, label_id: &str) -> Result<()> {
        self.chat_modify(&ChatModification::AddChatLabel(ChatLabelAssociationActionBody { label_id: label_id.to_string() }), jid)
    }
    /// Removes label for the chat
    pub fn remove_chat_label(&self, jid: &str, label_id: &str) -> Result<()> {
        self.chat_modify(&ChatModification::RemoveChatLabel(ChatLabelAssociationActionBody { label_id: label_id.to_string() }), jid)
    }
    /// Adds label for the message
    pub fn add_message_label(&self, jid: &str, message_id: &str, label_id: &str) -> Result<()> {
        self.chat_modify(&ChatModification::AddMessageLabel(MessageLabelAssociationActionBody { label_id: label_id.to_string(), message_id: message_id.to_string() }), jid)
    }
    /// Removes label for the message
    pub fn remove_message_label(&self, jid: &str, message_id: &str, label_id: &str) -> Result<()> {
        self.chat_modify(&ChatModification::RemoveMessageLabel(MessageLabelAssociationActionBody { label_id: label_id.to_string(), message_id: message_id.to_string() }), jid)
    }
    /// Add or Edit Quick Reply
    pub fn add_or_edit_quick_reply(&self, quick_reply: QuickReplyAction) -> Result<()> {
        self.chat_modify(&ChatModification::QuickReply(quick_reply), "")
    }
    /// Remove Quick Reply
    pub fn remove_quick_reply(&self, timestamp: &str) -> Result<()> {
        self.chat_modify(&ChatModification::QuickReply(QuickReplyAction { action: ProtoQuickReplyAction::default().with_deleted(true), timestamp: Some(timestamp.to_string()) }), "")
    }
    /// queries need to be fired on connection open
    /// help ensure parity with WA Web
    fn execute_init_queries(&self) -> Result<()> {
        // Upstream sends the three at once and fails with the first error. All three run here too.
        let props = self.fetch_props().map(|_| ());
        let blocklist = self.fetch_blocklist().map(|_| ());
        let privacy = self.fetch_privacy_settings(false).map(|_| ());
        props.and(blocklist).and(privacy)
    }
    fn do_app_state_sync(&self) -> Result<()> {
        let syncing = *self.chats.sync_state.lock().unwrap() == SyncState::Syncing;
        if syncing {
            // All collections will be synced, so clear any blocked ones
            self.chats.blocked_collections.lock().unwrap().clear();
            self.logger.info("Doing app state sync");
            self.resync_app_state(&ALL_WA_PATCH_NAMES, true)?;
            // Sync is complete, go online and flush everything
            *self.chats.sync_state.lock().unwrap() = SyncState::Online;
            self.logger.info("App state sync complete, transitioning to Online state and flushing buffer");
            self.ev.flush();
            let account_sync_counter = self.creds.lock().unwrap().account_sync_counter + 1;
            self.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { account_sync_counter: Some(account_sync_counter), ..CredsUpdate::default() })));
        }
        Ok(())
    }
    pub fn upsert_message(&self, msg: WAMessage, r#type: MessageUpsertType) -> Result<()> {
        self.ev.run_buffered(|| self.upsert_message_inner(msg, r#type))
    }
    fn upsert_message_inner(&self, msg: WAMessage, r#type: MessageUpsertType) -> Result<()> {
        self.ev.emit(BaileysEvent::MessagesUpsert(MessagesUpsert { messages: vec![msg.clone()], r#type, request_id: None }));
        let from_me = msg.key().and_then(|k| k.from_me()) == Some(true);
        if let Some(push_name) = msg.push_name().filter(|n| !n.as_str().is_empty()) {
            if !from_me {
                let key = msg.key();
                let jid = key.and_then(|k| k.participant()).filter(|p| !p.as_str().is_empty()).or_else(|| key.and_then(|k| k.remote_jid())).map_or("", |s| s.as_str());
                let jid = jid_normalized_user(jid);
                let mut contact = Contact::new(jid);
                contact.notify = Some(push_name.as_str().to_string());
                contact.verified_name = msg.verified_biz_name().map(|v| v.as_str().to_string());
                self.ev.emit(BaileysEvent::ContactsUpdate(vec![ContactUpdate::new(contact)]));
            } else {
                // update our pushname too
                let me = self.user();
                if me.as_ref().and_then(|m| m.name.as_deref()) != Some(push_name.as_str()) {
                    let mut me = me.unwrap_or_default();
                    me.name = Some(push_name.as_str().to_string());
                    self.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { me: Some(Some(me)), ..CredsUpdate::default() })));
                }
            }
        }
        let history_msg = msg.message().and_then(get_history_msg);
        let should_process_history_msg = history_msg.is_some_and(|h| (self.config.should_sync_history_message)(h) && h.sync_type().is_some_and(|t| PROCESSABLE_HISTORY_TYPES.iter().any(|p| p.0 == t.0)));
        if let Some(h) = history_msg.filter(|_| should_process_history_msg) {
            self.on_history_chunk(h);
        }
        // State machine: decide on sync and flush
        if history_msg.is_some() {
            let mut state = self.chats.sync_state.lock().unwrap();
            if *state == SyncState::AwaitingInitialSync {
                cancel(&self.chats.awaiting_sync_timeout);
                if should_process_history_msg {
                    *state = SyncState::Syncing;
                    self.logger.info("Transitioned to Syncing state");
                    // Let doAppStateSync handle the final flush after it's done
                } else {
                    *state = SyncState::Online;
                    drop(state);
                    self.logger.info("History sync skipped, transitioning to Online state and flushing buffer");
                    self.ev.flush();
                }
            }
        }
        // Promise.all of upstream: both run, and the first error is the result
        let synced = if should_process_history_msg { self.do_app_state_sync() } else { Ok(()) };
        let creds = self.creds.lock().unwrap().clone();
        let get_message = self.config.get_message.clone();
        let processed = process_message(
            &msg,
            &ProcessMessageContext {
                signal_repository: self.signal_repository.as_ref(),
                should_process_history_msg,
                placeholder_resend_cache: Some(self.chats.placeholder_resend_cache.as_ref()),
                ev: &self.ev,
                creds: &creds,
                key_store: self.keys.as_ref(),
                logger: Some(self.logger.as_ref()),
                options: &self.config.options,
                get_message: &*get_message,
            },
        );
        synced.and(processed)?;
        // If the app state key arrives and we are waiting to sync, trigger the sync now.
        let key_share = msg.message().and_then(|m| m.protocol_message()).is_some_and(|p| p.app_state_sync_key_share().is_some());
        if key_share && *self.chats.sync_state.lock().unwrap() == SyncState::Syncing {
            self.logger.info("App state sync key arrived, triggering app state sync");
            self.do_app_state_sync()?;
        }
        Ok(())
    }
    fn emit_history_status(&self, sync_type: HistorySyncType, status: HistorySyncStatus, explicit: bool) {
        self.ev.emit(BaileysEvent::MessagingHistoryStatus(MessagingHistoryStatus { sync_type, status, explicit }));
    }
    fn on_history_chunk(&self, h: &HistorySyncNotification) {
        let Some(sync_type) = h.sync_type().map(|t| HistorySyncType(t.0)) else { return };
        let mut completed = false;
        let mut status = self.chats.history_sync_status.lock().unwrap();
        // INITIAL_BOOTSTRAP — fire immediately, no progress check (same as WA Web K function)
        if sync_type == HistorySyncType::INITIAL_BOOTSTRAP && !status.initial_bootstrap_complete {
            status.initial_bootstrap_complete = true;
            completed = true;
        }
        // RECENT with progress === 100 — explicit completion
        if sync_type == HistorySyncType::RECENT && h.progress() == Some(100) && !status.recent_sync_complete {
            status.recent_sync_complete = true;
            cancel(&self.chats.history_sync_paused_timeout);
            completed = true;
        }
        let recent_open = sync_type == HistorySyncType::RECENT && !status.recent_sync_complete;
        drop(status);
        if completed {
            self.emit_history_status(sync_type, HistorySyncStatus::Complete, true);
        }
        // Reset 120s paused timeout on any RECENT chunk (like WA Web's handleChunkProgress)
        if recent_open {
            cancel(&self.chats.history_sync_paused_timeout);
            let weak = self.self_weak();
            let timer = set_timeout(HISTORY_SYNC_PAUSED_TIMEOUT_MS, move || {
                let Some(s) = upgrade(&weak) else { return };
                let fire = {
                    let mut st = s.chats.history_sync_status.lock().unwrap();
                    let fire = !st.recent_sync_complete;
                    st.recent_sync_complete = true;
                    fire
                };
                if fire {
                    s.emit_history_status(HistorySyncType::RECENT, HistorySyncStatus::Paused, false);
                }
                s.chats.history_sync_paused_timeout.lock().unwrap().take();
            });
            *self.chats.history_sync_paused_timeout.lock().unwrap() = Some(timer);
        }
    }
    pub(crate) fn on_dirty_chats(&self, node: &BinaryNode, dirty: &BinaryNode) {
        match dirty.attr("type") {
            Some("account_sync") => {
                if let Some(ts) = dirty.attr("timestamp").filter(|t| !t.is_empty()) {
                    if let Some(last) = self.creds.lock().unwrap().last_account_sync_timestamp.filter(|l| *l != 0) {
                        if let Err(e) = self.clean_dirty_bits("account_sync", Some(&last.to_string())) {
                            self.on_unexpected_error(&e, "dirty");
                        }
                    }
                    let last_account_sync_timestamp = attr_num(Some(ts)) as u64;
                    self.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { last_account_sync_timestamp: Some(Some(last_account_sync_timestamp)), ..CredsUpdate::default() })));
                }
            }
            // handled in groups.rs
            Some("groups") => {}
            _ => {
                let _ = node;
                self.logger.info("received unknown sync");
            }
        }
    }
    fn on_connection_update_chats(&self, update: &ConnectionState) {
        let connection = update.connection;
        if connection == Some(WAConnectionState::Close) {
            self.chats.blocked_collections.lock().unwrap().clear();
            cancel(&self.chats.history_sync_paused_timeout);
        }
        if connection == Some(WAConnectionState::Open) {
            let sock = upgrade(&self.self_weak());
            if let Some(sock) = sock {
                // the presence goes first, so that a slow reply to the queries does not delay it
                sock.spawn_task("presence update requests", |s| s.send_presence_update(if s.config.mark_online_on_connect { WAPresence::Available } else { WAPresence::Unavailable }, None));
                if self.config.fire_init_queries {
                    sock.spawn_task("init queries", |s| s.execute_init_queries());
                }
            }
        }
        let received = update.received_pending_notifications == Some(true);
        let mut state = self.chats.sync_state.lock().unwrap();
        if !received || *state != SyncState::Connecting {
            return;
        }
        {
            let mut st = self.chats.history_sync_status.lock().unwrap();
            st.initial_bootstrap_complete = false;
            st.recent_sync_complete = false;
        }
        cancel(&self.chats.history_sync_paused_timeout);
        *state = SyncState::AwaitingInitialSync;
        self.logger.info("Connection is now AwaitingInitialSync, buffering events");
        self.ev.buffer();
        let probe = HistorySyncNotification::default().with_sync_type(waproto::message::HistorySyncType(HistorySyncType::RECENT.0));
        let will_sync_history = (self.config.should_sync_history_message)(&probe);
        let flush_soon = || {
            let ev = self.ev.clone();
            set_timeout(0, move || {
                ev.flush();
            });
        };
        if !will_sync_history {
            self.logger.info("History sync is disabled by config, not waiting for notification. Transitioning to Online.");
            *state = SyncState::Online;
            flush_soon();
            return;
        }
        // On reconnection (accountSyncCounter > 0), the server does not push
        // history sync notifications — the device already has its data.
        // Skip the 20s wait and go online immediately.
        if self.creds.lock().unwrap().account_sync_counter > 0 {
            self.logger.info("Reconnection with existing sync data, skipping history sync wait. Transitioning to Online.");
            *state = SyncState::Online;
            flush_soon();
            return;
        }
        self.logger.info("First connection, awaiting history sync notification with a 20s timeout.");
        cancel(&self.chats.awaiting_sync_timeout);
        let weak = self.self_weak();
        let timer = set_timeout(20_000, move || {
            let Some(s) = upgrade(&weak) else { return };
            let mut state = s.chats.sync_state.lock().unwrap();
            if *state == SyncState::AwaitingInitialSync {
                s.logger.warn("Timeout in AwaitingInitialSync, forcing state to Online and flushing buffer");
                *state = SyncState::Online;
                drop(state);
                s.ev.flush();
                // Increment so subsequent reconnections skip the 20s wait.
                // Late-arriving history is still processed via processMessage
                // regardless of the state machine phase.
                let account_sync_counter = s.creds.lock().unwrap().account_sync_counter + 1;
                s.ev.emit(BaileysEvent::CredsUpdate(Box::new(CredsUpdate { account_sync_counter: Some(account_sync_counter), ..CredsUpdate::default() })));
            }
        });
        *self.chats.awaiting_sync_timeout.lock().unwrap() = Some(timer);
    }
}
impl Socket {
    pub(crate) fn register_chats_listeners(&self) {
        let weak = self.weak();
        self.ev.on(
            EventKind::ConnectionUpdate,
            Arc::new(move |e: &BaileysEvent| {
                if let (BaileysEvent::ConnectionUpdate(u), Some(s)) = (e, upgrade(&weak)) {
                    s.on_connection_update_chats(u);
                }
            }),
        );
        // When an app state sync key arrives (myAppStateKeyId is set) and there are
        // collections blocked on a missing key, trigger a re-sync for just those collections.
        // This mirrors WA Web's Blocked → retry-on-key-arrival behavior.
        let weak = self.weak();
        self.ev.on(
            EventKind::CredsUpdate,
            Arc::new(move |e: &BaileysEvent| {
                let (BaileysEvent::CredsUpdate(u), Some(s)) = (e, upgrade(&weak)) else { return };
                if u.my_app_state_key_id.as_ref().and_then(|k| k.as_deref()).is_none_or(str::is_empty) {
                    return;
                }
                let collections = std::mem::take(&mut *s.chats.blocked_collections.lock().unwrap());
                // If we're in the middle of a full sync, doAppStateSync handles all collections
                if collections.is_empty() || *s.chats.sync_state.lock().unwrap() == SyncState::Syncing {
                    return;
                }
                s.logger.info("app state sync key arrived, re-syncing blocked collections");
                s.spawn_task("blocked collections resync", move |s| s.resync_app_state(&collections, false));
            }),
        );
        let weak = self.weak();
        self.ev.on(
            EventKind::LidMappingUpdate,
            Arc::new(move |e: &BaileysEvent| {
                let (BaileysEvent::LidMappingUpdate(m), Some(s)) = (e, upgrade(&weak)) else { return };
                if let Err(error) = s.signal_repository.lid_mapping().store_lid_pn_mappings(std::slice::from_ref(m)) {
                    s.logger.warn(&format!("Failed to store LID-PN mapping: {error}"));
                }
            }),
        );
        let weak = self.weak();
        self.register_socket_end_handler(Arc::new(move |_| {
            let Some(s) = upgrade(&weak) else { return };
            cancel(&s.chats.awaiting_sync_timeout);
            if s.config.placeholder_resend_cache.is_none() {
                s.chats.placeholder_resend_cache.close();
            }
            *s.chats.sync_state.lock().unwrap() = SyncState::Connecting;
            *s.chats.privacy_settings.lock().unwrap() = None;
        }));
    }
}
