//! Same as Utils/identity-change-handler.ts.
use crate::error::{Boom, Result};
use crate::signal::repository::SessionValidation;
use crate::types::{CacheStore, cache_get, cache_set};
use crate::utils::generics::is_string_null_or_empty;
use crate::utils::logger::{LogLevel, Logger};
use crate::wabinary::{BinaryNode, are_jids_same_user, get_binary_node_child, jid_decode};
use std::sync::Arc;
use waproto::pb::Json;

#[derive(Clone, Debug, PartialEq)]
pub enum IdentityChangeResult {
    NoIdentityNode,
    InvalidNotification,
    SkippedCompanionDevice { device: u32 },
    SkippedSelfPrimary,
    Debounced,
    SkippedOffline,
    SkippedNoSession,
    SessionRefreshed,
    SessionRefreshFailed { error: Boom },
}
impl IdentityChangeResult {
    /// The `action` field of the upstream result.
    pub fn action(&self) -> &'static str {
        match self {
            IdentityChangeResult::NoIdentityNode => "no_identity_node",
            IdentityChangeResult::InvalidNotification => "invalid_notification",
            IdentityChangeResult::SkippedCompanionDevice { .. } => "skipped_companion_device",
            IdentityChangeResult::SkippedSelfPrimary => "skipped_self_primary",
            IdentityChangeResult::Debounced => "debounced",
            IdentityChangeResult::SkippedOffline => "skipped_offline",
            IdentityChangeResult::SkippedNoSession => "skipped_no_session",
            IdentityChangeResult::SessionRefreshed => "session_refreshed",
            IdentityChangeResult::SessionRefreshFailed { .. } => "session_refresh_failed",
        }
    }
}

#[derive(Clone)]
pub struct IdentityChangeContext {
    pub me_id: Option<String>,
    pub me_lid: Option<String>,
    pub validate_session: Arc<dyn Fn(&str) -> Result<SessionValidation> + Send + Sync>,
    /// The arguments are the JIDs and `force`.
    pub assert_sessions: Arc<dyn Fn(&[String], bool) -> Result<bool> + Send + Sync>,
    pub debounce_cache: Arc<dyn CacheStore>,
    pub logger: Arc<dyn Logger>,
    /// Invoked right before `assert_sessions` is called for an existing-session identity change.
    /// Used to kick off fire-and-forget side effects (e.g. tctoken re-issuance) in the same
    /// order WA Web does, i.e. before the E2E session is re-established.
    /// Must not panic; implementations are responsible for their own error handling.
    pub on_before_session_refresh: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

fn log_jid(logger: &dyn Logger, level: LogLevel, jid: &str, msg: &str) {
    if logger.is_enabled(level) {
        logger.at(level, Some(&Json::Obj(vec![("jid".to_string(), Json::Str(jid.to_string()))])), msg);
    }
}

pub fn handle_identity_change(node: &BinaryNode, ctx: &IdentityChangeContext) -> Result<IdentityChangeResult> {
    let Some(from) = node.attr("from").filter(|f| !f.is_empty()) else {
        return Ok(IdentityChangeResult::InvalidNotification);
    };
    if get_binary_node_child(Some(node), "identity").is_none() {
        return Ok(IdentityChangeResult::NoIdentityNode);
    }
    let logger = ctx.logger.as_ref();
    log_jid(logger, LogLevel::Info, from, "identity changed");

    if let Some(device) = jid_decode(from).and_then(|d| d.device).filter(|d| *d != 0) {
        log_jid(logger, LogLevel::Debug, from, "ignoring identity change from companion device");
        return Ok(IdentityChangeResult::SkippedCompanionDevice { device });
    }

    // an empty `me_id` or `me_lid` is falsy upstream
    let me_id = ctx.me_id.as_deref().filter(|m| !m.is_empty());
    let me_lid = ctx.me_lid.as_deref().filter(|m| !m.is_empty());
    let is_self_primary = me_id.is_some() && (are_jids_same_user(Some(from), me_id) || (me_lid.is_some() && are_jids_same_user(Some(from), me_lid)));
    if is_self_primary {
        log_jid(logger, LogLevel::Info, from, "self primary identity changed");
        return Ok(IdentityChangeResult::SkippedSelfPrimary);
    }

    if cache_get::<bool>(ctx.debounce_cache.as_ref(), from).is_some_and(|v| *v) {
        log_jid(logger, LogLevel::Debug, from, "skipping identity assert (debounced)");
        return Ok(IdentityChangeResult::Debounced);
    }
    cache_set(ctx.debounce_cache.as_ref(), from, true);

    let is_offline_notification = !is_string_null_or_empty(node.attr("offline"));
    let has_existing_session = (ctx.validate_session)(from)?;

    if !has_existing_session.exists {
        log_jid(logger, LogLevel::Debug, from, "no old session, skipping session refresh");
        return Ok(IdentityChangeResult::SkippedNoSession);
    }
    log_jid(logger, LogLevel::Debug, from, "old session exists, will refresh session");

    if is_offline_notification {
        log_jid(logger, LogLevel::Debug, from, "skipping session refresh during offline processing");
        return Ok(IdentityChangeResult::SkippedOffline);
    }

    if let Some(f) = &ctx.on_before_session_refresh {
        f(from);
    }

    match (ctx.assert_sessions)(&[from.to_string()], true) {
        Ok(_) => Ok(IdentityChangeResult::SessionRefreshed),
        Err(error) => {
            if logger.is_enabled(LogLevel::Warn) {
                let obj = Json::Obj(vec![("error".to_string(), Json::Str(error.message.clone())), ("jid".to_string(), Json::Str(from.to_string()))]);
                logger.warn_obj(&obj, "failed to assert sessions after identity change");
            }
            Ok(IdentityChangeResult::SessionRefreshFailed { error })
        }
    }
}
