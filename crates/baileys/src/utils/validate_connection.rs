//! Same as Utils/validate-connection.ts.
use crate::auth::{AuthenticationCreds, CredsUpdate, SignalCreds};
use crate::crypto;
use crate::defaults::{KEY_BUNDLE_TYPE, WA_ADV_ACCOUNT_SIG_PREFIX, WA_ADV_DEVICE_SIG_PREFIX, WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX};
use crate::error::{Boom, Result};
use crate::types::{Contact, SocketConfig};
use crate::utils::generics::encode_big_endian;
use crate::utils::signal::create_signal_identity;
use crate::wabinary::{Attrs, BinaryNode, Content, S_WHATSAPP_NET, get_binary_node_child, jid_decode};
use waproto::client_payload::user_agent::{AppVersion, Platform, ReleaseChannel};
use waproto::client_payload::web_info::WebSubPlatform;
use waproto::client_payload::{ConnectReason, ConnectType, DevicePairingRegistrationData, UserAgent, WebInfo};
use waproto::device_props::{self, HistorySyncConfig, PlatformType};
use waproto::pb::{Json, PbMessage, base64_decode};
use waproto::{ADVDeviceIdentity, ADVEncryptionType, ADVSignedDeviceIdentity, ADVSignedDeviceIdentityHMAC, ClientPayload, DeviceProps};

fn is_android(config: &SocketConfig) -> bool {
    config.browser[1].to_lowercase().contains("android")
}

fn get_user_agent(config: &SocketConfig) -> UserAgent {
    UserAgent::default()
        .with_app_version(AppVersion::default().with_primary(config.version[0]).with_secondary(config.version[1]).with_tertiary(config.version[2]))
        .with_platform(if is_android(config) { Platform::ANDROID } else { Platform::WEB })
        .with_release_channel(ReleaseChannel::RELEASE)
        .with_os_version("0.1")
        .with_device("Desktop")
        .with_os_build_number("0.1")
        .with_locale_language_iso6391("en")
        .with_mnc("000")
        .with_mcc("000")
        .with_locale_country_iso31661_alpha2(config.country_code.as_str())
}

fn get_web_info(config: &SocketConfig) -> WebInfo {
    let mut web_sub_platform = WebSubPlatform::WEB_BROWSER;
    if config.sync_full_history && config.browser[1] == "Desktop" {
        match config.browser[0].as_str() {
            "Mac OS" => web_sub_platform = WebSubPlatform::DARWIN,
            "Windows" => web_sub_platform = WebSubPlatform::WIN_HYBRID,
            _ => {}
        }
    }
    WebInfo::default().with_web_sub_platform(web_sub_platform)
}

fn get_client_payload(config: &SocketConfig) -> ClientPayload {
    let mut payload = ClientPayload::default().with_connect_type(ConnectType::WIFI_UNKNOWN).with_connect_reason(ConnectReason::USER_ACTIVATED).with_user_agent(get_user_agent(config));
    if !is_android(config) {
        payload.set_web_info(get_web_info(config));
    }
    if let Some(name) = config.push_name.as_deref().filter(|n| !n.is_empty()) {
        payload.set_push_name(name);
    }
    payload
}

/// `+user` passed through `fromObject`: a JavaScript number, and 0 for text that is not a number.
fn username_of(user: &str) -> u64 {
    user.trim().parse::<u64>().map_or(0, |n| n as f64 as u64)
}

pub fn generate_login_node(user_jid: &str, config: &SocketConfig) -> Result<ClientPayload> {
    let jid = jid_decode(user_jid).ok_or_else(|| Boom::new("Cannot destructure property 'user' of undefined"))?;
    let mut payload = get_client_payload(config).with_passive(true).with_pull(true).with_username(username_of(jid.user)).with_lid_db_migrated(false);
    if let Some(device) = jid.device {
        payload.set_device(device);
    }
    Ok(payload)
}

fn get_platform_type(platform: &str) -> PlatformType {
    let platform_type = platform.to_uppercase();
    if platform_type == "ANDROID" {
        return PlatformType::ANDROID_PHONE;
    }
    // UNKNOWN is 0, which is falsy upstream
    PlatformType::from_name(&platform_type).filter(|p| p.0 != 0).unwrap_or(PlatformType::CHROME)
}

pub fn generate_registration_node(creds: &SignalCreds, config: &SocketConfig) -> ClientPayload {
    // the app version needs to be md5 hashed
    // and passed in
    let version = format!("{}.{}.{}", config.version[0], config.version[1], config.version[2]);
    let app_version_buf = crypto::md5(version.as_bytes());

    let history_sync_config = HistorySyncConfig::default()
        .with_storage_quota_mb(10240u32)
        .with_inline_initial_payload_in_e2_ee_msg(true)
        .with_support_call_log_history(false)
        .with_support_bot_user_agent_chat_history(true)
        .with_support_cag_reactions_and_polls(true)
        .with_support_biz_hosted_msg(true)
        .with_support_recent_sync_chunk_message_count_tuning(true)
        .with_support_hosted_group_msg(true)
        .with_support_fbid_bot_chat_history(true)
        .with_support_message_association(true)
        .with_support_group_history(false);
    let companion = DeviceProps::default()
        .with_os(config.browser[0].as_str())
        .with_platform_type(get_platform_type(&config.browser[1]))
        .with_require_full_sync(config.sync_full_history)
        .with_history_sync_config(history_sync_config)
        .with_version(device_props::AppVersion::default().with_primary(10u32).with_secondary(15u32).with_tertiary(7u32));

    get_client_payload(config).with_passive(false).with_pull(false).with_device_pairing_data(
        DevicePairingRegistrationData::default()
            .with_build_hash(app_version_buf)
            .with_device_props(companion.encode())
            .with_e_regid(encode_big_endian(creds.registration_id, 4))
            .with_e_keytype(KEY_BUNDLE_TYPE)
            .with_e_ident(creds.signed_identity_key.public)
            .with_e_skey_id(encode_big_endian(creds.signed_pre_key.key_id, 3))
            .with_e_skey_val(creds.signed_pre_key.key_pair.public)
            .with_e_skey_sig(creds.signed_pre_key.signature.as_slice()),
    )
}

/// The `data` of the Boom for a bad pair success node.
pub(crate) fn node_to_json(n: &BinaryNode) -> Json {
    let mut o = vec![("tag".to_string(), Json::Str(n.tag.as_str().to_string()))];
    o.push(("attrs".to_string(), Json::Obj(n.attrs.iter().map(|(k, v)| (k.to_string(), Json::Str(v.to_string()))).collect())));
    match &n.content {
        Some(Content::Nodes(c)) => o.push(("content".to_string(), Json::Arr(c.iter().map(node_to_json).collect()))),
        Some(Content::Binary(b)) => o.push(("content".to_string(), Json::Bytes(b.as_slice().to_vec()))),
        Some(Content::Text(t)) => o.push(("content".to_string(), Json::Str(t.as_str().to_string()))),
        None => {}
    }
    Json::Obj(o)
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// The result of `configure_successful_pairing`.
#[derive(Clone, Debug, PartialEq)]
pub struct SuccessfulPairing {
    pub creds: CredsUpdate,
    pub reply: BinaryNode,
}

/// Uses `adv_secret_key`, `signed_identity_key` and `signal_identities` of `creds`.
pub fn configure_successful_pairing(stanza: &BinaryNode, creds: &AuthenticationCreds) -> Result<SuccessfulPairing> {
    let msg_id = stanza.attr("id");

    let pair_success_node = get_binary_node_child(Some(stanza), "pair-success");
    let device_identity_node = get_binary_node_child(pair_success_node, "device-identity");
    let platform_node = get_binary_node_child(pair_success_node, "platform");
    let device_node = get_binary_node_child(pair_success_node, "device");
    let business_node = get_binary_node_child(pair_success_node, "biz");

    let (Some(device_identity_node), Some(device_node)) = (device_identity_node, device_node) else {
        return Err(Boom::with_data("Missing device-identity or device in pair success node", node_to_json(stanza)));
    };

    let biz_name = business_node.and_then(|n| n.attr("name"));
    let jid = device_node.attr("jid");
    let lid = device_node.attr("lid");

    let Some(Content::Binary(identity_bytes)) = &device_identity_node.content else {
        return Err(Boom::new("illegal buffer"));
    };
    let hmac_identity = ADVSignedDeviceIdentityHMAC::decode(identity_bytes.as_slice())?;
    let details = hmac_identity.details().map_or(&[][..], |b| b.as_slice());
    let hmac = hmac_identity.hmac().map_or(&[][..], |b| b.as_slice());

    let hmac_prefix: &[u8] = if hmac_identity.account_type() == Some(ADVEncryptionType::HOSTED) { &WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX } else { &[] };
    let adv_sign = crypto::hmac_sha256(&base64_decode(&creds.adv_secret_key), &concat(&[hmac_prefix, details]));
    if hmac != adv_sign {
        return Err(Boom::new("Invalid account signature"));
    }

    let mut account = ADVSignedDeviceIdentity::decode(details)?;
    let account_signature_key = account.account_signature_key().map_or(Vec::new(), |b| b.as_slice().to_vec());
    let device_details = account.details().map_or(Vec::new(), |b| b.as_slice().to_vec());
    let device_identity = ADVDeviceIdentity::decode(&device_details)?;

    let account_signature_prefix: &[u8] = if device_identity.device_type() == Some(ADVEncryptionType::HOSTED) { &WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX } else { &WA_ADV_ACCOUNT_SIG_PREFIX };
    let identity_public = &creds.signed_identity_key.public;
    let account_msg = concat(&[account_signature_prefix, &device_details, identity_public]);
    let account_signature = account.account_signature().map_or(&[][..], |b| b.as_slice());
    // Stricter than upstream on purpose: `Curve.verify` there only rejects a signature of the wrong length.
    if !crypto::verify(&account_signature_key, &account_msg, account_signature) {
        return Err(Boom::new("Failed to verify account signature"));
    }

    let device_msg = concat(&[&WA_ADV_DEVICE_SIG_PREFIX, &device_details, identity_public, &account_signature_key]);
    account.set_device_signature(crypto::sign(&creds.signed_identity_key.private, &device_msg));

    let identity = create_signal_identity(lid.unwrap_or(""), &account_signature_key);
    let account_enc = encode_signed_device_identity(&account, false);
    let key_index = device_identity.key_index().ok_or_else(|| Boom::new("Cannot read properties of null (reading 'toString')"))?;

    let mut iq_attrs = Attrs::new();
    iq_attrs.set("to", S_WHATSAPP_NET);
    iq_attrs.set("type", "result");
    if let Some(id) = msg_id {
        iq_attrs.set("id", id);
    }
    let reply = BinaryNode::with_nodes(
        "iq",
        iq_attrs,
        vec![BinaryNode::with_nodes(
            "pair-device-sign",
            Attrs::new(),
            vec![BinaryNode::with_bytes("device-identity", Attrs::from([("key-index", key_index.to_string())]), account_enc)],
        )],
    );

    let mut signal_identities = creds.signal_identities.clone().unwrap_or_default();
    signal_identities.push(identity);
    let auth_update = CredsUpdate {
        account: Some(Some(account)),
        me: Some(Some(Contact { id: jid.unwrap_or("").to_string(), name: biz_name.map(str::to_string), lid: lid.map(str::to_string), ..Contact::default() })),
        signal_identities: Some(Some(signal_identities)),
        platform: Some(platform_node.and_then(|n| n.attr("name")).map(str::to_string)),
        ..CredsUpdate::default()
    };
    Ok(SuccessfulPairing { creds: auth_update, reply })
}

pub fn encode_signed_device_identity(account: &ADVSignedDeviceIdentity, include_signature_key: bool) -> Vec<u8> {
    let mut account = account.clone();
    // leave it out if we are not to include the signature key
    // or if we are including the signature key but it is empty
    if !include_signature_key || account.account_signature_key().is_none_or(|k| k.as_slice().is_empty()) {
        account.clear_account_signature_key();
    }
    account.encode()
}
