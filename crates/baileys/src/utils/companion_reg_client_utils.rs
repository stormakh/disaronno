//! Same behavior as Utils/companion-reg-client-utils.ts.
use crate::types::WABrowserDescription;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompanionWebClientType {
    Unknown = 0,
    Chrome = 1,
    Edge = 2,
    Firefox = 3,
    Ie = 4,
    Opera = 5,
    Safari = 6,
    Electron = 7,
    Uwp = 8,
    OtherWebClient = 9,
}
pub fn get_companion_web_client_type(browser: &WABrowserDescription) -> CompanionWebClientType {
    let [os, browser_name, _] = browser;
    match browser_name.as_str() {
        "Desktop" if os == "Windows" => CompanionWebClientType::Uwp,
        "Desktop" => CompanionWebClientType::Electron,
        "Chrome" => CompanionWebClientType::Chrome,
        "Edge" => CompanionWebClientType::Edge,
        "Firefox" => CompanionWebClientType::Firefox,
        "IE" => CompanionWebClientType::Ie,
        "Opera" => CompanionWebClientType::Opera,
        "Safari" => CompanionWebClientType::Safari,
        _ => CompanionWebClientType::OtherWebClient,
    }
}
pub fn get_companion_platform_id(browser: &WABrowserDescription) -> String {
    (get_companion_web_client_type(browser) as u32).to_string()
}
pub fn build_pairing_qr_data(r#ref: &str, noise_key_b64: &str, identity_key_b64: &str, adv_b64: &str, browser: &WABrowserDescription) -> String {
    format!("https://wa.me/settings/linked_devices#{},{},{},{},{}", r#ref, noise_key_b64, identity_key_b64, adv_b64, get_companion_platform_id(browser))
}
