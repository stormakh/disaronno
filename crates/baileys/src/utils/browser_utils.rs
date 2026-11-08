//! Same behavior as Utils/browser-utils.ts.
use crate::types::WABrowserDescription;
use waproto::device_props::PlatformType;

fn desc(a: &str, b: &str, c: &str) -> WABrowserDescription {
    [a.to_string(), b.to_string(), c.to_string()]
}
/// `Browsers` from upstream.
pub struct Browsers;
impl Browsers {
    pub fn ubuntu(browser: &str) -> WABrowserDescription {
        desc("Ubuntu", browser, "22.04.4")
    }
    pub fn mac_os(browser: &str) -> WABrowserDescription {
        desc("Mac OS", browser, "14.4.1")
    }
    pub fn baileys(browser: &str) -> WABrowserDescription {
        desc("Baileys", browser, "6.5.0")
    }
    pub fn windows(browser: &str) -> WABrowserDescription {
        desc("Windows", browser, "10.0.22631")
    }
    pub fn android(browser: &str) -> WABrowserDescription {
        desc(browser, "Android", "")
    }
    /// The appropriate browser based on your OS & release
    pub fn appropriate(browser: &str) -> WABrowserDescription {
        let name = match std::env::consts::OS {
            "aix" => "AIX",
            "macos" => "Mac OS",
            "windows" => "Windows",
            "android" => "Android",
            "freebsd" => "FreeBSD",
            "openbsd" => "OpenBSD",
            "solaris" | "illumos" => "Solaris",
            _ => "Ubuntu",
        };
        desc(name, browser, &os_release())
    }
}
/// Same text as `os.release()` where the kernel gives it. Other systems get an empty string.
fn os_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default()
}
/// A numeric name reads the reverse table, as `PlatformType['1']` gives `'CHROME'`.
pub fn get_platform_id(browser: &str) -> String {
    let upper = browser.to_uppercase();
    if let Some(v) = PlatformType::from_name(&upper).filter(|v| v.0 != 0) {
        return v.0.to_string();
    }
    if let Some(n) = upper.parse::<i32>().ok().filter(|n| n.to_string() == upper).and_then(|n| PlatformType(n).name()) {
        return n.to_string();
    }
    "1".to_string() //chrome
}
