//! Same behavior as Utils/link-preview.ts. Upstream asks the optional `link-preview-js` package for the page data.
//! This port reads the page itself: the Open Graph and Twitter tags first, then `<title>`, description and `<img>`.
use crate::error::{Boom, Result};
use crate::types::*;
use crate::utils::http::{self, Redirect, Request, Url};
use crate::utils::logger::Logger;
use crate::utils::messages::prepare_wa_message_media;
use crate::utils::messages_media::{MediaInput, extract_image_thumb, get_http_stream};
use std::sync::Arc;

const THUMBNAIL_WIDTH_PX: u32 = 192;
const MAX_REDIRECT: u32 = 5;
const MAX_PAGE: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct URLGenerationOptions {
    pub thumbnail_width: u32,
    /// Timeout in ms
    pub timeout_ms: u64,
    pub headers: Vec<(String, String)>,
    pub upload_image: Option<WAMediaUploadFunction>,
    pub logger: Option<Arc<dyn Logger>>,
}
impl Default for URLGenerationOptions {
    fn default() -> URLGenerationOptions {
        URLGenerationOptions { thumbnail_width: THUMBNAIL_WIDTH_PX, timeout_ms: 3000, headers: Vec::new(), upload_image: None, logger: None }
    }
}
/// The same hosts that `handleRedirects` of upstream accepts: the same host, with or without `www.`.
fn same_site(base: &Url, forwarded: &Url) -> bool {
    forwarded.hostname == base.hostname || forwarded.hostname == format!("www.{}", base.hostname) || format!("www.{}", forwarded.hostname) == base.hostname
}
/// Fetches an HTML page. `None` means that the answer is not a page that a preview can read.
fn fetch_page(link: &str, opts: &URLGenerationOptions) -> Result<Option<(String, String)>> {
    let mut url = Url::parse(link)?;
    let mut retries = 0;
    loop {
        let shown = url.to_string();
        let req = Request { redirect: Redirect::Manual, timeout_ms: Some(opts.timeout_ms), ..Request::get(&shown, &opts.headers) };
        let mut res = http::fetch(&req)?;
        if (300..400).contains(&res.status) {
            let Some(location) = res.header("location") else { return Ok(None) };
            let next = url.join(location)?;
            if retries >= MAX_REDIRECT || !same_site(&url, &next) {
                return Ok(None);
            }
            retries += 1;
            url = next;
            continue;
        }
        if !res.ok() {
            return Err(Boom::new(format!("link preview failed with status {}", res.status)));
        }
        if res.header("content-type").is_some_and(|c| !c.to_ascii_lowercase().contains("html")) {
            return Ok(None);
        }
        let mut body = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        while body.len() < MAX_PAGE {
            let n = res.read(&mut buf)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        return Ok(Some((shown, String::from_utf8_lossy(&body).into_owned())));
    }
}
/// The value of one attribute inside the text of a tag.
fn tag_attr(tag: &str, name: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(p) = lower[from..].find(name) {
        let at = from + p;
        from = at + name.len();
        if at > 0 && !bytes[at - 1].is_ascii_whitespace() {
            continue;
        }
        let rest = tag[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else { continue };
        let rest = rest.trim_start();
        return Some(match rest.chars().next() {
            Some(q @ ('"' | '\'')) => rest[1..].split(q).next().unwrap_or("").to_string(),
            _ => rest.split(|c: char| c.is_whitespace() || c == '>').next().unwrap_or("").to_string(),
        });
    }
    None
}
/// The text of each tag with this name.
fn tags<'a>(html: &'a str, lower: &'a str, name: &'a str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = lower[from..].find(&open) {
        let at = from + p + open.len();
        let Some(end) = lower[at..].find('>') else { break };
        if lower.as_bytes().get(at).is_some_and(|c| c.is_ascii_whitespace() || *c == b'/') {
            out.push(&html[at..at + end]);
        }
        from = at + end;
    }
    out
}
fn decode_entities(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&#39;", "'").replace("&#x27;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").trim().to_string()
}
fn meta_content(metas: &[&str], names: &[&str]) -> Option<String> {
    for name in names {
        for m in metas {
            let key = tag_attr(m, "property").or_else(|| tag_attr(m, "name"));
            if key.is_some_and(|k| k.eq_ignore_ascii_case(name)) {
                if let Some(c) = tag_attr(m, "content").filter(|c| !c.trim().is_empty()) {
                    return Some(decode_entities(&c));
                }
            }
        }
    }
    None
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct PageInfo {
    url: String,
    title: Option<String>,
    description: Option<String>,
    images: Vec<String>,
}
fn parse_page(url: &str, html: &str) -> PageInfo {
    let lower = html.to_ascii_lowercase();
    let metas = tags(html, &lower, "meta");
    let mut title = meta_content(&metas, &["og:title", "twitter:title"]);
    if title.is_none() {
        if let Some(open) = lower.find("<title") {
            if let Some(start) = lower[open..].find('>').map(|i| open + i + 1) {
                if let Some(end) = lower[start..].find("</title").map(|i| start + i) {
                    title = Some(decode_entities(&html[start..end])).filter(|t| !t.is_empty());
                }
            }
        }
    }
    let description = meta_content(&metas, &["og:description", "twitter:description", "description"]);
    let base = Url::parse(url).ok();
    let absolute = |src: &str| base.as_ref().and_then(|b| b.join(src).ok()).map(|u| u.to_string());
    let mut images: Vec<String> = meta_content(&metas, &["og:image", "og:image:url", "og:image:secure_url", "twitter:image", "twitter:image:src"]).as_deref().and_then(absolute).into_iter().collect();
    if images.is_empty() {
        images = tags(html, &lower, "img").iter().filter_map(|t| tag_attr(t, "src")).filter(|s| !s.is_empty()).filter_map(|s| absolute(&s)).collect();
    }
    PageInfo { url: url.to_string(), title, description, images }
}
/// Given a piece of text, checks for any URL present, generates link preview for the same and returns it
/// Return `None` if the page has no title. `text` is the first matched URL in the text.
pub fn get_url_info(text: &str, opts: &URLGenerationOptions) -> Result<Option<WAUrlInfo>> {
    let preview_link = if text.starts_with("https://") || text.starts_with("http://") { text.to_string() } else { format!("https://{text}") };
    let Some((final_url, html)) = fetch_page(&preview_link, opts)? else {
        return Ok(None);
    };
    let info = parse_page(&final_url, &html);
    let Some(title) = info.title else { return Ok(None) };
    let image = info.images.first().cloned();
    let mut url_info = WAUrlInfo { canonical_url: info.url, matched_text: text.to_string(), title, description: info.description, jpeg_thumbnail: None, high_quality_thumbnail: None, original_thumbnail_url: image.clone() };
    if let Some(upload) = &opts.upload_image {
        let media = AnyMediaMessageContent {
            media: MediaContent::Image { image: WAMediaUpload::Url(image.unwrap_or_else(|| "undefined".to_string())), caption: None, jpeg_thumbnail: None, mentions: Mentionable::default(), context_info: None, width: None, height: None },
            mimetype: None,
            edit: None,
            album_parent_key: None,
        };
        let options = MessageContentGenerationOptions {
            media: MediaGenerationOptions {
                logger: None,
                media_type_override: Some(crate::defaults::MediaType::ThumbnailLink),
                upload: upload.clone(),
                media_cache: None,
                media_upload_timeout_ms: None,
                options: Some(RequestInit { headers: opts.headers.clone(), client: None }),
                background_color: None,
                font: None,
            },
            get_url_info: None,
            get_profile_pic_url: None,
            get_call_link: None,
            jid: None,
        };
        let prepared = prepare_wa_message_media(&media, &options)?;
        if let Some(img) = prepared.image_message() {
            url_info.jpeg_thumbnail = img.jpeg_thumbnail().cloned();
            url_info.high_quality_thumbnail = Some(img.clone());
        }
    } else if let Some(image) = image {
        let thumb = || -> Result<Vec<u8>> {
            let stream = get_http_stream(&image, &RequestInit { headers: opts.headers.clone(), client: None })?;
            Ok(extract_image_thumb(MediaInput::Stream(&*stream), Some(opts.thumbnail_width))?.buffer)
        };
        match thumb() {
            Ok(b) => url_info.jpeg_thumbnail = Some(b.into()),
            Err(error) => {
                if let Some(l) = &opts.logger {
                    l.debug(&format!("error in generating thumbnail: {error}"));
                }
            }
        }
    }
    Ok(Some(url_info))
}
