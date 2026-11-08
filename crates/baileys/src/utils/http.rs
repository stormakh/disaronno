//! Small blocking HTTP/1.1 client. It takes the place of `fetch`, `undici`, `https.request` and `http.request`.
//! TLS needs the `native` feature. Without it, https returns an error and plain http still works.
use crate::error::{Boom, Result};
use crate::types::HttpResponse;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The error message of a request that passed its time limit.
pub const TIMEOUT_MESSAGE: &str = "request timed out";
/// Same limit as `fetch`.
const MAX_REDIRECTS: u32 = 20;
const IO_CHUNK: usize = 64 * 1024;
const MAX_HEAD: usize = 256 * 1024;

fn io_err(e: std::io::Error) -> Boom {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Boom::new(TIMEOUT_MESSAGE),
        _ => Boom::new(e.to_string()),
    }
}
/// A parsed `http` or `https` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    /// Lower case. An IPv6 host keeps its brackets.
    pub hostname: String,
    pub port: Option<u16>,
    /// The path and the query. It is never empty.
    pub path: String,
}
fn invalid_url(s: &str) -> Boom {
    Boom::new(format!("Invalid URL: {s}"))
}
/// Same set as the URL path encoder: other bytes stay as they are.
fn encode_path(p: &str) -> String {
    let mut o = String::with_capacity(p.len());
    for b in p.bytes() {
        if b <= 0x20 || b >= 0x7f || matches!(b, b'"' | b'<' | b'>' | b'`' | b'{' | b'}') {
            o.push('%');
            o.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
            o.push(char::from_digit((b & 15) as u32, 16).unwrap_or('0').to_ascii_uppercase());
        } else {
            o.push(b as char);
        }
    }
    o
}
/// Removes `.` and `..` segments from a path that has no query.
fn normalize_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    let last = segs.len().saturating_sub(1);
    for (i, s) in segs.iter().enumerate() {
        match *s {
            "." => {
                if i == last {
                    out.push("");
                }
            }
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
                if i == last {
                    out.push("");
                }
            }
            _ => out.push(s),
        }
    }
    let joined = out.join("/");
    if joined.starts_with('/') { joined } else { format!("/{joined}") }
}
impl Url {
    /// Accepts only absolute `http` and `https` URLs. User info is not supported.
    pub fn parse(s: &str) -> Result<Url> {
        let s = s.trim();
        let (scheme, rest) = s.split_once("://").ok_or_else(|| invalid_url(s))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(Boom::new(format!("Unsupported URL scheme: {scheme}")));
        }
        let rest = rest.split('#').next().unwrap_or("");
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') {
            return Err(invalid_url(s));
        }
        let (hostname, port) = match authority.rfind(':') {
            Some(i) if !authority.ends_with(']') => {
                let p = &authority[i + 1..];
                let port = if p.is_empty() { None } else { Some(p.parse::<u16>().map_err(|_| invalid_url(s))?) };
                (&authority[..i], port)
            }
            _ => (authority, None),
        };
        if hostname.is_empty() || hostname.bytes().any(|c| c <= 0x20 || c >= 0x7f) {
            return Err(invalid_url(s));
        }
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (raw_path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (tail, None),
        };
        let mut path = normalize_segments(&encode_path(raw_path));
        if let Some(q) = query {
            path.push('?');
            path.push_str(&encode_path(q));
        }
        Ok(Url { hostname: hostname.to_ascii_lowercase(), port: port.filter(|p| *p != default_port), path, scheme })
    }
    /// Same as `url.host`: the hostname, and the port when it is not the default.
    pub fn host(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.hostname),
            None => self.hostname.clone(),
        }
    }
    /// Same as `new URL(location, base)`.
    pub fn join(&self, location: &str) -> Result<Url> {
        let location = location.trim();
        if location.contains("://") && !location.starts_with('/') && !location.starts_with('?') {
            return Url::parse(location);
        }
        let origin = format!("{}://{}", self.scheme, self.host());
        if let Some(r) = location.strip_prefix("//") {
            return Url::parse(&format!("{}://{r}", self.scheme));
        }
        if location.starts_with('/') {
            return Url::parse(&format!("{origin}{location}"));
        }
        let base_path = self.path.split('?').next().unwrap_or("/");
        if location.is_empty() {
            return Ok(self.clone());
        }
        if location.starts_with('?') {
            return Url::parse(&format!("{origin}{base_path}{location}"));
        }
        if location.starts_with('#') {
            return Ok(self.clone());
        }
        let dir = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
        Url::parse(&format!("{origin}{dir}{location}"))
    }
    fn same_origin(&self, o: &Url) -> bool {
        self.scheme == o.scheme && self.hostname == o.hostname && self.port == o.port
    }
    pub(crate) fn socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        let host = self.hostname.trim_start_matches('[').trim_end_matches(']');
        builtin_name_lookup();
        let addrs: Vec<SocketAddr> = (host, self.port.unwrap_or(default_port)).to_socket_addrs().map_err(|e| Boom::new(format!("getaddrinfo failed for {host}: {e}")))?.collect();
        if addrs.is_empty() {
            return Err(Boom::new(format!("getaddrinfo found no address for {host}")));
        }
        Ok(addrs)
    }
}
/// A static glibc crashes in `getaddrinfo` when nsswitch.conf names a module it must load, such as `resolve`.
/// This limits host lookups to `files` and `dns`, which are inside libc and read /etc/hosts and /etc/resolv.conf.
#[cfg(all(feature = "native", target_env = "gnu", target_feature = "crt-static"))]
fn builtin_name_lookup() {
    unsafe extern "C" {
        fn __nss_configure_lookup(db: *const std::ffi::c_char, line: *const std::ffi::c_char) -> i32;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: both are valid C strings, and `Once` runs it before any lookup of this library.
    ONCE.call_once(|| unsafe {
        __nss_configure_lookup(c"hosts".as_ptr(), c"files dns".as_ptr());
    });
}
#[cfg(not(all(feature = "native", target_env = "gnu", target_feature = "crt-static")))]
fn builtin_name_lookup() {}
impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.host(), self.path)
    }
}
#[cfg(feature = "native")]
pub(crate) fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    use std::sync::{Arc, OnceLock};
    static C: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    C.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("the aws-lc provider supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    })
    .clone()
}
enum Conn {
    Plain(TcpStream),
    #[cfg(feature = "native")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}
impl Conn {
    #[cfg(feature = "native")]
    fn tls(sock: TcpStream, url: &Url) -> Result<Conn> {
        let host = url.hostname.trim_start_matches('[').trim_end_matches(']').to_string();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(|e| Boom::new(format!("invalid TLS server name: {e}")))?;
        let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| Boom::new(e.to_string()))?;
        Ok(Conn::Tls(Box::new(rustls::StreamOwned::new(conn, sock))))
    }
    #[cfg(not(feature = "native"))]
    fn tls(_sock: TcpStream, _url: &Url) -> Result<Conn> {
        Err(Boom::new("https needs the native feature"))
    }
    fn open(url: &Url, timeout_ms: Option<u64>) -> Result<Conn> {
        let timeout = timeout_ms.filter(|t| *t > 0).map(Duration::from_millis);
        let mut last = None;
        let mut sock = None;
        for a in url.socket_addrs()? {
            let r = match timeout {
                Some(t) => TcpStream::connect_timeout(&a, t),
                None => TcpStream::connect(a),
            };
            match r {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let Some(sock) = sock else {
            return Err(last.map_or_else(|| Boom::new("connect failed"), io_err));
        };
        sock.set_read_timeout(timeout).map_err(io_err)?;
        sock.set_write_timeout(timeout).map_err(io_err)?;
        sock.set_nodelay(true).map_err(io_err)?;
        if url.scheme == "https" { Conn::tls(sock, url) } else { Ok(Conn::Plain(sock)) }
    }
    fn write_all(&mut self, d: &[u8]) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.write_all(d),
            #[cfg(feature = "native")]
            Conn::Tls(s) => s.write_all(d),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            #[cfg(feature = "native")]
            Conn::Tls(s) => s.flush(),
        }
    }
    fn read(&mut self, d: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(d),
            #[cfg(feature = "native")]
            Conn::Tls(s) => s.read(d),
        }
    }
}
/// What goes in the request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    Empty,
    Bytes(&'a [u8]),
    /// The file is read in chunks, so its size in memory stays small.
    File(&'a str),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redirect {
    /// Follow as `fetch` does.
    Follow,
    /// Give the 3xx response to the caller.
    Manual,
}
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Body<'a>,
    pub timeout_ms: Option<u64>,
    pub redirect: Redirect,
    /// Add the headers that `fetch` adds. `http.request` adds none.
    pub fetch_headers: bool,
}
impl<'a> Request<'a> {
    pub fn get(url: &'a str, headers: &'a [(String, String)]) -> Request<'a> {
        Request { method: "GET", url, headers, body: Body::Empty, timeout_ms: None, redirect: Redirect::Follow, fetch_headers: true }
    }
}
fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}
fn write_head(out: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    let bad = |s: &str| s.bytes().any(|c| c == b'\r' || c == b'\n' || c == 0);
    if name.is_empty() || bad(name) || bad(value) {
        return Err(Boom::new(format!("Invalid header: {name}")));
    }
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(())
}
fn body_len(body: &Body<'_>) -> Result<Option<u64>> {
    Ok(match body {
        Body::Empty => None,
        Body::Bytes(b) => Some(b.len() as u64),
        Body::File(p) => Some(std::fs::metadata(p).map_err(io_err)?.len()),
    })
}
fn send(conn: &mut Conn, req: &Request<'_>, url: &Url) -> Result<()> {
    let len = body_len(&req.body)?;
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(req.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(url.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    if !has_header(req.headers, "host") {
        write_head(&mut head, "Host", &url.host())?;
    }
    for (k, v) in req.headers {
        if !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("connection") {
            write_head(&mut head, k, v)?;
        }
    }
    if req.fetch_headers {
        if !has_header(req.headers, "accept") {
            head.extend_from_slice(b"Accept: */*\r\n");
        }
        if !has_header(req.headers, "user-agent") {
            head.extend_from_slice(b"User-Agent: node\r\n");
        }
    }
    if let Some(n) = len {
        write_head(&mut head, "Content-Length", &n.to_string())?;
    } else if req.method == "POST" {
        head.extend_from_slice(b"Content-Length: 0\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    conn.write_all(&head).map_err(io_err)?;
    let r = match req.body {
        Body::Empty => Ok(()),
        Body::Bytes(b) => conn.write_all(b),
        Body::File(p) => {
            let mut f = File::open(p).map_err(io_err)?;
            let mut buf = vec![0u8; IO_CHUNK];
            loop {
                let n = f.read(&mut buf).map_err(io_err)?;
                if n == 0 {
                    break Ok(());
                }
                if let Err(e) = conn.write_all(&buf[..n]) {
                    break Err(e);
                }
            }
        }
    };
    // a server may answer and close before it reads the body, as with a redirect, so only a timeout stops here
    match r {
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Err(io_err(e)),
        _ => {
            let _ = conn.flush();
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyMode {
    Empty,
    Length(u64),
    /// How much of the current chunk is left. `None` means that a size line comes next.
    Chunked(Option<u64>),
    Close,
    Done,
}
/// A response with its body not read yet.
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    /// The URL that gave this response, after redirects.
    pub url: String,
    conn: Conn,
    buf: Vec<u8>,
    pos: usize,
    mode: BodyMode,
}
impl Response {
    /// Same as `response.ok`.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    fn fill(&mut self) -> Result<usize> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let n = self.buf.len();
        self.buf.resize(n + IO_CHUNK, 0);
        let r = self.conn.read(&mut self.buf[n..]);
        match r {
            Ok(got) => {
                self.buf.truncate(n + got);
                Ok(got)
            }
            Err(e) => {
                self.buf.truncate(n);
                // a TLS peer that closes without close_notify, when only the close marks the end
                if e.kind() == ErrorKind::UnexpectedEof && self.mode == BodyMode::Close {
                    return Ok(0);
                }
                Err(io_err(e))
            }
        }
    }
    fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(i) = self.buf[self.pos..].iter().position(|c| *c == b'\n') {
                let end = self.pos + i;
                let line = String::from_utf8_lossy(&self.buf[self.pos..end]).trim_end_matches('\r').to_string();
                self.pos = end + 1;
                return Ok(line);
            }
            if self.buf.len() - self.pos > MAX_HEAD {
                return Err(Boom::new("response header is too large"));
            }
            if self.fill()? == 0 {
                return Err(Boom::new("connection closed before the response ended"));
            }
        }
    }
    fn read_head(&mut self, head_request: bool) -> Result<()> {
        loop {
            let status_line = self.read_line()?;
            let mut parts = status_line.splitn(3, ' ');
            let version = parts.next().unwrap_or("");
            if !version.starts_with("HTTP/1.") {
                return Err(Boom::new(format!("invalid HTTP response: {status_line}")));
            }
            self.status = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| Boom::new(format!("invalid HTTP response: {status_line}")))?;
            self.status_text = parts.next().unwrap_or("").to_string();
            self.headers.clear();
            loop {
                let line = self.read_line()?;
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    self.headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            // 100 Continue and other interim responses come before the real one
            if self.status >= 200 || self.status == 101 {
                break;
            }
        }
        let chunked = self.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = self.header("content-length").and_then(|v| v.parse::<u64>().ok());
        self.mode = if head_request || self.status == 204 || self.status == 304 {
            BodyMode::Empty
        } else if chunked {
            BodyMode::Chunked(None)
        } else {
            match length {
                Some(0) => BodyMode::Empty,
                Some(n) => BodyMode::Length(n),
                None => BodyMode::Close,
            }
        };
        Ok(())
    }
    /// Copies body bytes that are in the buffer, or reads more from the socket.
    fn take(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            if self.fill()? == 0 {
                return Ok(0);
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
    /// Reads up to `out.len()` body bytes. 0 means the end of the body.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.mode {
                BodyMode::Empty | BodyMode::Done => return Ok(0),
                BodyMode::Close => return self.take(out),
                BodyMode::Length(left) => {
                    let want = (left.min(out.len() as u64)) as usize;
                    let n = self.take(&mut out[..want])?;
                    if n == 0 {
                        return Err(Boom::new("connection closed before the response ended"));
                    }
                    self.mode = if left == n as u64 { BodyMode::Done } else { BodyMode::Length(left - n as u64) };
                    return Ok(n);
                }
                BodyMode::Chunked(Some(left)) => {
                    let want = (left.min(out.len() as u64)) as usize;
                    let n = self.take(&mut out[..want])?;
                    if n == 0 {
                        return Err(Boom::new("connection closed before the response ended"));
                    }
                    if left == n as u64 {
                        self.read_line()?;
                        self.mode = BodyMode::Chunked(None);
                    } else {
                        self.mode = BodyMode::Chunked(Some(left - n as u64));
                    }
                    return Ok(n);
                }
                BodyMode::Chunked(None) => {
                    let line = self.read_line()?;
                    let size = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size, 16).map_err(|_| Boom::new(format!("invalid chunk size: {line}")))?;
                    if size == 0 {
                        // trailers end with an empty line
                        while !self.read_line()?.is_empty() {}
                        self.mode = BodyMode::Done;
                    } else {
                        self.mode = BodyMode::Chunked(Some(size));
                    }
                }
            }
        }
    }
    pub fn bytes(mut self) -> Result<Vec<u8>> {
        let mut o = Vec::new();
        let mut buf = vec![0u8; IO_CHUNK];
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                return Ok(o);
            }
            o.extend_from_slice(&buf[..n]);
        }
    }
    /// Reads the whole body into the type that `HttpClient` returns.
    pub fn into_http_response(self) -> Result<HttpResponse> {
        let (status, status_text) = (self.status, self.status_text.clone());
        Ok(HttpResponse { status, status_text, body: self.bytes()? })
    }
}
fn request_once(req: &Request<'_>, url: &Url) -> Result<Response> {
    let mut conn = Conn::open(url, req.timeout_ms)?;
    send(&mut conn, req, url)?;
    let mut r = Response { status: 0, status_text: String::new(), headers: Vec::new(), url: url.to_string(), conn, buf: Vec::new(), pos: 0, mode: BodyMode::Empty };
    r.read_head(req.method == "HEAD")?;
    Ok(r)
}
/// Sends a request. `Redirect::Follow` acts as `fetch`: 303, and 301 or 302 after a POST, change to GET.
pub fn fetch(req: &Request<'_>) -> Result<Response> {
    let mut url = Url::parse(req.url)?;
    let mut res = request_once(req, &url)?;
    if req.redirect == Redirect::Manual {
        return Ok(res);
    }
    let mut owned_headers: Option<Vec<(String, String)>> = None;
    let mut method = req.method.to_string();
    let mut body = req.body;
    let mut count = 0;
    while matches!(res.status, 301 | 302 | 303 | 307 | 308) {
        let Some(location) = res.header("location") else { break };
        count += 1;
        if count > MAX_REDIRECTS {
            return Err(Boom::new("redirect count exceeded"));
        }
        let next = url.join(location)?;
        let mut headers = owned_headers.take().unwrap_or_else(|| req.headers.to_vec());
        if res.status == 303 && method != "GET" && method != "HEAD" || matches!(res.status, 301 | 302) && method == "POST" {
            method = "GET".to_string();
            body = Body::Empty;
            headers.retain(|(k, _)| !k.to_ascii_lowercase().starts_with("content-"));
        }
        if !next.same_origin(&url) {
            headers.retain(|(k, _)| !matches!(k.to_ascii_lowercase().as_str(), "authorization" | "proxy-authorization" | "cookie" | "host"));
        }
        let hop = Request { method: &method, url: req.url, headers: &headers, body, timeout_ms: req.timeout_ms, redirect: Redirect::Manual, fetch_headers: req.fetch_headers };
        res = request_once(&hop, &next)?;
        url = next;
        owned_headers = Some(headers);
    }
    Ok(res)
}
/// GET with the redirects followed and the whole body read.
pub fn get(url: &str, headers: &[(String, String)]) -> Result<HttpResponse> {
    fetch(&Request::get(url, headers))?.into_http_response()
}
/// POST of a file with redirects followed and the whole body read.
pub fn post_file(url: &str, file_path: &str, headers: &[(String, String)], timeout_ms: Option<u64>) -> Result<HttpResponse> {
    let req = Request { method: "POST", url, headers, body: Body::File(file_path), timeout_ms, redirect: Redirect::Follow, fetch_headers: true };
    fetch(&req)?.into_http_response()
}
/// Same as `encodeURIComponent` for text.
pub fn encode_uri_component(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')') {
            o.push(b as char);
        } else {
            o.push('%');
            o.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
            o.push(char::from_digit((b & 15) as u32, 16).unwrap_or('0').to_ascii_uppercase());
        }
    }
    o
}
