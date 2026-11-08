//! Same job as Socket/Client: the transport under the socket, and a WebSocket client over
//! `std::net::TcpStream`, with TLS through rustls under the `native` feature.
//!
//! One thread reads and any thread writes. The read path takes no lock while it blocks on the
//! network, so a slow read never stalls a write, and `close` can stop a blocked read.
use crate::crypto;
use crate::defaults::DEFAULT_ORIGIN;
use crate::error::{Boom, Result};
use crate::types::SocketConfig;
use crate::utils::http::Url;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use waproto::pb::base64_encode;

/// What the socket needs from a connection. A test implements this to mock the network.
pub trait Transport: Send + Sync {
    /// Opens the connection. The socket calls this once, on its reader thread.
    fn connect(&self) -> Result<()>;
    /// Sends one binary message. Any thread can call this.
    fn send(&self, data: &[u8]) -> Result<()>;
    /// Blocks for the next binary message. `Ok(None)` means the connection is closed.
    /// The socket calls this only on its reader thread.
    fn recv(&self) -> Result<Option<Vec<u8>>>;
    /// Closes the connection, and makes a blocked `recv` return. Any thread can call this.
    fn close(&self);
}

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Same limit as the default `maxPayload` of the `ws` package.
const MAX_PAYLOAD: u64 = 100 * 1024 * 1024;
/// The read chunk of the TCP stream. `BUF_KEEP` is what the frame buffer keeps after a large frame.
const RAW_CHUNK: usize = 8 * 1024;
const BUF_KEEP: usize = 32 * 1024;
const OP_CONTINUATION: u8 = 0;
const OP_TEXT: u8 = 1;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

fn io_err(e: std::io::Error) -> Boom {
    if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) {
        return Boom::new(format!("connection timed out: {e}"));
    }
    Boom::new(e.to_string())
}
/// SHA-1 is only used for the `Sec-WebSocket-Accept` check, which RFC 6455 defines with it.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut m = data.to_vec();
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    let mut w = [0u32; 80];
    for chunk in m.chunks_exact(64) {
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (o, v) in out.chunks_exact_mut(4).zip(h) {
        o.copy_from_slice(&v.to_be_bytes());
    }
    out
}
#[cfg(feature = "native")]
type TlsConn = Arc<Mutex<rustls::ClientConnection>>;
#[cfg(not(feature = "native"))]
type TlsConn = ();

struct Writer {
    tcp: TcpStream,
    tls: Option<TlsConn>,
}
impl Writer {
    #[cfg(feature = "native")]
    fn write_all(&mut self, d: &[u8]) -> std::io::Result<()> {
        if let Some(tls) = &self.tls {
            let mut out = Vec::with_capacity(d.len() + 64);
            let mut rest = d;
            let mut c = tls.lock().unwrap();
            // the TLS buffer has a limit, so a large message goes through in parts
            while !rest.is_empty() {
                let n = c.writer().write(rest)?;
                rest = &rest[n..];
                while c.wants_write() {
                    c.write_tls(&mut out)?;
                }
            }
            drop(c);
            return self.tcp.write_all(&out);
        }
        self.tcp.write_all(d)
    }
    #[cfg(not(feature = "native"))]
    fn write_all(&mut self, d: &[u8]) -> std::io::Result<()> {
        self.tcp.write_all(d)
    }
    /// Writes what the TLS state wants to send on its own, such as an alert.
    #[cfg(feature = "native")]
    fn flush_tls(&mut self) -> std::io::Result<()> {
        if let Some(tls) = &self.tls {
            let mut out = Vec::new();
            {
                let mut c = tls.lock().unwrap();
                while c.wants_write() {
                    c.write_tls(&mut out)?;
                }
            }
            if !out.is_empty() {
                self.tcp.write_all(&out)?;
            }
        }
        Ok(())
    }
}
struct Reader {
    tcp: TcpStream,
    tls: Option<TlsConn>,
    buf: Vec<u8>,
    pos: usize,
    raw: Vec<u8>,
    /// The part of `raw` that TLS did not take yet.
    raw_start: usize,
    raw_end: usize,
    /// Payload of a fragmented message.
    fragments: Vec<u8>,
    in_fragments: bool,
}
impl Reader {
    #[cfg(feature = "native")]
    fn read_some(&mut self, writer: &Mutex<Option<Writer>>) -> std::io::Result<usize> {
        let Some(tls) = self.tls.clone() else { return self.read_plain() };
        loop {
            // plaintext goes first: `read_tls` fails while the plaintext buffer of rustls is full
            let at = self.buf.len();
            self.buf.resize(at + self.raw.len(), 0);
            let got = tls.lock().unwrap().reader().read(&mut self.buf[at..]);
            match got {
                Ok(n) => {
                    // zero is the TLS close from the peer
                    self.buf.truncate(at + n);
                    return Ok(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => self.buf.truncate(at),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // the peer ended the TCP stream without a TLS close: same as a close here
                    self.buf.truncate(at);
                    return Ok(0);
                }
                Err(e) => {
                    self.buf.truncate(at);
                    return Err(e);
                }
            }
            if self.raw_start == self.raw_end {
                let n = self.tcp.read(&mut self.raw)?;
                if n == 0 {
                    return Ok(0);
                }
                self.raw_start = 0;
                self.raw_end = n;
            }
            let wants_write = {
                let mut c = tls.lock().unwrap();
                let mut input = &self.raw[self.raw_start..self.raw_end];
                let used = c.read_tls(&mut input)?;
                if used == 0 {
                    // rustls takes no more input after the close from the peer
                    return Ok(0);
                }
                self.raw_start += used;
                c.process_new_packets().map_err(std::io::Error::other)?;
                c.wants_write()
            };
            if wants_write {
                if let Some(w) = writer.lock().unwrap().as_mut() {
                    w.flush_tls()?;
                }
            }
        }
    }
    #[cfg(not(feature = "native"))]
    fn read_some(&mut self, _writer: &Mutex<Option<Writer>>) -> std::io::Result<usize> {
        self.read_plain()
    }
    fn read_plain(&mut self) -> std::io::Result<usize> {
        let at = self.buf.len();
        self.buf.resize(at + self.raw.len(), 0);
        let got = self.tcp.read(&mut self.buf[at..]);
        match got {
            Ok(n) => {
                self.buf.truncate(at + n);
                Ok(n)
            }
            Err(e) => {
                self.buf.truncate(at);
                Err(e)
            }
        }
    }
    /// Makes `n` unread bytes ready at `buf[pos..]`. `false` means the stream ended first.
    fn fill(&mut self, n: usize, writer: &Mutex<Option<Writer>>) -> std::io::Result<bool> {
        if self.pos > 0 && self.buf.len() - self.pos < n {
            self.buf.drain(..self.pos);
            self.pos = 0;
            // one large frame must not keep its buffer for the life of the connection
            if self.buf.capacity() > BUF_KEEP && self.buf.len() <= BUF_KEEP / 2 && n <= BUF_KEEP / 2 {
                self.buf.shrink_to(BUF_KEEP);
            }
        }
        while self.buf.len() - self.pos < n {
            if self.read_some(writer)? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
/// The WebSocket client, a port of what `ws` does for `Client/websocket.ts`.
pub struct WebSocketClient {
    url: Url,
    headers: Vec<(String, String)>,
    timeout_ms: u64,
    writer: Mutex<Option<Writer>>,
    reader: Mutex<Option<Reader>>,
    /// A clone only for `close`: no thread holds a lock on it while it blocks.
    shutdown: Mutex<Option<TcpStream>>,
    closed: AtomicBool,
    sent_close: AtomicBool,
}
impl WebSocketClient {
    pub fn new(config: &SocketConfig) -> Result<WebSocketClient> {
        let raw = config.wa_web_socket_url.as_str();
        let http = if let Some(r) = raw.strip_prefix("wss://") {
            format!("https://{r}")
        } else if let Some(r) = raw.strip_prefix("ws://") {
            format!("http://{r}")
        } else {
            raw.to_string()
        };
        Ok(WebSocketClient {
            url: Url::parse(&http)?,
            headers: config.options.headers.clone(),
            timeout_ms: config.connect_timeout_ms,
            writer: Mutex::new(None),
            reader: Mutex::new(None),
            shutdown: Mutex::new(None),
            closed: AtomicBool::new(false),
            sent_close: AtomicBool::new(false),
        })
    }
    fn open_tcp(&self) -> Result<TcpStream> {
        let timeout = (self.timeout_ms > 0).then(|| Duration::from_millis(self.timeout_ms));
        let mut last = None;
        for a in self.url.socket_addrs()? {
            let r = match timeout {
                Some(t) => TcpStream::connect_timeout(&a, t),
                None => TcpStream::connect(a),
            };
            match r {
                Ok(s) => {
                    s.set_read_timeout(timeout).map_err(io_err)?;
                    s.set_write_timeout(timeout).map_err(io_err)?;
                    s.set_nodelay(true).map_err(io_err)?;
                    return Ok(s);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(|| Boom::new("connect failed"), io_err))
    }
    #[cfg(feature = "native")]
    fn open_tls(&self, tcp: &mut TcpStream) -> Result<Option<TlsConn>> {
        if self.url.scheme != "https" {
            return Ok(None);
        }
        let host = self.url.hostname.trim_start_matches('[').trim_end_matches(']').to_string();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(|e| Boom::new(format!("invalid TLS server name: {e}")))?;
        let mut conn = rustls::ClientConnection::new(crate::utils::http::tls_config(), name).map_err(|e| Boom::new(e.to_string()))?;
        conn.complete_io(tcp).map_err(io_err)?;
        Ok(Some(Arc::new(Mutex::new(conn))))
    }
    #[cfg(not(feature = "native"))]
    fn open_tls(&self, _tcp: &mut TcpStream) -> Result<Option<TlsConn>> {
        if self.url.scheme != "https" {
            return Ok(None);
        }
        Err(Boom::new("wss needs the native feature"))
    }
    fn handshake(&self, writer: &mut Writer, reader: &mut Reader) -> Result<()> {
        let mut key = [0u8; 16];
        crypto::random_bytes(&mut key);
        let key = base64_encode(&key);
        let mut req = String::with_capacity(256);
        req.push_str("GET ");
        req.push_str(&self.url.path);
        req.push_str(" HTTP/1.1\r\nHost: ");
        req.push_str(&self.url.host());
        req.push_str("\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        req.push_str(&key);
        req.push_str("\r\nOrigin: ");
        req.push_str(DEFAULT_ORIGIN);
        req.push_str("\r\n");
        for (k, v) in &self.headers {
            req.push_str(k);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        writer.write_all(req.as_bytes()).map_err(io_err)?;

        let none = Mutex::new(None);
        let head_end = loop {
            if let Some(i) = reader.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if reader.buf.len() > 65536 {
                return Err(Boom::new("Invalid WebSocket frame: response head is too long"));
            }
            if reader.read_some(&none).map_err(io_err)? == 0 {
                return Err(Boom::new("socket hang up"));
            }
        };
        let head = String::from_utf8_lossy(&reader.buf[..head_end]).into_owned();
        reader.pos = head_end + 4;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let code = status_line.split(' ').nth(1).unwrap_or("");
        if code != "101" {
            // same text as `ws`, which `getCodeFromWSError` reads
            return Err(Boom::new(format!("Unexpected server response: {code}")));
        }
        let mut accept = None;
        let (mut upgrade, mut connection) = (false, false);
        for l in lines {
            if let Some((k, v)) = l.split_once(':') {
                let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
                match k.as_str() {
                    "sec-websocket-accept" => accept = Some(v.to_string()),
                    "upgrade" => upgrade = v.eq_ignore_ascii_case("websocket"),
                    "connection" => connection = v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")),
                    // this client asks for neither, so a server must not choose one
                    "sec-websocket-extensions" | "sec-websocket-protocol" => return Err(Boom::new(format!("Server sent a {k} header but none was requested"))),
                    _ => {}
                }
            }
        }
        if !upgrade || !connection {
            return Err(Boom::new("Invalid Upgrade or Connection header"));
        }
        let mut material = key.into_bytes();
        material.extend_from_slice(WS_GUID);
        if accept.as_deref() != Some(base64_encode(&sha1(&material)).as_str()) {
            return Err(Boom::new("Invalid Sec-WebSocket-Accept header"));
        }
        Ok(())
    }
    fn write_frame(w: &mut Writer, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut f = Vec::with_capacity(payload.len() + 14);
        f.push(0x80 | opcode);
        let n = payload.len();
        if n < 126 {
            f.push(0x80 | n as u8);
        } else if n < 65536 {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        crypto::random_bytes(&mut mask);
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        w.write_all(&f)
    }
    fn send_frame(&self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut g = self.writer.lock().unwrap();
        let w = g.as_mut().ok_or_else(|| Boom::new("WebSocket is not open: readyState 0 (CONNECTING)"))?;
        Self::write_frame(w, opcode, payload).map_err(io_err)
    }
    fn read_message(&self, r: &mut Reader) -> Result<Option<Vec<u8>>> {
        loop {
            if !r.fill(2, &self.writer).map_err(io_err)? {
                return Ok(None);
            }
            let (b0, b1) = (r.buf[r.pos], r.buf[r.pos + 1]);
            let (fin, opcode, masked, len7) = (b0 & 0x80 != 0, b0 & 0x0f, b1 & 0x80 != 0, (b1 & 0x7f) as usize);
            if b0 & 0x70 != 0 {
                return Err(Boom::new("Invalid WebSocket frame: RSV1 must be clear"));
            }
            if masked {
                return Err(Boom::new("Invalid WebSocket frame: MASK must be clear"));
            }
            if opcode >= OP_CLOSE && (!fin || len7 > 125) {
                return Err(Boom::new("Invalid WebSocket frame: bad control frame"));
            }
            let ext = match len7 {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            let header = 2 + ext;
            if !r.fill(header, &self.writer).map_err(io_err)? {
                return Ok(None);
            }
            let at = r.pos + 2;
            let len = match ext {
                2 => u16::from_be_bytes([r.buf[at], r.buf[at + 1]]) as u64,
                8 => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&r.buf[at..at + 8]);
                    u64::from_be_bytes(b)
                }
                _ => len7 as u64,
            };
            if len > MAX_PAYLOAD || len + r.fragments.len() as u64 > MAX_PAYLOAD {
                return Err(Boom::new("Max payload size exceeded"));
            }
            if !r.fill(header + len as usize, &self.writer).map_err(io_err)? {
                return Ok(None);
            }
            let start = r.pos + header;
            let end = start + len as usize;
            match opcode {
                OP_TEXT | OP_BINARY | OP_CONTINUATION => {
                    let continues = opcode == OP_CONTINUATION;
                    if continues != r.in_fragments {
                        return Err(Boom::new(format!("Invalid WebSocket frame: unexpected opcode {opcode}")));
                    }
                    if fin && !continues {
                        let out = r.buf[start..end].to_vec();
                        r.pos = end;
                        return Ok(Some(out));
                    }
                    r.fragments.extend_from_slice(&r.buf[start..end]);
                    r.in_fragments = !fin;
                    r.pos = end;
                    if fin {
                        // `take` leaves no buffer behind
                        return Ok(Some(std::mem::take(&mut r.fragments)));
                    }
                }
                OP_PING => {
                    let payload = r.buf[start..end].to_vec();
                    r.pos = end;
                    // a failed pong shows up as a failed read soon after
                    let _ = self.send_frame(OP_PONG, &payload);
                }
                OP_PONG => r.pos = end,
                OP_CLOSE => {
                    let payload = r.buf[start..end].to_vec();
                    r.pos = end;
                    if !self.sent_close.swap(true, Ordering::AcqRel) {
                        let echo = if payload.len() >= 2 { &payload[..2] } else { &[][..] };
                        let _ = self.send_frame(OP_CLOSE, echo);
                    }
                    return Ok(None);
                }
                other => return Err(Boom::new(format!("Invalid WebSocket frame: invalid opcode {other}"))),
            }
        }
    }
}
impl Transport for WebSocketClient {
    fn connect(&self) -> Result<()> {
        let mut tcp = self.open_tcp()?;
        *self.shutdown.lock().unwrap() = Some(tcp.try_clone().map_err(io_err)?);
        if self.closed.load(Ordering::Acquire) {
            let _ = tcp.shutdown(Shutdown::Both);
            return Err(Boom::new("WebSocket was closed before the connection was established"));
        }
        let tls = self.open_tls(&mut tcp)?;
        let mut writer = Writer { tcp: tcp.try_clone().map_err(io_err)?, tls: tls.clone() };
        let mut reader = Reader { tcp: tcp.try_clone().map_err(io_err)?, tls, buf: Vec::with_capacity(RAW_CHUNK), pos: 0, raw: vec![0u8; RAW_CHUNK], raw_start: 0, raw_end: 0, fragments: Vec::new(), in_fragments: false };
        self.handshake(&mut writer, &mut reader)?;
        // from now on a read waits for as long as the server is silent, and keep-alive watches that
        tcp.set_read_timeout(None).map_err(io_err)?;
        *self.writer.lock().unwrap() = Some(writer);
        *self.reader.lock().unwrap() = Some(reader);
        Ok(())
    }
    fn send(&self, data: &[u8]) -> Result<()> {
        self.send_frame(OP_BINARY, data)
    }
    fn recv(&self) -> Result<Option<Vec<u8>>> {
        let mut g = self.reader.lock().unwrap();
        let Some(r) = g.as_mut() else { return Ok(None) };
        match self.read_message(r) {
            Err(_) if self.closed.load(Ordering::Acquire) => Ok(None),
            other => other,
        }
    }
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // Only a free writer can send the close frame. A stuck writer must not stop the close.
        if let Ok(mut g) = self.writer.try_lock() {
            if let Some(w) = g.as_mut() {
                if !self.sent_close.swap(true, Ordering::AcqRel) {
                    let _ = Self::write_frame(w, OP_CLOSE, &1000u16.to_be_bytes());
                }
            }
        }
        if let Some(t) = self.shutdown.lock().unwrap().as_ref() {
            let _ = t.shutdown(Shutdown::Both);
        }
    }
}
/// `Arc<dyn Transport>` for the default client.
pub fn make_web_socket_client(config: &SocketConfig) -> Result<Arc<dyn Transport>> {
    Ok(Arc::new(WebSocketClient::new(config)?))
}
