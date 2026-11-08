//! Same behavior as Utils/messages-media.ts.
//!
//! Node streams become `MediaStream`. `sharp`, `jimp`, `music-metadata` and `audio-decode` become `ffmpeg` and
//! `ffprobe` through `std::process`, as upstream already does for video thumbnails.
use crate::crypto::{self, CbcDecryptor, CbcEncryptor, HmacSha256Stream, Sha256Stream};
use crate::defaults::{DEFAULT_ORIGIN, MediaType};
use crate::error::{Boom, Result};
use crate::events::{MediaRetryData, MessageMediaUpdate};
use crate::types::*;
use crate::utils::generics::generate_message_id_v2;
use crate::utils::http::{self, Body, Redirect, Request, Response, Url, encode_uri_component};
use crate::utils::logger::Logger;
use crate::wabinary::{Attrs, BinaryNode, get_binary_node_child, get_binary_node_child_buffer, jid_normalized_user};
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{Scope, ScopedJoinHandle};
use waproto::media_retry_notification::ResultType;
use waproto::pb::{Bytes, Json, PbMessage, base64_decode, base64_encode};
use waproto::{MediaRetryNotification, ServerErrorReceipt};

/// Same size as the read chunks of `fs.createReadStream`, doubled: fewer write calls, and the memory stays small.
const STREAM_CHUNK: usize = 128 * 1024;
pub const DEF_MEDIA_HOST: &str = "mmg.whatsapp.net";
const AES_CHUNK_SIZE: usize = 16;

fn tmp_path(name: &str) -> String {
    std::env::temp_dir().join(name).to_string_lossy().into_owned()
}
fn io_err(e: std::io::Error) -> Boom {
    Boom::new(e.to_string())
}
fn no_image_library() -> Boom {
    Boom::new("No image processing library available")
}
/// Removes the file when it goes out of scope, unless it is released.
struct TempFile(Option<String>);
impl TempFile {
    fn release(mut self) -> Option<String> {
        self.0.take()
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// A `Buffer` given as a stream.
pub struct BufferStream {
    data: Bytes,
    pos: Mutex<usize>,
}
impl BufferStream {
    pub fn new(data: Bytes) -> BufferStream {
        BufferStream { data, pos: Mutex::new(0) }
    }
}
impl MediaStream for BufferStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut pos = self.pos.lock().unwrap();
        let n = buf.len().min(self.data.len() - *pos);
        buf[..n].copy_from_slice(&self.data[*pos..*pos + n]);
        *pos += n;
        Ok(n)
    }
}
/// `fs.createReadStream`.
pub struct FileStream(Mutex<File>);
impl FileStream {
    pub fn open(path: &str) -> Result<FileStream> {
        Ok(FileStream(Mutex::new(File::open(path).map_err(io_err)?)))
    }
}
impl MediaStream for FileStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.lock().unwrap().read(buf).map_err(io_err)
    }
}
/// The body of an HTTP response, read as it arrives.
pub struct HttpBodyStream(Mutex<Response>);
impl MediaStream for HttpBodyStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
}
struct ReadAdapter<'a>(&'a dyn MediaStream);
impl Read for ReadAdapter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).map_err(|e| std::io::Error::other(e.message))
    }
}
/// Gives a media stream to code that wants `std::io::Read`.
pub fn stream_reader(s: &dyn MediaStream) -> impl Read + '_ {
    ReadAdapter(s)
}

pub fn hkdf_info_key(t: MediaType) -> String {
    let mut s = String::with_capacity(32);
    s.push_str("WhatsApp ");
    s.push_str(t.hkdf_key());
    s.push_str(" Keys");
    s
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMediaUploadData {
    pub file_path: String,
    pub file_sha256: [u8; 32],
    pub file_length: u64,
}
pub fn get_raw_media_upload_data(media: &WAMediaUpload, media_type: MediaType, logger: Option<&dyn Logger>) -> Result<RawMediaUploadData> {
    let GetStreamResult { stream, .. } = get_stream(media, None)?;
    if let Some(l) = logger {
        l.debug("got stream for raw upload");
    }
    let mut hasher = Sha256Stream::new();
    let path = tmp_path(&(media_type.as_str().to_string() + &generate_message_id_v2(None)));
    let guard = TempFile(Some(path.clone()));
    let mut file = File::create(&path).map_err(io_err)?;
    let mut file_length = 0u64;
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file_length += n as u64;
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(io_err)?;
    }
    if let Some(l) = logger {
        l.debug("hashed data for raw upload");
    }
    guard.release();
    Ok(RawMediaUploadData { file_path: path, file_sha256: hasher.finish(), file_length })
}
fn media_keys_with_info(buffer: Option<&[u8]>, info: &str) -> Result<MediaDecryptionKeyInfo> {
    let Some(buffer) = buffer else {
        return Err(Boom::new("Cannot derive from empty media key"));
    };
    // expand using HKDF to 112 bytes, also pass in the relevant app info
    let expanded = crypto::hkdf(buffer, 112, None, info.as_bytes());
    Ok(MediaDecryptionKeyInfo { iv: expanded[..16].to_vec(), cipher_key: expanded[16..48].to_vec(), mac_key: Some(expanded[48..80].to_vec()) })
}
/// generates all the keys required to encrypt/decrypt & sign a media message
pub fn get_media_keys(buffer: Option<&[u8]>, media_type: MediaType) -> Result<MediaDecryptionKeyInfo> {
    media_keys_with_info(buffer, &hkdf_info_key(media_type))
}
/// `getMediaKeys` with a base64 string in place of a buffer.
pub fn get_media_keys_from_string(s: &str, media_type: MediaType) -> Result<MediaDecryptionKeyInfo> {
    if s.is_empty() {
        return get_media_keys(None, media_type);
    }
    let decoded = base64_decode(&s.replacen("data:;base64,", "", 1));
    get_media_keys(Some(&decoded), media_type)
}
/// A `Readable`, `Buffer` or file path.
#[derive(Clone, Copy)]
pub enum MediaInput<'a> {
    Stream(&'a dyn MediaStream),
    Buffer(&'a [u8]),
    Path(&'a str),
}
/// A file path for the input. A stream or buffer goes to a temporary file that the guard removes.
fn input_path(input: MediaInput<'_>) -> Result<(String, TempFile)> {
    let bytes;
    let data = match input {
        MediaInput::Path(p) => return Ok((p.to_string(), TempFile(None))),
        MediaInput::Buffer(b) => b,
        MediaInput::Stream(s) => {
            bytes = to_buffer(s)?;
            &bytes[..]
        }
    };
    let path = tmp_path(&(generate_message_id_v2(None) + "-input"));
    std::fs::write(&path, data).map_err(io_err)?;
    let guard = TempFile(Some(path.clone()));
    Ok((path, guard))
}
/// Runs a tool and returns its stdout. A tool that is not installed gives `None` in the error slot.
fn run_tool(tool: &str, args: &[&str]) -> std::result::Result<Vec<u8>, Option<String>> {
    let out = match Command::new(tool).args(args).stdin(Stdio::null()).stderr(Stdio::piped()).stdout(Stdio::piped()).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(None),
        Err(e) => return Err(Some(e.to_string())),
    };
    if !out.status.success() {
        return Err(Some(format!("{tool} failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(out.stdout)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Dimensions {
    pub width: u32,
    pub height: u32,
}
fn probe_dimensions(path: &str) -> Option<Dimensions> {
    let out = run_tool("ffprobe", &["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height", "-of", "csv=p=0:s=x", path]).ok()?;
    let text = String::from_utf8_lossy(&out);
    let (w, h) = text.trim().split_once('x')?;
    Some(Dimensions { width: w.parse().ok()?, height: h.parse().ok()? })
}
/// One JPEG frame through the given video filter. `-q:v 8` is close to JPEG quality 50.
fn ffmpeg_jpeg(path: &str, filter: &str) -> Result<Vec<u8>> {
    match run_tool("ffmpeg", &["-v", "error", "-i", path, "-vf", filter, "-frames:v", "1", "-q:v", "8", "-f", "image2pipe", "-c:v", "mjpeg", "-"]) {
        Ok(o) => Ok(o),
        Err(None) => Err(no_image_library()),
        Err(Some(e)) => Err(Boom::new(e)),
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ImageThumb {
    pub buffer: Vec<u8>,
    pub original: Option<Dimensions>,
}
/// Upstream uses `sharp` or `jimp`. This port uses `ffmpeg`, and gives the same error when it is not installed.
pub fn extract_image_thumb(input: MediaInput<'_>, width: Option<u32>) -> Result<ImageThumb> {
    let (path, _guard) = input_path(input)?;
    let filter = format!("scale={}:-1", width.unwrap_or(32));
    let buffer = ffmpeg_jpeg(&path, &filter)?;
    Ok(ImageThumb { buffer, original: probe_dimensions(&path) })
}
pub fn encode_base64_encoded_string_for_upload(b64: &str) -> String {
    let s: String = b64.chars().map(|c| match c { '+' => '-', '/' => '_', c => c }).collect();
    encode_uri_component(s.trim_end_matches('='))
}
/// Upstream uses `sharp`, whose default fit crops to cover the size. This port asks `ffmpeg` for the same.
pub fn generate_profile_picture(media: &WAMediaUpload, dimensions: Option<Dimensions>) -> Result<Vec<u8>> {
    let Dimensions { width: w, height: h } = dimensions.unwrap_or(Dimensions { width: 640, height: 640 });
    let GetStreamResult { stream, .. } = get_stream(media, None)?;
    let buffer = to_buffer(&*stream)?;
    let (path, _guard) = input_path(MediaInput::Buffer(&buffer))?;
    ffmpeg_jpeg(&path, &format!("scale={w}:{h}:force_original_aspect_ratio=increase,crop={w}:{h}"))
}
/// The first field of the message, as `Object.values(message)[0]`.
fn first_field(message: &WAMessageContent) -> Option<(String, Json)> {
    match message.to_json() {
        Json::Obj(mut o) if !o.is_empty() => Some(o.swap_remove(0)),
        _ => None,
    }
}
/// gets the SHA256 of the given media message
pub fn media_message_sha256_b64(message: &WAMessageContent) -> Option<String> {
    let (_, media) = first_field(message)?;
    media.get("fileSha256").and_then(|v| v.as_str()).map(str::to_string)
}
/// Upstream uses `music-metadata`. This port uses `ffprobe`. `None` means that the file has no duration.
pub fn get_audio_duration(input: MediaInput<'_>) -> Result<Option<f64>> {
    let (path, _guard) = input_path(input)?;
    match run_tool("ffprobe", &["-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", &path]) {
        Ok(o) => Ok(String::from_utf8_lossy(&o).trim().parse::<f64>().ok()),
        Err(None) => Err(Boom::new("Cannot find ffprobe, which reads the audio duration")),
        Err(Some(e)) => Err(Boom::new(e)),
    }
}
/// Upstream uses `audio-decode`. This port has `ffmpeg` decode the first channel.
/// referenced from and modifying https://github.com/wppconnect-team/wa-js/blob/main/src/chat/functions/prepareAudioWaveform.ts
pub fn get_audio_waveform(input: MediaInput<'_>, logger: Option<&dyn Logger>) -> Option<Vec<u8>> {
    let run = || -> std::result::Result<Vec<u8>, String> {
        let (path, _guard) = input_path(input).map_err(|e| e.message)?;
        let pcm = run_tool("ffmpeg", &["-v", "error", "-i", &path, "-af", "pan=mono|c0=c0", "-f", "f32le", "-"]).map_err(|e| e.unwrap_or_else(|| "Cannot find ffmpeg".to_string()))?;
        Ok(waveform_from_samples(&pcm))
    };
    match run() {
        Ok(w) => Some(w),
        Err(e) => {
            if let Some(l) = logger {
                l.debug(&format!("Failed to generate waveform: {e}"));
            }
            None
        }
    }
}
fn waveform_from_samples(pcm: &[u8]) -> Vec<u8> {
    const SAMPLES: usize = 64;
    let raw: Vec<f32> = pcm.chunks_exact(4).map(|c| f32::from_bits(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))).collect();
    let block_size = raw.len() / SAMPLES;
    if block_size == 0 {
        // the average of an empty block is NaN, and NaN in a Uint8Array is 0
        return vec![0; SAMPLES];
    }
    let filtered: Vec<f64> = (0..SAMPLES).map(|i| raw[block_size * i..block_size * (i + 1)].iter().map(|v| v.abs() as f64).sum::<f64>() / block_size as f64).collect();
    // This guarantees that the largest data point will be set to 1, and the rest of the data will scale proportionally.
    let max = filtered.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    filtered.iter().map(|n| if max > 0.0 { (100.0 * (n / max)).floor() as u8 } else { 0 }).collect()
}
pub fn to_readable(buffer: Bytes) -> Arc<dyn MediaStream> {
    Arc::new(BufferStream::new(buffer))
}
pub fn to_buffer(stream: &dyn MediaStream) -> Result<Vec<u8>> {
    let mut o = Vec::new();
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(o);
        }
        o.extend_from_slice(&buf[..n]);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaStreamType {
    Buffer,
    Readable,
    Remote,
    File,
}
pub struct GetStreamResult {
    pub stream: Arc<dyn MediaStream>,
    pub r#type: MediaStreamType,
}
pub fn get_stream(item: &WAMediaUpload, opts: Option<&RequestInit>) -> Result<GetStreamResult> {
    match item {
        WAMediaUpload::Buffer(b) => Ok(GetStreamResult { stream: to_readable(b.clone()), r#type: MediaStreamType::Buffer }),
        WAMediaUpload::Stream(s) => Ok(GetStreamResult { stream: s.clone(), r#type: MediaStreamType::Readable }),
        WAMediaUpload::Url(url) => {
            if url.starts_with("data:") {
                let Some(data) = url.split(',').nth(1) else {
                    return Err(Boom::new("The \"string\" argument must be of type string. Received undefined"));
                };
                return Ok(GetStreamResult { stream: to_readable(base64_decode(data).into()), r#type: MediaStreamType::Buffer });
            }
            if url.starts_with("http://") || url.starts_with("https://") {
                let default_init = RequestInit::default();
                return Ok(GetStreamResult { stream: get_http_stream(url, opts.unwrap_or(&default_init))?, r#type: MediaStreamType::Remote });
            }
            Ok(GetStreamResult { stream: Arc::new(FileStream::open(url)?), r#type: MediaStreamType::File })
        }
    }
}
/// Extracts video thumb using FFMPEG
fn extract_video_thumb(path: &str, dest_path: &str, time: &str, size: Dimensions) -> Result<()> {
    let filter = format!("scale={}:-1", size.width);
    match run_tool("ffmpeg", &["-ss", time, "-i", path, "-y", "-vf", &filter, "-vframes", "1", "-f", "image2", dest_path]) {
        Ok(_) => Ok(()),
        Err(None) => Err(Boom::new("Cannot find ffmpeg")),
        Err(Some(e)) => Err(Boom::new(e)),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThumbnailMediaType {
    Video,
    Image,
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GeneratedThumbnail {
    pub thumbnail: Option<String>,
    pub original_image_dimensions: Option<Dimensions>,
}
/// generates a thumbnail for a given media, if required
pub fn generate_thumbnail(file: &str, media_type: ThumbnailMediaType, logger: Option<&dyn Logger>) -> Result<GeneratedThumbnail> {
    let mut out = GeneratedThumbnail::default();
    match media_type {
        ThumbnailMediaType::Image => {
            let ImageThumb { buffer, original } = extract_image_thumb(MediaInput::Path(file), None)?;
            out.thumbnail = Some(base64_encode(&buffer));
            out.original_image_dimensions = original.filter(|d| d.width != 0 && d.height != 0);
        }
        ThumbnailMediaType::Video => {
            let img = tmp_path(&(generate_message_id_v2(None) + ".jpg"));
            let run = || -> Result<Vec<u8>> {
                extract_video_thumb(file, &img, "00:00:00", Dimensions { width: 32, height: 32 })?;
                let buff = std::fs::read(&img).map_err(io_err)?;
                std::fs::remove_file(&img).map_err(io_err)?;
                Ok(buff)
            };
            match run() {
                Ok(buff) => out.thumbnail = Some(base64_encode(&buff)),
                Err(err) => {
                    if let Some(l) = logger {
                        l.debug(&format!("could not generate video thumb: {err}"));
                    }
                }
            }
        }
    }
    Ok(out)
}
fn fetch_failed(url: &str, status: u16) -> Boom {
    let mut e = Boom::with_data(format!("Failed to fetch stream from {url}"), Json::Obj(vec![("url".to_string(), Json::Str(url.to_string()))]));
    e.status_code = Some(status);
    e
}
/// A client in `options` gets the whole body at once. Without one, the body is read as it arrives.
pub fn get_http_stream(url: &str, options: &RequestInit) -> Result<Arc<dyn MediaStream>> {
    if let Some(c) = &options.client {
        let r = c.get(url, &options.headers)?;
        if !r.ok() {
            return Err(fetch_failed(url, r.status));
        }
        return Ok(to_readable(r.body.into()));
    }
    let res = http::fetch(&Request::get(url, &options.headers))?;
    if !res.ok() {
        return Err(fetch_failed(url, res.status));
    }
    Ok(Arc::new(HttpBodyStream(Mutex::new(res))))
}
#[derive(Clone, Default)]
pub struct EncryptedStreamOptions {
    pub save_original_file_if_required: bool,
    pub logger: Option<Arc<dyn Logger>>,
    pub opts: Option<RequestInit>,
    /// `opts.maxContentLength`.
    pub max_content_length: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedStream {
    pub media_key: [u8; 32],
    pub original_file_path: Option<String>,
    pub enc_file_path: String,
    pub mac: [u8; 10],
    pub file_enc_sha256: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_length: u64,
}
pub fn encrypted_stream(media: &WAMediaUpload, media_type: MediaType, options: &EncryptedStreamOptions) -> Result<EncryptedStream> {
    let GetStreamResult { stream, r#type } = get_stream(media, options.opts.as_ref())?;
    let logger = options.logger.as_deref();
    if let Some(l) = logger {
        l.debug("fetched media stream");
    }
    let mut media_key = [0u8; 32];
    crypto::random_bytes(&mut media_key);
    let keys = get_media_keys(Some(&media_key), media_type)?;
    let mac_key = keys.mac_key.as_deref().unwrap_or(&[]);

    let enc_path = tmp_path(&(media_type.as_str().to_string() + &generate_message_id_v2(None) + "-enc"));
    let enc_guard = TempFile(Some(enc_path.clone()));
    let mut enc_file = File::create(&enc_path).map_err(io_err)?;
    let mut original = None;
    let mut original_guard = TempFile(None);
    if options.save_original_file_if_required {
        let p = tmp_path(&(media_type.as_str().to_string() + &generate_message_id_v2(None) + "-original"));
        original_guard = TempFile(Some(p.clone()));
        original = Some((File::create(&p).map_err(io_err)?, p));
    }

    let mut file_length = 0u64;
    let mut aes = CbcEncryptor::new(&keys.cipher_key, &keys.iv)?;
    let mut hmac = HmacSha256Stream::new(mac_key);
    hmac.update(&keys.iv);

    // SHA-256 takes most of the time here, so each of the three hashes runs on its own thread
    let (mac, file_enc_sha256, file_sha256) = std::thread::scope(|scope| -> Result<([u8; 10], [u8; 32], [u8; 32])> {
        let (plain_tx, plain_done) = hash_thread(scope, Sha256Stream::new(), Sha256Stream::update);
        let (enc_tx, enc_done) = hash_thread(scope, Sha256Stream::new(), Sha256Stream::update);
        let (mac_tx, mac_done) = hash_thread(scope, hmac, HmacSha256Stream::update);
        let send = |tx: &HashQueue, chunk: &Arc<Vec<u8>>| tx.send(chunk.clone()).map_err(|_| Boom::new("hash thread stopped"));

        // the bytes that do not fill a block wait at the start of the buffer, and new data goes after them
        let mut buf = vec![0u8; STREAM_CHUNK + AES_CHUNK_SIZE];
        let mut pending = 0usize;
        loop {
            let n = stream.read(&mut buf[pending..])?;
            if n == 0 {
                break;
            }
            file_length += n as u64;
            if r#type == MediaStreamType::Remote && options.max_content_length.is_some_and(|max| file_length + n as u64 > max) {
                return Err(Boom::new("content length exceeded when encrypting \"remote\""));
            }
            let data = &buf[pending..pending + n];
            if let Some((f, _)) = original.as_mut() {
                f.write_all(data).map_err(io_err)?;
            }
            send(&plain_tx, &Arc::new(data.to_vec()))?;
            let total = pending + n;
            let whole = total - total % AES_CHUNK_SIZE;
            if whole > 0 {
                let blocks = &mut buf[..whole];
                aes.encrypt_blocks(blocks);
                let chunk = Arc::new(blocks.to_vec());
                send(&enc_tx, &chunk)?;
                send(&mac_tx, &chunk)?;
                enc_file.write_all(blocks).map_err(io_err)?;
            }
            buf.copy_within(whole..total, 0);
            pending = total - whole;
        }
        // PKCS7
        let pad = AES_CHUNK_SIZE - pending;
        buf[pending..AES_CHUNK_SIZE].fill(pad as u8);
        let last = &mut buf[..AES_CHUNK_SIZE];
        aes.encrypt_blocks(last);
        let chunk = Arc::new(last.to_vec());
        send(&enc_tx, &chunk)?;
        send(&mac_tx, &chunk)?;
        enc_file.write_all(last).map_err(io_err)?;

        drop(mac_tx);
        let mut mac = [0u8; 10];
        mac.copy_from_slice(&mac_done.join().map_err(|_| Boom::new("hash thread stopped"))?.finish()[..10]);
        send(&enc_tx, &Arc::new(mac.to_vec()))?;
        drop(enc_tx);
        drop(plain_tx);
        let file_enc_sha256 = enc_done.join().map_err(|_| Boom::new("hash thread stopped"))?.finish();
        let file_sha256 = plain_done.join().map_err(|_| Boom::new("hash thread stopped"))?.finish();
        enc_file.write_all(&mac).map_err(io_err)?;
        Ok((mac, file_enc_sha256, file_sha256))
    })?;
    if let Some(l) = logger {
        l.debug("encrypted data successfully");
    }
    enc_guard.release();
    original_guard.release();
    Ok(EncryptedStream { media_key, original_file_path: original.map(|(_, p)| p), enc_file_path: enc_path, mac, file_enc_sha256, file_sha256, file_length })
}
type HashQueue = SyncSender<Arc<Vec<u8>>>;
/// Starts a thread that feeds each queued chunk to `hash`, and gives `hash` back when the queue is closed.
fn hash_thread<'s, 'e, H: Send + 's>(scope: &'s Scope<'s, 'e>, mut hash: H, update: fn(&mut H, &[u8])) -> (HashQueue, ScopedJoinHandle<'s, H>) {
    let (tx, rx) = sync_channel::<Arc<Vec<u8>>>(4);
    let done = scope.spawn(move || {
        while let Ok(chunk) = rx.recv() {
            update(&mut hash, chunk.as_slice());
        }
        hash
    });
    (tx, done)
}
fn to_smallest_chunk_size(num: u64) -> u64 {
    num / AES_CHUNK_SIZE as u64 * AES_CHUNK_SIZE as u64
}
#[derive(Clone, Default)]
pub struct MediaDownloadOptions {
    pub start_byte: Option<u64>,
    pub end_byte: Option<u64>,
    pub options: Option<RequestInit>,
    /// Optional media host override; falls back to DEF_MEDIA_HOST when not provided.
    pub host: Option<String>,
}
pub fn get_url_from_direct_path(direct_path: &str, host: Option<&str>) -> String {
    let host = host.unwrap_or(DEF_MEDIA_HOST);
    let mut s = String::with_capacity(8 + host.len() + direct_path.len());
    s.push_str("https://");
    s.push_str(host);
    s.push_str(direct_path);
    s
}
fn extract_host(url: Option<&str>) -> Option<String> {
    Url::parse(url.filter(|u| !u.is_empty())?).ok().map(|u| u.host())
}
pub fn download_content_from_message(msg: &DownloadableMessage, media_type: MediaType, opts: &MediaDownloadOptions) -> Result<DecryptedMediaStream> {
    download_with_info(msg, &hkdf_info_key(media_type), opts)
}
/// `info` is the HKDF info. A content type without a media type gives `WhatsApp undefined Keys`, as upstream.
pub(crate) fn download_with_info(msg: &DownloadableMessage, info: &str, opts: &MediaDownloadOptions) -> Result<DecryptedMediaStream> {
    // Fallback host: explicit opt > host parsed from `url` > DEF_MEDIA_HOST.
    // Lets us honor a non-default host carried by the proto without forcing callers to thread it through.
    let fallback_host = opts.host.clone().or_else(|| extract_host(msg.url.as_deref()));
    let download_url = match msg.direct_path.as_deref().filter(|d| !d.is_empty()) {
        Some(d) => Some(get_url_from_direct_path(d, fallback_host.as_deref())),
        None => msg.url.clone().filter(|u| !u.is_empty()),
    };
    let Some(download_url) = download_url else {
        return Err(Boom::status("No valid media URL or directPath present in message", 400));
    };
    let keys = media_keys_with_info(msg.media_key.as_deref(), info)?;
    download_encrypted_content(&download_url, &keys, opts)
}
/// Decrypts and downloads an AES256-CBC encrypted file given the keys.
/// Assumes the SHA256 of the plaintext is appended to the end of the ciphertext
pub fn download_encrypted_content(download_url: &str, keys: &MediaDecryptionKeyInfo, opts: &MediaDownloadOptions) -> Result<DecryptedMediaStream> {
    let (mut bytes_fetched, mut start_chunk, mut first_block_is_iv) = (0u64, 0u64, false);
    // if a start byte is specified -- then we need to fetch the previous chunk as that will form the IV
    if let Some(start) = opts.start_byte.filter(|s| *s != 0) {
        let chunk = to_smallest_chunk_size(start);
        if chunk != 0 {
            start_chunk = chunk - AES_CHUNK_SIZE as u64;
            bytes_fetched = chunk;
            first_block_is_iv = true;
        }
    }
    let end_chunk = opts.end_byte.filter(|e| *e != 0).map(|e| to_smallest_chunk_size(e) + AES_CHUNK_SIZE as u64);
    let mut init = opts.options.clone().unwrap_or_default();
    init.headers.retain(|(k, _)| k != "Origin");
    init.headers.push(("Origin".to_string(), DEFAULT_ORIGIN.to_string()));
    if start_chunk != 0 || end_chunk.is_some() {
        let range = match end_chunk {
            Some(e) => format!("bytes={start_chunk}-{e}"),
            None => format!("bytes={start_chunk}-"),
        };
        init.headers.retain(|(k, _)| k != "Range");
        init.headers.push(("Range".to_string(), range));
    }
    // download the message
    let source = get_http_stream(download_url, &init)?;
    Ok(DecryptedMediaStream(Mutex::new(DecryptState {
        source,
        cipher_key: keys.cipher_key.clone(),
        iv: keys.iv.clone(),
        aes: None,
        first_block_is_iv,
        // if an end byte that is not EOF is specified
        // stop auto padding (PKCS7) -- otherwise throws an error for decryption
        auto_padding: end_chunk.is_none(),
        start_byte: opts.start_byte,
        end_byte: opts.end_byte,
        bytes_fetched,
        pending: Vec::new(),
        held: None,
        out: Vec::new(),
        out_pos: 0,
        finished: false,
    })))
}
struct DecryptState {
    source: Arc<dyn MediaStream>,
    cipher_key: Vec<u8>,
    iv: Vec<u8>,
    aes: Option<CbcDecryptor>,
    first_block_is_iv: bool,
    auto_padding: bool,
    start_byte: Option<u64>,
    end_byte: Option<u64>,
    bytes_fetched: u64,
    /// Ciphertext that does not fill a block yet. The MAC at the end stays here and is dropped.
    pending: Vec<u8>,
    /// The last plaintext block, kept until the padding can be checked.
    held: Option<[u8; 16]>,
    out: Vec<u8>,
    out_pos: usize,
    finished: bool,
}
impl DecryptState {
    /// `pushBytes`. A set `start_byte` without `end_byte` gives no bytes, because upstream slices with
    /// `Math.max(undefined - fetched, 0)`, which is NaN, as its end.
    fn push_bytes(&mut self, bytes: &[u8]) {
        if self.start_byte.is_none_or(|s| s == 0) && self.end_byte.is_none_or(|e| e == 0) {
            self.out.extend_from_slice(bytes);
            return;
        }
        let len = bytes.len() as u64;
        let start = match self.start_byte {
            Some(s) if self.bytes_fetched < s => s - self.bytes_fetched,
            _ => 0,
        };
        let end = match self.end_byte {
            Some(e) if self.bytes_fetched + len < e => len,
            Some(e) => e.saturating_sub(self.bytes_fetched),
            None => 0,
        };
        if start < end {
            self.out.extend_from_slice(&bytes[start.min(len) as usize..end.min(len) as usize]);
        }
        self.bytes_fetched += len;
    }
    /// Decrypts the whole blocks in `pending`.
    fn transform(&mut self) -> Result<()> {
        let whole = self.pending.len() - self.pending.len() % AES_CHUNK_SIZE;
        if whole == 0 {
            return Ok(());
        }
        let mut data: Vec<u8> = self.pending.drain(..whole).collect();
        let mut from = 0;
        if self.aes.is_none() {
            let aes = if self.first_block_is_iv {
                from = AES_CHUNK_SIZE;
                CbcDecryptor::new(&self.cipher_key, &data[..AES_CHUNK_SIZE])?
            } else {
                CbcDecryptor::new(&self.cipher_key, &self.iv)?
            };
            self.aes = Some(aes);
        }
        let blocks = &mut data[from..];
        if blocks.is_empty() {
            return Ok(());
        }
        if let Some(aes) = self.aes.as_mut() {
            aes.decrypt_blocks(blocks);
        }
        if self.auto_padding {
            // hold back the last block until the end, as `decipher.update` does
            let (head, tail) = blocks.split_at(blocks.len() - AES_CHUNK_SIZE);
            if let Some(h) = self.held.take() {
                self.push_bytes(&h);
            }
            self.push_bytes(head);
            let mut h = [0u8; 16];
            h.copy_from_slice(tail);
            self.held = Some(h);
        } else {
            self.push_bytes(blocks);
        }
        Ok(())
    }
    /// `decipher.final` and the end of the stream.
    fn finish(&mut self) -> Result<()> {
        self.finished = true;
        if self.aes.is_none() {
            return Err(Boom::new("Cannot read properties of undefined (reading 'final')"));
        }
        if !self.auto_padding {
            return Ok(());
        }
        let Some(h) = self.held.take() else {
            return Err(Boom::new("wrong final block length"));
        };
        let n = h[15] as usize;
        if n == 0 || n > AES_CHUNK_SIZE || h[AES_CHUNK_SIZE - n..].iter().any(|v| *v as usize != n) {
            return Err(Boom::new("bad decrypt"));
        }
        self.push_bytes(&h[..AES_CHUNK_SIZE - n]);
        Ok(())
    }
}
/// The decrypted plaintext of a download. It is read as it arrives, as the Transform stream of upstream is.
pub struct DecryptedMediaStream(Mutex<DecryptState>);
impl MediaStream for DecryptedMediaStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut s = self.0.lock().unwrap();
        loop {
            if s.out_pos < s.out.len() {
                let n = buf.len().min(s.out.len() - s.out_pos);
                let from = s.out_pos;
                buf[..n].copy_from_slice(&s.out[from..from + n]);
                s.out_pos += n;
                return Ok(n);
            }
            s.out.clear();
            s.out_pos = 0;
            if s.finished {
                return Ok(0);
            }
            let at = s.pending.len();
            s.pending.resize(at + STREAM_CHUNK, 0);
            let source = s.source.clone();
            let read = source.read(&mut s.pending[at..]);
            match read {
                Ok(0) => {
                    s.pending.truncate(at);
                    s.transform()?;
                    s.finish()?;
                }
                Ok(n) => {
                    s.pending.truncate(at + n);
                    s.transform()?;
                }
                Err(e) => {
                    s.pending.truncate(at);
                    s.finished = true;
                    return Err(e);
                }
            }
        }
    }
}
/// The text after `/` in the mimetype, as `.jpeg` for location and product messages.
pub fn extension_for_media_message(message: &WAMessageContent) -> Result<Option<String>> {
    let (key, media) = first_field(message).ok_or_else(|| Boom::new("Cannot read properties of undefined (reading 'mimetype')"))?;
    if key == "locationMessage" || key == "liveLocationMessage" || key == "productMessage" {
        return Ok(Some(".jpeg".to_string()));
    }
    let mimetype = media.get("mimetype").and_then(|v| v.as_str()).ok_or_else(|| Boom::new("Cannot read properties of undefined (reading 'split')"))?;
    Ok(mimetype.split(';').next().and_then(|m| m.split('/').nth(1)).map(str::to_string))
}
/// `agent` of upstream has no port: the client connects directly.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UploadParams {
    pub url: String,
    pub file_path: String,
    pub headers: Vec<(String, String)>,
    pub timeout_ms: Option<u64>,
}
/// The JSON that the server answers with. `None` is an answer that is not JSON.
pub fn upload_with_node_http(params: &UploadParams) -> Result<Option<Json>> {
    upload_with_redirects(params, 0)
}
fn upload_with_redirects(params: &UploadParams, redirect_count: u32) -> Result<Option<Json>> {
    if redirect_count > 5 {
        return Err(Boom::new("Too many redirects"));
    }
    let parsed = Url::parse(&params.url)?;
    let req = Request { method: "POST", url: &params.url, headers: &params.headers, body: Body::File(&params.file_path), timeout_ms: params.timeout_ms, redirect: Redirect::Manual, fetch_headers: false };
    let timeout_err = |e: Boom| if e.message == http::TIMEOUT_MESSAGE { Boom::new("Upload timeout") } else { e };
    let res = http::fetch(&req).map_err(timeout_err)?;
    // Handle redirects (3xx)
    if (300..400).contains(&res.status) {
        if let Some(location) = res.header("location") {
            let next = UploadParams { url: parsed.join(location)?.to_string(), file_path: params.file_path.clone(), headers: params.headers.clone(), timeout_ms: params.timeout_ms };
            return upload_with_redirects(&next, redirect_count + 1);
        }
    }
    let body = res.bytes().map_err(timeout_err)?;
    Ok(Json::parse(&String::from_utf8_lossy(&body)).ok())
}
/// Same reason as upstream: Node's `fetch` buffers the request body, so uploads use the plain HTTP path.
/// This port has only that path. A client in the options takes its place.
fn upload_media(params: &UploadParams, client: Option<&Arc<dyn HttpClient>>, logger: &dyn Logger) -> Result<Option<Json>> {
    logger.debug("Using Node.js https module for upload (avoids undici buffering bug)");
    match client {
        None => upload_with_node_http(params),
        Some(c) => {
            let r = c.post_file(&params.url, &params.file_path, &params.headers, params.timeout_ms)?;
            Ok(Json::parse(&String::from_utf8_lossy(&r.body)).ok())
        }
    }
}
pub type RefreshMediaConn = Arc<dyn Fn(bool) -> Result<MediaConnInfo> + Send + Sync>;
fn truthy_str(j: &Json, k: &str) -> Option<String> {
    j.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string)
}
fn json_u64(j: &Json, k: &str) -> Option<u64> {
    match j.get(k) {
        Some(Json::Num(n)) if *n >= 0.0 => Some(*n as u64),
        _ => None,
    }
}
/// `fetchAgent` of the config has no port: the client connects directly. See `UploadParams`.
pub fn get_wa_upload_to_server(config: &SocketConfig, refresh_media_conn: RefreshMediaConn) -> WAMediaUploadFunction {
    let custom_upload_hosts = config.custom_upload_hosts.clone();
    let logger = config.logger.clone();
    let options = config.options.clone();
    Arc::new(move |file_path: &str, opts: &MediaUploadOpts| -> Result<MediaUploadResult> {
        // send a query JSON to obtain the url & auth token to upload our media
        let mut upload_info = refresh_media_conn(false)?;
        let mut urls = None;
        let mut hosts = custom_upload_hosts.clone();
        hosts.extend(upload_info.hosts.iter().cloned());
        let file_enc_sha256_b64 = encode_base64_encoded_string_for_upload(&opts.file_enc_sha256_b64);
        let mut headers: Vec<(String, String)> = options.headers.iter().filter(|(k, _)| k != "Content-Type" && k != "Origin").cloned().collect();
        headers.push(("Content-Type".to_string(), "application/octet-stream".to_string()));
        headers.push(("Origin".to_string(), DEFAULT_ORIGIN.to_string()));
        for host in &hosts {
            let hostname = &host.hostname;
            logger.debug(&format!("uploading to \"{hostname}\""));
            let auth = encode_uri_component(&upload_info.auth);
            // a type without a path gives `undefined` in the URL, as upstream
            let url = format!("https://{hostname}{}/{file_enc_sha256_b64}?auth={auth}&token={file_enc_sha256_b64}", opts.media_type.path().unwrap_or("undefined"));
            let params = UploadParams { url, file_path: file_path.to_string(), headers: headers.clone(), timeout_ms: opts.timeout_ms };
            let mut result = None;
            let attempt = (|| -> Result<Option<MediaUploadResult>> {
                result = upload_media(&params, options.client.as_ref(), &*logger)?;
                let found = result.as_ref().filter(|r| truthy_str(r, "url").is_some() || truthy_str(r, "direct_path").is_some());
                if let Some(r) = found {
                    return Ok(Some(MediaUploadResult {
                        media_url: truthy_str(r, "url").unwrap_or_default(),
                        direct_path: truthy_str(r, "direct_path").unwrap_or_default(),
                        meta_hmac: truthy_str(r, "meta_hmac"),
                        ts: json_u64(r, "ts"),
                        fbid: json_u64(r, "fbid"),
                    }));
                }
                upload_info = refresh_media_conn(true)?;
                let shown = result.as_ref().map_or_else(|| "undefined".to_string(), Json::stringify);
                Err(Boom::new(format!("upload failed, reason: {shown}")))
            })();
            match attempt {
                Ok(Some(u)) => {
                    urls = Some(u);
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    let is_last = upload_info.hosts.len().checked_sub(1).and_then(|i| hosts.get(i)).is_some_and(|h| h.hostname == *hostname);
                    let retry = if is_last { "" } else { ", retrying..." };
                    logger.warn(&format!("Error in uploading to {hostname} {retry}: {error}"));
                }
            }
        }
        urls.ok_or_else(|| Boom::status("Media upload failed on all hosts", 500))
    })
}
fn get_media_retry_key(media_key: &[u8]) -> Vec<u8> {
    crypto::hkdf(media_key, 32, None, b"WhatsApp Media Retry Notification")
}
/// Generate a binary node that will request the phone to re-upload the media & return the newly uploaded URL
pub fn encrypt_media_retry_request(key: &WAMessageKey, media_key: &[u8], me_id: &str) -> Result<BinaryNode> {
    let id = key.id().map_or("", |s| s.as_str());
    let mut recp = ServerErrorReceipt::new();
    if let Some(i) = key.id() {
        recp.set_stanza_id(i.clone());
    }
    let recp_buffer = recp.encode();
    let mut iv = [0u8; 12];
    crypto::random_bytes(&mut iv);
    let retry_key = get_media_retry_key(media_key);
    let ciphertext = crypto::aes_encrypt_gcm(&recp_buffer, &retry_key, &iv, id.as_bytes())?;
    let mut rmr = Attrs::new();
    rmr.set("jid", key.remote_jid().map_or("", |s| s.as_str()));
    rmr.set("from_me", if key.from_me() == Some(true) { "true" } else { "false" });
    if let Some(p) = key.participant().filter(|p| !p.is_empty()) {
        rmr.set("participant", p.as_str());
    }
    Ok(BinaryNode::with_nodes(
        "receipt",
        Attrs::from([("id", id.to_string()), ("to", jid_normalized_user(me_id)), ("type", "server-error".to_string())]),
        vec![
            // this encrypt node is actually pretty useless
            // the media is returned even without this node
            // keeping it here to maintain parity with WA Web
            BinaryNode::with_nodes("encrypt", Attrs::new(), vec![BinaryNode::with_bytes("enc_p", Attrs::new(), ciphertext), BinaryNode::with_bytes("enc_iv", Attrs::new(), iv)]),
            BinaryNode::tag("rmr", rmr),
        ],
    ))
}
pub fn decode_media_retry_node(node: &BinaryNode) -> Result<MessageMediaUpdate> {
    let rmr = get_binary_node_child(Some(node), "rmr").ok_or_else(|| Boom::new("Cannot read properties of undefined (reading 'attrs')"))?;
    let mut key = WAMessageKey::new();
    if let Some(v) = node.attr("id") {
        key.set_id(v);
    }
    if let Some(v) = rmr.attr("jid") {
        key.set_remote_jid(v);
    }
    key.set_from_me(rmr.attr("from_me") == Some("true"));
    if let Some(v) = rmr.attr("participant") {
        key.set_participant(v);
    }
    let mut event = MessageMediaUpdate { key, media: None, error: None };
    if let Some(error_node) = get_binary_node_child(Some(node), "error") {
        let code_text = error_node.attr("code").unwrap_or("");
        let shown = code_text.parse::<i64>().map_or_else(|_| "NaN".to_string(), |c| c.to_string());
        let code = code_text.parse::<i32>().ok();
        let attrs = error_node.attrs.iter().map(|(k, v)| (k.to_string(), Json::Str(v.to_string()))).collect();
        let mut e = Boom::with_data(format!("Failed to re-upload media ({shown})"), Json::Obj(attrs));
        e.status_code = code.and_then(get_status_code_for_media_retry);
        event.error = Some(e);
    } else {
        let encrypted = get_binary_node_child(Some(node), "encrypt");
        let ciphertext = get_binary_node_child_buffer(encrypted, "enc_p");
        let iv = get_binary_node_child_buffer(encrypted, "enc_iv");
        match (ciphertext, iv) {
            (Some(ciphertext), Some(iv)) => event.media = Some(MediaRetryData { ciphertext: ciphertext.clone(), iv: iv.clone() }),
            _ => event.error = Some(Boom::status("Failed to re-upload media (missing ciphertext)", 404)),
        }
    }
    Ok(event)
}
pub fn decrypt_media_retry_data(ciphertext: &[u8], iv: &[u8], media_key: &[u8], msg_id: &str) -> Result<MediaRetryNotification> {
    let retry_key = get_media_retry_key(media_key);
    let plaintext = crypto::aes_decrypt_gcm(ciphertext, &retry_key, iv, msg_id.as_bytes())?;
    Ok(MediaRetryNotification::decode(&plaintext)?)
}
pub fn get_status_code_for_media_retry(code: i32) -> Option<u16> {
    match ResultType(code) {
        ResultType::SUCCESS => Some(200),
        ResultType::DECRYPTION_ERROR => Some(412),
        ResultType::NOT_FOUND => Some(404),
        ResultType::GENERAL_ERROR => Some(418),
        _ => None,
    }
}
