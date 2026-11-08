//! Port of Utils/messages-media.test.ts. The server is a real local HTTP server, as in upstream.
use baileys::defaults::{MediaType, default_connection_config};
use baileys::error::Result;
use baileys::proto::pb::{Bytes, Json};
use baileys::types::*;
use baileys::utils::messages_media::{EncryptedStreamOptions, UploadParams, encrypted_stream, get_wa_upload_to_server, upload_with_node_http};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
const TEST_FILE_CONTENT: &str = "Hello, this is test content for upload!";

fn create_temp_file(content: &str) -> String {
    let n = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("test-upload-{}-{n}.txt", std::process::id())).to_string_lossy().into_owned();
    std::fs::write(&path, content).unwrap();
    path
}
fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
}
#[derive(Clone, Debug, Default)]
struct SeenRequest {
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl SeenRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}
/// One answer of the handler: status, header lines and body.
struct Answer(u16, Vec<(String, String)>, Vec<u8>);
fn json(body: &str) -> Answer {
    Answer(200, vec![("Content-Type".to_string(), "application/json".to_string())], body.as_bytes().to_vec())
}
fn redirect(status: u16, location: String) -> Answer {
    Answer(status, vec![("Location".to_string(), location)], Vec::new())
}
struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<SeenRequest>>>,
}
impl Server {
    fn seen(&self) -> Vec<SeenRequest> {
        self.requests.lock().unwrap().clone()
    }
}
fn read_request(sock: &mut TcpStream) -> Option<(String, Vec<(String, String)>, usize, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = sock.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let url = lines.next()?.split(' ').nth(1)?.to_string();
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    let len = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    Some((url, headers, len, buf[head_end + 4..].to_vec()))
}
/// `handler(url, port)` answers each request. Upstream reads the body before the answer only on some routes;
/// here `drain_first(url)` says which ones. A route that answers first still reads the body afterwards, as Node does.
fn start_server(handler: Arc<dyn Fn(&str, u16) -> Answer + Send + Sync>, drain_first: fn(&str) -> bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { continue };
            let (handler, seen) = (handler.clone(), seen.clone());
            std::thread::spawn(move || {
                let Some((url, headers, len, mut body)) = read_request(&mut sock) else { return };
                let drain = |sock: &mut TcpStream, body: &mut Vec<u8>| {
                    let mut chunk = [0u8; 4096];
                    while body.len() < len {
                        match sock.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => body.extend_from_slice(&chunk[..n]),
                        }
                    }
                };
                if drain_first(&url) {
                    drain(&mut sock, &mut body);
                }
                let Answer(status, answer_headers, answer_body) = handler(&url, port);
                let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", answer_body.len()).into_bytes();
                for (k, v) in answer_headers {
                    out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
                }
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(&answer_body);
                let _ = sock.write_all(&out);
                drain(&mut sock, &mut body);
                seen.lock().unwrap().push(SeenRequest { url, headers, body });
                let _ = sock.shutdown(Shutdown::Both);
            });
        }
    });
    Server { port, requests }
}
fn params(port: u16, path: &str, file: &str, headers: &[(&str, &str)]) -> UploadParams {
    UploadParams { url: format!("http://localhost:{port}{path}"), file_path: file.to_string(), headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), timeout_ms: None }
}
const OCTET: (&str, &str) = ("Content-Type", "application/octet-stream");
fn seen_on<'a>(all: &'a [SeenRequest], url: &str) -> &'a SeenRequest {
    all.iter().find(|r| r.url == url).unwrap()
}
fn wait_for(server: &Server, count: usize) -> Vec<SeenRequest> {
    // the handler thread records a request after it answers, so give it a moment
    for _ in 0..500 {
        let all = server.seen();
        if all.len() >= count {
            return all;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    server.seen()
}

#[test]
fn t_uploadwithnodehttp_should_successfully_upload_a_file_and_receive_json_response() {
    let expected = r#"{"url":"https://example.com/media/123","direct_path":"/media/123"}"#;
    let server = start_server(Arc::new(move |_, _| json(expected)), |_| true);
    let file = create_temp_file(TEST_FILE_CONTENT);
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &[OCTET])).unwrap();
    assert_eq!(result, Some(Json::parse(expected).unwrap()));
    let seen = wait_for(&server, 1);
    assert_eq!(seen[0].body, TEST_FILE_CONTENT.as_bytes());
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_follow_a_single_redirect_302() {
    let expected = r#"{"url":"https://example.com/media/456","direct_path":"/media/456"}"#;
    let server = start_server(
        Arc::new(move |url, port| match url {
            "/upload" => redirect(302, format!("http://localhost:{port}/final")),
            _ => json(expected),
        }),
        |u| u == "/final",
    );
    let file = create_temp_file(TEST_FILE_CONTENT);
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &[OCTET])).unwrap();
    assert_eq!(result, Some(Json::parse(expected).unwrap()));
    assert_eq!(wait_for(&server, 2).len(), 2);
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_follow_multiple_redirects_301_302_200() {
    let expected = r#"{"url":"https://example.com/media/789","direct_path":"/media/789"}"#;
    let server = start_server(
        Arc::new(move |url, port| match url {
            "/upload" => redirect(301, format!("http://localhost:{port}/redirect1")),
            "/redirect1" => redirect(302, format!("http://localhost:{port}/redirect2")),
            "/redirect2" => redirect(307, format!("http://localhost:{port}/final")),
            _ => json(expected),
        }),
        |u| u == "/final",
    );
    let file = create_temp_file(TEST_FILE_CONTENT);
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &[OCTET])).unwrap();
    assert_eq!(result, Some(Json::parse(expected).unwrap()));
    assert_eq!(wait_for(&server, 4).len(), 4);
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_throw_error_on_too_many_redirects_more_than_5() {
    let server = start_server(
        Arc::new(|url, port| {
            let current: u32 = url.trim_start_matches("/redirect").parse().unwrap_or(0);
            redirect(302, format!("http://localhost:{port}/redirect{}", current + 1))
        }),
        |_| false,
    );
    let file = create_temp_file(TEST_FILE_CONTENT);
    let err = upload_with_node_http(&params(server.port, "/redirect0", &file, &[OCTET])).unwrap_err();
    assert!(err.message.contains("Too many redirects"), "{}", err.message);
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_return_undefined_for_non_json_response() {
    let server = start_server(Arc::new(|_, _| Answer(200, vec![("Content-Type".to_string(), "text/html".to_string())], b"<html>Not JSON</html>".to_vec())), |_| true);
    let file = create_temp_file(TEST_FILE_CONTENT);
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &[OCTET])).unwrap();
    assert_eq!(result, None);
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_handle_relative_redirect_urls() {
    let expected = r#"{"url":"https://example.com/media/rel","direct_path":"/media/rel"}"#;
    let server = start_server(
        Arc::new(move |url, _| match url {
            "/upload" => redirect(302, "/final".to_string()),
            _ => json(expected),
        }),
        |u| u == "/final",
    );
    let file = create_temp_file(TEST_FILE_CONTENT);
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &[OCTET])).unwrap();
    assert_eq!(result, Some(Json::parse(expected).unwrap()));
    assert_eq!(wait_for(&server, 2).len(), 2);
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_preserve_headers_on_redirect() {
    let expected = r#"{"success":true}"#;
    let server = start_server(
        Arc::new(move |url, port| match url {
            "/upload" => redirect(302, format!("http://localhost:{port}/final")),
            _ => json(expected),
        }),
        |u| u == "/final",
    );
    let file = create_temp_file(TEST_FILE_CONTENT);
    let headers = [OCTET, ("X-Custom-Header", "test-value"), ("Authorization", "Bearer token123")];
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &headers)).unwrap();
    assert_eq!(result, Some(Json::parse(expected).unwrap()));
    let all = wait_for(&server, 2);
    let captured = seen_on(&all, "/final");
    assert_eq!(captured.header("x-custom-header"), Some("test-value"));
    assert_eq!(captured.header("authorization"), Some("Bearer token123"));
    cleanup(&file);
}
#[test]
fn t_uploadwithnodehttp_should_re_stream_file_content_on_redirect() {
    let expected = r#"{"success":true}"#;
    let server = start_server(
        Arc::new(move |url, port| match url {
            "/upload" => redirect(302, format!("http://localhost:{port}/final")),
            _ => json(expected),
        }),
        |_| true,
    );
    let file = create_temp_file(TEST_FILE_CONTENT);
    let result = upload_with_node_http(&params(server.port, "/upload", &file, &[OCTET])).unwrap();
    assert_eq!(result, Some(Json::parse(expected).unwrap()));
    let all = wait_for(&server, 2);
    assert_eq!(seen_on(&all, "/final").body, TEST_FILE_CONTENT.as_bytes());
    cleanup(&file);
}

#[derive(Default)]
struct RecordingClient {
    posts: Mutex<Vec<(String, Vec<(String, String)>, Vec<u8>)>>,
}
impl HttpClient for RecordingClient {
    fn get(&self, _url: &str, _headers: &[(String, String)]) -> Result<HttpResponse> {
        panic!("the upload must not use GET");
    }
    fn post_file(&self, url: &str, file_path: &str, headers: &[(String, String)], _timeout_ms: Option<u64>) -> Result<HttpResponse> {
        self.posts.lock().unwrap().push((url.to_string(), headers.to_vec(), std::fs::read(file_path).unwrap()));
        Ok(HttpResponse { status: 200, status_text: "OK".to_string(), body: br#"{"url":"https://example.com/media","direct_path":"/media"}"#.to_vec() })
    }
}
#[test]
fn t_getwauploadtoserver_does_not_pass_a_generic_https_agent_as_a_fetch_dispatcher() {
    // adapted: upstream mocks `fetch` and reads its `dispatcher` option. Here the client in `options` is the fetch
    // mock, and its `post_file` has no agent argument, so a generic agent in the config cannot reach the request.
    // The check is that the upload works with such an agent set, and that the result and the request are right.
    let file = create_temp_file("fetch upload content");
    let client = Arc::new(RecordingClient::default());
    let media_conn = MediaConnInfo { auth: "auth-token".to_string(), ttl: 60, hosts: vec![MediaConnHost { hostname: "upload.example.com".to_string(), max_content_length_bytes: 1024 }], fetch_date_ms: 0 };
    let mut config = default_connection_config();
    config.custom_upload_hosts = vec![];
    config.fetch_agent = Some(Arc::new("a generic https Agent"));
    config.options = RequestInit { headers: vec![], client: Some(client.clone()) };
    let upload = get_wa_upload_to_server(&config, Arc::new(move |_| Ok(media_conn.clone())));
    let result = upload(&file, &MediaUploadOpts { file_enc_sha256_b64: "abc123".to_string(), media_type: MediaType::Image, timeout_ms: None }).unwrap();
    assert_eq!(result, MediaUploadResult { media_url: "https://example.com/media".to_string(), direct_path: "/media".to_string(), meta_hmac: None, fbid: None, ts: None });
    let posts = client.posts.lock().unwrap();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].0, "https://upload.example.com/mms/image/abc123?auth=auth-token&token=abc123");
    assert_eq!(posts[0].2, b"fetch upload content");
    cleanup(&file);
}

fn buffer(data: &[u8]) -> WAMediaUpload {
    WAMediaUpload::Buffer(Bytes::copy_from(data))
}
fn cleanup_files(files: &[Option<&str>]) {
    for f in files.iter().flatten() {
        cleanup(f);
    }
}
struct ChunkStream(Mutex<VecDeque<Vec<u8>>>);
impl MediaStream for ChunkStream {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut q = self.0.lock().unwrap();
        let Some(front) = q.front_mut() else { return Ok(0) };
        let n = buf.len().min(front.len());
        buf[..n].copy_from_slice(&front[..n]);
        front.drain(..n);
        if front.is_empty() {
            q.pop_front();
        }
        Ok(n)
    }
}
#[test]
fn t_encryptedstream_should_encrypt_a_buffer_and_return_valid_result_without_hanging() {
    let test_data = b"Hello, this is test content for encryption!";
    let result = encrypted_stream(&buffer(test_data), MediaType::Image, &EncryptedStreamOptions::default()).unwrap();
    assert_eq!(result.media_key.len(), 32);
    assert!(!result.enc_file_path.is_empty());
    assert_eq!(result.file_sha256.len(), 32);
    assert_eq!(result.file_enc_sha256.len(), 32);
    assert_eq!(result.mac.len(), 10);
    assert_eq!(result.file_length, test_data.len() as u64);
    assert!(std::path::Path::new(&result.enc_file_path).exists());
    cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
}
#[test]
fn t_encryptedstream_should_encrypt_a_stream_and_complete_without_race_condition() {
    let chunks = ["chunk1", "chunk2", "chunk3", "chunk4", "chunk5"];
    let stream = ChunkStream(Mutex::new(chunks.iter().map(|c| c.as_bytes().to_vec()).collect()));
    let result = encrypted_stream(&WAMediaUpload::Stream(Arc::new(stream)), MediaType::Document, &EncryptedStreamOptions::default()).unwrap();
    assert_eq!(result.media_key.len(), 32);
    assert!(!result.enc_file_path.is_empty());
    assert_eq!(result.file_length, chunks.concat().len() as u64);
    cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
}
#[test]
fn t_encryptedstream_should_save_original_file_when_saveoriginalfileifrequired_is_true() {
    let test_data = b"Original file content to save";
    let options = EncryptedStreamOptions { save_original_file_if_required: true, ..EncryptedStreamOptions::default() };
    let result = encrypted_stream(&buffer(test_data), MediaType::Audio, &options).unwrap();
    let original = result.original_file_path.as_deref().unwrap();
    assert_eq!(std::fs::read(original).unwrap(), test_data);
    cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
}
#[test]
fn t_encryptedstream_should_complete_encryption_for_various_media_types() {
    for media_type in [MediaType::Image, MediaType::Video, MediaType::Audio, MediaType::Document, MediaType::Sticker] {
        let result = encrypted_stream(&buffer(b"Test data for different media types"), media_type, &EncryptedStreamOptions::default()).unwrap();
        assert_eq!(result.media_key.len(), 32);
        assert!(!result.enc_file_path.is_empty());
        cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
    }
}
#[test]
fn t_encryptedstream_should_handle_empty_buffer_without_hanging() {
    let result = encrypted_stream(&buffer(b""), MediaType::Image, &EncryptedStreamOptions::default()).unwrap();
    assert_eq!(result.file_length, 0);
    assert!(!result.enc_file_path.is_empty());
    cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
}
#[test]
fn t_encryptedstream_should_handle_small_content_that_finishes_quickly() {
    let result = encrypted_stream(&buffer(b"x"), MediaType::Image, &EncryptedStreamOptions::default()).unwrap();
    assert_eq!(result.file_length, 1);
    cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
}
#[test]
fn t_encryptedstream_should_complete_multiple_concurrent_encryptions_without_deadlock() {
    let handles: Vec<_> = (0..5).map(|_| std::thread::spawn(|| encrypted_stream(&buffer(b"Concurrent encryption test"), MediaType::Image, &EncryptedStreamOptions::default()))).collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.len(), 5);
    for result in results {
        let result = result.unwrap();
        assert_eq!(result.media_key.len(), 32);
        cleanup_files(&[Some(&result.enc_file_path), result.original_file_path.as_deref()]);
    }
}
