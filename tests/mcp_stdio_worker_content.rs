#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOURCE: &str =
    "export default { fetch() { return new Response('source-private-sentinel'); } };\n";
const TOKEN: &str = "synthetic-authorization-sentinel";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct PrivateRoot(PathBuf);
impl PrivateRoot {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from("/tmp").join(format!(
            "content-read-fixture-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn count(&self) -> usize {
        fs::read_dir(&self.0).unwrap().count()
    }
}
impl Drop for PrivateRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Process {
    child: Child,
    input: ChildStdin,
    responses: mpsc::Receiver<Value>,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    readers: Vec<thread::JoinHandle<()>>,
}
impl Process {
    fn new(root: Option<&PrivateRoot>, origin: &str, timeout: u64, fixture: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cloudflare-mcp"));
        command
            .arg("--stdio")
            .env_clear()
            .env("CLOUDFLARE_MCP_AUTH_MODE", "off")
            .env("CLOUDFLARE_MCP_API_TOKEN", TOKEN)
            .env("CLOUDFLARE_MCP_API_BASE_URL", origin)
            .env("CLOUDFLARE_MCP_API_TIMEOUT_MS", timeout.to_string())
            .env("CLOUDFLARE_MCP_API_MAX_RETRIES", "4")
            .env("CLOUDFLARE_MCP_API_PARITY_ENABLED", "true")
            .env(
                "CLOUDFLARE_MCP_WORKER_CONTENT_FIXTURE_HTTP",
                if fixture { "true" } else { "false" },
            )
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(root) = root {
            command.env("CLOUDFLARE_MCP_WORKER_CONTENT_ROOT", &root.0);
        }
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let errors = child.stderr.take().unwrap();
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        let (tx, responses) = mpsc::channel();
        let capture = stdout.clone();
        let out_reader = thread::spawn(move || {
            for line in BufReader::new(output).lines().map_while(Result::ok) {
                capture.lock().unwrap().push_str(&line);
                if let Ok(value) = serde_json::from_str(&line) {
                    let _ = tx.send(value);
                }
            }
        });
        let capture = stderr.clone();
        let err_reader = thread::spawn(move || {
            let mut bytes = String::new();
            BufReader::new(errors).read_to_string(&mut bytes).unwrap();
            *capture.lock().unwrap() = bytes;
        });
        let mut process = Self {
            child,
            input,
            responses,
            stdout,
            stderr,
            readers: vec![out_reader, err_reader],
        };
        process.request(
            1,
            "initialize",
            json!({"protocolVersion":"2025-11-25", "capabilities":{},
            "clientInfo":{"name":"synthetic-content-reader", "version":"1"}}),
        );
        process.send(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
        process
    }
    fn send(&mut self, value: Value) {
        writeln!(self.input, "{value}").unwrap();
        self.input.flush().unwrap();
    }
    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}));
        loop {
            let value = self
                .responses
                .recv_timeout(Duration::from_secs(30))
                .unwrap();
            if value["id"] == id {
                return value;
            }
        }
    }
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request(2, "tools/call", json!({"name":name, "arguments":arguments}));
        response["result"]["structuredContent"].clone()
    }
    fn finish(&mut self, root: &PrivateRoot) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
        for capture in [&self.stdout, &self.stderr] {
            let output = capture.lock().unwrap();
            for secret in [
                SOURCE,
                "source-private-sentinel",
                TOKEN,
                root.0.to_str().unwrap(),
            ] {
                assert!(
                    !output.contains(secret),
                    "sensitive content escaped MCP process"
                );
            }
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn args(cap: usize) -> Value {
    json!({"account_id":"account-a", "script_name":"worker-a",
    "acknowledge_private_source":true, "max_bytes":cap})
}

fn server(response: Vec<u8>, delay: Duration) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}/client/v4", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 16384);
        }
        thread::sleep(delay);
        let _ = socket.write_all(&response);
        String::from_utf8(request).unwrap()
    });
    (origin, handle)
}
fn response(content_type: &str, bytes: &[u8]) -> Vec<u8> {
    let mut output = format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).into_bytes();
    output.extend_from_slice(bytes);
    output
}
fn assert_request(request: &str) {
    let lines: Vec<_> = request.lines().collect();
    assert_eq!(
        lines[0],
        "GET /client/v4/accounts/account-a/workers/scripts/worker-a/content/v2 HTTP/1.1"
    );
    let auth: Vec<_> = lines
        .iter()
        .copied()
        .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        .collect();
    assert_eq!(auth, vec![format!("authorization: Bearer {TOKEN}")]);
    assert!(!request.contains("cookie:"));
    assert!(!request.contains("x-cloudflare-api-token:"));
}
fn expected_error(code: &str) -> Value {
    json!({"ok":false, "error":{"code":code,
        "message":"Worker content read did not produce a verified private artifact",
        "hint":"Inspect the content-free error code; do not infer source or active-version equivalence.",
        "retryable":false, "status":null}})
}

#[test]
fn private_content_success_is_complete_exact_and_never_active_version_proof() {
    for (content_type, bytes, format, count) in [
        ("application/javascript", SOURCE.as_bytes().to_vec(), "javascript_text", 1),
        ("Application/JavaScript; CHARSET=\"UTF-8\"", SOURCE.as_bytes().to_vec(), "javascript_text", 1),
        ("multipart/form-data; charset=\"UTF-8\"; BOUNDARY=\"fixture\"", format!("--fixture\r\nContent-Disposition: FORM-DATA; NAME=main.js; FILENAME=\"main.js\"\r\nContent-Type: application/javascript\r\n\r\n{SOURCE}\r\n--fixture--\r\n").into_bytes(), "multipart_form_data", 1),
        ("multipart/form-data; boundary=fixture", format!("--fixture\r\nContent-Disposition: form-data; name=\"main.js\"; filename=\"main.js\"\r\nContent-Type: application/javascript\r\n\r\n{SOURCE}\r\n--fixture\r\nContent-Disposition: form-data; name=\"data.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\0\u{1}\r\n--fixture--\r\n").into_bytes(), "multipart_form_data", 2),
    ] {
        let root = PrivateRoot::new();
        let (origin, handle) = server(response(content_type, &bytes), Duration::ZERO);
        let mut process = Process::new(Some(&root), &origin, 5000, true);
        let listed = process.request(3, "tools/list", json!({}));
        assert!(listed["result"]["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "workers_get_script_content"));
        let result = process.call("workers_get_script_content", args(bytes.len()));
        let name = result["artifact"]["name"].as_str().unwrap();
        assert!(name.starts_with("worker-content-") && !name.contains('/'));
        assert_eq!(result, json!({"ok":true, "operation":"workers_get_script_content", "read_only":true,
            "provenance":"synthetic_http_fixture", "endpoint":"/accounts/{account_id}/workers/scripts/{script_name}/content/v2",
            "target_sha256":hash(b"account-a\0worker-a"), "http_status":200, "body_complete":true,
            "format":format, "part_count":count,
            "artifact":{"name":name, "size_bytes":bytes.len(), "sha256":hash(&bytes),
                "custody":"verified_private_file", "representation":"exact_response_body"},
            "source_generation":"unversioned_endpoint_content", "active_version_equivalence":"unverified",
            "syntax_validated":false, "max_bytes":bytes.len(), "deadline_ms":5000}));
        // Observe the actual private namespace, not an output-directed file path.
        let mut entries = fs::read_dir(&root.0).unwrap();
        let entry = entries.next().unwrap().unwrap();
        assert!(entries.next().is_none());
        assert_eq!(entry.file_name().to_str().unwrap(), name);
        let directory = fs::File::open(&root.0).unwrap();
        let basename = CString::new(entry.file_name().as_bytes()).unwrap();
        // SAFETY: the directory and C string remain live; openat returns a new
        // owned descriptor. A single basename and NOFOLLOW prevent redirection.
        let descriptor = unsafe {
            libc::openat(directory.as_raw_fd(), basename.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        };
        assert!(descriptor >= 0, "private artifact open failed");
        // SAFETY: openat succeeded and this is the descriptor's only owner.
        let artifact = unsafe { fs::File::from_raw_fd(descriptor) };
        let metadata = artifact.metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let mut retained = Vec::new();
        artifact.take(bytes.len() as u64 + 1).read_to_end(&mut retained).unwrap();
        assert_eq!(retained, bytes);
        assert_eq!(root.count(), 1);
        assert_request(&handle.join().unwrap());
        process.finish(&root);
    }
}

#[test]
fn content_http_and_format_failures_leave_no_artifact_or_source_output() {
    let mut chunked = b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    chunked.extend_from_slice(format!("{:x}\r\n{SOURCE}\r\n0\r\n\r\n", SOURCE.len()).as_bytes());
    let cases = vec![
        (b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid/source-private-sentinel\r\nContent-Length: 0\r\n\r\n".to_vec(), 1024, Duration::ZERO, "workers.content_redirect_denied"),
        (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 23\r\n\r\nsource-private-sentinel".to_vec(), 1024, Duration::ZERO, "workers.content_permission_denied"),
        (response("application/javascript", SOURCE.as_bytes()), SOURCE.len()-1, Duration::ZERO, "workers.content_over_cap"),
        (chunked, SOURCE.len()-1, Duration::ZERO, "workers.content_over_cap"),
        (b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 200\r\nConnection: close\r\n\r\nsource-private-sentinel".to_vec(), 1024, Duration::ZERO, "workers.content_incomplete"),
        (response("application/javascript", SOURCE.as_bytes()), 1024, Duration::from_secs(1), "workers.content_timeout"),
        (response("multipart/form-data; boundary=fixture", b"--fixture\r\nContent-Disposition: form-data; name=\"main.js\"\r\n\r\nsource-private-sentinel"), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("application/json", b"{\"source\":\"source-private-sentinel\"}"), 1024, Duration::ZERO, "workers.content_format_unsupported"),
        (response("application/javascript", &[255]), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("application/javascript", b""), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("application/javascript; charset=\"UTF-8", SOURCE.as_bytes()), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("multipart/form-data; boundary=fixture; BOUNDARY=fixture", SOURCE.as_bytes()), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("multipart/form-data; boundary=fixture", b"--fixture\r\nContent-Disposition: form-data; name=main.js; NAME=other.js\r\n\r\nsource-private-sentinel\r\n--fixture--\r\n"), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("multipart/form-data; boundary=fixture", b"--fixture\r\nContent-Disposition: form-data; filename=\"main.js\"\r\n\r\nsource-private-sentinel\r\n--fixture--\r\n"), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (response("multipart/form-data; boundary=fixture", b"--fixture\r\nContent-Disposition: form-data; name=\"unterminated\r\n\r\nsource-private-sentinel\r\n--fixture--\r\n"), 1024, Duration::ZERO, "workers.content_format_invalid"),
        (b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".to_vec(), 1024, Duration::ZERO, "workers.content_encoding_unsupported"),
    ];
    for (response, cap, delay, code) in cases {
        let root = PrivateRoot::new();
        let (origin, handle) = server(response, delay);
        let mut process = Process::new(
            Some(&root),
            &origin,
            if delay.is_zero() { 5000 } else { 100 },
            true,
        );
        assert_eq!(
            process.call("workers_get_script_content", args(cap)),
            expected_error(code)
        );
        assert_request(&handle.join().unwrap());
        assert_eq!(root.count(), 0);
        process.finish(&root);
    }
}

#[test]
fn content_admission_and_generic_json_contracts_are_preserved() {
    let root = PrivateRoot::new();
    let mut process = Process::new(Some(&root), "http://127.0.0.1:1/client/v4", 5000, false);
    assert_eq!(
        process.call("workers_get_script_content", args(1024)),
        expected_error("workers.content_origin_denied")
    );
    process.finish(&root);
    let mut process = Process::new(None, "https://api.cloudflare.com/client/v4", 5000, false);
    assert_eq!(
        process.call("workers_get_script_content", args(1024)),
        expected_error("workers.content_root_unconfigured")
    );
    let mut denied = args(1024);
    denied["acknowledge_private_source"] = json!(false);
    assert_eq!(
        process.call("workers_get_script_content", denied),
        expected_error("workers.content_acknowledgement_required")
    );
    let mut invalid = args(1024);
    invalid["script_name"] = json!("../worker-a");
    assert_eq!(
        process.call("workers_get_script_content", invalid),
        expected_error("workers.content_target_invalid")
    );
    assert_eq!(
        process.call("workers_get_script_content", args(0)),
        expected_error("workers.content_limit_invalid")
    );
    let prepared = process.call("api_prepare_call", json!({"operation_id":"worker-script-get-content", "path_params":{"account_id":"account-a", "script_name":"worker-a"}}));
    assert_eq!(
        prepared,
        json!({"ok":true, "operation":"api_prepare_call", "status":"sensitive_read_requires_acknowledgement",
        "executor":"workers_get_script_content", "call":{"tool":"workers_get_script_content", "arguments":{
            "account_id":"account-a", "script_name":"worker-a", "acknowledge_private_source":false, "max_bytes":1048576}},
        "requires_configured_private_root":true, "active_version_equivalence":"unverified"})
    );
    let generic = process.call("api_read", json!({"operation_id":"worker-script-get-content", "path_params":{"account_id":"account-a", "script_name":"worker-a"}}));
    assert_eq!(
        generic["error"]["code"],
        "workers.content_sensitive_route_required"
    );
    process.finish(&root);

    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    let mut process = Process::new(Some(&root), "http://127.0.0.1:1/client/v4", 5000, true);
    assert_eq!(
        process.call("workers_get_script_content", args(1024)),
        expected_error("workers.content_custody_invalid")
    );
    process.finish(&root);
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();

    let body = br#"{"success":true,"errors":[],"messages":[],"result":[{"id":"account-a"}]}"#;
    let (origin, handle) = server(response("application/json", body), Duration::ZERO);
    let mut process = Process::new(Some(&root), &origin, 5000, true);
    let generic = process.call(
        "api_read",
        json!({"operation_id":"accounts-list-accounts", "path_params":{}}),
    );
    let mut expected = json!({"ok":true, "operation":"api_read", "api_operation":{
        "operation_id":"accounts-list-accounts", "method":"GET", "path":"/accounts", "rendered_path":"/accounts",
        "tag":"Accounts", "preferred_tool":null}, "result":[{"id":"account-a"}]});
    let size = serde_json::to_vec(&expected).unwrap().len();
    expected["response_size"] = json!({"bytes":size, "truncated":false});
    assert_eq!(generic, expected);
    assert!(
        handle
            .join()
            .unwrap()
            .starts_with("GET /client/v4/accounts ")
    );
    assert_eq!(root.count(), 0);
    process.finish(&root);
}
