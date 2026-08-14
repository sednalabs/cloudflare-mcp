use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn expected_d1_reconciliation_semantic_error(code: &str, message: &str, hint: &str) -> Value {
    json!({
        "ok": false,
        "operation": "d1_reconcile_migration_manifest",
        "dry_run": true,
        "read_only": true,
        "status": "reconciliation_required",
        "outcome": "unknown",
        "capability_state": "contradictory",
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "not_acquired",
        "lease_retained": null,
        "custody_status": "not_inspected",
        "query_sha256": null,
        "response_evidence": [],
        "provider_calls": 0,
        "provider_read_lifecycle": [],
        "provider_mutations": 0,
        "local_namespace_mutations": 0,
        "error": {
            "code": code,
            "message": message,
            "hint": hint,
        },
    })
}

fn fixture_material(label: &str) -> String {
    let mut value = String::from("fixture-");
    value.push_str(label);
    value.push_str("-value");
    value
}

fn manifest_target_path(lease_root: &Path) -> PathBuf {
    lease_root.join(format!(
        "d1-migration-target-{}",
        sha256_hex("acct-1\0db-1")
    ))
}

fn assert_private_regular_active_lease(lease_root: &Path) -> PathBuf {
    let target = manifest_target_path(lease_root);
    let target_metadata = fs::symlink_metadata(&target).expect("manifest target metadata");
    assert!(target_metadata.is_dir(), "manifest target is a directory");
    assert!(
        !target_metadata.file_type().is_symlink(),
        "manifest target must not be a symlink"
    );
    let active = target.join("active.lease.json");
    let metadata = fs::symlink_metadata(&active).expect("retained active lease metadata");
    assert!(metadata.is_file(), "retained active lease is regular");
    assert!(
        !metadata.file_type().is_symlink(),
        "retained active lease must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert!(metadata.len() > 0, "retained active lease has payload");
    active
}

fn retired_manifest_entries(target: &Path) -> Vec<PathBuf> {
    fs::read_dir(target)
        .expect("read permanent target custody")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("retired.") {
                return None;
            }
            let metadata = fs::symlink_metadata(&path).expect("retired evidence metadata");
            assert!(metadata.is_file(), "retired evidence is regular");
            assert!(
                !metadata.file_type().is_symlink(),
                "retired evidence must not be a symlink"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }
            Some(path)
        })
        .collect()
}

fn assert_released_manifest_target_custody(lease_root: &Path) {
    let target = manifest_target_path(lease_root);
    let target_metadata = fs::symlink_metadata(&target).expect("manifest target metadata");
    assert!(target_metadata.is_dir(), "manifest target is a directory");
    assert!(
        !target_metadata.file_type().is_symlink(),
        "manifest target must not be a symlink"
    );
    let guard_metadata =
        fs::symlink_metadata(target.join("guard.lock")).expect("permanent guard metadata");
    assert!(
        guard_metadata.is_file() && !guard_metadata.file_type().is_symlink(),
        "permanent guard remains"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(guard_metadata.permissions().mode() & 0o777, 0o600);
    }
    let active = target.join("active.lease.json");
    assert!(
        matches!(fs::symlink_metadata(&active), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "normal completion has no active custody evidence"
    );
    let retired = retired_manifest_entries(&target);
    assert!(
        retired.len() == 1,
        "normal completion retains a terminal retirement record"
    );
}

fn create_retained_reconciliation_fixture(
    lease_root: &Path,
    manifest: &Value,
) -> (String, String, String) {
    #[derive(Serialize)]
    struct ApprovedPlan<'a> {
        version: u8,
        operation: &'static str,
        account_id: &'static str,
        database_id: &'static str,
        migration_family: &'static str,
        migrations_table: &'static str,
        manifest: &'a Value,
        ledger: Vec<Value>,
    }

    let target = manifest_target_path(lease_root);
    fs::create_dir(&target).expect("create retained target");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("make retained target private");
    }
    let guard = target.join("guard.lock");
    fs::write(&guard, []).expect("create retained guard");
    let nonce = "b".repeat(64);
    let manifest_summary = Value::Array(
        manifest
            .as_array()
            .expect("manifest array")
            .iter()
            .map(|entry| {
                json!({
                    "name": entry["name"],
                    "size_bytes": entry["size_bytes"],
                    "sql_sha256": entry["sql_sha256"],
                })
            })
            .collect(),
    );
    let plan = ApprovedPlan {
        version: 1,
        operation: "d1_apply_migration_manifest",
        account_id: "acct-1",
        database_id: "db-1",
        migration_family: "newsletter-core",
        migrations_table: "d1_migrations",
        manifest: &manifest_summary,
        ledger: Vec::new(),
    };
    let approved_plan_sha256 = {
        let bytes = serde_json::to_vec(&plan).expect("serialize approved plan");
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    };
    let payload = json!({
        "version": 2,
        "target_key_sha256": sha256_hex("acct-1\0db-1"),
        "nonce": nonce,
        "approved_plan_sha256": approved_plan_sha256,
        "migration_family": "newsletter-core",
        "created_at_unix_ms": 1_800_000_000_000_u64,
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize retained payload");
    let payload_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        format!("{:x}", hasher.finalize())
    };
    let active = target.join("active.lease.json");
    fs::write(&active, payload_bytes).expect("write retained payload");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).expect("make guard private");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600))
            .expect("make active evidence private");
    }
    (approved_plan_sha256, nonce, payload_sha256)
}

fn assert_fresh_process_blocked_without_provider_request(
    env: Vec<(&'static str, String)>,
    manifest: &Value,
    plan: &str,
    requests: &Arc<Mutex<Vec<Value>>>,
    expected_requests: usize,
    label: &str,
) {
    let mut contender = McpStdioProcess::start_with_env(env);
    let response = contender.call_tool(
        900,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "fresh-caller",
            "manifest": manifest.clone(),
            "approved_plan_sha256": plan,
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{label}: {content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_target_lease_held"),
        "{label}: fresh caller must stop at retained active evidence"
    );
    assert_eq!(
        requests.lock().expect("request log").len(),
        expected_requests,
        "{label}: fresh caller must not issue another provider request"
    );
    drop(contender);
}

struct McpStdioProcess {
    child: Child,
    stdin: ChildStdin,
    responses: mpsc::Receiver<Value>,
}

impl McpStdioProcess {
    fn start() -> Self {
        Self::start_with_env(Vec::new())
    }

    fn start_with_env(envs: Vec<(&'static str, String)>) -> Self {
        let exe = env!("CARGO_BIN_EXE_cloudflare-mcp");
        let mut command = Command::new(exe);
        command
            .arg("--stdio")
            .env_remove("CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT")
            .env("RUST_LOG", "off")
            .env("CLOUDFLARE_MCP_AUTH_MODE", "off")
            .env("CLOUDFLARE_API_TOKEN", fixture_material("cf-api"))
            .env("CLOUDFLARE_MCP_API_TOKEN", fixture_material("cf-mcp-api"))
            .env("CLOUDFLARE_ACCOUNT_ID", "acct-1")
            .env("CLOUDFLARE_ZONE_ID", "zone-1")
            .env("CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID", "acct-1")
            .env("CLOUDFLARE_MCP_DEFAULT_ZONE_ID", "zone-1")
            .env(
                "CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES",
                "https://staff.example.com/api/agent/",
            )
            .env("AGENT_API_TOKEN", fixture_material("agent"))
            .env("CLOUDFLARE_MCP_ACCESS_CLIENT_ID", "probe-access-id")
            .env(
                "CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET",
                fixture_material("access-material"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = command.spawn().expect("spawn cloudflare-mcp stdio process");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let stderr = child.stderr.take().expect("child stderr");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    let _ = tx.send(value);
                }
            }
        });
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("cloudflare-mcp stderr: {line}");
            }
        });

        let mut process = Self {
            child,
            stdin,
            responses: rx,
        };
        process.send(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "cloudflare-mcp-stdio-smoke", "version": "0.0.0"}
            }
        }));
        let init = process.response(1);
        assert_eq!(init["result"]["protocolVersion"], json!("2025-11-25"));
        process.send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        }));
        process
    }

    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn send(&mut self, value: Value) {
        let line = serde_json::to_string(&value).expect("serialize JSON-RPC request");
        writeln!(self.stdin, "{line}").expect("write JSON-RPC request");
        self.stdin.flush().expect("flush JSON-RPC request");
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }));
        self.response(id)
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }));
        self.response(id)
    }

    fn response(&self, id: u64) -> Value {
        let deadline = Duration::from_secs(10);
        loop {
            let value = self
                .responses
                .recv_timeout(deadline)
                .unwrap_or_else(|_| panic!("timed out waiting for JSON-RPC response id {id}"));
            if value.get("id") == Some(&json!(id)) {
                return value;
            }
        }
    }
}

impl Drop for McpStdioProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn structured_content(response: &Value) -> &Value {
    response
        .get("result")
        .and_then(|result| result.get("structuredContent"))
        .unwrap_or_else(|| panic!("missing structuredContent in response: {response}"))
}

fn text_resource_content(response: &Value) -> String {
    response["result"]["contents"]
        .as_array()
        .expect("resource contents")
        .iter()
        .filter_map(|content| content.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n")
}

fn read_http_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read request header");
        if line.is_empty() {
            break;
        }
        headers.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .or_else(|| {
            headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length:"))
        })
        .and_then(|value| value.trim().parse::<usize>().ok());
    let transfer_encoding = headers
        .lines()
        .find_map(|line| line.strip_prefix("transfer-encoding:"))
        .or_else(|| {
            headers
                .lines()
                .find_map(|line| line.strip_prefix("Transfer-Encoding:"))
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut body = Vec::new();
    if let Some(content_length) = content_length {
        body.resize(content_length, 0);
        if content_length > 0 {
            reader.read_exact(&mut body).expect("read body");
        }
    } else if transfer_encoding.contains("chunked") {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).expect("read chunk size");
            let size_text = size_line
                .trim()
                .split_once(';')
                .map(|(size, _)| size)
                .unwrap_or_else(|| size_line.trim());
            let size = usize::from_str_radix(size_text, 16).expect("parse chunk size");
            if size == 0 {
                let mut trailer = String::new();
                reader.read_line(&mut trailer).expect("read chunk trailer");
                break;
            }
            let offset = body.len();
            body.resize(offset + size, 0);
            reader
                .read_exact(&mut body[offset..])
                .expect("read chunk body");
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).expect("read chunk delimiter");
            assert_eq!(&crlf, b"\r\n");
        }
    }
    (headers, body)
}

fn spawn_fake_r2_api() -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_fake_r2_api_with_requests(2)
}

fn spawn_fake_r2_api_with_requests(expected_requests: usize) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake R2 API");
    let addr = listener.local_addr().expect("fake R2 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake R2 stream");
            let (headers, _) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(format!("{method} {path}"));
            assert_eq!(path, "/bucket-a/folder/file.csv");
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: aws4-hmac-sha256"),
                "{headers}"
            );

            let body = b"col1,col2\n1,2";
            match method.as_str() {
                "HEAD" => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: text/csv\r\ncontent-length: {}\r\netag: \"etag-1\"\r\nlast-modified: Fri, 22 May 2026 00:00:00 GMT\r\n\r\n",
                        body.len()
                    )
                    .expect("write R2 head response");
                }
                "GET" => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: text/csv\r\ncontent-length: {}\r\netag: \"etag-1\"\r\nlast-modified: Fri, 22 May 2026 00:00:00 GMT\r\n\r\n",
                        body.len()
                    )
                    .expect("write R2 get response headers");
                    stream.write_all(body).expect("write R2 body");
                }
                _ => panic!("unexpected R2 method: {method}"),
            }
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_r2_binary_api() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake binary R2 API");
    let addr = listener.local_addr().expect("fake binary R2 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut stream = stream.expect("fake binary R2 stream");
            let (headers, _) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(format!("{method} {path}"));
            assert_eq!(path, "/bucket-a/bin/blob.dat");
            let body = [0u8, 159, 146, 150, 255, 1, 2, 3];
            match method.as_str() {
                "HEAD" => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\netag: \"etag-bin\"\r\n\r\n",
                        body.len()
                    )
                    .expect("write binary R2 head response");
                }
                "GET" => {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\netag: \"etag-bin\"\r\n\r\n",
                        body.len()
                    )
                    .expect("write binary R2 get response headers");
                    stream.write_all(&body).expect("write binary R2 body");
                }
                _ => panic!("unexpected binary R2 method: {method}"),
            }
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_d1_migrations_api(
    expected_requests: usize,
    ledger_fails: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake D1 migrations API");
    let addr = listener.local_addr().expect("fake D1 migrations addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake D1 migrations stream");
            let (headers, body) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            let body_json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            assert_eq!(method, "POST");
            assert_eq!(path, "/accounts/acct-1/d1/database/db-1/query");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let response = if sql.starts_with("CREATE TABLE IF NOT EXISTS \"d1_migrations\"") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "results": []}]
                })
            } else if sql == "SELECT * FROM \"d1_migrations\" ORDER BY id" {
                if ledger_fails {
                    json!({
                        "success": false,
                        "errors": [{"code": 7500, "message": "SQLITE_AUTH: access denied"}],
                        "messages": [],
                        "result": null
                    })
                } else {
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{
                            "success": true,
                            "results": [{"id": 1, "name": "0001_initial.sql"}],
                            "meta": {"served_by": "ledger"}
                        }]
                    })
                }
            } else if sql
                .contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0002_second.sql')")
            {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "results": [{"ok": true}]}]
                })
            } else {
                json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected SQL: {sql}")}],
                    "messages": [],
                    "result": null
                })
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_manifest_apply_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake manifest D1 API");
    let addr = listener.local_addr().expect("manifest D1 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let mut apply_seen = false;
        for stream in listener.incoming().take(6) {
            let mut stream = stream.expect("fake manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("manifest request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let ledger = if apply_seen {
                vec![
                    json!({"id": 1, "name": "0001_initial.sql"}),
                    json!({"id": 2, "name": "0002_second.sql"}),
                ]
            } else {
                vec![json!({"id": 1, "name": "0001_initial.sql"})]
            };
            let response = if sql == "SELECT * FROM \"d1_migrations\" ORDER BY id" {
                json!({"success": true, "errors": [], "messages": [], "result": [{"success": true, "results": ledger}]})
            } else if sql
                .contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0002_second.sql')")
            {
                apply_seen = true;
                json!({"success": true, "errors": [], "messages": [], "result": [{"success": true, "results": [{"ok": true}]}]})
            } else {
                panic!("unexpected manifest migration SQL: {sql}");
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write manifest headers");
            stream
                .write_all(&response)
                .expect("write manifest response");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_blocked_manifest_preflight_api() -> (
    String,
    Arc<Mutex<Vec<Value>>>,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind blocked manifest D1 API");
    let addr = listener.local_addr().expect("blocked manifest D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    thread::spawn(move || {
        for request_index in 0..2 {
            let mut stream = listener
                .accept()
                .expect("accept blocked manifest request")
                .0;
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("blocked request JSON");
            assert_eq!(
                body_json["sql"],
                json!("SELECT * FROM \"d1_migrations\" ORDER BY id")
            );
            requests_for_thread
                .lock()
                .expect("blocked request log")
                .push(body_json);
            if request_index == 1 {
                entered_tx.send(()).expect("notify held active lease");
                resume_rx.recv().expect("release blocked preflight");
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"success": true, "results": [{"id": 1, "name": "0001_initial.sql"}]}]
            }))
            .expect("serialize blocked response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write blocked response headers");
            let _ = stream.write_all(&response);
        }
    });
    (format!("http://{addr}"), requests, entered_rx, resume_tx)
}

fn spawn_fake_manifest_malformed_ledger_api(result_set: Value) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind malformed ledger D1 API");
    let addr = listener.local_addr().expect("malformed ledger D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let mut stream = stream.expect("fake malformed ledger D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("malformed ledger request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            assert_eq!(
                body_json["sql"],
                json!("SELECT * FROM \"d1_migrations\" ORDER BY id")
            );
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [result_set],
            }))
            .expect("serialize malformed ledger response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write malformed ledger headers");
            stream
                .write_all(&response)
                .expect("write malformed ledger response");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_manifest_outer_error_api(
    outer_errors: Option<Value>,
    error_on_write: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind outer-error manifest D1 API");
    let addr = listener
        .local_addr()
        .expect("outer-error manifest D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let expected_requests = if error_on_write { 6 } else { 2 };
        let mut ledger_reads = 0usize;
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake outer-error manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("outer-error manifest request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let is_write = sql.contains("INSERT INTO \"d1_migrations\"");
            let has_outer_error = if error_on_write {
                is_write
            } else {
                assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
                ledger_reads += 1;
                ledger_reads == 2
            };
            let result = if is_write {
                vec![json!({"success": true, "errors": [], "results": [{"ok": true}]})]
            } else {
                vec![json!({
                    "success": true,
                    "errors": [],
                    "results": [{"id": 1, "name": "0001_initial.sql"}],
                })]
            };
            let mut envelope = serde_json::Map::new();
            envelope.insert("success".to_string(), json!(true));
            if !has_outer_error || outer_errors.is_some() {
                envelope.insert(
                    "errors".to_string(),
                    if has_outer_error {
                        outer_errors.clone().expect("outer error field present")
                    } else {
                        json!([])
                    },
                );
            }
            envelope.insert("messages".to_string(), json!([]));
            envelope.insert("result".to_string(), Value::Array(result));
            let response = serde_json::to_vec(&Value::Object(envelope))
                .expect("serialize outer-error manifest response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write outer-error manifest headers");
            stream
                .write_all(&response)
                .expect("write outer-error manifest response");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_manifest_ambiguous_api(
    ledger_names_commit_after_ambiguous_response: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ambiguous manifest D1 API");
    let addr = listener.local_addr().expect("ambiguous manifest D1 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let mut apply_seen = false;
        for stream in listener.incoming().take(6) {
            let mut stream = stream.expect("fake ambiguous manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("ambiguous request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            if sql.contains("INSERT INTO \"d1_migrations\"") {
                apply_seen = ledger_names_commit_after_ambiguous_response;
                write!(stream, "HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-length: 0\r\n\r\n").expect("write ambiguous response");
                continue;
            }
            assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
            let ledger = if apply_seen {
                vec![
                    json!({"id": 1, "name": "0001_initial.sql"}),
                    json!({"id": 2, "name": "0002_second.sql"}),
                ]
            } else {
                vec![json!({"id": 1, "name": "0001_initial.sql"})]
            };
            let response = serde_json::to_vec(&json!({
                "success": true, "errors": [], "messages": [],
                "result": [{"success": true, "results": ledger}]
            }))
            .expect("serialize response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write headers");
            stream.write_all(&response).expect("write response");
        }
    });
    (format!("http://{addr}"), requests)
}

#[derive(Clone)]
enum ReconciliationFault {
    None,
    WrongStatementMarker,
    MalformedReadOnlyMetadata,
    Redirect,
    MalformedUtf8HttpStatus(u16),
    MalformedJsonStatus(u16),
    ZeroByteTruncatedHttpStatus(u16),
    TruncatedHttpStatus(u16),
    OversizedResponse,
    HttpStatus(u16),
    HttpStatusCustodyDrift(u16, PathBuf),
    OversizedHttpStatus(u16),
    CustodyDrift(PathBuf),
    SecondBatchCustodyDrift(PathBuf),
    PrimaryMetaMissing,
    PrimaryMarkerMissing,
    PrimaryMarkerFalse,
    PrimaryMarkerNull,
    PrimaryMarkerWrongType,
    MixedPrimaryMarkers,
    SecondBatchPrimaryFalse,
    SecondBatchHttpStatus(u16),
    SecondBatchTransportFailure(Option<PathBuf>),
    DuplicateOuterSuccess(bool, Arc<Mutex<Vec<u8>>>),
    DuplicateNestedRowId(bool, Arc<Mutex<Vec<u8>>>),
    LedgerNotManifestPrefix,
    UnstableSecondBatch,
}

fn reconciliation_http_error_response(status: u16) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "success": false,
        "errors": [{"code": 1000, "message": format!("synthetic HTTP {status}")}],
        "messages": [],
        "result": null,
    }))
    .expect("serialize reconciliation HTTP error")
}

fn duplicate_reconciliation_response(
    results: &[Value],
    fault: &ReconciliationFault,
) -> Option<Vec<u8>> {
    let result_json = serde_json::to_string(results).expect("serialize reconciliation results");
    let (response, capture) = match fault {
        ReconciliationFault::DuplicateOuterSuccess(reverse, capture) => {
            let duplicate = if *reverse {
                r#""success":true,"success":false"#
            } else {
                r#""success":false,"success":true"#
            };
            (
                format!(r#"{{{duplicate},"errors":[],"messages":[],"result":{result_json}}}"#),
                capture,
            )
        }
        ReconciliationFault::DuplicateNestedRowId(reverse, capture) => {
            let needle = r#""id":1,"name":"0001_create.sql""#;
            assert!(
                result_json.contains(needle),
                "synthetic ledger row must remain uniquely replaceable"
            );
            let duplicate = if *reverse {
                r#""id":2,"id":1,"name":"0001_create.sql""#
            } else {
                r#""id":1,"id":2,"name":"0001_create.sql""#
            };
            (
                format!(
                    r#"{{"success":true,"errors":[],"messages":[],"result":{}}}"#,
                    result_json.replacen(needle, duplicate, 1)
                ),
                capture,
            )
        }
        _ => return None,
    };
    let response = response.into_bytes();
    *capture.lock().expect("duplicate response capture") = response.clone();
    Some(response)
}

fn reconciliation_statement_markers(sql: &str) -> Vec<String> {
    sql.split(";\n")
        .map(|statement| {
            statement
                .strip_prefix("SELECT '")
                .and_then(|value| value.split_once("' AS \"__cf_mcp_statement_id\""))
                .map(|(marker, _)| marker.to_string())
                .expect("fixed reconciliation statement marker")
        })
        .collect()
}

fn tagged_reconciliation_result(
    marker: &str,
    fields: &[&str],
    rows: Vec<Value>,
    meta: Option<Value>,
) -> Value {
    let mut tagged = Vec::new();
    let mut sentinel = serde_json::Map::new();
    sentinel.insert("__cf_mcp_statement_id".to_string(), json!(marker));
    sentinel.insert("__cf_mcp_row_kind".to_string(), json!(0));
    for field in fields {
        sentinel.insert((*field).to_string(), Value::Null);
    }
    tagged.push(Value::Object(sentinel));
    for row in rows {
        let mut row = row.as_object().expect("reconciliation data row").clone();
        row.insert("__cf_mcp_statement_id".to_string(), json!(marker));
        row.insert("__cf_mcp_row_kind".to_string(), json!(1));
        tagged.push(Value::Object(row));
    }
    let mut meta = meta.unwrap_or_else(|| json!({}));
    meta.as_object_mut()
        .expect("reconciliation result metadata")
        .entry("served_by_primary".to_string())
        .or_insert_with(|| json!(true));
    let mut result = json!({"success": true, "results": tagged});
    result
        .as_object_mut()
        .expect("reconciliation result")
        .insert("meta".to_string(), meta);
    result
}

fn one_table_reconciliation_case() -> (Value, Value) {
    let migration_sql = "CREATE TABLE items(id INTEGER PRIMARY KEY);";
    let manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": migration_sql.len(),
        "sql_sha256": sha256_hex(migration_sql),
        "sql": migration_sql,
    }]);
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "items",
                "table_name": "items",
                "sql_sha256": sha256_hex("CREATE TABLE items(id INTEGER PRIMARY KEY)"),
            }],
            "tables": [{
                "name": "items",
                "columns": [{
                    "cid": 0,
                    "name": "id",
                    "declared_type": "INTEGER",
                    "not_null": false,
                    "default_value": null,
                    "primary_key_position": 1,
                    "hidden": 0,
                }],
                "foreign_keys": [],
            }],
        }
    ]);
    (manifest, expectations)
}

fn spawn_fake_reconciliation_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_reconciliation_api_with_fault(ReconciliationFault::None)
}

fn spawn_fake_reconciliation_api_with_fault(
    fault: ReconciliationFault,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reconciliation D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("reconciliation D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (request_index, stream) in listener.incoming().take(2).enumerate() {
            let mut stream = stream.expect("fake reconciliation stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("reconciliation request JSON");
            let markers = reconciliation_statement_markers(
                body_json["sql"].as_str().expect("reconciliation SQL"),
            );
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json);
            if let ReconciliationFault::SecondBatchTransportFailure(custody_path) = &fault {
                if request_index == 1 {
                    if let Some(path) = custody_path {
                        fs::write(path, b"tampered retained evidence")
                            .expect("tamper retained evidence before transport failure");
                    }
                    continue;
                }
            }
            if matches!(&fault, ReconciliationFault::Redirect) {
                let response = b"redirect refused";
                let redirect_location =
                    format!("http://{}:9/must-not-be-followed", Ipv4Addr::LOCALHOST); // DevSkim: ignore DS137138 -- loopback-only no-follow fixture
                write!(stream, "HTTP/1.1 302 Found\r\nconnection: close\r\nlocation: {redirect_location}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write reconciliation redirect headers");
                stream
                    .write_all(response)
                    .expect("write reconciliation redirect body");
                continue;
            }
            if let ReconciliationFault::MalformedUtf8HttpStatus(status) = &fault {
                let response = [0xff, 0xfe];
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write malformed UTF-8 reconciliation headers");
                stream
                    .write_all(&response)
                    .expect("write malformed UTF-8 reconciliation body");
                continue;
            }
            if let ReconciliationFault::MalformedJsonStatus(status) = &fault {
                let response = b"{";
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write malformed JSON reconciliation headers");
                stream
                    .write_all(response)
                    .expect("write malformed JSON reconciliation body");
                continue;
            }
            if let ReconciliationFault::ZeroByteTruncatedHttpStatus(status) = &fault {
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n").expect("write zero-byte truncated reconciliation headers");
                continue;
            }
            if let ReconciliationFault::TruncatedHttpStatus(status) = &fault {
                let response = b"{";
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n").expect("write truncated reconciliation headers");
                stream
                    .write_all(response)
                    .expect("write truncated reconciliation body");
                continue;
            }
            if let ReconciliationFault::HttpStatusCustodyDrift(status, path) = &fault {
                fs::write(path, b"tampered retained evidence")
                    .expect("tamper retained evidence before provider error");
                let response = reconciliation_http_error_response(*status);
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write reconciliation drift HTTP error headers");
                stream
                    .write_all(&response)
                    .expect("write reconciliation drift HTTP error");
                continue;
            }
            if let ReconciliationFault::SecondBatchHttpStatus(status) = &fault {
                if request_index == 1 {
                    let response = reconciliation_http_error_response(*status);
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write second reconciliation HTTP error headers");
                    stream
                        .write_all(&response)
                        .expect("write second reconciliation HTTP error");
                    continue;
                }
            }
            if let ReconciliationFault::OversizedHttpStatus(status) = &fault {
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", 16 * 1024 * 1024 + 1).expect("write oversized reconciliation HTTP error headers");
                continue;
            }
            if matches!(&fault, ReconciliationFault::OversizedResponse) {
                let response = vec![b'x'; 16 * 1024 * 1024 + 1];
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write oversized reconciliation headers");
                let _ = stream.write_all(&response);
                continue;
            }
            if let ReconciliationFault::HttpStatus(status) = &fault {
                let response = reconciliation_http_error_response(*status);
                write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write reconciliation HTTP error headers");
                stream
                    .write_all(&response)
                    .expect("write reconciliation HTTP error");
                continue;
            }
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    vec![json!({"id": 1, "name": "0001_create.sql"})],
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    vec![
                        json!({"type": "table", "name": "items", "tbl_name": "items", "sql": "CREATE TABLE items(id INTEGER PRIMARY KEY)"}),
                    ],
                    None,
                ),
                tagged_reconciliation_result(
                    &markers[2],
                    &[
                        "cid",
                        "name",
                        "type",
                        "notnull",
                        "dflt_value",
                        "pk",
                        "hidden",
                    ],
                    vec![
                        json!({"cid": 0, "name": "id", "type": "INTEGER", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0}),
                    ],
                    None,
                ),
                tagged_reconciliation_result(
                    &markers[3],
                    &[
                        "id",
                        "seq",
                        "table",
                        "from",
                        "to",
                        "on_update",
                        "on_delete",
                        "match",
                    ],
                    Vec::new(),
                    None,
                ),
                tagged_reconciliation_result(
                    &markers[4],
                    &["table", "rowid", "parent", "fkid"],
                    Vec::new(),
                    None,
                ),
            ];
            match &fault {
                ReconciliationFault::WrongStatementMarker => {
                    results[0]["results"][0]["__cf_mcp_statement_id"] = json!("f".repeat(64));
                }
                ReconciliationFault::MalformedReadOnlyMetadata => {
                    results[0]["meta"]["changes"] = json!("0");
                }
                ReconciliationFault::CustodyDrift(path) => {
                    fs::write(path, b"tampered retained evidence")
                        .expect("tamper retained evidence fixture");
                }
                ReconciliationFault::SecondBatchCustodyDrift(path) if request_index == 1 => {
                    fs::write(path, b"tampered retained evidence")
                        .expect("tamper retained evidence after second provider read");
                }
                ReconciliationFault::PrimaryMetaMissing => {
                    results[0]
                        .as_object_mut()
                        .expect("result object")
                        .remove("meta");
                }
                ReconciliationFault::PrimaryMarkerMissing => {
                    results[0]["meta"]
                        .as_object_mut()
                        .expect("metadata object")
                        .remove("served_by_primary");
                }
                ReconciliationFault::PrimaryMarkerFalse => {
                    results[0]["meta"]["served_by_primary"] = json!(false);
                }
                ReconciliationFault::PrimaryMarkerNull => {
                    results[0]["meta"]["served_by_primary"] = Value::Null;
                }
                ReconciliationFault::PrimaryMarkerWrongType => {
                    results[0]["meta"]["served_by_primary"] = json!("true");
                }
                ReconciliationFault::MixedPrimaryMarkers => {
                    results[2]["meta"]["served_by_primary"] = json!(false);
                }
                ReconciliationFault::SecondBatchPrimaryFalse if request_index == 1 => {
                    results[3]["meta"]["served_by_primary"] = json!(false);
                }
                ReconciliationFault::LedgerNotManifestPrefix => {
                    results[0]["results"][1]["name"] = json!("0099_unknown.sql");
                }
                ReconciliationFault::UnstableSecondBatch if request_index == 1 => {
                    results[1]["results"][1]["sql"] =
                        json!("CREATE TABLE items(id INTEGER PRIMARY KEY, changed TEXT)");
                }
                ReconciliationFault::None
                | ReconciliationFault::Redirect
                | ReconciliationFault::MalformedUtf8HttpStatus(_)
                | ReconciliationFault::MalformedJsonStatus(_)
                | ReconciliationFault::ZeroByteTruncatedHttpStatus(_)
                | ReconciliationFault::TruncatedHttpStatus(_)
                | ReconciliationFault::OversizedResponse
                | ReconciliationFault::HttpStatus(_)
                | ReconciliationFault::HttpStatusCustodyDrift(_, _)
                | ReconciliationFault::OversizedHttpStatus(_)
                | ReconciliationFault::SecondBatchCustodyDrift(_)
                | ReconciliationFault::PrimaryMetaMissing
                | ReconciliationFault::PrimaryMarkerMissing
                | ReconciliationFault::PrimaryMarkerFalse
                | ReconciliationFault::PrimaryMarkerNull
                | ReconciliationFault::PrimaryMarkerWrongType
                | ReconciliationFault::MixedPrimaryMarkers
                | ReconciliationFault::SecondBatchPrimaryFalse
                | ReconciliationFault::SecondBatchHttpStatus(_)
                | ReconciliationFault::SecondBatchTransportFailure(_)
                | ReconciliationFault::DuplicateOuterSuccess(_, _)
                | ReconciliationFault::DuplicateNestedRowId(_, _)
                | ReconciliationFault::UnstableSecondBatch => {}
            }
            let response =
                duplicate_reconciliation_response(&results, &fault).unwrap_or_else(|| {
                    serde_json::to_vec(&json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": results,
                    }))
                    .expect("serialize reconciliation response")
                });
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write reconciliation headers");
            stream
                .write_all(&response)
                .expect("write reconciliation response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_manifest_ambiguous_result_api(
    write_result: Value,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ambiguous result manifest D1 API");
    let addr = listener
        .local_addr()
        .expect("ambiguous result manifest D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let write_commits = write_result.as_array().is_some_and(|result_sets| {
            !result_sets.is_empty()
                && result_sets.iter().all(|result_set| {
                    result_set["success"] == json!(true)
                        && result_set["errors"].as_array().is_none_or(Vec::is_empty)
                        && result_set["results"].is_array()
                })
        });
        let mut apply_seen = false;
        for stream in listener.incoming().take(6) {
            let mut stream = stream.expect("fake ambiguous result manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("ambiguous result request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let response = if sql.contains("INSERT INTO \"d1_migrations\"") {
                apply_seen = write_commits;
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": write_result,
                })
            } else {
                assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "results": if apply_seen {
                        vec![
                            json!({"id": 1, "name": "0001_initial.sql"}),
                            json!({"id": 2, "name": "0002_second.sql"}),
                        ]
                    } else {
                        vec![json!({"id": 1, "name": "0001_initial.sql"})]
                    }}],
                })
            };
            let response =
                serde_json::to_vec(&response).expect("serialize ambiguous result response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write ambiguous result headers");
            stream
                .write_all(&response)
                .expect("write ambiguous result response");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_partial_manifest_ambiguous_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind partial ambiguous manifest D1 API");
    let addr = listener
        .local_addr()
        .expect("partial ambiguous manifest D1 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let mut first_apply_seen = false;
        let mut ambiguous_second_apply_seen = false;
        for stream in listener.incoming().take(7) {
            let mut stream = stream.expect("fake partial ambiguous manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("partial ambiguous request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            if sql.contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0001_initial.sql')") {
                first_apply_seen = true;
                let response = serde_json::to_vec(&json!({
                    "success": true, "errors": [], "messages": [],
                    "result": [{"success": true, "results": [{"ok": true}]}]
                }))
                .expect("serialize first apply response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write first apply headers");
                stream
                    .write_all(&response)
                    .expect("write first apply response");
                continue;
            }
            if sql.contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0002_second.sql')") {
                ambiguous_second_apply_seen = true;
                write!(stream, "HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-length: 0\r\n\r\n").expect("write second ambiguous response");
                continue;
            }
            assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
            let ledger = if ambiguous_second_apply_seen {
                vec![
                    json!({"id": 1, "name": "0001_initial.sql"}),
                    json!({"id": 2, "name": "0002_second.sql"}),
                ]
            } else if first_apply_seen {
                vec![json!({"id": 1, "name": "0001_initial.sql"})]
            } else {
                Vec::new()
            };
            let response = serde_json::to_vec(&json!({
                "success": true, "errors": [], "messages": [],
                "result": [{"success": true, "results": ledger}]
            }))
            .expect("serialize ledger response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write ledger headers");
            stream.write_all(&response).expect("write ledger response");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_cloudflare_api() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Cloudflare API");
    let addr = listener.local_addr().expect("fake API addr");
    thread::spawn(move || {
        let mut requests_seen = 0usize;
        let mut waf_custom_ruleset = json!({
            "id": "ruleset-custom",
            "name": "Zone custom WAF rules",
            "kind": "zone",
            "phase": "http_request_firewall_custom",
            "version": "7",
            "last_updated": "2026-06-04T00:00:00Z",
            "rules": [{
                "id": "rule-1",
                "version": "3",
                "description": "Block admin probes",
                "action": "block",
                "enabled": true,
                "expression": "http.request.uri.path contains \"/admin\"",
                "ref": "block-admin"
            }]
        });
        for stream in listener.incoming() {
            let mut stream = stream.expect("fake API stream");
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).expect("read request");
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&request);
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .or_else(|| {
                    headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                stream.read_exact(&mut body).expect("read body");
            }
            let path = headers
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            let method = headers
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().next())
                .unwrap_or_default()
                .to_string();
            let path_only = path.split('?').next().unwrap_or(path.as_str());
            let body_text = String::from_utf8_lossy(&body).to_string();
            let body_json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let d1_sql = body_json
                .get("sql")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let response = if path_only.ends_with("/graphql") {
                if body_json
                    .get("query")
                    .and_then(Value::as_str)
                    .is_some_and(|query| {
                        query.contains("WafSecurityEvents") || query.contains("WafRuleActivity")
                    })
                {
                    json!({
                        "data": {
                            "viewer": {
                                "zones": [{
                                    "settings": {
                                        "firewallEventsAdaptive": {
                                            "maxDuration": 86400,
                                            "maxPageSize": 100,
                                            "notOlderThan": "2026-06-01T00:00:00Z"
                                        }
                                    },
                                    "byAction": [{
                                        "count": 3,
                                        "dimensions": {"action": "block"}
                                    }],
                                    "bySource": [{
                                        "count": 3,
                                        "dimensions": {"source": "waf"}
                                    }],
                                    "byHost": [{
                                        "count": 3,
                                        "dimensions": {"clientRequestHTTPHost": "example.com"}
                                    }],
                                    "samples": [{
                                        "action": "block",
                                        "clientIP": "203.0.113.10",
                                        "clientRequestHTTPHost": "example.com",
                                        "clientRequestPath": "/admin",
                                        "datetime": "2026-06-04T01:02:03Z",
                                        "source": "waf",
                                        "ruleId": "rule-1",
                                        "rulesetId": "ruleset-custom",
                                        "userAgent": "curl/8"
                                    }]
                                }]
                            }
                        }
                    })
                } else {
                    json!({
                        "data": {
                            "viewer": {
                                "accounts": [{
                                    "d1AnalyticsAdaptiveGroups": [{
                                        "sum": {"rowsRead": 10, "rowsWritten": 4},
                                        "dimensions": {"date": "2026-06-02", "databaseId": "db-1"}
                                    }]
                                }]
                            }
                        }
                    })
                }
            } else if path_only.ends_with("/paygo-usage") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "ServiceName": "D1",
                        "ConsumedQuantity": 42,
                        "ConsumedUnit": "rows"
                    }]
                })
            } else if path_only.ends_with("/analytics_engine/sql") {
                match body_text.as_str() {
                    "SHOW TABLES" => json!({
                        "meta": [{"name": "name", "type": "String"}],
                        "data": [
                            {"name": "WEB"},
                            {"dataset": "example_staff_publish_telemetry"}
                        ],
                        "rows": 2
                    }),
                    sql if sql.starts_with("SELECT") => json!({
                        "meta": [
                            {"name": "path", "type": "String"},
                            {"name": "views", "type": "UInt64"}
                        ],
                        "data": [{"path": "/", "views": 1}],
                        "rows": 1
                    }),
                    sql => json!({
                        "success": false,
                        "errors": [{"code": 7000, "message": format!("unexpected AE SQL: {sql}")}],
                        "messages": [],
                        "result": null
                    }),
                }
            } else if path_only.ends_with("/queues/queue-1/metrics") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "backlog_bytes": 700,
                        "backlog_count": 7,
                        "oldest_message_timestamp_ms": 0
                    }
                })
            } else if path_only.ends_with("/queues/dlq-1/metrics") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "backlog_bytes": 200,
                        "backlog_count": 2,
                        "oldest_message_timestamp_ms": 0
                    }
                })
            } else if path_only.ends_with("/queues/queue-1/consumers") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "consumer_id": "consumer-1",
                        "type": "worker",
                        "script_name": "consumer-worker",
                        "dead_letter_queue": "editor-forwarder-dlq",
                        "settings": {"max_retries": 5}
                    }]
                })
            } else if path_only.ends_with("/queues/queue-1/purge") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"completed": "2026-05-21T00:00:00Z"}
                })
            } else if path_only.ends_with("/queues/queue-1") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "queue_id": "queue-1",
                        "queue_name": "editor-forwarder",
                        "settings": {"delivery_paused": false},
                        "consumers_total_count": 1
                    }
                })
            } else if path_only.ends_with("/queues") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [
                        {"queue_id": "queue-1", "queue_name": "editor-forwarder"},
                        {"queue_id": "dlq-1", "queue_name": "editor-forwarder-dlq"}
                    ]
                })
            } else if path_only.ends_with("/workers/observability/telemetry/values") {
                if body_json.get("timeframe").is_some()
                    && body_json.get("type").is_some()
                    && body_json.get("datasets").is_some()
                {
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"key": "$workers.scriptName", "type": "string", "value": "pages-worker"}]
                    })
                } else {
                    json!({
                        "success": false,
                        "errors": [{"code": 7000, "message": "missing timeframe/type"}],
                        "messages": [],
                        "result": null
                    })
                }
            } else if path_only.ends_with("/workers/observability/telemetry/keys") {
                if body_json.get("from").is_some()
                    && body_json.get("to").is_some()
                    && body_json.get("datasets").is_some()
                    && body_json.get("timeframe").is_none()
                {
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"key": "$workers.scriptName", "type": "string"}]
                    })
                } else {
                    json!({
                        "success": false,
                        "errors": [{"code": 7000, "message": "missing top-level from/to/datasets"}],
                        "messages": [],
                        "result": null
                    })
                }
            } else if path_only.ends_with("/workers/observability/telemetry/query") {
                if body_json.get("timeframe").is_some()
                    && body_json.get("queryId").is_some()
                    && body_json.get("limit").is_some()
                    && body_json.get("parameters").is_some()
                {
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {"events": []}
                    })
                } else {
                    json!({
                        "success": false,
                        "errors": [{"code": 7000, "message": "missing timeframe/queryId/parameters"}],
                        "messages": [],
                        "result": null
                    })
                }
            } else if path_only
                .ends_with("/rulesets/phases/http_request_firewall_custom/entrypoint")
            {
                if method == "PUT" {
                    waf_custom_ruleset = body_json.clone();
                }
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": waf_custom_ruleset
                })
            } else if path_only
                .ends_with("/rulesets/phases/http_request_firewall_managed/entrypoint")
            {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": "ruleset-managed",
                        "name": "Zone managed WAF rules",
                        "kind": "zone",
                        "phase": "http_request_firewall_managed",
                        "version": "2",
                        "rules": []
                    }
                })
            } else if path_only.ends_with("/rulesets/phases/http_ratelimit/entrypoint") {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": "ruleset-ratelimit",
                        "name": "Zone rate limiting rules",
                        "kind": "zone",
                        "phase": "http_ratelimit",
                        "version": "1",
                        "rules": []
                    }
                })
            } else {
                match d1_sql {
                    sql if sql.contains("sqlite_master") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"type": "table", "name": "_cf_KV", "tbl_name": "_cf_KV", "sql": "CREATE TABLE _cf_KV (key TEXT)"},
                            {"type": "table", "name": "submissions", "tbl_name": "submissions", "sql": "CREATE TABLE submissions (id TEXT)"},
                            {"type": "table", "name": "submission_events", "tbl_name": "submission_events", "sql": "CREATE TABLE submission_events (id TEXT)"},
                            {"type": "table", "name": "users", "tbl_name": "users", "sql": "CREATE TABLE users (id TEXT)"}
                        ],
                        "meta": {"duration": 1}
                    }]
                    }),
                    "PRAGMA table_info(\"submissions\")" => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                    }),
                    "PRAGMA table_info(\"submission_events\")" => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                    }),
                    "PRAGMA table_info(\"users\")" => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                    }),
                    sql if sql.starts_with("EXPLAIN QUERY PLAN") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"id": 2, "parent": 0, "notused": 0, "detail": "SCAN submissions"}],
                        "meta": {"duration": 1}
                    }]
                    }),
                    _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected SQL: {d1_sql}")}],
                    "messages": [],
                    "result": null
                    }),
                }
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
            requests_seen += 1;
            if requests_seen >= 20 {
                break;
            }
        }
    });
    format!("http://{addr}")
}

fn spawn_fake_graphql_api(response_body: Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake GraphQL API");
    let addr = listener.local_addr().expect("fake GraphQL API addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.expect("fake GraphQL API stream");
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).expect("read request");
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&request);
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .or_else(|| {
                    headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                stream.read_exact(&mut body).expect("read body");
            }
            let path = headers
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_string();
            assert!(path.ends_with("/graphql"), "unexpected path: {path}");
            let response = serde_json::to_vec(&response_body).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    format!("http://{addr}")
}

fn spawn_fake_d1_database_mutation_api(
    expected_requests: usize,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake D1 API");
    let addr = listener.local_addr().expect("fake D1 API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake D1 API stream");
            let (headers, body) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            let body_json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(json!({
                    "method": method,
                    "path": path,
                    "body": body_json,
                }));

            let response = match (method.as_str(), path.as_str()) {
                ("PATCH", "/accounts/acct-1/d1/database/db-1") => {
                    assert_eq!(body_json["name"], json!("renamed-db"));
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "uuid": "db-1",
                            "name": "renamed-db",
                            "created_at": "2026-05-22T00:00:00Z"
                        },
                    })
                }
                ("DELETE", "/accounts/acct-1/d1/database/db-1") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"id": "db-1", "deleted": true},
                }),
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_worker_upload_api(expected_requests: usize) -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_worker_upload_api_with_readback(expected_requests, "worker.js")
}

fn spawn_fake_worker_upload_api_with_readback(
    expected_requests: usize,
    readback_main_module: &'static str,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Worker upload API");
    let addr = listener.local_addr().expect("fake Worker upload API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake Worker upload API stream");
            let (headers, body) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            let content_type = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-type:"))
                .or_else(|| {
                    headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Type:"))
                })
                .map(str::trim)
                .unwrap_or_default()
                .to_string();
            let if_none_match = headers
                .lines()
                .find_map(|line| line.strip_prefix("if-none-match:"))
                .or_else(|| {
                    headers
                        .lines()
                        .find_map(|line| line.strip_prefix("If-None-Match:"))
                })
                .map(str::trim)
                .unwrap_or_default()
                .to_string();
            let body_text = String::from_utf8_lossy(&body).to_string();
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(json!({
                    "method": method,
                    "path": path,
                    "content_type": content_type,
                    "if_none_match": if_none_match,
                    "body_text": body_text,
                }));

            let response = match (method.as_str(), path.as_str()) {
                ("PUT", "/accounts/acct-1/workers/scripts/worker-a") => {
                    assert!(body_text.contains("name=\"metadata\""));
                    assert!(body_text.contains("\"main_module\":\"worker.js\""));
                    assert!(body_text.contains("name=\"worker.js\"; filename=\"worker.js\""));
                    assert!(body_text.contains("export default"));
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "id": "worker-a",
                            "script_name": "worker-a",
                            "modified_on": "2026-06-03T00:00:00Z"
                        },
                    })
                }
                ("GET", "/accounts/acct-1/workers/scripts/worker-a/settings") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "main_module": readback_main_module,
                        "compatibility_date": "2026-06-03",
                        "bindings": []
                    },
                }),
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_worker_settings_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake Worker settings API");
    let addr = listener
        .local_addr()
        .expect("fake Worker settings API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(4) {
            let mut stream = stream.expect("fake Worker settings API stream");
            let (headers, body) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            let content_type = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-type:"))
                .or_else(|| {
                    headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Type:"))
                })
                .map(str::trim)
                .unwrap_or_default()
                .to_string();
            let body_text = String::from_utf8_lossy(&body).to_string();
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(json!({
                    "method": method,
                    "path": path,
                    "content_type": content_type,
                    "body_text": body_text,
                }));

            let response = match (method.as_str(), path.as_str()) {
                ("GET", "/accounts/acct-1/workers/scripts/worker-a/settings") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "new"}],
                        "compatibility_date": "2026-06-03"
                    },
                }),
                ("PATCH", "/accounts/acct-1/workers/scripts/worker-a/settings") => {
                    assert!(content_type.starts_with("multipart/form-data;"));
                    assert!(body_text.contains("name=\"settings\""));
                    assert!(body_text.contains(
                        r#""bindings":[{"name":"DESTINATION","text":"new","type":"plain_text"}]"#
                    ));
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "new"}],
                            "compatibility_date": "2026-06-03"
                        },
                    })
                }
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_worker_upload_version_attestation_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_worker_upload_version_attestation_api_with_identity(false)
}

fn spawn_fake_worker_upload_version_attestation_cross_target_api()
-> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_worker_upload_version_attestation_api_with_identity(true)
}

fn spawn_fake_worker_upload_version_attestation_api_with_identity(
    cross_target: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake Worker attestation API");
    let addr = listener
        .local_addr()
        .expect("fake Worker attestation API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(7) {
            let mut stream = stream.expect("fake Worker attestation API stream");
            let (headers, body) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts
                .next()
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
                .to_string();
            let body_text = String::from_utf8_lossy(&body).to_string();
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(json!({"method": method, "path": path, "body_text": body_text}));

            let response = match (method.as_str(), path.as_str()) {
                ("PUT", "/accounts/acct-1/workers/scripts/worker-a") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": if cross_target { "worker-other" } else { "worker-a" },
                        "script_name": "worker-a",
                        "etag": "etag-1"
                    },
                }),
                ("GET", "/accounts/acct-1/workers/scripts/worker-a/settings") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"main_module": null, "bindings": []},
                }),
                ("GET", "/accounts/acct-1/workers/scripts") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"id": "worker-a", "etag": "etag-1"}],
                }),
                ("GET", "/accounts/acct-1/workers/scripts/worker-a/versions") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"items": [{"id": "version-1"}]},
                    "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1},
                }),
                ("GET", "/accounts/acct-1/workers/scripts/worker-a/versions/version-1") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": "version-1",
                        "author_email": "redacted-author",
                        "resources": {"script": {
                            "etag": "etag-1",
                            "handlers": ["fetch"],
                            "named_handlers": []
                        }}
                    },
                }),
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_access_policy_api() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Access policy API");
    let addr = listener.local_addr().expect("fake API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let mut policy = json!({
            "id": "pol-1",
            "name": "allow",
            "decision": "allow",
            "include": [{"email": {"email": "old@example.com"}}],
            "exclude": [],
            "require": [],
        });

        for stream in listener.incoming().take(3) {
            let mut stream = stream.expect("fake Access policy API stream");
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).expect("read request");
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&request);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .or_else(|| {
                    headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                stream.read_exact(&mut body).expect("read body");
            }
            let body_json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(format!("{method} {path}"));

            let response = match (method.as_str(), path.as_str()) {
                ("GET", "/accounts/acct-1/access/apps/app-1/policies") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [policy.clone()],
                }),
                ("PUT", "/accounts/acct-1/access/apps/app-1/policies") => json!({
                    "success": false,
                    "errors": [{"code": 405, "message": "collection PUT must not be used"}],
                    "messages": [],
                    "result": null,
                }),
                ("PUT", "/accounts/acct-1/access/apps/app-1/policies/pol-1") => {
                    if body_json.get("id").and_then(Value::as_str) == Some("pol-1") {
                        policy = json!({
                            "id": "pol-1",
                            "name": body_json["name"],
                            "decision": body_json["decision"],
                            "include": body_json["include"],
                            "exclude": body_json["exclude"],
                            "require": body_json["require"],
                        });
                        json!({
                            "success": true,
                            "errors": [],
                            "messages": [],
                            "result": policy.clone(),
                        })
                    } else {
                        json!({
                            "success": false,
                            "errors": [{"code": 7000, "message": "missing policy id in update body"}],
                            "messages": [],
                            "result": null,
                        })
                    }
                }
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn create_static_pages_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "cloudflare-mcp-pages-{name}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("assets")).expect("create Pages fixture directory");
    fs::write(root.join("index.html"), "<!doctype html><h1>Hello</h1>").expect("write index.html");
    fs::write(root.join("assets/app.css"), "body{color:#123}").expect("write app.css");
    fs::write(root.join("_headers"), "/*\n  x-test: yes\n").expect("write _headers");
    root
}

fn create_pages_dir_with_worker(name: &str) -> PathBuf {
    let root = create_static_pages_dir(name);
    fs::write(
        root.join("_worker.js"),
        "export default { fetch(request, env) { return env.ASSETS.fetch(request); } };",
    )
    .expect("write _worker.js");
    root
}

fn pages_dir_with_worker_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pages-single-module-worker")
}

fn create_pages_dir_with_worker_bundle(name: &str) -> PathBuf {
    let root = create_static_pages_dir(name);
    fs::write(
        root.join("_worker.bundle"),
        "------formdata-worker-bundle\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n------formdata-worker-bundle--\r\n",
    )
    .expect("write _worker.bundle");
    root
}

fn create_pages_dir_with_routes_only(name: &str) -> PathBuf {
    let root = create_static_pages_dir(name);
    fs::write(
        root.join("_routes.json"),
        r#"{"version":1,"include":["/*"],"exclude":[]}"#,
    )
    .expect("write _routes.json");
    root
}

fn create_pages_project_with_functions(name: &str) -> (PathBuf, PathBuf) {
    let project = create_static_pages_dir(name);
    let dist = project.join("dist");
    fs::create_dir_all(dist.join("assets")).expect("create dist assets");
    fs::write(dist.join("index.html"), "<!doctype html><h1>Hello</h1>").expect("write dist index");
    fs::write(dist.join("assets/app.css"), "body{color:#456}").expect("write dist app.css");
    fs::write(dist.join("_headers"), "/*\n  x-test: yes\n").expect("write dist _headers");
    fs::create_dir_all(project.join("functions/api")).expect("create functions");
    fs::write(
        project.join("functions/api/deployment.js"),
        "export function onRequestPost() { return new Response('ok'); }",
    )
    .expect("write function");
    (project, dist)
}

fn create_fake_wrangler(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "cloudflare-mcp-fake-wrangler-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create fake wrangler dir");
    let path = root.join("wrangler");
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
outfile=""
routes=""
config=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --outfile)
      shift
      outfile="$1"
      ;;
    --output-routes-path)
      shift
      routes="$1"
      ;;
    --output-config-path)
      shift
      config="$1"
      ;;
  esac
  shift || true
done
test -n "$outfile"
printf '%s' '------formdata-worker-bundle
Content-Disposition: form-data; name="metadata"

{"main_module":"functionsWorker.js"}
------formdata-worker-bundle
Content-Disposition: form-data; name="functionsWorker.js"; filename="functionsWorker.js"

export default {};
------formdata-worker-bundle--
' > "$outfile"
test -z "$routes" || printf '%s' '{"version":1,"include":["/api/*"],"exclude":[]}' > "$routes"
test -z "$config" || printf '%s' '{"routes":[{"routePath":"/api/agent/changes/deployment","mountPath":"/api/agent/changes/deployment","method":"POST"}]}' > "$config"
"#,
    )
    .expect("write fake wrangler");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path)
            .expect("fake wrangler metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("chmod fake wrangler");
    }
    path
}

fn spawn_fake_pages_direct_upload_api(
    expect_check_missing: bool,
) -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_fake_pages_direct_upload_api_with_options(
        expect_check_missing,
        ExpectedWorkerUpload::None,
    )
}

#[derive(Clone, Copy)]
enum ExpectedWorkerUpload {
    None,
    Script,
    ScriptWithRoutes,
    Bundle,
    FunctionsBundle,
}

fn spawn_fake_pages_direct_upload_api_with_options(
    expect_check_missing: bool,
    expected_worker: ExpectedWorkerUpload,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Pages API");
    let addr = listener.local_addr().expect("fake API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let expected_requests = if expect_check_missing { 5 } else { 4 };
    thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake Pages API stream");
            let (headers, body) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            let body_text = String::from_utf8_lossy(&body).to_string();
            let body_json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(format!("{method} {path}"));

            let response = match (method.as_str(), path.as_str()) {
                ("GET", "/accounts/acct-1/pages/projects/site/upload-token") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"jwt": "pages-upload-token"},
                }),
                ("POST", "/pages/assets/check-missing") => {
                    let hashes = body_json["hashes"]
                        .as_array()
                        .expect("hashes array")
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": hashes,
                    })
                }
                ("POST", "/pages/assets/upload") => {
                    assert!(body_json.as_array().is_some_and(|items| !items.is_empty()));
                    assert!(
                        body_json
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|item| item.get("key").is_some() && item.get("value").is_some())
                    );
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {},
                    })
                }
                ("POST", "/pages/assets/upsert-hashes") => {
                    assert!(
                        body_json["hashes"]
                            .as_array()
                            .is_some_and(|items| !items.is_empty())
                    );
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {},
                    })
                }
                ("POST", "/accounts/acct-1/pages/projects/site/deployments") => {
                    assert!(body_text.contains("name=\"manifest\""), "{body_text}");
                    assert!(body_text.contains("/index.html"), "{body_text}");
                    assert!(body_text.contains("name=\"branch\""), "{body_text}");
                    assert!(body_text.contains("preview"), "{body_text}");
                    assert!(body_text.contains("name=\"_headers\""), "{body_text}");
                    match expected_worker {
                        ExpectedWorkerUpload::Script | ExpectedWorkerUpload::ScriptWithRoutes => {
                            assert!(body_text.contains("name=\"_worker.js\""), "{body_text}");
                            assert!(body_text.contains("env.ASSETS.fetch"), "{body_text}");
                            if matches!(expected_worker, ExpectedWorkerUpload::ScriptWithRoutes) {
                                assert!(body_text.contains("name=\"_routes.json\""), "{body_text}");
                            }
                        }
                        ExpectedWorkerUpload::Bundle | ExpectedWorkerUpload::FunctionsBundle => {
                            assert!(body_text.contains("name=\"_worker.bundle\""), "{body_text}");
                            assert!(
                                body_text.contains("------formdata-worker-bundle"),
                                "{body_text}"
                            );
                            assert!(
                                !body_text.contains("name=\"_worker.js\"; filename=\"_worker.js\""),
                                "{body_text}"
                            );
                            if matches!(expected_worker, ExpectedWorkerUpload::FunctionsBundle) {
                                assert!(
                                    body_text.contains(
                                        "name=\"functions-filepath-routing-config.json\""
                                    ),
                                    "{body_text}"
                                );
                                assert!(body_text.contains("name=\"_routes.json\""), "{body_text}");
                            }
                        }
                        ExpectedWorkerUpload::None => {
                            assert!(!body_text.contains("name=\"_worker.js\""), "{body_text}");
                            assert!(
                                !body_text.contains("name=\"_worker.bundle\""),
                                "{body_text}"
                            );
                        }
                    }
                    json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "id": "deployment-1",
                            "project_name": "site",
                            "environment": "preview",
                            "url": "https://deployment-1.pages.dev",
                            "aliases": [],
                        },
                    })
                }
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_pages_direct_upload_project_api() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Pages project API");
    let addr = listener.local_addr().expect("fake API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let mut stream = stream.expect("fake Pages project API stream");
            let (headers, _) = read_http_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            let mut request_parts = request_line.split_whitespace();
            let method = request_parts.next().unwrap_or_default().to_string();
            let path = request_parts.next().unwrap_or_default().to_string();
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(format!("{method} {path}"));
            let response = match (method.as_str(), path.as_str()) {
                ("GET", "/accounts/acct-1/pages/projects/direct-only") => json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": "project-1",
                        "name": "direct-only",
                        "source": null,
                    },
                }),
                _ => json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
                }),
            };
            let response = serde_json::to_vec(&response).expect("serialize response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write response body");
        }
    });
    (format!("http://{addr}"), requests)
}

#[test]
fn stdio_tool_calls_cover_context_and_body_normalization_edges() {
    let mut mcp = McpStdioProcess::start();

    let portal = mcp.call_tool(
        2,
        "portal_agent_request",
        json!({
            "url": "https://staff.example.com/api/agent/submissions/sub-1/events",
            "method": "POST",
            "use_agent_token": true,
            "use_access_service_token": true,
            "body": "{\"status\":\"in_progress\"}",
            "dry_run": true
        }),
    );
    assert!(
        portal.get("error").is_none(),
        "portal_agent_request failed before tool body: {portal}"
    );
    let portal_content = structured_content(&portal);
    assert_eq!(portal_content["ok"], json!(true));
    assert_eq!(portal_content["operation"], json!("portal_agent_request"));
    assert_eq!(
        portal_content["audit"]["correlation"]["session_id"],
        Value::Null,
        "stdio fallback request parts should not invent an HTTP session id"
    );

    let api_mutate = mcp.call_tool(
        3,
        "api_mutate",
        json!({
            "operation_id": "d1-query-database",
            "path_params": {
                "account_id": "acct-1",
                "database_id": "db-1"
            },
            "body": "{\"sql\":\"UPDATE submissions SET status = ? WHERE id = ?\",\"params\":[\"in_progress\",\"sub-1\"]}",
            "dry_run": true,
            "reason": "stdio smoke normalization"
        }),
    );
    assert!(
        api_mutate.get("error").is_none(),
        "api_mutate failed before tool body: {api_mutate}"
    );
    let api_content = structured_content(&api_mutate);
    assert_eq!(api_content["ok"], json!(true));
    assert_eq!(
        api_content["request_plan"]["body_normalized_from_json_string"],
        json!(true)
    );
    assert_eq!(
        api_content["request_plan"]["body"]["sql"],
        json!("UPDATE submissions SET status = ? WHERE id = ?")
    );
    assert_eq!(
        api_content["request_plan"]["body"]["params"],
        json!(["in_progress", "sub-1"])
    );

    let account_token = mcp.call_tool(
        4,
        "account_api_tokens",
        json!({
            "account_id": "acct-1",
            "action": "create",
            "body": "{\"name\":\"deploy-token\",\"policies\":[{\"effect\":\"allow\",\"resources\":{\"com.cloudflare.api.account.acct-1\":\"*\"},\"permission_groups\":[{\"id\":\"perm-1\"}]}]}",
            "dry_run": true,
            "reason": "stdio smoke token planning"
        }),
    );
    assert!(
        account_token.get("error").is_none(),
        "account_api_tokens failed before tool body: {account_token}"
    );
    let token_content = structured_content(&account_token);
    assert_eq!(token_content["ok"], json!(true));
    assert_eq!(
        token_content["request_plan"]["body_normalized_from_json_string"],
        json!(true)
    );
    assert_eq!(
        token_content["request_plan"]["body"]["name"],
        json!("deploy-token")
    );
    assert_eq!(
        token_content["request_plan"]["body"]["policies"][0]["permission_groups"][0]["id"],
        json!("perm-1")
    );

    let token_permission_plan = mcp.call_tool(
        5,
        "account_api_token_permission_plan",
        json!({
            "account_id": "acct-1",
            "token_id": "token-1",
            "current_token": {
                "id": "token-1",
                "name": "deploy-token",
                "policies": [{
                    "effect": "allow",
                    "resources": {"com.cloudflare.api.account.acct-1": "*"},
                    "permission_groups": [
                        {"id": "perm-d1-read", "name": "D1 Read"},
                        {"id": "perm-account-analytics-read", "name": "Account Analytics Read"}
                    ]
                }]
            },
            "permission_groups": [
                {"id": "perm-d1-read", "name": "D1 Read"},
                {"id": "perm-account-analytics-read", "name": "Account Analytics Read"},
                {"id": "perm-workers-scripts-edit", "name": "Workers Scripts Edit"}
            ],
            "add": ["Workers Scripts Edit"],
            "remove": ["Account Analytics Read"],
            "reason": "stdio smoke token permission planning"
        }),
    );
    assert!(
        token_permission_plan.get("error").is_none(),
        "account_api_token_permission_plan failed before tool body: {token_permission_plan}"
    );
    let token_plan_content = structured_content(&token_permission_plan);
    assert_eq!(token_plan_content["ok"], json!(true));
    assert_eq!(token_plan_content["read_only"], json!(true));
    assert_eq!(
        token_plan_content["delta"]["permissions_to_add"][0]["id"],
        json!("perm-workers-scripts-edit")
    );
    assert_eq!(
        token_plan_content["update_body"]["policies"][0]["permission_groups"],
        json!([
            {"id": "perm-d1-read"},
            {"id": "perm-workers-scripts-edit"}
        ])
    );
    assert_eq!(
        token_plan_content["next_call"]["arguments"]["dry_run"],
        json!(true)
    );

    let find_tools = mcp.call_tool(
        6,
        "find_tools",
        json!({
            "query": "d1",
            "limit": 10,
            "include_schema": false
        }),
    );
    let tools_content = structured_content(&find_tools);
    let result_names = tools_content["results"]
        .as_array()
        .expect("find_tools results")
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(
        result_names.contains(&"d1_query_read_only"),
        "find_tools should expose curated D1 tools: {tools_content}"
    );
}

#[test]
fn stdio_boundary_covers_large_catalog_deferred_loading_contract() {
    let mut mcp = McpStdioProcess::start();

    let list = mcp.request(2, "tools/list", json!({}));
    let tool_names = list["result"]["tools"]
        .as_array()
        .expect("tools/list tools")
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(tool_names.len() >= 100, "large catalog should stay visible");
    assert!(tool_names.contains(&"find_tools"));
    assert!(tool_names.contains(&"api_prepare_call"));
    assert!(tool_names.contains(&"waf_ruleset_plan_change"));

    let narrowed = mcp.call_tool(
        3,
        "find_tools",
        json!({
            "query": "d1",
            "group": "d1",
            "read_only": true,
            "limit": 20,
            "include_schema": true
        }),
    );
    let narrowed_content = structured_content(&narrowed);
    assert_eq!(narrowed_content["ok"], json!(true), "{narrowed_content}");
    assert_eq!(
        narrowed_content["openai_deferred_loading"]["recommended_model"],
        json!("gpt-5.5")
    );
    let allowed = narrowed_content["openai_allowed_tools"]
        .as_array()
        .expect("allowed tools");
    assert!(allowed.iter().any(|tool| tool == "d1_inspect_schema"));
    assert!(allowed.iter().any(|tool| tool == "d1_query_read_only"));
    assert!(!allowed.iter().any(|tool| tool == "d1_execute_write"));
    assert!(narrowed_content["schemas"]["d1_inspect_schema"].is_object());
    assert!(narrowed_content["schemas"]["d1_query_read_only"].is_object());

    let config_resource = mcp.request(
        4,
        "resources/read",
        json!({
            "uri": "cloudflare-mcp://openai/tool-search-config"
        }),
    );
    let config_text = text_resource_content(&config_resource);
    let config: Value = serde_json::from_str(&config_text).expect("tool search config json");
    assert_eq!(config["tools"][0]["type"], json!("mcp"));
    assert_eq!(config["tools"][0]["defer_loading"], json!(true));
    assert_eq!(config["tools"][1]["type"], json!("tool_search"));
    assert!(config["tools"][0]["require_approval"].is_null());
    assert!(
        config["optional_trusted_read_only_approval_override"]["require_approval"]["never"]
            ["tool_names"]
            .as_array()
            .expect("trusted read-only tools")
            .iter()
            .any(|tool| tool == "find_tools")
    );

    let denied = mcp.call_tool(5, "not_registered_tool", json!({}));
    assert!(
        denied.get("error").is_some(),
        "strict inventory should reject unknown tool calls: {denied}"
    );
}

#[test]
fn replace_access_policies_uses_policy_item_update_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_access_policy_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "replace_access_policies",
        json!({
            "app_id": "app-1",
            "dry_run": false,
            "policies": [{
                "id": "pol-1",
                "name": "allow-updated",
                "decision": "allow",
                "include": [{"email": {"email": "new@example.com"}}],
                "exclude": [],
                "require": [],
                "precedence": 1
            }]
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["policies"][0]["id"], json!("pol-1"));
    assert_eq!(content["policies"][0]["name"], json!("allow-updated"));
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "GET /accounts/acct-1/access/apps/app-1/policies",
            "PUT /accounts/acct-1/access/apps/app-1/policies/pol-1",
            "GET /accounts/acct-1/access/apps/app-1/policies",
        ]
    );
}

#[test]
fn r2_get_object_file_mode_writes_local_file_through_stdio_boundary() {
    let (r2_endpoint, requests) = spawn_fake_r2_api();
    let output_dir =
        std::env::temp_dir().join(format!("cloudflare-mcp-r2-stdio-{}", std::process::id()));
    let output_path = output_dir.join("downloads/file.csv");
    let _ = fs::remove_dir_all(&output_dir);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_R2_ENDPOINT", r2_endpoint),
        ("CLOUDFLARE_MCP_R2_ACCESS_KEY_ID", fixture_material("r2-id")),
        (
            "CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY",
            fixture_material("r2-material"),
        ),
    ]);
    let response = mcp.call_tool(
        2,
        "r2_get_object",
        json!({
            "bucket_name": "bucket-a",
            "object_key": "folder/file.csv",
            "response_mode": "file",
            "output_path": output_path.to_string_lossy(),
            "create_parent_dirs": true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["encoding"], json!("file"));
    assert_eq!(content["bytes_written"], json!(13));
    assert_eq!(
        content["sha256"],
        json!("3859dd5cfe2b51951a9fad553d665d1999016f2c2d03c97d5702ca70aee1fade")
    );
    assert_eq!(content["content_type"], json!("text/csv"));
    assert_eq!(
        fs::read_to_string(&output_path).expect("read downloaded file"),
        "col1,col2\n1,2"
    );
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "HEAD /bucket-a/folder/file.csv",
            "GET /bucket-a/folder/file.csv"
        ]
    );
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn r2_get_object_can_persist_output_path_through_stdio_boundary() {
    let (r2_endpoint, requests) = spawn_fake_r2_api_with_requests(4);
    let output_dir =
        std::env::temp_dir().join(format!("cloudflare-mcp-r2-persist-{}", std::process::id()));
    let output_path = output_dir.join("persisted/file.csv");
    let state_file = output_dir.join("state/r2-output-path.json");
    let _ = fs::remove_dir_all(&output_dir);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_R2_ENDPOINT", r2_endpoint),
        (
            "CLOUDFLARE_MCP_R2_OUTPUT_PATH_STATE_FILE",
            state_file.to_string_lossy().to_string(),
        ),
        ("CLOUDFLARE_MCP_R2_ACCESS_KEY_ID", fixture_material("r2-id")),
        (
            "CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY",
            fixture_material("r2-material"),
        ),
    ]);
    let first = mcp.call_tool(
        2,
        "r2_get_object",
        json!({
            "bucket_name": "bucket-a",
            "object_key": "folder/file.csv",
            "response_mode": "file",
            "output_path": output_path.to_string_lossy(),
            "persist_output_path": true,
            "create_parent_dirs": true
        }),
    );
    let first_content = structured_content(&first);
    assert_eq!(first_content["ok"], json!(true), "{first_content}");
    assert_eq!(first_content["output_path_source"], json!("argument"));
    assert_eq!(first_content["persisted_output_path"], json!(true));

    let second = mcp.call_tool(
        3,
        "r2_get_object",
        json!({
            "bucket_name": "bucket-a",
            "object_key": "folder/file.csv",
            "response_mode": "file"
        }),
    );
    let second_content = structured_content(&second);
    assert_eq!(second_content["ok"], json!(true), "{second_content}");
    assert_eq!(
        second_content["output_path"],
        json!(output_path.to_string_lossy())
    );
    assert_eq!(second_content["output_path_source"], json!("persisted"));
    assert_eq!(second_content["persisted_output_path"], json!(true));
    assert_eq!(
        fs::read_to_string(&output_path).expect("read persisted output"),
        "col1,col2\n1,2"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&fs::read_to_string(&state_file).expect("read state"))
            .expect("parse state")["output_path"],
        json!(output_path.to_string_lossy())
    );
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "HEAD /bucket-a/folder/file.csv",
            "GET /bucket-a/folder/file.csv",
            "HEAD /bucket-a/folder/file.csv",
            "GET /bucket-a/folder/file.csv",
        ]
    );
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn r2_get_object_auto_writes_binary_to_file_through_stdio_boundary() {
    let (r2_endpoint, requests) = spawn_fake_r2_binary_api();
    let output_dir =
        std::env::temp_dir().join(format!("cloudflare-mcp-r2-binary-{}", std::process::id()));
    let output_path = output_dir.join("blob.dat");
    let _ = fs::remove_dir_all(&output_dir);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_R2_ENDPOINT", r2_endpoint),
        ("CLOUDFLARE_MCP_R2_ACCESS_KEY_ID", fixture_material("r2-id")),
        (
            "CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY",
            fixture_material("r2-material"),
        ),
    ]);
    let response = mcp.call_tool(
        2,
        "r2_get_object",
        json!({
            "bucket_name": "bucket-a",
            "object_key": "bin/blob.dat",
            "response_mode": "auto",
            "output_path": output_path.to_string_lossy(),
            "create_parent_dirs": true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["encoding"], json!("file"));
    assert_eq!(content["auto_switched_to_file"], json!(true));
    assert_eq!(content["content_type"], json!("application/octet-stream"));
    assert_eq!(
        content["sha256"],
        json!("1001fdad51f06efbb8281c57f03cf026d9ee39892a6224c35cb013fc0a5104fe")
    );
    assert_eq!(
        fs::read(&output_path).expect("read downloaded binary"),
        vec![0u8, 159, 146, 150, 255, 1, 2, 3]
    );
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        ["HEAD /bucket-a/bin/blob.dat", "GET /bucket-a/bin/blob.dat"]
    );
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn pages_deploy_directory_live_apply_uses_direct_upload_manifest_through_stdio_boundary() {
    let directory = create_static_pages_dir("live-apply");
    let (base_url, requests) = spawn_fake_pages_direct_upload_api(true);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "branch": "preview",
            "commit_hash": "abc123",
            "commit_message": "deploy via stdio smoke",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["deployment"]["id"], json!("deployment-1"));
    assert_eq!(content["upload"]["requested_asset_count"], json!(2));
    assert_eq!(content["upload"]["uploaded_asset_count"], json!(2));
    assert_eq!(content["upload"]["cached_asset_count"], json!(0));
    assert_eq!(content["upload"]["batch_count"], json!(1));
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "GET /accounts/acct-1/pages/projects/site/upload-token",
            "POST /pages/assets/check-missing",
            "POST /pages/assets/upload",
            "POST /pages/assets/upsert-hashes",
            "POST /accounts/acct-1/pages/projects/site/deployments",
        ]
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn pages_deploy_directory_live_apply_uploads_advanced_mode_worker_through_stdio_boundary() {
    let directory = create_pages_dir_with_worker("worker-apply");
    let (base_url, requests) =
        spawn_fake_pages_direct_upload_api_with_options(true, ExpectedWorkerUpload::Script);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "branch": "preview",
            "commit_hash": "abc123",
            "commit_message": "deploy _worker.js via stdio smoke",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["directory"]["special_files"]["worker"]["name"],
        json!("_worker.js")
    );
    assert_eq!(content["directory"]["asset_count"], json!(2));
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "GET /accounts/acct-1/pages/projects/site/upload-token",
            "POST /pages/assets/check-missing",
            "POST /pages/assets/upload",
            "POST /pages/assets/upsert-hashes",
            "POST /accounts/acct-1/pages/projects/site/deployments",
        ]
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn pages_deploy_directory_live_apply_uploads_single_module_worker_directory_through_stdio_boundary()
{
    let directory = pages_dir_with_worker_directory();
    let (base_url, requests) = spawn_fake_pages_direct_upload_api_with_options(
        true,
        ExpectedWorkerUpload::ScriptWithRoutes,
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "branch": "preview",
            "commit_hash": "abc123",
            "commit_message": "deploy _worker.js/index.js via stdio smoke",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["directory"]["special_files"]["worker"]["name"],
        json!("_worker.js")
    );
    assert_eq!(content["directory"]["asset_count"], json!(2));
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "GET /accounts/acct-1/pages/projects/site/upload-token",
            "POST /pages/assets/check-missing",
            "POST /pages/assets/upload",
            "POST /pages/assets/upsert-hashes",
            "POST /accounts/acct-1/pages/projects/site/deployments",
        ]
    );
}

#[test]
fn pages_deploy_directory_live_apply_uploads_worker_bundle_through_stdio_boundary() {
    let directory = create_pages_dir_with_worker_bundle("worker-bundle-apply");
    let (base_url, requests) =
        spawn_fake_pages_direct_upload_api_with_options(true, ExpectedWorkerUpload::Bundle);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "branch": "preview",
            "commit_hash": "abc123",
            "commit_message": "deploy _worker.bundle via stdio smoke",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["directory"]["special_files"]["worker_bundle"]["name"],
        json!("_worker.bundle")
    );
    assert_eq!(content["directory"]["asset_count"], json!(2));
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "GET /accounts/acct-1/pages/projects/site/upload-token",
            "POST /pages/assets/check-missing",
            "POST /pages/assets/upload",
            "POST /pages/assets/upsert-hashes",
            "POST /accounts/acct-1/pages/projects/site/deployments",
        ]
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn pages_deploy_directory_live_apply_bundles_pages_functions_through_stdio_boundary() {
    let (project_root, directory) = create_pages_project_with_functions("functions-apply");
    let wrangler = create_fake_wrangler("functions-apply");
    let (base_url, requests) = spawn_fake_pages_direct_upload_api_with_options(
        true,
        ExpectedWorkerUpload::FunctionsBundle,
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_WRANGLER_BIN",
            wrangler.display().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "project_root": project_root.to_string_lossy(),
            "branch": "preview",
            "commit_hash": "abc123",
            "commit_message": "deploy Pages Functions via stdio smoke",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["directory"]["functions"]["detected"], json!(true));
    assert_eq!(content["directory"]["functions"]["included"], json!(true));
    assert_eq!(
        content["directory"]["special_files"]["worker_bundle"]["name"],
        json!("_worker.bundle")
    );
    assert_eq!(
        content["directory"]["special_files"]["functions_filepath_routing_config"]["name"],
        json!("functions-filepath-routing-config.json")
    );
    let request_log = requests.lock().expect("request log lock").clone();
    assert_eq!(
        request_log.first().map(String::as_str),
        Some("GET /accounts/acct-1/pages/projects/site/upload-token")
    );
    assert!(request_log.contains(&"POST /pages/assets/check-missing".to_string()));
    assert!(request_log.contains(&"POST /pages/assets/upload".to_string()));
    assert_eq!(
        request_log.last().map(String::as_str),
        Some("POST /accounts/acct-1/pages/projects/site/deployments")
    );
    let _ = fs::remove_dir_all(project_root);
    let _ = fs::remove_dir_all(wrangler.parent().expect("fake wrangler parent"));
}

#[test]
fn pages_deploy_directory_rejects_routes_without_worker_through_stdio_boundary() {
    let directory = create_pages_dir_with_routes_only("routes-only");
    let mut mcp = McpStdioProcess::start();
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "branch": "production",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("pages.routes_without_worker")
    );
    assert!(
        content["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("Use Wrangler")
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn pages_deploy_directory_skip_caching_uploads_without_check_missing_through_stdio_boundary() {
    let directory = create_static_pages_dir("skip-caching");
    let (base_url, requests) = spawn_fake_pages_direct_upload_api(false);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "pages_deploy_directory",
        json!({
            "project_name": "site",
            "directory": directory.to_string_lossy(),
            "branch": "preview",
            "skip_caching": true,
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["upload"]["skip_caching"], json!(true));
    assert_eq!(content["upload"]["uploaded_asset_count"], json!(2));
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        [
            "GET /accounts/acct-1/pages/projects/site/upload-token",
            "POST /pages/assets/upload",
            "POST /pages/assets/upsert-hashes",
            "POST /accounts/acct-1/pages/projects/site/deployments",
        ]
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn pages_trigger_deployment_rejects_direct_upload_project_before_manifest_error() {
    let (base_url, requests) = spawn_fake_pages_direct_upload_project_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "pages_trigger_deployment",
        json!({
            "project_name": "direct-only",
            "branch": "main",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("pages.trigger_requires_git_source")
    );
    assert_eq!(
        requests.lock().expect("request log lock").as_slice(),
        ["GET /accounts/acct-1/pages/projects/direct-only"]
    );
}

#[test]
fn d1_inspect_schema_works_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "d1_inspect_schema",
        json!({
            "database_id": "db-1",
            "include_columns": true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["schema"]["discovery_strategy"],
        json!("sqlite_master")
    );
    assert_eq!(
        content["schema"]["objects"][0]["name"],
        json!("submissions")
    );
    assert_eq!(content["schema"]["columns"][0]["column_name"], json!("id"));
}

#[test]
fn d1_inspect_schema_skips_internal_and_filters_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "d1_inspect_schema",
        json!({
            "database_id": "db-1",
            "include_columns": true,
            "include_tables": ["submissions"]
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["schema"]["summary"]["message"],
        json!("schema returned for application tables; internal Cloudflare tables skipped")
    );
    assert_eq!(
        content["schema"]["objects"],
        json!([{
            "type": "table",
            "name": "submissions",
            "tbl_name": "submissions",
            "sql": "CREATE TABLE submissions (id TEXT)"
        }])
    );
    assert_eq!(
        content["schema"]["skipped_internal_tables"][0]["name"],
        json!("_cf_KV")
    );
    assert!(content["schema"]["column_errors"].is_null(), "{content}");
    assert_eq!(
        content["schema"]["filter"]["matched_application_objects"],
        json!(1)
    );
}

#[test]
fn d1_validate_query_works_through_stdio_boundary_without_executing_user_query() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "d1_validate_query",
        json!({
            "database_id": "db-1",
            "sql": "SELECT id FROM submissions",
            "include_query_plan": true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["executed_user_query"], json!(false));
    assert_eq!(content["validation"]["ok"], json!(true));
    assert_eq!(content["query_plan"]["available"], json!(true));
}

#[test]
fn d1_apply_migrations_skips_wrangler_applied_files_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_d1_migrations_api(3, false);
    let dir = std::env::temp_dir().join(format!("cloudflare-mcp-d1-stdio-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create migrations dir");
    fs::write(
        dir.join("0001_initial.sql"),
        "CREATE TABLE submissions(id TEXT);",
    )
    .expect("write migration 1");
    fs::write(
        dir.join("0002_second.sql"),
        "ALTER TABLE submissions ADD COLUMN status TEXT;",
    )
    .expect("write migration 2");

    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "d1_apply_migrations",
        json!({
            "database_id": "db-1",
            "migrations_directory": dir.to_string_lossy(),
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["already_applied"][0], json!("0001_initial.sql"));
    assert_eq!(
        content["skipped_migrations"][0]["name"],
        json!("0001_initial.sql")
    );
    assert_eq!(
        content["applied_migrations"][0]["name"],
        json!("0002_second.sql")
    );
    let requests = requests.lock().expect("request log lock").clone();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0]["sql"]
            .as_str()
            .unwrap()
            .starts_with("CREATE TABLE IF NOT EXISTS \"d1_migrations\"")
    );
    assert_eq!(
        requests[1]["sql"],
        json!("SELECT * FROM \"d1_migrations\" ORDER BY id")
    );
    let apply_sql = requests[2]["sql"].as_str().unwrap();
    assert!(apply_sql.contains("ADD COLUMN status"));
    assert!(apply_sql.contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0002_second.sql')"));
    assert!(!apply_sql.contains("0001_initial"));
    let content_text = serde_json::to_string(content).expect("content json");
    assert!(!content_text.contains("ADD COLUMN status"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn d1_apply_migrations_fails_closed_on_unreadable_ledger_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_d1_migrations_api(2, true);
    let dir = std::env::temp_dir().join(format!(
        "cloudflare-mcp-d1-ledger-fail-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create migrations dir");
    fs::write(
        dir.join("0001_initial.sql"),
        "CREATE TABLE submissions(id TEXT);",
    )
    .expect("write migration 1");

    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "d1_apply_migrations",
        json!({
            "database_id": "db-1",
            "migrations_directory": dir.to_string_lossy(),
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["unknown_ledger"], json!(true));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_ledger_unreadable")
    );
    assert_eq!(
        requests.lock().expect("request log lock").len(),
        2,
        "migration SQL must not execute after ledger read failure"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn d1_apply_migration_manifest_dry_run_reaches_stdio_and_never_sends_sql_bytes() {
    let (base_url, requests) = spawn_fake_d1_migrations_api(1, false);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let first_sql = "CREATE TABLE submissions(id TEXT);";
    let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let response = mcp.call_tool(
        3,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "dry_run": true,
            "manifest": [
                {
                    "name": "0001_initial.sql",
                    "size_bytes": first_sql.len(),
                    "sql_sha256": sha256_hex(first_sql),
                    "sql": first_sql,
                },
                {
                    "name": "0002_second.sql",
                    "size_bytes": second_sql.len(),
                    "sql_sha256": sha256_hex(second_sql),
                    "sql": second_sql,
                }
            ]
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["pending_migrations"][0]["name"],
        json!("0002_second.sql")
    );
    assert_eq!(content["plan_sha256"].as_str().map(str::len), Some(64));
    assert_eq!(requests.lock().expect("requests lock").len(), 1);
    assert!(
        !serde_json::to_string(content)
            .expect("content json")
            .contains(second_sql)
    );
}

#[test]
fn d1_apply_migration_manifest_rejects_malformed_ledger_before_any_provider_write() {
    for (index, (label, result_set)) in [
        ("missing success", json!({"results": []})),
        ("false success", json!({"success": false, "results": []})),
        (
            "nonboolean success",
            json!({"success": "true", "results": []}),
        ),
        ("missing results", json!({"success": true})),
        ("null results", json!({"success": true, "results": null})),
        ("nonarray results", json!({"success": true, "results": {}})),
        (
            "contradictory errors",
            json!({"success": true, "errors": [{"code": 1}], "results": []}),
        ),
        (
            "malformed errors",
            json!({"success": true, "errors": {}, "results": []}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) = spawn_fake_manifest_malformed_ledger_api(result_set);
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-malformed-ledger-manifest-{index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make lease root private");
        }
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
        let manifest = json!([
            {"name": "0001_initial.sql", "size_bytes": "CREATE TABLE submissions(id TEXT);".len(), "sql_sha256": sha256_hex("CREATE TABLE submissions(id TEXT);"), "sql": "CREATE TABLE submissions(id TEXT);"},
            {"name": "0002_second.sql", "size_bytes": sql.len(), "sql_sha256": sha256_hex(sql), "sql": sql}
        ]);
        let response = mcp.call_tool(
            40 + index as u64,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
                "approved_plan_sha256": "a".repeat(64),
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_ledger_malformed"),
            "{label}"
        );
        let observed = requests.lock().expect("requests lock").clone();
        assert_eq!(observed.len(), 1, "{label}");
        assert!(
            observed.iter().all(|request| !request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\""))),
            "{label} must never reach a provider write"
        );
        assert_released_manifest_target_custody(&lease_root);
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_outer_ledger_errors_release_pre_write_lease() {
    for (index, (label, outer_errors)) in [
        (
            "contradictory",
            Some(json!([{"code": 1, "message": "contradictory"}])),
        ),
        (
            "malformed",
            Some(json!({"code": 1, "message": "malformed"})),
        ),
        ("omitted", None),
        ("null", Some(Value::Null)),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) = spawn_fake_manifest_outer_error_api(outer_errors, false);
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-outer-ledger-error-{index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make lease root private");
        }
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let first_sql = "CREATE TABLE submissions(id TEXT);";
        let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
        let manifest = json!([
            {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
            {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
        ]);
        let dry = mcp.call_tool(
            50 + index as u64 * 2,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
            }),
        );
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("plan")
            .to_string();
        let live = mcp.call_tool(
            51 + index as u64 * 2,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
                "approved_plan_sha256": plan,
            }),
        );
        let content = structured_content(&live);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["status"],
            json!("reconciliation_required"),
            "{label}"
        );
        assert_eq!(content["unknown_ledger"], json!(true), "{label}");
        let observed = requests.lock().expect("requests lock").clone();
        assert_eq!(observed.len(), 2, "{label}");
        assert!(
            observed.iter().all(|request| !request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\""))),
            "{label} must fail before a migration provider write"
        );
        assert_released_manifest_target_custody(&lease_root);
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_outer_write_errors_remain_unknown_and_retain_lease() {
    for (index, (label, outer_errors)) in [
        (
            "contradictory",
            Some(json!([{"code": 1, "message": "contradictory"}])),
        ),
        (
            "malformed",
            Some(json!({"code": 1, "message": "malformed"})),
        ),
        ("omitted", None),
        ("null", Some(Value::Null)),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) = spawn_fake_manifest_outer_error_api(outer_errors, true);
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-outer-write-error-{index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make lease root private");
        }
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url.clone()),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let first_sql = "CREATE TABLE submissions(id TEXT);";
        let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
        let manifest = json!([
            {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
            {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
        ]);
        let dry = mcp.call_tool(
            60 + index as u64 * 2,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
            }),
        );
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("plan")
            .to_string();
        let live = mcp.call_tool(
            61 + index as u64 * 2,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest.clone(),
                "approved_plan_sha256": plan.clone(),
            }),
        );
        let content = structured_content(&live);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["status"],
            json!("reconciliation_required"),
            "{label}"
        );
        assert_eq!(content["outcome"], json!("unknown"), "{label}");
        assert_eq!(content["lease_retained"], json!(true), "{label}");
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_apply_outcome_unknown"),
            "{label}"
        );
        let observed = requests.lock().expect("requests lock").clone();
        assert_eq!(observed.len(), 6, "{label} must not retry the write");
        assert_eq!(
            observed
                .iter()
                .filter(|request| request["sql"]
                    .as_str()
                    .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
                .count(),
            1,
            "{label} must issue one non-idempotent write"
        );
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        assert_fresh_process_blocked_without_provider_request(
            vec![
                ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
                (
                    "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                    lease_root.to_string_lossy().to_string(),
                ),
            ],
            &manifest,
            &plan,
            &requests,
            6,
            label,
        );
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_live_rechecks_plan_and_stably_reads_back_before_release() {
    let (base_url, requests) = spawn_fake_manifest_apply_api();
    // The custody contract rejects the shared build TMPDIR's writable ancestor.
    // `/tmp` is sticky on Unix and therefore a safe parent for this fixture.
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-manifest-lease-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let first_sql = "CREATE TABLE submissions(id TEXT);";
    let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
        {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
    ]);
    let dry = mcp.call_tool(4, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let dry_content = structured_content(&dry);
    let plan = dry_content["plan_sha256"]
        .as_str()
        .expect("plan digest")
        .to_string();
    let live = mcp.call_tool(
        5,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
            "approved_plan_sha256": plan,
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["status"], json!("applied"));
    assert_eq!(
        content["applied_migrations"][0]["sql_sha256"],
        json!(sha256_hex(second_sql))
    );
    assert_released_manifest_target_custody(&lease_root);
    let requests = requests.lock().expect("requests lock").clone();
    assert_eq!(
        requests.len(),
        6,
        "dry, stable re-read, apply, stable post-apply reads"
    );
    assert!(
        requests[3]["sql"]
            .as_str()
            .expect("apply SQL")
            .contains(second_sql)
    );
    assert!(
        !requests[3]["sql"]
            .as_str()
            .expect("apply SQL")
            .contains(first_sql)
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_manifest_crashed_stdio_holder_retains_active_evidence_and_contender_never_calls_provider() {
    let (base_url, requests, entered, resume) = spawn_blocked_manifest_preflight_api();
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-manifest-crash-custody-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let first_sql = "CREATE TABLE submissions(id TEXT);";
    let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
        {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
    ]);
    let mut holder = McpStdioProcess::start_with_env(env.clone());
    let dry = holder.call_tool(70, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("plan digest")
        .to_string();
    holder.send(json!({
        "jsonrpc": "2.0", "id": 71, "method": "tools/call",
        "params": {"name": "d1_apply_migration_manifest", "arguments": {
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest.clone(), "approved_plan_sha256": plan.clone()
        }}
    }));
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("holder has created active evidence and is blocked in preflight");

    let mut contender = McpStdioProcess::start_with_env(env.clone());
    let response = contender.call_tool(72, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "different-family", "manifest": manifest.clone(), "approved_plan_sha256": plan.clone(),
    }));
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_target_guard_locked")
    );
    assert_eq!(
        requests.lock().expect("request log").len(),
        2,
        "the concurrent MCP process must stop at the held target guard without a provider request"
    );
    holder.terminate();
    drop(contender);

    let mut recovered_contender = McpStdioProcess::start_with_env(env);
    let response = recovered_contender.call_tool(73, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "different-family", "manifest": manifest, "approved_plan_sha256": plan,
    }));
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_target_lease_held")
    );
    assert_eq!(
        requests.lock().expect("request log").len(),
        2,
        "the next MCP process after the holder exits must stop at active evidence without a provider request"
    );
    let target = manifest_target_path(&lease_root);
    let active_metadata =
        fs::symlink_metadata(target.join("active.lease.json")).expect("active lease metadata");
    assert!(active_metadata.is_file() && !active_metadata.file_type().is_symlink());
    resume.send(()).expect("release fake preflight handler");
    drop(recovered_contender);
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_response_loss_stops_without_retry_and_next_process_is_blocked() {
    let (base_url, requests) = spawn_fake_manifest_ambiguous_api(false);
    // Keep this retained-lease fixture under the sticky system temporary root.
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-ambiguous-manifest-lease-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let mut mcp = McpStdioProcess::start_with_env(env.clone());
    let first_sql = "CREATE TABLE submissions(id TEXT);";
    let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
        {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
    ]);
    let dry = mcp.call_tool(6, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("plan")
        .to_string();
    let live = mcp.call_tool(
        7,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest.clone(),
            "approved_plan_sha256": plan.clone(),
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_apply_outcome_unknown")
    );
    assert_eq!(
        content["error"]["cause"]["kind"],
        json!("transport"),
        "the provider category remains available for diagnosis"
    );
    assert_eq!(
        content["error"]["cause"]["code"],
        json!("cloudflare.http_server_error")
    );
    assert_eq!(content["error"]["cause"]["status"], json!(503));
    assert_eq!(content["error"]["cause"]["retryable"], json!(false));
    assert_eq!(
        content["error"]["cause"]["operator_guidance"],
        json!("reconciliation_only")
    );
    assert!(
        content["error"]["cause"].get("hint").is_none()
            && content["error"]["cause"].get("classification").is_none(),
        "nested provider guidance must not advise retry after the non-idempotent write"
    );
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(content["outcome"], json!("unknown"));
    assert_eq!(
        content["audit"]["action"],
        json!("d1_apply_migration_manifest")
    );
    assert!(content["audit"]["correlation"]["correlation_id"].is_string());
    assert_eq!(
        content["plan"]["operation"],
        json!("d1_apply_migration_manifest")
    );
    assert!(content["plan"]["steps"].is_array());
    assert!(content["audit"]["target"]["target_key_sha256"].is_string());
    let observed = requests.lock().expect("requests lock").clone();
    assert_eq!(
        observed.len(),
        6,
        "dry, stable re-read, one apply, stable reconciliation reads; no retry"
    );
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
            .count(),
        1,
        "a retryable HTTP status after a non-idempotent write must not issue a second write"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    assert_fresh_process_blocked_without_provider_request(
        env,
        &manifest,
        &plan,
        &requests,
        6,
        "response loss",
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_wraps_semantic_validation_in_fixed_order() {
    fn args(manifest: Value, migration_family: &str) -> Value {
        json!({
            "account_id": "acct-1",
            "database_id": "db-1",
            "migration_family": migration_family,
            "manifest": manifest,
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": [],
        })
    }

    let sql = "CREATE TABLE items(id INTEGER PRIMARY KEY);";
    let valid_manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": sql.len(),
        "sql_sha256": sha256_hex(sql),
        "sql": sql,
    }]);
    let mut digest_drift = valid_manifest.clone();
    digest_drift[0]["sql_sha256"] = json!("0".repeat(64));

    let mut invalid_target = args(json!([]), "bad family");
    invalid_target["account_id"] = json!(" acct-1");
    invalid_target["migrations_table"] = json!("bad-name");
    let mut invalid_table = args(json!([]), "bad family");
    invalid_table["migrations_table"] = json!("bad-name");
    let cases = [
        (
            "target precedes every later invalid field",
            invalid_target,
            expected_d1_reconciliation_semantic_error(
                "d1.invalid_manifest_target_identity",
                "account_id must be a non-empty canonical identifier, not a dot path segment, and without surrounding whitespace",
                "Use the exact account_id and database_id read from the intended Cloudflare resource.",
            ),
        ),
        (
            "table precedes manifest and family",
            invalid_table,
            expected_d1_reconciliation_semantic_error(
                "d1.invalid_migrations_table",
                "migrations_table must be an ASCII SQL identifier with at most 64 characters",
                "Use a simple table name such as d1_migrations.",
            ),
        ),
        (
            "empty manifest precedes family",
            args(json!([]), "bad family"),
            expected_d1_reconciliation_semantic_error(
                "d1.empty_migration_manifest",
                "manifest must contain at least one exact migration",
                "Provide the complete approved migration manifest in lexical Wrangler order.",
            ),
        ),
        (
            "manifest digest drift precedes family",
            args(digest_drift, "bad family"),
            expected_d1_reconciliation_semantic_error(
                "d1.manifest_sha256_mismatch",
                "manifest sql_sha256 does not match the supplied exact SQL bytes",
                "Recompute SHA-256 from the same SQL string that will be applied.",
            ),
        ),
        (
            "family is wrapped after earlier fields validate",
            args(valid_manifest, "bad family"),
            expected_d1_reconciliation_semantic_error(
                "d1.invalid_migration_family",
                "migration_family must be 1..128 ASCII letters, digits, '.', '_', '-', or ':' characters",
                "Use a stable operator-facing family label such as newsletter-core.",
            ),
        ),
    ];
    let mut mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_API_BASE_URL",
        "http://127.0.0.1:9".to_string(),
    )]);
    for (index, (label, arguments, expected)) in cases.into_iter().enumerate() {
        let response = mcp.call_tool(
            730 + index as u64,
            "d1_reconcile_migration_manifest",
            arguments,
        );
        assert_eq!(structured_content(&response), &expected, "{label}");
    }

    let schema_error = mcp.call_tool(
        735,
        "d1_reconcile_migration_manifest",
        json!({"database_id": 42}),
    );
    assert_eq!(
        schema_error,
        json!({
            "jsonrpc": "2.0",
            "id": 735,
            "result": {
                "content": [{
                    "type": "text",
                    "text": "failed to deserialize parameters: invalid type: integer `42`, expected a string",
                }],
                "isError": true,
            },
        }),
        "schema parsing must remain outside semantic tool execution",
    );
    mcp.terminate();
}

#[test]
fn d1_reconcile_migration_manifest_proves_stable_full_state_without_retry_or_mutation() {
    let (base_url, requests) = spawn_fake_reconciliation_api();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-manifest-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create reconciliation lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make reconciliation root private");
    }
    let migration_sql = "CREATE TABLE items(id INTEGER PRIMARY KEY);";
    let manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": migration_sql.len(),
        "sql_sha256": sha256_hex(migration_sql),
        "sql": migration_sql,
    }]);
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let retained_before =
        fs::read(assert_private_regular_active_lease(&lease_root)).expect("read retained before");
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        740,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {
                    "manifest_prefix_length": 1,
                    "schema_objects": [{
                        "object_type": "table",
                        "name": "items",
                        "table_name": "items",
                        "sql_sha256": sha256_hex("CREATE TABLE items(id INTEGER PRIMARY KEY)"),
                    }],
                    "tables": [{
                        "name": "items",
                        "columns": [{
                            "cid": 0,
                            "name": "id",
                            "declared_type": "INTEGER",
                            "not_null": false,
                            "default_value": null,
                            "primary_key_position": 1,
                            "hidden": 0,
                        }],
                        "foreign_keys": [],
                    }],
                }
            ],
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["outcome"], json!("full_state_converged"));
    assert_eq!(
        content["retry_decision"],
        json!("do_not_retry_same_attempt")
    );
    assert_eq!(content["lease_decision"], json!("retain"));
    assert_eq!(content["provider_calls"], json!(2));
    assert_eq!(
        content["provider_read_lifecycle"],
        json!([
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            }
        ])
    );
    assert_eq!(content["provider_mutations"], json!(0));
    assert_eq!(content["local_namespace_mutations"], json!(0));
    assert!(content["query_sha256"].as_str().is_some());
    assert!(content["canonical_snapshot_sha256"].as_str().is_some());
    assert!(content["reconciliation_plan_sha256"].as_str().is_some());
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(2)
    );
    let observed = requests.lock().expect("request log");
    assert_eq!(observed.len(), 2, "exactly two complete batches");
    for request in observed.iter() {
        let sql = request["sql"].as_str().expect("fixed reconciliation SQL");
        assert!(sql.split(';').all(|statement| {
            statement.trim().is_empty() || statement.trim_start().starts_with("SELECT ")
        }));
        assert!(!sql.contains("INSERT"));
        assert!(!sql.contains("UPDATE"));
        assert!(!sql.contains("DELETE"));
    }
    drop(observed);
    let retained_after =
        fs::read(assert_private_regular_active_lease(&lease_root)).expect("read retained after");
    assert_eq!(
        retained_after, retained_before,
        "retained evidence is immutable"
    );
    assert!(retired_manifest_entries(&manifest_target_path(&lease_root)).is_empty());
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_rejects_unproven_effects_and_incomplete_expectations_before_custody()
 {
    let data_create = "CREATE TABLE items AS VALUES (1);";
    let data_manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": data_create.len(),
        "sql_sha256": sha256_hex(data_create),
        "sql": data_create,
    }]);
    let mut mcp = McpStdioProcess::start();
    let rejected_effect = mcp.call_tool(
        741,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": data_manifest,
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {"manifest_prefix_length": 1, "schema_objects": [], "tables": []}
            ],
        }),
    );
    let content = structured_content(&rejected_effect);
    assert_eq!(
        content,
        &json!({
            "ok": false,
            "operation": "d1_reconcile_migration_manifest",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "outcome": "unknown",
            "capability_state": "capability_gap",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "not_acquired",
            "lease_retained": null,
            "custody_status": "not_inspected",
            "query_sha256": null,
            "response_evidence": [],
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_reconciliation_effect_proof_unavailable",
                "message": "the built-in effect registry cannot exactly prove arbitrary DML, ALTER, DROP, PRAGMA, trigger, view, virtual table, or data-producing CREATE effects",
                "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result."
            }
        }),
        "{content}"
    );

    let schema_create = "CREATE TABLE items(id INTEGER PRIMARY KEY);";
    let schema_manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": schema_create.len(),
        "sql_sha256": sha256_hex(schema_create),
        "sql": schema_create,
    }]);
    let omitted_schema = mcp.call_tool(
        742,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": schema_manifest.clone(),
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {"manifest_prefix_length": 1, "schema_objects": [], "tables": []}
            ],
        }),
    );
    let content = structured_content(&omitted_schema);
    assert_eq!(
        content,
        &json!({
            "ok": false,
            "operation": "d1_reconcile_migration_manifest",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "outcome": "unknown",
            "capability_state": "contradictory",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "not_acquired",
            "lease_retained": null,
            "custody_status": "not_inspected",
            "query_sha256": null,
            "response_evidence": [],
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_reconciliation_schema_expectation_incomplete",
                "message": "schema object expectations must exactly match every CREATE target derived from the manifest prefix",
                "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result."
            }
        }),
        "{content}"
    );

    let inspection_failed = mcp.call_tool(
        743,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": schema_manifest,
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {
                    "manifest_prefix_length": 1,
                    "schema_objects": [{
                        "object_type": "table",
                        "name": "items",
                        "table_name": "items",
                        "sql_sha256": sha256_hex("CREATE TABLE items(id INTEGER PRIMARY KEY)"),
                    }],
                    "tables": [{
                        "name": "items",
                        "columns": [{
                            "cid": 0,
                            "name": "id",
                            "declared_type": "INTEGER",
                            "not_null": false,
                            "default_value": null,
                            "primary_key_position": 1,
                            "hidden": 0,
                        }],
                        "foreign_keys": [],
                    }],
                }
            ],
        }),
    );
    let content = structured_content(&inspection_failed);
    let query_sha256 = content["query_sha256"]
        .as_str()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .expect("canonical fixed-query SHA-256")
        .to_string();
    assert_eq!(
        content,
        &json!({
            "ok": false,
            "operation": "d1_reconcile_migration_manifest",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "not_acquired",
            "lease_retained": null,
            "custody_status": "inspection_failed",
            "query_sha256": query_sha256,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_reconciliation_lease_root_unconfigured",
                "message": "read-only reconciliation requires the configured operator-owned migration lease root",
                "hint": "Retain the exact custody evidence and resolve this boundary before any provider read or migration retry."
            }
        }),
        "{content}"
    );
    mcp.terminate();
}

#[test]
fn d1_reconcile_migration_manifest_stdio_requires_primary_current_evidence_for_every_result_set() {
    let (manifest, expectations) = one_table_reconciliation_case();
    for (index, (fault, expected_calls)) in [
        (ReconciliationFault::PrimaryMetaMissing, 1),
        (ReconciliationFault::PrimaryMarkerMissing, 1),
        (ReconciliationFault::PrimaryMarkerFalse, 1),
        (ReconciliationFault::PrimaryMarkerNull, 1),
        (ReconciliationFault::PrimaryMarkerWrongType, 1),
        (ReconciliationFault::MixedPrimaryMarkers, 1),
        (ReconciliationFault::SecondBatchPrimaryFalse, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-reconcile-primary-{}-{index}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create primary reconciliation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make primary reconciliation root private");
        }
        let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
            create_retained_reconciliation_fixture(&lease_root, &manifest);
        let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(fault);
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let response = mcp.call_tool(
            730 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_only_v1",
                "state_expectations": expectations.clone(),
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{content}");
        assert_eq!(content["capability_state"], json!("contradictory"));
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_reconciliation_primary_evidence_contradictory"),
            "{content}"
        );
        assert_eq!(
            content["retry_decision"],
            json!("do_not_retry_same_attempt")
        );
        assert_eq!(content["lease_retained"], json!(true), "{content}");
        assert_eq!(
            content["custody_status"],
            json!("retained_evidence_verified"),
            "{content}"
        );
        assert_eq!(
            content["provider_calls"],
            json!(expected_calls),
            "{content}"
        );
        assert_eq!(
            content["response_evidence"].as_array().map(Vec::len),
            Some(expected_calls),
            "{content}"
        );
        assert_eq!(requests.lock().expect("request log").len(), expected_calls);
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_reconcile_migration_manifest_stdio_reports_pre_dispatch_without_provider_call() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-no-token-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create no-token reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make no-token reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let (base_url, requests) = spawn_fake_reconciliation_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        ("CLOUDFLARE_MCP_API_TOKEN", String::new()),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        738,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": expectations,
        }),
    );
    let content = structured_content(&response);
    let query_sha256 = content["query_sha256"].clone();
    assert_eq!(
        content,
        &json!({
            "ok": false,
            "operation": "d1_reconcile_migration_manifest",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "outcome": "unknown",
            "capability_state": "capability_gap",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "retain",
            "lease_retained": true,
            "custody_status": "retained_evidence_verified",
            "query_sha256": query_sha256,
            "response_evidence": [],
            "provider_read_lifecycle": [{
                "dispatch_stage": "pre_dispatch",
                "response_stage": "not_received",
                "body_stage": "not_read",
                "http_status": null,
            }],
            "provider_calls": 0,
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "provider_cause": {
                "code": "cloudflare.config_missing_token",
                "status": null,
                "retryable": false,
                "operator_guidance": "reconciliation_only",
            },
            "error": {
                "code": "d1.migration_reconciliation_query_capability_gap",
                "message": "provider could not return one complete strict read-only reconciliation batch",
                "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
            },
        }),
        "{content}"
    );
    assert_eq!(requests.lock().expect("request log").len(), 0);
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_does_not_follow_redirects() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-redirect-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create redirect reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make redirect reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let (base_url, requests) =
        spawn_fake_reconciliation_api_with_fault(ReconciliationFault::Redirect);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        739,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": expectations,
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["capability_state"], json!("contradictory"));
    assert_eq!(content["provider_cause"]["status"], json!(302));
    assert_eq!(content["provider_calls"], json!(1));
    assert_eq!(
        content["provider_read_lifecycle"],
        json!([{
            "dispatch_stage": "attempted",
            "response_stage": "received",
            "body_stage": "completely_read",
            "http_status": 302,
        }]),
        "{content}"
    );
    assert_eq!(requests.lock().expect("request log").len(), 1);
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_rejects_marker_metadata_and_oversized_provider_evidence() {
    let migration_sql = "CREATE TABLE items(id INTEGER PRIMARY KEY);";
    let manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": migration_sql.len(),
        "sql_sha256": sha256_hex(migration_sql),
        "sql": migration_sql,
    }]);
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "items",
                "table_name": "items",
                "sql_sha256": sha256_hex("CREATE TABLE items(id INTEGER PRIMARY KEY)"),
            }],
            "tables": [{
                "name": "items",
                "columns": [{
                    "cid": 0,
                    "name": "id",
                    "declared_type": "INTEGER",
                    "not_null": false,
                    "default_value": null,
                    "primary_key_position": 1,
                    "hidden": 0,
                }],
                "foreign_keys": [],
            }],
        }
    ]);
    for (index, (fault, expected_code)) in [
        (
            ReconciliationFault::WrongStatementMarker,
            "d1.migration_reconciliation_statement_marker_malformed",
        ),
        (
            ReconciliationFault::MalformedReadOnlyMetadata,
            "d1.migration_reconciliation_read_only_meta_contradictory",
        ),
        (
            ReconciliationFault::MalformedJsonStatus(200),
            "d1.migration_reconciliation_provider_evidence_contradictory",
        ),
        (
            ReconciliationFault::OversizedResponse,
            "d1.migration_reconciliation_provider_evidence_contradictory",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(fault);
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-reconcile-negative-{}-{index}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create negative reconciliation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make negative reconciliation root private");
        }
        let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
            create_retained_reconciliation_fixture(&lease_root, &manifest);
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let response = mcp.call_tool(
            750 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_only_v1",
                "state_expectations": expectations.clone(),
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{content}");
        assert_eq!(content["error"]["code"], json!(expected_code), "{content}");
        assert_eq!(content["lease_retained"], json!(true), "{content}");
        assert_eq!(
            content["custody_status"],
            json!("retained_evidence_verified"),
            "{content}"
        );
        assert_eq!(requests.lock().expect("request log").len(), 1);
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_reconcile_migration_manifest_stdio_keeps_drifted_custody_unverified() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create drift reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make drift reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let active = assert_private_regular_active_lease(&lease_root);
    let (base_url, requests) =
        spawn_fake_reconciliation_api_with_fault(ReconciliationFault::CustodyDrift(active));
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        760,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": expectations,
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_reconciliation_lease_changed"),
        "{content}"
    );
    assert_eq!(content["lease_decision"], json!("retain"), "{content}");
    assert_eq!(content["lease_retained"], Value::Null, "{content}");
    assert_eq!(
        content["custody_status"],
        json!("retained_evidence_unverified"),
        "{content}"
    );
    assert_eq!(content["provider_calls"], json!(1), "{content}");
    assert_eq!(requests.lock().expect("request log").len(), 1);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_preserves_identical_reads_after_second_custody_drift() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-second-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create second-drift reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make second-drift reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let active = assert_private_regular_active_lease(&lease_root);
    let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(
        ReconciliationFault::SecondBatchCustodyDrift(active),
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        766,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": expectations,
        }),
    );
    let content = structured_content(&response);
    let query_sha256 = content["query_sha256"].clone();
    let evidence = content["response_evidence"]
        .as_array()
        .expect("two chronological response summaries");
    assert_eq!(evidence.len(), 2, "{content}");
    assert_eq!(evidence[0], evidence[1], "{content}");
    let response_summary = evidence[0].clone();
    let lifecycle = response_summary["lifecycle"].clone();
    assert_eq!(
        content,
        &json!({
            "ok": false,
            "operation": "d1_reconcile_migration_manifest",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "retain",
            "lease_retained": null,
            "custody_status": "retained_evidence_unverified",
            "query_sha256": query_sha256,
            "response_evidence": [response_summary.clone(), response_summary],
            "provider_read_lifecycle": [lifecycle.clone(), lifecycle],
            "provider_calls": 2,
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_reconciliation_lease_changed",
                "message": "retained lease payload digest changed",
                "hint": "Retain the exact custody evidence and resolve this boundary before any provider read or migration retry.",
            },
        }),
        "{content}"
    );
    assert_eq!(requests.lock().expect("request log").len(), 2);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_revalidates_custody_after_provider_error() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-provider-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create provider drift reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make provider drift reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let active = assert_private_regular_active_lease(&lease_root);
    let expected_response = reconciliation_http_error_response(503);
    let expected_response_sha256 =
        sha256_hex(std::str::from_utf8(&expected_response).expect("synthetic HTTP error is UTF-8"));
    let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(
        ReconciliationFault::HttpStatusCustodyDrift(503, active),
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        762,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": expectations,
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["capability_state"], json!("unavailable"));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_reconciliation_provider_unavailable")
    );
    assert_eq!(
        content["custody_cause"]["code"],
        json!("d1.migration_reconciliation_lease_changed")
    );
    assert_eq!(content["lease_retained"], Value::Null, "{content}");
    assert_eq!(
        content["custody_status"],
        json!("retained_evidence_unverified"),
        "{content}"
    );
    assert_eq!(content["provider_calls"], json!(1), "{content}");
    assert_eq!(
        content["response_evidence"][0]["response_body_sha256"],
        json!(expected_response_sha256),
        "{content}"
    );
    assert_eq!(requests.lock().expect("request log").len(), 1);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_keeps_post_read_contradictions_verified() {
    let (manifest, expectations) = one_table_reconciliation_case();
    for (index, (fault, expected_code, expected_message)) in [
        (
            ReconciliationFault::UnstableSecondBatch,
            "d1.migration_reconciliation_evidence_unstable",
            "two complete read-only reconciliation batches were not canonically equivalent",
        ),
        (
            ReconciliationFault::LedgerNotManifestPrefix,
            "d1.migration_reconciliation_ledger_not_manifest_prefix",
            "stable migration ledger is not an exact prefix of the supplied manifest",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-reconcile-post-read-{}-{index}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create post-read reconciliation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make post-read reconciliation root private");
        }
        let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
            create_retained_reconciliation_fixture(&lease_root, &manifest);
        let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(fault);
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let response = mcp.call_tool(
            761 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_only_v1",
                "state_expectations": expectations.clone(),
            }),
        );
        let content = structured_content(&response);
        let query_sha256 = content["query_sha256"].clone();
        let response_evidence = content["response_evidence"].clone();
        let evidence = response_evidence
            .as_array()
            .expect("two chronological response summaries");
        assert_eq!(evidence.len(), 2, "{content}");
        for summary in evidence {
            assert_eq!(summary.as_object().map(|value| value.len()), Some(3));
            assert!(summary["response_body_sha256"].as_str().is_some());
            assert!(summary["response_body_size_bytes"].as_u64().is_some());
            assert_eq!(
                summary["lifecycle"],
                json!({
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 200,
                })
            );
        }
        let lifecycle = json!([
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
        ]);
        assert_eq!(
            content,
            &json!({
                "ok": false,
                "operation": "d1_reconcile_migration_manifest",
                "dry_run": true,
                "read_only": true,
                "status": "reconciliation_required",
                "outcome": "unknown",
                "capability_state": "contradictory",
                "retry_decision": "do_not_retry_same_attempt",
                "lease_decision": "retain",
                "lease_retained": true,
                "custody_status": "retained_evidence_verified",
                "query_sha256": query_sha256,
                "response_evidence": response_evidence,
                "provider_read_lifecycle": lifecycle,
                "provider_calls": 2,
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "error": {
                    "code": expected_code,
                    "message": expected_message,
                    "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
                },
            }),
            "{content}"
        );
        assert_eq!(requests.lock().expect("request log").len(), 2);
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_reconcile_migration_manifest_stdio_preserves_both_batches_when_second_call_errors() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-second-error-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create second-error reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make second-error reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let expected_second = reconciliation_http_error_response(503);
    let expected_second_sha256 =
        sha256_hex(std::str::from_utf8(&expected_second).expect("synthetic HTTP error is UTF-8"));
    let (base_url, requests) =
        spawn_fake_reconciliation_api_with_fault(ReconciliationFault::SecondBatchHttpStatus(503));
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        763,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": expectations,
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["capability_state"], json!("unavailable"));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_reconciliation_provider_unavailable")
    );
    assert_eq!(content["lease_retained"], json!(true), "{content}");
    assert_eq!(
        content["custody_status"],
        json!("retained_evidence_verified"),
        "{content}"
    );
    assert_eq!(content["provider_calls"], json!(2), "{content}");
    assert_eq!(
        content["provider_read_lifecycle"],
        json!([
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            },
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 503,
            }
        ]),
        "{content}"
    );
    let evidence = content["response_evidence"]
        .as_array()
        .expect("chronological response evidence");
    assert_eq!(evidence.len(), 2, "{content}");
    assert_ne!(
        evidence[0]["response_body_sha256"], evidence[1]["response_body_sha256"],
        "{content}"
    );
    assert_eq!(
        evidence[1]["response_body_sha256"],
        json!(expected_second_sha256),
        "{content}"
    );
    assert_eq!(requests.lock().expect("request log").len(), 2);
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_preserves_second_transport_invocation_without_body() {
    let (manifest, expectations) = one_table_reconciliation_case();
    for (index, custody_verified) in [true, false].into_iter().enumerate() {
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-reconcile-second-transport-{}-{index}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create second-transport reconciliation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make second-transport reconciliation root private");
        }
        let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
            create_retained_reconciliation_fixture(&lease_root, &manifest);
        let active = assert_private_regular_active_lease(&lease_root);
        let fault =
            ReconciliationFault::SecondBatchTransportFailure((!custody_verified).then_some(active));
        let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(fault);
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let response = mcp.call_tool(
            764 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_only_v1",
                "state_expectations": expectations.clone(),
            }),
        );
        let content = structured_content(&response);
        let query_sha256 = content["query_sha256"].clone();
        let first = content["response_evidence"][0].clone();
        assert_eq!(first.as_object().map(|value| value.len()), Some(3));
        let mut expected = json!({
            "ok": false,
            "operation": "d1_reconcile_migration_manifest",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "outcome": "unknown",
            "capability_state": "unavailable",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "retain",
            "lease_retained": custody_verified.then_some(true),
            "custody_status": if custody_verified {
                "retained_evidence_verified"
            } else {
                "retained_evidence_unverified"
            },
            "query_sha256": query_sha256,
            "response_evidence": [first.clone()],
            "provider_read_lifecycle": [
                first["lifecycle"].clone(),
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "not_received",
                    "body_stage": "not_read",
                    "http_status": null,
                },
            ],
            "provider_calls": 2,
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "provider_cause": {
                "code": "cloudflare.transport_error",
                "status": null,
                "retryable": false,
                "operator_guidance": "reconciliation_only",
            },
            "error": {
                "code": "d1.migration_reconciliation_provider_unavailable",
                "message": "provider could not return one complete strict read-only reconciliation batch",
                "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
            },
        });
        if !custody_verified {
            expected.as_object_mut().expect("expected object").insert(
                "custody_cause".to_string(),
                json!({
                    "code": "d1.migration_reconciliation_lease_changed",
                    "message": "retained lease payload digest changed",
                    "hint": "Retain the exact custody evidence and resolve this boundary before any provider read or migration retry.",
                }),
            );
        }
        assert_eq!(content, &expected, "custody_verified={custody_verified}");
        assert_eq!(requests.lock().expect("request log").len(), 2);
        if custody_verified {
            assert_private_regular_active_lease(&lease_root);
        }
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_reconcile_migration_manifest_stdio_rejects_recursive_duplicate_keys_in_both_orders() {
    let (manifest, expectations) = one_table_reconciliation_case();
    for (index, (nested, reverse)) in [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-reconcile-duplicate-json-{}-{index}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create duplicate-json reconciliation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make duplicate-json reconciliation root private");
        }
        let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
            create_retained_reconciliation_fixture(&lease_root, &manifest);
        let raw_response = Arc::new(Mutex::new(Vec::new()));
        let fault = if nested {
            ReconciliationFault::DuplicateNestedRowId(reverse, raw_response.clone())
        } else {
            ReconciliationFault::DuplicateOuterSuccess(reverse, raw_response.clone())
        };
        let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(fault);
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let response = mcp.call_tool(
            766 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_only_v1",
                "state_expectations": expectations.clone(),
            }),
        );
        let raw_response = raw_response.lock().expect("raw duplicate response").clone();
        let raw_response_text =
            std::str::from_utf8(&raw_response).expect("synthetic response UTF-8");
        let response_body_sha256 = sha256_hex(raw_response_text);
        let content = structured_content(&response);
        let query_sha256 = content["query_sha256"].clone();
        let lifecycle = json!({
            "dispatch_stage": "attempted",
            "response_stage": "received",
            "body_stage": "completely_read",
            "http_status": 200,
        });
        assert_eq!(
            content,
            &json!({
                "ok": false,
                "operation": "d1_reconcile_migration_manifest",
                "dry_run": true,
                "read_only": true,
                "status": "reconciliation_required",
                "outcome": "unknown",
                "capability_state": "contradictory",
                "retry_decision": "do_not_retry_same_attempt",
                "lease_decision": "retain",
                "lease_retained": true,
                "custody_status": "retained_evidence_verified",
                "query_sha256": query_sha256,
                "response_evidence": [{
                    "response_body_sha256": response_body_sha256,
                    "response_body_size_bytes": raw_response.len(),
                    "complete_body_digest": true,
                    "lifecycle": lifecycle.clone(),
                }],
                "provider_read_lifecycle": [lifecycle],
                "provider_calls": 1,
                "provider_mutations": 0,
                "local_namespace_mutations": 0,
                "provider_cause": {
                    "code": "cloudflare.d1.migration_reconciliation_duplicate_object_key",
                    "status": 200,
                    "retryable": false,
                    "operator_guidance": "reconciliation_only",
                },
                "error": {
                    "code": "d1.migration_reconciliation_provider_evidence_contradictory",
                    "message": "provider could not return one complete strict read-only reconciliation batch",
                    "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
                },
            }),
            "nested={nested} reverse={reverse}: {content}"
        );
        assert_eq!(requests.lock().expect("request log").len(), 1);
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_reconcile_migration_manifest_stdio_treats_auth_rate_limit_and_5xx_evidence_as_unavailable_without_retry()
 {
    let (manifest, expectations) = one_table_reconciliation_case();
    for (index, (fault, status, body_stage, incomplete_size)) in [
        (
            ReconciliationFault::HttpStatus(401),
            401,
            "completely_read",
            None,
        ),
        (
            ReconciliationFault::HttpStatus(403),
            403,
            "completely_read",
            None,
        ),
        (
            ReconciliationFault::HttpStatus(429),
            429,
            "completely_read",
            None,
        ),
        (
            ReconciliationFault::HttpStatus(503),
            503,
            "completely_read",
            None,
        ),
        (
            ReconciliationFault::MalformedUtf8HttpStatus(429),
            429,
            "completely_read",
            None,
        ),
        (
            ReconciliationFault::MalformedUtf8HttpStatus(503),
            503,
            "completely_read",
            None,
        ),
        (
            ReconciliationFault::ZeroByteTruncatedHttpStatus(503),
            503,
            "not_read",
            Some(0),
        ),
        (
            ReconciliationFault::TruncatedHttpStatus(503),
            503,
            "partially_read",
            Some(1),
        ),
        (
            ReconciliationFault::OversizedHttpStatus(429),
            429,
            "not_read",
            None,
        ),
        (
            ReconciliationFault::OversizedHttpStatus(503),
            503,
            "not_read",
            None,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-reconcile-http-{}-{status}-{index}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create HTTP reconciliation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make HTTP reconciliation root private");
        }
        let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
            create_retained_reconciliation_fixture(&lease_root, &manifest);
        let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(fault);
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let response = mcp.call_tool(
            770 + status as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_only_v1",
                "state_expectations": expectations.clone(),
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{content}");
        assert_eq!(content["capability_state"], json!("unavailable"));
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_reconciliation_provider_unavailable")
        );
        assert_eq!(
            content["retry_decision"],
            json!("do_not_retry_same_attempt")
        );
        assert_eq!(content["provider_calls"], json!(1));
        assert_eq!(
            content["provider_cause"]["status"],
            json!(status),
            "{content}"
        );
        assert_eq!(
            content["provider_read_lifecycle"],
            json!([{
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": body_stage,
                "http_status": status,
            }]),
            "{content}"
        );
        assert_eq!(requests.lock().expect("request log").len(), 1);
        if let Some(expected_size) = incomplete_size {
            assert_eq!(
                content["response_evidence"],
                json!([{
                    "response_body_sha256": null,
                    "response_body_size_bytes": expected_size,
                    "complete_body_digest": false,
                    "lifecycle": {
                        "dispatch_stage": "attempted",
                        "response_stage": "received",
                        "body_stage": body_stage,
                        "http_status": status,
                    },
                }]),
                "{content}"
            );
        }
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_same_name_after_response_loss_stays_unknown_and_retains_lease() {
    let (base_url, requests) = spawn_fake_manifest_ambiguous_api(true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-ambiguous-manifest-same-name-lease-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url.clone()),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let first_sql = "CREATE TABLE submissions(id TEXT);";
    let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
        {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
    ]);
    let dry = mcp.call_tool(8, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("plan")
        .to_string();
    let live = mcp.call_tool(
        9,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest.clone(),
            "approved_plan_sha256": plan.clone(),
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["outcome"], json!("unknown"));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_apply_outcome_unknown")
    );
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(content["migration"]["name"], json!("0002_second.sql"));
    assert_eq!(content["ledger_evidence"]["state"], json!("known"));
    assert!(
        content["applied_migrations"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        requests.lock().expect("requests lock").len(),
        6,
        "same-name ledger evidence must neither release the lease nor apply the next statement"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    assert_fresh_process_blocked_without_provider_request(
        vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ],
        &manifest,
        &plan,
        &requests,
        6,
        "same-name response loss",
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_ambiguous_inner_result_shapes_retain_lease_without_retry() {
    for (index, (label, write_result, classification)) in [
        ("missing", Value::Null, "missing_or_non_array_result"),
        ("empty", json!([]), "empty_result_set_sequence"),
        ("null", json!([null]), "malformed_result_set"),
        (
            "malformed",
            json!([{"success": true, "errors": [], "results": null}]),
            "missing_or_malformed_inner_results",
        ),
        (
            "mixed success and failure",
            json!([
                {"success": true, "errors": [], "results": []},
                {"success": false, "errors": [], "results": []}
            ]),
            "inner_statement_failure_or_missing_success",
        ),
        (
            "inner error",
            json!([{"success": true, "errors": [{"code": 1}], "results": []}]),
            "inner_statement_error",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) = spawn_fake_manifest_ambiguous_result_api(write_result);
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-ambiguous-manifest-result-{index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make lease root private");
        }
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url.clone()),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
        let manifest = json!([
            {"name": "0001_initial.sql", "size_bytes": "CREATE TABLE submissions(id TEXT);".len(), "sql_sha256": sha256_hex("CREATE TABLE submissions(id TEXT);"), "sql": "CREATE TABLE submissions(id TEXT);"},
            {"name": "0002_second.sql", "size_bytes": sql.len(), "sql_sha256": sha256_hex(sql), "sql": sql}
        ]);
        let dry = mcp.call_tool(12 + index as u64 * 2, "d1_apply_migration_manifest", json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
        }));
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("plan")
            .to_string();
        let live = mcp.call_tool(
            13 + index as u64 * 2,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest.clone(),
                "approved_plan_sha256": plan.clone(),
            }),
        );
        let content = structured_content(&live);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["status"],
            json!("reconciliation_required"),
            "{label}"
        );
        assert_eq!(content["outcome"], json!("unknown"), "{label}");
        assert_eq!(content["lease_retained"], json!(true), "{label}");
        assert_eq!(
            content["error"]["cause"]["kind"],
            json!("provider_result"),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["classification"],
            json!(classification),
            "{label}"
        );
        assert!(
            content["error"]["cause"].get("detail").is_none()
                && content["error"]["cause"].get("hint").is_none(),
            "{label} must not expose raw provider detail or inherited guidance"
        );
        assert!(
            content["applied_migrations"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "{label} must not claim the statement applied"
        );
        let observed = requests.lock().expect("requests lock").clone();
        assert_eq!(observed.len(), 6, "{label} must not retry the write");
        assert_eq!(
            observed
                .iter()
                .filter(|request| request["sql"]
                    .as_str()
                    .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
                .count(),
            1,
            "{label} must issue one non-idempotent write"
        );
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        assert_fresh_process_blocked_without_provider_request(
            vec![
                ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
                (
                    "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                    lease_root.to_string_lossy().to_string(),
                ),
            ],
            &manifest,
            &plan,
            &requests,
            6,
            label,
        );
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_multiple_successful_query_results_apply_once() {
    let (base_url, requests) = spawn_fake_manifest_ambiguous_result_api(json!([
        {"success": true, "errors": [], "results": []},
        {"success": true, "errors": [], "results": []}
    ]));
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-multi-result-manifest-lease-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": "CREATE TABLE submissions(id TEXT);".len(), "sql_sha256": sha256_hex("CREATE TABLE submissions(id TEXT);"), "sql": "CREATE TABLE submissions(id TEXT);"},
        {"name": "0002_second.sql", "size_bytes": sql.len(), "sql_sha256": sha256_hex(sql), "sql": sql}
    ]);
    let dry = mcp.call_tool(30, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("plan")
        .to_string();
    let live = mcp.call_tool(
        31,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
            "approved_plan_sha256": plan,
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["status"], json!("applied"));
    assert_eq!(
        content["applied_migrations"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(requests.lock().expect("requests lock").len(), 6);
    assert_released_manifest_target_custody(&lease_root);
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_partial_multi_statement_response_loss_stays_unknown() {
    let (base_url, requests) = spawn_fake_partial_manifest_ambiguous_api();
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-partial-ambiguous-manifest-lease-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url.clone()),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let first_sql = "CREATE TABLE submissions(id TEXT);";
    let second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
        {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(second_sql), "sql": second_sql}
    ]);
    let dry = mcp.call_tool(10, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("plan")
        .to_string();
    let live = mcp.call_tool(
        11,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest.clone(),
            "approved_plan_sha256": plan.clone(),
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["outcome"], json!("unknown"));
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(content["migration"]["name"], json!("0002_second.sql"));
    assert_eq!(
        content["applied_migrations"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        content["applied_migrations"][0]["name"],
        json!("0001_initial.sql")
    );
    assert_eq!(
        requests.lock().expect("requests lock").len(),
        7,
        "first statement may have committed; second ambiguity must stop the batch without any retry"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    assert_fresh_process_blocked_without_provider_request(
        vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ],
        &manifest,
        &plan,
        &requests,
        7,
        "partial response loss",
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_rename_database_uses_patch_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_d1_database_mutation_api(1);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "d1_rename_database",
        json!({
            "database_id": "db-1",
            "name": "renamed-db",
            "dry_run": false
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["database"]["name"], json!("renamed-db"));
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["method"], json!("PATCH"));
    assert_eq!(
        requests[0]["path"],
        json!("/accounts/acct-1/d1/database/db-1")
    );
    assert_eq!(requests[0]["body"]["name"], json!("renamed-db"));
}

#[test]
fn d1_delete_database_requires_token_and_deletes_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_d1_database_mutation_api(1);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let dry_run = mcp.call_tool(
        2,
        "d1_delete_database",
        json!({
            "database_id": "db-1",
            "dry_run": true,
            "reason": "stdio regression"
        }),
    );
    let dry_run_content = structured_content(&dry_run);
    assert_eq!(dry_run_content["ok"], json!(true), "{dry_run_content}");
    assert_eq!(dry_run_content["planned"], json!(true));
    assert_eq!(requests.lock().expect("request log lock").len(), 0);
    let token = dry_run_content["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();

    let response = mcp.call_tool(
        3,
        "d1_delete_database",
        json!({
            "database_id": "db-1",
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["result"]["deleted"], json!(true));
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["method"], json!("DELETE"));
    assert_eq!(
        requests[0]["path"],
        json!("/accounts/acct-1/d1/database/db-1")
    );
    assert_eq!(requests[0]["body"], Value::Null);
}

#[test]
fn workers_upload_script_requires_token_and_reads_back_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_worker_upload_api(2);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let dry_run = mcp.call_tool(
        2,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "dry_run": true,
            "reason": "stdio regression"
        }),
    );
    let dry_run_content = structured_content(&dry_run);
    assert_eq!(dry_run_content["ok"], json!(true), "{dry_run_content}");
    assert_eq!(dry_run_content["planned"], json!(true));
    assert_eq!(dry_run_content["upload"]["main_module"], json!("worker.js"));
    assert_eq!(dry_run_content["upload"]["metadata"], Value::Null);
    assert_eq!(
        dry_run_content["upload"]["metadata_keys"],
        json!(["compatibility_date", "main_module"])
    );
    assert!(dry_run_content["upload"]["metadata_sha256"].is_string());
    assert_eq!(requests.lock().expect("request log lock").len(), 0);
    let token = dry_run_content["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();

    let response = mcp.call_tool(
        3,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["script"]["script_name"], json!("worker-a"));
    assert_eq!(
        content["readback_settings"]["main_module"],
        json!("worker.js")
    );
    assert_eq!(
        content["readback_verification"]["code"],
        json!("workers.upload_main_module_matched")
    );
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["method"], json!("PUT"));
    assert_eq!(
        requests[0]["path"],
        json!("/accounts/acct-1/workers/scripts/worker-a")
    );
    assert!(
        requests[0]["content_type"]
            .as_str()
            .unwrap_or_default()
            .starts_with("multipart/form-data;")
    );
    assert_eq!(requests[1]["method"], json!("GET"));
    assert_eq!(
        requests[1]["path"],
        json!("/accounts/acct-1/workers/scripts/worker-a/settings")
    );
    assert_eq!(requests[0]["if_none_match"], json!(""));
}

#[test]
fn workers_upload_script_create_only_binds_token_and_sends_atomic_precondition() {
    let (base_url, requests) = spawn_fake_worker_upload_api(2);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let dry_run = mcp.call_tool(
        2,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": true,
            "dry_run": true,
            "reason": "stdio create-only regression"
        }),
    );
    let dry_run_content = structured_content(&dry_run);
    assert_eq!(dry_run_content["ok"], json!(true), "{dry_run_content}");
    assert_eq!(dry_run_content["create_only"], json!(true));
    let token = dry_run_content["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();

    let mismatched_apply = mcp.call_tool(
        3,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": false,
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio create-only mismatch regression"
        }),
    );
    let mismatched_content = structured_content(&mismatched_apply);
    assert_eq!(mismatched_content["ok"], json!(false));
    assert_eq!(
        mismatched_content["error"]["code"],
        json!("workers.upload_confirmation_required")
    );
    assert_eq!(requests.lock().expect("request log lock").len(), 0);

    let response = mcp.call_tool(
        4,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": true,
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio create-only regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["create_only"], json!(true));
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["if_none_match"], json!("*"));
}

#[test]
fn workers_upload_script_create_only_version_attestation_is_sanitized_through_stdio() {
    let (base_url, requests) = spawn_fake_worker_upload_version_attestation_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let dry_run = mcp.call_tool(
        2,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": true,
            "dry_run": true,
            "reason": "stdio version attestation regression"
        }),
    );
    let dry_content = structured_content(&dry_run);
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    let token = dry_content["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();

    let response = mcp.call_tool(
        3,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": true,
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio version attestation regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["readback_settings"]["main_module"], Value::Null);
    assert_eq!(
        content["readback_verification"]["code"],
        json!("workers.upload_version_readback_matched")
    );
    assert!(content.get("version_evidence").is_none());
    let serialized = content.to_string();
    assert!(!serialized.contains("version-1"));
    assert!(!serialized.contains("redacted-author"));

    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[0]["method"], json!("PUT"));
    assert_eq!(
        requests[1]["path"],
        json!("/accounts/acct-1/workers/scripts/worker-a/settings")
    );
    assert_eq!(
        requests[2]["path"],
        json!("/accounts/acct-1/workers/scripts")
    );
    assert_eq!(
        requests[3]["path"],
        json!("/accounts/acct-1/workers/scripts/worker-a/versions")
    );
    assert_eq!(
        requests[4]["path"],
        json!("/accounts/acct-1/workers/scripts/worker-a/versions/version-1")
    );
    assert_eq!(
        requests[5]["path"],
        json!("/accounts/acct-1/workers/scripts")
    );
    assert_eq!(
        requests[6]["path"],
        json!("/accounts/acct-1/workers/scripts/worker-a/versions")
    );
}

#[test]
fn workers_upload_script_create_only_rejects_cross_target_identity_through_stdio() {
    let (base_url, requests) = spawn_fake_worker_upload_version_attestation_cross_target_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let dry_run = mcp.call_tool(
        2,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": true,
            "dry_run": true,
            "reason": "stdio cross-target regression"
        }),
    );
    let token = structured_content(&dry_run)["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();
    let response = mcp.call_tool(
        3,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "create_only": true,
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio cross-target regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("workers.upload_version_readback_mismatch")
    );
    assert_eq!(
        content["readback_verification"]["code"],
        json!("workers.upload_script_identity_invalid")
    );
    let serialized = content.to_string();
    assert!(!serialized.contains("version-1"));
    assert!(!serialized.contains("redacted-author"));
    assert_eq!(requests.lock().expect("request log lock").len(), 7);
}

#[test]
fn workers_upload_script_reports_readback_mismatch_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_worker_upload_api_with_readback(2, "unexpected.js");
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let dry_run = mcp.call_tool(
        2,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "dry_run": true,
            "reason": "stdio regression"
        }),
    );
    let dry_run_content = structured_content(&dry_run);
    let token = dry_run_content["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();

    let response = mcp.call_tool(
        3,
        "workers_upload_script",
        json!({
            "script_name": "worker-a",
            "main_module": "worker.js",
            "script_content": "export default { fetch() { return new Response('ok'); } };",
            "metadata": {"compatibility_date": "2026-06-03"},
            "dry_run": false,
            "confirmation_token": token,
            "reason": "stdio regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("workers.upload_readback_mismatch")
    );
    assert_eq!(
        content["readback_verification"]["code"],
        json!("workers.upload_main_module_mismatch")
    );
    assert_eq!(
        content["readback_verification"]["observed_main_module"],
        json!("unexpected.js")
    );
    assert_eq!(requests.lock().expect("request log lock").len(), 2);
}

#[test]
fn patch_worker_settings_uses_object_schema_and_multipart_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_worker_settings_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let patch = json!({
        "bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "new"}]
    });

    let tools = mcp.request(2, "tools/list", json!({}));
    let tool = tools["result"]["tools"]
        .as_array()
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| tool["name"] == json!("patch_worker_settings"))
        })
        .expect("patch_worker_settings tool schema");
    assert_eq!(
        tool["inputSchema"]["properties"]["settings_patch"]["type"],
        json!("object")
    );

    let dry_run = mcp.call_tool(
        3,
        "patch_worker_settings",
        json!({"script_name": "worker-a", "settings_patch": patch, "dry_run": true}),
    );
    let dry_content = structured_content(&dry_run);
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    assert_eq!(
        dry_content["dry_run_note"],
        json!("No Cloudflare mutation applied.")
    );
    assert_eq!(requests.lock().expect("request log lock").len(), 1);

    let response = mcp.call_tool(
        4,
        "patch_worker_settings",
        json!({
            "script_name": "worker-a",
            "settings_patch": {"bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "new"}]},
            "expect_binding": {"name": "DESTINATION", "binding_type": "plain_text", "field": "text", "value": "new"}
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["binding_verification"]["matched"], json!(true));
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0]["method"], json!("GET"));
    assert_eq!(requests[1]["method"], json!("GET"));
    assert_eq!(requests[2]["method"], json!("PATCH"));
    assert_eq!(requests[3]["method"], json!("GET"));
    assert!(
        requests[2]["content_type"]
            .as_str()
            .is_some_and(|value| value.starts_with("multipart/form-data;"))
    );
}

#[test]
fn workers_observability_values_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "workers_observability_list_values",
        json!({
            "key": "$workers.scriptName",
            "script_name": "pages-worker",
            "limit": 50
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["page"]["items"][0]["value"], json!("pages-worker"));
}

#[test]
fn workers_observability_keys_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "workers_observability_list_keys",
        json!({
            "script_name": "pages-worker",
            "limit": 50
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["page"]["items"][0]["key"],
        json!("$workers.scriptName")
    );
}

#[test]
fn workers_observability_query_events_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "workers_observability_query_events",
        json!({
            "limit": 20
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["result"]["events"], json!([]));
}

#[test]
fn queue_health_and_api_prepare_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let prepared = mcp.call_tool(
        2,
        "api_prepare_call",
        json!({
            "query": "queue metrics",
            "tag": "Queue",
            "method": "GET",
            "scope": "account",
            "risk": "read",
            "path_params": {"queue_id": "queue-1"},
            "limit": 1
        }),
    );
    let prepared_content = structured_content(&prepared);
    assert_eq!(prepared_content["ok"], json!(true), "{prepared_content}");
    assert_eq!(prepared_content["call"]["tool"], json!("api_read"));
    assert_eq!(
        prepared_content["call"]["arguments"]["operation_id"],
        json!("queues-get-metrics")
    );

    let health = mcp.call_tool(
        3,
        "queues_health",
        json!({
            "queue_id": "queue-1",
            "include_dlq": true
        }),
    );
    let health_content = structured_content(&health);
    assert_eq!(health_content["ok"], json!(true), "{health_content}");
    assert_eq!(health_content["metrics"]["backlog_count"], json!(7.0));
    assert_eq!(
        health_content["consumer_status"]["state"],
        json!("configured")
    );
    assert_eq!(health_content["dlq"]["backlog_count"], json!(2.0));
}

#[test]
fn billing_usage_and_graphql_analytics_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let prepared = mcp.call_tool(
        2,
        "api_prepare_call",
        json!({
            "operation_id": "billable-usage-get-paygo-account-usage",
            "query_params": {
                "from": "2026-06-01T00:00:00Z",
                "to": "2026-06-02T00:00:00Z"
            }
        }),
    );
    let prepared_content = structured_content(&prepared);
    assert_eq!(prepared_content["ok"], json!(true), "{prepared_content}");
    assert_eq!(
        prepared_content["rendered_path"],
        json!("/accounts/acct-1/paygo-usage")
    );
    assert_eq!(
        prepared_content["resolved_path_params"],
        json!({"account_id": "acct-1"})
    );
    assert_eq!(
        prepared_content["call"]["arguments"]["path_params"],
        json!({"account_id": "acct-1"})
    );
    assert_eq!(
        prepared_content["api_operation"]["call_template"]["path_params"]["account_id"],
        json!("<account_id>")
    );

    let usage = mcp.call_tool(
        3,
        "account_billing_usage",
        json!({
            "from": "2026-06-01T00:00:00Z",
            "to": "2026-06-02T00:00:00Z"
        }),
    );
    let usage_content = structured_content(&usage);
    assert_eq!(usage_content["ok"], json!(true), "{usage_content}");
    assert_eq!(usage_content["path"], json!("/accounts/acct-1/paygo-usage"));
    assert_eq!(usage_content["result"][0]["ConsumedQuantity"], json!(42));

    let graphql = mcp.call_tool(
        4,
        "graphql_analytics_query",
        json!({
            "query": "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead rowsWritten } } } } }",
            "variables": {"accountTag": "acct-1"}
        }),
    );
    let graphql_content = structured_content(&graphql);
    assert_eq!(graphql_content["ok"], json!(true), "{graphql_content}");
    assert_eq!(
        graphql_content["result"]["data"]["viewer"]["accounts"][0]["d1AnalyticsAdaptiveGroups"][0]
            ["sum"]["rowsWritten"],
        json!(4)
    );
}

#[test]
fn graphql_analytics_query_reports_likely_entitlement_restriction_through_stdio_boundary() {
    let base_url = spawn_fake_graphql_api(json!({
        "data": {
            "viewer": {
                "accounts": [{}]
            }
        },
        "errors": [{
            "message": "does not have access to the path",
            "path": ["viewer", "accounts", 0, "d1AnalyticsAdaptiveGroups"]
        }]
    }));
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let graphql = mcp.call_tool(
        2,
        "graphql_analytics_query",
        json!({
            "query": "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead rowsWritten } } } } }",
            "variables": {"accountTag": "acct-1"}
        }),
    );
    let graphql_content = structured_content(&graphql);
    assert_eq!(graphql_content["ok"], json!(false), "{graphql_content}");
    assert_eq!(
        graphql_content["diagnostics"]["authz_classification"]["code"],
        json!("likely_entitlement_or_product_restriction")
    );
}

#[test]
fn graphql_analytics_query_reports_grouped_partial_success_through_stdio_boundary() {
    let base_url = spawn_fake_graphql_api(json!({
        "data": {
            "viewer": {
                "accounts": [{
                    "accountTag": "acct-1"
                }]
            }
        },
        "errors": [{
            "message": "does not have access to the path",
            "path": ["viewer", "accounts", 0, "d1AnalyticsAdaptiveGroups"]
        }]
    }));
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let graphql = mcp.call_tool(
        2,
        "graphql_analytics_query",
        json!({
            "query": "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { accountTag d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead rowsWritten } } } } }",
            "variables": {"accountTag": "acct-1"}
        }),
    );
    let graphql_content = structured_content(&graphql);
    assert_eq!(graphql_content["ok"], json!(false), "{graphql_content}");
    assert_eq!(
        graphql_content["diagnostics"]["authz_classification"]["code"],
        json!("grouped_path_blocked_partial_success")
    );
    assert_eq!(
        graphql_content["diagnostics"]["authz_classification"]["evidence"]["partial_data_available"],
        json!(true)
    );
}

#[test]
fn waf_ruleset_and_security_events_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let tools = mcp.call_tool(
        2,
        "find_tools",
        json!({
            "query": "what WAF rule blocked this request security events analytics plan apply",
            "include_schema": true,
            "limit": 8
        }),
    );
    let tools_content = structured_content(&tools);
    assert_eq!(tools_content["ok"], json!(true), "{tools_content}");
    let allowed = tools_content["openai_allowed_tools"]
        .as_array()
        .expect("allowed tools");
    assert!(
        allowed.iter().any(|tool| tool == "waf_ruleset_summary"),
        "{tools_content}"
    );
    assert!(
        allowed
            .iter()
            .any(|tool| tool == "waf_security_events_summary")
    );
    assert!(allowed.iter().any(|tool| tool == "waf_rule_activity"));
    assert!(allowed.iter().any(|tool| tool == "waf_ruleset_plan_change"));
    assert!(
        allowed
            .iter()
            .any(|tool| tool == "waf_ruleset_apply_change")
    );

    let rulesets = mcp.call_tool(
        3,
        "waf_ruleset_summary",
        json!({
            "phases": ["custom"],
            "include_rules": true
        }),
    );
    let rulesets_content = structured_content(&rulesets);
    assert_eq!(rulesets_content["ok"], json!(true), "{rulesets_content}");
    assert_eq!(
        rulesets_content["rulesets"][0]["ruleset"]["id"],
        json!("ruleset-custom")
    );
    assert_eq!(
        rulesets_content["rulesets"][0]["rules"][0]["id"],
        json!("rule-1")
    );
    assert_eq!(
        rulesets_content["source"]["ruleset_phases"][0],
        json!("http_request_firewall_custom")
    );

    let events = mcp.call_tool(
        4,
        "waf_security_events_summary",
        json!({
            "since": "2026-06-04T00:00:00Z",
            "until": "2026-06-04T02:00:00Z",
            "group_by": ["action", "source", "host"],
            "action": "block",
            "host": "example.com",
            "sample_limit": 5,
            "include_query": true
        }),
    );
    let events_content = structured_content(&events);
    assert_eq!(events_content["ok"], json!(true), "{events_content}");
    assert_eq!(
        events_content["analytics"]["groups"]["byAction"][0]["dimensions"]["action"],
        json!("block")
    );
    assert_eq!(
        events_content["analytics"]["samples"][0]["ruleId"],
        json!("rule-1")
    );
    assert!(
        events_content["graphql"]["query"]
            .as_str()
            .expect("query")
            .contains("firewallEventsAdaptive")
    );

    let activity = mcp.call_tool(
        5,
        "waf_rule_activity",
        json!({
            "rule_id": "rule-1",
            "phases": ["custom"],
            "since": "2026-06-04T00:00:00Z",
            "until": "2026-06-04T02:00:00Z",
            "include_raw": false
        }),
    );
    let activity_content = structured_content(&activity);
    assert_eq!(activity_content["ok"], json!(true), "{activity_content}");
    assert_eq!(activity_content["matching_rules"][0]["id"], json!("rule-1"));
    assert_eq!(
        activity_content["analytics"]["samples"][0]["clientRequestPath"],
        json!("/admin")
    );

    let stale_plan = mcp.call_tool(
        6,
        "waf_ruleset_plan_change",
        json!({
            "phase": "custom",
            "max_rules": 5,
            "stale_list_refs": ["blocked_ips"],
            "edits": [{
                "operation": "add",
                "rule_ref": "stale-list-rule",
                "description": "Block stale list",
                "expression": "ip.src in $blocked_ips",
                "rule_action": "block"
            }]
        }),
    );
    let stale_content = structured_content(&stale_plan);
    assert_eq!(stale_content["ok"], json!(false), "{stale_content}");
    assert_eq!(
        stale_content["error"]["code"],
        json!("waf.stale_list_reference")
    );

    let cap_plan = mcp.call_tool(
        7,
        "waf_ruleset_plan_change",
        json!({
            "phase": "custom",
            "max_rules": 1,
            "edits": [{
                "operation": "add",
                "rule_ref": "extra-rule",
                "description": "Log suspicious probes",
                "expression": "http.request.uri.path contains \"/probe\"",
                "rule_action": "log"
            }]
        }),
    );
    let cap_content = structured_content(&cap_plan);
    assert_eq!(cap_content["ok"], json!(false), "{cap_content}");
    assert_eq!(cap_content["error"]["code"], json!("waf.rule_cap_exceeded"));

    let plan = mcp.call_tool(
        8,
        "waf_ruleset_plan_change",
        json!({
            "phase": "custom",
            "max_rules": 5,
            "edits": [{
                "operation": "update",
                "rule_id": "rule-1",
                "description": "Challenge admin probes",
                "expression": "http.request.uri.path contains \"/admin\"",
                "rule_action": "managed_challenge",
                "enabled": true
            }]
        }),
    );
    let plan_content = structured_content(&plan);
    assert_eq!(plan_content["ok"], json!(true), "{plan_content}");
    assert_eq!(
        plan_content["diff"]["changes"][0]["after"]["action"],
        json!("managed_challenge")
    );
    assert_eq!(
        plan_content["diff"]["action_change_warnings"][0]["rule"],
        json!("rule-1")
    );
    let token = plan_content["required_confirmation_token"]
        .as_str()
        .expect("confirmation token")
        .to_string();

    let denied = mcp.call_tool(
        9,
        "waf_ruleset_apply_change",
        json!({
            "phase": "custom",
            "confirmation_token": "wrong-token",
            "edits": [{
                "operation": "update",
                "rule_id": "rule-1",
                "description": "Challenge admin probes",
                "expression": "http.request.uri.path contains \"/admin\"",
                "rule_action": "managed_challenge",
                "enabled": true
            }]
        }),
    );
    let denied_content = structured_content(&denied);
    assert_eq!(denied_content["ok"], json!(false), "{denied_content}");
    assert_eq!(
        denied_content["error"]["code"],
        json!("waf.confirmation_required")
    );

    let applied = mcp.call_tool(
        10,
        "waf_ruleset_apply_change",
        json!({
            "phase": "custom",
            "confirmation_token": token,
            "readback_security_events": true,
            "readback_sample_limit": 3,
            "edits": [{
                "operation": "update",
                "rule_id": "rule-1",
                "description": "Challenge admin probes",
                "expression": "http.request.uri.path contains \"/admin\"",
                "rule_action": "managed_challenge",
                "enabled": true
            }]
        }),
    );
    let applied_content = structured_content(&applied);
    assert_eq!(applied_content["ok"], json!(true), "{applied_content}");
    assert_eq!(
        applied_content["readback"]["rules"][0]["action"],
        json!("managed_challenge")
    );
    assert_eq!(
        applied_content["security_events_readback"]["enabled"],
        json!(true)
    );
    assert_eq!(
        applied_content["audit"]["action"],
        json!("waf_ruleset_apply_change")
    );
}

#[test]
fn waf_security_events_summary_reports_grouped_authz_diagnostics_through_stdio_boundary() {
    let base_url = spawn_fake_graphql_api(json!({
        "data": {
            "viewer": {
                "zones": [{
                    "settings": {
                        "firewallEventsAdaptive": {
                            "maxDuration": 86400,
                            "maxPageSize": 100,
                            "notOlderThan": "2026-06-01T00:00:00Z"
                        }
                    },
                    "samples": [{
                        "action": "block",
                        "clientIP": "203.0.113.10",
                        "clientRequestHTTPHost": "example.com",
                        "clientRequestPath": "/admin",
                        "datetime": "2026-06-04T01:02:03Z",
                        "source": "waf",
                        "ruleId": "rule-1"
                    }]
                }]
            }
        },
        "errors": [{
            "message": "does not have access to the path",
            "path": ["viewer", "zones", 0, "byAction"]
        }]
    }));
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let events = mcp.call_tool(
        2,
        "waf_security_events_summary",
        json!({
            "since": "2026-06-04T00:00:00Z",
            "until": "2026-06-04T02:00:00Z",
            "group_by": ["action"],
            "sample_limit": 5
        }),
    );
    let events_content = structured_content(&events);
    assert_eq!(events_content["ok"], json!(false), "{events_content}");
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["code"],
        json!("grouped_path_blocked_raw_path_works")
    );
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
        json!(true)
    );
}

#[test]
fn waf_security_events_summary_zero_sample_window_does_not_claim_raw_path_success() {
    let base_url = spawn_fake_graphql_api(json!({
        "data": {
            "viewer": {
                "zones": [{
                    "settings": {
                        "firewallEventsAdaptive": {
                            "maxDuration": 86400,
                            "maxPageSize": 100,
                            "notOlderThan": "2026-06-01T00:00:00Z"
                        }
                    },
                    "samples": []
                }]
            }
        },
        "errors": [{
            "message": "does not have access to the path",
            "path": ["viewer", "zones", 0, "byAction"]
        }]
    }));
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let events = mcp.call_tool(
        2,
        "waf_security_events_summary",
        json!({
            "since": "2026-06-04T00:00:00Z",
            "until": "2026-06-04T02:00:00Z",
            "group_by": ["action"],
            "sample_limit": 0
        }),
    );
    let events_content = structured_content(&events);
    assert_eq!(events_content["ok"], json!(false), "{events_content}");
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["code"],
        json!("likely_entitlement_or_product_restriction")
    );
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
        json!(false)
    );
}

#[test]
fn waf_security_events_summary_raw_field_authz_denial_is_not_mislabeled_as_grouped_only() {
    let base_url = spawn_fake_graphql_api(json!({
        "data": {
            "viewer": {
                "zones": [{
                    "settings": {
                        "firewallEventsAdaptive": {
                            "maxDuration": 86400,
                            "maxPageSize": 100,
                            "notOlderThan": "2026-06-01T00:00:00Z"
                        }
                    },
                    "samples": [{
                        "action": "block",
                        "clientIP": "203.0.113.10",
                        "clientRequestHTTPHost": "example.com",
                        "clientRequestPath": "/admin",
                        "datetime": "2026-06-04T01:02:03Z",
                        "source": "waf",
                        "ruleId": "rule-1"
                    }],
                    "byAction": [{
                        "count": 1,
                        "dimensions": {"action": "block"}
                    }]
                }]
            }
        },
        "errors": [{
            "message": "does not have access to the path",
            "path": ["viewer", "zones", 0, "samples"]
        }]
    }));
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);

    let events = mcp.call_tool(
        2,
        "waf_security_events_summary",
        json!({
            "since": "2026-06-04T00:00:00Z",
            "until": "2026-06-04T02:00:00Z",
            "group_by": ["action"],
            "sample_limit": 5
        }),
    );
    let events_content = structured_content(&events);
    assert_eq!(events_content["ok"], json!(false), "{events_content}");
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["code"],
        json!("likely_entitlement_or_product_restriction")
    );
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
        json!(true)
    );
    assert_eq!(
        events_content["diagnostics"]["authz_classification"]["evidence"]["grouped_path_mentioned"],
        json!(false)
    );
}

#[test]
fn analytics_engine_query_works_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "analytics_engine_query",
        json!({
            "sql": "SELECT blob1 AS path, SUM(_sample_interval) AS views FROM WEB GROUP BY path",
            "max_rows": 10
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["result"]["data"][0]["path"], json!("/"));
}

#[test]
fn analytics_engine_list_datasets_works_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(2, "analytics_engine_list_datasets", json!({}));
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["datasets"]["data"][0]["name"], json!("WEB"));
}

#[test]
fn analytics_engine_validate_and_describe_schema_work_through_stdio_boundary() {
    let base_url = spawn_fake_cloudflare_api();
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let validate = mcp.call_tool(
        2,
        "analytics_engine_validate_query",
        json!({
            "sql": "SELECT blob1 AS path, SUM(_sample_interval) AS views FROM WEB GROUP BY path",
            "include_dataset_readback": true
        }),
    );
    let validate_content = structured_content(&validate);
    assert_eq!(validate_content["ok"], json!(true), "{validate_content}");
    assert_eq!(validate_content["executed_user_query"], json!(false));
    assert_eq!(
        validate_content["schema"]["blob_mapping"]["columns"][0],
        json!("blob1")
    );
    let validate_dataset_key = mcp.call_tool(
        3,
        "analytics_engine_validate_query",
        json!({
            "sql": "SELECT blob2 AS event_name, SUM(_sample_interval) AS events FROM example_staff_publish_telemetry WHERE blob1 = 'publish-confidence.v2' GROUP BY event_name",
            "include_dataset_readback": true
        }),
    );
    let validate_dataset_key_content = structured_content(&validate_dataset_key);
    assert_eq!(
        validate_dataset_key_content["ok"],
        json!(true),
        "{validate_dataset_key_content}"
    );
    assert_eq!(
        validate_dataset_key_content["schema"]["objects"][1]["name"],
        json!("example_staff_publish_telemetry")
    );
    let validate_functions = mcp.call_tool(
        4,
        "analytics_engine_validate_query",
        json!({
            "sql": "SELECT coalesce(blob1, 'unknown') AS route, quantileExactWeighted(0.95)(double1, _sample_interval) AS p95 FROM WEB WHERE timestamp >= toDateTime('2026-01-01') GROUP BY route",
            "include_dataset_readback": true
        }),
    );
    let validate_functions_content = structured_content(&validate_functions);
    assert_eq!(
        validate_functions_content["ok"],
        json!(true),
        "{validate_functions_content}"
    );
    assert_eq!(
        validate_functions_content["validation"]["referenced_functions"],
        json!(["coalesce", "quantileexactweighted", "todatetime"])
    );

    let describe = mcp.call_tool(5, "analytics_engine_describe_schema", json!({}));
    let describe_content = structured_content(&describe);
    assert_eq!(describe_content["ok"], json!(true), "{describe_content}");
    assert_eq!(
        describe_content["schema"]["schema_version"],
        json!("workers_analytics_engine_sql_v1")
    );
}

#[test]
fn bot_management_permission_pair_preflight_works_through_stdio_boundary() {
    let mut mcp = McpStdioProcess::start();
    let base_arguments = json!({
        "operation_id": "bot-management-for-a-zone-update-config",
        "path_params": {"zone_id": "zone-1"},
        "body": {"fight_mode": true},
        "dry_run": true,
        "reason": "fixture Bot Fight Mode update"
    });

    let mut incomplete_arguments = base_arguments.clone();
    incomplete_arguments["token_permissions"] = json!(["Bot Management Write"]);
    let incomplete = mcp.call_tool(2, "api_mutate", incomplete_arguments);
    assert!(
        incomplete.get("error").is_none(),
        "api_mutate preflight failed before tool body: {incomplete}"
    );
    let incomplete_content = structured_content(&incomplete);
    assert_eq!(
        incomplete_content["permission_preflight"]["missing_permissions"],
        json!(["Zone Settings Write"])
    );
    assert!(
        incomplete_content["request_plan"]
            .get("required_confirmation_token")
            .is_none()
    );

    let mut ready_arguments = base_arguments.clone();
    ready_arguments["token_permissions"] = json!(["Bot Management Write", "Zone Settings Write"]);
    let ready = mcp.call_tool(3, "api_mutate", ready_arguments.clone());
    assert!(
        ready.get("error").is_none(),
        "api_mutate ready preflight failed before tool body: {ready}"
    );
    let ready_content = structured_content(&ready);
    assert_eq!(
        ready_content["permission_preflight"]["status"],
        json!("ready")
    );
    assert!(
        ready_content["request_plan"]["required_confirmation_token"]
            .as_str()
            .is_some_and(|token| token.starts_with("cf-api-"))
    );

    ready_arguments["dry_run"] = json!(false);
    let apply_without_confirmation = mcp.call_tool(4, "api_mutate", ready_arguments);
    assert!(
        apply_without_confirmation.get("error").is_none(),
        "api_mutate apply gate failed before tool body: {apply_without_confirmation}"
    );
    let apply_content = structured_content(&apply_without_confirmation);
    assert_eq!(
        apply_content["error"]["code"],
        json!("api_mutate.confirmation_required")
    );

    let rendered = incomplete_content.to_string().to_ascii_lowercase();
    for forbidden in ["dashboard", "novnc", "human"] {
        assert!(
            !rendered.contains(forbidden),
            "found {forbidden}: {rendered}"
        );
    }
}

#[test]
fn api_mutate_keeps_invalid_json_strings_as_strings_in_dry_run_plan() {
    let mut mcp = McpStdioProcess::start();
    let response = mcp.call_tool(
        2,
        "api_mutate",
        json!({
            "operation_id": "d1-query-database",
            "path_params": {
                "account_id": "acct-1",
                "database_id": "db-1"
            },
            "body": "{\"sql\":",
            "dry_run": true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(
        content["request_plan"]["body_normalized_from_json_string"],
        json!(false)
    );
    assert_eq!(content["request_plan"]["body"], json!("{\"sql\":"));
}

#[test]
fn api_mutate_denies_generic_worker_script_upload_and_names_curated_path() {
    let mut mcp = McpStdioProcess::start();
    let prepared = mcp.call_tool(
        2,
        "api_prepare_call",
        json!({
            "operation_id": "worker-script-put-content"
        }),
    );
    let prepared_content = structured_content(&prepared);
    assert_eq!(prepared_content["ok"], json!(false));
    assert_eq!(
        prepared_content["error"]["code"],
        json!("api_catalog.denied_by_default")
    );
    assert_eq!(
        prepared_content["preferred_tool"],
        json!("workers_upload_script")
    );

    let generic_denial = mcp.call_tool(
        3,
        "api_prepare_call",
        json!({
            "operation_id": "account-subscriptions-create-subscription"
        }),
    );
    let generic_denial_content = structured_content(&generic_denial);
    assert_eq!(generic_denial_content["ok"], json!(false));
    assert_eq!(
        generic_denial_content["error"]["code"],
        json!("api_catalog.denied_by_default")
    );
    assert_eq!(
        generic_denial_content["error"]["hint"],
        json!(
            "Use a curated safe tool when available, or explicitly allow this operation in a future policy profile."
        )
    );

    let response = mcp.call_tool(
        4,
        "api_mutate",
        json!({
            "operation_id": "worker-script-put-content",
            "path_params": {
                "account_id": "acct-1",
                "script_name": "worker-fixture"
            },
            "body": {"main_module": "worker.js"},
            "dry_run": true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false));
    assert_eq!(
        content["error"]["code"],
        json!("api_catalog.denied_by_default")
    );
    assert_eq!(
        content["error"]["hint"],
        json!(
            "Use the curated workers_upload_script tool for this operation; generic api_mutate remains denied."
        )
    );
    assert_eq!(content["preferred_tool"], json!("workers_upload_script"));
}

#[test]
fn api_mutate_preserves_non_string_body_shapes_in_dry_run_plan() {
    let mut mcp = McpStdioProcess::start();
    let shapes = BTreeMap::from([
        ("object", json!({"sql": "SELECT 1", "params": []})),
        ("array", json!(["not", "an", "object"])),
        ("null", Value::Null),
    ]);

    for (index, (label, body)) in shapes.into_iter().enumerate() {
        let response = mcp.call_tool(
            10 + index as u64,
            "api_mutate",
            json!({
                "operation_id": "d1-query-database",
                "path_params": {
                    "account_id": "acct-1",
                    "database_id": "db-1"
                },
                "body": body,
                "dry_run": true
            }),
        );
        let content = structured_content(&response);
        assert_eq!(
            content["request_plan"]["body_normalized_from_json_string"],
            json!(false),
            "{label} body should not be treated as a JSON string"
        );
    }
}
