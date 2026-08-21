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
        "query_shape_receipt": null,
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
    #[derive(Serialize)]
    struct ApprovedPlanV2<'a> {
        version: u8,
        operation: &'static str,
        account_id: &'static str,
        database_id: &'static str,
        migration_family: &'static str,
        migrations_table: &'static str,
        manifest: &'a Value,
        execution_manifest: &'a Value,
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
    let approved_plan_sha256 = {
        let transformed = manifest
            .as_array()
            .expect("manifest array")
            .iter()
            .any(|entry| {
                entry["sql"]
                    .as_str()
                    .is_some_and(|sql| sql.starts_with("PRAGMA foreign_keys = ON;\n\n"))
            });
        let bytes = if transformed {
            let execution_manifest = Value::Array(
                manifest
                    .as_array()
                    .expect("manifest array")
                    .iter()
                    .map(|entry| {
                        let name = entry["name"].as_str().expect("migration name");
                        let source_sql = entry["sql"].as_str().expect("migration SQL");
                        let (transform_id, executed_sql) = source_sql
                            .strip_prefix("PRAGMA foreign_keys = ON;\n\n")
                            .map(|sql| ("drop-leading-pragma-foreign-keys-on-v1", sql))
                            .unwrap_or(("identity-v1", source_sql));
                        let provider_sql = format!(
                            "{executed_sql}\n\nINSERT INTO \"d1_migrations\" (name) VALUES ('{}');",
                            name.replace('\'', "''")
                        );
                        json!({
                            "source_name": name,
                            "source_sql_sha256": entry["sql_sha256"],
                            "transform_id": transform_id,
                            "transform_version": 1,
                            "executed_size_bytes": executed_sql.len(),
                            "executed_sql_sha256": sha256_hex(executed_sql),
                            "provider_statement_sha256": sha256_hex(&provider_sql),
                        })
                    })
                    .collect(),
            );
            serde_json::to_vec(&ApprovedPlanV2 {
                version: 2,
                operation: "d1_apply_migration_manifest",
                account_id: "acct-1",
                database_id: "db-1",
                migration_family: "newsletter-core",
                migrations_table: "d1_migrations",
                manifest: &manifest_summary,
                execution_manifest: &execution_manifest,
                ledger: Vec::new(),
            })
            .expect("serialize transformed approved plan")
        } else {
            serde_json::to_vec(&ApprovedPlan {
                version: 1,
                operation: "d1_apply_migration_manifest",
                account_id: "acct-1",
                database_id: "db-1",
                migration_family: "newsletter-core",
                migrations_table: "d1_migrations",
                manifest: &manifest_summary,
                ledger: Vec::new(),
            })
            .expect("serialize legacy approved plan")
        };
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
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
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
                            "meta": {"served_by_primary": true}
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
                    "result": [{"success": true, "results": [{"ok": true}], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}]
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

fn is_manifest_ledger_authority_sql(sql: &str) -> bool {
    sql.starts_with("SELECT type, name, tbl_name, sql FROM sqlite_master ")
}

fn manifest_ledger_authority_response(table: &str) -> Value {
    let schema = format!(
        "CREATE TABLE \"{}\"(\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    name TEXT UNIQUE,\n    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n)",
        table.replace('"', "\"\"")
    );
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": [{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": [{"type": "table", "name": table, "tbl_name": table, "sql": schema}],
        }],
    })
}

fn wrangler_manifest_ledger_authority_response(table: &str) -> Value {
    let schema = format!(
        "CREATE TABLE \"{}\"(\n\t\tid         INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tname       TEXT UNIQUE,\n\t\tapplied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL\n)",
        table.replace('"', "\"\"")
    );
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": [{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": [{"type": "table", "name": table, "tbl_name": table, "sql": schema}],
        }],
    })
}

fn manifest_ledger_response(rows: Vec<Value>) -> Value {
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": [{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": rows,
        }],
    })
}

fn bootstrap_inventory_response(
    initialized: bool,
    conflict: bool,
    cloudflare_internal_visible: bool,
) -> Value {
    let mut results = if conflict {
        vec![json!({
            "type": "table",
            "name": "application_rows",
            "tbl_name": "application_rows",
            "sql": "CREATE TABLE application_rows(id INTEGER)",
        })]
    } else if initialized {
        manifest_ledger_authority_response("d1_migrations")["result"][0]["results"]
            .as_array()
            .expect("canonical authority rows")
            .clone()
    } else {
        Vec::new()
    };
    if cloudflare_internal_visible {
        results.insert(
            0,
            json!({
                "type": "table",
                "name": "_cf_KV",
                "tbl_name": "_cf_KV",
                "sql": "CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID",
            }),
        );
        results.truncate(2);
    }
    json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": [{
            "success": true,
            "errors": [],
            "meta": {"served_by_primary": true},
            "results": results,
        }],
    })
}

fn is_bootstrap_inventory_sql(sql: &str) -> bool {
    sql.starts_with("SELECT type, name, tbl_name, sql FROM sqlite_master ")
        && sql.contains("lower(name) NOT GLOB 'sqlite_*'")
        && sql.ends_with("LIMIT 2")
}

fn spawn_fake_bootstrap_api(
    expected_requests: usize,
    conflict: bool,
    ambiguous_initializer: bool,
    cloudflare_internal_present: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_bootstrap_api_with_inner_result(
        expected_requests,
        conflict,
        ambiguous_initializer,
        cloudflare_internal_present,
        None,
    )
}

fn spawn_fake_bootstrap_api_with_inner_result(
    expected_requests: usize,
    conflict: bool,
    ambiguous_initializer: bool,
    cloudflare_internal_present: bool,
    initializer_inner_result: Option<Value>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let initializer_http_error = ambiguous_initializer.then(|| {
        (
            503,
            9_911,
            "private-initializer-body-marker".to_string(),
            false,
        )
    });
    spawn_fake_bootstrap_api_with_initializer_http_error(
        expected_requests,
        conflict,
        cloudflare_internal_present,
        initializer_inner_result,
        initializer_http_error,
    )
}

fn spawn_fake_bootstrap_api_with_initializer_http_error(
    expected_requests: usize,
    conflict: bool,
    cloudflare_internal_present: bool,
    initializer_inner_result: Option<Value>,
    initializer_http_error: Option<(u16, i64, String, bool)>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind bootstrap D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("bootstrap D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let mut initialized = false;
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("bootstrap D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("bootstrap request JSON");
            requests_for_thread
                .lock()
                .expect("bootstrap request log")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            if sql.starts_with("CREATE TABLE IF NOT EXISTS \"d1_migrations\"") {
                initialized = true;
                if let Some((status, code, message, include_messages)) =
                    initializer_http_error.as_ref()
                {
                    let response = if *include_messages {
                        serde_json::to_vec(&json!({
                            "success": false,
                            "errors": [{"code": code, "message": message}],
                            "messages": [],
                            "result": null,
                        }))
                        .expect("serialize initializer HTTP error")
                    } else {
                        assert_eq!(
                            (*status, *code, message.as_str()),
                            (503, 9_911, "private-initializer-body-marker")
                        );
                        br#"{"success":false,"errors":[{"code":9911,"message":"private-initializer-body-marker"}],"result":null}"#.to_vec()
                    };
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                        .expect("write ambiguous initializer response headers");
                    stream
                        .write_all(&response)
                        .expect("write private ambiguous initializer body");
                    continue;
                }
                let response = serde_json::to_vec(&json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": initializer_inner_result.clone().unwrap_or_else(|| json!([{
                        "success": true,
                        "errors": [],
                        "results": [],
                        "meta": {
                            "served_by_primary": true,
                            "changed_db": true,
                            "changes": 0,
                            "rows_written": 0,
                        },
                    }])),
                }))
                .expect("serialize initializer response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                    .expect("write initializer headers");
                stream
                    .write_all(&response)
                    .expect("write initializer response");
                continue;
            }
            let response = if is_bootstrap_inventory_sql(sql) {
                let filters_cloudflare_internal = sql.contains("lower(name) NOT GLOB '_cf_*'")
                    && sql.contains("lower(tbl_name) NOT GLOB '_cf_*'");
                bootstrap_inventory_response(
                    initialized,
                    conflict,
                    cloudflare_internal_present && !filters_cloudflare_internal,
                )
            } else if sql == "SELECT * FROM \"d1_migrations\" ORDER BY id" {
                assert!(initialized, "ledger reads follow initializer dispatch");
                manifest_ledger_response(Vec::new())
            } else {
                panic!("unexpected bootstrap SQL: {sql}");
            };
            let response = serde_json::to_vec(&response).expect("serialize bootstrap response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write bootstrap headers");
            stream
                .write_all(&response)
                .expect("write bootstrap response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

#[derive(Clone, Copy)]
enum BootstrapReadFault {
    HttpStatus(u16),
    Redirect,
    TransportLoss,
    Truncated(bool),
    Oversized,
    MalformedJson,
    InvalidUtf8,
    PrimaryMarkerWrongType,
    Unstable,
}

fn spawn_fake_bootstrap_read_fault_api(
    fault: BootstrapReadFault,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind bootstrap read-fault API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("bootstrap read-fault address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let expected_calls = if matches!(fault, BootstrapReadFault::Unstable) {
        2
    } else {
        1
    };
    thread::spawn(move || {
        for (index, stream) in listener.incoming().take(expected_calls).enumerate() {
            let mut stream = stream.expect("bootstrap read-fault stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let request: Value =
                serde_json::from_slice(&body).expect("bootstrap read-fault request JSON");
            assert!(is_bootstrap_inventory_sql(
                request["sql"].as_str().unwrap_or_default()
            ));
            requests_for_thread
                .lock()
                .expect("bootstrap read-fault request log")
                .push(request);
            match fault {
                BootstrapReadFault::HttpStatus(status) => {
                    let response = reconciliation_http_error_response(status);
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                        .expect("write bootstrap HTTP error headers");
                    stream
                        .write_all(&response)
                        .expect("write bootstrap HTTP error body");
                }
                BootstrapReadFault::Redirect => {
                    let response = b"redirect refused";
                    write!(stream, "HTTP/1.1 302 Found\r\nconnection: close\r\nlocation: http://127.0.0.1:9/must-not-be-followed\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n", response.len()) // DevSkim: ignore DS137138 -- loopback-only no-follow fixture
                        .expect("write bootstrap redirect headers");
                    stream
                        .write_all(response)
                        .expect("write bootstrap redirect body");
                }
                BootstrapReadFault::TransportLoss => {}
                BootstrapReadFault::Truncated(partial) => {
                    write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n")
                        .expect("write bootstrap truncated headers");
                    if partial {
                        stream
                            .write_all(b"{")
                            .expect("write bootstrap partial response body");
                    }
                }
                BootstrapReadFault::Oversized => {
                    write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", 16 * 1024 * 1024 + 1)
                        .expect("write oversized bootstrap headers");
                }
                BootstrapReadFault::MalformedJson => {
                    let response = b"{";
                    write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                        .expect("write malformed bootstrap JSON headers");
                    stream
                        .write_all(response)
                        .expect("write malformed bootstrap JSON");
                }
                BootstrapReadFault::InvalidUtf8 => {
                    let response = [0xff, 0xfe];
                    write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                        .expect("write invalid UTF-8 bootstrap headers");
                    stream
                        .write_all(&response)
                        .expect("write invalid UTF-8 bootstrap body");
                }
                BootstrapReadFault::PrimaryMarkerWrongType => {
                    let mut response = bootstrap_inventory_response(false, false, false);
                    response["result"][0]["meta"]["served_by_primary"] = json!("true");
                    let response =
                        serde_json::to_vec(&response).expect("serialize primary-marker fault");
                    write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                        .expect("write primary-marker fault headers");
                    stream
                        .write_all(&response)
                        .expect("write primary-marker fault body");
                }
                BootstrapReadFault::Unstable => {
                    let response = bootstrap_inventory_response(false, index == 1, false);
                    let response =
                        serde_json::to_vec(&response).expect("serialize unstable bootstrap read");
                    write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                        .expect("write unstable bootstrap headers");
                    stream
                        .write_all(&response)
                        .expect("write unstable bootstrap response");
                }
            }
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

enum BootstrapRecoveryFixtureFault {
    CustodyDrift(PathBuf),
    TargetReadOnly(PathBuf),
}

fn spawn_fake_initialized_bootstrap_recovery_api(
    expected_requests: usize,
    fault: Option<(usize, BootstrapRecoveryFixtureFault)>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind initialized bootstrap recovery API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("initialized bootstrap recovery address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (index, stream) in listener.incoming().take(expected_requests).enumerate() {
            let mut stream = stream.expect("initialized bootstrap recovery stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("bootstrap recovery request JSON");
            requests_for_thread
                .lock()
                .expect("bootstrap recovery request log")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let response = if is_bootstrap_inventory_sql(sql) {
                bootstrap_inventory_response(true, false, false)
            } else if sql == "SELECT * FROM \"d1_migrations\" ORDER BY id" {
                manifest_ledger_response(Vec::new())
            } else {
                panic!("unexpected initialized bootstrap recovery SQL: {sql}");
            };
            let response =
                serde_json::to_vec(&response).expect("serialize bootstrap recovery response");
            if fault
                .as_ref()
                .is_some_and(|(request, _)| *request == index + 1)
            {
                match &fault.as_ref().expect("selected bootstrap fault").1 {
                    BootstrapRecoveryFixtureFault::CustodyDrift(active) => {
                        fs::rename(active, active.with_extension("custody-drifted"))
                            .expect("displace active bootstrap custody before response completion");
                    }
                    BootstrapRecoveryFixtureFault::TargetReadOnly(target) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            fs::set_permissions(target, fs::Permissions::from_mode(0o500))
                                .expect("make bootstrap target read-only before retirement");
                        }
                    }
                }
            }
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write initialized bootstrap recovery headers");
            stream
                .write_all(&response)
                .expect("write initialized bootstrap recovery response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_bootstrap_recovery_http_failure_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind bootstrap recovery failure API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("bootstrap recovery failure address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("bootstrap recovery failure stream");
        let (headers, body) = read_http_request(&mut stream);
        assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
        let body_json: Value =
            serde_json::from_slice(&body).expect("bootstrap recovery failure request JSON");
        requests_for_thread
            .lock()
            .expect("bootstrap recovery failure request log")
            .push(body_json);
        let response = serde_json::to_vec(&json!({
            "success": false,
            "errors": [{"code": 7500, "message": "provider unavailable"}],
            "messages": [],
            "result": null,
        }))
        .expect("serialize bootstrap recovery failure response");
        write!(stream, "HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
            .expect("write bootstrap recovery failure headers");
        stream
            .write_all(&response)
            .expect("write bootstrap recovery failure response");
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_manifest_authority_rejection_api(
    authority_responses: Vec<Value>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind authority rejection D1 API");
    let addr = listener
        .local_addr()
        .expect("authority rejection D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (index, stream) in listener
            .incoming()
            .take(authority_responses.len().saturating_add(1))
            .enumerate()
        {
            let mut stream = stream.expect("authority rejection request");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("authority request JSON");
            requests_for_thread
                .lock()
                .expect("authority request log")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let response = if index == 0 {
                assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
                manifest_ledger_response(Vec::new())
            } else {
                assert!(is_manifest_ledger_authority_sql(sql));
                authority_responses[index - 1].clone()
            };
            let response = serde_json::to_vec(&response).expect("serialize authority response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write authority headers");
            stream
                .write_all(&response)
                .expect("write authority response");
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
        for stream in listener.incoming().take(12) {
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
            let response = if is_manifest_ledger_authority_sql(sql) {
                manifest_ledger_authority_response("d1_migrations")
            } else if sql == "SELECT * FROM \"d1_migrations\" ORDER BY id" {
                manifest_ledger_response(ledger)
            } else if sql
                .contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0002_second.sql')")
            {
                apply_seen = true;
                json!({"success": true, "errors": [], "messages": [], "result": [{"success": true, "results": [{"ok": true}], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}]})
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

/// A bounded provider fixture whose authority responses are consumed exactly
/// in query order.  It is deliberately separate from the happy-path fixture
/// so drift tests prove that no hidden adapter retry can turn an unstable
/// two-read authority proof into a provider mutation.
fn spawn_manifest_authority_schedule_api(
    initial_ledger: Vec<Value>,
    authority_responses: Vec<Value>,
    expected_requests: usize,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_manifest_authority_schedule_api_for_table(
        "d1_migrations",
        initial_ledger,
        authority_responses,
        expected_requests,
    )
}

fn spawn_manifest_authority_schedule_api_for_table(
    migrations_table: &str,
    initial_ledger: Vec<Value>,
    authority_responses: Vec<Value>,
    expected_requests: usize,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind authority schedule D1 API");
    let addr = listener
        .local_addr()
        .expect("authority schedule D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let migrations_table = migrations_table.to_string();
    thread::spawn(move || {
        let mut authority = authority_responses.into_iter();
        let mut writes = 0_usize;
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("authority schedule request");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("authority schedule JSON");
            let sql = body_json["sql"].as_str().unwrap_or_default();
            requests_for_thread
                .lock()
                .expect("authority schedule request log")
                .push(body_json.clone());
            let response = if is_manifest_ledger_authority_sql(sql) {
                authority
                    .next()
                    .expect("bounded authority response for every authority query")
            } else if sql == format!("SELECT * FROM \"{migrations_table}\" ORDER BY id") {
                let mut ledger = initial_ledger.clone();
                if writes > 0
                    && !ledger
                        .iter()
                        .any(|row| row["name"] == json!("0002_second.sql"))
                {
                    ledger.push(json!({"id": 2, "name": "0002_second.sql"}));
                }
                manifest_ledger_response(ledger)
            } else if sql.contains(&format!("INSERT INTO \"{migrations_table}\"")) {
                writes += 1;
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "errors": [], "results": [{"ok": true}], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}],
                })
            } else {
                panic!("unexpected authority schedule SQL: {sql}");
            };
            let response = serde_json::to_vec(&response).expect("serialize authority schedule");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write authority schedule headers");
            stream
                .write_all(&response)
                .expect("write authority schedule response");
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
        for request_index in 0..4 {
            let mut stream = listener
                .accept()
                .expect("accept blocked manifest request")
                .0;
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("blocked request JSON");
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let is_authority = is_manifest_ledger_authority_sql(sql);
            assert!(is_authority || sql == "SELECT * FROM \"d1_migrations\" ORDER BY id");
            requests_for_thread
                .lock()
                .expect("blocked request log")
                .push(body_json);
            if request_index == 3 {
                entered_tx.send(()).expect("notify held active lease");
                resume_rx.recv().expect("release blocked preflight");
            }
            let response = serde_json::to_vec(&if is_authority {
                manifest_ledger_authority_response("d1_migrations")
            } else {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "meta": {"served_by_primary": true}, "results": [{"id": 1, "name": "0001_initial.sql"}]}]
                })
            })
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
        for stream in listener.incoming().take(3) {
            let mut stream = stream.expect("fake malformed ledger D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("malformed ledger request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let response = serde_json::to_vec(&if is_manifest_ledger_authority_sql(sql) {
                manifest_ledger_authority_response("d1_migrations")
            } else {
                assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [result_set],
                })
            })
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
        let expected_requests = if error_on_write { 10 } else { 4 };
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
            if is_manifest_ledger_authority_sql(sql) {
                let response =
                    serde_json::to_vec(&manifest_ledger_authority_response("d1_migrations"))
                        .expect("serialize authority response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write authority response headers");
                stream
                    .write_all(&response)
                    .expect("write authority response");
                continue;
            }
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
                    "meta": {"served_by_primary": true},
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
    spawn_fake_manifest_http_error_api(ledger_names_commit_after_ambiguous_response, None)
}

fn spawn_fake_manifest_http_error_api(
    ledger_names_commit_after_ambiguous_response: bool,
    provider_error: Option<(u16, i64, String, bool)>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ambiguous manifest D1 API");
    let addr = listener.local_addr().expect("ambiguous manifest D1 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let mut apply_seen = false;
        for stream in listener.incoming().take(10) {
            let mut stream = stream.expect("fake ambiguous manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("ambiguous request JSON");
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            if is_manifest_ledger_authority_sql(sql) {
                let response =
                    serde_json::to_vec(&manifest_ledger_authority_response("d1_migrations"))
                        .expect("serialize authority response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write authority headers");
                stream
                    .write_all(&response)
                    .expect("write authority response");
                continue;
            }
            if sql.contains("INSERT INTO \"d1_migrations\"") {
                apply_seen = ledger_names_commit_after_ambiguous_response;
                if let Some((status, code, message, omit_messages)) = provider_error.as_ref() {
                    let mut envelope = json!({
                        "success": false,
                        "errors": [{"code": code, "message": message}],
                        "messages": [],
                        "result": null,
                    });
                    if *omit_messages {
                        envelope
                            .as_object_mut()
                            .expect("synthetic migration provider error envelope")
                            .remove("messages");
                    }
                    let response =
                        serde_json::to_vec(&envelope).expect("serialize migration provider error");
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write migration provider-error headers");
                    stream
                        .write_all(&response)
                        .expect("write migration provider-error body");
                } else {
                    write!(stream, "HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-length: 0\r\n\r\n").expect("write ambiguous response");
                }
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
            let response =
                serde_json::to_vec(&manifest_ledger_response(ledger)).expect("serialize response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write headers");
            stream.write_all(&response).expect("write response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_manifest_oversized_write_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind oversized manifest D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("oversized manifest D1 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(10) {
            let mut stream = stream.expect("oversized manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("oversized manifest request JSON");
            requests_for_thread
                .lock()
                .expect("oversized manifest request log")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            if is_manifest_ledger_authority_sql(sql) {
                let response =
                    serde_json::to_vec(&manifest_ledger_authority_response("d1_migrations"))
                        .expect("serialize oversized fixture authority response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write oversized fixture authority headers");
                stream
                    .write_all(&response)
                    .expect("write oversized fixture authority response");
                continue;
            }
            if sql.contains("INSERT INTO \"d1_migrations\"") {
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", 16 * 1024 * 1024 + 1)
                    .expect("write oversized migration response headers");
                continue;
            }
            assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
            let response = serde_json::to_vec(&manifest_ledger_response(vec![json!({
                "id": 1,
                "name": "0001_initial.sql"
            })]))
            .expect("serialize oversized fixture ledger response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write oversized fixture ledger headers");
            stream
                .write_all(&response)
                .expect("write oversized fixture ledger response");
        }
    });
    (format!("http://{addr}"), requests)
}

fn spawn_fake_manifest_deep_write_api(private_message: &str) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind deep manifest D1 API");
    let addr = listener.local_addr().expect("deep manifest D1 addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let private_message = private_message.to_string();
    thread::spawn(move || {
        for stream in listener.incoming().take(10) {
            let mut stream = stream.expect("deep manifest D1 stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("deep manifest request JSON");
            requests_for_thread
                .lock()
                .expect("deep manifest request log")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            let response = if is_manifest_ledger_authority_sql(sql) {
                serde_json::to_vec(&manifest_ledger_authority_response("d1_migrations"))
                    .expect("serialize deep fixture authority response")
            } else if sql.contains("INSERT INTO \"d1_migrations\"") {
                let nested = format!("{}0{}", "[".repeat(40), "]".repeat(40));
                format!(
                    r#"{{"success":true,"errors":[],"messages":[],"result":[{{"success":true,"errors":[],"results":[{{"ok":true,"message":{},"nested":{nested}}}],"meta":{{"served_by_primary":true,"changed_db":true,"changes":1,"rows_written":1}}}}]}}"#,
                    serde_json::to_string(&private_message)
                        .expect("serialize private deep acknowledgement message")
                )
                .into_bytes()
            } else {
                assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
                serde_json::to_vec(&manifest_ledger_response(vec![json!({
                    "id": 1,
                    "name": "0001_initial.sql"
                })]))
                .expect("serialize deep fixture ledger response")
            };
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write deep manifest response headers");
            stream
                .write_all(&response)
                .expect("write deep manifest response");
        }
    });
    (format!("http://{addr}"), requests)
}

/// Coordinate one response-loss boundary so the test can alter local custody
/// only after the non-idempotent write has reached its provider boundary.
fn spawn_blocked_ambiguous_manifest_api() -> (
    String,
    Arc<Mutex<Vec<Value>>>,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind blocked ambiguous D1 API");
    let addr = listener
        .local_addr()
        .expect("blocked ambiguous manifest address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    thread::spawn(move || {
        for _ in 0..10 {
            let mut stream = listener
                .accept()
                .expect("accept blocked ambiguous request")
                .0;
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("blocked ambiguous JSON");
            requests_for_thread
                .lock()
                .expect("blocked ambiguous request log")
                .push(body_json.clone());
            let sql = body_json["sql"].as_str().unwrap_or_default();
            if is_manifest_ledger_authority_sql(sql) {
                let response =
                    serde_json::to_vec(&manifest_ledger_authority_response("d1_migrations"))
                        .expect("serialize blocked authority response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write blocked authority headers");
                stream
                    .write_all(&response)
                    .expect("write blocked authority response");
                continue;
            }
            if sql.contains("INSERT INTO \"d1_migrations\"") {
                entered_tx.send(()).expect("notify write dispatch");
                resume_rx
                    .recv()
                    .expect("resume ambiguous provider response");
                write!(stream, "HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-length: 0\r\n\r\n")
                    .expect("write ambiguous provider response");
                continue;
            }
            assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
            let response = serde_json::to_vec(&manifest_ledger_response(vec![json!({
                "id": 1,
                "name": "0001_initial.sql"
            })]))
            .expect("serialize blocked ledger response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write blocked ledger headers");
            stream
                .write_all(&response)
                .expect("write blocked ledger response");
        }
    });
    (format!("http://{addr}"), requests, entered_rx, resume_tx)
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
    CustodyRelease(PathBuf, PathBuf),
    SecondBatchCustodyDrift(PathBuf),
    PrimaryMetaMissing,
    PrimaryMarkerMissing,
    PrimaryMarkerFalse,
    PrimaryMarkerNull,
    PrimaryMarkerWrongType,
    MixedPrimaryMarkers,
    SecondBatchPrimaryFalse,
    SecondBatchHttpStatus(u16),
    SecondBatchAllowlistedHttpError(u16, i64, String),
    SecondBatchDeepHttpError(u16, String),
    SecondBatchTransportFailure(Option<PathBuf>),
    RequestTransportFailure(usize),
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

fn predecessor_two_table_full_union_query(proof_sha256: &str) -> String {
    fn marker(proof_sha256: &str, logical_identity: &str) -> String {
        sha256_hex(&format!(
            "d1-reconciliation-statement-v1\0{proof_sha256}\0{logical_identity}"
        ))
    }

    fn tagged(
        marker: &str,
        fields: &[&str],
        data_sql: &str,
        data_order_positions: &[usize],
    ) -> String {
        let null_fields = fields
            .iter()
            .map(|field| format!("NULL AS \"{field}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut order = vec!["2".to_string()];
        order.extend(data_order_positions.iter().map(ToString::to_string));
        format!(
            "SELECT '{marker}' AS \"__cf_mcp_statement_id\", 0 AS \"__cf_mcp_row_kind\", {null_fields} UNION ALL SELECT '{marker}', 1, * FROM ({data_sql}) ORDER BY {}",
            order.join(", ")
        )
    }

    let mut statements = vec![
        tagged(
            &marker(proof_sha256, "ledger"),
            &["id", "name"],
            "SELECT id, name FROM \"d1_migrations\" ORDER BY id LIMIT 3",
            &[3],
        ),
        tagged(
            &marker(proof_sha256, "sqlite_master"),
            &["type", "name", "tbl_name", "sql"],
            "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name COLLATE NOCASE IN ('Current', 'Future') ORDER BY type, name LIMIT 3",
            &[3, 4],
        ),
    ];
    for table in ["Current", "Future"] {
        statements.extend([
            tagged(
                &marker(proof_sha256, &format!("table_xinfo\0{table}")),
                &[
                    "cid",
                    "name",
                    "type",
                    "notnull",
                    "dflt_value",
                    "pk",
                    "hidden",
                ],
                &format!(
                    "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo('{table}') ORDER BY cid LIMIT 257"
                ),
                &[3],
            ),
            tagged(
                &marker(proof_sha256, &format!("foreign_key_list\0{table}")),
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
                &format!(
                    "SELECT id, seq, \"table\", \"from\", \"to\", on_update, on_delete, \"match\" FROM pragma_foreign_key_list('{table}') ORDER BY id, seq LIMIT 257"
                ),
                &[3, 4],
            ),
            tagged(
                &marker(proof_sha256, &format!("foreign_key_check\0{table}")),
                &["table", "rowid", "parent", "fkid"],
                &format!(
                    "SELECT \"table\", rowid, parent, fkid FROM pragma_foreign_key_check('{table}') LIMIT 1"
                ),
                &[],
            ),
        ]);
    }
    statements.join(";\n")
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

fn two_table_partial_reconciliation_case() -> (Value, Value) {
    let current_sql = "CREATE TABLE Current(id TEXT PRIMARY KEY)";
    let future_sql = "CREATE TABLE Future(id TEXT PRIMARY KEY)";
    let first_sql = format!("{current_sql};");
    let second_sql = format!("{future_sql};");
    let manifest = json!([
        {
            "name": "0001_current.sql",
            "size_bytes": first_sql.len(),
            "sql_sha256": sha256_hex(&first_sql),
            "sql": first_sql,
        },
        {
            "name": "0002_future.sql",
            "size_bytes": second_sql.len(),
            "sql_sha256": sha256_hex(&second_sql),
            "sql": second_sql,
        },
    ]);
    let column = json!({
        "cid": 0,
        "name": "id",
        "declared_type": "TEXT",
        "not_null": false,
        "default_value": null,
        "primary_key_position": 1,
        "hidden": 0,
    });
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "Current",
                "table_name": "Current",
                "sql_sha256": sha256_hex(current_sql),
            }],
            "tables": [{
                "name": "Current",
                "columns": [column.clone()],
                "foreign_keys": [],
            }],
        },
        {
            "manifest_prefix_length": 2,
            "schema_objects": [
                {
                    "object_type": "table",
                    "name": "Current",
                    "table_name": "Current",
                    "sql_sha256": sha256_hex(current_sql),
                },
                {
                    "object_type": "table",
                    "name": "Future",
                    "table_name": "Future",
                    "sql_sha256": sha256_hex(future_sql),
                },
            ],
            "tables": [
                {"name": "Current", "columns": [column.clone()], "foreign_keys": []},
                {"name": "Future", "columns": [column], "foreign_keys": []},
            ],
        },
    ]);
    (manifest, expectations)
}

fn table_index_view_trigger_reconciliation_case() -> (Value, Value, Vec<Value>) {
    let table_sql = "CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)";
    let index_sql = "CREATE INDEX items_by_name ON items(name)";
    let view_sql = "CREATE VIEW item_names AS SELECT id, name FROM items";
    let trigger_sql = "CREATE TRIGGER items_after_update AFTER UPDATE OF name ON items BEGIN INSERT INTO item_audit(item_id, value) VALUES (NEW.id, CASE WHEN NEW.name = '' THEN 'empty' ELSE NEW.name END); UPDATE items SET name = NEW.name WHERE id = NEW.id; END";
    let migration_sql = format!("{table_sql};\n{index_sql};\n{view_sql};\n{trigger_sql};");
    let manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": migration_sql.len(),
        "sql_sha256": sha256_hex(&migration_sql),
        "sql": migration_sql,
    }]);
    let schema_rows = vec![
        json!({"type": "index", "name": "items_by_name", "tbl_name": "items", "sql": index_sql}),
        json!({"type": "table", "name": "items", "tbl_name": "items", "sql": table_sql}),
        json!({"type": "trigger", "name": "items_after_update", "tbl_name": "items", "sql": trigger_sql}),
        json!({"type": "view", "name": "item_names", "tbl_name": "item_names", "sql": view_sql}),
    ];
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [
                {
                    "object_type": "index",
                    "name": "items_by_name",
                    "table_name": "items",
                    "sql_sha256": sha256_hex(index_sql),
                },
                {
                    "object_type": "table",
                    "name": "items",
                    "table_name": "items",
                    "sql_sha256": sha256_hex(table_sql),
                },
                {
                    "object_type": "trigger",
                    "name": "items_after_update",
                    "table_name": "items",
                    "sql_sha256": sha256_hex(trigger_sql),
                },
                {
                    "object_type": "view",
                    "name": "item_names",
                    "table_name": "item_names",
                    "sql_sha256": sha256_hex(view_sql),
                },
            ],
            "tables": [{
                "name": "items",
                "columns": [
                    {
                        "cid": 0,
                        "name": "id",
                        "declared_type": "INTEGER",
                        "not_null": false,
                        "default_value": null,
                        "primary_key_position": 1,
                        "hidden": 0,
                    },
                    {
                        "cid": 1,
                        "name": "name",
                        "declared_type": "TEXT",
                        "not_null": false,
                        "default_value": null,
                        "primary_key_position": 0,
                        "hidden": 0,
                    },
                ],
                "foreign_keys": [],
            }],
        }
    ]);
    (manifest, expectations, schema_rows)
}

fn additive_reconciliation_case() -> (Value, Value, Vec<Value>) {
    let baseline_sql = "CREATE TABLE items(id INTEGER PRIMARY KEY)";
    let current_sql = "CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)";
    let migration_sql = "PRAGMA foreign_keys = ON; ALTER TABLE items ADD COLUMN name TEXT;";
    let manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": migration_sql.len(),
        "sql_sha256": sha256_hex(migration_sql),
        "sql": migration_sql,
    }]);
    let baseline_column = json!({
        "cid": 0,
        "name": "id",
        "declared_type": "INTEGER",
        "not_null": false,
        "default_value": null,
        "primary_key_position": 1,
        "hidden": 0,
    });
    let added_column = json!({
        "cid": 1,
        "name": "name",
        "declared_type": "TEXT",
        "not_null": false,
        "default_value": null,
        "primary_key_position": 0,
        "hidden": 0,
    });
    let expectations = json!([
        {
            "manifest_prefix_length": 0,
            "schema_objects": [{
                "object_type": "table",
                "name": "items",
                "table_name": "items",
                "sql_sha256": sha256_hex(baseline_sql),
            }],
            "tables": [{
                "name": "items",
                "columns": [baseline_column.clone()],
                "foreign_keys": [],
            }],
        },
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "items",
                "table_name": "items",
                "sql_sha256": sha256_hex(current_sql),
            }],
            "tables": [{
                "name": "items",
                "columns": [baseline_column, added_column],
                "foreign_keys": [],
            }],
        }
    ]);
    let schema_rows =
        vec![json!({"type": "table", "name": "items", "tbl_name": "items", "sql": current_sql})];
    (manifest, expectations, schema_rows)
}

fn uppercase_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn seed_rowset_sha256(table_name: &str, columns: &[&str], rows: &[&[&str]]) -> String {
    let mut rows = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|value| {
                    json!({
                        "storage_class": "text",
                        "value": uppercase_hex(value),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        serde_json::to_vec(left)
            .expect("seed row serialization")
            .cmp(&serde_json::to_vec(right).expect("seed row serialization"))
    });
    sha256_hex(
        &serde_json::to_string(&json!({
            "version": 1,
            "table_name": table_name,
            "columns": columns,
            "rows": rows,
        }))
        .expect("seed row-set proof serialization"),
    )
}

fn typed_seed_rowset_sha256(table_name: &str, columns: &[&str], rows: Vec<Vec<Value>>) -> String {
    typed_seed_rowset_sha256_version(1, table_name, columns, rows)
}

fn typed_seed_rowset_sha256_version(
    version: u8,
    table_name: &str,
    columns: &[&str],
    mut rows: Vec<Vec<Value>>,
) -> String {
    rows.sort_by(|left, right| {
        serde_json::to_vec(left)
            .expect("typed seed row serialization")
            .cmp(&serde_json::to_vec(right).expect("typed seed row serialization"))
    });
    sha256_hex(
        &serde_json::to_string(&json!({
            "version": version,
            "table_name": table_name,
            "columns": columns,
            "rows": rows,
        }))
        .expect("typed seed row-set proof serialization"),
    )
}

fn canonical_seed_row_reconciliation_case() -> (Value, Value, Vec<Value>, Vec<Value>) {
    let publications_table_sql =
        "CREATE TABLE publications(publication TEXT PRIMARY KEY, display_name TEXT NOT NULL)";
    let publications_insert_sql = "INSERT INTO publications (publication, display_name) VALUES ('daily', 'Daily'), ('events', 'Events'), ('weekly', 'Weekly')";
    let origins_table_sql = "CREATE TABLE trusted_first_party_origins(origin TEXT PRIMARY KEY)";
    let origins_insert_sql = "INSERT INTO trusted_first_party_origins (origin) VALUES ('https://example.com'), ('https://www.example.com')";
    let origins_trigger_sql = "CREATE TRIGGER trusted_first_party_origins_no_update BEFORE UPDATE ON trusted_first_party_origins BEGIN SELECT RAISE(ABORT, 'immutable seed'); END";
    let migration_one_sql = format!("{publications_table_sql};\n{publications_insert_sql};");
    let migration_two_sql =
        format!("{origins_table_sql};\n{origins_insert_sql};\n{origins_trigger_sql};");
    let manifest = json!([
        {
            "name": "0001_publications.sql",
            "size_bytes": migration_one_sql.len(),
            "sql_sha256": sha256_hex(&migration_one_sql),
            "sql": migration_one_sql,
        },
        {
            "name": "0002_trusted_origins.sql",
            "size_bytes": migration_two_sql.len(),
            "sql_sha256": sha256_hex(&migration_two_sql),
            "sql": migration_two_sql,
        },
    ]);
    let publication_seed = json!({
        "table_name": "publications",
        "columns": ["publication", "display_name"],
        "row_count": 3,
        "rows_sha256": seed_rowset_sha256(
            "publications",
            &["publication", "display_name"],
            &[
                &["daily", "Daily"],
                &["events", "Events"],
                &["weekly", "Weekly"],
            ],
        ),
    });
    let origin_seed = json!({
        "table_name": "trusted_first_party_origins",
        "columns": ["origin"],
        "row_count": 2,
        "rows_sha256": seed_rowset_sha256(
            "trusted_first_party_origins",
            &["origin"],
            &[
                &["https://example.com"],
                &["https://www.example.com"],
            ],
        ),
    });
    let publications_object = json!({
        "object_type": "table",
        "name": "publications",
        "table_name": "publications",
        "sql_sha256": sha256_hex(publications_table_sql),
    });
    let origins_object = json!({
        "object_type": "table",
        "name": "trusted_first_party_origins",
        "table_name": "trusted_first_party_origins",
        "sql_sha256": sha256_hex(origins_table_sql),
    });
    let trigger_object = json!({
        "object_type": "trigger",
        "name": "trusted_first_party_origins_no_update",
        "table_name": "trusted_first_party_origins",
        "sql_sha256": sha256_hex(origins_trigger_sql),
    });
    let publications_table = json!({
        "name": "publications",
        "columns": [
            {"cid": 0, "name": "publication", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 1, "hidden": 0},
            {"cid": 1, "name": "display_name", "declared_type": "TEXT", "not_null": true, "default_value": null, "primary_key_position": 0, "hidden": 0},
        ],
        "foreign_keys": [],
    });
    let origins_table = json!({
        "name": "trusted_first_party_origins",
        "columns": [
            {"cid": 0, "name": "origin", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 1, "hidden": 0},
        ],
        "foreign_keys": [],
    });
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [publications_object.clone()],
            "tables": [publications_table.clone()],
            "seed_tables": [publication_seed.clone()],
        },
        {
            "manifest_prefix_length": 2,
            "schema_objects": [publications_object, origins_object, trigger_object],
            "tables": [publications_table, origins_table],
            "seed_tables": [publication_seed, origin_seed],
        },
    ]);
    let schema_rows = vec![
        json!({"type": "table", "name": "publications", "tbl_name": "publications", "sql": publications_table_sql}),
        json!({"type": "table", "name": "trusted_first_party_origins", "tbl_name": "trusted_first_party_origins", "sql": origins_table_sql}),
        json!({"type": "trigger", "name": "trusted_first_party_origins_no_update", "tbl_name": "trusted_first_party_origins", "sql": origins_trigger_sql}),
    ];
    let ledger_rows = vec![
        json!({"id": 1, "name": "0001_publications.sql"}),
        json!({"id": 2, "name": "0002_trusted_origins.sql"}),
    ];
    (manifest, expectations, schema_rows, ledger_rows)
}

fn seed_prefix_reconciliation_case() -> (Value, Value) {
    let create_sql = "CREATE TABLE Channels(id TEXT PRIMARY KEY);";
    let seed_sql = "INSERT INTO channels (id) VALUES ('daily');";
    let manifest = json!([
        {
            "name": "0001_create.sql",
            "size_bytes": create_sql.len(),
            "sql_sha256": sha256_hex(create_sql),
            "sql": create_sql,
        },
        {
            "name": "0002_seed.sql",
            "size_bytes": seed_sql.len(),
            "sql_sha256": sha256_hex(seed_sql),
            "sql": seed_sql,
        }
    ]);
    let table_object = json!({
        "object_type": "table",
        "name": "Channels",
        "table_name": "Channels",
        "sql_sha256": sha256_hex("CREATE TABLE Channels(id TEXT PRIMARY KEY)"),
    });
    let table = json!({
        "name": "Channels",
        "columns": [{
            "cid": 0,
            "name": "id",
            "declared_type": "TEXT",
            "not_null": false,
            "default_value": null,
            "primary_key_position": 1,
            "hidden": 0,
        }],
        "foreign_keys": [],
    });
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [table_object.clone()],
            "tables": [table.clone()],
            "seed_tables": [{
                "table_name": "Channels",
                "columns": ["id"],
                "row_count": 0,
                "rows_sha256": typed_seed_rowset_sha256("Channels", &["id"], Vec::new()),
            }],
        },
        {
            "manifest_prefix_length": 2,
            "schema_objects": [table_object],
            "tables": [table],
            "seed_tables": [{
                "table_name": "Channels",
                "columns": ["id"],
                "row_count": 1,
                "rows_sha256": typed_seed_rowset_sha256(
                    "Channels",
                    &["id"],
                    vec![vec![json!({
                        "storage_class": "text",
                        "value": uppercase_hex("daily"),
                    })]],
                ),
            }],
        },
    ]);
    (manifest, expectations)
}

fn additive_check_reconciliation_case() -> (Value, Value, Vec<Value>, Vec<Value>, Vec<Value>) {
    let additions = [
        (
            "plain_col TEXT",
            json!({"cid": 1, "name": "plain_col", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 0, "hidden": 0}),
        ),
        (
            "token TEXT CHECK (token IS NULL OR (length(token)=35 AND substr(token,1,3)='pre'))",
            json!({"cid": 2, "name": "token", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 0, "hidden": 0}),
        ),
        (
            "state TEXT NOT NULL DEFAULT 'x' CHECK (state='x')",
            json!({"cid": 3, "name": "state", "declared_type": "TEXT", "not_null": true, "default_value": "'x'", "primary_key_position": 0, "hidden": 0}),
        ),
        (
            "kind TEXT NOT NULL DEFAULT 'x' CHECK (kind IN ('x','y'))",
            json!({"cid": 4, "name": "kind", "declared_type": "TEXT", "not_null": true, "default_value": "'x'", "primary_key_position": 0, "hidden": 0}),
        ),
        (
            "rank INTEGER DEFAULT 0",
            json!({"cid": 5, "name": "rank", "declared_type": "INTEGER", "not_null": false, "default_value": "0", "primary_key_position": 0, "hidden": 0}),
        ),
    ];
    let index_sql = "CREATE INDEX records_by_state ON records(state)";
    let view_sql = "CREATE VIEW record_ids AS SELECT id FROM records";
    let baseline_column = json!({
        "cid": 0,
        "name": "id",
        "declared_type": "INTEGER",
        "not_null": false,
        "default_value": null,
        "primary_key_position": 1,
        "hidden": 0,
    });
    let mut definitions = vec!["id INTEGER PRIMARY KEY".to_string()];
    let mut columns = vec![baseline_column.clone()];
    let mut table_sql = "CREATE TABLE records(id INTEGER PRIMARY KEY)".to_string();
    let mut expectations = vec![json!({
        "manifest_prefix_length": 0,
        "schema_objects": [{
            "object_type": "table",
            "name": "records",
            "table_name": "records",
            "sql_sha256": sha256_hex(&table_sql),
        }],
        "tables": [{"name": "records", "columns": columns.clone(), "foreign_keys": []}],
    })];
    let mut manifest = Vec::new();
    let mut ledger_rows = Vec::new();

    for (index, (definition, column)) in additions.iter().enumerate() {
        let migration_number = index + 1;
        let name = format!("{migration_number:04}_add.sql");
        let mut sql =
            format!("PRAGMA foreign_keys = ON; ALTER TABLE records ADD COLUMN {definition};");
        if migration_number == 4 {
            sql.push_str(" CREATE INDEX records_by_state ON records(state);");
        }
        if migration_number == 5 {
            sql.push_str(" CREATE VIEW record_ids AS SELECT id FROM records;");
        }
        manifest.push(json!({
            "name": name,
            "size_bytes": sql.len(),
            "sql_sha256": sha256_hex(&sql),
            "sql": sql,
        }));
        ledger_rows.push(json!({"id": migration_number, "name": name}));

        definitions.push((*definition).to_string());
        columns.push(column.clone());
        table_sql = format!("CREATE TABLE records({})", definitions.join(", "));
        let mut schema_objects = Vec::new();
        if migration_number >= 4 {
            schema_objects.push(json!({
                "object_type": "index",
                "name": "records_by_state",
                "table_name": "records",
                "sql_sha256": sha256_hex(index_sql),
            }));
        }
        schema_objects.push(json!({
            "object_type": "table",
            "name": "records",
            "table_name": "records",
            "sql_sha256": sha256_hex(&table_sql),
        }));
        if migration_number >= 5 {
            schema_objects.push(json!({
                "object_type": "view",
                "name": "record_ids",
                "table_name": "record_ids",
                "sql_sha256": sha256_hex(view_sql),
            }));
        }
        expectations.push(json!({
            "manifest_prefix_length": migration_number,
            "schema_objects": schema_objects,
            "tables": [{"name": "records", "columns": columns.clone(), "foreign_keys": []}],
        }));
    }

    let schema_rows = vec![
        json!({"type": "index", "name": "records_by_state", "tbl_name": "records", "sql": index_sql}),
        json!({"type": "table", "name": "records", "tbl_name": "records", "sql": table_sql}),
        json!({"type": "view", "name": "record_ids", "tbl_name": "record_ids", "sql": view_sql}),
    ];
    let xinfo_rows = columns
        .into_iter()
        .map(|column| {
            json!({
                "cid": column["cid"],
                "name": column["name"],
                "type": column["declared_type"],
                "notnull": if column["not_null"] == json!(true) { 1 } else { 0 },
                "dflt_value": column["default_value"],
                "pk": column["primary_key_position"],
                "hidden": column["hidden"],
            })
        })
        .collect::<Vec<_>>();
    (
        Value::Array(manifest),
        Value::Array(expectations),
        schema_rows,
        ledger_rows,
        xinfo_rows,
    )
}

fn terminal_request_args(
    manifest: &Value,
    state_expectations: &Value,
    approved_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
) -> Value {
    json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_only_v1",
        "state_expectations": state_expectations,
        "expected_reconciliation_plan_sha256": "1".repeat(64),
        "expected_expectation_proof_sha256": "2".repeat(64),
        "expected_query_sha256": "3".repeat(64),
        "expected_canonical_snapshot_sha256": "4".repeat(64),
        "expected_outcome": "not_committed",
        "expected_original_prefix_length": 0,
        "expected_current_prefix_length": 0,
        "terminal_request_sha256": "5".repeat(64),
        "terminal_attempt_sha256": "6".repeat(64),
        "dry_run": true,
    })
}

fn terminal_args_from_reconciliation(
    manifest: &Value,
    state_expectations: &Value,
    approved_plan_sha256: &str,
    lease_nonce: &str,
    lease_payload_sha256: &str,
    reconciled: &Value,
) -> Value {
    let mut args = terminal_request_args(
        manifest,
        state_expectations,
        approved_plan_sha256,
        lease_nonce,
        lease_payload_sha256,
    );
    args["expected_reconciliation_plan_sha256"] = reconciled["reconciliation_plan_sha256"].clone();
    args["expected_expectation_proof_sha256"] = reconciled["expectation_proof_sha256"].clone();
    args["expected_query_sha256"] = reconciled["query_sha256"].clone();
    args["expected_canonical_snapshot_sha256"] = reconciled["canonical_snapshot_sha256"].clone();
    args["expected_outcome"] = reconciled["outcome"].clone();
    args["expected_original_prefix_length"] =
        reconciled["reconstructed_original_prefix_length"].clone();
    args["expected_current_prefix_length"] = reconciled["current_manifest_prefix_length"].clone();
    args
}

fn predecessor_two_table_reconciliation_evidence(
    manifest: &Value,
    reconciled: &Value,
) -> (String, String, String) {
    let proof_sha256 = reconciled["expectation_proof_sha256"]
        .as_str()
        .expect("expectation proof digest");
    let predecessor_query = predecessor_two_table_full_union_query(proof_sha256);
    let query_sha256 = sha256_hex(&predecessor_query);
    let scoped_query_sha256 = reconciled["query_sha256"]
        .as_str()
        .expect("scoped query digest");
    assert_ne!(
        query_sha256, scoped_query_sha256,
        "the partial-prefix predecessor query must retain a distinct full-table-union identity"
    );
    let current_sql_sha256 = sha256_hex("CREATE TABLE Current(id TEXT PRIMARY KEY)");
    let snapshot = format!(
        r#"{{"ledger":[{{"id":1,"name":"0001_current.sql"}}],"schema_objects":[{{"object_type":"table","name":"Current","table_name":"Current","sql_sha256":"{current_sql_sha256}"}}],"tables":[{{"name":"Current","columns":[{{"cid":0,"name":"id","declared_type":"TEXT","not_null":false,"default_value":null,"primary_key_position":1,"hidden":0}}],"foreign_keys":[]}},{{"name":"Future","columns":[],"foreign_keys":[]}}]}}"#
    );
    let canonical_snapshot_sha256 = sha256_hex(&snapshot);
    let reconciliation_plan_sha256 = historical_v2_two_table_reconciliation_plan_sha256(
        manifest,
        reconciled,
        &query_sha256,
        &canonical_snapshot_sha256,
    );
    (
        query_sha256,
        canonical_snapshot_sha256,
        reconciliation_plan_sha256,
    )
}

fn historical_v2_two_table_reconciliation_plan_sha256(
    manifest: &Value,
    reconciled: &Value,
    query_sha256: &str,
    canonical_snapshot_sha256: &str,
) -> String {
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
    let plan = json!({
        "version": 1,
        "operation": "d1_reconcile_migration_manifest",
        "target_key_sha256": sha256_hex("acct-1\0db-1"),
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "migrations_table": "d1_migrations",
        "manifest": manifest_summary,
        "lease": reconciled["lease"],
        "original_prefix_length": 0,
        "current_prefix_length": 1,
        "outcome": "partial_state_converged",
        "query_sha256": query_sha256,
        "canonical_snapshot_sha256": canonical_snapshot_sha256,
        "effect_assertion_id": "schema_create_only_v1",
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "next_slice": "persist_terminal_reconciliation_receipt_then_guarded_retirement",
    });
    let reconciliation_plan_sha256 =
        sha256_hex(&serde_json::to_string(&plan).expect("serialize predecessor plan"));
    reconciliation_plan_sha256
}

fn assert_terminal_negative_whole_response(content: &Value, mut expected: Value) {
    let plan = content["plan"].clone();
    let audit = content["audit"].clone();
    assert_eq!(
        plan["operation"],
        json!("d1_finalize_migration_reconciliation"),
        "{content}"
    );
    assert_eq!(
        audit["action"],
        json!("d1_finalize_migration_reconciliation"),
        "{content}"
    );
    assert_eq!(audit["outcome"], json!("error"), "{content}");
    expected["plan"] = plan;
    expected["audit"] = audit;
    assert_eq!(content, &expected, "{content}");
}

fn spawn_fake_reconciliation_api() -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_reconciliation_api_with_fault_and_calls(ReconciliationFault::None, 3)
}

fn spawn_fake_reconciliation_api_for_calls(call_count: usize) -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_reconciliation_api_with_fault_and_calls(ReconciliationFault::None, call_count)
}

fn spawn_fake_reconciliation_api_with_fault(
    fault: ReconciliationFault,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_reconciliation_api_with_fault_and_calls(fault, 3)
}

fn spawn_fake_reconciliation_api_with_fault_and_calls(
    fault: ReconciliationFault,
    call_count: usize,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind reconciliation D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("reconciliation D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (request_index, stream) in listener.incoming().take(call_count).enumerate() {
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
                if request_index == 2 {
                    if let Some(path) = custody_path {
                        fs::write(path, b"tampered retained evidence")
                            .expect("tamper retained evidence before transport failure");
                    }
                    continue;
                }
            }
            if matches!(&fault, ReconciliationFault::RequestTransportFailure(index) if *index == request_index)
            {
                continue;
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
                if request_index == 2 {
                    let response = reconciliation_http_error_response(*status);
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write second reconciliation HTTP error headers");
                    stream
                        .write_all(&response)
                        .expect("write second reconciliation HTTP error");
                    continue;
                }
            }
            if let ReconciliationFault::SecondBatchAllowlistedHttpError(status, code, message) =
                &fault
            {
                if request_index == 2 {
                    let response = serde_json::to_vec(&json!({
                        "success": false,
                        "errors": [{"code": code, "message": message}],
                        "messages": [],
                        "result": null,
                    }))
                    .expect("serialize allowlisted reconciliation HTTP error");
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write allowlisted second reconciliation HTTP error headers");
                    stream
                        .write_all(&response)
                        .expect("write allowlisted second reconciliation HTTP error");
                    continue;
                }
            }
            if let ReconciliationFault::SecondBatchDeepHttpError(status, message) = &fault {
                if request_index == 2 {
                    let nested = format!("{}0{}", "[".repeat(40), "]".repeat(40));
                    let response = format!(
                        r#"{{"success":false,"errors":[{{"code":7500,"message":{},"nested":{nested}}}],"messages":[],"result":null}}"#,
                        serde_json::to_string(message)
                            .expect("serialize deep reconciliation error message")
                    )
                    .into_bytes();
                    write!(stream, "HTTP/1.1 {status} Synthetic\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write deep second reconciliation HTTP error headers");
                    stream
                        .write_all(&response)
                        .expect("write deep second reconciliation HTTP error");
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
            let selection = markers.len() == 2;
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
                    if selection {
                        Vec::new()
                    } else {
                        vec![
                            json!({"type": "table", "name": "items", "tbl_name": "items", "sql": "CREATE TABLE items(id INTEGER PRIMARY KEY)"}),
                        ]
                    },
                    None,
                ),
            ];
            if !selection {
                results.extend([tagged_reconciliation_result(
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
                ), tagged_reconciliation_result(
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
                ), tagged_reconciliation_result(
                    &markers[4],
                    &["table", "rowid", "parent", "fkid"],
                    Vec::new(),
                    None,
                )]);
            }
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
                ReconciliationFault::CustodyRelease(active, retiring) => {
                    results[0]["meta"]["changes"] = json!("0");
                    fs::rename(active, retiring)
                        .expect("move retained evidence during provider read");
                    fs::File::open(
                        retiring
                            .parent()
                            .expect("retained evidence target directory"),
                    )
                    .expect("open retained evidence target")
                    .sync_all()
                    .expect("sync retained evidence move");
                }
                ReconciliationFault::SecondBatchCustodyDrift(path) if request_index == 2 => {
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
                    let last = results.len() - 1;
                    results[last]["meta"]["served_by_primary"] = json!(false);
                }
                ReconciliationFault::SecondBatchPrimaryFalse if request_index == 2 => {
                    let last = results.len() - 1;
                    results[last]["meta"]["served_by_primary"] = json!(false);
                }
                ReconciliationFault::LedgerNotManifestPrefix if !selection => {
                    results[0]["results"][1]["name"] = json!("0099_unknown.sql");
                }
                ReconciliationFault::UnstableSecondBatch if request_index == 2 => {
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
                | ReconciliationFault::SecondBatchPrimaryFalse
                | ReconciliationFault::SecondBatchHttpStatus(_)
                | ReconciliationFault::SecondBatchAllowlistedHttpError(_, _, _)
                | ReconciliationFault::SecondBatchDeepHttpError(_, _)
                | ReconciliationFault::SecondBatchTransportFailure(_)
                | ReconciliationFault::RequestTransportFailure(_)
                | ReconciliationFault::DuplicateOuterSuccess(_, _)
                | ReconciliationFault::DuplicateNestedRowId(_, _)
                | ReconciliationFault::LedgerNotManifestPrefix
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

fn spawn_fake_predecessor_query_compatibility_api(
    call_count: usize,
    fail_request_index: Option<usize>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind predecessor-query compatibility D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("predecessor-query compatibility D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (request_index, stream) in listener.incoming().take(call_count).enumerate() {
            let mut stream = stream.expect("predecessor-query compatibility stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("predecessor-query request JSON");
            let sql = body_json["sql"].as_str().expect("predecessor-query SQL");
            let markers = reconciliation_statement_markers(sql);
            assert!(
                matches!(markers.len(), 2 | 5 | 8),
                "only selection, selected-prefix, or predecessor full-union shapes are valid: {sql}"
            );
            if markers.len() == 2 {
                assert!(!sql.contains("pragma_table_xinfo"));
            } else {
                assert!(sql.contains("'Current', 'Future'"));
                assert!(sql.contains("pragma_table_xinfo('Current')"));
                assert_eq!(
                    sql.contains("pragma_table_xinfo('Future')"),
                    markers.len() == 8,
                    "only the predecessor query probes the future table"
                );
            }
            requests_for_thread
                .lock()
                .expect("predecessor-query request log")
                .push(body_json);
            if fail_request_index == Some(request_index) {
                continue;
            }

            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    vec![json!({"id": 1, "name": "0001_current.sql"})],
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if markers.len() == 2 {
                        Vec::new()
                    } else {
                        vec![json!({
                            "type": "table",
                            "name": "Current",
                            "tbl_name": "Current",
                            "sql": "CREATE TABLE Current(id TEXT PRIMARY KEY)",
                        })]
                    },
                    None,
                ),
            ];
            for (offset, table) in ["Current", "Future"]
                .into_iter()
                .take((markers.len().saturating_sub(2)) / 3)
                .enumerate()
            {
                let marker_offset = 2 + offset * 3;
                results.extend([
                    tagged_reconciliation_result(
                        &markers[marker_offset],
                        &[
                            "cid",
                            "name",
                            "type",
                            "notnull",
                            "dflt_value",
                            "pk",
                            "hidden",
                        ],
                        if table == "Current" {
                            vec![json!({
                                "cid": 0,
                                "name": "id",
                                "type": "TEXT",
                                "notnull": 0,
                                "dflt_value": null,
                                "pk": 1,
                                "hidden": 0,
                            })]
                        } else {
                            Vec::new()
                        },
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[marker_offset + 1],
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
                        &markers[marker_offset + 2],
                        &["table", "rowid", "parent", "fkid"],
                        Vec::new(),
                        None,
                    ),
                ]);
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize predecessor-query response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write predecessor-query response headers");
            stream
                .write_all(&response)
                .expect("write predecessor-query response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_schema_object_reconciliation_api(
    call_count: usize,
    schema_rows: Vec<Value>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake_custom_schema_reconciliation_api(
        call_count,
        vec![json!({"id": 1, "name": "0001_create.sql"})],
        schema_rows,
        vec![
            json!({"cid": 0, "name": "id", "type": "INTEGER", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0}),
            json!({"cid": 1, "name": "name", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 0, "hidden": 0}),
        ],
    )
}

fn spawn_fake_canonical_seed_reconciliation_api(
    call_count: usize,
    schema_rows: Vec<Value>,
    ledger_rows: Vec<Value>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind canonical seed reconciliation D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("canonical seed reconciliation D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(call_count) {
            let mut stream = stream.expect("canonical seed reconciliation stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("canonical seed request JSON");
            let sql = body_json["sql"]
                .as_str()
                .expect("canonical seed reconciliation SQL");
            let markers = reconciliation_statement_markers(sql);
            assert!(matches!(markers.len(), 2 | 10));
            assert!(
                sql.split(";\n")
                    .all(|statement| statement.starts_with("SELECT "))
            );
            requests_for_thread
                .lock()
                .expect("canonical seed request log lock")
                .push(body_json);

            let publications_xinfo = vec![
                json!({"cid": 0, "name": "publication", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0}),
                json!({"cid": 1, "name": "display_name", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 0, "hidden": 0}),
            ];
            let origins_xinfo = vec![
                json!({"cid": 0, "name": "origin", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0}),
            ];
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    ledger_rows.clone(),
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if markers.len() == 2 {
                        Vec::new()
                    } else {
                        schema_rows.clone()
                    },
                    None,
                ),
            ];
            if markers.len() == 10 {
                results.extend([
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
                        publications_xinfo,
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
                    tagged_reconciliation_result(
                        &markers[5],
                        &[
                            "cid",
                            "name",
                            "type",
                            "notnull",
                            "dflt_value",
                            "pk",
                            "hidden",
                        ],
                        origins_xinfo,
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[6],
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
                        &markers[7],
                        &["table", "rowid", "parent", "fkid"],
                        Vec::new(),
                        None,
                    ),
                ]);
                results.push(tagged_reconciliation_result(
                    &markers[8],
                    &["t0", "v0", "t1", "v1"],
                    vec![
                        json!({"t0": "text", "v0": uppercase_hex("daily"), "t1": "text", "v1": uppercase_hex("Daily")}),
                        json!({"t0": "text", "v0": uppercase_hex("events"), "t1": "text", "v1": uppercase_hex("Events")}),
                        json!({"t0": "text", "v0": uppercase_hex("weekly"), "t1": "text", "v1": uppercase_hex("Weekly")}),
                    ],
                    None,
                ));
                results.push(tagged_reconciliation_result(
                    &markers[9],
                    &["t0", "v0"],
                    vec![
                        json!({"t0": "text", "v0": uppercase_hex("https://example.com")}),
                        json!({"t0": "text", "v0": uppercase_hex("https://www.example.com")}),
                    ],
                    None,
                ));
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize canonical seed response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write canonical seed response headers");
            stream
                .write_all(&response)
                .expect("write canonical seed response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_null_seed_reconciliation_api(
    call_count: usize,
    table_sql: String,
    ledger_rows: Vec<Value>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind NULL seed reconciliation D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("NULL seed reconciliation D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(call_count) {
            let mut stream = stream.expect("NULL seed reconciliation stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("NULL seed request JSON");
            let sql = body_json["sql"]
                .as_str()
                .expect("NULL seed reconciliation SQL");
            let markers = reconciliation_statement_markers(sql);
            assert!(matches!(markers.len(), 2 | 6));
            assert!(
                sql.split(";\n")
                    .all(|statement| statement.starts_with("SELECT "))
            );
            if markers.len() == 6 {
                assert_eq!(sql.matches("WHEN 'null' THEN NULL").count(), 7);
            }
            requests_for_thread
                .lock()
                .expect("NULL seed request log lock")
                .push(body_json);

            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    ledger_rows.clone(),
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if markers.len() == 2 {
                        Vec::new()
                    } else {
                        vec![json!({
                            "type": "table",
                            "name": "bootstrap_state",
                            "tbl_name": "bootstrap_state",
                            "sql": table_sql.clone(),
                        })]
                    },
                    None,
                ),
            ];
            if markers.len() == 6 {
                let xinfo_rows = (0..7)
                    .map(|index| {
                        json!({
                            "cid": index,
                            "name": format!("value_{index}"),
                            "type": "TEXT",
                            "notnull": 0,
                            "dflt_value": null,
                            "pk": 0,
                            "hidden": 0,
                        })
                    })
                    .collect::<Vec<_>>();
                results.extend([
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
                        xinfo_rows,
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
                ]);
                let mut null_row = serde_json::Map::new();
                let mut fields = Vec::new();
                for index in 0..7 {
                    fields.push(format!("t{index}"));
                    fields.push(format!("v{index}"));
                    null_row.insert(format!("t{index}"), json!("null"));
                    null_row.insert(format!("v{index}"), Value::Null);
                }
                let field_refs = fields.iter().map(String::as_str).collect::<Vec<_>>();
                results.push(tagged_reconciliation_result(
                    &markers[5],
                    &field_refs,
                    vec![Value::Object(null_row)],
                    None,
                ));
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize NULL seed response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write NULL seed response headers");
            stream
                .write_all(&response)
                .expect("write NULL seed response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_case_variant_seed_reconciliation_api(
    wrong_seed_storage: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind case-variant seed D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("case-variant seed D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(3) {
            let mut stream = stream.expect("case-variant seed stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("case-variant seed request JSON");
            let sql = body_json["sql"].as_str().expect("case-variant seed SQL");
            let markers = reconciliation_statement_markers(sql);
            assert!(matches!(markers.len(), 2 | 6));
            if markers.len() == 6 {
                assert!(sql.contains("pragma_table_xinfo('Channels')"));
                assert!(!sql.contains("pragma_table_xinfo('channels')"));
                assert!(!sql.contains("pragma_table_xinfo('CHANNELS')"));
                assert!(sql.contains("FROM \"Channels\""));
                assert!(!sql.contains("FROM \"CHANNELS\""));
                assert!(!sql.contains("FROM \"cHaNnElS\""));
            }
            requests_for_thread
                .lock()
                .expect("case-variant seed request log")
                .push(body_json);

            let table_sql = "CREATE TABLE Channels(id TEXT PRIMARY KEY, rank INTEGER, note TEXT)";
            let index_sql = "CREATE INDEX channels_by_rank ON cHaNnElS(rank)";
            let trigger_sql = "CREATE TRIGGER channels_guard BEFORE UPDATE ON CHANNELS BEGIN SELECT RAISE(ABORT, 'immutable'); END";
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    vec![
                        json!({"id": 1, "name": "0001_channels.sql"}),
                        json!({"id": 2, "name": "0002_seed.sql"}),
                    ],
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if markers.len() == 2 {
                        Vec::new()
                    } else {
                        vec![
                            json!({"type": "index", "name": "channels_by_rank", "tbl_name": "Channels", "sql": index_sql}),
                            json!({"type": "table", "name": "Channels", "tbl_name": "Channels", "sql": table_sql}),
                            json!({"type": "trigger", "name": "channels_guard", "tbl_name": "CHANNELS", "sql": trigger_sql}),
                        ]
                    },
                    None,
                ),
            ];
            if markers.len() == 6 {
                results.extend([
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
                        json!({"cid": 0, "name": "id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0}),
                        json!({"cid": 1, "name": "rank", "type": "INTEGER", "notnull": 0, "dflt_value": null, "pk": 0, "hidden": 0}),
                        json!({"cid": 2, "name": "note", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 0, "hidden": 0}),
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
                ]);
                let (integer_type, integer_value) = if wrong_seed_storage {
                    ("text", uppercase_hex(&i64::MIN.to_string()))
                } else {
                    ("integer", i64::MIN.to_string())
                };
                results.push(tagged_reconciliation_result(
                    &markers[5],
                    &["t0", "v0", "t1", "v1"],
                    vec![json!({
                        "t0": "text",
                        "v0": uppercase_hex("daily"),
                        "t1": integer_type,
                        "v1": integer_value,
                    })],
                    None,
                ));
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize case-variant seed response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write case-variant seed response headers");
            stream
                .write_all(&response)
                .expect("write case-variant seed response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_seed_prefix_reconciliation_api(
    current_prefix: usize,
    unexpected_intermediate_row: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind seed-prefix D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("seed-prefix D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (request_index, stream) in listener.incoming().take(6).enumerate() {
            let mut stream = stream.expect("seed-prefix stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("seed-prefix request JSON");
            let sql = body_json["sql"].as_str().expect("seed-prefix SQL");
            let markers = reconciliation_statement_markers(sql);
            let selection = request_index % 3 == 0;
            if selection {
                assert_eq!(markers.len(), 2);
                assert!(!sql.contains("pragma_table_xinfo"));
                assert!(!sql.contains("FROM \"Channels\""));
            } else {
                assert_eq!(markers.len(), if current_prefix == 0 { 2 } else { 6 });
                assert_eq!(
                    sql.contains("pragma_table_xinfo('Channels')"),
                    current_prefix > 0
                );
                assert_eq!(sql.contains("FROM \"Channels\""), current_prefix > 0);
            }
            requests_for_thread
                .lock()
                .expect("seed-prefix request log")
                .push(body_json);

            let ledger_rows = [
                json!({"id": 1, "name": "0001_create.sql"}),
                json!({"id": 2, "name": "0002_seed.sql"}),
            ]
            .into_iter()
            .take(current_prefix)
            .collect::<Vec<_>>();
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    ledger_rows,
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if selection || current_prefix == 0 {
                        Vec::new()
                    } else {
                        vec![json!({
                            "type": "table",
                            "name": "Channels",
                            "tbl_name": "Channels",
                            "sql": "CREATE TABLE Channels(id TEXT PRIMARY KEY)",
                        })]
                    },
                    None,
                ),
            ];
            if !selection && current_prefix > 0 {
                results.extend([
                    tagged_reconciliation_result(
                        &markers[2],
                        &["cid", "name", "type", "notnull", "dflt_value", "pk", "hidden"],
                        vec![json!({"cid": 0, "name": "id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0})],
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[3],
                        &["id", "seq", "table", "from", "to", "on_update", "on_delete", "match"],
                        Vec::new(),
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[4],
                        &["table", "rowid", "parent", "fkid"],
                        Vec::new(),
                        None,
                    ),
                ]);
                results.push(tagged_reconciliation_result(
                    &markers[5],
                    &["t0", "v0"],
                    if current_prefix == 2 || unexpected_intermediate_row {
                        vec![json!({"t0": "text", "v0": uppercase_hex("daily")})]
                    } else {
                        Vec::new()
                    },
                    None,
                ));
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize seed-prefix response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write seed-prefix response headers");
            stream
                .write_all(&response)
                .expect("write seed-prefix response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_seed_ledger_sequence_api(
    ledger_prefixes: Vec<usize>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind seed-ledger D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener.local_addr().expect("seed-ledger D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for (stream, ledger_prefix) in listener.incoming().zip(ledger_prefixes) {
            let mut stream = stream.expect("seed-ledger stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value = serde_json::from_slice(&body).expect("seed-ledger request JSON");
            let sql = body_json["sql"].as_str().expect("seed-ledger SQL");
            let markers = reconciliation_statement_markers(sql);
            let selection = markers.len() == 2;
            if selection {
                assert!(!sql.contains("pragma_table_xinfo"));
                assert!(!sql.contains("FROM \"Channels\""));
            } else {
                assert_eq!(markers.len(), 6);
                assert!(sql.contains("pragma_table_xinfo('Channels')"));
                assert!(sql.contains("FROM \"Channels\""));
            }
            requests_for_thread
                .lock()
                .expect("seed-ledger request log")
                .push(body_json);

            let ledger_rows = [
                json!({"id": 1, "name": "0001_create.sql"}),
                json!({"id": 2, "name": "0002_seed.sql"}),
            ]
            .into_iter()
            .take(ledger_prefix)
            .collect::<Vec<_>>();
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    ledger_rows,
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if selection {
                        Vec::new()
                    } else {
                        vec![json!({
                            "type": "table",
                            "name": "Channels",
                            "tbl_name": "Channels",
                            "sql": "CREATE TABLE Channels(id TEXT PRIMARY KEY)",
                        })]
                    },
                    None,
                ),
            ];
            if !selection {
                results.extend([
                    tagged_reconciliation_result(
                        &markers[2],
                        &["cid", "name", "type", "notnull", "dflt_value", "pk", "hidden"],
                        vec![json!({"cid": 0, "name": "id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0})],
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[3],
                        &["id", "seq", "table", "from", "to", "on_update", "on_delete", "match"],
                        Vec::new(),
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[4],
                        &["table", "rowid", "parent", "fkid"],
                        Vec::new(),
                        None,
                    ),
                    tagged_reconciliation_result(
                        &markers[5],
                        &["t0", "v0"],
                        if ledger_prefix == 2 {
                            vec![json!({"t0": "text", "v0": uppercase_hex("daily")})]
                        } else {
                            Vec::new()
                        },
                        None,
                    ),
                ]);
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize seed-ledger response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write seed-ledger response headers");
            stream
                .write_all(&response)
                .expect("write seed-ledger response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

#[derive(Clone, Copy, Debug)]
enum PrematureManifestFact {
    Table,
    Index,
    View,
    Trigger,
    AlteredTableStructure,
    CaseVariantTable,
    CaseVariantIndex,
    CaseVariantView,
    CaseVariantTrigger,
}

fn premature_manifest_fact_reconciliation_case() -> (Value, Value) {
    let current_create = "CREATE TABLE Current(id TEXT PRIMARY KEY)";
    let current_after_alter = "CREATE TABLE Current(id TEXT PRIMARY KEY, rank INTEGER)";
    let future_create = "CREATE TABLE Future(id TEXT PRIMARY KEY)";
    let future_index = "CREATE INDEX current_by_rank ON Current(rank)";
    let future_view = "CREATE VIEW current_ids AS SELECT id FROM Current";
    let future_trigger = "CREATE TRIGGER current_guard BEFORE DELETE ON Current BEGIN SELECT RAISE(ABORT, 'immutable'); END";
    let first_sql = format!("{current_create}; INSERT INTO Current (id) VALUES ('base');");
    let second_sql = format!(
        "ALTER TABLE Current ADD COLUMN rank INTEGER; {future_create}; {future_index}; {future_view}; INSERT INTO Future (id) VALUES ('future'); {future_trigger};"
    );
    let manifest = json!([
        {
            "name": "0001_current.sql",
            "size_bytes": first_sql.len(),
            "sql_sha256": sha256_hex(&first_sql),
            "sql": first_sql,
        },
        {
            "name": "0002_future.sql",
            "size_bytes": second_sql.len(),
            "sql_sha256": sha256_hex(&second_sql),
            "sql": second_sql,
        },
    ]);
    let current_column = json!({
        "cid": 0,
        "name": "id",
        "declared_type": "TEXT",
        "not_null": false,
        "default_value": null,
        "primary_key_position": 1,
        "hidden": 0,
    });
    let rank_column = json!({
        "cid": 1,
        "name": "rank",
        "declared_type": "INTEGER",
        "not_null": false,
        "default_value": null,
        "primary_key_position": 0,
        "hidden": 0,
    });
    let current_seed = json!({
        "table_name": "Current",
        "columns": ["id"],
        "row_count": 1,
        "rows_sha256": typed_seed_rowset_sha256(
            "Current",
            &["id"],
            vec![vec![json!({
                "storage_class": "text",
                "value": uppercase_hex("base"),
            })]],
        ),
    });
    let future_seed = json!({
        "table_name": "Future",
        "columns": ["id"],
        "row_count": 1,
        "rows_sha256": typed_seed_rowset_sha256(
            "Future",
            &["id"],
            vec![vec![json!({
                "storage_class": "text",
                "value": uppercase_hex("future"),
            })]],
        ),
    });
    let expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "Current",
                "table_name": "Current",
                "sql_sha256": sha256_hex(current_create),
            }],
            "tables": [{
                "name": "Current",
                "columns": [current_column.clone()],
                "foreign_keys": [],
            }],
            "seed_tables": [current_seed.clone()],
        },
        {
            "manifest_prefix_length": 2,
            "schema_objects": [
                {"object_type": "index", "name": "current_by_rank", "table_name": "Current", "sql_sha256": sha256_hex(future_index)},
                {"object_type": "table", "name": "Current", "table_name": "Current", "sql_sha256": sha256_hex(current_after_alter)},
                {"object_type": "table", "name": "Future", "table_name": "Future", "sql_sha256": sha256_hex(future_create)},
                {"object_type": "trigger", "name": "current_guard", "table_name": "Current", "sql_sha256": sha256_hex(future_trigger)},
                {"object_type": "view", "name": "current_ids", "table_name": "current_ids", "sql_sha256": sha256_hex(future_view)},
            ],
            "tables": [
                {"name": "Current", "columns": [current_column.clone(), rank_column], "foreign_keys": []},
                {"name": "Future", "columns": [current_column], "foreign_keys": []},
            ],
            "seed_tables": [current_seed, future_seed],
        },
    ]);
    (manifest, expectations)
}

fn spawn_fake_premature_manifest_fact_api(
    selected_prefix: usize,
    fact: PrematureManifestFact,
    clean_first_cycle: bool,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind premature-manifest-fact D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("premature-manifest-fact D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    let call_count = if clean_first_cycle { 6 } else { 3 };
    thread::spawn(move || {
        for (call_index, stream) in listener.incoming().take(call_count).enumerate() {
            let mut stream = stream.expect("premature-manifest-fact stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("premature-manifest-fact request JSON");
            let sql = body_json["sql"]
                .as_str()
                .expect("premature-manifest-fact SQL");
            let markers = reconciliation_statement_markers(sql);
            let selection = call_index % 3 == 0;
            if selection {
                assert_eq!(markers.len(), 2);
                assert!(!sql.contains("pragma_table_xinfo"));
                assert!(!sql.contains("FROM \"Current\""));
                assert!(!sql.contains("FROM \"Future\""));
            } else {
                assert_eq!(markers.len(), if selected_prefix == 0 { 2 } else { 6 });
                assert!(sql.contains("WHERE name COLLATE NOCASE IN"));
                for object in [
                    "Current",
                    "Future",
                    "current_by_rank",
                    "current_ids",
                    "current_guard",
                ] {
                    assert!(
                        sql.contains(object),
                        "full object union omitted {object}: {sql}"
                    );
                }
                assert_eq!(
                    sql.contains("pragma_table_xinfo('Current')"),
                    selected_prefix == 1
                );
                assert!(!sql.contains("pragma_table_xinfo('Future')"));
                assert_eq!(sql.contains("FROM \"Current\""), selected_prefix == 1);
                assert!(!sql.contains("FROM \"Future\""));
            }
            requests_for_thread
                .lock()
                .expect("premature-manifest-fact request log")
                .push(body_json);

            let ledger_rows = [json!({"id": 1, "name": "0001_current.sql"})]
                .into_iter()
                .take(selected_prefix)
                .collect::<Vec<_>>();
            let flawed = !selection && (!clean_first_cycle || call_index >= 3);
            let current_object = json!({
                "type": "table",
                "name": "Current",
                "tbl_name": "Current",
                "sql": "CREATE TABLE Current(id TEXT PRIMARY KEY)",
            });
            let mut schema_rows = if selection || selected_prefix == 0 {
                Vec::new()
            } else {
                vec![current_object.clone()]
            };
            if flawed {
                schema_rows = match fact {
                    PrematureManifestFact::Table if selected_prefix == 0 => vec![current_object],
                    PrematureManifestFact::Table => vec![
                        current_object,
                        json!({"type": "table", "name": "Future", "tbl_name": "Future", "sql": "CREATE TABLE Future(id TEXT PRIMARY KEY)"}),
                    ],
                    PrematureManifestFact::Index => vec![
                        json!({"type": "index", "name": "current_by_rank", "tbl_name": "Current", "sql": "CREATE INDEX current_by_rank ON Current(rank)"}),
                        current_object,
                    ],
                    PrematureManifestFact::View => vec![
                        current_object,
                        json!({"type": "view", "name": "current_ids", "tbl_name": "current_ids", "sql": "CREATE VIEW current_ids AS SELECT id FROM Current"}),
                    ],
                    PrematureManifestFact::Trigger => vec![
                        current_object,
                        json!({"type": "trigger", "name": "current_guard", "tbl_name": "Current", "sql": "CREATE TRIGGER current_guard BEFORE DELETE ON Current BEGIN SELECT RAISE(ABORT, 'immutable'); END"}),
                    ],
                    PrematureManifestFact::AlteredTableStructure => vec![current_object],
                    PrematureManifestFact::CaseVariantTable if selected_prefix == 0 => vec![
                        json!({"type": "table", "name": "CURRENT", "tbl_name": "CURRENT", "sql": "CREATE TABLE CURRENT(id TEXT PRIMARY KEY)"}),
                    ],
                    PrematureManifestFact::CaseVariantTable => vec![
                        current_object,
                        json!({"type": "table", "name": "FUTURE", "tbl_name": "FUTURE", "sql": "CREATE TABLE FUTURE(id TEXT PRIMARY KEY)"}),
                    ],
                    PrematureManifestFact::CaseVariantIndex => vec![
                        json!({"type": "index", "name": "CURRENT_BY_RANK", "tbl_name": "CURRENT", "sql": "CREATE INDEX CURRENT_BY_RANK ON CURRENT(rank)"}),
                        current_object,
                    ],
                    PrematureManifestFact::CaseVariantView => vec![
                        current_object,
                        json!({"type": "view", "name": "CURRENT_IDS", "tbl_name": "CURRENT_IDS", "sql": "CREATE VIEW CURRENT_IDS AS SELECT id FROM CURRENT"}),
                    ],
                    PrematureManifestFact::CaseVariantTrigger => vec![
                        current_object,
                        json!({"type": "trigger", "name": "CURRENT_GUARD", "tbl_name": "CURRENT", "sql": "CREATE TRIGGER CURRENT_GUARD BEFORE DELETE ON CURRENT BEGIN SELECT RAISE(ABORT, 'immutable'); END"}),
                    ],
                };
            }
            let current_exists = selected_prefix == 1
                || (flawed
                    && selected_prefix == 0
                    && matches!(
                        fact,
                        PrematureManifestFact::Table | PrematureManifestFact::CaseVariantTable
                    ));
            let current_altered = flawed
                && selected_prefix == 1
                && matches!(fact, PrematureManifestFact::AlteredTableStructure);
            let mut current_columns = if current_exists {
                vec![
                    json!({"cid": 0, "name": "id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1, "hidden": 0}),
                ]
            } else {
                Vec::new()
            };
            if current_altered {
                current_columns.push(json!({"cid": 1, "name": "rank", "type": "INTEGER", "notnull": 0, "dflt_value": null, "pk": 0, "hidden": 0}));
            }
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    ledger_rows,
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    schema_rows,
                    None,
                ),
            ];
            if !selection && selected_prefix == 1 {
                results.extend([
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
                        current_columns,
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
                ]);
                results.push(tagged_reconciliation_result(
                    &markers[5],
                    &["t0", "v0"],
                    vec![json!({"t0": "text", "v0": uppercase_hex("base")})],
                    None,
                ));
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize premature-manifest-fact response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write premature-manifest-fact response headers");
            stream
                .write_all(&response)
                .expect("write premature-manifest-fact response");
        }
    });
    (format!("http://{addr}"), requests) // DevSkim: ignore DS137138 -- loopback-only MCP test fixture
}

fn spawn_fake_custom_schema_reconciliation_api(
    call_count: usize,
    ledger_rows: Vec<Value>,
    schema_rows: Vec<Value>,
    xinfo_rows: Vec<Value>,
) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind schema-object reconciliation D1 API"); // DevSkim: ignore DS162092 -- loopback-only MCP test fixture
    let addr = listener
        .local_addr()
        .expect("schema-object reconciliation D1 address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(call_count) {
            let mut stream = stream.expect("schema-object reconciliation stream");
            let (headers, body) = read_http_request(&mut stream);
            assert!(headers.starts_with("POST /accounts/acct-1/d1/database/db-1/query"));
            let body_json: Value =
                serde_json::from_slice(&body).expect("schema-object reconciliation request JSON");
            let markers = reconciliation_statement_markers(
                body_json["sql"]
                    .as_str()
                    .expect("schema-object reconciliation SQL"),
            );
            let selection = markers.len() == 2;
            assert!(
                matches!(markers.len(), 2 | 5),
                "selection has only ledger/catalog; the full proof adds one physical table's xinfo/FK statements",
            );
            requests_for_thread
                .lock()
                .expect("schema-object request log lock")
                .push(body_json);
            let mut results = vec![
                tagged_reconciliation_result(
                    &markers[0],
                    &["id", "name"],
                    ledger_rows.clone(),
                    Some(json!({"changed_db": false, "changes": 0, "rows_written": 0})),
                ),
                tagged_reconciliation_result(
                    &markers[1],
                    &["type", "name", "tbl_name", "sql"],
                    if selection {
                        Vec::new()
                    } else {
                        schema_rows.clone()
                    },
                    None,
                ),
            ];
            if !selection {
                results.extend([
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
                        xinfo_rows.clone(),
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
                ]);
            }
            let response = serde_json::to_vec(&json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": results,
            }))
            .expect("serialize schema-object reconciliation response");
            write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len())
                .expect("write schema-object reconciliation headers");
            stream
                .write_all(&response)
                .expect("write schema-object reconciliation response");
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
                && result_sets
                    .iter()
                    .try_fold(
                        (false, 0_u64, 0_u64),
                        |(changed, changes, rows), result_set| {
                            let meta = result_set["meta"].as_object()?;
                            let changed_db = meta.get("changed_db")?.as_bool()?;
                            let result_changes = meta.get("changes")?.as_u64()?;
                            let result_rows = meta.get("rows_written")?.as_u64()?;
                            (result_set["success"] == json!(true)
                                && result_set["errors"].as_array().is_none_or(Vec::is_empty)
                                && result_set["results"].is_array()
                                && meta.get("served_by_primary") == Some(&json!(true))
                                && (changed_db || (result_changes == 0 && result_rows == 0)))
                                .then_some((
                                    changed || changed_db,
                                    changes.checked_add(result_changes)?,
                                    rows.checked_add(result_rows)?,
                                ))
                        },
                    )
                    .is_some_and(|(changed, changes, rows)| changed && changes > 0 && rows > 0)
        });
        let mut apply_seen = false;
        let expected_requests = if write_commits { 12 } else { 10 };
        for stream in listener.incoming().take(expected_requests) {
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
            } else if is_manifest_ledger_authority_sql(sql) {
                manifest_ledger_authority_response("d1_migrations")
            } else {
                assert_eq!(sql, "SELECT * FROM \"d1_migrations\" ORDER BY id");
                manifest_ledger_response(if apply_seen {
                    vec![
                        json!({"id": 1, "name": "0001_initial.sql"}),
                        json!({"id": 2, "name": "0002_second.sql"}),
                    ]
                } else {
                    vec![json!({"id": 1, "name": "0001_initial.sql"})]
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
        for stream in listener.incoming().take(13) {
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
            if is_manifest_ledger_authority_sql(sql) {
                let response =
                    serde_json::to_vec(&manifest_ledger_authority_response("d1_migrations"))
                        .expect("serialize authority response");
                write!(stream, "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", response.len()).expect("write authority headers");
                stream
                    .write_all(&response)
                    .expect("write authority response");
                continue;
            }
            if sql.contains("INSERT INTO \"d1_migrations\" (name) VALUES ('0001_initial.sql')") {
                first_apply_seen = true;
                let response = serde_json::to_vec(&json!({
                    "success": true, "errors": [], "messages": [],
                    "result": [{"success": true, "results": [{"ok": true}], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}]
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
            let response = serde_json::to_vec(&manifest_ledger_response(ledger))
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

fn spawn_fake_worker_version_api(expected_requests: usize) -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Worker version API");
    let addr = listener.local_addr().expect("fake Worker version API addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::spawn(move || {
        let base_id = "11111111-1111-4111-8111-111111111111";
        let candidate_id = "22222222-2222-4222-8222-222222222222";
        let mut uploaded = false;
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("fake Worker version API stream");
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
            let authorization_present = headers.lines().any(|line| {
                line.to_ascii_lowercase()
                    .starts_with("authorization: bearer ")
            });
            requests_for_thread
                .lock()
                .expect("request log lock")
                .push(json!({
                    "method": method,
                    "path": path,
                    "content_type": content_type,
                    "authorization_present": authorization_present,
                    "body_sha256": format!("{:x}", Sha256::digest(&body)),
                }));

            let path_without_query = path.split('?').next().unwrap_or_default();
            let response = if method == "GET"
                && path_without_query == "/accounts/acct-1/workers/scripts/worker-a/versions"
            {
                let mut items = vec![json!({"id": base_id})];
                if uploaded {
                    items.insert(0, json!({"id": candidate_id}));
                }
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"items": items},
                })
            } else if method == "GET"
                && path_without_query
                    == format!("/accounts/acct-1/workers/scripts/worker-a/versions/{base_id}")
            {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": base_id,
                        "resources": {
                            "script": {"etag": "a".repeat(64)},
                            "bindings": [
                                {"name":"SECRET","type":"secret_text","text":"never-surface"}
                            ]
                        }
                    },
                })
            } else if method == "GET"
                && path_without_query
                    == format!("/accounts/acct-1/workers/scripts/worker-a/versions/{candidate_id}")
            {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": candidate_id,
                        "resources": {
                            "script": {"etag": "b".repeat(64)},
                            "bindings": [
                                {"name":"SECRET","type":"secret_text","text":"never-surface"}
                            ]
                        }
                    },
                })
            } else if method == "GET"
                && path_without_query == "/accounts/acct-1/workers/scripts/worker-a/deployments"
            {
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {"deployments": []},
                })
            } else if method == "POST"
                && path_without_query == "/accounts/acct-1/workers/scripts/worker-a/versions"
            {
                assert!(path.contains("bindings_inherit=strict"));
                assert!(content_type.starts_with("multipart/form-data;"));
                assert!(!body.is_empty());
                uploaded = true;
                json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": {
                        "id": candidate_id,
                        "resources": {
                            "script": {"etag": "b".repeat(64)},
                            "bindings": [
                                {"name":"SECRET","type":"secret_text","text":"never-surface"}
                            ]
                        }
                    },
                })
            } else {
                json!({
                    "success": false,
                    "errors": [{"code":7000,"message":format!("unexpected request: {method} {path}")}],
                    "messages": [],
                    "result": null,
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
    let root = PathBuf::from("/tmp").join(format!(
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
            "operation_id": "d1-create-database",
            "path_params": {
                "account_id": "acct-1"
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
            "limit": 30,
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
    assert!(
        result_names.contains(&"d1_bootstrap_migration_ledger"),
        "find_tools should expose the guarded ledger bootstrap: {tools_content}"
    );
    assert!(
        result_names.contains(&"d1_reconcile_bootstrap_migration_ledger")
            && result_names.contains(&"d1_finalize_bootstrap_migration_ledger")
            && result_names.contains(&"d1_abort_bootstrap_migration_ledger"),
        "find_tools should expose the bootstrap-specific recovery boundary: {tools_content}"
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
fn d1_apply_migrations_retires_live_mutation_through_stdio_boundary() {
    let (base_url, requests) = spawn_fake_d1_migrations_api(3, false);
    let dir = PathBuf::from("/tmp").join(format!("cloudflare-mcp-d1-stdio-{}", std::process::id()));
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
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("retired"));
    assert_eq!(
        content["error"]["code"],
        json!("d1.legacy_migration_apply_retired")
    );
    assert_eq!(content["provider_calls"], json!(0));
    assert_eq!(content["provider_mutations"], json!(0));
    let requests = requests.lock().expect("request log lock").clone();
    assert!(requests.is_empty(), "retired live path must not call D1");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn d1_apply_migrations_retires_before_any_ledger_or_provider_access() {
    let (base_url, requests) = spawn_fake_d1_migrations_api(2, true);
    let dir = PathBuf::from("/tmp").join(format!(
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
    assert_eq!(
        content["error"]["code"],
        json!("d1.legacy_migration_apply_retired")
    );
    assert_eq!(
        requests.lock().expect("request log lock").len(),
        0,
        "retired migration path must not probe or mutate the provider"
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn d1_bootstrap_migration_ledger_dry_run_and_live_prove_one_initializer_only() {
    let (base_url, requests) = spawn_fake_bootstrap_api(9, false, false, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-ledger-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create bootstrap lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make bootstrap lease root private");
    }
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let mut mcp = McpStdioProcess::start_with_env(env);

    let invalid = mcp.call_tool(
        30,
        "d1_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "migrations_table": " d1_migrations",
            "dry_run": true,
        }),
    );
    let invalid = structured_content(&invalid);
    assert_eq!(invalid["ok"], json!(false), "{invalid}");
    assert_eq!(invalid["provider_calls"], json!(0));
    assert_eq!(invalid["provider_mutations"], json!(0));
    assert!(requests.lock().expect("request log").is_empty());

    for (id, migrations_table) in [(31, "_cf_ledger"), (32, "SQLITE_ledger")] {
        let reserved = mcp.call_tool(
            id,
            "d1_bootstrap_migration_ledger",
            json!({
                "database_id": "db-1",
                "migrations_table": migrations_table,
                "dry_run": true,
            }),
        );
        let reserved = structured_content(&reserved);
        assert_eq!(reserved["ok"], json!(false), "{reserved}");
        assert_eq!(
            reserved["error"]["code"],
            json!("d1.bootstrap_reserved_migrations_table")
        );
        assert_eq!(reserved["provider_calls"], json!(0));
        assert_eq!(reserved["provider_mutations"], json!(0));
    }
    assert!(requests.lock().expect("request log").is_empty());

    let dry = mcp.call_tool(
        33,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let dry = structured_content(&dry);
    assert_eq!(dry["ok"], json!(true), "{dry}");
    assert_eq!(dry["status"], json!("previewed"));
    assert_eq!(dry["target_inventory"]["state"], json!("empty"));
    assert_eq!(dry["provider_calls"], json!(2));
    assert_eq!(dry["provider_mutations"], json!(0));
    assert_eq!(
        dry["provider_read_lifecycle"].as_array().map(Vec::len),
        Some(2),
        "{dry}"
    );
    assert!(
        dry["provider_read_lifecycle"]
            .as_array()
            .is_some_and(|reads| {
                reads.iter().enumerate().all(|(index, read)| {
                    read["phase"]
                        == json!(format!(
                            "dry_run_preflight.inventory.{}",
                            if index == 0 { "first" } else { "second" }
                        ))
                        && read["query_sha256"]
                            .as_str()
                            .is_some_and(|value| value.len() == 64)
                        && read["lifecycle"]["dispatch_stage"] == json!("attempted")
                        && read["lifecycle"]["response_stage"] == json!("received")
                        && read["lifecycle"]["body_stage"] == json!("completely_read")
                        && read["lifecycle"]["http_status"] == json!(200)
                })
            })
    );
    assert_eq!(dry["response_evidence"].as_array().map(Vec::len), Some(2));
    let plan = dry["plan_sha256"].as_str().expect("bootstrap plan");

    let live = mcp.call_tool(
        34,
        "d1_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_plan_sha256": plan,
        }),
    );
    let live = structured_content(&live);
    assert_eq!(live["ok"], json!(true), "{live}");
    assert_eq!(live["status"], json!("applied_proven"));
    assert_eq!(live["provider_calls"], json!(7));
    assert_eq!(live["provider_mutations"], json!(1));
    assert_eq!(
        live["provider_read_lifecycle"].as_array().map(Vec::len),
        Some(6),
        "{live}"
    );
    assert_eq!(
        live["response_evidence"].as_array().map(Vec::len),
        Some(6),
        "{live}"
    );
    assert_eq!(
        live["provider_read_lifecycle"]
            .as_array()
            .expect("live lifecycle")
            .iter()
            .map(|entry| entry["phase"].as_str().expect("bounded phase"))
            .collect::<Vec<_>>(),
        vec![
            "live_predispatch.inventory.first",
            "live_predispatch.inventory.second",
            "post_write_proof.inventory.first",
            "post_write_proof.inventory.second",
            "post_write_proof.ledger.first",
            "post_write_proof.ledger.second",
        ],
        "{live}"
    );
    assert_eq!(live["migration_sql_executed"], json!(false));
    assert_eq!(live["post_write"]["ledger_row_count"], json!(0));
    assert_eq!(
        live["post_write"]["target_inventory"]["state"],
        json!("canonical_ledger_only")
    );
    assert_released_manifest_target_custody(&lease_root);

    let requests = requests.lock().expect("request log").clone();
    assert_eq!(requests.len(), 9);
    let initializer_requests = requests
        .iter()
        .filter(|request| {
            request["sql"]
                .as_str()
                .is_some_and(|sql| sql.starts_with("CREATE TABLE IF NOT EXISTS \"d1_migrations\""))
        })
        .count();
    assert_eq!(initializer_requests, 1, "exactly one initializer dispatch");
    assert!(requests.iter().all(|request| {
        request["sql"]
            .as_str()
            .is_some_and(|sql| !sql.contains("INSERT INTO") && !sql.contains("ALTER TABLE"))
    }));
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_reads_are_one_attempt_bounded_and_report_exact_lifecycle() {
    for (index, (fault, status, body_stage, expected_code, expected_calls)) in [
        (
            BootstrapReadFault::HttpStatus(400),
            Some(400),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::HttpStatus(401),
            Some(401),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::HttpStatus(403),
            Some(403),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::HttpStatus(429),
            Some(429),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::HttpStatus(503),
            Some(503),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::Redirect,
            Some(302),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::TransportLoss,
            None,
            "not_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::Truncated(false),
            Some(200),
            "not_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::Truncated(true),
            Some(200),
            "partially_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::Oversized,
            Some(200),
            "not_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::MalformedJson,
            Some(200),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::InvalidUtf8,
            Some(200),
            "completely_read",
            "d1.bootstrap_inventory_unreadable",
            1,
        ),
        (
            BootstrapReadFault::PrimaryMarkerWrongType,
            Some(200),
            "completely_read",
            "d1.bootstrap_inventory_malformed",
            1,
        ),
        (
            BootstrapReadFault::Unstable,
            Some(200),
            "completely_read",
            "d1.bootstrap_inventory_unstable",
            2,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) = spawn_fake_bootstrap_read_fault_api(fault);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
        let content = structured_content(&mcp.call_tool(
            500 + index as u64,
            "d1_bootstrap_migration_ledger",
            json!({"database_id": "db-1", "dry_run": true}),
        ))
        .clone();
        assert_eq!(content["ok"], json!(false), "case {index}: {content}");
        assert_eq!(
            content["error"]["code"],
            json!(expected_code),
            "case {index}: {content}"
        );
        assert_eq!(
            content["provider_calls"],
            json!(expected_calls),
            "case {index}: {content}"
        );
        assert_eq!(content["provider_mutations"], json!(0), "{content}");
        assert_eq!(
            content["automatic_retry_permitted"],
            json!(false),
            "case {index}: {content}"
        );
        assert_eq!(
            content["provider_read_lifecycle"].as_array().map(Vec::len),
            Some(expected_calls),
            "case {index}: {content}"
        );
        assert_eq!(
            content["provider_read_lifecycle"][expected_calls - 1]["lifecycle"]["http_status"],
            status.map_or(Value::Null, Value::from),
            "case {index}: {content}"
        );
        assert_eq!(
            content["provider_read_lifecycle"][expected_calls - 1]["lifecycle"]["body_stage"],
            json!(body_stage),
            "case {index}: {content}"
        );
        for (read_index, entry) in content["provider_read_lifecycle"]
            .as_array()
            .expect("provider lifecycle array")
            .iter()
            .enumerate()
        {
            assert_eq!(
                entry["phase"],
                json!(format!(
                    "dry_run_preflight.inventory.{}",
                    if read_index == 0 { "first" } else { "second" }
                )),
                "case {index}: {content}"
            );
            assert!(
                entry["query_sha256"]
                    .as_str()
                    .is_some_and(|value| value.len() == 64),
                "case {index}: {content}"
            );
        }
        let evidence = content["response_evidence"]
            .as_array()
            .expect("response evidence array");
        assert_eq!(evidence.len(), expected_calls, "case {index}: {content}");
        let last = &evidence[expected_calls - 1];
        assert_eq!(
            last["phase"],
            json!(if expected_calls == 1 {
                "dry_run_preflight.inventory.first"
            } else {
                "dry_run_preflight.inventory.second"
            })
        );
        if body_stage == "completely_read" {
            assert!(
                last["response"]["body_sha256"]
                    .as_str()
                    .is_some_and(|value| value.len() == 64),
                "case {index}: {content}"
            );
            assert_eq!(
                last["response"]["complete_body_digest"],
                json!(true),
                "{content}"
            );
        } else {
            assert!(
                last["response"]["body_sha256"].is_null(),
                "case {index}: {content}"
            );
            assert_eq!(
                last["response"]["complete_body_digest"],
                json!(false),
                "{content}"
            );
            if status.is_some() {
                assert!(
                    last["response"]["body_size_bytes"].as_u64().is_some(),
                    "case {index}: {content}"
                );
            } else {
                assert!(last["response"]["body_size_bytes"].is_null(), "{content}");
            }
        }
        if expected_code == "d1.bootstrap_inventory_unreadable" {
            assert_eq!(
                content["error"]["cause"]["retryable"],
                json!(false),
                "{content}"
            );
            assert_eq!(
                content["error"]["cause"]["operator_guidance"],
                json!("reconciliation_only"),
                "{content}"
            );
            assert!(content["error"]["cause"].get("hint").is_none(), "{content}");
            assert!(
                content["error"]["cause"].get("message").is_none(),
                "{content}"
            );
            assert!(!content.to_string().contains("synthetic HTTP"), "{content}");
        }
        assert_eq!(
            requests
                .lock()
                .expect("bootstrap read-fault requests")
                .len(),
            expected_calls,
            "case {index}: no hidden retry is permitted"
        );
        mcp.terminate();
    }

    let mut pre_dispatch = McpStdioProcess::start_with_env(vec![
        (
            "CLOUDFLARE_MCP_API_BASE_URL",
            "http://127.0.0.1:9".to_string(),
        ),
        ("CLOUDFLARE_API_TOKEN", String::new()),
        ("CLOUDFLARE_MCP_API_TOKEN", String::new()),
    ]);
    let content = structured_content(&pre_dispatch.call_tool(
        599,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    ))
    .clone();
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["provider_calls"], json!(0), "{content}");
    assert_eq!(
        content["automatic_retry_permitted"],
        json!(false),
        "{content}"
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["lifecycle"],
        json!({
            "dispatch_stage": "pre_dispatch",
            "response_stage": "not_received",
            "body_stage": "not_read",
            "http_status": null,
        }),
        "{content}"
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["phase"],
        json!("dry_run_preflight.inventory.first")
    );
    assert!(
        content["provider_read_lifecycle"][0]["query_sha256"]
            .as_str()
            .is_some_and(|value| value.len() == 64)
    );
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(1),
        "{content}"
    );
    assert!(content["response_evidence"][0]["response"]["body_sha256"].is_null());
    pre_dispatch.terminate();

    let mut builder_failure = McpStdioProcess::start_with_env(vec![
        (
            "CLOUDFLARE_MCP_API_BASE_URL",
            "http://127.0.0.1:9".to_string(),
        ),
        ("CLOUDFLARE_API_TOKEN", "invalid\nheader".to_string()),
        ("CLOUDFLARE_MCP_API_TOKEN", "invalid\nheader".to_string()),
    ]);
    let content = structured_content(&builder_failure.call_tool(
        600,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    ))
    .clone();
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["provider_calls"], json!(0), "{content}");
    assert_eq!(
        content["error"]["cause"]["code"],
        json!("cloudflare.request_build_failed"),
        "{content}"
    );
    assert_eq!(
        content["error"]["cause"]["retryable"],
        json!(false),
        "{content}"
    );
    assert_eq!(
        content["error"]["cause"]["operator_guidance"],
        json!("reconciliation_only"),
        "{content}"
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["phase"],
        json!("dry_run_preflight.inventory.first"),
        "{content}"
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["lifecycle"]["dispatch_stage"],
        json!("pre_dispatch"),
        "{content}"
    );
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(1),
        "{content}"
    );
    builder_failure.terminate();
}

#[test]
fn d1_bootstrap_migration_ledger_rejects_application_objects_without_write() {
    let (base_url, requests) = spawn_fake_bootstrap_api(2, true, false, true);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        33,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.bootstrap_target_not_empty")
    );
    assert_eq!(content["provider_calls"], json!(2));
    assert_eq!(content["provider_mutations"], json!(0));
    let requests = requests.lock().expect("request log").clone();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| is_bootstrap_inventory_sql(request["sql"].as_str().unwrap_or_default()))
    );
}

#[test]
fn d1_bootstrap_migration_ledger_rejects_stale_plan_after_fresh_empty_preflight() {
    let (base_url, requests) = spawn_fake_bootstrap_api(2, false, false, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-stale-plan-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create stale-plan bootstrap lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make stale-plan lease root private");
    }
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        34,
        "d1_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_plan_sha256": "a".repeat(64),
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.bootstrap_plan_digest_mismatch")
    );
    assert_eq!(content["provider_calls"], json!(2));
    assert_eq!(content["provider_mutations"], json!(0));
    assert_eq!(content["automatic_retry_permitted"], json!(false));
    assert_released_manifest_target_custody(&lease_root);
    let requests = requests.lock().expect("request log").clone();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| {
        is_bootstrap_inventory_sql(request["sql"].as_str().unwrap_or_default())
    }));
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_zero_dispatch_abort_retires_only_exact_marker_aware_custody() {
    let (dry_url, _) = spawn_fake_bootstrap_api(2, false, false, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-zero-dispatch-abort-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create zero-dispatch bootstrap lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make zero-dispatch lease root private");
    }
    let mut dry = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", dry_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let preview = dry.call_tool(
        340,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let plan = structured_content(&preview)["plan_sha256"]
        .as_str()
        .expect("zero-dispatch bootstrap plan")
        .to_string();
    dry.terminate();

    // Force a pre-dispatch provider conflict, then put the exact terminally
    // released bytes back in active to model the reviewed release-failure seam.
    let (conflict_url, conflict_requests) = spawn_fake_bootstrap_api(2, true, false, true);
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", conflict_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let mut bootstrap = McpStdioProcess::start_with_env(env.clone());
    let blocked = bootstrap.call_tool(
        341,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": plan}),
    );
    let blocked = structured_content(&blocked);
    assert_eq!(blocked["ok"], json!(false), "{blocked}");
    assert_eq!(blocked["provider_mutations"], json!(0), "{blocked}");
    assert_eq!(blocked["provider_outcome"], json!("not_dispatched"));
    let nonce = blocked["lease"]["nonce"]
        .as_str()
        .unwrap_or_else(|| panic!("zero-dispatch lease nonce: {blocked}"))
        .to_string();
    let payload = blocked["lease"]["payload_sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("zero-dispatch lease payload: {blocked}"))
        .to_string();
    bootstrap.terminate();
    assert_eq!(
        conflict_requests.lock().expect("conflict requests").len(),
        2
    );
    let target = manifest_target_path(&lease_root);
    let retired = target.join(format!("retired.{nonce}.lease.json"));
    let active = target.join("active.lease.json");
    fs::rename(&retired, &active).expect("model zero-dispatch release failure");

    let terminal_request = "7".repeat(64);
    let terminal_attempt = "8".repeat(64);
    let abort_args = |attempt: &str, dry_run: bool, approved: Option<&str>| {
        let mut args = json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": plan,
            "lease_nonce": nonce,
            "lease_payload_sha256": payload,
            "terminal_request_sha256": terminal_request,
            "terminal_attempt_sha256": attempt,
            "dry_run": dry_run,
        });
        if let Some(approved) = approved {
            args["approved_terminal_plan_sha256"] = json!(approved);
        }
        args
    };
    let mut abort = McpStdioProcess::start_with_env(env);

    let displaced = target.join("displaced.active.lease.json");
    fs::rename(&active, &displaced).expect("temporarily remove active evidence");
    let absent = structured_content(&abort.call_tool(
        342,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&terminal_attempt, true, None),
    ))
    .clone();
    assert_eq!(absent["ok"], json!(false), "{absent}");
    assert_eq!(absent["custody_status"], json!("inspection_failed"));
    assert_eq!(absent["provider_calls"], json!(0));
    fs::rename(&displaced, &active).expect("restore active evidence");

    let retiring = target.join("retiring.lease.json");
    fs::rename(&active, &retiring).expect("install retiring evidence");
    let retiring_result = structured_content(&abort.call_tool(
        343,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&terminal_attempt, true, None),
    ))
    .clone();
    assert_eq!(retiring_result["ok"], json!(false), "{retiring_result}");
    assert_eq!(
        retiring_result["error"]["code"],
        json!("d1.bootstrap_abort_terminal_receipt_absent")
    );
    fs::rename(&retiring, &active).expect("restore active from retiring fixture");

    let marker = target.join(format!(
        "bootstrap-initializer-attempt.{nonce}.receipt.json"
    ));
    fs::write(&marker, b"{malformed").expect("install malformed attempt evidence");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("make malformed marker private");
    }
    let malformed = structured_content(&abort.call_tool(
        344,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&terminal_attempt, true, None),
    ))
    .clone();
    assert_eq!(malformed["ok"], json!(false), "{malformed}");
    assert_eq!(
        malformed["error"]["code"],
        json!("d1.bootstrap_abort_dispatch_not_absent")
    );
    fs::remove_file(&marker).expect("remove malformed test fixture");

    let preview = structured_content(&abort.call_tool(
        345,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&terminal_attempt, true, None),
    ))
    .clone();
    assert_eq!(preview["ok"], json!(true), "{preview}");
    assert_eq!(
        preview["status"],
        json!("bootstrap_zero_dispatch_abort_plan_ready")
    );
    assert_eq!(preview["provider_initializer_dispatches"], json!(0));
    assert_eq!(preview["provider_calls"], json!(0));
    let terminal_plan = preview["terminal_plan_sha256"]
        .as_str()
        .expect("zero-dispatch terminal plan")
        .to_string();

    let completed = structured_content(&abort.call_tool(
        346,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&terminal_attempt, false, Some(&terminal_plan)),
    ))
    .clone();
    assert_eq!(completed["ok"], json!(true), "{completed}");
    assert_eq!(
        completed["status"],
        json!("bootstrap_zero_dispatch_abort_complete")
    );
    assert_eq!(
        completed["custody_status"],
        json!("retired_evidence_verified")
    );
    assert_eq!(completed["local_namespace_mutations"], json!(3));
    assert_eq!(completed["provider_calls"], json!(0));

    let replay = structured_content(&abort.call_tool(
        347,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&terminal_attempt, false, Some(&terminal_plan)),
    ))
    .clone();
    assert_eq!(replay["ok"], json!(true), "{replay}");
    assert_eq!(replay["replayed"], json!(true));
    assert_eq!(replay["local_namespace_mutations"], json!(0));
    assert_eq!(replay["provider_calls"], json!(0));

    let conflict = structured_content(&abort.call_tool(
        348,
        "d1_abort_bootstrap_migration_ledger",
        abort_args(&"9".repeat(64), true, None),
    ))
    .clone();
    assert_eq!(conflict["ok"], json!(false), "{conflict}");
    assert_eq!(conflict["capability_state"], json!("contradictory"));
    assert_eq!(conflict["provider_calls"], json!(0));
    abort.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_migration_ledger_ambiguous_inner_results_preserve_write_evidence_without_retry() {
    for (index, (label, inner_result, classification)) in [
        (
            "malformed inner result",
            Value::Null,
            "missing_or_non_array_result",
        ),
        (
            "failed inner result",
            json!([{
                "success": false,
                "errors": [],
                "results": [],
                "meta": {
                    "served_by_primary": true,
                    "changed_db": true,
                    "changes": 0,
                    "rows_written": 0,
                },
            }]),
            "inner_statement_failure_or_missing_success",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let expected_write_response = serde_json::to_vec(&json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": inner_result.clone(),
        }))
        .expect("serialize expected ambiguous initializer response");
        let expected_write_response_sha256 = sha256_hex(
            &String::from_utf8(expected_write_response.clone())
                .expect("expected ambiguous initializer response is UTF-8"),
        );
        let (base_url, requests) =
            spawn_fake_bootstrap_api_with_inner_result(9, false, false, true, Some(inner_result));
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-bootstrap-inner-result-{index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create ambiguous bootstrap lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make ambiguous bootstrap lease root private");
        }
        let env = vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ];
        let mut mcp = McpStdioProcess::start_with_env(env.clone());
        let dry = mcp.call_tool(
            380 + index as u64 * 3,
            "d1_bootstrap_migration_ledger",
            json!({"database_id": "db-1", "dry_run": true}),
        );
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("ambiguous inner-result bootstrap plan")
            .to_string();
        let live = mcp.call_tool(
            381 + index as u64 * 3,
            "d1_bootstrap_migration_ledger",
            json!({"database_id": "db-1", "approved_plan_sha256": plan}),
        );
        let content = structured_content(&live);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["status"],
            json!("reconciliation_required"),
            "{label}"
        );
        assert_eq!(content["provider_calls"], json!(7), "{label}");
        assert_eq!(content["provider_mutations"], json!(1), "{label}");
        assert_eq!(content["provider_outcome"], json!("unknown"), "{label}");
        assert_eq!(content["lease_retained"], json!(true), "{label}");
        assert_eq!(
            content["error"]["cause"]["kind"],
            json!("provider_result"),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["detail"]["classification"],
            json!(classification),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["detail"]["provider_write_lifecycle"],
            json!({
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            }),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["detail"]["response_body_sha256"],
            json!(expected_write_response_sha256),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["detail"]["response_body_size_bytes"],
            json!(expected_write_response.len()),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["detail"]["retryable"],
            json!(false),
            "{label}"
        );
        assert_private_regular_active_lease(&lease_root);

        let observed_before_blocked = requests.lock().expect("request log").clone();
        assert_eq!(observed_before_blocked.len(), 9, "{label}");
        assert_eq!(
            observed_before_blocked
                .iter()
                .filter(|request| request["sql"]
                    .as_str()
                    .is_some_and(|sql| sql.starts_with("CREATE TABLE IF NOT EXISTS")))
                .count(),
            1,
            "{label} must dispatch the initializer exactly once"
        );
        mcp.terminate();

        let mut fresh = McpStdioProcess::start_with_env(env);
        let blocked = fresh.call_tool(
            382 + index as u64 * 3,
            "d1_bootstrap_migration_ledger",
            json!({"database_id": "db-1", "approved_plan_sha256": "a".repeat(64)}),
        );
        let blocked = structured_content(&blocked);
        assert_eq!(
            blocked["error"]["code"],
            json!("d1.migration_target_lease_held")
        );
        assert_eq!(blocked["provider_calls"], json!(0), "{label}");
        assert_eq!(
            requests.lock().expect("request log").len(),
            9,
            "{label} must not replay or read provider state from the blocked process"
        );
        fresh.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_bootstrap_migration_ledger_response_loss_retains_custody_and_never_retries() {
    let (base_url, requests) = spawn_fake_bootstrap_api(9, false, true, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-ambiguous-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create ambiguous bootstrap lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make ambiguous lease root private");
    }
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let mut mcp = McpStdioProcess::start_with_env(env.clone());
    let dry = mcp.call_tool(
        34,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("ambiguous bootstrap plan")
        .to_string();
    let live = mcp.call_tool(
        35,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": plan}),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["provider_calls"], json!(7));
    assert_eq!(content["provider_mutations"], json!(1));
    assert_eq!(content["provider_outcome"], json!("unknown"));
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(content["automatic_retry_permitted"], json!(false));
    assert_eq!(
        content["provider_read_lifecycle"].as_array().map(Vec::len),
        Some(6),
        "two pre-dispatch proof reads plus four ambiguity readbacks: {content}"
    );
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(6),
        "{content}"
    );
    let phases = content["provider_read_lifecycle"]
        .as_array()
        .expect("ambiguous lifecycle")
        .iter()
        .map(|entry| entry["phase"].as_str().expect("bounded phase"))
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec![
            "live_predispatch.inventory.first",
            "live_predispatch.inventory.second",
            "ambiguous_write_reconciliation.inventory.first",
            "ambiguous_write_reconciliation.inventory.second",
            "ambiguous_write_reconciliation.ledger.first",
            "ambiguous_write_reconciliation.ledger.second",
        ],
        "{content}"
    );
    assert_eq!(
        content["error"]["cause"],
        json!({
            "kind": "transport",
            "detail": {
                "code": "cloudflare.http_server_error",
                "status": 503,
                "retryable": false,
                "operator_guidance": "reconciliation_only",
                "provider_write_lifecycle": {
                    "dispatch_stage": "attempted",
                    "response_stage": "received",
                    "body_stage": "completely_read",
                    "http_status": 503,
                },
                "response_body_sha256": "50ab9a4d22f15c104d768ad5449f5fd7ca69f12290133c7af485f289793cfc4b",
                "response_body_size_bytes": 100,
            },
        }),
        "{content}"
    );
    assert!(
        !content
            .to_string()
            .contains("private-initializer-body-marker"),
        "provider body excerpt leaked: {content}"
    );
    assert_eq!(
        content["reconciliation_evidence"]["state"],
        json!("canonical_empty_ledger_observed")
    );
    assert_eq!(
        content["reconciliation_evidence"]["effect_attribution"],
        json!("unknown")
    );
    assert_eq!(
        content["reconciliation_evidence"]["provider_read_lifecycle"]
            .as_array()
            .map(Vec::len),
        Some(4),
        "{content}"
    );
    assert_eq!(
        content["reconciliation_evidence"]["response_evidence"]
            .as_array()
            .map(Vec::len),
        Some(4),
        "{content}"
    );
    assert_eq!(
        content["reconciliation_evidence"]["provider_read_lifecycle"]
            .as_array()
            .expect("reconciliation lifecycle")
            .iter()
            .map(|entry| entry["phase"].as_str().expect("bounded phase"))
            .collect::<Vec<_>>(),
        phases[2..],
        "{content}"
    );
    assert_private_regular_active_lease(&lease_root);

    let mut fresh = McpStdioProcess::start_with_env(env);
    let blocked = fresh.call_tool(
        36,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": "a".repeat(64)}),
    );
    let blocked = structured_content(&blocked);
    assert_eq!(blocked["ok"], json!(false), "{blocked}");
    assert_eq!(
        blocked["error"]["code"],
        json!("d1.migration_target_lease_held")
    );
    assert_eq!(blocked["provider_calls"], json!(0));

    let abort_after_attempt = fresh.call_tool(
        37,
        "d1_abort_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": plan,
            "lease_nonce": content["lease"]["nonce"],
            "lease_payload_sha256": content["lease"]["payload_sha256"],
            "terminal_request_sha256": "7".repeat(64),
            "terminal_attempt_sha256": "8".repeat(64),
            "dry_run": true,
        }),
    );
    let abort_after_attempt = structured_content(&abort_after_attempt);
    assert_eq!(
        abort_after_attempt["ok"],
        json!(false),
        "{abort_after_attempt}"
    );
    assert_eq!(abort_after_attempt["provider_calls"], json!(0));
    assert_eq!(
        abort_after_attempt["error"]["code"],
        json!("d1.bootstrap_abort_dispatch_not_absent")
    );
    assert_private_regular_active_lease(&lease_root);

    let requests = requests.lock().expect("request log").clone();
    assert_eq!(requests.len(), 9);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.starts_with("CREATE TABLE IF NOT EXISTS")))
            .count(),
        1,
        "ambiguous initializer is dispatched once and never retried"
    );
    let _ = fs::remove_dir_all(lease_root);
}

fn assert_bootstrap_provider_error_location(offset_bytes: u64, expect_location: bool, label: &str) {
    let private_message = format!(
        "D1_ERROR: too many arguments on function private_initializer_function at offset {offset_bytes}: SQLITE_ERROR"
    );
    let (base_url, requests) = spawn_fake_bootstrap_api_with_initializer_http_error(
        9,
        false,
        true,
        None,
        Some((400, 7_500, private_message.clone(), true)),
    );
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-provider-error-{}-{label}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create provider-error bootstrap lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make provider-error bootstrap lease root private");
    }
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let mut mcp = McpStdioProcess::start_with_env(env.clone());
    let dry = mcp.call_tool(
        1772,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("provider-error bootstrap plan")
        .to_string();
    let live = mcp.call_tool(
        1773,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": plan}),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["provider_calls"], json!(7));
    assert_eq!(content["provider_mutations"], json!(1));
    assert_eq!(content["provider_outcome"], json!("unknown"));
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(content["automatic_retry_permitted"], json!(false));
    assert_eq!(
        content["error"]["code"],
        json!("d1.bootstrap_initializer_outcome_unknown")
    );
    assert_eq!(content["error"]["cause"]["kind"], json!("transport"));
    let detail = &content["error"]["cause"]["detail"];
    assert_eq!(detail["code"], json!("cloudflare.http_error"));
    assert_eq!(detail["status"], json!(400));
    assert_eq!(detail["provider_error_code"], json!(7_500));
    assert_eq!(detail["provider_error_category"], json!("d1_error"));
    let expected_location =
        expect_location.then(|| json!({"kind": "sql_byte_offset", "offset_bytes": offset_bytes}));
    assert_eq!(
        detail.get("provider_error_location"),
        expected_location.as_ref(),
        "{label}: {content}"
    );
    assert_eq!(detail["retryable"], json!(false));
    assert_eq!(detail["operator_guidance"], json!("reconciliation_only"));
    assert_eq!(
        detail["provider_write_lifecycle"],
        json!({
            "dispatch_stage": "attempted",
            "response_stage": "received",
            "body_stage": "completely_read",
            "http_status": 400,
        })
    );
    assert!(
        detail["response_body_sha256"].as_str().is_some_and(
            |digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        ),
        "{content}"
    );
    assert!(
        detail["response_body_size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0),
        "{content}"
    );
    let serialized = serde_json::to_string(content).expect("serialize bootstrap provider error");
    assert!(!serialized.contains(&private_message));
    assert!(!serialized.contains("private_initializer_function"));
    assert_private_regular_active_lease(&lease_root);

    let observed = requests.lock().expect("provider-error request log").clone();
    assert_eq!(
        observed.len(),
        9,
        "{label}: one write plus bounded reconciliation"
    );
    let dispatched_sql = observed
        .iter()
        .find_map(|request| {
            request["sql"]
                .as_str()
                .filter(|sql| sql.starts_with("CREATE TABLE IF NOT EXISTS"))
        })
        .expect("dispatched bootstrap initializer SQL");
    assert_eq!(
        offset_bytes < dispatched_sql.len() as u64,
        expect_location,
        "{label}: location evidence must be strictly inside the dispatched SQL bytes"
    );
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.starts_with("CREATE TABLE IF NOT EXISTS")))
            .count(),
        1,
        "provider HTTP error must not replay the non-idempotent initializer"
    );
    mcp.terminate();

    let mut fresh = McpStdioProcess::start_with_env(env);
    let blocked = fresh.call_tool(
        1774,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": "a".repeat(64)}),
    );
    let blocked = structured_content(&blocked);
    assert_eq!(
        blocked["error"]["code"],
        json!("d1.migration_target_lease_held")
    );
    assert_eq!(blocked["provider_calls"], json!(0));
    assert_eq!(
        requests.lock().expect("provider-error request log").len(),
        9,
        "the blocked process must not replay or read provider state"
    );
    fresh.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_migration_ledger_bounds_redacted_provider_location_without_retry() {
    assert_bootstrap_provider_error_location(42, true, "valid");
    assert_bootstrap_provider_error_location(761, false, "out-of-range");
}

#[test]
fn d1_bootstrap_response_loss_reconciles_and_retires_without_retrying_initializer() {
    let (base_url, requests) = spawn_fake_bootstrap_api(41, false, true, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-terminal-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create bootstrap terminal lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make bootstrap terminal lease root private");
    }
    let env = vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ];
    let mut mcp = McpStdioProcess::start_with_env(env.clone());
    let dry = mcp.call_tool(
        200,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let bootstrap_plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("bootstrap plan")
        .to_string();
    let ambiguous = mcp.call_tool(
        201,
        "d1_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_plan_sha256": bootstrap_plan,
        }),
    );
    let ambiguous = structured_content(&ambiguous);
    assert_eq!(ambiguous["status"], json!("reconciliation_required"));
    assert_eq!(ambiguous["lease_retained"], json!(true));
    let lease_nonce = ambiguous["lease"]["nonce"]
        .as_str()
        .expect("retained bootstrap nonce")
        .to_string();
    let lease_payload_sha256 = ambiguous["lease"]["payload_sha256"]
        .as_str()
        .expect("retained bootstrap payload digest")
        .to_string();

    let reconcile = mcp.call_tool(
        202,
        "d1_reconcile_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": bootstrap_plan,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
        }),
    );
    let reconcile = structured_content(&reconcile);
    assert_eq!(reconcile["ok"], json!(true), "{reconcile}");
    assert_eq!(reconcile["status"], json!("bootstrap_reconciled"));
    assert_eq!(reconcile["capability_state"], json!("terminal_proof_ready"));
    assert_eq!(reconcile["outcome"], json!("canonical_empty_ledger"));
    assert_eq!(reconcile["provider_calls"], json!(8));
    assert_eq!(reconcile["provider_mutations"], json!(0));
    assert_eq!(reconcile["local_namespace_mutations"], json!(0));
    let reconcile_lifecycle = reconcile["provider_read_lifecycle"]
        .as_array()
        .expect("bootstrap reconciliation lifecycle");
    assert_eq!(reconcile_lifecycle.len(), 8);
    assert!(reconcile_lifecycle.iter().all(|entry| {
        entry["provider_call_attempted"] == json!(true)
            && entry["lifecycle"]["dispatch_stage"] == json!("attempted")
            && entry["lifecycle"]["response_stage"] == json!("received")
            && entry["lifecycle"]["body_stage"] == json!("completely_read")
            && entry["response"]["body_sha256"]
                .as_str()
                .is_some_and(|value| value.len() == 64)
            && entry["response"]["body_size_bytes"].as_u64().is_some()
    }));
    assert_eq!(
        reconcile["response_evidence"]
            .as_array()
            .expect("bootstrap reconciliation response evidence")
            .len(),
        9,
        "eight exact response-byte products plus the stable before/after snapshot"
    );
    assert_eq!(reconcile["lease_retained"], json!(true));
    assert_eq!(
        reconcile["retry_decision"],
        json!("do_not_retry_initializer")
    );
    let reconciliation_plan = reconcile["reconciliation_plan_sha256"]
        .as_str()
        .expect("bootstrap reconciliation plan")
        .to_string();
    let initializer_authority = reconcile["initializer_authority_sha256"]
        .as_str()
        .expect("initializer authority")
        .to_string();
    let query_authority = reconcile["query_authority_sha256"]
        .as_str()
        .expect("query authority")
        .to_string();
    let canonical_snapshot = reconcile["canonical_snapshot_sha256"]
        .as_str()
        .expect("canonical bootstrap snapshot")
        .to_string();
    let terminal_request = "7".repeat(64);
    let terminal_attempt = "8".repeat(64);
    let terminal_args = |snapshot: &str, dry_run: bool, approved: Option<&str>| {
        let mut args = json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": bootstrap_plan,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "expected_reconciliation_plan_sha256": reconciliation_plan,
            "expected_initializer_authority_sha256": initializer_authority,
            "expected_query_authority_sha256": query_authority,
            "expected_canonical_snapshot_sha256": snapshot,
            "terminal_request_sha256": terminal_request,
            "terminal_attempt_sha256": terminal_attempt,
            "dry_run": dry_run,
        });
        if let Some(approved) = approved {
            args["approved_terminal_plan_sha256"] = json!(approved);
        }
        args
    };

    let contradictory = mcp.call_tool(
        203,
        "d1_finalize_bootstrap_migration_ledger",
        terminal_args(&"9".repeat(64), true, None),
    );
    let contradictory = structured_content(&contradictory);
    assert_eq!(contradictory["ok"], json!(false), "{contradictory}");
    assert_eq!(
        contradictory["error"]["code"],
        json!("d1.bootstrap_terminal_reconciliation_plan_mismatch")
    );
    assert_eq!(contradictory["provider_calls"], json!(0));
    assert_eq!(contradictory["provider_mutations"], json!(0));
    assert_eq!(contradictory["local_namespace_mutations"], json!(0));
    assert_private_regular_active_lease(&lease_root);

    let terminal_dry = mcp.call_tool(
        204,
        "d1_finalize_bootstrap_migration_ledger",
        terminal_args(&canonical_snapshot, true, None),
    );
    let terminal_dry = structured_content(&terminal_dry);
    assert_eq!(terminal_dry["ok"], json!(true), "{terminal_dry}");
    assert_eq!(
        terminal_dry["status"],
        json!("bootstrap_terminal_plan_ready")
    );
    assert_eq!(terminal_dry["provider_calls"], json!(8));
    assert_eq!(terminal_dry["provider_mutations"], json!(0));
    assert_eq!(terminal_dry["local_namespace_mutations"], json!(0));
    let terminal_plan = terminal_dry["terminal_plan_sha256"]
        .as_str()
        .expect("bootstrap terminal plan")
        .to_string();

    let terminal_live = mcp.call_tool(
        205,
        "d1_finalize_bootstrap_migration_ledger",
        terminal_args(&canonical_snapshot, false, Some(&terminal_plan)),
    );
    let terminal_live = structured_content(&terminal_live);
    assert_eq!(terminal_live["ok"], json!(true), "{terminal_live}");
    assert_eq!(
        terminal_live["status"],
        json!("bootstrap_terminal_complete")
    );
    assert_eq!(terminal_live["provider_calls"], json!(16));
    assert_eq!(terminal_live["provider_mutations"], json!(0));
    assert_eq!(terminal_live["local_namespace_mutations"], json!(3));
    assert_eq!(terminal_live["lease_retained"], json!(false));
    assert_eq!(
        terminal_live["provider_read_lifecycle"]
            .as_array()
            .expect("bootstrap terminal lifecycle")
            .len(),
        16
    );
    assert_eq!(
        terminal_live["response_evidence"]
            .as_array()
            .expect("bootstrap terminal response evidence")
            .len(),
        19,
        "sixteen exact response-byte products plus three canonical snapshot products"
    );
    assert_eq!(
        terminal_live["custody_status"],
        json!("retired_evidence_verified")
    );

    let target = manifest_target_path(&lease_root);
    assert!(!target.join("active.lease.json").exists());
    assert!(!target.join("retiring.lease.json").exists());
    assert!(
        target
            .join(format!("retired.{lease_nonce}.lease.json"))
            .is_file()
    );
    assert!(
        target
            .join(format!(
                "terminal-reconciliation.{lease_nonce}.receipt.json"
            ))
            .is_file()
    );

    let mut replay = McpStdioProcess::start_with_env(env);
    let replay_result = replay.call_tool(
        206,
        "d1_finalize_bootstrap_migration_ledger",
        terminal_args(&canonical_snapshot, false, Some(&terminal_plan)),
    );
    let replay_result = structured_content(&replay_result);
    assert_eq!(replay_result["ok"], json!(true), "{replay_result}");
    assert_eq!(
        replay_result["status"],
        json!("bootstrap_terminal_already_complete")
    );
    assert_eq!(replay_result["provider_calls"], json!(0));
    assert_eq!(replay_result["provider_mutations"], json!(0));
    assert_eq!(replay_result["local_namespace_mutations"], json!(0));

    let requests = requests
        .lock()
        .expect("bootstrap recovery requests")
        .clone();
    assert_eq!(requests.len(), 41);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.starts_with("CREATE TABLE IF NOT EXISTS")))
            .count(),
        1,
        "bootstrap recovery never retries the initializer"
    );
    assert!(requests.iter().all(|request| {
        request["sql"]
            .as_str()
            .is_some_and(|sql| !sql.contains("INSERT INTO") && !sql.contains("ALTER TABLE"))
    }));
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_terminal_custody_drift_never_claims_stale_retention() {
    for (label, drift_after_request, expected_receipt, expected_local_mutations) in [
        ("before-receipt", 12usize, false, 0usize),
        ("before-retirement", 16usize, true, 1usize),
    ] {
        let (bootstrap_url, bootstrap_requests) = spawn_fake_bootstrap_api(9, false, true, true);
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-bootstrap-terminal-drift-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create bootstrap drift lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make bootstrap drift lease root private");
        }
        let bootstrap_env = vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", bootstrap_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ];
        let mut bootstrap = McpStdioProcess::start_with_env(bootstrap_env);
        let dry = bootstrap.call_tool(
            220,
            "d1_bootstrap_migration_ledger",
            json!({"database_id": "db-1", "dry_run": true}),
        );
        let bootstrap_plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("bootstrap drift plan")
            .to_string();
        let ambiguous = bootstrap.call_tool(
            221,
            "d1_bootstrap_migration_ledger",
            json!({
                "database_id": "db-1",
                "approved_plan_sha256": bootstrap_plan,
            }),
        );
        let ambiguous = structured_content(&ambiguous);
        let lease_nonce = ambiguous["lease"]["nonce"]
            .as_str()
            .expect("bootstrap drift nonce")
            .to_string();
        let lease_payload_sha256 = ambiguous["lease"]["payload_sha256"]
            .as_str()
            .expect("bootstrap drift payload")
            .to_string();
        assert_eq!(bootstrap_requests.lock().expect("request log").len(), 9);
        bootstrap.terminate();

        let (proof_url, proof_requests) = spawn_fake_initialized_bootstrap_recovery_api(16, None);
        let proof_env = vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", proof_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ];
        let mut proof_process = McpStdioProcess::start_with_env(proof_env);
        let reconcile = proof_process.call_tool(
            222,
            "d1_reconcile_bootstrap_migration_ledger",
            json!({
                "database_id": "db-1",
                "approved_bootstrap_plan_sha256": bootstrap_plan,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
            }),
        );
        let reconcile = structured_content(&reconcile);
        assert_eq!(reconcile["ok"], json!(true), "{label}: {reconcile}");
        let reconciliation_plan = reconcile["reconciliation_plan_sha256"]
            .as_str()
            .expect("bootstrap drift reconciliation plan")
            .to_string();
        let initializer_authority = reconcile["initializer_authority_sha256"]
            .as_str()
            .expect("bootstrap drift initializer authority")
            .to_string();
        let query_authority = reconcile["query_authority_sha256"]
            .as_str()
            .expect("bootstrap drift query authority")
            .to_string();
        let canonical_snapshot = reconcile["canonical_snapshot_sha256"]
            .as_str()
            .expect("bootstrap drift snapshot")
            .to_string();
        let terminal_request = "7".repeat(64);
        let terminal_attempt = "8".repeat(64);
        let terminal_arguments = |dry_run: bool, approved: Option<&str>| {
            let mut args = json!({
                "database_id": "db-1",
                "approved_bootstrap_plan_sha256": bootstrap_plan,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "expected_reconciliation_plan_sha256": reconciliation_plan,
                "expected_initializer_authority_sha256": initializer_authority,
                "expected_query_authority_sha256": query_authority,
                "expected_canonical_snapshot_sha256": canonical_snapshot,
                "terminal_request_sha256": terminal_request,
                "terminal_attempt_sha256": terminal_attempt,
                "dry_run": dry_run,
            });
            if let Some(approved) = approved {
                args["approved_terminal_plan_sha256"] = json!(approved);
            }
            args
        };
        let terminal_dry = proof_process.call_tool(
            223,
            "d1_finalize_bootstrap_migration_ledger",
            terminal_arguments(true, None),
        );
        let terminal_dry = structured_content(&terminal_dry);
        assert_eq!(terminal_dry["ok"], json!(true), "{label}: {terminal_dry}");
        let terminal_plan = terminal_dry["terminal_plan_sha256"]
            .as_str()
            .expect("bootstrap drift terminal plan")
            .to_string();
        assert_eq!(proof_requests.lock().expect("proof requests").len(), 16);
        proof_process.terminate();

        let active = assert_private_regular_active_lease(&lease_root);
        let (drift_url, drift_requests) = spawn_fake_initialized_bootstrap_recovery_api(
            drift_after_request,
            Some((
                drift_after_request,
                BootstrapRecoveryFixtureFault::CustodyDrift(active.clone()),
            )),
        );
        let mut terminal = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", drift_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let result = terminal.call_tool(
            224,
            "d1_finalize_bootstrap_migration_ledger",
            terminal_arguments(false, Some(&terminal_plan)),
        );
        let content = structured_content(&result);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["status"],
            json!("reconciliation_required"),
            "{label}: {content}"
        );
        assert_eq!(
            content["custody_status"],
            json!("retained_evidence_unverified"),
            "{label}: {content}"
        );
        assert_eq!(content["lease_retained"], Value::Null, "{label}: {content}");
        assert_eq!(content["lease_decision"], Value::Null, "{label}: {content}");
        assert_eq!(
            content["provider_calls"],
            json!(drift_after_request),
            "{label}: {content}"
        );
        assert_eq!(content["provider_mutations"], json!(0), "{label}");
        assert_eq!(
            content["local_namespace_mutations"],
            json!(expected_local_mutations),
            "{label}: {content}"
        );
        assert_eq!(
            content["receipt_persisted"],
            json!(expected_receipt),
            "{label}: {content}"
        );
        assert_eq!(
            content["response_evidence"]
                .as_array()
                .expect("bootstrap drift response evidence")
                .len(),
            drift_after_request,
            "{label}: every attempted read retains exact response-byte evidence"
        );
        let observed = drift_requests.lock().expect("drift requests").clone();
        assert_eq!(observed.len(), drift_after_request, "{label}");
        assert!(observed.iter().all(|request| {
            request["sql"].as_str().is_some_and(|sql| {
                is_bootstrap_inventory_sql(sql)
                    || sql == "SELECT * FROM \"d1_migrations\" ORDER BY id"
            })
        }));
        assert!(
            active.with_extension("custody-drifted").is_file(),
            "{label}"
        );
        let receipt = manifest_target_path(&lease_root).join(format!(
            "terminal-reconciliation.{lease_nonce}.receipt.json"
        ));
        assert_eq!(receipt.is_file(), expected_receipt, "{label}");
        terminal.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[cfg(unix)]
#[test]
fn d1_bootstrap_retirement_failure_preserves_persisted_receipt_accounting() {
    use std::os::unix::fs::PermissionsExt;

    let (bootstrap_url, bootstrap_requests) = spawn_fake_bootstrap_api(9, false, true, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-retirement-failure-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create bootstrap retirement-failure lease root");
    fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
        .expect("make bootstrap retirement-failure lease root private");
    let mut bootstrap = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", bootstrap_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let dry = bootstrap.call_tool(
        240,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let bootstrap_plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure plan")
        .to_string();
    let ambiguous = bootstrap.call_tool(
        241,
        "d1_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_plan_sha256": bootstrap_plan,
        }),
    );
    let ambiguous = structured_content(&ambiguous);
    let lease_nonce = ambiguous["lease"]["nonce"]
        .as_str()
        .expect("bootstrap retirement-failure nonce")
        .to_string();
    let lease_payload_sha256 = ambiguous["lease"]["payload_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure payload")
        .to_string();
    assert_eq!(bootstrap_requests.lock().expect("request log").len(), 9);
    bootstrap.terminate();

    let (proof_url, proof_requests) = spawn_fake_initialized_bootstrap_recovery_api(16, None);
    let mut proof_process = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", proof_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconcile = proof_process.call_tool(
        242,
        "d1_reconcile_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": bootstrap_plan,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
        }),
    );
    let reconcile = structured_content(&reconcile);
    assert_eq!(reconcile["ok"], json!(true), "{reconcile}");
    let reconciliation_plan = reconcile["reconciliation_plan_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure reconciliation plan")
        .to_string();
    let initializer_authority = reconcile["initializer_authority_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure initializer authority")
        .to_string();
    let query_authority = reconcile["query_authority_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure query authority")
        .to_string();
    let canonical_snapshot = reconcile["canonical_snapshot_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure snapshot")
        .to_string();
    let terminal_request = "7".repeat(64);
    let terminal_attempt = "8".repeat(64);
    let terminal_arguments = |dry_run: bool, approved: Option<&str>| {
        let mut args = json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": bootstrap_plan,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "expected_reconciliation_plan_sha256": reconciliation_plan,
            "expected_initializer_authority_sha256": initializer_authority,
            "expected_query_authority_sha256": query_authority,
            "expected_canonical_snapshot_sha256": canonical_snapshot,
            "terminal_request_sha256": terminal_request,
            "terminal_attempt_sha256": terminal_attempt,
            "dry_run": dry_run,
        });
        if let Some(approved) = approved {
            args["approved_terminal_plan_sha256"] = json!(approved);
        }
        args
    };
    let terminal_dry = proof_process.call_tool(
        243,
        "d1_finalize_bootstrap_migration_ledger",
        terminal_arguments(true, None),
    );
    let terminal_plan = structured_content(&terminal_dry)["terminal_plan_sha256"]
        .as_str()
        .expect("bootstrap retirement-failure terminal plan")
        .to_string();
    assert_eq!(proof_requests.lock().expect("proof requests").len(), 16);
    proof_process.terminate();

    let target = manifest_target_path(&lease_root);
    let (failure_url, failure_requests) = spawn_fake_initialized_bootstrap_recovery_api(
        16,
        Some((
            16,
            BootstrapRecoveryFixtureFault::TargetReadOnly(target.clone()),
        )),
    );
    let mut terminal = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", failure_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let result = terminal.call_tool(
        244,
        "d1_finalize_bootstrap_migration_ledger",
        terminal_arguments(false, Some(&terminal_plan)),
    );
    let content = structured_content(&result);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["provider_calls"], json!(16), "{content}");
    assert_eq!(content["provider_mutations"], json!(0), "{content}");
    assert_eq!(content["receipt_persisted"], json!(true), "{content}");
    assert_eq!(content["local_namespace_mutations"], json!(1), "{content}");
    assert_eq!(failure_requests.lock().expect("failure requests").len(), 16);
    assert!(target.join("active.lease.json").is_file());
    assert!(!target.join("retiring.lease.json").exists());
    assert!(
        target
            .join(format!(
                "terminal-reconciliation.{lease_nonce}.receipt.json"
            ))
            .is_file()
    );
    terminal.terminate();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
        .expect("restore bootstrap target permissions for cleanup");
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_reconciliation_reports_provider_conflict_and_keeps_custody() {
    let (bootstrap_url, bootstrap_requests) = spawn_fake_bootstrap_api(9, false, true, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-conflict-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create bootstrap conflict lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make bootstrap conflict lease root private");
    }
    let mut bootstrap = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", bootstrap_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let dry = bootstrap.call_tool(
        210,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("bootstrap conflict plan")
        .to_string();
    let ambiguous = bootstrap.call_tool(
        211,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": plan}),
    );
    let ambiguous = structured_content(&ambiguous);
    let nonce = ambiguous["lease"]["nonce"]
        .as_str()
        .expect("bootstrap conflict nonce")
        .to_string();
    let payload = ambiguous["lease"]["payload_sha256"]
        .as_str()
        .expect("bootstrap conflict payload")
        .to_string();
    assert_eq!(bootstrap_requests.lock().expect("request log").len(), 9);

    let (conflict_url, conflict_requests) = spawn_fake_bootstrap_api(2, true, false, true);
    let mut reconcile = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", conflict_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let result = reconcile.call_tool(
        212,
        "d1_reconcile_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": plan,
            "lease_nonce": nonce,
            "lease_payload_sha256": payload,
        }),
    );
    let content = structured_content(&result);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["capability_state"], json!("conflicting"));
    assert_eq!(content["outcome"], json!("conflict"));
    assert_eq!(
        content["error"]["code"],
        json!("d1.bootstrap_recovery_schema_conflict")
    );
    assert_eq!(content["provider_calls"], json!(2));
    assert_eq!(content["provider_mutations"], json!(0));
    assert_eq!(content["local_namespace_mutations"], json!(0));
    assert_eq!(content["lease_retained"], json!(true));
    assert_private_regular_active_lease(&lease_root);
    assert_eq!(
        conflict_requests.lock().expect("conflict requests").len(),
        2
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_bootstrap_reconciliation_provider_failure_is_one_attempt_and_nonterminal() {
    let (bootstrap_url, bootstrap_requests) = spawn_fake_bootstrap_api(9, false, true, true);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-bootstrap-provider-failure-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create bootstrap provider-failure lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make bootstrap provider-failure lease root private");
    }
    let mut bootstrap = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", bootstrap_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let dry = bootstrap.call_tool(
        230,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "dry_run": true}),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("bootstrap provider-failure plan")
        .to_string();
    let ambiguous = bootstrap.call_tool(
        231,
        "d1_bootstrap_migration_ledger",
        json!({"database_id": "db-1", "approved_plan_sha256": plan}),
    );
    let ambiguous = structured_content(&ambiguous);
    let nonce = ambiguous["lease"]["nonce"]
        .as_str()
        .expect("bootstrap provider-failure nonce")
        .to_string();
    let payload = ambiguous["lease"]["payload_sha256"]
        .as_str()
        .expect("bootstrap provider-failure payload")
        .to_string();
    assert_eq!(bootstrap_requests.lock().expect("request log").len(), 9);
    bootstrap.terminate();

    let (failure_url, failure_requests) = spawn_fake_bootstrap_recovery_http_failure_api();
    let mut reconcile = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", failure_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let result = reconcile.call_tool(
        232,
        "d1_reconcile_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": plan,
            "lease_nonce": nonce,
            "lease_payload_sha256": payload,
        }),
    );
    let content = structured_content(&result);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["capability_state"], json!("unknown"), "{content}");
    assert_eq!(content["outcome"], json!("unknown"), "{content}");
    assert_eq!(content["provider_calls"], json!(1), "{content}");
    assert_eq!(content["provider_mutations"], json!(0), "{content}");
    assert_eq!(content["local_namespace_mutations"], json!(0), "{content}");
    assert_eq!(content["lease_retained"], json!(true), "{content}");
    assert_eq!(
        content["error"]["cause"]["retryable"],
        json!(false),
        "{content}"
    );
    assert_eq!(
        content["error"]["cause"]["operator_guidance"],
        json!("reconciliation_only"),
        "{content}"
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["lifecycle"]["http_status"],
        json!(503),
        "{content}"
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["lifecycle"]["body_stage"],
        json!("completely_read"),
        "{content}"
    );
    assert!(
        content["response_evidence"][0]["response"]["body_sha256"]
            .as_str()
            .is_some_and(|value| value.len() == 64),
        "{content}"
    );
    assert_eq!(failure_requests.lock().expect("failure requests").len(), 1);
    assert_private_regular_active_lease(&lease_root);
    reconcile.terminate();

    let mut pre_dispatch = McpStdioProcess::start_with_env(vec![
        (
            "CLOUDFLARE_MCP_API_BASE_URL",
            "http://127.0.0.1:9".to_string(),
        ),
        ("CLOUDFLARE_API_TOKEN", String::new()),
        ("CLOUDFLARE_MCP_API_TOKEN", String::new()),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let result = pre_dispatch.call_tool(
        233,
        "d1_reconcile_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": plan,
            "lease_nonce": nonce,
            "lease_payload_sha256": payload,
        }),
    );
    let content = structured_content(&result);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["provider_calls"], json!(0), "{content}");
    assert_eq!(
        content["provider_read_lifecycle"][0]["lifecycle"]["dispatch_stage"],
        json!("pre_dispatch"),
        "{content}"
    );
    assert_eq!(content["response_evidence"], json!([]), "{content}");
    assert_eq!(content["lease_retained"], json!(true), "{content}");
    assert_private_regular_active_lease(&lease_root);
    pre_dispatch.terminate();

    let active = assert_private_regular_active_lease(&lease_root);
    let retiring = active.with_file_name("retiring.lease.json");
    fs::rename(&active, &retiring).expect("move bootstrap fixture into retiring custody");
    let (retiring_url, retiring_requests) = spawn_fake_initialized_bootstrap_recovery_api(8, None);
    let mut retiring_reconcile = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", retiring_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let result = retiring_reconcile.call_tool(
        234,
        "d1_reconcile_bootstrap_migration_ledger",
        json!({
            "database_id": "db-1",
            "approved_bootstrap_plan_sha256": plan,
            "lease_nonce": nonce,
            "lease_payload_sha256": payload,
        }),
    );
    let content = structured_content(&result);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(
        content["custody_status"],
        json!("retiring_evidence_verified"),
        "{content}"
    );
    assert_eq!(content["lease_retained"], Value::Null, "{content}");
    assert_eq!(content["lease_decision"], Value::Null, "{content}");
    assert_eq!(
        retiring_requests.lock().expect("retiring requests").len(),
        8
    );
    retiring_reconcile.terminate();
    let _ = fs::remove_dir_all(lease_root);
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
                    "name": "2_second/migration.sql",
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
        json!("2_second/migration.sql")
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
fn d1_manifest_execution_transform_rejects_noncanonical_pragma_before_provider() {
    let mut mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_API_BASE_URL",
        "http://127.0.0.1:9".to_string(), // DevSkim: ignore DS137138 -- loopback-only zero-call fixture
    )]);
    for (index, (sql, expected_code)) in [
        (
            "pragma foreign_keys = on;\n\nCREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "PRAGMA foreign_keys = ON;\nCREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "CREATE TABLE items(id INTEGER); PRAGMA foreign_keys = ON;",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "PRAGMA foreign_keys = ON;\n\nPRAGMA foreign_keys = ON;\nCREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_ambiguous",
        ),
        (
            "PRAGMA/*;*/foreign_keys = ON; CREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "PRAGMA -- ;\n foreign_keys = ON; CREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "PRAGMA optimize; PRAGMA main.foreign_keys(ON);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "\u{feff}PRAGMA foreign_keys = ON;\n\nCREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            " \u{feff}PRAGMA foreign_keys = ON; CREATE TABLE items(id INTEGER);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "EXPLAIN PRAGMA foreign_keys = OFF;",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "EXPLAIN QUERY PLAN PRAGMA main.\"foreign_keys\"(OFF);",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "EXPLAIN QUERY -- prefix trivia\n PLAN \u{feff}PRAGMA foreign_keys = OFF;",
            "d1.migration_execution_transform_unsupported",
        ),
        (
            "PRAGMA foreign_keys = ON;\n\n\u{feff}",
            "d1.migration_execution_transform_ambiguous",
        ),
        (
            "PRAGMA foreign_keys = ON;\n\n \t\u{feff}\r\n",
            "d1.migration_execution_transform_ambiguous",
        ),
        (
            "PRAGMA foreign_keys = ON;\n\n;",
            "d1.migration_execution_transform_ambiguous",
        ),
        (
            "PRAGMA foreign_keys = ON;\n\n;;;",
            "d1.migration_execution_transform_ambiguous",
        ),
        (
            "PRAGMA foreign_keys = ON;\n\n; \u{feff}\t/* empty */;-- empty\n;;",
            "d1.migration_execution_transform_ambiguous",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let response = mcp.call_tool(
            3000 + index as u64,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "dry_run": true,
                "manifest": [{
                    "name": "0001_core.sql",
                    "size_bytes": sql.len(),
                    "sql_sha256": sha256_hex(sql),
                    "sql": sql,
                }],
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{content}");
        assert_eq!(content["provider_calls"], json!(0), "{content}");
        assert_eq!(content["provider_mutations"], json!(0), "{content}");
        assert_eq!(content["local_namespace_mutations"], json!(0), "{content}");
        assert_eq!(
            content["lease_decision"],
            json!("not_acquired"),
            "{content}"
        );
        assert_eq!(
            content["custody_status"],
            json!("not_inspected"),
            "{content}"
        );
        assert_eq!(
            content["error"]["code"],
            expected_code,
            "{content}"
        );
    }
    mcp.terminate();
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
        (
            "missing primary proof",
            json!({"success": true, "errors": [], "results": []}),
        ),
        (
            "false primary proof",
            json!({"success": true, "errors": [], "meta": {"served_by_primary": false}, "results": []}),
        ),
        (
            "nonboolean primary proof",
            json!({"success": true, "errors": [], "meta": {"served_by_primary": 1}, "results": []}),
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
        assert_eq!(observed.len(), 3, "{label}");
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
fn d1_apply_migration_manifest_rejects_unproven_reserved_ledger_authority_before_custody() {
    let valid_authority = manifest_ledger_authority_response("d1_migrations");
    let mut missing = valid_authority.clone();
    missing["result"][0]["results"] = json!([]);
    let mut duplicate = valid_authority.clone();
    duplicate["result"][0]["results"]
        .as_array_mut()
        .expect("authority rows")
        .push(json!({
            "type": "table", "name": "D1_MIGRATIONS", "tbl_name": "D1_MIGRATIONS",
            "sql": "CREATE TABLE \"D1_MIGRATIONS\"(id INTEGER)"
        }));
    let mut trigger = valid_authority.clone();
    trigger["result"][0]["results"]
        .as_array_mut()
        .expect("authority rows")
        .push(json!({
            "type": "trigger", "name": "ledger_trigger", "tbl_name": "d1_migrations",
            "sql": "CREATE TRIGGER ledger_trigger AFTER INSERT ON d1_migrations BEGIN SELECT 1; END"
        }));
    let mut not_primary = valid_authority.clone();
    not_primary["result"][0]["meta"]["served_by_primary"] = json!(false);
    let mut malformed = valid_authority.clone();
    malformed["result"][0]["results"] = Value::Null;
    let mut schema_drift = valid_authority.clone();
    schema_drift["result"][0]["results"][0]["sql"] =
        json!("CREATE TABLE d1_migrations(id INTEGER)");
    let invalid_cases = vec![
        (
            "missing ledger row",
            vec![missing],
            "d1.migration_ledger_authority_invalid",
        ),
        (
            "case-equivalent duplicate",
            vec![duplicate],
            "d1.migration_ledger_authority_invalid",
        ),
        (
            "trigger target",
            vec![trigger],
            "d1.migration_ledger_authority_invalid",
        ),
        (
            "not primary",
            vec![not_primary],
            "d1.migration_ledger_authority_not_primary",
        ),
        (
            "malformed decoded results",
            vec![malformed],
            "d1.migration_ledger_authority_malformed",
        ),
        (
            "schema drift",
            vec![schema_drift],
            "d1.migration_ledger_authority_invalid",
        ),
    ];

    for (index, (label, authority_responses, expected_code)) in
        invalid_cases.into_iter().enumerate()
    {
        let (base_url, requests) = spawn_manifest_authority_rejection_api(authority_responses);
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-ledger-authority-{index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir_all(&lease_root).expect("create authority lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make authority lease root private");
        }
        let mut mcp = McpStdioProcess::start_with_env(vec![
            ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
            (
                "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
                lease_root.to_string_lossy().to_string(),
            ),
        ]);
        let sql = "CREATE TABLE submissions(id TEXT);";
        let manifest = json!([{
            "name": "0001_initial.sql", "size_bytes": sql.len(), "sql_sha256": sha256_hex(sql), "sql": sql,
        }]);
        let dry = mcp.call_tool(1500 + index as u64 * 2, "d1_apply_migration_manifest", json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
        }));
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("dry plan")
            .to_string();
        let live = mcp.call_tool(
            1501 + index as u64 * 2,
            "d1_apply_migration_manifest",
            json!({
                "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
                "approved_plan_sha256": plan,
            }),
        );
        let content = structured_content(&live);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["error"]["code"],
            json!(expected_code),
            "{label}: {content}"
        );
        let has_provider_write =
            requests
                .lock()
                .expect("authority requests")
                .iter()
                .any(|request| {
                    request
                        .get("sql")
                        .and_then(Value::as_str)
                        .is_some_and(|sql| sql.starts_with("INSERT INTO"))
                });
        assert!(
            !has_provider_write,
            "{label} must not reach a provider mutation"
        );
        assert!(
            fs::read_dir(&lease_root)
                .expect("authority lease root")
                .next()
                .is_none(),
            "{label} must not create local custody before authority is proven"
        );
        mcp.terminate();
        let _ = fs::remove_dir_all(&lease_root);
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
        assert_eq!(observed.len(), 4, "{label}");
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
        assert_eq!(
            content["error"]["cause"]["provider_write_lifecycle"],
            json!({
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            }),
            "{label}"
        );
        assert!(
            content["error"]["cause"]["response_body_sha256"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64),
            "{label}: {content}"
        );
        assert!(
            content["error"]["cause"]["response_body_size_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0),
            "{label}: {content}"
        );
        assert_eq!(
            content["error"]["cause"]["retryable"],
            json!(false),
            "{label}"
        );
        let observed = requests.lock().expect("requests lock").clone();
        assert_eq!(observed.len(), 10, "{label} must not retry the write");
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
            10,
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
    let executed_second_sql = "ALTER TABLE submissions ADD COLUMN status TEXT;";
    let second_sql = format!("PRAGMA foreign_keys = ON;\n\n{executed_second_sql}");
    let manifest = json!([
        {"name": "0001_initial.sql", "size_bytes": first_sql.len(), "sql_sha256": sha256_hex(first_sql), "sql": first_sql},
        {"name": "0002_second.sql", "size_bytes": second_sql.len(), "sql_sha256": sha256_hex(&second_sql), "sql": second_sql}
    ]);
    let dry = mcp.call_tool(4, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let dry_content = structured_content(&dry);
    let plan = dry_content["plan_sha256"]
        .as_str()
        .expect("plan digest")
        .to_string();
    assert_eq!(
        dry_content["execution_manifest"][1]["transform_id"],
        "drop-leading-pragma-foreign-keys-on-v1"
    );
    assert_eq!(
        dry_content["execution_manifest"][1]["executed_sql_sha256"],
        sha256_hex(executed_second_sql)
    );
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
        content["execution_manifest"][1]["transform_id"],
        "drop-leading-pragma-foreign-keys-on-v1"
    );
    assert_eq!(
        content["execution_manifest"][1]["executed_sql_sha256"],
        sha256_hex(executed_second_sql)
    );
    assert_eq!(
        content["applied_migrations"][0]["sql_sha256"],
        json!(sha256_hex(&second_sql))
    );
    assert_released_manifest_target_custody(&lease_root);
    let requests = requests.lock().expect("requests lock").clone();
    assert_eq!(
        requests.len(),
        12,
        "dry, initial authority, stable ledger, per-mutation authority, apply, post-apply ledger, and final-release authority proofs"
    );
    assert_eq!(
        requests[7]["sql"].as_str().expect("apply SQL"),
        "ALTER TABLE submissions ADD COLUMN status TEXT;\n\nINSERT INTO \"d1_migrations\" (name) VALUES ('0002_second.sql');"
    );
    assert!(
        !requests[7]["sql"]
            .as_str()
            .expect("apply SQL")
            .contains("PRAGMA foreign_keys")
    );
    assert!(
        !requests[7]["sql"]
            .as_str()
            .expect("apply SQL")
            .contains(first_sql)
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_accepts_wrangler_custom_case_preserving_ledger_authority() {
    for (index, migrations_table) in ["custom_migrations", "CasePreserving_Ledger"]
        .into_iter()
        .enumerate()
    {
        let authority = wrangler_manifest_ledger_authority_response(migrations_table);
        let (base_url, requests) = spawn_manifest_authority_schedule_api_for_table(
            migrations_table,
            vec![json!({"id": 1, "name": "0001_initial.sql"})],
            vec![authority; 6],
            12,
        );
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-wrangler-ledger-{index}-{}",
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
        let dry = mcp.call_tool(900 + index as u64 * 2, "d1_apply_migration_manifest", json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "migrations_table": migrations_table,
            "dry_run": true, "manifest": manifest.clone(),
        }));
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("plan digest")
            .to_string();
        let live = mcp.call_tool(901 + index as u64 * 2, "d1_apply_migration_manifest", json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "migrations_table": migrations_table,
            "manifest": manifest, "approved_plan_sha256": plan,
        }));
        let content = structured_content(&live);
        assert_eq!(content["ok"], json!(true), "{migrations_table}: {content}");
        assert_eq!(content["status"], json!("applied"));
        assert_released_manifest_target_custody(&lease_root);
        assert!(
            requests
                .lock()
                .expect("request log")
                .iter()
                .any(|request| request["sql"]
                    == json!(format!("SELECT * FROM \"{migrations_table}\" ORDER BY id"))),
            "{migrations_table} must remain exact in the provider ledger query"
        );
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_rejects_valid_first_invalid_second_authority_read_before_first_write()
 {
    let valid = manifest_ledger_authority_response("d1_migrations");
    let mut invalid = valid.clone();
    invalid["result"][0]["results"][0]["sql"] =
        json!("CREATE TABLE \"d1_migrations\"(id INTEGER PRIMARY KEY)");
    let (base_url, requests) = spawn_manifest_authority_schedule_api(
        vec![json!({"id": 1, "name": "0001_initial.sql"})],
        vec![valid.clone(), valid.clone(), valid, invalid],
        7,
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-first-authority-unstable-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create first-authority unstable lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make first-authority unstable root private");
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
    let dry = mcp.call_tool(801, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("first-authority unstable plan")
        .to_string();
    let live = mcp.call_tool(
        802,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
            "approved_plan_sha256": plan,
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_ledger_authority_unstable"),
        "{content}"
    );
    assert_eq!(
        requests
            .lock()
            .expect("first-authority unstable requests")
            .len(),
        7
    );
    assert!(
        requests
            .lock()
            .expect("first-authority unstable requests")
            .iter()
            .all(|request| !request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\""))),
        "a valid-first/invalid-second authority proof must prevent the first migration write"
    );
    assert_released_manifest_target_custody(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_retains_custody_when_second_migration_authority_drifts() {
    let valid = manifest_ledger_authority_response("d1_migrations");
    let mut invalid = valid.clone();
    invalid["result"][0]["results"][0]["sql"] =
        json!("CREATE TABLE \"d1_migrations\"(id INTEGER PRIMARY KEY)");
    let (base_url, requests) = spawn_manifest_authority_schedule_api(
        Vec::new(),
        vec![
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid,
            invalid,
        ],
        10,
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-per-migration-authority-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create per-migration authority drift lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make per-migration authority drift root private");
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
    let dry = mcp.call_tool(803, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("per-migration authority drift plan")
        .to_string();
    let live = mcp.call_tool(
        804,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
            "approved_plan_sha256": plan,
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["status"],
        json!("reconciliation_required"),
        "{content}"
    );
    assert_eq!(content["lease_retained"], json!(true), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_ledger_authority_unstable"),
        "{content}"
    );
    let observed = requests
        .lock()
        .expect("per-migration authority drift requests")
        .clone();
    assert_eq!(
        observed.len(),
        10,
        "one acknowledged write plus second-proof drift"
    );
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
            .count(),
        1,
        "the drift must stop the second migration mutation"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_retains_custody_when_final_release_authority_drifts() {
    let valid = manifest_ledger_authority_response("d1_migrations");
    let mut invalid = valid.clone();
    invalid["result"][0]["results"][0]["sql"] =
        json!("CREATE TABLE \"d1_migrations\"(id INTEGER PRIMARY KEY)");
    let (base_url, requests) = spawn_manifest_authority_schedule_api(
        vec![json!({"id": 1, "name": "0001_initial.sql"})],
        vec![
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            valid.clone(),
            invalid,
        ],
        12,
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-final-release-authority-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create final-release authority drift lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make final-release authority drift root private");
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
    let dry = mcp.call_tool(805, "d1_apply_migration_manifest", json!({
        "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
    }));
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("final-release authority drift plan")
        .to_string();
    let live = mcp.call_tool(
        806,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
            "approved_plan_sha256": plan,
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["status"],
        json!("reconciliation_required"),
        "{content}"
    );
    assert_eq!(content["lease_retained"], json!(true), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_ledger_authority_unstable"),
        "{content}"
    );
    let observed = requests
        .lock()
        .expect("final-release authority drift requests")
        .clone();
    assert_eq!(
        observed.len(),
        12,
        "final release must perform its own two-read proof"
    );
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
            .count(),
        1,
        "final-release drift must not replay the acknowledged write"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
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
        4,
        "the holder's dry, stable authority, and blocked ledger reads are retained; the concurrent process adds no provider request"
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
        4,
        "the next MCP process after the holder exits stops at active evidence without adding a provider request"
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
        10,
        "dry, initial and final ledger-authority proofs, stable ledger re-read, one apply, stable reconciliation reads; no retry"
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
        10,
        "response loss",
    );
    let _ = fs::remove_dir_all(lease_root);
}

fn assert_manifest_provider_error_location(
    offset_bytes: u64,
    expect_location: bool,
    omit_messages: bool,
    label: &str,
) {
    let private_message = format!(
        "D1_ERROR: too many arguments on function private_function at offset {offset_bytes}: SQLITE_ERROR"
    );
    let (base_url, requests) = spawn_fake_manifest_http_error_api(
        false,
        Some((400, 7_500, private_message.clone(), omit_messages)),
    );
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-provider-error-manifest-{}-{label}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create provider-error lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make provider-error lease root private");
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
    let dry = mcp.call_tool(
        1770,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "dry_run": true,
            "manifest": manifest.clone(),
        }),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("provider-error plan")
        .to_string();
    let live = mcp.call_tool(
        1771,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": plan.clone(),
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["outcome"], json!("unknown"));
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_apply_outcome_unknown")
    );
    assert_eq!(content["error"]["cause"]["kind"], json!("transport"));
    assert_eq!(
        content["error"]["cause"]["code"],
        json!("cloudflare.http_error")
    );
    assert_eq!(content["error"]["cause"]["status"], json!(400));
    assert_eq!(
        content["error"]["cause"]["provider_error_code"],
        json!(7_500)
    );
    assert_eq!(
        content["error"]["cause"]["provider_error_category"],
        json!("d1_error")
    );
    let expected_location =
        expect_location.then(|| json!({"kind": "sql_byte_offset", "offset_bytes": offset_bytes}));
    assert_eq!(
        content["error"]["cause"].get("provider_error_location"),
        expected_location.as_ref(),
        "{label}: {content}"
    );
    assert_eq!(content["error"]["cause"]["retryable"], json!(false));
    assert_eq!(
        content["error"]["cause"]["operator_guidance"],
        json!("reconciliation_only")
    );
    assert_eq!(
        content["error"]["cause"]["provider_write_lifecycle"],
        json!({
            "dispatch_stage": "attempted",
            "response_stage": "received",
            "body_stage": "completely_read",
            "http_status": 400,
        })
    );
    assert!(
        content["error"]["cause"]["response_body_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64),
        "{content}"
    );
    assert!(
        content["error"]["cause"]["response_body_size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0),
        "{content}"
    );
    let serialized = serde_json::to_string(content).expect("serialize provider error result");
    assert!(!serialized.contains(&private_message));
    assert!(!serialized.contains("private_function"));
    let observed = requests.lock().expect("provider-error request log").clone();
    assert_eq!(
        observed.len(),
        10,
        "{label}: one write plus bounded reconciliation"
    );
    let dispatched_sql = observed
        .iter()
        .find_map(|request| {
            request["sql"]
                .as_str()
                .filter(|sql| sql.contains("INSERT INTO \"d1_migrations\""))
        })
        .expect("dispatched manifest provider SQL");
    assert_eq!(
        offset_bytes < dispatched_sql.len() as u64,
        expect_location,
        "{label}: location evidence must be strictly inside the dispatched SQL bytes"
    );
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
            .count(),
        1,
        "provider HTTP error must not replay the non-idempotent write"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    assert_fresh_process_blocked_without_provider_request(
        env,
        &manifest,
        &plan,
        &requests,
        10,
        "provider HTTP error",
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_bounds_redacted_provider_location_without_replay() {
    assert_manifest_provider_error_location(42, true, false, "valid");
    assert_manifest_provider_error_location(761, false, false, "out-of-range");
    assert_manifest_provider_error_location(761, false, true, "omitted-messages");
}

#[test]
fn d1_apply_migration_manifest_oversized_write_response_retains_custody_without_replay() {
    let (base_url, requests) = spawn_fake_manifest_oversized_write_api();
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-oversized-manifest-write-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create oversized-write lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make oversized-write lease root private");
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
    let dry = mcp.call_tool(
        74,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "dry_run": true,
            "manifest": manifest.clone(),
        }),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("oversized-write plan")
        .to_string();
    let live = mcp.call_tool(
        75,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": plan.clone(),
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["outcome"], json!("unknown"));
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_apply_outcome_unknown")
    );
    assert_eq!(content["error"]["cause"]["kind"], json!("transport"));
    assert_eq!(
        content["error"]["cause"]["code"],
        json!("cloudflare.d1.migration_manifest_response_too_large")
    );
    assert_eq!(content["error"]["cause"]["status"], json!(200));
    assert_eq!(content["error"]["cause"]["retryable"], json!(false));
    assert_eq!(
        content["error"]["cause"]["operator_guidance"],
        json!("reconciliation_only")
    );
    assert_eq!(
        content["error"]["cause"]["provider_write_lifecycle"],
        json!({
            "dispatch_stage": "attempted",
            "response_stage": "received",
            "body_stage": "not_read",
            "http_status": 200,
        })
    );
    assert_eq!(
        content["error"]["cause"]["response_body_sha256"],
        Value::Null
    );
    assert_eq!(
        content["error"]["cause"]["response_body_size_bytes"],
        json!(16 * 1024 * 1024 + 1)
    );
    let observed = requests
        .lock()
        .expect("oversized-write request log")
        .clone();
    assert_eq!(observed.len(), 10, "one write plus bounded reconciliation");
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
            .count(),
        1,
        "oversized response must not replay the non-idempotent write"
    );
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    assert_fresh_process_blocked_without_provider_request(
        env,
        &manifest,
        &plan,
        &requests,
        10,
        "oversized migration-write response",
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_apply_migration_manifest_over_depth_acknowledgement_is_ambiguous_and_retains_custody() {
    let private_message = "SQL SELECT * FROM private_table at /private/path";
    let (base_url, requests) = spawn_fake_manifest_deep_write_api(private_message);
    let lease_root = std::path::PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-deep-manifest-write-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir_all(&lease_root).expect("create deep-write lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make deep-write lease root private");
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
    let dry = mcp.call_tool(
        1765,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "dry_run": true,
            "manifest": manifest.clone(),
        }),
    );
    let plan = structured_content(&dry)["plan_sha256"]
        .as_str()
        .expect("deep-write plan")
        .to_string();
    let live = mcp.call_tool(
        1766,
        "d1_apply_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": plan.clone(),
        }),
    );
    let content = structured_content(&live);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(content["status"], json!("reconciliation_required"));
    assert_eq!(content["outcome"], json!("unknown"));
    assert_eq!(content["lease_retained"], json!(true));
    assert_eq!(
        content["error"]["code"],
        json!("d1.migration_apply_outcome_unknown")
    );
    assert_eq!(
        content["error"]["cause"]["code"],
        json!("cloudflare.d1.migration_manifest_malformed_envelope")
    );
    assert_eq!(content["error"]["cause"]["status"], json!(200));
    assert_eq!(content["error"]["cause"]["retryable"], json!(false));
    assert_eq!(
        content["error"]["cause"]["operator_guidance"],
        json!("reconciliation_only")
    );
    assert_eq!(
        content["error"]["cause"]["provider_write_lifecycle"],
        json!({
            "dispatch_stage": "attempted",
            "response_stage": "received",
            "body_stage": "completely_read",
            "http_status": 200,
        })
    );
    assert!(
        content["error"]["cause"]["response_body_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64),
        "{content}"
    );
    assert!(
        content["error"]["cause"]["response_body_size_bytes"]
            .as_u64()
            .is_some_and(|size| size > 0),
        "{content}"
    );
    let serialized = serde_json::to_string(content).expect("serialize deep write result");
    assert!(!serialized.contains(private_message));
    assert!(!serialized.contains("private_table"));
    assert!(!serialized.contains("/private/path"));
    let observed = requests.lock().expect("deep-write request log").clone();
    assert_eq!(observed.len(), 10, "one write plus bounded reconciliation");
    assert_eq!(
        observed
            .iter()
            .filter(|request| request["sql"]
                .as_str()
                .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
            .count(),
        1,
        "over-depth acknowledgement must not replay the non-idempotent write"
    );
    let active = assert_private_regular_active_lease(&lease_root);
    let target = active.parent().expect("manifest custody target");
    assert!(!target.join("retiring.lease.json").exists());
    assert!(!target.join("retired.lease.json").exists());
    mcp.terminate();
    assert_fresh_process_blocked_without_provider_request(
        env,
        &manifest,
        &plan,
        &requests,
        10,
        "over-depth migration-write acknowledgement",
    );
    let _ = fs::remove_dir_all(lease_root);
}

#[cfg(unix)]
#[test]
fn d1_apply_migration_manifest_ambiguous_apply_never_claims_retained_custody_after_drift() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    for label in [
        "active-missing",
        "active-inode",
        "active-symlink",
        "root-replaced",
    ] {
        let (base_url, requests, entered, resume) = spawn_blocked_ambiguous_manifest_api();
        let lease_root = std::path::PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-ambiguous-custody-{label}-{}",
            std::process::id()
        ));
        let displaced_root = lease_root.with_extension("displaced");
        let _ = fs::remove_dir_all(&lease_root);
        let _ = fs::remove_dir_all(&displaced_root);
        fs::create_dir_all(&lease_root).expect("create lease root");
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
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
        let mut mcp = McpStdioProcess::start_with_env(env);
        let dry = mcp.call_tool(100, "d1_apply_migration_manifest", json!({
            "database_id": "db-1", "migration_family": "newsletter-core", "dry_run": true, "manifest": manifest.clone(),
        }));
        let plan = structured_content(&dry)["plan_sha256"]
            .as_str()
            .expect("plan digest")
            .to_string();
        mcp.send(json!({
            "jsonrpc": "2.0", "id": 101, "method": "tools/call",
            "params": {"name": "d1_apply_migration_manifest", "arguments": {
                "database_id": "db-1", "migration_family": "newsletter-core", "manifest": manifest,
                "approved_plan_sha256": plan,
            }}
        }));
        entered
            .recv_timeout(Duration::from_secs(10))
            .expect("provider write has reached the ambiguous boundary");
        let active = manifest_target_path(&lease_root).join("active.lease.json");
        match label {
            "active-missing" => {
                fs::rename(&active, active.with_extension("displaced"))
                    .expect("remove active namespace entry");
            }
            "active-inode" => {
                fs::rename(&active, active.with_extension("displaced"))
                    .expect("displace active evidence");
                fs::write(&active, b"replacement active evidence")
                    .expect("replace active evidence");
                fs::set_permissions(&active, fs::Permissions::from_mode(0o600))
                    .expect("make replacement private");
            }
            "active-symlink" => {
                fs::rename(&active, active.with_extension("displaced"))
                    .expect("displace active evidence");
                symlink("/dev/null", &active).expect("replace active evidence with symlink");
            }
            "root-replaced" => {
                fs::rename(&lease_root, &displaced_root).expect("displace lease root");
                fs::create_dir_all(&lease_root).expect("replace lease root");
                fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                    .expect("make replacement root private");
            }
            _ => unreachable!(),
        }
        resume
            .send(())
            .expect("release ambiguous provider response");
        let response = mcp.response(101);
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{label}: {content}");
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_apply_outcome_unknown_custody_lost"),
            "{label}: {content}"
        );
        assert_eq!(content["lease_retained"], Value::Null, "{label}: {content}");
        assert_eq!(
            content["custody_status"],
            json!("lost_or_unverifiable_after_ambiguous_apply"),
            "{label}: {content}"
        );
        assert!(
            content.get("lease").is_none(),
            "{label}: no local blocker claim"
        );
        assert!(
            content["prior_lease_identity"]["nonce"].is_string(),
            "{label}"
        );
        assert!(
            content["operator_handoff"]
                .as_str()
                .is_some_and(|value| value.contains("Do not replay") && value.contains("absent")),
            "{label}: later operator guidance must not infer replay safety"
        );
        let observed = requests.lock().expect("requests lock").clone();
        assert_eq!(
            observed.len(),
            10,
            "{label}: no retry or omitted reconciliation"
        );
        assert_eq!(
            observed
                .iter()
                .filter(|request| request["sql"]
                    .as_str()
                    .is_some_and(|sql| sql.contains("INSERT INTO \"d1_migrations\"")))
                .count(),
            1,
            "{label}: no later process path may replay the same attempt"
        );
        mcp.terminate();
        let _ = fs::remove_dir_all(&lease_root);
        let _ = fs::remove_dir_all(&displaced_root);
    }
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
                "Provide the complete approved migration manifest in current Wrangler migration order.",
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
            args(valid_manifest.clone(), "bad family"),
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

    let mut missing_account_mcp = McpStdioProcess::start_with_env(vec![
        (
            "CLOUDFLARE_MCP_API_BASE_URL",
            "http://127.0.0.1:9".to_string(), // DevSkim: ignore DS137138 -- loopback-only no-provider-call test fixture
        ),
        ("CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID", String::new()),
    ]);
    let mut missing_account_args = args(valid_manifest, "newsletter-core");
    missing_account_args
        .as_object_mut()
        .expect("missing-account arguments object")
        .remove("account_id");
    let response =
        missing_account_mcp.call_tool(736, "d1_reconcile_migration_manifest", missing_account_args);
    assert_eq!(
        structured_content(&response),
        &expected_d1_reconciliation_semantic_error(
            "d1.invalid_manifest_target_identity",
            "account_id must be supplied or configured as a canonical identifier",
            "Use the exact account_id read from the intended Cloudflare resource.",
        ),
    );
    missing_account_mcp.terminate();
}

#[test]
fn generic_manifest_tools_reject_the_reserved_bootstrap_family_before_any_effect() {
    let provider = TcpListener::bind("127.0.0.1:0").expect("bind no-call provider witness");
    provider
        .set_nonblocking(true)
        .expect("make provider witness nonblocking");
    let provider_url = format!(
        "http://{}",
        provider.local_addr().expect("provider witness address")
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reserved-bootstrap-family-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create private lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make lease root private");
    }

    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", provider_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let reserved_family = "migration-ledger-bootstrap-v1";
    let apply = mcp.call_tool(
        737,
        "d1_apply_migration_manifest",
        json!({
            "account_id": "acct-1",
            "database_id": "db-1",
            "migration_family": reserved_family,
            "manifest": manifest.clone(),
            "approved_plan_sha256": "a".repeat(64),
            "dry_run": false,
        }),
    );
    let reconcile = mcp.call_tool(
        738,
        "d1_reconcile_migration_manifest",
        json!({
            "account_id": "acct-1",
            "database_id": "db-1",
            "migration_family": reserved_family,
            "manifest": manifest.clone(),
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations.clone(),
        }),
    );
    let mut terminal_args = terminal_request_args(
        &manifest,
        &state_expectations,
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
    );
    terminal_args["account_id"] = json!("acct-1");
    terminal_args["migration_family"] = json!(reserved_family);
    let finalize = mcp.call_tool(739, "d1_finalize_migration_reconciliation", terminal_args);

    for (operation, response) in [
        ("d1_apply_migration_manifest", apply),
        ("d1_reconcile_migration_manifest", reconcile),
        ("d1_finalize_migration_reconciliation", finalize),
    ] {
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{operation}: {content}");
        assert_eq!(content["operation"], json!(operation), "{content}");
        assert_eq!(
            content["error"]["code"],
            json!("d1.reserved_migration_family"),
            "{operation}: {content}"
        );
        assert_eq!(content["provider_calls"], json!(0), "{content}");
        assert_eq!(content["provider_mutations"], json!(0), "{content}");
        assert_eq!(content["local_namespace_mutations"], json!(0), "{content}");
        assert_eq!(content["lease_retained"], Value::Null, "{content}");
        assert_eq!(content["custody_status"], "not_inspected", "{content}");
    }

    assert!(
        matches!(provider.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "reserved-family rejection must not connect to the provider"
    );
    assert!(
        !manifest_target_path(&lease_root).exists(),
        "reserved-family rejection must not create or retire target custody"
    );
    assert_eq!(
        fs::read_dir(&lease_root)
            .expect("read empty lease root")
            .count(),
        0,
        "reserved-family rejection leaves no local custody or receipt artifact"
    );

    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
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
    assert_eq!(content["provider_calls"], json!(3));
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
    assert_eq!(
        content["effect_assertion"]["scope"],
        json!({
            "statement_class": "schema_create_only",
            "schema_object_types": ["table", "index"],
        })
    );
    assert!(content["query_sha256"].as_str().is_some());
    assert_eq!(
        content["query_shape_receipt"]["receipt_version"],
        json!("d1-reconciliation-query-shape-v1")
    );
    assert_eq!(
        content["query_shape_receipt"]["query_sha256"],
        content["query_sha256"]
    );
    assert_eq!(
        content["query_shape_receipt"]["statement_classes"],
        json!({
            "ledger": {"count": 1, "present": true},
            "schema_catalog": {"count": 1, "present": true},
            "table_xinfo": {"count": 1, "present": true},
            "foreign_key_definition": {"count": 1, "present": true},
            "foreign_key_check": {"count": 1, "present": true},
            "seed": {"count": 0, "present": false},
        })
    );
    assert!(content["canonical_snapshot_sha256"].as_str().is_some());
    assert!(content["reconciliation_plan_sha256"].as_str().is_some());
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(3)
    );
    let observed = requests.lock().expect("request log");
    assert_eq!(
        observed.len(),
        3,
        "one prefix selection precedes exactly two complete batches"
    );
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
fn d1_reconciliation_and_terminal_finalize_share_view_trigger_effect_proof() {
    let (manifest, state_expectations, schema_rows) =
        table_index_view_trigger_reconciliation_case();
    let (base_url, requests) = spawn_fake_schema_object_reconciliation_api(11, schema_rows);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-schema-objects-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create schema-object reconciliation lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make schema-object reconciliation root private");
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
    let reconciliation_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_tables_indexes_views_triggers_v1",
        "state_expectations": state_expectations,
    });
    let reconciliation = mcp.call_tool(
        810,
        "d1_reconcile_migration_manifest",
        reconciliation_args.clone(),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    assert_eq!(reconciled["outcome"], json!("full_state_converged"));
    assert_eq!(reconciled["provider_calls"], json!(3));
    assert_eq!(reconciled["provider_mutations"], json!(0));
    assert_eq!(
        reconciled["effect_assertion"]["id"],
        json!("schema_create_tables_indexes_views_triggers_v1")
    );
    assert_eq!(
        reconciled["effect_assertion"]["scope"],
        json!({
            "statement_class": "schema_create_tables_indexes_views_triggers",
            "schema_object_types": ["table", "index", "view", "trigger"],
        })
    );

    let mut terminal_args = reconciliation_args;
    terminal_args["expected_reconciliation_plan_sha256"] =
        reconciled["reconciliation_plan_sha256"].clone();
    terminal_args["expected_expectation_proof_sha256"] =
        reconciled["expectation_proof_sha256"].clone();
    terminal_args["expected_query_sha256"] = reconciled["query_sha256"].clone();
    terminal_args["expected_canonical_snapshot_sha256"] =
        reconciled["canonical_snapshot_sha256"].clone();
    terminal_args["expected_outcome"] = reconciled["outcome"].clone();
    terminal_args["expected_original_prefix_length"] =
        reconciled["reconstructed_original_prefix_length"].clone();
    terminal_args["expected_current_prefix_length"] =
        reconciled["current_manifest_prefix_length"].clone();
    terminal_args["terminal_request_sha256"] = json!("d".repeat(64));
    terminal_args["terminal_attempt_sha256"] = json!("e".repeat(64));
    terminal_args["dry_run"] = json!(true);
    let dry = mcp.call_tool(
        811,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    assert_eq!(
        dry_content["status"],
        json!("terminal_reconciliation_plan_ready")
    );
    assert_eq!(dry_content["provider_calls"], json!(3));

    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let live = mcp.call_tool(
        812,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let live_content = structured_content(&live);
    assert_eq!(live_content["ok"], json!(true), "{live_content}");
    assert_eq!(
        live_content["status"],
        json!("terminal_reconciliation_complete")
    );
    assert_eq!(live_content["provider_calls"], json!(5));
    assert_eq!(live_content["provider_mutations"], json!(0));
    assert_eq!(live_content["local_namespace_mutations"], json!(3));
    assert_eq!(live_content["lease_retained"], json!(false));
    assert_eq!(
        live_content["effect_assertion_id"],
        json!("schema_create_tables_indexes_views_triggers_v1")
    );
    assert_released_manifest_target_custody(&lease_root);

    let target = manifest_target_path(&lease_root);
    let receipt_path = fs::read_dir(&target)
        .expect("read terminal target")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("terminal-reconciliation.")
            })
        })
        .expect("durable terminal receipt");
    let receipt: Value =
        serde_json::from_slice(&fs::read(receipt_path).expect("read durable terminal receipt"))
            .expect("parse durable terminal receipt");
    assert_eq!(receipt["version"], json!(2));
    assert_eq!(
        receipt["effect_assertion_id"],
        json!("schema_create_tables_indexes_views_triggers_v1")
    );

    let replay = mcp.call_tool(815, "d1_finalize_migration_reconciliation", terminal_args);
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], json!(true), "{replay_content}");
    assert_eq!(
        replay_content["status"],
        json!("terminal_reconciliation_already_complete")
    );
    assert_eq!(
        replay_content["effect_assertion_id"],
        json!("schema_create_tables_indexes_views_triggers_v1")
    );
    assert_eq!(replay_content["provider_calls"], json!(0));

    let observed = requests.lock().expect("schema-object request log");
    assert_eq!(observed.len(), 11);
    for request in observed.iter() {
        let sql = request["sql"].as_str().expect("fixed reconciliation SQL");
        let selection = reconciliation_statement_markers(sql).len() == 2;
        assert_eq!(
            sql.matches("pragma_table_xinfo").count(),
            usize::from(!selection)
        );
        assert_eq!(
            sql.matches("pragma_foreign_key_list").count(),
            usize::from(!selection)
        );
        assert_eq!(
            sql.matches("pragma_foreign_key_check").count(),
            usize::from(!selection)
        );
        assert_eq!(sql.contains("'item_names'"), !selection);
        assert_eq!(sql.contains("'items_after_update'"), !selection);
    }
    drop(observed);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconciliation_and_terminal_finalize_share_additive_effect_proof() {
    let (manifest, state_expectations, schema_rows) = additive_reconciliation_case();
    let (base_url, requests) = spawn_fake_schema_object_reconciliation_api(11, schema_rows);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-additive-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create additive reconciliation lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make additive reconciliation root private");
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
    let reconciliation_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_objects_additive_v1",
        "state_expectations": state_expectations,
    });
    let reconciliation = mcp.call_tool(
        830,
        "d1_reconcile_migration_manifest",
        reconciliation_args.clone(),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    assert_eq!(reconciled["outcome"], json!("full_state_converged"));
    assert_eq!(reconciled["provider_calls"], json!(3));
    assert_eq!(reconciled["provider_mutations"], json!(0));
    assert_eq!(
        reconciled["effect_assertion"]["id"],
        json!("schema_create_objects_additive_v1")
    );
    assert_eq!(
        reconciled["effect_assertion"]["scope"],
        json!({
            "statement_class": "schema_create_objects_additive",
            "schema_object_types": [
                "table",
                "index",
                "view",
                "trigger",
                "alter_table_add_column",
                "pragma_foreign_keys_on",
            ],
        })
    );

    let mut terminal_args = reconciliation_args;
    terminal_args["expected_reconciliation_plan_sha256"] =
        reconciled["reconciliation_plan_sha256"].clone();
    terminal_args["expected_expectation_proof_sha256"] =
        reconciled["expectation_proof_sha256"].clone();
    terminal_args["expected_query_sha256"] = reconciled["query_sha256"].clone();
    terminal_args["expected_canonical_snapshot_sha256"] =
        reconciled["canonical_snapshot_sha256"].clone();
    terminal_args["expected_outcome"] = reconciled["outcome"].clone();
    terminal_args["expected_original_prefix_length"] =
        reconciled["reconstructed_original_prefix_length"].clone();
    terminal_args["expected_current_prefix_length"] =
        reconciled["current_manifest_prefix_length"].clone();
    terminal_args["terminal_request_sha256"] = json!("7".repeat(64));
    terminal_args["terminal_attempt_sha256"] = json!("8".repeat(64));
    terminal_args["dry_run"] = json!(true);
    let dry = mcp.call_tool(
        831,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    assert_eq!(
        dry_content["status"],
        json!("terminal_reconciliation_plan_ready")
    );
    assert_eq!(dry_content["provider_calls"], json!(3));

    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let live = mcp.call_tool(
        832,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let live_content = structured_content(&live);
    assert_eq!(live_content["ok"], json!(true), "{live_content}");
    assert_eq!(
        live_content["status"],
        json!("terminal_reconciliation_complete")
    );
    assert_eq!(live_content["provider_calls"], json!(5));
    assert_eq!(live_content["provider_mutations"], json!(0));
    assert_eq!(live_content["local_namespace_mutations"], json!(3));
    assert_eq!(live_content["lease_retained"], json!(false));
    assert_eq!(
        live_content["effect_assertion_id"],
        json!("schema_create_objects_additive_v1")
    );
    assert_released_manifest_target_custody(&lease_root);

    let target = manifest_target_path(&lease_root);
    let receipt_path = fs::read_dir(&target)
        .expect("read additive terminal target")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("terminal-reconciliation.")
            })
        })
        .expect("durable additive terminal receipt");
    let receipt: Value = serde_json::from_slice(
        &fs::read(receipt_path).expect("read durable additive terminal receipt"),
    )
    .expect("parse durable additive terminal receipt");
    assert_eq!(receipt["version"], json!(2));
    assert_eq!(
        receipt["effect_assertion_id"],
        json!("schema_create_objects_additive_v1")
    );

    let replay = mcp.call_tool(
        833,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], json!(true), "{replay_content}");
    assert_eq!(
        replay_content["status"],
        json!("terminal_reconciliation_already_complete")
    );
    assert_eq!(replay_content["provider_calls"], json!(0));

    let mut conflicting_replay_args = terminal_args;
    conflicting_replay_args["state_expectations"][1]["tables"][0]["columns"][1]["declared_type"] =
        json!("INTEGER");
    let conflicting = mcp.call_tool(
        834,
        "d1_finalize_migration_reconciliation",
        conflicting_replay_args,
    );
    let conflicting_content = structured_content(&conflicting);
    assert_eq!(conflicting_content["ok"], json!(false));
    assert_eq!(conflicting_content["provider_calls"], json!(0));
    assert_eq!(
        conflicting_content["error"]["code"],
        json!("d1.migration_reconciliation_additive_column_drift")
    );

    let observed = requests.lock().expect("additive request log");
    assert_eq!(observed.len(), 11);
    for request in observed.iter() {
        let sql = request["sql"].as_str().expect("fixed reconciliation SQL");
        let selection = reconciliation_statement_markers(sql).len() == 2;
        assert_eq!(
            sql.matches("pragma_table_xinfo").count(),
            usize::from(!selection)
        );
        assert!(!sql.contains("ALTER TABLE"));
        assert!(!sql.contains("PRAGMA foreign_keys = ON"));
    }
    drop(observed);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_canonical_five_seed_rows_bind_reconciliation_terminal_receipt_and_replay() {
    let (manifest, state_expectations, schema_rows, ledger_rows) =
        canonical_seed_row_reconciliation_case();
    assert!(state_expectations[0].get("seed_tables").is_none());
    assert_eq!(
        state_expectations[1]["seed_tables"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        state_expectations[2]["seed_tables"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let (base_url, requests) =
        spawn_fake_canonical_seed_reconciliation_api(11, schema_rows, ledger_rows);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-canonical-seeds-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create canonical seed reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make canonical seed reconciliation root private");
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
    let reconciliation_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
        "state_expectations": state_expectations,
    });
    let reconciliation = mcp.call_tool(
        841,
        "d1_reconcile_migration_manifest",
        reconciliation_args.clone(),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    assert_eq!(reconciled["outcome"], json!("full_state_converged"));
    assert_eq!(reconciled["provider_calls"], json!(3));
    assert_eq!(reconciled["provider_mutations"], json!(0));
    assert_eq!(
        reconciled["seed_row_evidence"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(reconciled["seed_row_evidence"][0]["row_count"], json!(3));
    assert_eq!(reconciled["seed_row_evidence"][1]["row_count"], json!(2));
    assert_eq!(
        reconciled["effect_assertion"]["scope"],
        json!({
            "statement_class": "schema_create_objects_additive_seed_rows",
            "schema_object_types": [
                "table",
                "index",
                "view",
                "trigger",
                "alter_table_add_column",
                "pragma_foreign_keys_on",
                "insert_seed_values",
            ],
        })
    );
    let response_json = serde_json::to_string(&reconciled).expect("serialize seed response");
    for private_value in ["Daily", "Events", "Weekly", "example.com"] {
        assert!(
            !response_json.contains(private_value),
            "aggregate response must not expose seed values: {private_value}"
        );
    }

    let mut terminal_args = reconciliation_args;
    terminal_args["expected_reconciliation_plan_sha256"] =
        reconciled["reconciliation_plan_sha256"].clone();
    terminal_args["expected_expectation_proof_sha256"] =
        reconciled["expectation_proof_sha256"].clone();
    terminal_args["expected_query_sha256"] = reconciled["query_sha256"].clone();
    terminal_args["expected_canonical_snapshot_sha256"] =
        reconciled["canonical_snapshot_sha256"].clone();
    terminal_args["expected_outcome"] = reconciled["outcome"].clone();
    terminal_args["expected_original_prefix_length"] =
        reconciled["reconstructed_original_prefix_length"].clone();
    terminal_args["expected_current_prefix_length"] =
        reconciled["current_manifest_prefix_length"].clone();
    terminal_args["terminal_request_sha256"] = json!("9".repeat(64));
    terminal_args["terminal_attempt_sha256"] = json!("a".repeat(64));
    terminal_args["dry_run"] = json!(true);
    let dry = mcp.call_tool(
        842,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    assert_eq!(dry_content["provider_calls"], json!(3));

    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let live = mcp.call_tool(
        843,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let live_content = structured_content(&live);
    assert_eq!(live_content["ok"], json!(true), "{live_content}");
    assert_eq!(live_content["provider_calls"], json!(5));
    assert_eq!(live_content["provider_mutations"], json!(0));
    assert_eq!(live_content["lease_retained"], json!(false));
    assert_eq!(
        live_content["effect_assertion_id"],
        json!("schema_create_objects_additive_seed_rows_v1")
    );

    let target = manifest_target_path(&lease_root);
    let receipt_path = fs::read_dir(&target)
        .expect("read canonical seed terminal target")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("terminal-reconciliation.")
            })
        })
        .expect("canonical seed terminal receipt");
    let receipt: Value = serde_json::from_slice(
        &fs::read(receipt_path).expect("read canonical seed terminal receipt"),
    )
    .expect("parse canonical seed terminal receipt");
    assert_eq!(receipt["version"], json!(2));
    assert_eq!(
        receipt["effect_assertion_id"],
        json!("schema_create_objects_additive_seed_rows_v1")
    );

    let replay = mcp.call_tool(844, "d1_finalize_migration_reconciliation", terminal_args);
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], json!(true), "{replay_content}");
    assert_eq!(
        replay_content["status"],
        json!("terminal_reconciliation_already_complete")
    );
    assert_eq!(replay_content["provider_calls"], json!(0));

    let observed = requests.lock().expect("canonical seed request log");
    assert_eq!(observed.len(), 11);
    assert_eq!(
        observed
            .iter()
            .filter(
                |request| reconciliation_statement_markers(request["sql"].as_str().unwrap()).len()
                    == 2
            )
            .count(),
        3,
        "one no-seed selection read precedes each complete proof"
    );
    for request in observed.iter() {
        let sql = request["sql"].as_str().expect("canonical seed proof SQL");
        assert!(
            sql.split(";\n")
                .all(|statement| statement.starts_with("SELECT "))
        );
        assert!(!sql.contains("Daily"));
        assert!(!sql.contains("example.com"));
    }
    drop(observed);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_v2_seven_null_seed_literals_bind_reconciliation_terminal_receipt_and_replay() {
    let columns = (0..7)
        .map(|index| format!("value_{index} TEXT"))
        .collect::<Vec<_>>();
    let column_names = (0..7)
        .map(|index| format!("value_{index}"))
        .collect::<Vec<_>>();
    let column_name_refs = column_names.iter().map(String::as_str).collect::<Vec<_>>();
    let table_sql = format!("CREATE TABLE bootstrap_state({})", columns.join(", "));
    let insert_sql = format!(
        "INSERT INTO bootstrap_state ({}) VALUES ({})",
        column_names.join(", "),
        ["NULL"; 7].join(", ")
    );
    let migration_sql = format!("PRAGMA foreign_keys = ON;\n\n{table_sql};\n{insert_sql};");
    let manifest = json!([{
        "name": "0001_bootstrap_state.sql",
        "size_bytes": migration_sql.len(),
        "sql_sha256": sha256_hex(&migration_sql),
        "sql": migration_sql,
    }]);
    let table_columns = (0..7)
        .map(|index| {
            json!({
                "cid": index,
                "name": format!("value_{index}"),
                "declared_type": "TEXT",
                "not_null": false,
                "default_value": null,
                "primary_key_position": 0,
                "hidden": 0,
            })
        })
        .collect::<Vec<_>>();
    let null_row = (0..7)
        .map(|_| json!({"storage_class": "null", "value": null}))
        .collect::<Vec<_>>();
    let state_expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "bootstrap_state",
                "table_name": "bootstrap_state",
                "sql_sha256": sha256_hex(&table_sql),
            }],
            "tables": [{
                "name": "bootstrap_state",
                "columns": table_columns,
                "foreign_keys": [],
            }],
            "seed_tables": [{
                "table_name": "bootstrap_state",
                "columns": column_names,
                "row_count": 1,
                "rows_sha256": typed_seed_rowset_sha256_version(
                    2,
                    "bootstrap_state",
                    &column_name_refs,
                    vec![null_row],
                ),
            }],
        },
    ]);

    let mut v1_mcp = McpStdioProcess::start();
    let v1_rejection = v1_mcp.call_tool(
        900,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": state_expectations.clone(),
        }),
    );
    let v1_content = structured_content(&v1_rejection);
    assert_eq!(v1_content["ok"], json!(false));
    assert_eq!(v1_content["provider_calls"], json!(0));
    assert_eq!(
        v1_content["error"]["code"],
        "d1.migration_reconciliation_seed_insert_effect_unavailable"
    );
    v1_mcp.terminate();

    let rowid_table_sql = "CREATE TABLE rowid_seed(id INTEGER PRIMARY KEY) STRICT";
    let rowid_insert_sql = "INSERT INTO rowid_seed (id) VALUES (NULL)";
    let rowid_migration_sql = format!("{rowid_table_sql};\n{rowid_insert_sql};");
    let rowid_manifest = json!([{
        "name": "0001_rowid_seed.sql",
        "size_bytes": rowid_migration_sql.len(),
        "sql_sha256": sha256_hex(&rowid_migration_sql),
        "sql": rowid_migration_sql,
    }]);
    let rowid_state_expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [{
                "object_type": "table",
                "name": "rowid_seed",
                "table_name": "rowid_seed",
                "sql_sha256": sha256_hex(rowid_table_sql),
            }],
            "tables": [{
                "name": "rowid_seed",
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
            "seed_tables": [{
                "table_name": "rowid_seed",
                "columns": ["id"],
                "row_count": 1,
                "rows_sha256": typed_seed_rowset_sha256_version(
                    2,
                    "rowid_seed",
                    &["id"],
                    vec![vec![json!({"storage_class": "null", "value": null})]],
                ),
            }],
        },
    ]);
    let mut rowid_mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_API_BASE_URL",
        "http://127.0.0.1:9".to_string(), // DevSkim: ignore DS137138 -- loopback-only zero-call fixture
    )]);
    let rowid_rejection = rowid_mcp.call_tool(
        905,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": rowid_manifest,
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v2",
            "state_expectations": rowid_state_expectations,
        }),
    );
    let rowid_content = structured_content(&rowid_rejection);
    assert_eq!(rowid_content["ok"], json!(false), "{rowid_content}");
    assert_eq!(rowid_content["provider_calls"], json!(0), "{rowid_content}");
    assert_eq!(
        rowid_content["error"]["code"],
        "d1.migration_reconciliation_seed_affinity_unstable"
    );
    rowid_mcp.terminate();

    let (base_url, requests) = spawn_fake_null_seed_reconciliation_api(
        11,
        table_sql.clone(),
        vec![json!({"id": 1, "name": "0001_bootstrap_state.sql"})],
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-null-seeds-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create NULL seed reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make NULL seed reconciliation root private");
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
    let reconciliation_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_objects_additive_seed_rows_v2",
        "state_expectations": state_expectations,
    });
    let reconciliation = mcp.call_tool(
        901,
        "d1_reconcile_migration_manifest",
        reconciliation_args.clone(),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    assert_eq!(reconciled["outcome"], json!("full_state_converged"));
    assert_eq!(reconciled["provider_calls"], json!(3));
    assert_eq!(reconciled["provider_mutations"], json!(0));
    assert_eq!(
        reconciled["effect_assertion"]["id"],
        "schema_create_objects_additive_seed_rows_v2"
    );
    assert_eq!(
        reconciled["effect_assertion"]["scope"]["statement_class"],
        "schema_create_objects_additive_seed_rows_with_nulls"
    );
    assert_eq!(reconciled["seed_row_evidence"][0]["row_count"], 1);

    let mut terminal_args = reconciliation_args;
    terminal_args["expected_reconciliation_plan_sha256"] =
        reconciled["reconciliation_plan_sha256"].clone();
    terminal_args["expected_expectation_proof_sha256"] =
        reconciled["expectation_proof_sha256"].clone();
    terminal_args["expected_query_sha256"] = reconciled["query_sha256"].clone();
    terminal_args["expected_canonical_snapshot_sha256"] =
        reconciled["canonical_snapshot_sha256"].clone();
    terminal_args["expected_outcome"] = reconciled["outcome"].clone();
    terminal_args["expected_original_prefix_length"] =
        reconciled["reconstructed_original_prefix_length"].clone();
    terminal_args["expected_current_prefix_length"] =
        reconciled["current_manifest_prefix_length"].clone();
    terminal_args["terminal_request_sha256"] = json!("d".repeat(64));
    terminal_args["terminal_attempt_sha256"] = json!("e".repeat(64));
    terminal_args["dry_run"] = json!(true);
    let dry = mcp.call_tool(
        902,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    assert_eq!(dry_content["provider_calls"], json!(3));

    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let live = mcp.call_tool(
        903,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let live_content = structured_content(&live);
    assert_eq!(live_content["ok"], json!(true), "{live_content}");
    assert_eq!(live_content["provider_calls"], json!(5));
    assert_eq!(live_content["provider_mutations"], json!(0));
    assert_eq!(live_content["lease_retained"], json!(false));
    assert_eq!(
        live_content["effect_assertion_id"],
        "schema_create_objects_additive_seed_rows_v2"
    );

    let replay = mcp.call_tool(
        904,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], json!(true), "{replay_content}");
    assert_eq!(
        replay_content["status"],
        "terminal_reconciliation_already_complete"
    );
    assert_eq!(replay_content["provider_calls"], json!(0));
    let drifted_sql = format!("{table_sql};\n{insert_sql};");
    let mut drifted_args = terminal_args;
    drifted_args["manifest"][0]["size_bytes"] = json!(drifted_sql.len());
    drifted_args["manifest"][0]["sql_sha256"] = json!(sha256_hex(&drifted_sql));
    drifted_args["manifest"][0]["sql"] = json!(drifted_sql);
    let drifted = mcp.call_tool(905, "d1_finalize_migration_reconciliation", drifted_args);
    let drifted_content = structured_content(&drifted);
    assert_eq!(drifted_content["ok"], json!(false), "{drifted_content}");
    assert_eq!(
        drifted_content["provider_calls"],
        json!(0),
        "{drifted_content}"
    );
    assert_eq!(
        drifted_content["error"]["code"],
        "d1.migration_terminal_approved_evidence_mismatch"
    );
    assert_eq!(requests.lock().expect("NULL seed request log").len(), 11);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_seed_projection_registry_proves_zero_create_only_and_full_prefixes() {
    let (manifest, state_expectations) = seed_prefix_reconciliation_case();

    for (case_index, (prefix, unexpected_intermediate, expected_outcome)) in [
        (0usize, false, "not_committed"),
        (1usize, true, ""),
        (1usize, false, "partial_state_converged"),
        (2usize, false, "full_state_converged"),
    ]
    .into_iter()
    .enumerate()
    {
        let (base_url, requests) =
            spawn_fake_seed_prefix_reconciliation_api(prefix, unexpected_intermediate);
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-seed-prefix-{case_index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create seed-prefix lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make seed-prefix root private");
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
        let args = json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": state_expectations.clone(),
        });
        let response = mcp.call_tool(
            847 + case_index as u64,
            "d1_reconcile_migration_manifest",
            args,
        );
        let content = structured_content(&response).clone();
        if unexpected_intermediate {
            assert_eq!(content["ok"], false, "{content}");
            assert_eq!(
                content["error"]["code"],
                "d1.migration_reconciliation_seed_rows_extra"
            );
            assert_eq!(content["provider_calls"], 2);
            assert_eq!(content["provider_mutations"], 0);
            assert_eq!(content["local_namespace_mutations"], 0);
            assert_eq!(content["lease_retained"], true);
            assert_eq!(requests.lock().expect("unexpected-row requests").len(), 2);
        } else {
            assert_eq!(content["ok"], true, "{content}");
            assert_eq!(content["outcome"], expected_outcome);
            assert_eq!(content["current_manifest_prefix_length"], prefix);
            assert_eq!(content["provider_calls"], 3);
            assert_eq!(
                content["scope_completeness"]["sqlite_master"],
                "complete_exact_declared_object_union"
            );
            assert_eq!(
                content["scope_completeness"]["table_xinfo"],
                "complete_exact_selected_prefix_table_set"
            );
            assert_eq!(
                content["scope_completeness"]["seed_rows"],
                "complete_selected_prefix_manifest_derived_storage_class_and_value_row_set"
            );
            let evidence = content["seed_row_evidence"]
                .as_array()
                .expect("seed evidence array");
            if prefix == 0 {
                assert!(evidence.is_empty());
            } else {
                assert_eq!(evidence.len(), 1);
                assert_eq!(evidence[0]["row_count"], usize::from(prefix == 2));
            }

            if prefix == 1 {
                let mut terminal_args = terminal_args_from_reconciliation(
                    &manifest,
                    &state_expectations,
                    &approved_plan_sha256,
                    &lease_nonce,
                    &lease_payload_sha256,
                    &content,
                );
                terminal_args["effect_assertion_id"] =
                    json!("schema_create_objects_additive_seed_rows_v1");
                let dry = mcp.call_tool(860, "d1_finalize_migration_reconciliation", terminal_args);
                let dry_content = structured_content(&dry);
                assert_eq!(dry_content["ok"], true, "{dry_content}");
                assert_eq!(dry_content["provider_calls"], 3);
                assert_eq!(
                    requests.lock().expect("terminal zero-proof requests").len(),
                    6,
                    "terminal planning must rerun selection plus both zero-row proofs",
                );
            } else {
                assert_eq!(requests.lock().expect("prefix requests").len(), 3);
            }
        }
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_seed_complete_proofs_bind_the_exact_selected_ledger_in_reconcile_and_terminal_paths() {
    let (manifest, state_expectations) = seed_prefix_reconciliation_case();
    let ledger_digest = |prefix: usize| {
        let rows = [
            json!({"id": 1, "name": "0001_create.sql"}),
            json!({"id": 2, "name": "0002_seed.sql"}),
        ]
        .into_iter()
        .take(prefix)
        .collect::<Vec<_>>();
        sha256_hex(&serde_json::to_string(&rows).expect("serialize expected ledger"))
    };

    for (case_index, (sequence, expected_code)) in [
        (
            vec![2usize, 1, 1],
            "d1.migration_reconciliation_selected_ledger_changed",
        ),
        (
            vec![2usize, 2, 1],
            "d1.migration_reconciliation_evidence_unstable",
        ),
        (
            vec![2usize, 1, 2],
            "d1.migration_reconciliation_evidence_unstable",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let expected_complete_prefixes = [sequence[1], sequence[2]];
        let (base_url, requests) = spawn_fake_seed_ledger_sequence_api(sequence);
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-seed-ledger-drift-{case_index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create seed-ledger drift lease root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make seed-ledger drift root private");
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
            870 + case_index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest.clone(),
                "approved_plan_sha256": approved_plan_sha256,
                "lease_nonce": lease_nonce,
                "lease_payload_sha256": lease_payload_sha256,
                "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
                "state_expectations": state_expectations.clone(),
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], false, "{content}");
        assert_eq!(content["error"]["code"], expected_code);
        assert_eq!(content["provider_calls"], 3);
        assert_eq!(content["provider_mutations"], 0);
        assert_eq!(content["local_namespace_mutations"], 0);
        assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
        assert_eq!(content["lease_retained"], true);
        assert_eq!(content["custody_status"], "retained_evidence_verified");
        assert_eq!(
            content["response_evidence"]
                .as_array()
                .expect("drift response evidence")
                .len(),
            3,
        );
        assert_eq!(
            content["selection_binding"]["selected_manifest_prefix_length"],
            2
        );
        assert_eq!(
            content["selection_binding"]["selected_ledger_sha256"],
            ledger_digest(2),
        );
        assert_eq!(
            content["selection_binding"]["selection_query_sha256"]
                .as_str()
                .expect("selection query digest")
                .len(),
            64,
        );
        assert_eq!(
            content["selection_binding"]["complete_ledger_sha256s"],
            json!([
                ledger_digest(expected_complete_prefixes[0]),
                ledger_digest(expected_complete_prefixes[1]),
            ]),
        );
        assert_eq!(requests.lock().expect("drift requests").len(), 3);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }

    let (base_url, requests) = spawn_fake_seed_ledger_sequence_api(vec![2usize, 2, 2, 2, 1, 1]);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-seed-terminal-ledger-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create terminal seed-ledger drift lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make terminal seed-ledger root private");
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
    let args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest.clone(),
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
        "state_expectations": state_expectations.clone(),
    });
    let reconciliation = mcp.call_tool(880, "d1_reconcile_migration_manifest", args);
    let reconciliation_content = structured_content(&reconciliation).clone();
    assert_eq!(
        reconciliation_content["ok"], true,
        "{reconciliation_content}"
    );
    assert_eq!(
        reconciliation_content["selection_binding"]["selected_ledger_sha256"],
        ledger_digest(2),
    );
    assert_eq!(
        reconciliation_content["selection_binding"]["complete_ledger_sha256s"],
        json!([ledger_digest(2), ledger_digest(2)]),
    );

    let mut terminal_args = terminal_args_from_reconciliation(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
        &reconciliation_content,
    );
    terminal_args["effect_assertion_id"] = json!("schema_create_objects_additive_seed_rows_v1");
    let terminal = mcp.call_tool(881, "d1_finalize_migration_reconciliation", terminal_args);
    let terminal_content = structured_content(&terminal);
    assert_eq!(terminal_content["ok"], false, "{terminal_content}");
    assert_eq!(
        terminal_content["error"]["code"],
        "d1.migration_reconciliation_selected_ledger_changed",
    );
    assert_eq!(terminal_content["provider_calls"], 3);
    assert_eq!(terminal_content["provider_mutations"], 0);
    assert_eq!(terminal_content["local_namespace_mutations"], 0);
    assert_eq!(
        terminal_content["retry_decision"],
        "do_not_retry_same_attempt"
    );
    assert_eq!(terminal_content["lease_retained"], true);
    assert_eq!(
        terminal_content["custody_status"],
        "retained_evidence_verified"
    );
    assert_eq!(
        terminal_content["selection_binding"]["complete_ledger_sha256s"],
        json!([ledger_digest(1), ledger_digest(1)]),
    );
    assert_eq!(
        terminal_content["response_evidence"]
            .as_array()
            .expect("terminal drift response evidence")
            .len(),
        3,
    );
    assert_eq!(requests.lock().expect("terminal drift requests").len(), 6);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_seed_complete_proofs_reject_every_premature_manifest_fact_in_reconcile_and_terminal_paths() {
    let (manifest, state_expectations) = premature_manifest_fact_reconciliation_case();
    let cases = [
        (
            0usize,
            PrematureManifestFact::Table,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::Table,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::Index,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::View,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::Trigger,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::AlteredTableStructure,
            "d1.migration_reconciliation_table_proof_mismatch",
        ),
        (
            0usize,
            PrematureManifestFact::CaseVariantTable,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::CaseVariantIndex,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::CaseVariantView,
            "d1.migration_reconciliation_schema_mismatch",
        ),
        (
            1usize,
            PrematureManifestFact::CaseVariantTrigger,
            "d1.migration_reconciliation_schema_mismatch",
        ),
    ];

    for (case_index, (prefix, fact, expected_code)) in cases.into_iter().enumerate() {
        let (base_url, requests) = spawn_fake_premature_manifest_fact_api(prefix, fact, false);
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-premature-manifest-reconcile-{case_index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create premature-manifest reconcile root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make premature-manifest reconcile root private");
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
        let args = json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": state_expectations.clone(),
        });
        let response = mcp.call_tool(
            890 + case_index as u64,
            "d1_reconcile_migration_manifest",
            args,
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], false, "{fact:?}: {content}");
        assert_eq!(
            content["error"]["code"], expected_code,
            "{fact:?}: {content}"
        );
        assert_eq!(content["provider_calls"], 3);
        assert_eq!(content["provider_mutations"], 0);
        assert_eq!(content["local_namespace_mutations"], 0);
        assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
        assert_eq!(content["lease_retained"], true);
        assert_eq!(content["custody_status"], "retained_evidence_verified");
        assert_eq!(
            content["response_evidence"]
                .as_array()
                .expect("premature reconcile evidence")
                .len(),
            3,
        );
        assert_eq!(
            requests.lock().expect("premature reconcile requests").len(),
            3
        );
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }

    for (case_index, (prefix, fact, expected_code)) in cases.into_iter().enumerate() {
        let (base_url, requests) = spawn_fake_premature_manifest_fact_api(prefix, fact, true);
        let lease_root = PathBuf::from("/tmp").join(format!(
            "cloudflare-mcp-premature-manifest-terminal-{case_index}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&lease_root);
        fs::create_dir(&lease_root).expect("create premature-manifest terminal root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
                .expect("make premature-manifest terminal root private");
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
        let args = json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": state_expectations.clone(),
        });
        let reconciliation = mcp.call_tool(
            910 + case_index as u64,
            "d1_reconcile_migration_manifest",
            args,
        );
        let reconciled = structured_content(&reconciliation).clone();
        assert_eq!(reconciled["ok"], true, "{fact:?}: {reconciled}");
        let mut terminal_args = terminal_args_from_reconciliation(
            &manifest,
            &state_expectations,
            &approved_plan_sha256,
            &lease_nonce,
            &lease_payload_sha256,
            &reconciled,
        );
        terminal_args["effect_assertion_id"] = json!("schema_create_objects_additive_seed_rows_v1");
        let terminal = mcp.call_tool(
            930 + case_index as u64,
            "d1_finalize_migration_reconciliation",
            terminal_args,
        );
        let content = structured_content(&terminal);
        assert_eq!(content["ok"], false, "{fact:?}: {content}");
        assert_eq!(
            content["error"]["code"], expected_code,
            "{fact:?}: {content}"
        );
        assert_eq!(content["provider_calls"], 3);
        assert_eq!(content["provider_mutations"], 0);
        assert_eq!(content["local_namespace_mutations"], 0);
        assert_eq!(
            content["query_sha256"], reconciled["query_sha256"],
            "terminal proof must rederive the prefix-scoped query identity: {fact:?}"
        );
        assert_eq!(
            content["query_shape_receipt"], reconciled["query_shape_receipt"],
            "terminal proof must rederive the prefix-scoped query receipt: {fact:?}"
        );
        assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
        assert_eq!(content["lease_retained"], true);
        assert_eq!(content["custody_status"], "retained_evidence_verified");
        assert_eq!(
            content["response_evidence"]
                .as_array()
                .expect("premature terminal evidence")
                .len(),
            3,
        );
        assert_eq!(
            requests.lock().expect("premature terminal requests").len(),
            6
        );
        assert_private_regular_active_lease(&lease_root);
        mcp.terminate();
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_case_variant_parents_and_identity_stable_mixed_seed_storage_converge() {
    let initial_table_sql = "CREATE TABLE Channels(id TEXT PRIMARY KEY, rank INTEGER)";
    let current_table_sql = "CREATE TABLE Channels(id TEXT PRIMARY KEY, rank INTEGER, note TEXT)";
    let alter_sql = "ALTER TABLE channels ADD COLUMN note TEXT";
    let index_sql = "CREATE INDEX channels_by_rank ON cHaNnElS(rank)";
    let insert_sql = "INSERT INTO CHANNELS (ID, RANK) VALUES ('daily', -9223372036854775808)";
    let trigger_sql = "CREATE TRIGGER channels_guard BEFORE UPDATE ON CHANNELS BEGIN SELECT RAISE(ABORT, 'immutable'); END";
    let first_migration_sql = format!("{initial_table_sql};");
    let second_migration_sql = format!("{alter_sql}; {index_sql}; {insert_sql}; {trigger_sql};");
    let manifest = json!([
        {
            "name": "0001_channels.sql",
            "size_bytes": first_migration_sql.len(),
            "sql_sha256": sha256_hex(&first_migration_sql),
            "sql": first_migration_sql,
        },
        {
            "name": "0002_seed.sql",
            "size_bytes": second_migration_sql.len(),
            "sql_sha256": sha256_hex(&second_migration_sql),
            "sql": second_migration_sql,
        }
    ]);
    let seed_rows_sha256 = typed_seed_rowset_sha256(
        "Channels",
        &["ID", "RANK"],
        vec![vec![
            json!({"storage_class": "text", "value": uppercase_hex("daily")}),
            json!({"storage_class": "integer", "value": i64::MIN.to_string()}),
        ]],
    );
    let state_expectations = json!([
        {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
        {
            "manifest_prefix_length": 1,
            "schema_objects": [
                {"object_type": "table", "name": "Channels", "table_name": "Channels", "sql_sha256": sha256_hex(initial_table_sql)},
            ],
            "tables": [{
                "name": "Channels",
                "columns": [
                    {"cid": 0, "name": "id", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 1, "hidden": 0},
                    {"cid": 1, "name": "rank", "declared_type": "INTEGER", "not_null": false, "default_value": null, "primary_key_position": 0, "hidden": 0},
                ],
                "foreign_keys": [],
            }],
            "seed_tables": [{
                "table_name": "Channels",
                "columns": ["ID", "RANK"],
                "row_count": 0,
                "rows_sha256": typed_seed_rowset_sha256("Channels", &["ID", "RANK"], vec![]),
            }],
        },
        {
            "manifest_prefix_length": 2,
            "schema_objects": [
                {"object_type": "index", "name": "channels_by_rank", "table_name": "Channels", "sql_sha256": sha256_hex(index_sql)},
                {"object_type": "table", "name": "Channels", "table_name": "Channels", "sql_sha256": sha256_hex(current_table_sql)},
                {"object_type": "trigger", "name": "channels_guard", "table_name": "Channels", "sql_sha256": sha256_hex(trigger_sql)},
            ],
            "tables": [{
                "name": "Channels",
                "columns": [
                    {"cid": 0, "name": "id", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 1, "hidden": 0},
                    {"cid": 1, "name": "rank", "declared_type": "INTEGER", "not_null": false, "default_value": null, "primary_key_position": 0, "hidden": 0},
                    {"cid": 2, "name": "note", "declared_type": "TEXT", "not_null": false, "default_value": null, "primary_key_position": 0, "hidden": 0},
                ],
                "foreign_keys": [],
            }],
            "seed_tables": [{
                "table_name": "Channels",
                "columns": ["ID", "RANK"],
                "row_count": 1,
                "rows_sha256": seed_rows_sha256,
            }],
        },
    ]);
    let (base_url, requests) = spawn_fake_case_variant_seed_reconciliation_api(false);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-case-variant-seed-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create case-variant seed reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make case-variant seed reconciliation root private");
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
        845,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": state_expectations.clone(),
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["outcome"], json!("full_state_converged"));
    assert_eq!(content["provider_calls"], json!(3));
    assert_eq!(content["provider_mutations"], json!(0));
    assert_eq!(content["local_namespace_mutations"], json!(0));
    assert_eq!(content["seed_row_evidence"][0]["table_name"], "Channels");
    assert_eq!(
        content["seed_row_evidence"][0]["columns"],
        json!(["ID", "RANK"])
    );
    assert_eq!(content["seed_row_evidence"][0]["row_count"], 1);
    let response_json = serde_json::to_string(content).expect("serialize case-variant result");
    assert!(!response_json.contains("daily"));
    assert!(!response_json.contains("9223372036854775808"));
    assert_eq!(requests.lock().expect("case-variant request log").len(), 3);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);

    let (mismatch_base_url, mismatch_requests) =
        spawn_fake_case_variant_seed_reconciliation_api(true);
    let mismatch_lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-case-variant-seed-mismatch-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&mismatch_lease_root);
    fs::create_dir(&mismatch_lease_root).expect("create seed mismatch reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&mismatch_lease_root, fs::Permissions::from_mode(0o700))
            .expect("make seed mismatch reconciliation root private");
    }
    let (mismatch_plan, mismatch_nonce, mismatch_payload) =
        create_retained_reconciliation_fixture(&mismatch_lease_root, &manifest);
    let mut mismatch_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", mismatch_base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            mismatch_lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let mismatch = mismatch_mcp.call_tool(
        846,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": mismatch_plan,
            "lease_nonce": mismatch_nonce,
            "lease_payload_sha256": mismatch_payload,
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": state_expectations,
        }),
    );
    let mismatch_content = structured_content(&mismatch);
    assert_eq!(mismatch_content["ok"], json!(false), "{mismatch_content}");
    assert_eq!(
        mismatch_content["error"]["code"],
        "d1.migration_reconciliation_seed_rows_mismatch"
    );
    assert_eq!(mismatch_content["provider_calls"], 3);
    assert_eq!(mismatch_content["provider_mutations"], 0);
    assert_eq!(mismatch_content["local_namespace_mutations"], 0);
    assert_eq!(mismatch_content["lease_retained"], true);
    assert_eq!(
        mismatch_requests
            .lock()
            .expect("seed mismatch request log")
            .len(),
        3
    );
    mismatch_mcp.terminate();
    let _ = fs::remove_dir_all(mismatch_lease_root);
}

#[test]
fn d1_additive_reconciliation_proves_five_prefixes_with_bounded_checks() {
    let (manifest, state_expectations, schema_rows, ledger_rows, xinfo_rows) =
        additive_check_reconciliation_case();
    assert_eq!(manifest.as_array().map(Vec::len), Some(5));
    assert!(
        manifest
            .as_array()
            .is_some_and(|entries| entries.iter().all(|entry| entry["sql"]
                .as_str()
                .is_some_and(|sql| sql.matches("PRAGMA foreign_keys = ON").count() == 1)))
    );
    let (base_url, requests) =
        spawn_fake_custom_schema_reconciliation_api(3, ledger_rows, schema_rows, xinfo_rows);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-additive-checks-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create additive CHECK reconciliation lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make additive CHECK reconciliation root private");
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
        835,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_objects_additive_v1",
            "state_expectations": state_expectations,
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["outcome"], json!("full_state_converged"));
    assert_eq!(content["current_manifest_prefix_length"], json!(5));
    assert_eq!(content["provider_calls"], json!(3));
    assert_eq!(content["provider_mutations"], json!(0));
    assert_eq!(content["lease_retained"], json!(true));

    let observed = requests.lock().expect("additive CHECK request log");
    assert_eq!(observed.len(), 3);
    for request in observed.iter() {
        let sql = request["sql"].as_str().expect("fixed reconciliation SQL");
        assert!(!sql.contains("ALTER TABLE"));
        assert!(!sql.contains("CHECK"));
        assert!(!sql.contains("PRAGMA foreign_keys = ON"));
    }
    drop(observed);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_terminal_plan_rejects_effect_assertion_change_after_approval_for_identical_table_state() {
    let (base_url, requests) = spawn_fake_reconciliation_api_for_calls(9);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-assertion-binding-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create assertion-binding lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make assertion-binding root private");
    }
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_only_v1",
        "state_expectations": state_expectations,
    });
    let reconciliation = mcp.call_tool(
        816,
        "d1_reconcile_migration_manifest",
        reconciliation_args.clone(),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");

    let mut extended_reconciliation_args = reconciliation_args;
    extended_reconciliation_args["effect_assertion_id"] =
        json!("schema_create_tables_indexes_views_triggers_v1");
    let extended_reconciliation = mcp.call_tool(
        819,
        "d1_reconcile_migration_manifest",
        extended_reconciliation_args,
    );
    let extended = structured_content(&extended_reconciliation);
    assert_eq!(extended["ok"], json!(true), "{extended}");
    assert_eq!(
        extended["canonical_snapshot_sha256"],
        reconciled["canonical_snapshot_sha256"]
    );
    assert_eq!(extended["query_sha256"], reconciled["query_sha256"]);
    assert_ne!(
        extended["reconciliation_plan_sha256"], reconciled["reconciliation_plan_sha256"],
        "selected assertion must change approval identity even for identical table state"
    );
    let mut terminal_args = terminal_args_from_reconciliation(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
        &reconciled,
    );
    let dry = mcp.call_tool(
        817,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");

    terminal_args["effect_assertion_id"] = json!("schema_create_tables_indexes_views_triggers_v1");
    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let rejected = mcp.call_tool(818, "d1_finalize_migration_reconciliation", terminal_args);
    let rejected_content = structured_content(&rejected);
    assert_eq!(rejected_content["ok"], json!(false), "{rejected_content}");
    assert_eq!(
        rejected_content["error"]["code"],
        json!("d1.migration_terminal_plan_mismatch")
    );
    assert_eq!(rejected_content["provider_calls"], json!(0));
    assert_private_regular_active_lease(&lease_root);
    assert_eq!(requests.lock().expect("request log").len(), 9);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_terminal_equal_query_sha_preserves_historical_v2_chronology_across_custody() {
    let (base_url, requests) = spawn_fake_reconciliation_api_with_fault_and_calls(
        ReconciliationFault::RequestTransportFailure(11),
        12,
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-equal-query-active-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create equal-query active root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make equal-query active root private");
    }
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = mcp.call_tool(
        938,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], true, "{reconciled}");
    assert_eq!(reconciled["provider_calls"], 3);
    let historical_v2_plan = json!({
        "version": 1,
        "operation": "d1_reconcile_migration_manifest",
        "target_key_sha256": sha256_hex("acct-1\0db-1"),
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "migrations_table": "d1_migrations",
        "manifest": reconciled["manifest"],
        "lease": reconciled["lease"],
        "original_prefix_length": reconciled["reconstructed_original_prefix_length"],
        "current_prefix_length": reconciled["current_manifest_prefix_length"],
        "outcome": reconciled["outcome"],
        "query_sha256": reconciled["query_sha256"],
        "canonical_snapshot_sha256": reconciled["canonical_snapshot_sha256"],
        "effect_assertion_id": "schema_create_only_v1",
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "next_slice": "persist_terminal_reconciliation_receipt_then_guarded_retirement",
    });
    let historical_v2_plan_sha256 = sha256_hex(
        &serde_json::to_string(&historical_v2_plan).expect("serialize equal-query plan"),
    );
    let mut scoped_v3_plan = historical_v2_plan.clone();
    scoped_v3_plan["version"] = json!(3);
    scoped_v3_plan["query_chronology"] = json!("selected_prefix_v1");
    let scoped_v3_plan_sha256 =
        sha256_hex(&serde_json::to_string(&scoped_v3_plan).expect("serialize scoped-v3 plan"));
    assert_eq!(
        reconciled["reconciliation_plan_sha256"], scoped_v3_plan_sha256,
        "fresh reconciliation must emit the scoped-v3 plan family"
    );
    assert_ne!(historical_v2_plan_sha256, scoped_v3_plan_sha256);
    let mut terminal_args = terminal_args_from_reconciliation(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
        &reconciled,
    );
    let mut unknown_plan_args = terminal_args.clone();
    unknown_plan_args["expected_reconciliation_plan_sha256"] = json!("f".repeat(64));
    let unknown = mcp.call_tool(
        948,
        "d1_finalize_migration_reconciliation",
        unknown_plan_args,
    );
    let unknown_content = structured_content(&unknown);
    assert_eq!(unknown_content["ok"], false, "{unknown_content}");
    assert_eq!(unknown_content["provider_calls"], 0);
    assert_eq!(
        unknown_content["error"]["code"],
        "d1.migration_terminal_approved_evidence_mismatch"
    );
    assert_eq!(requests.lock().expect("unknown-plan requests").len(), 3);
    let current_dry = mcp.call_tool(
        939,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let current_dry_content = structured_content(&current_dry);
    assert_eq!(current_dry_content["ok"], true, "{current_dry_content}");
    assert_eq!(current_dry_content["provider_calls"], 3);
    terminal_args["expected_reconciliation_plan_sha256"] = json!(historical_v2_plan_sha256);

    let dry = mcp.call_tool(
        949,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], true, "{dry_content}");
    assert_eq!(dry_content["provider_calls"], 2);
    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let interrupted = mcp.call_tool(
        950,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let interrupted_content = structured_content(&interrupted);
    assert_eq!(interrupted_content["ok"], false, "{interrupted_content}");
    assert_eq!(interrupted_content["provider_calls"], 4);
    assert_eq!(interrupted_content["local_namespace_mutations"], 1);
    assert_eq!(interrupted_content["receipt_persisted"], true);

    let observed = requests.lock().expect("equal-query active requests");
    assert_eq!(observed.len(), 12);
    assert_eq!(
        observed
            .iter()
            .map(|request| reconciliation_statement_markers(
                request["sql"].as_str().expect("request SQL")
            )
            .len())
            .collect::<Vec<_>>(),
        vec![2, 5, 5, 2, 5, 5, 5, 5, 5, 5, 5, 5],
        "fresh reconciliation and current-plan terminal proof select once, while equal-SHA predecessor terminal proof does not"
    );
    drop(observed);
    mcp.terminate();

    let target = manifest_target_path(&lease_root);
    fs::rename(
        target.join("active.lease.json"),
        target.join("retiring.lease.json"),
    )
    .expect("model equal-query historical-v2 interruption in retiring namespace");
    fs::File::open(&target)
        .expect("open equal-query historical-v2 target")
        .sync_all()
        .expect("sync equal-query historical-v2 retiring namespace");

    let (resume_url, resume_requests) = spawn_fake_reconciliation_api_for_calls(4);
    let mut resume_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", resume_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let resumed = resume_mcp.call_tool(
        951,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let resumed_content = structured_content(&resumed);
    assert_eq!(resumed_content["ok"], true, "{resumed_content}");
    assert_eq!(resumed_content["provider_calls"], 4);
    assert_eq!(resumed_content["local_namespace_mutations"], 1);
    assert_eq!(resumed_content["terminal_receipt_version"], 2);
    assert_eq!(resume_requests.lock().expect("resume requests").len(), 4);

    let replay = resume_mcp.call_tool(952, "d1_finalize_migration_reconciliation", terminal_args);
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], true, "{replay_content}");
    assert_eq!(replay_content["provider_calls"], 0);
    assert_released_manifest_target_custody(&lease_root);
    resume_mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_terminal_historical_v2_distinct_full_union_finalizes_and_replays_from_active_custody() {
    let (base_url, requests) = spawn_fake_predecessor_query_compatibility_api(9, None);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-predecessor-active-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create predecessor active root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make predecessor active root private");
    }
    let (manifest, state_expectations) = two_table_partial_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = mcp.call_tool(
        940,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], true, "{reconciled}");
    assert_eq!(reconciled["current_manifest_prefix_length"], 1);
    assert_eq!(reconciled["provider_calls"], 3);
    let (historical_query_sha256, historical_snapshot_sha256, historical_plan_sha256) =
        predecessor_two_table_reconciliation_evidence(&manifest, &reconciled);

    let mut terminal_args = terminal_args_from_reconciliation(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
        &reconciled,
    );
    terminal_args["expected_query_sha256"] = json!(historical_query_sha256);
    terminal_args["expected_canonical_snapshot_sha256"] = json!(historical_snapshot_sha256);
    terminal_args["expected_reconciliation_plan_sha256"] = json!(historical_plan_sha256);

    let mut unknown_query_args = terminal_args.clone();
    let unknown_query_sha256 = "f".repeat(64);
    unknown_query_args["expected_query_sha256"] = json!(unknown_query_sha256);
    unknown_query_args["expected_reconciliation_plan_sha256"] =
        json!(historical_v2_two_table_reconciliation_plan_sha256(
            &manifest,
            &reconciled,
            &unknown_query_sha256,
            terminal_args["expected_canonical_snapshot_sha256"]
                .as_str()
                .expect("predecessor snapshot digest"),
        ));
    let unknown = mcp.call_tool(
        941,
        "d1_finalize_migration_reconciliation",
        unknown_query_args,
    );
    let unknown_content = structured_content(&unknown);
    assert_eq!(unknown_content["ok"], false, "{unknown_content}");
    assert_eq!(unknown_content["provider_calls"], 0);
    assert_eq!(
        unknown_content["error"]["code"],
        "d1.migration_reconciliation_expected_query_unrecognized"
    );
    assert_eq!(requests.lock().expect("unknown-query requests").len(), 3);

    let dry = mcp.call_tool(
        942,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], true, "{dry_content}");
    assert_eq!(dry_content["provider_calls"], 2);

    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let live = mcp.call_tool(
        943,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let live_content = structured_content(&live);
    assert_eq!(live_content["ok"], true, "{live_content}");
    assert_eq!(live_content["provider_calls"], 4);
    assert_eq!(live_content["provider_mutations"], 0);
    assert_eq!(live_content["local_namespace_mutations"], 3);
    assert_eq!(live_content["lease_retained"], false);
    let receipt_path = manifest_target_path(&lease_root).join(format!(
        "terminal-reconciliation.{lease_nonce}.receipt.json"
    ));
    let durable_receipt: Value = serde_json::from_slice(
        &fs::read(&receipt_path).expect("read predecessor terminal receipt"),
    )
    .expect("decode predecessor terminal receipt");
    assert_eq!(durable_receipt["version"], 2);
    assert_eq!(
        durable_receipt["effect_assertion_id"],
        "schema_create_only_v1"
    );
    assert_eq!(
        durable_receipt["reconciliation_plan_sha256"],
        terminal_args["expected_reconciliation_plan_sha256"]
    );
    assert_eq!(
        durable_receipt["query_sha256"], terminal_args["expected_query_sha256"],
        "the durable receipt must retain the exact predecessor query authority"
    );

    let replay = mcp.call_tool(944, "d1_finalize_migration_reconciliation", terminal_args);
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], true, "{replay_content}");
    assert_eq!(
        replay_content["status"],
        "terminal_reconciliation_already_complete"
    );
    assert_eq!(replay_content["provider_calls"], 0);

    let observed = requests.lock().expect("predecessor active requests");
    assert_eq!(observed.len(), 9);
    let statement_counts = observed
        .iter()
        .map(|request| {
            reconciliation_statement_markers(request["sql"].as_str().expect("request SQL")).len()
        })
        .collect::<Vec<_>>();
    assert_eq!(statement_counts, vec![2, 5, 5, 8, 8, 8, 8, 8, 8]);
    let predecessor_query = predecessor_two_table_full_union_query(
        reconciled["expectation_proof_sha256"]
            .as_str()
            .expect("expectation proof digest"),
    );
    assert!(
        observed[3..]
            .iter()
            .all(|request| request["sql"] == predecessor_query),
        "terminal proof and both refreshes must reuse the exact predecessor query"
    );
    drop(observed);
    assert_released_manifest_target_custody(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_terminal_historical_v2_distinct_full_union_resumes_from_retiring_custody() {
    let (base_url, first_requests) = spawn_fake_predecessor_query_compatibility_api(9, Some(8));
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-predecessor-retiring-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create predecessor retiring root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make predecessor retiring root private");
    }
    let (manifest, state_expectations) = two_table_partial_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut first_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = first_mcp.call_tool(
        945,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], true, "{reconciled}");
    let (historical_query_sha256, historical_snapshot_sha256, historical_plan_sha256) =
        predecessor_two_table_reconciliation_evidence(&manifest, &reconciled);
    let mut terminal_args = terminal_args_from_reconciliation(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
        &reconciled,
    );
    terminal_args["expected_query_sha256"] = json!(historical_query_sha256);
    terminal_args["expected_canonical_snapshot_sha256"] = json!(historical_snapshot_sha256);
    terminal_args["expected_reconciliation_plan_sha256"] = json!(historical_plan_sha256);
    let dry = first_mcp.call_tool(
        946,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry).clone();
    assert_eq!(dry_content["ok"], true, "{dry_content}");
    assert_eq!(dry_content["provider_calls"], 2);
    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();

    let interrupted = first_mcp.call_tool(
        947,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let interrupted_content = structured_content(&interrupted);
    assert_eq!(interrupted_content["ok"], false, "{interrupted_content}");
    assert_eq!(interrupted_content["provider_calls"], 4);
    assert_eq!(interrupted_content["local_namespace_mutations"], 1);
    assert_eq!(interrupted_content["receipt_persisted"], true);
    assert_eq!(
        first_requests
            .lock()
            .expect("first predecessor requests")
            .len(),
        9
    );
    first_mcp.terminate();

    let target = manifest_target_path(&lease_root);
    fs::rename(
        target.join("active.lease.json"),
        target.join("retiring.lease.json"),
    )
    .expect("model predecessor interruption in retiring namespace");
    fs::File::open(&target)
        .expect("open predecessor target")
        .sync_all()
        .expect("sync predecessor retiring namespace");

    let (resume_url, resume_requests) = spawn_fake_predecessor_query_compatibility_api(4, None);
    let mut resume_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", resume_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let resumed = resume_mcp.call_tool(
        948,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let resumed_content = structured_content(&resumed);
    assert_eq!(resumed_content["ok"], true, "{resumed_content}");
    assert_eq!(
        resumed_content["status"],
        "terminal_reconciliation_complete"
    );
    assert_eq!(resumed_content["provider_calls"], 4);
    assert_eq!(resumed_content["provider_mutations"], 0);
    assert_eq!(resumed_content["local_namespace_mutations"], 1);
    assert_eq!(resumed_content["lease_retained"], false);
    assert_eq!(
        resume_requests
            .lock()
            .expect("resume predecessor requests")
            .len(),
        4
    );

    let replay = resume_mcp.call_tool(949, "d1_finalize_migration_reconciliation", terminal_args);
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], true, "{replay_content}");
    assert_eq!(
        replay_content["status"],
        "terminal_reconciliation_already_complete"
    );
    assert_eq!(replay_content["provider_calls"], 0);
    assert_released_manifest_target_custody(&lease_root);
    resume_mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_terminal_replays_canonical_v1_retirement_as_legacy_and_rejects_extended_reinterpretation() {
    #[derive(Serialize)]
    struct LegacyReceipt<'a> {
        version: u8,
        operation: &'static str,
        target_key_sha256: &'a str,
        lease_nonce: &'a str,
        lease_payload_sha256: &'a str,
        approved_apply_plan_sha256: &'a str,
        reconciliation_plan_sha256: &'a str,
        expectation_proof_sha256: &'a str,
        query_sha256: &'a str,
        canonical_snapshot_sha256: &'a str,
        terminal_request_sha256: &'a str,
        terminal_attempt_sha256: &'a str,
        terminal_plan_sha256: &'a str,
        outcome: &'static str,
        original_prefix_length: usize,
        current_prefix_length: usize,
    }

    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-v1-replay-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create v1 replay root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make v1 replay root private");
    }
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let target_key_sha256 = sha256_hex("acct-1\0db-1");
    // The proof hashes the typed expectation structs in declaration order, not
    // the alphabetically keyed input Value used by this stdio fixture.
    let expectation_proof_sha256 =
        "b23a531fbe61cf4fc636dabd6d3cf6d7a4b0f6173e859008f8291d7fd424247b".to_string();
    let query_sha256 = "3".repeat(64);
    let snapshot_sha256 = "4".repeat(64);
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
    let legacy_reconciliation_plan = json!({
        "version": 1,
        "operation": "d1_reconcile_migration_manifest",
        "target_key_sha256": target_key_sha256,
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "migrations_table": "d1_migrations",
        "manifest": manifest_summary,
        "lease": {
            "target_key_sha256": target_key_sha256,
            "namespace": "active",
            "nonce": lease_nonce,
            "payload_sha256": lease_payload_sha256,
            "approved_plan_sha256": approved_plan_sha256,
        },
        "original_prefix_length": 0,
        "current_prefix_length": 0,
        "outcome": "not_committed",
        "query_sha256": query_sha256,
        "canonical_snapshot_sha256": snapshot_sha256,
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "next_slice": "persist_terminal_reconciliation_receipt_then_guarded_retirement",
    });
    let reconciliation_plan_sha256 = sha256_hex(
        &serde_json::to_string(&legacy_reconciliation_plan)
            .expect("legacy reconciliation plan JSON"),
    );
    let terminal_request_sha256 = "5".repeat(64);
    let terminal_attempt_sha256 = "6".repeat(64);
    let terminal_plan = |effect_assertion_id: Option<&str>| {
        let mut plan = json!({
            "version": 1,
            "operation": "d1_finalize_migration_reconciliation",
            "target_key_sha256": target_key_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "approved_apply_plan_sha256": approved_plan_sha256,
            "reconciliation_plan_sha256": reconciliation_plan_sha256,
            "expectation_proof_sha256": expectation_proof_sha256,
            "query_sha256": query_sha256,
            "canonical_snapshot_sha256": snapshot_sha256,
            "outcome": "not_committed",
            "original_prefix_length": 0,
            "current_prefix_length": 0,
            "terminal_request_sha256": terminal_request_sha256,
            "terminal_attempt_sha256": terminal_attempt_sha256,
            "effect": "create_exact_terminal_receipt_then_guarded_retained_lease_retirement",
            "provider_mutations": 0,
        });
        if let Some(id) = effect_assertion_id {
            plan.as_object_mut()
                .expect("terminal plan object")
                .insert("effect_assertion_id".to_string(), json!(id));
        }
        sha256_hex(&serde_json::to_string(&plan).expect("terminal plan JSON"))
    };
    let legacy_terminal_plan = terminal_plan(None);
    let receipt = LegacyReceipt {
        version: 1,
        operation: "d1_finalize_migration_reconciliation",
        target_key_sha256: &target_key_sha256,
        lease_nonce: &lease_nonce,
        lease_payload_sha256: &lease_payload_sha256,
        approved_apply_plan_sha256: &approved_plan_sha256,
        reconciliation_plan_sha256: &reconciliation_plan_sha256,
        expectation_proof_sha256: &expectation_proof_sha256,
        query_sha256: &query_sha256,
        canonical_snapshot_sha256: &snapshot_sha256,
        terminal_request_sha256: &terminal_request_sha256,
        terminal_attempt_sha256: &terminal_attempt_sha256,
        terminal_plan_sha256: &legacy_terminal_plan,
        outcome: "not_committed",
        original_prefix_length: 0,
        current_prefix_length: 0,
    };
    let target = manifest_target_path(&lease_root);
    let receipt_path = target.join(format!(
        "terminal-reconciliation.{lease_nonce}.receipt.json"
    ));
    fs::write(
        &receipt_path,
        serde_json::to_vec(&receipt).expect("canonical v1 receipt"),
    )
    .expect("install canonical v1 receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
            .expect("make v1 receipt private");
    }
    fs::rename(
        target.join("active.lease.json"),
        target.join(format!("retired.{lease_nonce}.lease.json")),
    )
    .expect("install predecessor retired state");
    fs::File::open(&target)
        .expect("open v1 target")
        .sync_all()
        .expect("sync v1 target");

    let mut mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
        lease_root.to_string_lossy().to_string(),
    )]);
    let mut legacy_args = terminal_request_args(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
    );
    legacy_args["expected_reconciliation_plan_sha256"] = json!(reconciliation_plan_sha256.clone());
    legacy_args["expected_expectation_proof_sha256"] = json!(expectation_proof_sha256.clone());
    legacy_args["expected_query_sha256"] = json!(query_sha256.clone());
    legacy_args["expected_canonical_snapshot_sha256"] = json!(snapshot_sha256.clone());
    legacy_args["expected_outcome"] = json!("not_committed");
    legacy_args["expected_original_prefix_length"] = json!(0);
    legacy_args["expected_current_prefix_length"] = json!(0);
    legacy_args["terminal_request_sha256"] = json!(terminal_request_sha256.clone());
    legacy_args["terminal_attempt_sha256"] = json!(terminal_attempt_sha256.clone());
    legacy_args["dry_run"] = json!(false);
    legacy_args["approved_terminal_plan_sha256"] = json!(legacy_terminal_plan.clone());
    let replay = mcp.call_tool(
        820,
        "d1_finalize_migration_reconciliation",
        legacy_args.clone(),
    );
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], json!(true), "{replay_content}");
    assert_eq!(
        replay_content["status"],
        json!("terminal_reconciliation_already_complete")
    );
    assert_eq!(replay_content["terminal_receipt_version"], json!(1));
    assert_eq!(
        replay_content["effect_assertion_id"],
        json!("schema_create_only_v1")
    );
    assert_eq!(replay_content["provider_calls"], json!(0));

    let mut changed_manifest_args = legacy_args.clone();
    changed_manifest_args["manifest"][0]["name"] = json!("9999_changed_name.sql");
    let changed_manifest = mcp.call_tool(
        824,
        "d1_finalize_migration_reconciliation",
        changed_manifest_args,
    );
    let changed_manifest_content = structured_content(&changed_manifest);
    assert_eq!(changed_manifest_content["ok"], json!(false));
    assert_eq!(changed_manifest_content["provider_calls"], json!(0));
    assert_eq!(
        changed_manifest_content["error"]["code"],
        json!("d1.migration_terminal_approved_evidence_mismatch")
    );

    let mut empty_schema_args = legacy_args.clone();
    empty_schema_args["state_expectations"][1]["schema_objects"] = json!([]);
    empty_schema_args["state_expectations"][1]["tables"] = json!([]);
    let empty_schema = mcp.call_tool(
        825,
        "d1_finalize_migration_reconciliation",
        empty_schema_args,
    );
    let empty_schema_content = structured_content(&empty_schema);
    assert_eq!(empty_schema_content["ok"], json!(false));
    assert_eq!(empty_schema_content["provider_calls"], json!(0));
    assert_eq!(
        empty_schema_content["error"]["code"],
        json!("d1.migration_reconciliation_schema_expectation_incomplete")
    );

    let mut changed_table_args = legacy_args.clone();
    changed_table_args["state_expectations"][1]["tables"][0]["columns"][0]["declared_type"] =
        json!("TEXT");
    let changed_table = mcp.call_tool(
        826,
        "d1_finalize_migration_reconciliation",
        changed_table_args,
    );
    let changed_table_content = structured_content(&changed_table);
    assert_eq!(changed_table_content["ok"], json!(false));
    assert_eq!(changed_table_content["provider_calls"], json!(0));
    assert_eq!(
        changed_table_content["error"]["code"],
        json!("d1.migration_terminal_approved_evidence_mismatch")
    );

    let mut changed_prefix_args = legacy_args.clone();
    changed_prefix_args["expected_current_prefix_length"] = json!(1);
    let changed_prefix = mcp.call_tool(
        827,
        "d1_finalize_migration_reconciliation",
        changed_prefix_args,
    );
    let changed_prefix_content = structured_content(&changed_prefix);
    assert_eq!(changed_prefix_content["ok"], json!(false));
    assert_eq!(changed_prefix_content["provider_calls"], json!(0));
    assert_eq!(changed_prefix_content["provider_mutations"], json!(0));
    assert_eq!(
        changed_prefix_content["local_namespace_mutations"],
        json!(0)
    );
    assert_eq!(
        changed_prefix_content["error"]["code"],
        json!("d1.migration_terminal_request_invalid")
    );

    let (view_trigger_manifest, view_trigger_expectations, _) =
        table_index_view_trigger_reconciliation_case();
    let mut legacy_view_trigger_args = legacy_args.clone();
    legacy_view_trigger_args["manifest"] = view_trigger_manifest;
    legacy_view_trigger_args["state_expectations"] = view_trigger_expectations;
    let legacy_view_trigger = mcp.call_tool(
        828,
        "d1_finalize_migration_reconciliation",
        legacy_view_trigger_args,
    );
    let legacy_view_trigger_content = structured_content(&legacy_view_trigger);
    assert_eq!(legacy_view_trigger_content["ok"], json!(false));
    assert_eq!(legacy_view_trigger_content["provider_calls"], json!(0));
    assert_eq!(
        legacy_view_trigger_content["error"]["code"],
        json!("d1.migration_reconciliation_effect_proof_unavailable")
    );

    let mut extended_args = legacy_args;
    extended_args["effect_assertion_id"] = json!("schema_create_tables_indexes_views_triggers_v1");
    extended_args["approved_terminal_plan_sha256"] = json!(terminal_plan(Some(
        "schema_create_tables_indexes_views_triggers_v1"
    )));
    let rejected = mcp.call_tool(821, "d1_finalize_migration_reconciliation", extended_args);
    let rejected_content = structured_content(&rejected);
    assert_eq!(rejected_content["ok"], json!(false), "{rejected_content}");
    assert_eq!(rejected_content["provider_calls"], json!(0));
    assert_eq!(
        rejected_content["error"]["code"],
        json!("d1.migration_terminal_evidence_invalid")
    );
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_terminal_preserves_equal_query_v1_chronology_from_active_through_retiring() {
    #[derive(Serialize)]
    struct LegacyReceipt<'a> {
        version: u8,
        operation: &'static str,
        target_key_sha256: &'a str,
        lease_nonce: &'a str,
        lease_payload_sha256: &'a str,
        approved_apply_plan_sha256: &'a str,
        reconciliation_plan_sha256: &'a str,
        expectation_proof_sha256: &'a str,
        query_sha256: &'a str,
        canonical_snapshot_sha256: &'a str,
        terminal_request_sha256: &'a str,
        terminal_attempt_sha256: &'a str,
        terminal_plan_sha256: &'a str,
        outcome: &'a str,
        original_prefix_length: usize,
        current_prefix_length: usize,
    }

    let (base_url, requests) = spawn_fake_reconciliation_api_for_calls(9);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-v1-retiring-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create v1 retiring root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make v1 retiring root private");
    }
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = mcp.call_tool(
        822,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    let legacy_reconciliation_plan = json!({
        "version": 1,
        "operation": "d1_reconcile_migration_manifest",
        "target_key_sha256": sha256_hex("acct-1\0db-1"),
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "migrations_table": "d1_migrations",
        "manifest": reconciled["manifest"],
        "lease": reconciled["lease"],
        "original_prefix_length": reconciled["reconstructed_original_prefix_length"],
        "current_prefix_length": reconciled["current_manifest_prefix_length"],
        "outcome": reconciled["outcome"],
        "query_sha256": reconciled["query_sha256"],
        "canonical_snapshot_sha256": reconciled["canonical_snapshot_sha256"],
        "retry_decision": "do_not_retry_same_attempt",
        "lease_decision": "retain",
        "next_slice": "persist_terminal_reconciliation_receipt_then_guarded_retirement",
    });
    let legacy_reconciliation_plan_sha256 = sha256_hex(
        &serde_json::to_string(&legacy_reconciliation_plan)
            .expect("legacy reconciliation plan JSON"),
    );
    let terminal_request_sha256 = "d".repeat(64);
    let terminal_attempt_sha256 = "e".repeat(64);
    let legacy_terminal_plan = json!({
        "version": 1,
        "operation": "d1_finalize_migration_reconciliation",
        "target_key_sha256": sha256_hex("acct-1\0db-1"),
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "approved_apply_plan_sha256": approved_plan_sha256,
        "reconciliation_plan_sha256": legacy_reconciliation_plan_sha256,
        "expectation_proof_sha256": reconciled["expectation_proof_sha256"],
        "query_sha256": reconciled["query_sha256"],
        "canonical_snapshot_sha256": reconciled["canonical_snapshot_sha256"],
        "outcome": reconciled["outcome"],
        "original_prefix_length": reconciled["reconstructed_original_prefix_length"],
        "current_prefix_length": reconciled["current_manifest_prefix_length"],
        "terminal_request_sha256": terminal_request_sha256,
        "terminal_attempt_sha256": terminal_attempt_sha256,
        "effect": "create_exact_terminal_receipt_then_guarded_retained_lease_retirement",
        "provider_mutations": 0,
    });
    let legacy_terminal_plan_sha256 = sha256_hex(
        &serde_json::to_string(&legacy_terminal_plan).expect("legacy terminal plan JSON"),
    );
    let mut terminal_args = terminal_args_from_reconciliation(
        &manifest,
        &state_expectations,
        &approved_plan_sha256,
        &lease_nonce,
        &lease_payload_sha256,
        &reconciled,
    );
    terminal_args["expected_reconciliation_plan_sha256"] =
        json!(legacy_reconciliation_plan_sha256.clone());
    terminal_args["terminal_request_sha256"] = json!(terminal_request_sha256.clone());
    terminal_args["terminal_attempt_sha256"] = json!(terminal_attempt_sha256.clone());
    let active_dry = mcp.call_tool(
        829,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let active_dry_content = structured_content(&active_dry);
    assert_eq!(active_dry_content["ok"], true, "{active_dry_content}");
    assert_eq!(active_dry_content["provider_calls"], 2);
    let target_key_sha256 = sha256_hex("acct-1\0db-1");
    let receipt = LegacyReceipt {
        version: 1,
        operation: "d1_finalize_migration_reconciliation",
        target_key_sha256: &target_key_sha256,
        lease_nonce: &lease_nonce,
        lease_payload_sha256: &lease_payload_sha256,
        approved_apply_plan_sha256: &approved_plan_sha256,
        reconciliation_plan_sha256: &legacy_reconciliation_plan_sha256,
        expectation_proof_sha256: reconciled["expectation_proof_sha256"]
            .as_str()
            .expect("expectation digest"),
        query_sha256: reconciled["query_sha256"].as_str().expect("query digest"),
        canonical_snapshot_sha256: reconciled["canonical_snapshot_sha256"]
            .as_str()
            .expect("snapshot digest"),
        terminal_request_sha256: &terminal_request_sha256,
        terminal_attempt_sha256: &terminal_attempt_sha256,
        terminal_plan_sha256: &legacy_terminal_plan_sha256,
        outcome: reconciled["outcome"].as_str().expect("outcome"),
        original_prefix_length: reconciled["reconstructed_original_prefix_length"]
            .as_u64()
            .expect("original prefix") as usize,
        current_prefix_length: reconciled["current_manifest_prefix_length"]
            .as_u64()
            .expect("current prefix") as usize,
    };
    let target = manifest_target_path(&lease_root);
    let receipt_path = target.join(format!(
        "terminal-reconciliation.{lease_nonce}.receipt.json"
    ));
    fs::write(
        &receipt_path,
        serde_json::to_vec(&receipt).expect("canonical v1 receipt"),
    )
    .expect("install v1 receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
            .expect("make v1 receipt private");
    }
    fs::rename(
        target.join("active.lease.json"),
        target.join("retiring.lease.json"),
    )
    .expect("install predecessor retiring state");
    fs::File::open(&target)
        .expect("open target")
        .sync_all()
        .expect("sync retiring state");
    terminal_args["dry_run"] = json!(false);
    terminal_args["approved_terminal_plan_sha256"] = json!(legacy_terminal_plan_sha256);
    let resumed = mcp.call_tool(823, "d1_finalize_migration_reconciliation", terminal_args);
    let resumed_content = structured_content(&resumed);
    assert_eq!(resumed_content["ok"], json!(true), "{resumed_content}");
    assert_eq!(
        resumed_content["status"],
        json!("terminal_reconciliation_complete")
    );
    assert_eq!(resumed_content["terminal_receipt_version"], json!(1));
    assert_eq!(resumed_content["provider_calls"], json!(4));
    assert_eq!(resumed_content["provider_mutations"], json!(0));
    assert_eq!(resumed_content["local_namespace_mutations"], json!(1));
    let observed = requests.lock().expect("request log");
    assert_eq!(observed.len(), 9);
    assert_eq!(
        observed
            .iter()
            .map(|request| reconciliation_statement_markers(
                request["sql"].as_str().expect("request SQL")
            )
            .len())
            .collect::<Vec<_>>(),
        vec![2, 5, 5, 5, 5, 5, 5, 5, 5],
        "equal-SHA legacy-v1 active and retiring proof must retain historical no-selection chronology"
    );
    drop(observed);
    assert_released_manifest_target_custody(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconciliation_stdio_rejects_view_trigger_effects_outside_the_explicit_registry() {
    let (manifest, _, _) = table_index_view_trigger_reconciliation_case();
    let temp_sql = "CREATE TEMP VIEW item_names AS SELECT id FROM items;";
    let temp_manifest = json!([{
        "name": "0001_create.sql",
        "size_bytes": temp_sql.len(),
        "sql_sha256": sha256_hex(temp_sql),
        "sql": temp_sql,
    }]);
    let mut mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_API_BASE_URL",
        "http://127.0.0.1:9".to_string(), // DevSkim: ignore DS137138 -- loopback-only no-provider-call test fixture
    )]);
    for (request_id, effect_assertion_id, candidate) in [
        (813, "schema_create_only_v1", manifest),
        (
            814,
            "schema_create_tables_indexes_views_triggers_v1",
            temp_manifest,
        ),
    ] {
        let response = mcp.call_tool(
            request_id,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": candidate,
                "approved_plan_sha256": "a".repeat(64),
                "lease_nonce": "b".repeat(64),
                "lease_payload_sha256": "c".repeat(64),
                "effect_assertion_id": effect_assertion_id,
                "state_expectations": [],
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{content}");
        assert_eq!(content["provider_calls"], json!(0));
        assert_eq!(
            content["error"]["code"],
            json!("d1.migration_reconciliation_effect_proof_unavailable")
        );
    }
    mcp.terminate();
}

#[test]
fn d1_finalize_migration_reconciliation_stdio_requires_preapproval_and_retires_after_two_fresh_reads()
 {
    let (base_url, requests) = spawn_fake_reconciliation_api_for_calls(11);
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-finalize-manifest-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create terminal lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make terminal root private");
    }
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = mcp.call_tool(
        746,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");

    let terminal_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_only_v1",
        "state_expectations": state_expectations,
        "expected_reconciliation_plan_sha256": reconciled["reconciliation_plan_sha256"],
        "expected_expectation_proof_sha256": reconciled["expectation_proof_sha256"],
        "expected_query_sha256": reconciled["query_sha256"],
        "expected_canonical_snapshot_sha256": reconciled["canonical_snapshot_sha256"],
        "expected_outcome": reconciled["outcome"],
        "expected_original_prefix_length": reconciled["reconstructed_original_prefix_length"],
        "expected_current_prefix_length": reconciled["current_manifest_prefix_length"],
        "terminal_request_sha256": "d".repeat(64),
        "terminal_attempt_sha256": "e".repeat(64),
        "dry_run": true,
    });
    let dry = mcp.call_tool(
        747,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry);
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    assert_eq!(
        dry_content["status"],
        json!("terminal_reconciliation_plan_ready")
    );
    assert_eq!(dry_content["provider_calls"], json!(3));
    assert_eq!(dry_content["lease_retained"], json!(true));
    assert_eq!(
        dry_content["custody_status"],
        json!("retained_evidence_verified")
    );
    assert_eq!(dry_content["lease_decision"], json!("retain"));
    assert_private_regular_active_lease(&lease_root);

    let mut live_args = terminal_args;
    live_args["dry_run"] = json!(false);
    live_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let live = mcp.call_tool(
        748,
        "d1_finalize_migration_reconciliation",
        live_args.clone(),
    );
    let live_content = structured_content(&live);
    assert_eq!(live_content["ok"], json!(true), "{live_content}");
    assert_eq!(
        live_content["status"],
        json!("terminal_reconciliation_complete")
    );
    assert_eq!(live_content["provider_calls"], json!(5));
    assert_eq!(live_content["provider_mutations"], json!(0));
    assert_eq!(live_content["local_namespace_mutations"], json!(3));
    assert_eq!(live_content["lease_retained"], json!(false));
    assert_eq!(
        live_content["custody_status"],
        json!("retired_evidence_verified")
    );
    assert_eq!(live_content["lease_decision"], json!("retired"));
    assert_eq!(
        live_content["provider_read_lifecycle"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );
    assert_released_manifest_target_custody(&lease_root);
    let target = manifest_target_path(&lease_root);
    let receipts = fs::read_dir(&target)
        .expect("read terminal target")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("terminal-reconciliation.")
        })
        .collect::<Vec<_>>();
    assert_eq!(receipts.len(), 1, "one durable terminal receipt");

    let replay = mcp.call_tool(
        749,
        "d1_finalize_migration_reconciliation",
        live_args.clone(),
    );
    let replay_content = structured_content(&replay);
    assert_eq!(replay_content["ok"], json!(true), "{replay_content}");
    assert_eq!(
        replay_content["status"],
        json!("terminal_reconciliation_already_complete")
    );
    assert_eq!(replay_content["replayed"], json!(true));
    assert_eq!(replay_content["provider_calls"], json!(0));
    assert_eq!(replay_content["provider_mutations"], json!(0));
    assert_eq!(replay_content["local_namespace_mutations"], json!(0));
    assert_eq!(replay_content["lease_retained"], json!(false));
    assert_eq!(
        replay_content["custody_status"],
        json!("retired_evidence_verified")
    );
    assert_eq!(replay_content["lease_decision"], json!("retired"));

    let mut changed_manifest_args = live_args;
    changed_manifest_args["manifest"][0]["name"] = json!("9999_changed_name.sql");
    let changed_manifest = mcp.call_tool(
        829,
        "d1_finalize_migration_reconciliation",
        changed_manifest_args,
    );
    let changed_manifest_content = structured_content(&changed_manifest);
    assert_eq!(changed_manifest_content["ok"], json!(false));
    assert_eq!(changed_manifest_content["provider_calls"], json!(0));
    assert_eq!(
        changed_manifest_content["error"]["code"],
        json!("d1.migration_terminal_approved_evidence_mismatch")
    );
    assert_eq!(requests.lock().expect("request log").len(), 11);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_finalize_migration_reconciliation_resumes_exact_receipt_from_retiring_namespace() {
    let (base_url, first_requests) = spawn_fake_reconciliation_api_with_fault_and_calls(
        ReconciliationFault::RequestTransportFailure(10),
        11,
    );
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-finalize-resume-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create terminal resume lease root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make terminal resume root private");
    }
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let mut first_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = first_mcp.call_tool(
        750,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    let terminal_args = json!({
        "database_id": "db-1",
        "migration_family": "newsletter-core",
        "manifest": manifest,
        "approved_plan_sha256": approved_plan_sha256,
        "lease_nonce": lease_nonce,
        "lease_payload_sha256": lease_payload_sha256,
        "effect_assertion_id": "schema_create_only_v1",
        "state_expectations": state_expectations,
        "expected_reconciliation_plan_sha256": reconciled["reconciliation_plan_sha256"],
        "expected_expectation_proof_sha256": reconciled["expectation_proof_sha256"],
        "expected_query_sha256": reconciled["query_sha256"],
        "expected_canonical_snapshot_sha256": reconciled["canonical_snapshot_sha256"],
        "expected_outcome": reconciled["outcome"],
        "expected_original_prefix_length": reconciled["reconstructed_original_prefix_length"],
        "expected_current_prefix_length": reconciled["current_manifest_prefix_length"],
        "terminal_request_sha256": "d".repeat(64),
        "terminal_attempt_sha256": "e".repeat(64),
        "dry_run": true,
    });
    let dry = first_mcp.call_tool(
        751,
        "d1_finalize_migration_reconciliation",
        terminal_args.clone(),
    );
    let dry_content = structured_content(&dry);
    assert_eq!(dry_content["ok"], json!(true), "{dry_content}");
    let mut live_args = terminal_args;
    live_args["dry_run"] = json!(false);
    live_args["approved_terminal_plan_sha256"] = dry_content["terminal_plan_sha256"].clone();
    let interrupted = first_mcp.call_tool(
        752,
        "d1_finalize_migration_reconciliation",
        live_args.clone(),
    );
    let interrupted_content = structured_content(&interrupted);
    assert_eq!(
        interrupted_content["ok"],
        json!(false),
        "{interrupted_content}"
    );
    assert_eq!(interrupted_content["provider_calls"], json!(5));
    assert_eq!(interrupted_content["provider_mutations"], json!(0));
    assert_eq!(interrupted_content["local_namespace_mutations"], json!(1));
    assert_eq!(interrupted_content["lease_retained"], json!(true));
    assert_eq!(
        interrupted_content["custody_status"],
        json!("retained_evidence_verified")
    );
    assert_eq!(interrupted_content["lease_decision"], json!("retain"));
    assert_eq!(first_requests.lock().expect("first request log").len(), 11);
    first_mcp.terminate();

    let target = manifest_target_path(&lease_root);
    let receipts = fs::read_dir(&target)
        .expect("read interrupted terminal target")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("terminal-reconciliation.")
        })
        .count();
    assert_eq!(
        receipts, 1,
        "receipt must precede the interrupted retirement"
    );
    fs::rename(
        target.join("active.lease.json"),
        target.join("retiring.lease.json"),
    )
    .expect("model interruption after entering retiring namespace");
    fs::File::open(&target)
        .expect("open target directory")
        .sync_all()
        .expect("sync modeled retiring namespace");

    let (resume_url, resume_requests) = spawn_fake_reconciliation_api_for_calls(5);
    let mut resume_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", resume_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let resumed = resume_mcp.call_tool(753, "d1_finalize_migration_reconciliation", live_args);
    let resumed_content = structured_content(&resumed);
    assert_eq!(resumed_content["ok"], json!(true), "{resumed_content}");
    assert_eq!(
        resumed_content["status"],
        json!("terminal_reconciliation_complete")
    );
    assert_eq!(resumed_content["provider_calls"], json!(5));
    assert_eq!(resumed_content["provider_mutations"], json!(0));
    assert_eq!(resumed_content["local_namespace_mutations"], json!(1));
    assert_eq!(resumed_content["lease_retained"], json!(false));
    assert_eq!(
        resumed_content["custody_status"],
        json!("retired_evidence_verified")
    );
    assert_eq!(resumed_content["lease_decision"], json!("retired"));
    assert_eq!(resume_requests.lock().expect("resume request log").len(), 5);
    assert_released_manifest_target_custody(&lease_root);
    resume_mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_finalize_migration_reconciliation_stdio_reports_preinspection_and_inspection_failures_exactly()
 {
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let mut mcp = McpStdioProcess::start();
    let base_args = terminal_request_args(
        &manifest,
        &state_expectations,
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
    );

    let mut invalid_args = base_args.clone();
    invalid_args["expected_outcome"] = json!("unknown");
    let invalid = mcp.call_tool(754, "d1_finalize_migration_reconciliation", invalid_args);
    let invalid_content = structured_content(&invalid);
    assert_terminal_negative_whole_response(
        invalid_content,
        json!({
            "ok": false,
            "operation": "d1_finalize_migration_reconciliation",
            "dry_run": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_retained": null,
            "custody_status": "not_inspected",
            "receipt_persisted": false,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_terminal_request_invalid",
                "message": "terminal reconciliation requires canonical distinct request/attempt digests, exact approved evidence, a valid outcome/prefix relationship, and a live approval pin",
                "hint": "Retain exact custody evidence. Do not retry the provider write or retire the lease outside this guarded terminal boundary."
            }
        }),
    );

    let mut approval_mismatch_args = base_args.clone();
    approval_mismatch_args["dry_run"] = json!(false);
    approval_mismatch_args["approved_terminal_plan_sha256"] = json!("f".repeat(64));
    let approval_mismatch = mcp.call_tool(
        755,
        "d1_finalize_migration_reconciliation",
        approval_mismatch_args,
    );
    let approval_mismatch_content = structured_content(&approval_mismatch);
    assert_terminal_negative_whole_response(
        approval_mismatch_content,
        json!({
            "ok": false,
            "operation": "d1_finalize_migration_reconciliation",
            "dry_run": false,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_retained": null,
            "custody_status": "not_inspected",
            "receipt_persisted": false,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_terminal_plan_mismatch",
                "message": "approved_terminal_plan_sha256 does not match the exact pre-existing terminal plan",
                "hint": "Retain exact custody evidence. Do not retry the provider write or retire the lease outside this guarded terminal boundary."
            }
        }),
    );

    let inspection_failed = mcp.call_tool(756, "d1_finalize_migration_reconciliation", base_args);
    let inspection_failed_content = structured_content(&inspection_failed);
    assert_terminal_negative_whole_response(
        inspection_failed_content,
        json!({
            "ok": false,
            "operation": "d1_finalize_migration_reconciliation",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_retained": null,
            "custody_status": "inspection_failed",
            "receipt_persisted": null,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_reconciliation_lease_root_unconfigured",
                "message": "terminal reconciliation requires the configured operator-owned migration lease root",
                "hint": "Retain the exact custody evidence and resolve this boundary before any provider read or migration retry."
            }
        }),
    );
    mcp.terminate();
}

#[test]
fn d1_terminal_request_rejects_the_complete_manifest_outcome_prefix_negative_matrix() {
    let (manifest, state_expectations) = seed_prefix_reconciliation_case();
    let invalid_products = [
        ("not_committed", 0usize, 1usize),
        ("not_committed", 1, 0),
        ("not_committed", 3, 3),
        ("partial_state_converged", 0, 0),
        ("partial_state_converged", 0, 2),
        ("partial_state_converged", 0, 3),
        ("partial_state_converged", 1, 0),
        ("full_state_converged", 0, 0),
        ("full_state_converged", 0, 1),
        ("full_state_converged", 0, 3),
        ("full_state_converged", 1, 0),
    ];
    let mut mcp = McpStdioProcess::start();
    for (case_index, (outcome, original_prefix_length, current_prefix_length)) in
        invalid_products.into_iter().enumerate()
    {
        let mut args = terminal_request_args(
            &manifest,
            &state_expectations,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
        );
        args["effect_assertion_id"] = json!("schema_create_objects_additive_seed_rows_v1");
        args["expected_outcome"] = json!(outcome);
        args["expected_original_prefix_length"] = json!(original_prefix_length);
        args["expected_current_prefix_length"] = json!(current_prefix_length);
        let rejected = mcp.call_tool(
            1100 + case_index as u64,
            "d1_finalize_migration_reconciliation",
            args,
        );
        let content = structured_content(&rejected);
        assert_eq!(content["ok"], false, "{content}");
        assert_eq!(
            content["error"]["code"], "d1.migration_terminal_request_invalid",
            "{outcome}: {original_prefix_length}->{current_prefix_length}"
        );
        assert_eq!(content["custody_status"], "not_inspected", "{content}");
        assert_eq!(content["provider_calls"], 0, "{content}");
        assert_eq!(content["provider_mutations"], 0, "{content}");
        assert_eq!(content["local_namespace_mutations"], 0, "{content}");
        assert_eq!(content["receipt_persisted"], false, "{content}");
    }
    mcp.terminate();
}

#[test]
fn d1_terminal_restored_v1_v2_semantic_contradictions_fail_read_only_in_every_namespace() {
    #[derive(Serialize)]
    struct RestoredReceipt<'a> {
        version: u8,
        operation: &'static str,
        target_key_sha256: &'a str,
        lease_nonce: &'a str,
        lease_payload_sha256: &'a str,
        approved_apply_plan_sha256: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        effect_assertion_id: Option<&'static str>,
        reconciliation_plan_sha256: &'a str,
        expectation_proof_sha256: &'a str,
        query_sha256: &'a str,
        canonical_snapshot_sha256: &'a str,
        terminal_request_sha256: &'a str,
        terminal_attempt_sha256: &'a str,
        terminal_plan_sha256: &'a str,
        outcome: &'a str,
        original_prefix_length: usize,
        current_prefix_length: usize,
    }

    let (manifest, state_expectations) = one_table_reconciliation_case();
    let contradictory_products = [
        ("not_committed", 0usize, 1usize),
        ("not_committed", 1, 0),
        ("partial_state_converged", 0, 0),
        ("partial_state_converged", 1, 0),
        ("full_state_converged", 0, 0),
        ("full_state_converged", 1, 0),
    ];
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-terminal-semantic-restores-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create semantic restore root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make semantic restore root private");
    }
    let mut mcp = McpStdioProcess::start_with_env(vec![
        (
            "CLOUDFLARE_MCP_API_BASE_URL",
            "http://127.0.0.1:9".to_string(), // DevSkim: ignore DS137138 -- loopback-only zero-call fixture
        ),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let target_key_sha256 = sha256_hex("acct-1\0db-1");
    let reconciliation_plan_sha256 = "1".repeat(64);
    let expectation_proof_sha256 = "2".repeat(64);
    let query_sha256 = "3".repeat(64);
    let canonical_snapshot_sha256 = "4".repeat(64);
    let terminal_request_sha256 = "5".repeat(64);
    let terminal_attempt_sha256 = "6".repeat(64);
    let terminal_plan_sha256 = "7".repeat(64);
    let mut request_id = 1200u64;

    for receipt_version in [1u8, 2] {
        for namespace in ["active", "retiring", "retired"] {
            for (outcome, original_prefix_length, current_prefix_length) in contradictory_products {
                let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
                    create_retained_reconciliation_fixture(&lease_root, &manifest);
                let target = manifest_target_path(&lease_root);
                let receipt = RestoredReceipt {
                    version: receipt_version,
                    operation: "d1_finalize_migration_reconciliation",
                    target_key_sha256: &target_key_sha256,
                    lease_nonce: &lease_nonce,
                    lease_payload_sha256: &lease_payload_sha256,
                    approved_apply_plan_sha256: &approved_plan_sha256,
                    effect_assertion_id: (receipt_version == 2).then_some("schema_create_only_v1"),
                    reconciliation_plan_sha256: &reconciliation_plan_sha256,
                    expectation_proof_sha256: &expectation_proof_sha256,
                    query_sha256: &query_sha256,
                    canonical_snapshot_sha256: &canonical_snapshot_sha256,
                    terminal_request_sha256: &terminal_request_sha256,
                    terminal_attempt_sha256: &terminal_attempt_sha256,
                    terminal_plan_sha256: &terminal_plan_sha256,
                    outcome,
                    original_prefix_length,
                    current_prefix_length,
                };
                let receipt_bytes =
                    serde_json::to_vec(&receipt).expect("encode restored semantic receipt");
                let receipt_path = target.join(format!(
                    "terminal-reconciliation.{lease_nonce}.receipt.json"
                ));
                fs::write(&receipt_path, &receipt_bytes)
                    .expect("install restored semantic receipt");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))
                        .expect("make restored semantic receipt private");
                }
                let evidence_path = match namespace {
                    "active" => target.join("active.lease.json"),
                    "retiring" => {
                        let path = target.join("retiring.lease.json");
                        fs::rename(target.join("active.lease.json"), &path)
                            .expect("install retiring semantic receipt fixture");
                        path
                    }
                    "retired" => {
                        let path = target.join(format!("retired.{lease_nonce}.lease.json"));
                        fs::rename(target.join("active.lease.json"), &path)
                            .expect("install retired semantic receipt fixture");
                        path
                    }
                    _ => unreachable!(),
                };
                let evidence_bytes = fs::read(&evidence_path).expect("read semantic evidence");
                let args = terminal_request_args(
                    &manifest,
                    &state_expectations,
                    &approved_plan_sha256,
                    &lease_nonce,
                    &lease_payload_sha256,
                );
                let rejected =
                    mcp.call_tool(request_id, "d1_finalize_migration_reconciliation", args);
                request_id += 1;
                let content = structured_content(&rejected);
                assert_eq!(content["ok"], false, "{content}");
                assert_eq!(
                    content["error"]["code"], "d1.migration_terminal_evidence_invalid",
                    "v{receipt_version} {namespace} {outcome} {original_prefix_length}->{current_prefix_length}"
                );
                assert_eq!(content["provider_calls"], 0, "{content}");
                assert_eq!(content["provider_mutations"], 0, "{content}");
                assert_eq!(content["local_namespace_mutations"], 0, "{content}");
                assert_eq!(content["receipt_persisted"], Value::Null, "{content}");
                assert_eq!(
                    fs::read(&receipt_path).expect("reread restored receipt"),
                    receipt_bytes,
                    "receipt rejection must not mutate local evidence"
                );
                assert_eq!(
                    fs::read(&evidence_path).expect("reread restored custody"),
                    evidence_bytes,
                    "custody rejection must not mutate local evidence"
                );
                fs::remove_dir_all(&target).expect("remove completed semantic fixture");
            }
        }
    }
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_finalize_migration_reconciliation_stdio_distinguishes_verified_retained_and_retired_without_receipt()
 {
    let (manifest, state_expectations) = one_table_reconciliation_case();

    let retained_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-finalize-retained-negative-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&retained_root);
    fs::create_dir(&retained_root).expect("create retained negative root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&retained_root, fs::Permissions::from_mode(0o700))
            .expect("make retained negative root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&retained_root, &manifest);
    let receipt = manifest_target_path(&retained_root).join(format!(
        "terminal-reconciliation.{lease_nonce}.receipt.json"
    ));
    fs::write(&receipt, b"{}").expect("write contradictory terminal receipt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600))
            .expect("make contradictory receipt private");
    }
    let mut retained_mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
        retained_root.to_string_lossy().to_string(),
    )]);
    let retained_failure = retained_mcp.call_tool(
        757,
        "d1_finalize_migration_reconciliation",
        terminal_request_args(
            &manifest,
            &state_expectations,
            &approved_plan_sha256,
            &lease_nonce,
            &lease_payload_sha256,
        ),
    );
    let retained_content = structured_content(&retained_failure);
    assert_terminal_negative_whole_response(
        retained_content,
        json!({
            "ok": false,
            "operation": "d1_finalize_migration_reconciliation",
            "dry_run": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_retained": null,
            "custody_status": "retained_evidence_unverified",
            "receipt_persisted": null,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_terminal_evidence_invalid",
                "message": "terminal reconciliation receipt is malformed, duplicate-keyed, or structurally unexpected",
                "hint": "Preserve the exact target custody directory and reconcile its receipt and lease namespaces before another terminal attempt."
            }
        }),
    );
    assert_private_regular_active_lease(&retained_root);
    retained_mcp.terminate();
    let _ = fs::remove_dir_all(&retained_root);

    let retired_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-finalize-retired-negative-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&retired_root);
    fs::create_dir(&retired_root).expect("create retired negative root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&retired_root, fs::Permissions::from_mode(0o700))
            .expect("make retired negative root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&retired_root, &manifest);
    let target = manifest_target_path(&retired_root);
    fs::rename(
        target.join("active.lease.json"),
        target.join(format!("retired.{lease_nonce}.lease.json")),
    )
    .expect("model retirement without receipt");
    fs::File::open(&target)
        .expect("open retired target")
        .sync_all()
        .expect("sync retired target");
    let mut retired_mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
        retired_root.to_string_lossy().to_string(),
    )]);
    let retired_failure = retired_mcp.call_tool(
        758,
        "d1_finalize_migration_reconciliation",
        terminal_request_args(
            &manifest,
            &state_expectations,
            &approved_plan_sha256,
            &lease_nonce,
            &lease_payload_sha256,
        ),
    );
    let retired_content = structured_content(&retired_failure);
    assert_terminal_negative_whole_response(
        retired_content,
        json!({
            "ok": false,
            "operation": "d1_finalize_migration_reconciliation",
            "dry_run": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_decision": "retired",
            "lease_retained": false,
            "custody_status": "retired_evidence_verified",
            "receipt_persisted": false,
            "provider_calls": 0,
            "provider_read_lifecycle": [],
            "response_evidence": [],
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_terminal_receipt_absent",
                "message": "terminal retirement exists without its exact terminal receipt",
                "hint": "Retain exact custody evidence. Do not retry the provider write or retire the lease outside this guarded terminal boundary."
            }
        }),
    );
    assert_eq!(retired_manifest_entries(&target).len(), 1);
    retired_mcp.terminate();
    let _ = fs::remove_dir_all(&retired_root);
}

#[test]
fn d1_finalize_migration_reconciliation_stdio_does_not_claim_retention_after_custody_drift() {
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-finalize-drift-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create terminal drift root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make terminal drift root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);

    let (baseline_url, baseline_requests) = spawn_fake_reconciliation_api();
    let mut baseline_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", baseline_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciled_response = baseline_mcp.call_tool(
        759,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations,
        }),
    );
    let reconciled = structured_content(&reconciled_response).clone();
    assert_eq!(reconciled["ok"], json!(true), "{reconciled}");
    assert_eq!(
        baseline_requests
            .lock()
            .expect("baseline request log")
            .len(),
        3
    );
    baseline_mcp.terminate();

    let active = assert_private_regular_active_lease(&lease_root);
    let (drift_url, drift_requests) =
        spawn_fake_reconciliation_api_with_fault(ReconciliationFault::CustodyDrift(active));
    let mut drift_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", drift_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let drift = drift_mcp.call_tool(
        760,
        "d1_finalize_migration_reconciliation",
        terminal_args_from_reconciliation(
            &manifest,
            &state_expectations,
            &approved_plan_sha256,
            &lease_nonce,
            &lease_payload_sha256,
            &reconciled,
        ),
    );
    let drift_content = structured_content(&drift);
    let query_sha256 = drift_content["query_sha256"].clone();
    let query_shape_receipt = drift_content["query_shape_receipt"].clone();
    let response_evidence = drift_content["response_evidence"].clone();
    let provider_lifecycle = drift_content["provider_read_lifecycle"].clone();
    assert_eq!(
        response_evidence.as_array().map(Vec::len),
        Some(1),
        "{drift_content}"
    );
    assert_eq!(
        provider_lifecycle.as_array().map(Vec::len),
        Some(1),
        "{drift_content}"
    );
    assert_terminal_negative_whole_response(
        drift_content,
        json!({
            "ok": false,
            "operation": "d1_finalize_migration_reconciliation",
            "dry_run": true,
            "read_only": true,
            "status": "reconciliation_required",
            "retry_decision": "do_not_retry_same_attempt",
            "lease_retained": null,
            "custody_status": "retained_evidence_unverified",
            "receipt_persisted": null,
            "query_sha256": query_sha256,
            "query_shape_receipt": query_shape_receipt,
            "response_evidence": response_evidence,
            "provider_calls": 1,
            "provider_read_lifecycle": provider_lifecycle,
            "provider_mutations": 0,
            "local_namespace_mutations": 0,
            "error": {
                "code": "d1.migration_reconciliation_lease_changed",
                "message": "retained lease payload digest changed",
                "hint": "Retain the exact custody evidence and resolve this boundary before any provider read or migration retry."
            }
        }),
    );
    assert_eq!(drift_requests.lock().expect("drift request log").len(), 1);
    drift_mcp.terminate();
    let _ = fs::remove_dir_all(&lease_root);
}

#[test]
fn d1_post_parse_custody_release_overrides_parse_failure_in_reconcile_and_terminal_paths() {
    let (manifest, state_expectations) = one_table_reconciliation_case();
    let reconcile_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-post-parse-release-reconcile-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&reconcile_root);
    fs::create_dir(&reconcile_root).expect("create post-parse reconcile root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&reconcile_root, fs::Permissions::from_mode(0o700))
            .expect("make post-parse reconcile root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&reconcile_root, &manifest);
    let active = assert_private_regular_active_lease(&reconcile_root);
    let retiring = active.with_file_name("retiring.lease.json");
    let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(
        ReconciliationFault::CustodyRelease(active.clone(), retiring.clone()),
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            reconcile_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        884,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations.clone(),
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], false, "{content}");
    assert_eq!(
        content["error"]["code"], "d1.migration_reconciliation_lease_changed",
        "{content}"
    );
    assert_eq!(content["custody_status"], "retained_evidence_unverified");
    assert_eq!(content["lease_retained"], Value::Null);
    assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
    assert_eq!(content["provider_calls"], 1);
    assert_eq!(content["provider_mutations"], 0);
    assert_eq!(content["local_namespace_mutations"], 0);
    assert_eq!(
        content["response_evidence"]
            .as_array()
            .expect("post-parse reconcile response evidence")
            .len(),
        1
    );
    let observed = requests.lock().expect("post-parse reconcile requests");
    assert_eq!(observed.len(), 1);
    assert_eq!(
        reconciliation_statement_markers(
            observed[0]["sql"].as_str().expect("selection request SQL")
        )
        .len(),
        2,
        "custody release after selection parsing must stop before either complete read"
    );
    drop(observed);
    assert!(!active.exists());
    assert!(retiring.exists());
    mcp.terminate();
    let _ = fs::remove_dir_all(&reconcile_root);

    let terminal_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-post-parse-release-terminal-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&terminal_root);
    fs::create_dir(&terminal_root).expect("create post-parse terminal root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&terminal_root, fs::Permissions::from_mode(0o700))
            .expect("make post-parse terminal root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&terminal_root, &manifest);
    let (baseline_url, baseline_requests) = spawn_fake_reconciliation_api();
    let mut baseline_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", baseline_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            terminal_root.to_string_lossy().to_string(),
        ),
    ]);
    let reconciliation = baseline_mcp.call_tool(
        885,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": approved_plan_sha256,
            "lease_nonce": lease_nonce,
            "lease_payload_sha256": lease_payload_sha256,
            "effect_assertion_id": "schema_create_only_v1",
            "state_expectations": state_expectations.clone(),
        }),
    );
    let reconciled = structured_content(&reconciliation).clone();
    assert_eq!(reconciled["ok"], true, "{reconciled}");
    assert_eq!(reconciled["provider_calls"], 3);
    assert_eq!(
        reconciled["response_evidence"]
            .as_array()
            .expect("baseline response evidence")
            .len(),
        3
    );
    assert_eq!(
        reconciled["provider_read_lifecycle"]
            .as_array()
            .expect("baseline provider chronology")
            .len(),
        3
    );
    let observed = baseline_requests.lock().expect("baseline requests");
    assert_eq!(
        observed
            .iter()
            .map(|request| reconciliation_statement_markers(
                request["sql"].as_str().expect("baseline request SQL")
            )
            .len())
            .collect::<Vec<_>>(),
        vec![2, 5, 5],
        "fresh scoped chronology must be selection followed by two complete reads"
    );
    assert_ne!(observed[0]["sql"], observed[1]["sql"]);
    assert_eq!(observed[1]["sql"], observed[2]["sql"]);
    assert_eq!(
        reconciled["selection_binding"]["selection_query_sha256"],
        sha256_hex(observed[0]["sql"].as_str().expect("selection SQL"))
    );
    assert_eq!(
        reconciled["query_sha256"],
        sha256_hex(observed[1]["sql"].as_str().expect("complete SQL"))
    );
    drop(observed);
    baseline_mcp.terminate();

    let active = assert_private_regular_active_lease(&terminal_root);
    let retiring = active.with_file_name("retiring.lease.json");
    let (release_url, release_requests) = spawn_fake_reconciliation_api_with_fault(
        ReconciliationFault::CustodyRelease(active.clone(), retiring.clone()),
    );
    let mut release_mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", release_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            terminal_root.to_string_lossy().to_string(),
        ),
    ]);
    let terminal = release_mcp.call_tool(
        886,
        "d1_finalize_migration_reconciliation",
        terminal_args_from_reconciliation(
            &manifest,
            &state_expectations,
            &approved_plan_sha256,
            &lease_nonce,
            &lease_payload_sha256,
            &reconciled,
        ),
    );
    let content = structured_content(&terminal);
    assert_eq!(content["ok"], false, "{content}");
    assert_eq!(
        content["error"]["code"], "d1.migration_reconciliation_lease_changed",
        "{content}"
    );
    assert_eq!(content["custody_status"], "retained_evidence_unverified");
    assert_eq!(content["lease_retained"], Value::Null);
    assert_eq!(content["receipt_persisted"], Value::Null);
    assert_eq!(content["retry_decision"], "do_not_retry_same_attempt");
    assert_eq!(content["provider_calls"], 1);
    assert_eq!(content["provider_mutations"], 0);
    assert_eq!(content["local_namespace_mutations"], 0);
    assert_eq!(
        content["response_evidence"]
            .as_array()
            .expect("post-parse terminal response evidence")
            .len(),
        1
    );
    let observed = release_requests.lock().expect("release requests");
    assert_eq!(observed.len(), 1);
    assert_eq!(
        reconciliation_statement_markers(
            observed[0]["sql"].as_str().expect("terminal selection SQL")
        )
        .len(),
        2,
        "terminal custody release after selection parsing must stop before either complete read"
    );
    drop(observed);
    assert!(!active.exists());
    assert!(retiring.exists());
    assert!(
        fs::read_dir(manifest_target_path(&terminal_root))
            .expect("read post-parse terminal target")
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with("terminal-reconciliation."))
    );
    release_mcp.terminate();
    let _ = fs::remove_dir_all(&terminal_root);
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
            "query_shape_receipt": null,
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
            "query_shape_receipt": null,
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
    let query_shape_receipt = content["query_shape_receipt"].clone();
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
            "query_shape_receipt": query_shape_receipt,
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
fn d1_canonical_seed_table_case_aliases_fail_before_custody_or_provider_access() {
    let cases = [
        (
            vec![
                "CREATE TABLE channels(id TEXT PRIMARY KEY); CREATE TRIGGER channels_guard BEFORE UPDATE ON CHANNELS BEGIN SELECT RAISE(ABORT, 'immutable'); END; INSERT INTO channels (id) VALUES ('daily');",
            ],
            "d1.migration_reconciliation_seed_after_trigger",
            "a canonical seed INSERT must precede every trigger on its target, including across manifest entries",
        ),
        (
            vec![
                "CREATE TABLE channels(id TEXT PRIMARY KEY); CREATE TRIGGER channels_guard BEFORE UPDATE ON CHANNELS BEGIN SELECT RAISE(ABORT, 'immutable'); END;",
                "INSERT INTO cHaNnElS (id) VALUES ('daily');",
            ],
            "d1.migration_reconciliation_seed_after_trigger",
            "a canonical seed INSERT must precede every trigger on its target, including across manifest entries",
        ),
        (
            vec![
                "CREATE TABLE Channels(id TEXT PRIMARY KEY); INSERT INTO channels (id) VALUES ('daily');",
                "INSERT INTO CHANNELS (id) VALUES ('weekly');",
            ],
            "d1.migration_reconciliation_seed_target_reused",
            "each manifest-created seed table may have exactly one canonical top-level seed INSERT",
        ),
    ];

    let mut mcp = McpStdioProcess::start();
    for (offset, (sql_entries, code, message)) in cases.into_iter().enumerate() {
        let manifest = sql_entries
            .into_iter()
            .enumerate()
            .map(|(index, sql)| {
                json!({
                    "name": format!("{:04}.sql", index + 1),
                    "size_bytes": sql.len(),
                    "sql_sha256": sha256_hex(sql),
                    "sql": sql,
                })
            })
            .collect::<Vec<_>>();
        let response = mcp.call_tool(
            757 + offset as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest,
                "approved_plan_sha256": "a".repeat(64),
                "lease_nonce": "b".repeat(64),
                "lease_payload_sha256": "c".repeat(64),
                "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
                "state_expectations": [],
            }),
        );
        let content = structured_content(&response);
        assert_eq!(
            content,
            &expected_d1_reconciliation_semantic_error(
                code,
                message,
                "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
            ),
            "{content}",
        );
    }

    let no_op_sql = "CREATE TABLE IF NOT EXISTS Channels(id TEXT PRIMARY KEY); CREATE TRIGGER IF NOT EXISTS channels_guard BEFORE UPDATE ON CHANNELS BEGIN SELECT RAISE(ABORT, 'immutable'); END; INSERT INTO channels (id) VALUES ('daily');";
    let no_op_response = mcp.call_tool(
        760,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": [{
                "name": "0001.sql",
                "size_bytes": no_op_sql.len(),
                "sql_sha256": sha256_hex(no_op_sql),
                "sql": no_op_sql,
            }],
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": [],
        }),
    );
    let no_op_content = structured_content(&no_op_response);
    let mut expected_no_op = expected_d1_reconciliation_semantic_error(
        "d1.migration_reconciliation_seed_create_if_not_exists_unavailable",
        "the seed-row assertion requires every classified CREATE object to be an unconditional actual creation",
        "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
    );
    expected_no_op["capability_state"] = json!("capability_gap");
    assert_eq!(no_op_content, &expected_no_op, "{no_op_content}");

    let trigger_no_op_sql = "CREATE TABLE Channels(id TEXT PRIMARY KEY); INSERT INTO channels (id) VALUES ('daily'); CREATE TRIGGER IF NOT EXISTS channels_guard BEFORE UPDATE ON CHANNELS BEGIN SELECT RAISE(ABORT, 'immutable'); END;";
    let trigger_no_op_response = mcp.call_tool(
        761,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": [{
                "name": "0001.sql",
                "size_bytes": trigger_no_op_sql.len(),
                "sql_sha256": sha256_hex(trigger_no_op_sql),
                "sql": trigger_no_op_sql,
            }],
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": [],
        }),
    );
    let trigger_no_op_content = structured_content(&trigger_no_op_response);
    assert_eq!(
        trigger_no_op_content, &expected_no_op,
        "{trigger_no_op_content}"
    );

    let affinity_sql = "CREATE TABLE metrics(value TEXT); INSERT INTO metrics (value) VALUES (1);";
    let affinity_response = mcp.call_tool(
        762,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": [{
                "name": "0001.sql",
                "size_bytes": affinity_sql.len(),
                "sql_sha256": sha256_hex(affinity_sql),
                "sql": affinity_sql,
            }],
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {
                    "manifest_prefix_length": 1,
                    "schema_objects": [{
                        "object_type": "table",
                        "name": "metrics",
                        "table_name": "metrics",
                        "sql_sha256": sha256_hex("CREATE TABLE metrics(value TEXT)"),
                    }],
                    "tables": [{
                        "name": "metrics",
                        "columns": [{
                            "cid": 0,
                            "name": "value",
                            "declared_type": "TEXT",
                            "not_null": false,
                            "default_value": null,
                            "primary_key_position": 0,
                            "hidden": 0,
                        }],
                        "foreign_keys": [],
                    }],
                    "seed_tables": [],
                },
            ],
        }),
    );
    let affinity_content = structured_content(&affinity_response);
    let mut expected_affinity = expected_d1_reconciliation_semantic_error(
        "d1.migration_reconciliation_seed_affinity_unstable",
        "a seed literal and reviewed SQLite table/column contract could reject or change its storage class or value",
        "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
    );
    expected_affinity["capability_state"] = json!("capability_gap");
    assert_eq!(affinity_content, &expected_affinity, "{affinity_content}");

    let strict_blob_sql = "CREATE TABLE StrictRows(value BLOB) STRICT; INSERT INTO strictrows (value) VALUES ('text');";
    let strict_blob_response = mcp.call_tool(
        763,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": [{
                "name": "0001.sql",
                "size_bytes": strict_blob_sql.len(),
                "sql_sha256": sha256_hex(strict_blob_sql),
                "sql": strict_blob_sql,
            }],
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_seed_rows_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {
                    "manifest_prefix_length": 1,
                    "schema_objects": [{
                        "object_type": "table",
                        "name": "StrictRows",
                        "table_name": "StrictRows",
                        "sql_sha256": sha256_hex("CREATE TABLE StrictRows(value BLOB) STRICT"),
                    }],
                    "tables": [{
                        "name": "StrictRows",
                        "columns": [{
                            "cid": 0,
                            "name": "value",
                            "declared_type": "BLOB",
                            "not_null": false,
                            "default_value": null,
                            "primary_key_position": 0,
                            "hidden": 0,
                        }],
                        "foreign_keys": [],
                    }],
                    "seed_tables": [],
                },
            ],
        }),
    );
    let strict_blob_content = structured_content(&strict_blob_response);
    assert_eq!(
        strict_blob_content, &expected_affinity,
        "{strict_blob_content}"
    );
    mcp.terminate();
}

#[test]
fn d1_additive_reconciliation_rejects_unsupported_and_drifted_state_before_custody() {
    let mut mcp = McpStdioProcess::start();
    for (index, (sql, code)) in [
        (
            "ALTER TABLE items RENAME TO other;",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE items DROP COLUMN status;",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE main.items ADD COLUMN status TEXT;",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "PRAGMA foreign_keys = OFF;",
            "d1.migration_reconciliation_pragma_effect_unavailable",
        ),
        (
            "PRAGMA journal_mode = WAL;",
            "d1.migration_reconciliation_pragma_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (EXISTS (SELECT 1));",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (other_column='x');",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (lower(state)='x');",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK ((state='x');",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (((((((state='x')))))));",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (state!='x');",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (state='x') REFERENCES parent(id);",
            "d1.migration_reconciliation_add_column_effect_unavailable",
        ),
        (
            "ALTER TABLE records ADD COLUMN state TEXT CHECK (state='x'); DELETE FROM records;",
            "d1.migration_reconciliation_effect_proof_unavailable",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let manifest = json!([{
            "name": "0001_create.sql",
            "size_bytes": sql.len(),
            "sql_sha256": sha256_hex(sql),
            "sql": sql,
        }]);
        let response = mcp.call_tool(
            840 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "manifest": manifest,
                "approved_plan_sha256": "a".repeat(64),
                "lease_nonce": "b".repeat(64),
                "lease_payload_sha256": "c".repeat(64),
                "effect_assertion_id": "schema_create_objects_additive_v1",
                "state_expectations": [
                    {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                    {"manifest_prefix_length": 1, "schema_objects": [], "tables": []},
                ],
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{content}");
        assert_eq!(content["custody_status"], json!("not_inspected"));
        assert_eq!(content["provider_calls"], json!(0));
        assert_eq!(content["provider_mutations"], json!(0));
        assert_eq!(content["error"]["code"], json!(code));
    }

    let (manifest, mut state_expectations, _) = additive_reconciliation_case();
    state_expectations[1]["tables"][0]["columns"] =
        state_expectations[0]["tables"][0]["columns"].clone();
    let missing_column = mcp.call_tool(
        860,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest.clone(),
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_v1",
            "state_expectations": state_expectations,
        }),
    );
    let missing_content = structured_content(&missing_column);
    assert_eq!(missing_content["ok"], json!(false));
    assert_eq!(missing_content["custody_status"], json!("not_inspected"));
    assert_eq!(missing_content["provider_calls"], json!(0));
    assert_eq!(
        missing_content["error"]["code"],
        json!("d1.migration_reconciliation_additive_column_drift")
    );

    let legacy = mcp.call_tool(
        861,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": manifest,
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_tables_indexes_views_triggers_v1",
            "state_expectations": [
                {"manifest_prefix_length": 0, "schema_objects": [], "tables": []},
                {"manifest_prefix_length": 1, "schema_objects": [], "tables": []},
            ],
        }),
    );
    let legacy_content = structured_content(&legacy);
    assert_eq!(legacy_content["ok"], json!(false));
    assert_eq!(legacy_content["provider_calls"], json!(0));
    assert_eq!(
        legacy_content["error"],
        json!({
            "code": "d1.migration_reconciliation_effect_proof_unavailable",
            "message": "the selected effect assertion cannot exactly prove this statement or any arbitrary top-level DML, ALTER, DROP, PRAGMA, virtual table, or data-producing CREATE effect",
            "hint": "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result."
        }),
        "the predecessor assertion response remains exact",
    );
    mcp.terminate();
}

#[test]
fn d1_reconciliation_reserves_the_migrations_table_before_custody() {
    let cases = vec![
        (
            "trigger-only ledger parent",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TRIGGER ledger_after_insert AFTER INSERT ON D1_MIGRATIONS BEGIN SELECT 1; END;",
            ],
        ),
        (
            "same entry alter then trigger",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "ALTER TABLE d1_migrations ADD COLUMN status TEXT; CREATE TRIGGER ledger_after_insert AFTER INSERT ON D1_MIGRATIONS BEGIN SELECT 1; END;",
            ],
        ),
        (
            "same entry trigger then alter",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TRIGGER ledger_after_insert AFTER INSERT ON d1_migrations BEGIN SELECT 1; END; ALTER TABLE D1_MIGRATIONS ADD COLUMN status TEXT;",
            ],
        ),
        (
            "cross entry alter then trigger",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "ALTER TABLE D1_MIGRATIONS ADD COLUMN status TEXT;",
                "CREATE TRIGGER ledger_after_insert AFTER INSERT ON d1_migrations BEGIN SELECT 1; END;",
            ],
        ),
        (
            "cross entry trigger then alter",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TRIGGER ledger_after_insert AFTER INSERT ON D1_MIGRATIONS BEGIN SELECT 1; END;",
                "ALTER TABLE d1_migrations ADD COLUMN status TEXT;",
            ],
        ),
        (
            "table identity case variant",
            "d1_migrations",
            "schema_create_only_v1",
            vec!["CREATE TABLE D1_MIGRATIONS(id INTEGER PRIMARY KEY);"],
        ),
        (
            "index parent case variant",
            "d1_migrations",
            "schema_create_only_v1",
            vec!["CREATE INDEX ledger_by_id ON D1_MiGrAtIoNs(id);"],
        ),
        (
            "index identity",
            "d1_migrations",
            "schema_create_only_v1",
            vec![
                "CREATE TABLE records(id INTEGER PRIMARY KEY); CREATE INDEX d1_migrations ON records(id);",
            ],
        ),
        (
            "view identity",
            "d1_migrations",
            "schema_create_tables_indexes_views_triggers_v1",
            vec!["CREATE VIEW D1_MIGRATIONS AS SELECT 1;"],
        ),
        (
            "trigger identity",
            "d1_migrations",
            "schema_create_tables_indexes_views_triggers_v1",
            vec!["CREATE TRIGGER d1_migrations AFTER INSERT ON records BEGIN SELECT 1; END;"],
        ),
        (
            "custom configured table case variant",
            "MigrationLedger",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TRIGGER custom_ledger_after_insert AFTER INSERT ON migrationledger BEGIN SELECT 1; END;",
            ],
        ),
        (
            "same entry trigger body delete",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_delete AFTER DELETE ON audit BEGIN DELETE FROM D1_MIGRATIONS; END;",
            ],
        ),
        (
            "same entry trigger body insert quoted",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_insert AFTER INSERT ON audit BEGIN INSERT INTO \"D1_MIGRATIONS\"(id) VALUES (NEW.id); END;",
            ],
        ),
        (
            "same entry trigger body update bracket quoted",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_update AFTER UPDATE ON audit BEGIN UPDATE [D1_MIGRATIONS] SET name = 'kept'; END;",
            ],
        ),
        (
            "same entry trigger body select from backtick quoted",
            "d1_migrations",
            "schema_create_tables_indexes_views_triggers_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_select AFTER INSERT ON audit BEGIN SELECT id FROM `D1_MIGRATIONS`; END;",
            ],
        ),
        (
            "same entry trigger body join case variant",
            "d1_migrations",
            "schema_create_tables_indexes_views_triggers_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_join AFTER INSERT ON audit BEGIN SELECT audit.id FROM audit JOIN D1_MiGrAtIoNs ON D1_MiGrAtIoNs.id = audit.id; END;",
            ],
        ),
        (
            "same entry trigger body qualified reference",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_qualified AFTER INSERT ON audit BEGIN SELECT D1_MIGRATIONS.id FROM audit; END;",
            ],
        ),
        (
            "trigger WHEN subquery reference",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_when_ledger AFTER INSERT ON audit WHEN EXISTS (SELECT 1 FROM D1_MIGRATIONS) BEGIN SELECT 1; END;",
            ],
        ),
        (
            "single-quoted DELETE target",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_delete_ledger AFTER INSERT ON audit BEGIN DELETE FROM 'D1_MIGRATIONS'; END;",
            ],
        ),
        (
            "keyword fallback with",
            "with",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_delete_with AFTER INSERT ON audit BEGIN DELETE FROM with; END;",
            ],
        ),
        (
            "keyword fallback recursive",
            "recursive",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_delete_recursive AFTER INSERT ON audit BEGIN DELETE FROM recursive; END;",
            ],
        ),
        (
            "keyword fallback replace",
            "replace",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_delete_replace AFTER INSERT ON audit BEGIN DELETE FROM replace; END;",
            ],
        ),
        (
            "cross entry trigger body reference",
            "d1_migrations",
            "schema_create_objects_additive_v1",
            vec![
                "CREATE TABLE audit(id INTEGER PRIMARY KEY);",
                "CREATE TRIGGER audit_after_cross_prefix AFTER INSERT ON audit BEGIN DELETE FROM d1_migrations; END;",
            ],
        ),
    ];
    let (base_url, requests) = spawn_fake_reconciliation_api_for_calls(0);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    for (index, (label, migrations_table, effect_assertion_id, statements)) in
        cases.into_iter().enumerate()
    {
        let manifest = Value::Array(
            statements
                .into_iter()
                .enumerate()
                .map(|(prefix, sql)| {
                    json!({
                        "name": format!("{:04}_reserved.sql", prefix + 1),
                        "size_bytes": sql.len(),
                        "sql_sha256": sha256_hex(sql),
                        "sql": sql,
                    })
                })
                .collect(),
        );
        let response = mcp.call_tool(
            862 + index as u64,
            "d1_reconcile_migration_manifest",
            json!({
                "database_id": "db-1",
                "migration_family": "newsletter-core",
                "migrations_table": migrations_table,
                "manifest": manifest,
                "approved_plan_sha256": "a".repeat(64),
                "lease_nonce": "b".repeat(64),
                "lease_payload_sha256": "c".repeat(64),
                "effect_assertion_id": effect_assertion_id,
                "state_expectations": [],
            }),
        );
        let content = structured_content(&response);
        let expected = expected_d1_reconciliation_semantic_error(
            "d1.migration_reconciliation_migrations_table_reserved",
            "the configured migrations table is reserved and cannot be created, indexed, used as a trigger parent, present as an exact trigger header/body token, named as another schema object, or altered by a reconciled manifest",
            "Retain the exact lease evidence. Do not retry the original migration attempt or mutate D1 from this result.",
        );
        assert_eq!(content, &expected, "{label}: {content}");
        assert_eq!(content["provider_calls"], json!(0), "{label}");
        assert_eq!(content["provider_mutations"], json!(0), "{label}");
        assert_eq!(content["local_namespace_mutations"], json!(0), "{label}");
    }
    assert_eq!(
        requests.lock().expect("reserved ledger request log").len(),
        0,
        "reserved ledger effects must stop before provider access",
    );

    let unrelated_sql = "CREATE TABLE d1_migrations_archive(id INTEGER PRIMARY KEY); CREATE TRIGGER archive_after_insert AFTER INSERT ON d1_migrations_archive WHEN 'd1_migrations_archive' IS NOT NULL BEGIN DELETE FROM d1_migrations_archive; END;";
    let unrelated = mcp.call_tool(
        899,
        "d1_reconcile_migration_manifest",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "migrations_table": "d1_migrations",
            "manifest": [{
                "name": "0001_unrelated.sql",
                "size_bytes": unrelated_sql.len(),
                "sql_sha256": sha256_hex(unrelated_sql),
                "sql": unrelated_sql,
            }],
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_v1",
            "state_expectations": [],
        }),
    );
    let unrelated_content = structured_content(&unrelated);
    assert_eq!(unrelated_content["ok"], json!(false), "{unrelated_content}");
    assert_eq!(
        unrelated_content["error"]["code"],
        json!("d1.migration_reconciliation_expectations_incomplete"),
        "longer unrelated trigger tokens must pass reservation and reach expectation validation",
    );
    assert_eq!(unrelated_content["provider_calls"], json!(0));
    assert_eq!(unrelated_content["provider_mutations"], json!(0));
    assert_eq!(unrelated_content["local_namespace_mutations"], json!(0));

    let terminal_sql = "CREATE TABLE audit(id INTEGER PRIMARY KEY); CREATE TRIGGER audit_after_insert AFTER INSERT ON audit BEGIN UPDATE D1_MIGRATIONS SET name = 'blocked'; END;";
    let terminal_manifest = json!([{
        "name": "0001_reserved.sql",
        "size_bytes": terminal_sql.len(),
        "sql_sha256": sha256_hex(terminal_sql),
        "sql": terminal_sql,
    }]);
    let terminal = mcp.call_tool(
        900,
        "d1_finalize_migration_reconciliation",
        json!({
            "database_id": "db-1",
            "migration_family": "newsletter-core",
            "manifest": terminal_manifest,
            "approved_plan_sha256": "a".repeat(64),
            "lease_nonce": "b".repeat(64),
            "lease_payload_sha256": "c".repeat(64),
            "effect_assertion_id": "schema_create_objects_additive_v1",
            "state_expectations": [],
            "expected_reconciliation_plan_sha256": "d".repeat(64),
            "expected_expectation_proof_sha256": "e".repeat(64),
            "expected_query_sha256": "f".repeat(64),
            "expected_canonical_snapshot_sha256": "1".repeat(64),
            "expected_outcome": "not_committed",
            "expected_original_prefix_length": 0,
            "expected_current_prefix_length": 0,
            "terminal_request_sha256": "2".repeat(64),
            "terminal_attempt_sha256": "3".repeat(64),
            "dry_run": true,
        }),
    );
    let terminal_content = structured_content(&terminal);
    assert_eq!(terminal_content["ok"], json!(false), "{terminal_content}");
    assert_eq!(
        terminal_content["error"]["code"],
        json!("d1.migration_reconciliation_migrations_table_reserved")
    );
    assert_eq!(terminal_content["custody_status"], json!("not_inspected"));
    assert_eq!(terminal_content["provider_calls"], json!(0));
    assert_eq!(terminal_content["provider_mutations"], json!(0));
    assert_eq!(terminal_content["local_namespace_mutations"], json!(0));
    assert_eq!(terminal_content["receipt_persisted"], json!(false));
    assert_eq!(
        requests.lock().expect("terminal reserved ledger log").len(),
        0,
        "terminal replay must reject the reserved ledger before provider access",
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
        (ReconciliationFault::SecondBatchPrimaryFalse, 3),
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
    let query_shape_receipt = content["query_shape_receipt"].clone();
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
            "query_shape_receipt": query_shape_receipt,
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
    let query_shape_receipt = content["query_shape_receipt"].clone();
    let evidence = content["response_evidence"]
        .as_array()
        .expect("selection and two chronological response summaries");
    assert_eq!(evidence.len(), 3, "{content}");
    assert_eq!(evidence[1], evidence[2], "{content}");
    let selection_summary = evidence[0].clone();
    let response_summary = evidence[1].clone();
    let selection_lifecycle = selection_summary["lifecycle"].clone();
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
            "query_shape_receipt": query_shape_receipt,
            "response_evidence": [selection_summary, response_summary.clone(), response_summary],
            "provider_read_lifecycle": [selection_lifecycle, lifecycle.clone(), lifecycle],
            "provider_calls": 3,
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
    assert_eq!(requests.lock().expect("request log").len(), 3);
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
            "d1.migration_reconciliation_selected_ledger_changed",
            "complete proof ledgers did not equal the exact initial selected ledger",
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
        let query_shape_receipt = content["query_shape_receipt"].clone();
        let selection_binding = content["selection_binding"].clone();
        let response_evidence = content["response_evidence"].clone();
        let evidence = response_evidence
            .as_array()
            .expect("selection and two chronological response summaries");
        assert_eq!(evidence.len(), 3, "{content}");
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
                "query_shape_receipt": query_shape_receipt,
                "selection_binding": selection_binding,
                "response_evidence": response_evidence,
                "provider_read_lifecycle": lifecycle,
                "provider_calls": 3,
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
        assert_eq!(requests.lock().expect("request log").len(), 3);
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
    assert_eq!(content["provider_calls"], json!(3), "{content}");
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
    assert_eq!(evidence.len(), 3, "{content}");
    assert_ne!(
        evidence[1]["response_body_sha256"], evidence[2]["response_body_sha256"],
        "{content}"
    );
    assert_eq!(
        evidence[2]["response_body_sha256"],
        json!(expected_second_sha256),
        "{content}"
    );
    assert_eq!(requests.lock().expect("request log").len(), 3);
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_reports_safe_allowlisted_second_error() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-safe-provider-error-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create safe-provider-error reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make safe-provider-error reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let private_message = "SQL SELECT * FROM private_table at /private/path";
    let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(
        ReconciliationFault::SecondBatchAllowlistedHttpError(
            400,
            7_500,
            private_message.to_string(),
        ),
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        1763,
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
    assert_eq!(content["provider_calls"], json!(3), "{content}");
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(
        content["provider_read_lifecycle"][0]["http_status"],
        json!(200)
    );
    assert_eq!(
        content["provider_read_lifecycle"][2]["http_status"],
        json!(400)
    );
    assert_eq!(
        content["provider_cause"]["provider_error_code"],
        json!(7_500)
    );
    assert_eq!(
        content["provider_cause"]["provider_error_category"],
        json!("d1_error")
    );
    let receipt = &content["query_shape_receipt"];
    assert_eq!(
        receipt["receipt_version"],
        json!("d1-reconciliation-query-shape-v1")
    );
    assert_eq!(receipt["query_sha256"], content["query_sha256"]);
    assert_eq!(receipt["statement_count"], json!(5));
    assert_eq!(
        receipt["statement_classes"],
        json!({
            "ledger": {"count": 1, "present": true},
            "schema_catalog": {"count": 1, "present": true},
            "table_xinfo": {"count": 1, "present": true},
            "foreign_key_definition": {"count": 1, "present": true},
            "foreign_key_check": {"count": 1, "present": true},
            "seed": {"count": 0, "present": false},
        })
    );
    assert_eq!(receipt["receipt_sha256"].as_str().map(str::len), Some(64));
    let serialized = serde_json::to_string(content).expect("serialize safe provider error");
    assert!(!serialized.contains(private_message));
    assert!(!serialized.contains("private_table"));
    assert!(!serialized.contains("/private/path"));
    assert_eq!(requests.lock().expect("request log").len(), 3);
    assert_private_regular_active_lease(&lease_root);
    mcp.terminate();
    let _ = fs::remove_dir_all(lease_root);
}

#[test]
fn d1_reconcile_migration_manifest_stdio_deep_error_is_generic_with_custody_retained() {
    let (manifest, expectations) = one_table_reconciliation_case();
    let lease_root = PathBuf::from("/tmp").join(format!(
        "cloudflare-mcp-reconcile-deep-provider-error-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&lease_root);
    fs::create_dir(&lease_root).expect("create deep-provider-error reconciliation root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lease_root, fs::Permissions::from_mode(0o700))
            .expect("make deep-provider-error reconciliation root private");
    }
    let (approved_plan_sha256, lease_nonce, lease_payload_sha256) =
        create_retained_reconciliation_fixture(&lease_root, &manifest);
    let private_message = "SQL SELECT * FROM private_table at /private/path";
    let (base_url, requests) = spawn_fake_reconciliation_api_with_fault(
        ReconciliationFault::SecondBatchDeepHttpError(400, private_message.to_string()),
    );
    let mut mcp = McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_API_BASE_URL", base_url),
        (
            "CLOUDFLARE_MCP_D1_MIGRATION_LEASE_ROOT",
            lease_root.to_string_lossy().to_string(),
        ),
    ]);
    let response = mcp.call_tool(
        1764,
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
    assert_eq!(content["provider_calls"], json!(3), "{content}");
    assert_eq!(content["provider_mutations"], json!(0), "{content}");
    assert_eq!(content["lease_retained"], json!(true), "{content}");
    assert_eq!(
        content["custody_status"],
        json!("retained_evidence_verified"),
        "{content}"
    );
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
            },
            {
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 400,
            }
        ]),
        "{content}"
    );
    assert_eq!(
        content["response_evidence"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(
        content["provider_cause"],
        json!({
            "code": "cloudflare.http_error",
            "operator_guidance": "reconciliation_only",
            "retryable": false,
            "status": 400,
        }),
        "{content}"
    );
    assert_eq!(
        content["query_shape_receipt"]["query_sha256"],
        content["query_sha256"]
    );
    let serialized = serde_json::to_string(content).expect("serialize deep provider error");
    assert!(!serialized.contains(private_message));
    assert!(!serialized.contains("private_table"));
    assert!(!serialized.contains("/private/path"));
    assert_eq!(requests.lock().expect("request log").len(), 3);
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
        let query_shape_receipt = content["query_shape_receipt"].clone();
        let selection = content["response_evidence"][0].clone();
        let first = content["response_evidence"][1].clone();
        assert_eq!(selection.as_object().map(|value| value.len()), Some(3));
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
            "query_shape_receipt": query_shape_receipt,
            "response_evidence": [selection.clone(), first.clone()],
            "provider_read_lifecycle": [
                selection["lifecycle"].clone(),
                first["lifecycle"].clone(),
                {
                    "dispatch_stage": "attempted",
                    "response_stage": "not_received",
                    "body_stage": "not_read",
                    "http_status": null,
                },
            ],
            "provider_calls": 3,
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
        assert_eq!(requests.lock().expect("request log").len(), 3);
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
        let query_shape_receipt = content["query_shape_receipt"].clone();
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
                "query_shape_receipt": query_shape_receipt,
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
        assert!(
            content["provider_cause"]
                .get("provider_error_code")
                .is_none(),
            "non-allowlisted or incomplete evidence must stay generic: {content}"
        );
        assert!(
            content["provider_cause"]
                .get("provider_error_category")
                .is_none(),
            "non-allowlisted or incomplete evidence must stay generic: {content}"
        );
        assert_eq!(
            content["query_shape_receipt"]["query_sha256"],
            content["query_sha256"]
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
        10,
        "same-name ledger evidence must neither release the lease nor apply the next statement after final authority revalidation"
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
        10,
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
                {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}},
                {"success": false, "errors": [], "results": []}
            ]),
            "inner_statement_failure_or_missing_success",
        ),
        (
            "inner error",
            json!([{"success": true, "errors": [{"code": 1}], "results": []}]),
            "inner_statement_error",
        ),
        (
            "missing mutation metadata",
            json!([{"success": true, "errors": [], "results": []}]),
            "missing_or_malformed_write_metadata",
        ),
        (
            "replica write metadata",
            json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": false, "changed_db": true, "changes": 1, "rows_written": 1}}]),
            "write_not_served_by_primary",
        ),
        (
            "unchanged write metadata",
            json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": false, "changes": 1, "rows_written": 1}}]),
            "write_metadata_contradictory",
        ),
        (
            "mixed contradictory non-mutating metadata",
            json!([
                {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": false, "changes": 1, "rows_written": 1}},
                {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 0, "rows_written": 0}}
            ]),
            "write_metadata_contradictory",
        ),
        (
            "empty mutation metadata",
            json!([{"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 0, "rows_written": 0}}]),
            "write_metadata_did_not_prove_mutation",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let expected_write_response = serde_json::to_vec(&json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": write_result.clone(),
        }))
        .expect("serialize expected ambiguous write response");
        let expected_write_response_sha256 = sha256_hex(&String::from_utf8(
            expected_write_response.clone(),
        )
        .expect("expected ambiguous write response is UTF-8"));
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
        assert_eq!(
            content["error"]["cause"]["provider_write_lifecycle"],
            json!({
                "dispatch_stage": "attempted",
                "response_stage": "received",
                "body_stage": "completely_read",
                "http_status": 200,
            }),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["response_body_sha256"],
            json!(expected_write_response_sha256),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["response_body_size_bytes"],
            json!(expected_write_response.len()),
            "{label}"
        );
        assert_eq!(
            content["error"]["cause"]["retryable"],
            json!(false),
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
        assert_eq!(observed.len(), 10, "{label} must not retry the write");
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
            10,
            label,
        );
        let _ = fs::remove_dir_all(lease_root);
    }
}

#[test]
fn d1_apply_migration_manifest_multiple_successful_query_results_apply_once() {
    let (base_url, requests) = spawn_fake_manifest_ambiguous_result_api(json!([
        {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": false, "changes": 0, "rows_written": 0}},
        {"success": true, "errors": [], "results": [], "meta": {"served_by_primary": true, "changed_db": true, "changes": 1, "rows_written": 1}}
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
    assert_eq!(requests.lock().expect("requests lock").len(), 12);
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
        13,
        "per-mutation ledger-authority proofs plus the second statement ambiguity must stop the batch without any retry"
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
        13,
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
fn workers_upload_version_dry_run_is_strict_digest_bound_and_provider_free() {
    let (base_url, requests) = spawn_fake_worker_upload_api(0);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "workers_upload_version",
        json!({
            "script_name":"worker-a",
            "base_version_id":"11111111-1111-4111-8111-111111111111",
            "base_version_etag":"a".repeat(64),
            "pre_upload_version_snapshot_sha256":"b".repeat(64),
            "pre_upload_deployment_snapshot_sha256":"c".repeat(64),
            "bindings_inherit":"strict",
            "main_module":"index.js",
            "script_content":"export default { fetch() { return new Response('ok') } }",
            "metadata":{
                "main_module":"index.js",
                "compatibility_date":"2026-07-10",
                "bindings":[
                    {"name":"SECRET","type":"inherit","version_id":"11111111-1111-4111-8111-111111111111"},
                    {"name":"MODE","type":"plain_text","text":"private-fixture-value"}
                ]
            },
            "dry_run":true,
            "reason":"stdio guarded version regression"
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(true), "{content}");
    assert_eq!(content["planned"], json!(true));
    assert_eq!(
        content["request_query"]["bindings_inherit"],
        json!("strict")
    );
    assert_eq!(content["deployment_created"], json!(false));
    assert!(content["required_confirmation_token"].is_string());
    assert!(content["upload"]["body_sha256"].is_string());
    assert!(content["upload"]["metadata_sha256"].is_string());
    assert!(content["upload"]["upload_contract_sha256"].is_string());
    let outward = content.to_string();
    assert!(!outward.contains("private-fixture-value"));
    assert!(!outward.contains("script_content"));
    assert!(requests.lock().expect("request log lock").is_empty());
}

#[test]
fn workers_upload_version_rejects_non_strict_inheritance_before_provider_access() {
    let (base_url, requests) = spawn_fake_worker_upload_api(0);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let response = mcp.call_tool(
        2,
        "workers_upload_version",
        json!({
            "script_name":"worker-a",
            "base_version_id":"11111111-1111-4111-8111-111111111111",
            "base_version_etag":"a".repeat(64),
            "pre_upload_version_snapshot_sha256":"b".repeat(64),
            "pre_upload_deployment_snapshot_sha256":"c".repeat(64),
            "bindings_inherit":"best_effort",
            "script_content":"export default {}",
            "metadata":{"main_module":"index.js"},
            "dry_run":true
        }),
    );
    let content = structured_content(&response);
    assert_eq!(content["ok"], json!(false), "{content}");
    assert_eq!(
        content["error"]["code"],
        json!("workers.version_upload_strict_inheritance_required")
    );
    assert!(requests.lock().expect("request log lock").is_empty());
}

#[test]
fn workers_upload_version_stdio_applies_once_and_proves_disabled_candidate() {
    let (base_url, requests) = spawn_fake_worker_version_api(16);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", base_url)]);
    let base_id = "11111111-1111-4111-8111-111111111111";
    let candidate_id = "22222222-2222-4222-8222-222222222222";

    let preflight = mcp.call_tool(
        2,
        "workers_capture_version_evidence",
        json!({
            "script_name":"worker-a",
            "per_page":100,
            "version_id":base_id
        }),
    );
    let preflight_content = structured_content(&preflight);
    assert_eq!(preflight_content["ok"], json!(true), "{preflight_content}");
    let version_snapshot_sha256 =
        preflight_content["evidence"]["versions"]["semantic_snapshot_sha256"]
            .as_str()
            .expect("version snapshot pin")
            .to_string();
    let deployment_snapshot_sha256 =
        preflight_content["evidence"]["deployments"]["semantic_snapshot_sha256"]
            .as_str()
            .expect("deployment snapshot pin")
            .to_string();

    let upload_args = json!({
        "script_name":"worker-a",
        "base_version_id":base_id,
        "base_version_etag":"a".repeat(64),
        "pre_upload_version_snapshot_sha256":version_snapshot_sha256,
        "pre_upload_deployment_snapshot_sha256":deployment_snapshot_sha256,
        "bindings_inherit":"strict",
        "main_module":"index.js",
        "script_content":"export default { fetch() { return new Response('ok') } }",
        "metadata":{
            "main_module":"index.js",
            "compatibility_date":"2026-07-10",
            "bindings":[
                {"name":"SECRET","type":"inherit","version_id":base_id},
                {"name":"MODE","type":"plain_text","text":"private-fixture-value"}
            ]
        },
        "per_page":100,
        "dry_run":true,
        "reason":"stdio guarded version apply regression"
    });
    let dry_run = mcp.call_tool(3, "workers_upload_version", upload_args.clone());
    let dry_run_content = structured_content(&dry_run);
    assert_eq!(dry_run_content["ok"], json!(true), "{dry_run_content}");
    assert_eq!(dry_run_content["planned"], json!(true));
    assert_eq!(requests.lock().expect("request log lock").len(), 5);

    let mut apply_args = upload_args;
    apply_args["dry_run"] = json!(false);
    apply_args["confirmation_token"] = dry_run_content["required_confirmation_token"].clone();
    let apply = mcp.call_tool(4, "workers_upload_version", apply_args);
    let apply_content = structured_content(&apply);
    assert_eq!(apply_content["ok"], json!(true), "{apply_content}");
    assert_eq!(apply_content["status"], json!("applied_proven"));
    assert_eq!(
        apply_content["upload_result"]["candidate_version_id"],
        json!(candidate_id)
    );
    assert_eq!(
        apply_content["post_upload_state"]["deployments"]["candidate_absent"],
        json!(true)
    );
    assert_eq!(apply_content["deployment_created"], json!(false));
    assert_eq!(apply_content["provider_mutation_dispatched"], json!(true));
    let outward = apply_content.to_string();
    assert!(!outward.contains("private-fixture-value"));
    assert!(!outward.contains("never-surface"));

    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 16);
    let posts = requests
        .iter()
        .filter(|request| request["method"] == json!("POST"))
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 1, "{requests:?}");
    assert!(
        posts[0]["path"]
            .as_str()
            .unwrap_or_default()
            .contains("/versions?bindings_inherit=strict")
    );
    assert!(
        requests
            .iter()
            .all(|request| request["authorization_present"] == json!(true))
    );
    assert!(!requests.iter().any(|request| {
        request["method"] == json!("POST")
            && request["path"]
                .as_str()
                .unwrap_or_default()
                .contains("/deployments")
    }));
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
            "operation_id": "d1-create-database",
            "path_params": {
                "account_id": "acct-1"
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
fn api_mutate_denies_existing_target_d1_schema_mutations_before_request_construction() {
    let provider = TcpListener::bind("127.0.0.1:0").expect("bind no-call D1 provider witness");
    provider
        .set_nonblocking(true)
        .expect("make D1 provider witness nonblocking");
    let provider_url = format!(
        "http://{}",
        provider.local_addr().expect("D1 provider witness address")
    );
    let mut mcp =
        McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", provider_url)]);

    for (index, operation_id) in [
        "d1-query-database",
        "d1-raw-database-query",
        "d1-import-database",
        "d1-time-travel-restore",
    ]
    .into_iter()
    .enumerate()
    {
        let mutation_payload_marker =
            format!("CREATE TABLE forbidden_{index}(id INTEGER PRIMARY KEY)");
        let response = mcp.call_tool(
            20 + index as u64,
            "api_mutate",
            json!({
                "operation_id": operation_id,
                "path_params": {
                    "account_id": "acct-1",
                    "database_id": "db-1"
                },
                "body": {"sql": mutation_payload_marker},
                "dry_run": false,
                "confirmation_token": "untrusted-raw-d1-confirmation",
                "reason": "negative policy proof"
            }),
        );
        let content = structured_content(&response);
        assert_eq!(content["ok"], json!(false), "{operation_id}: {content}");
        assert_eq!(
            content["error"]["code"],
            json!("api_catalog.denied_by_default"),
            "{operation_id}: {content}"
        );
        assert_eq!(
            content["api_operation"]["operation_id"],
            json!(operation_id)
        );
        assert_eq!(content["api_operation"]["risk"], json!("denied_by_default"));
        let expected_preferred_tool = match operation_id {
            "d1-query-database" | "d1-raw-database-query" => Some("d1_query_read_only"),
            "d1-import-database" | "d1-time-travel-restore" => None,
            _ => unreachable!(),
        };
        assert_eq!(content["preferred_tool"], json!(expected_preferred_tool));
        if expected_preferred_tool.is_none() {
            assert_eq!(
                content["error"]["hint"],
                json!(
                    "Use a governed curated lifecycle for this operation; generic api_mutate remains denied."
                )
            );
        }
        assert_eq!(content["request_constructed"], json!(false));
        assert_eq!(content["raw_body_dispatched"], json!(false));
        assert_eq!(content["provider_calls"], json!(0));
        assert_eq!(content["provider_mutations"], json!(0));
        assert!(content.get("request_plan").is_none(), "{content}");
        assert!(
            !content.to_string().contains(&mutation_payload_marker),
            "the denied mutation body must not be reflected or dispatched: {content}"
        );
    }

    let discovery = mcp.call_tool(
        24,
        "find_tools",
        json!({"group": "d1", "limit": 100, "include_schema": true}),
    );
    let discovery = structured_content(&discovery);
    let curated_names = discovery["results"]
        .as_array()
        .expect("curated D1 discovery results")
        .iter()
        .filter_map(|result| result["name"].as_str())
        .collect::<Vec<_>>();
    for expected in [
        "d1_query_read_only",
        "d1_execute_write",
        "d1_bootstrap_migration_ledger",
        "d1_apply_migration_manifest",
        "d1_reconcile_migration_manifest",
        "d1_finalize_migration_reconciliation",
        "d1_reconcile_bootstrap_migration_ledger",
        "d1_finalize_bootstrap_migration_ledger",
        "d1_abort_bootstrap_migration_ledger",
    ] {
        assert!(
            curated_names.contains(&expected),
            "curated D1 tool {expected} remains discoverable: {discovery}"
        );
        assert!(
            discovery["schemas"][expected].is_object(),
            "curated D1 tool {expected} remains loadable: {discovery}"
        );
    }

    let curated_read = mcp.call_tool(
        25,
        "d1_query_read_only",
        json!({
            "account_id": "acct-1",
            "database_id": "db-1",
            "sql": "CREATE TABLE curated_read_guard(id INTEGER PRIMARY KEY)"
        }),
    );
    assert_eq!(
        structured_content(&curated_read)["error"]["code"],
        json!("d1.sql_policy_denied"),
        "curated read tool remains callable and guarded"
    );
    let curated_write = mcp.call_tool(
        26,
        "d1_execute_write",
        json!({
            "account_id": "acct-1",
            "database_id": "db-1",
            "sql": "CREATE TABLE curated_write_guard(id INTEGER PRIMARY KEY)",
            "dry_run": true
        }),
    );
    assert_eq!(
        structured_content(&curated_write)["error"]["code"],
        json!("d1.write_policy_denied"),
        "curated write tool remains callable and guarded"
    );

    assert!(
        matches!(provider.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "denied existing-target D1 operations and curated policy checks make zero provider connections"
    );
    mcp.terminate();
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
                "operation_id": "d1-create-database",
                "path_params": {
                    "account_id": "acct-1"
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
