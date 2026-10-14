use super::*;
use hmac::{Hmac, Mac};

type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

fn fixture(responses: Vec<String>) -> (String, Requests, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // DevSkim: ignore DS162092 -- ephemeral loopback-only fixture
    let endpoint = format!("http://{}", listener.local_addr().unwrap()); // DevSkim: ignore DS137138 -- loopback-only fixture
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let handle = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let request = read_http_request(&mut stream);
            log.lock().unwrap().push(request);
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (endpoint, requests, handle)
}

fn start(endpoint: String) -> McpStdioProcess {
    McpStdioProcess::start_with_env(vec![
        ("CLOUDFLARE_MCP_R2_ENDPOINT", endpoint),
        ("CLOUDFLARE_MCP_R2_ACCESS_KEY_ID", fixture_material("r2-id")),
        (
            "CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY",
            fixture_material("r2-material"),
        ),
    ])
}

fn request_args() -> Value {
    json!({"bucket_name":"bucket-a", "object_key":"folder/file.txt", "content_text":"candidate", "content_type":"text/plain", "metadata":{"revision":"v2"}, "if_none_match":"*", "dry_run":true})
}

fn preview_apply(mcp: &mut McpStdioProcess, mut args: Value) -> Value {
    let preview = structured_content(&mcp.call_tool(2, "r2_put_object", args.clone())).clone();
    assert_eq!(preview["publication_state"], "previewed", "{preview}");
    assert_eq!(preview["payload_sha256"], sha256_hex("candidate"));
    args["dry_run"] = json!(false);
    args["expected_request_sha256"] = preview["request_sha256"].clone();
    structured_content(&mcp.call_tool(3, "r2_put_object", args)).clone()
}

fn header<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .unwrap()
}

fn hmac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(bytes);
    mac.finalize().into_bytes().to_vec()
}

/// Independent verifier reconstructs SigV4 from the actual transmitted bytes,
/// not the adapter's request-planning helpers.
fn verify_signature(headers: &str, body: &[u8], condition: Option<(&str, &str)>) {
    assert_eq!(
        headers.lines().next(),
        Some("PUT /bucket-a/folder/file.txt HTTP/1.1")
    );
    assert_eq!(header(headers, "content-type"), "text/plain");
    assert_eq!(header(headers, "x-amz-meta-revision"), "v2");
    let authorization = header(headers, "authorization");
    let signed = authorization
        .split("SignedHeaders=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap();
    let hash = format!("{:x}", Sha256::digest(body));
    assert_eq!(header(headers, "x-amz-content-sha256"), hash);
    if let Some((name, value)) = condition {
        assert_eq!(header(headers, name), value);
        assert!(signed.split(';').any(|key| key == name));
    } else {
        assert!(!signed.contains("if-match") && !signed.contains("if-none-match"));
    }
    let canonical_headers = signed
        .split(';')
        .map(|name| format!("{name}:{}\n", header(headers, name)))
        .collect::<String>();
    let request =
        format!("PUT\n/bucket-a/folder/file.txt\n\n{canonical_headers}\n{signed}\n{hash}");
    let date = header(headers, "x-amz-date");
    let scope = format!("{}/auto/s3/aws4_request", &date[..8]);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        sha256_hex(&request)
    );
    let key = hmac(
        format!("AWS4{}", fixture_material("r2-material")).as_bytes(),
        date[..8].as_bytes(),
    );
    let key = hmac(&key, b"auto");
    let key = hmac(&key, b"s3");
    let key = hmac(&key, b"aws4_request");
    let signature = hmac(&key, string_to_sign.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(authorization.ends_with(&format!("Signature={signature}")));
}

#[test]
fn r2_conditional_preview_denials_have_zero_provider_calls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // DevSkim: ignore DS162092 -- ephemeral loopback-only zero-call fixture
    listener.set_nonblocking(true).unwrap();
    let mut mcp = start(format!("http://{}", listener.local_addr().unwrap())); // DevSkim: ignore DS137138 -- loopback-only fixture
    let args = request_args();
    let preview = structured_content(&mcp.call_tool(2, "r2_put_object", args.clone())).clone();
    assert_eq!(preview["condition"], json!({"mode":"create_only"}));
    assert_eq!(
        preview["plan"]["steps"][0]["target"]["payload_sha256"],
        sha256_hex("candidate")
    );
    let mut id = 3;
    for (field, value) in [
        ("bucket_name", " bucket-a"),
        ("object_key", "folder/../file.txt"),
        ("bucket_name", "bucket/a"),
        ("bucket_name", "."),
        ("bucket_name", ".."),
    ] {
        let mut candidate = args.clone();
        candidate[field] = json!(value);
        let rejected = structured_content(&mcp.call_tool(id, "r2_put_object", candidate)).clone();
        assert_eq!(rejected["error"]["code"], "r2.invalid_target");
        id += 1;
    }
    for invalid in [
        json!({"if_match":"*"}),
        json!({"if_match":"W/\"v1\""}),
        json!({"if_match":"\"v1\",\"v2\""}),
        json!({"if_match":"\"v1\r\n\""}),
        json!({"if_none_match":"not-star"}),
        json!({"if_match":"\"v1\"", "if_none_match":"*"}),
    ] {
        let mut candidate = args.clone();
        candidate.as_object_mut().unwrap().remove("if_none_match");
        candidate
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        let rejected = structured_content(&mcp.call_tool(id, "r2_put_object", candidate)).clone();
        assert_eq!(rejected["error"]["code"], "r2.invalid_condition");
        id += 1;
    }
    for (field, value) in [
        ("content_text", json!("changed")),
        ("if_none_match", Value::Null),
        ("object_key", json!("different")),
        ("metadata", json!({"revision":"v3"})),
        ("content_type", json!("application/json")),
    ] {
        let mut candidate = args.clone();
        candidate["dry_run"] = json!(false);
        candidate["expected_request_sha256"] = preview["request_sha256"].clone();
        candidate[field] = value;
        let rejected = structured_content(&mcp.call_tool(id, "r2_put_object", candidate)).clone();
        assert_eq!(rejected["error"]["code"], "r2.preview_mismatch");
        id += 1;
    }
    let mut candidate = args.clone();
    candidate["dry_run"] = json!(false);
    let rejected = structured_content(&mcp.call_tool(id, "r2_put_object", candidate)).clone();
    assert_eq!(rejected["error"]["code"], "r2.preview_mismatch");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn r2_conditional_put_signs_exact_headers_and_preserves_unconditional_mode() {
    for condition in [
        Some(("if_none_match", "*")),
        Some(("if_match", "\"v1\"")),
        None,
    ] {
        let (endpoint, requests, handle) = fixture(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"v2\"\r\nConnection: close\r\n\r\n"
                .to_string(),
        ]);
        let mut mcp = start(endpoint);
        let mut args = request_args();
        args.as_object_mut().unwrap().remove("if_none_match");
        if let Some((name, value)) = condition {
            args[name] = json!(value);
        }
        let result = preview_apply(&mut mcp, args);
        assert_eq!(result["ok"], true);
        assert_eq!(result["publication_state"], "submitted");
        assert_eq!(result["readback_required"], true);
        handle.join().unwrap();
        let log = requests.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].1, b"candidate");
        verify_signature(
            &log[0].0,
            &log[0].1,
            condition.map(|(name, value)| {
                (
                    if name == "if_match" {
                        "if-match"
                    } else {
                        "if-none-match"
                    },
                    value,
                )
            }),
        );
    }
}

#[test]
fn r2_put_conflict_and_uncertain_results_never_authorize_retry() {
    for (response, state, code) in [
        (
            "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 50\r\nConnection: close\r\n\r\n",
            "not_applied",
            "cloudflare.r2_precondition_failed",
        ),
        (
            "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "reconcile_only",
            "cloudflare.r2_put_uncertain",
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 50\r\nConnection: close\r\n\r\nx",
            "reconcile_only",
            "cloudflare.r2_put_uncertain",
        ),
        ("", "reconcile_only", "cloudflare.r2_put_uncertain"),
    ] {
        let (endpoint, requests, handle) = fixture(vec![response.to_string()]);
        let result = preview_apply(&mut start(endpoint), request_args());
        assert_eq!(result["ok"], false, "{result}");
        assert_eq!(result["publication_state"], state);
        assert_eq!(result["error"]["code"], code);
        assert_eq!(result["error"]["retryable"], false);
        handle.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn r2_signed_requests_do_not_follow_redirects() {
    for method in ["PUT", "GET"] {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap(); // DevSkim: ignore DS162092 -- loopback-only never-follow destination
        destination.set_nonblocking(true).unwrap();
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", // DevSkim: ignore DS137138 -- loopback-only never-follow response
            destination.local_addr().unwrap()
        ); // DevSkim: ignore DS137138 -- loopback-only fixture
        let (endpoint, _, handle) = fixture(vec![response]);
        let mut mcp = start(endpoint);
        let result = if method == "PUT" {
            preview_apply(&mut mcp, request_args())
        } else {
            structured_content(&mcp.call_tool(
                2,
                "r2_get_object",
                json!({"bucket_name":"bucket-a", "object_key":"folder/file.txt"}),
            ))
            .clone()
        };
        assert_eq!(result["ok"], false);
        handle.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn r2_get_authority_uses_actual_complete_get_not_head_etag() {
    for (status, range, etag, cap, complete, authority) in [
        (200, "", "\"get-v2\"", 100, true, true),
        (
            206,
            "Content-Range: bytes 0-2/9\r\n",
            "\"get-v2\"",
            100,
            false,
            false,
        ),
        (200, "", "\"get-v2\"", 2, false, false),
        (200, "", "W/\"get-v2\"", 100, true, false),
        (200, "", "invalid", 100, true, false),
        (200, "", "", 100, true, false),
    ] {
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/plain\r\nETag: \"head-v1\"\r\nConnection: close\r\n\r\n".to_string();
        let get = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: 3\r\nContent-Type: text/plain\r\n{range}ETag: {etag}\r\nConnection: close\r\n\r\nabc"
        );
        let (endpoint, _, handle) = fixture(vec![head, get]);
        let result = structured_content(&start(endpoint).call_tool(2, "r2_get_object", json!({"bucket_name":"bucket-a", "object_key":"folder/file.txt", "response_mode":"text", "max_bytes":cap}))).clone();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["complete"], complete);
        assert_eq!(
            result["strong_etag"],
            if authority { json!(etag) } else { Value::Null }
        );
        assert_eq!(
            result["sha256"],
            sha256_hex(if cap == 2 { "ab" } else { "abc" })
        );
        handle.join().unwrap();
    }
}

#[test]
fn r2_create_read_correct_conflict_and_readback_join_in_one_stdio_process() {
    fn response(method: &str, body: &str, etag: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nETag: {etag}\r\nConnection: close\r\n\r\n{}",
            if method == "PUT" { 0 } else { body.len() },
            if method == "GET" { body } else { "" }
        )
    }
    let (endpoint, requests, handle) = fixture(vec![
        response("PUT", "", "\"v1\""),
        response("HEAD", "candidate", "\"v1\""),
        response("GET", "candidate", "\"v1\""),
        response("PUT", "", "\"v2\""),
        response("HEAD", "correction", "\"v2\""),
        response("GET", "correction", "\"v2\""),
        "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string(),
        response("HEAD", "correction", "\"v2\""),
        response("GET", "correction", "\"v2\""),
    ]);
    let mut mcp = start(endpoint);
    let created = preview_apply(&mut mcp, request_args());
    assert_eq!(created["publication_state"], "submitted");
    let get_args = json!({"bucket_name":"bucket-a", "object_key":"folder/file.txt", "response_mode":"text", "max_bytes":100});
    let initial = structured_content(&mcp.call_tool(4, "r2_get_object", get_args.clone())).clone();
    assert_eq!(initial["complete"], true);
    assert_eq!(initial["sha256"], created["payload_sha256"]);
    let mut update = request_args();
    update.as_object_mut().unwrap().remove("if_none_match");
    update["if_match"] = initial["strong_etag"].clone();
    update["content_text"] = json!("correction");
    let preview = structured_content(&mcp.call_tool(5, "r2_put_object", update.clone())).clone();
    update["dry_run"] = json!(false);
    update["expected_request_sha256"] = preview["request_sha256"].clone();
    let corrected = structured_content(&mcp.call_tool(6, "r2_put_object", update.clone())).clone();
    assert_eq!(corrected["publication_state"], "submitted");
    let current = structured_content(&mcp.call_tool(7, "r2_get_object", get_args.clone())).clone();
    assert_eq!(current["complete"], true);
    assert_eq!(current["sha256"], corrected["payload_sha256"]);
    assert_eq!(current["strong_etag"], "\"v2\"");
    let conflict = structured_content(&mcp.call_tool(8, "r2_put_object", update)).clone();
    assert_eq!(conflict["publication_state"], "not_applied");
    let unchanged = structured_content(&mcp.call_tool(9, "r2_get_object", get_args)).clone();
    assert_eq!(unchanged["content"], current["content"]);
    assert_eq!(unchanged["strong_etag"], current["strong_etag"]);
    handle.join().unwrap();
    let log = requests.lock().unwrap();
    assert_eq!(log.len(), 9);
    verify_signature(&log[0].0, &log[0].1, Some(("if-none-match", "*")));
    verify_signature(&log[3].0, &log[3].1, Some(("if-match", "\"v1\"")));
    assert_eq!(log[3].1, b"correction");
}
