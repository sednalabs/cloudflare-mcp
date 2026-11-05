use super::*;

#[test]
fn pages_deployment_pagination_rejects_invalid_values_without_provider_calls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // DevSkim: ignore DS162092 -- loopback-only zero-call fixture
    listener.set_nonblocking(true).unwrap();
    let mut mcp = McpStdioProcess::start_with_env(vec![(
        "CLOUDFLARE_MCP_API_BASE_URL",
        format!("http://{}", listener.local_addr().unwrap()), // DevSkim: ignore DS137138 -- loopback-only fixture
    )]);
    for (index, pagination) in [
        json!({"page": 0}),
        json!({"per_page": 0}),
        json!({"per_page": 26}),
        json!({"per_page": 30}),
        json!({"per_page": 50}),
        json!({"per_page": 100}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = json!({"project_name": "site"});
        args.as_object_mut()
            .unwrap()
            .extend(pagination.as_object().unwrap().clone());
        let response = mcp.call_tool(index as u64 + 2, "pages_list_deployments", args);
        let content = structured_content(&response);
        assert_eq!(content["ok"], false, "{content}");
        assert_eq!(
            content["error"]["code"], "cloudflare.pages.pagination_invalid",
            "{content}"
        );
        assert!(
            content["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("one page")
        );
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn pages_deployment_pagination_defaults_and_provider_errors_through_stdio() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // DevSkim: ignore DS162092 -- loopback-only fixture
    let endpoint = format!("http://{}", listener.local_addr().unwrap()); // DevSkim: ignore DS137138 -- loopback-only fixture
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let server = thread::spawn(move || {
        for index in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let (headers, body) = read_http_request(&mut stream);
            assert!(body.is_empty());
            let request = headers.lines().next().unwrap().to_string();
            recorded.lock().unwrap().push(request);
            let rejected = index == 4;
            let response = if rejected {
                json!({"success":false,"result":null,"messages":[],"errors":[{"code":8000024,"message":"Invalid list options"}]})
            } else {
                json!({
                    "success":true,"errors":[],"messages":[],
                    "result":[{"id":"deployment-1","project_name":"site","environment":"production"}],
                    "result_info":{"page":2,"per_page":25,"count":1,"total_count":26,"total_pages":2}
                })
            };
            let response = serde_json::to_vec(&response).unwrap();
            let status = if rejected {
                "400 Bad Request"
            } else {
                "200 OK"
            };
            write!(stream,"HTTP/1.1 {status}\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",response.len()).unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
    for (index, pagination) in [
        json!({}),
        json!({"page":null,"per_page":null}),
        json!({"page":2,"per_page":1}),
        json!({"page":2,"per_page":25,"environment":"production"}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = json!({"project_name":"site"});
        args.as_object_mut()
            .unwrap()
            .extend(pagination.as_object().unwrap().clone());
        let response = mcp.call_tool(index as u64 + 2, "pages_list_deployments", args);
        let content = structured_content(&response);
        assert_eq!(content["ok"], true, "{content}");
        assert_eq!(content["page"]["items"][0]["id"], "deployment-1");
        // Preserve provider metadata; do not present the returned page as all deployments.
        assert_eq!(
            content["page"]["page_info"],
            json!({"page":2,"per_page":25,"count":1,"total_count":26,"total_pages":2})
        );
    }
    let rejected = mcp.call_tool(
        10,
        "pages_list_deployments",
        json!({"project_name":"site","page":99}),
    );
    let rejected = structured_content(&rejected);
    assert_eq!(rejected["ok"], false);
    assert_eq!(rejected["error"]["status"], 400);
    server.join().unwrap();
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        [
            "GET /accounts/acct-1/pages/projects/site/deployments?page=1&per_page=25 HTTP/1.1",
            "GET /accounts/acct-1/pages/projects/site/deployments?page=1&per_page=25 HTTP/1.1",
            "GET /accounts/acct-1/pages/projects/site/deployments?page=2&per_page=1 HTTP/1.1",
            "GET /accounts/acct-1/pages/projects/site/deployments?page=2&per_page=25&env=production HTTP/1.1",
            "GET /accounts/acct-1/pages/projects/site/deployments?page=99&per_page=25 HTTP/1.1",
        ]
    );
}
