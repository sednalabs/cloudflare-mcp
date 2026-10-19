use super::*;

type Requests = Arc<Mutex<Vec<(String, Value)>>>;

#[derive(Clone, Copy)]
enum Fault {
    None,
    Reject,
    Unavailable,
    Malformed,
    Expression,
    Order,
    Membership,
    Configuration,
    Identity,
}

fn writable_rules() -> Value {
    json!([
        {"id":"rule-a","ref":"first","action":"block","description":"First rule","expression":"http.request.uri.path eq \"/a\"","enabled":true},
        {"id":"rule-b","ref":"second","action":"execute","description":"Managed configuration","expression":"true","enabled":true,"action_parameters":{"id":"managed-ruleset","version":"latest","overrides":{"rules":[{"id":"managed-rule","enabled":false}]}}},
        {"id":"rule-c","ref":"third","action":"block","expression":"http.request.uri.path eq \"/c\"","enabled":true,"ratelimit":{"characteristics":["ip.src"],"period":60,"requests_per_period":20,"mitigation_timeout":60,"counting_expression":"http.request.method eq \"POST\""}},
        {"id":"rule-d","ref":"fourth","action":"skip","expression":"http.request.uri.path eq \"/d\"","enabled":false,"action_parameters":{"ruleset":"current"},"logging":{"enabled":true}},
        {"id":"rule-e","ref":"fifth","action":"log","description":"Last rule","expression":"http.request.uri.path eq \"/e\"","enabled":true}
    ])
}

fn ruleset() -> Value {
    let mut rules = writable_rules();
    for rule in rules.as_array_mut().unwrap() {
        rule["version"] = json!("3");
        rule["last_updated"] = json!("2026-01-01T00:00:00Z");
        rule["categories"] = json!([]);
    }
    json!({"id":"ruleset-a","name":"Example ruleset","description":"Example configuration","kind":"zone","phase":"http_request_firewall_custom","version":"7","last_updated":"2026-01-01T00:00:00Z","rules":rules})
}

fn args() -> Value {
    json!({"scope":"zone","phase":"custom","max_rules":5,"edits":[{"operation":"update","rule_id":"rule-a","rule_ref":"first","description":"Reviewed first rule","expression":"http.request.uri.path eq \"/reviewed\"","rule_action":"managed_challenge","enabled":true}]})
}

// This provider validates the transmitted request independently of the adapter's
// projector. In particular, it rejects top-level id and nested response metadata
// but accepts rule IDs and action_parameters.* IDs, as the provider API does.
fn strict_body(body: &Value) -> bool {
    body.as_object().is_some_and(|body| {
        body.keys()
            .all(|key| ["description", "rules"].contains(&key.as_str()))
            && body
                .get("rules")
                .and_then(Value::as_array)
                .is_some_and(|rules| {
                    rules.iter().all(|rule| {
                        rule.as_object().is_some_and(|rule| {
                            rule.keys().all(|key| {
                                [
                                    "id",
                                    "ref",
                                    "action",
                                    "description",
                                    "expression",
                                    "enabled",
                                    "action_parameters",
                                    "ratelimit",
                                    "logging",
                                    "exposed_credential_check",
                                ]
                                .contains(&key.as_str())
                            })
                        })
                    })
                })
    })
}

fn fixture(
    initial: Value,
    fault: Fault,
    count: usize,
) -> (String, Arc<Mutex<Value>>, Requests, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // DevSkim: ignore DS162092 -- ephemeral loopback-only fixture
    let endpoint = format!("http://{}", listener.local_addr().unwrap()); // DevSkim: ignore DS137138 -- synthetic provider
    let state = Arc::new(Mutex::new(initial));
    let provider = state.clone();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    let handle = thread::spawn(move || {
        let mut put_seen = false;
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let (headers, bytes) = read_http_request(&mut stream);
            let line = headers.lines().next().unwrap().to_string();
            let body: Value = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            log.lock().unwrap().push((line.clone(), body.clone()));
            let mut status = "200 OK";
            let response = if line
                == "PUT /zones/zone-1/rulesets/phases/http_request_firewall_custom/entrypoint HTTP/1.1"
            {
                put_seen = true;
                if !strict_body(&body) || matches!(fault, Fault::Reject) {
                    status = "400 Bad Request";
                    json!({"success":false,"result":null,"errors":[{"code":1000,"message":"invalid JSON: unknown field id"}]})
                } else {
                    let mut state = provider.lock().unwrap();
                    state["rules"] = body["rules"].clone();
                    if let Some(description) = body.get("description") {
                        state["description"] = description.clone();
                    }
                    state["version"] = json!("8");
                    for (index, rule) in state["rules"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .enumerate()
                    {
                        if rule.get("id").is_none() {
                            rule["id"] = json!(format!("generated-{index}"));
                        }
                        if rule.get("ref").is_none() {
                            rule["ref"] = rule["id"].clone();
                        }
                        rule["version"] = json!("4");
                        rule["last_updated"] = json!("2026-01-02T00:00:00Z");
                    }
                    json!({"success":true,"result":state.clone(),"errors":[]})
                }
            } else if line
                == "GET /zones/zone-1/rulesets/phases/http_request_firewall_custom/entrypoint HTTP/1.1"
            {
                let mut result = provider.lock().unwrap().clone();
                if put_seen {
                    match fault {
                        Fault::Unavailable => {
                            status = "403 Forbidden";
                            result = Value::Null;
                        }
                        Fault::Malformed => {
                            result["rules"] = json!([null]);
                        }
                        Fault::Expression => {
                            result["rules"][0]["expression"] = json!("false");
                        }
                        Fault::Order => {
                            result["rules"].as_array_mut().unwrap().swap(1, 2);
                        }
                        Fault::Membership => {
                            result["rules"].as_array_mut().unwrap().pop();
                        }
                        Fault::Configuration => {
                            result["rules"][2]["ratelimit"]["requests_per_period"] = json!(200);
                        }
                        Fault::Identity => {
                            result["id"] = json!("different-ruleset");
                        }
                        _ => {}
                    }
                }
                json!({"success":status == "200 OK","result":result,"errors":[]})
            } else {
                panic!("unexpected synthetic provider route: {line}");
            };
            let bytes = serde_json::to_vec(&response).unwrap();
            write!(stream,"HTTP/1.1 {status}\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",bytes.len()).unwrap();
            stream.write_all(&bytes).unwrap();
        }
    });
    (endpoint, state, requests, handle)
}

fn preview(mcp: &mut McpStdioProcess, args: Value) -> Value {
    structured_content(&mcp.call_tool(2, "waf_ruleset_plan_change", args)).clone()
}

fn apply(mcp: &mut McpStdioProcess, mut args: Value, plan: &Value) -> Value {
    args["confirmation_token"] = plan["required_confirmation_token"].clone();
    args["readback_security_events"] = json!(false);
    mcp.call_tool(3, "waf_ruleset_apply_change", args)
}

#[test]
fn waf_write_payload_preserves_full_state_through_stdio() {
    assert!(
        !strict_body(&ruleset()),
        "the pre-repair response body must be rejected"
    );
    let (endpoint, _, requests, server) = fixture(ruleset(), Fault::None, 4);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
    let plan = preview(&mut mcp, args());
    assert_eq!(plan["ok"], true, "{plan}");
    assert_eq!(requests.lock().unwrap().len(), 1, "preview has no writes");
    let mut expected = json!({"description":"Example configuration","rules":writable_rules()});
    expected["rules"][0]["action"] = json!("managed_challenge");
    expected["rules"][0]["description"] = json!("Reviewed first rule");
    expected["rules"][0]["expression"] = json!("http.request.uri.path eq \"/reviewed\"");
    assert_eq!(plan["request_body"], expected);
    assert_eq!(plan["current_ruleset"], ruleset());
    assert_eq!(plan["validation"]["rule_cap"]["planned_rule_count"], 5);
    let result = apply(&mut mcp, args(), &plan);
    let content = structured_content(&result);
    assert_eq!(content["ok"], true, "{content}");
    assert_eq!(content["status"], "applied-proven");
    assert_eq!(content["audit"]["outcome"], "success");
    assert!(
        content["audit"]["correlation"]["correlation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    server.join().unwrap();
    let calls = requests.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(
        calls[2].1, expected,
        "complete reviewed write bytes, not a compact rule summary"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|(line, _)| line.starts_with("PUT "))
            .count(),
        1
    );
}

#[test]
fn waf_rejected_or_unproven_apply_is_an_audited_error_through_stdio() {
    for fault in [
        Fault::Reject,
        Fault::Unavailable,
        Fault::Malformed,
        Fault::Expression,
        Fault::Order,
        Fault::Membership,
        Fault::Configuration,
        Fault::Identity,
    ] {
        let count = if matches!(fault, Fault::Reject) { 3 } else { 4 };
        let (endpoint, _, requests, server) = fixture(ruleset(), fault, count);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let plan = preview(&mut mcp, args());
        let result = apply(&mut mcp, args(), &plan);
        let content = structured_content(&result);
        assert_eq!(result["result"]["isError"], true, "{result}");
        assert_eq!(content["ok"], false, "{content}");
        assert_eq!(content["audit"]["outcome"], "error");
        if !matches!(fault, Fault::Reject) {
            assert_eq!(content["status"], "applied-unproven");
            assert_eq!(
                content["error"]["code"],
                if matches!(fault, Fault::Unavailable) {
                    "waf.readback_unavailable"
                } else {
                    "waf.readback_mismatch"
                }
            );
        }
        server.join().unwrap();
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(line, _)| line.starts_with("PUT "))
                .count(),
            1,
            "never replay an apply"
        );
    }
}

#[test]
fn waf_stale_or_missing_confirmation_never_dispatches_a_write() {
    for stale in [false, true] {
        let (endpoint, state, requests, server) = fixture(ruleset(), Fault::None, 2);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let mut plan = preview(&mut mcp, args());
        if stale {
            // Even an overwritten edited field changing without a version bump
            // must invalidate the confirmation, not just the projected PUT.
            state.lock().unwrap()["rules"][0]["action"] = json!("log");
        } else {
            plan["required_confirmation_token"] = json!("wrong-token");
        }
        let result = apply(&mut mcp, args(), &plan);
        let content = structured_content(&result);
        assert_eq!(content["ok"], false, "{content}");
        assert_eq!(content["error"]["code"], "waf.confirmation_required");
        server.join().unwrap();
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(line, _)| line.starts_with("GET "))
        );
    }
}

#[test]
fn waf_malformed_or_unknown_configuration_blocks_before_write() {
    for initial in [
        json!(null),
        json!({"rules":[]}),
        {
            let mut initial = ruleset();
            initial["rules"][2]["ratelimit"] = json!("invalid");
            initial
        },
        {
            let mut initial = ruleset();
            initial["rules"][0]["unreviewed_setting"] = json!(true);
            initial
        },
        {
            let mut initial = ruleset();
            initial["unreviewed_setting"] = json!(true);
            initial
        },
    ] {
        let (endpoint, _, requests, server) = fixture(initial, Fault::None, 1);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let plan = preview(&mut mcp, args());
        assert_eq!(plan["ok"], false, "{plan}");
        assert_eq!(plan["error"]["code"], "waf.unsupported_ruleset_shape");
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn waf_cap_and_list_guards_still_block_through_stdio() {
    for (mut input, code, empty) in [
        (args(), "waf.rule_cap_exceeded", false),
        (args(), "waf.stale_list_reference", false),
        (args(), "waf.stale_list_reference", true),
    ] {
        if code == "waf.rule_cap_exceeded" {
            input["max_rules"] = json!(4);
        } else {
            input["edits"][0]["expression"] = json!("ip.src in $blocked_ips");
            input[if empty {
                "empty_list_refs"
            } else {
                "stale_list_refs"
            }] = json!(["blocked_ips"]);
        }
        let (endpoint, _, requests, server) = fixture(ruleset(), Fault::None, 1);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let plan = preview(&mut mcp, input);
        assert_eq!(plan["ok"], false, "{plan}");
        assert_eq!(plan["error"]["code"], code);
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn waf_add_delete_move_and_bounded_verdicts_work_through_stdio() {
    for (edit, count) in [
        (
            json!({"operation":"add","description":"New rule","expression":"false","rule_action":"log"}),
            6,
        ),
        (json!({"operation":"delete","rule_id":"rule-c"}), 4),
        (
            json!({"operation":"move","rule_id":"rule-e","before_rule_id":"rule-a"}),
            5,
        ),
    ] {
        let (endpoint, _, requests, server) = fixture(ruleset(), Fault::None, 4);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let mut input = args();
        input["edits"] = json!([edit]);
        input["max_rules"] = json!(6);
        let plan = preview(&mut mcp, input.clone());
        assert_eq!(plan["ok"], true, "{plan}");
        input["max_bytes"] = json!(1);
        let result = apply(&mut mcp, input, &plan);
        let content = structured_content(&result);
        assert_eq!(content["ok"], true, "{content}");
        assert_eq!(content["status"], "applied-proven");
        assert_eq!(content["response_size"]["truncated"], true);
        server.join().unwrap();
        let calls = requests.lock().unwrap();
        assert_eq!(calls[2].1, plan["request_body"]);
        assert_eq!(calls[2].1["rules"].as_array().unwrap().len(), count);
    }

    let (endpoint, _, _, server) = fixture(ruleset(), Fault::Order, 4);
    let mut mcp = McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
    let plan = preview(&mut mcp, args());
    let mut input = args();
    input["max_bytes"] = json!(1);
    let result = apply(&mut mcp, input, &plan);
    let content = structured_content(&result);
    assert_eq!(result["result"]["isError"], true);
    assert_eq!(content["ok"], false);
    assert_eq!(content["status"], "applied-unproven");
    assert_eq!(content["error"]["code"], "waf.readback_mismatch");
    server.join().unwrap();
}

#[test]
fn waf_versions_accept_string_or_positive_integer_and_reject_malformed_values() {
    for version in [json!("7"), json!(7)] {
        let mut initial = ruleset();
        initial["version"] = version;
        let (endpoint, _, _, server) = fixture(initial, Fault::None, 4);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let plan = preview(&mut mcp, args());
        assert_eq!(plan["ok"], true, "{plan}");
        let result = apply(&mut mcp, args(), &plan);
        assert_eq!(structured_content(&result)["status"], "applied-proven");
        server.join().unwrap();
    }
    for version in [
        json!(null),
        json!(false),
        json!(0),
        json!(-1),
        json!(1.5),
        json!(""),
        json!("latest"),
        json!("-1"),
    ] {
        let mut initial = ruleset();
        initial["version"] = version;
        let (endpoint, _, requests, server) = fixture(initial, Fault::None, 1);
        let mut mcp =
            McpStdioProcess::start_with_env(vec![("CLOUDFLARE_MCP_API_BASE_URL", endpoint)]);
        let plan = preview(&mut mcp, args());
        assert_eq!(plan["ok"], false, "{plan}");
        assert_eq!(plan["error"]["field"], "ruleset.version");
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}
