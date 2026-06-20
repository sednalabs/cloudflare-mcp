use mcp_toolkit_core::{
    openai_tool_search::{
        OpenAiMcpServerTool, OpenAiMcpToolSearchConfig, OpenAiReadOnlyApprovalOverride,
    },
    rmcp_models,
};
use rmcp::model::{Annotated, RawResource, ReadResourceResult, Resource, ResourceContents};
use serde_json::{Value, json};

use crate::verification::{VerificationStatus, now_unix_ms};
use mcp_toolkit_http::session::SessionStats;

const ABOUT_URI: &str = "cloudflare-mcp://about";
const HELP_URI: &str = "cloudflare-mcp://help";
const ADAPTER_URI: &str = "cloudflare-mcp://adapter-status";
const API_PARITY_URI: &str = "cloudflare-mcp://api-parity-status";
const OPENAI_TOOL_SEARCH_URI: &str = "cloudflare-mcp://openai/tool-search-config";
const OPENAI_SERVER_DESCRIPTION: &str = "Self-hosted Cloudflare operator workflows: Tunnel, DNS, Access, Pages, D1, R2, Workers, Queues, WAF, Email Routing, cache, guarded publish, dry-run planning, approval gates, and readback verification.";
const OPENAI_READ_ONLY_APPROVAL_NOTE: &str = "By default, OpenAI requests approval before sharing data with a remote MCP server. If this server and workflow are trusted, this read-only tool override can reduce approval friction while leaving mutating tools approval-gated.";

const MIME_MARKDOWN: &str = "text/markdown";
const MIME_JSON: &str = "application/json";

#[derive(Debug, Clone)]
pub struct AdapterStatusView {
    pub auth_enabled: bool,
    pub read_only_mode: bool,
    pub api_parity_enabled: bool,
    pub elicitation_enabled: bool,
    pub elicitation_apply_only: bool,
    pub elicitation_required_tools: Vec<String>,
    pub has_api_token: bool,
    pub api_token_source: String,
    pub api_token_header: String,
    pub default_account_id: Option<String>,
    pub default_zone_id: Option<String>,
    pub verification_status: Option<VerificationStatus>,
}

pub fn list_resources(
    adapter: &AdapterStatusView,
    session: Option<&SessionStats>,
    resume_mode: Option<&str>,
) -> Vec<Resource> {
    let about_text = build_about_text();
    let help_text = build_help_text();
    let adapter_status = build_adapter_status(adapter, session, resume_mode);
    let api_parity_status = build_api_parity_status();
    let openai_tool_search = build_openai_tool_search_config();

    vec![
        resource_for_text(
            ABOUT_URI,
            "about",
            "Cloudflare MCP",
            "Purpose, boundaries, and parity target.",
            MIME_MARKDOWN,
            Some(about_text.len()),
        ),
        resource_for_text(
            HELP_URI,
            "help",
            "Cloudflare MCP help",
            "Tool usage and safety defaults.",
            MIME_MARKDOWN,
            Some(help_text.len()),
        ),
        resource_for_text(
            ADAPTER_URI,
            "adapter-status",
            "Cloudflare adapter status",
            "Runtime adapter/auth/session summary.",
            MIME_JSON,
            Some(adapter_status.len()),
        ),
        resource_for_text(
            API_PARITY_URI,
            "api-parity-status",
            "Cloudflare API parity status",
            "REST API v4 catalog source and generic executor coverage.",
            MIME_JSON,
            Some(api_parity_status.len()),
        ),
        resource_for_text(
            OPENAI_TOOL_SEARCH_URI,
            "openai-tool-search-config",
            "OpenAI MCP tool search config",
            "Responses API MCP deferred-loading and tool_search template.",
            MIME_JSON,
            Some(openai_tool_search.len()),
        ),
    ]
}

pub fn read_resource(
    adapter: &AdapterStatusView,
    uri: &str,
    session: Option<&SessionStats>,
    resume_mode: Option<&str>,
) -> Result<ReadResourceResult, rmcp::ErrorData> {
    let text = match uri {
        ABOUT_URI => (MIME_MARKDOWN, build_about_text()),
        HELP_URI => (MIME_MARKDOWN, build_help_text()),
        ADAPTER_URI => (
            MIME_JSON,
            build_adapter_status(adapter, session, resume_mode),
        ),
        API_PARITY_URI => (MIME_JSON, build_api_parity_status()),
        OPENAI_TOOL_SEARCH_URI => (MIME_JSON, build_openai_tool_search_config()),
        _ => {
            return Err(rmcp::ErrorData::resource_not_found(
                "resource not found",
                None,
            ));
        }
    };

    Ok(rmcp_models::read_resource_result(vec![
        ResourceContents::TextResourceContents {
            uri: uri.to_string(),
            mime_type: Some(text.0.to_string()),
            text: text.1,
            meta: None,
        },
    ]))
}

fn build_about_text() -> String {
    [
        "# Cloudflare MCP",
        "",
        "Purpose:",
        "- Provide deterministic Cloudflare tunnel/DNS/Access operations with MCP ergonomics.",
        "",
        "Parity target:",
        "- cloudflared operator workflows + required Zero Trust orchestration.",
        "",
        "Non-goal:",
        "- Do not clone third-party Cloudflare MCP server ecosystems/tool surfaces.",
        "",
        "Security posture:",
        "- Auth-surface protection on /mcp.",
        "- Public health/attest endpoints.",
        "- Adapter errors are typed and token-safe.",
    ]
    .join("\n")
}

fn build_help_text() -> String {
    [
        "# Cloudflare MCP help",
        "",
        "Tools:",
        "- health",
        "- api_parity_status",
        "- api_find_operations",
        "- api_get_operation",
        "- api_prepare_call",
        "- api_read",
        "- api_mutate",
        "- account_billing_usage",
        "- graphql_analytics_query",
        "- waf_ruleset_summary",
        "- waf_security_events_summary",
        "- waf_rule_activity",
        "- waf_ruleset_plan_change",
        "- waf_ruleset_apply_change",
        "- list_tunnels",
        "- ensure_tunnel",
        "- generate_tunnel_ingress",
        "- connector_control",
        "- list_dns_records",
        "- r2_get_object",
        "- r2_inspect_object",
        "- r2_put_object",
        "- verify_dns_route",
        "- upsert_dns_cname",
        "- list_access_apps",
        "- upsert_access_app",
        "- list_access_policies",
        "- list_workers",
        "- get_worker_settings",
        "- patch_worker_settings",
        "- find_tools",
        "- cache_purge",
        "- cache_zone_setting",
        "- cache_rules",
        "- cache_reserve",
        "- cache_tiered",
        "- cache_variants",
        "- cache_origin_regions",
        "- replace_access_policies",
        "- apply_access_allowlist",
        "- publish_preflight",
        "- verify_http_gate",
        "- lock_first_publish",
        "- emergency_unpublish",
        "",
        "Safety defaults:",
        "- Route publish paths are policy-gated by default and fail closed without active Access allow policy.",
        "- `CLOUDFLARE_MCP_READ_ONLY=1` exposes only read-only tools and denies all mutating calls.",
        "- Optional RMCP elicitation gate can require human approval for configured dangerous tool calls.",
        "- Override requires explicit flag and reason, and is surfaced in structured audit payloads.",
        "- All mutating tools support `dry_run=true` and emit deterministic `plan` payloads with zero side effects.",
        "- Broad cache purge/ruleset replacement require dry-run confirmation tokens before apply.",
        "- OpenAI Responses API clients on GPT-5.4+ should combine MCP `defer_loading=true` with `{ \"type\": \"tool_search\" }`; use `gpt-5.5` for the current flagship model target.",
        "- Hosted OpenAI `tool_search` is client-side; non-hosted clients can call `find_tools` to produce a narrow `allowed_tools` list and optional MCP schemas.",
        "- For REST API parity, search with `api_find_operations`, inspect with `api_get_operation`, prepare exact fallback payloads with `api_prepare_call`, use `api_read` for GET, and run `api_mutate` with `dry_run=true` before apply.",
        "- For usage-spike investigations, use `account_billing_usage` for billing usage records and `graphql_analytics_query` for product analytics attribution such as D1 rows read/written.",
        "- For WAF investigations, use `waf_ruleset_summary`, `waf_security_events_summary`, and `waf_rule_activity` before composing raw Rulesets or GraphQL calls.",
        "- High-risk generic API operations are denied by default; prefer curated workflow tools when `preferred_tool` is present.",
        "- Mutating tool responses include structured `audit` metadata with actor + correlation ids + typed outcome/error code.",
        "- Access allowlist mutations enforce replace/additive invariants with post-apply readback validation.",
        "- If account_id/zone_id is omitted, server defaults are used when configured.",
        "- Adapter calls fail fast with typed errors when token/config is missing.",
        "",
        "Testing contracts:",
        "- Tool schema snapshot is enforced in tests.",
        "- Auth surface behavior is verified with protected /mcp checks.",
    ]
    .join("\n")
}

fn build_openai_tool_search_config() -> String {
    let read_only_auto_approval_tools = [
        "health",
        "find_tools",
        "api_parity_status",
        "api_find_operations",
        "api_get_operation",
        "api_prepare_call",
        "api_read",
        "account_billing_usage",
        "graphql_analytics_query",
        "waf_ruleset_summary",
        "waf_security_events_summary",
        "waf_rule_activity",
        "waf_ruleset_plan_change",
        "waf_ruleset_apply_change",
        "account_api_token_permission_plan",
        "list_tunnels",
        "generate_tunnel_ingress",
        "list_dns_records",
        "list_workers",
        "get_worker_settings",
        "d1_list_databases",
        "d1_get_database",
        "d1_inspect_schema",
        "d1_query_read_only",
        "d1_validate_query",
        "analytics_engine_query",
        "analytics_engine_validate_query",
        "analytics_engine_describe_schema",
        "analytics_engine_list_datasets",
        "capabilities_check",
        "pages_list_projects",
        "pages_get_project",
        "pages_list_deployments",
        "pages_get_deployment",
        "pages_list_domains",
        "pages_get_domain",
        "r2_get_object",
        "r2_inspect_object",
        "verify_dns_route",
        "list_access_apps",
        "access_get_app",
        "access_verify_hostname_gate",
        "list_access_policies",
        "queues_list",
        "queues_get",
        "queues_get_metrics",
        "queues_list_consumers",
        "queues_health",
        "workers_list_scripts",
        "workers_get_script_settings",
        "workers_list_tails",
        "workers_observability_query_events",
        "workers_observability_list_keys",
        "workers_observability_list_values",
        "bindings_discover",
        "email_routing_get_settings",
        "email_routing_get_dns",
        "email_routing_list_rules",
        "email_routing_get_rule",
        "email_routing_get_catch_all",
        "email_routing_list_addresses",
        "email_routing_get_address",
        "bulk_redirects_list_lists",
        "bulk_redirects_get_list",
        "bulk_redirects_list_items",
        "bulk_redirects_get_operation",
        "bulk_redirects_get_ruleset",
        "publish_preflight",
        "verify_http_gate",
    ];
    let mcp_tool = OpenAiMcpServerTool::new(
        "cloudflare",
        OPENAI_SERVER_DESCRIPTION,
        "https://<host>/mcp",
    );
    let mut config = OpenAiMcpToolSearchConfig::new(mcp_tool).with_notes([
        "Hosted OpenAI tool_search is client-side; this server exposes stable MCP tool descriptions and a find_tools helper for non-hosted clients.",
        "Keep the MCP server definition's server_label and server_description clear because the model sees those before individual deferred tool schemas are loaded.",
        "Use find_tools.openai_allowed_tools as the allowed_tools value when manually narrowing a follow-up Responses request.",
        "Use api_find_operations/api_get_operation/api_prepare_call/api_read/api_mutate for broad Cloudflare REST API v4 parity.",
        "Use account_billing_usage for billing records and graphql_analytics_query for Cloudflare Analytics GraphQL attribution.",
        "Use waf_ruleset_summary, waf_security_events_summary, and waf_rule_activity for WAF rules and Security Events triage.",
        "Use waf_ruleset_plan_change before waf_ruleset_apply_change for WAF mutations; the apply tool requires the plan token and performs readback.",
        "Keep approval enabled for mutating tools unless another workflow-level review gate applies.",
    ]);
    if let Some(approval_override) =
        OpenAiReadOnlyApprovalOverride::new(read_only_auto_approval_tools)
    {
        config = config.with_optional_trusted_read_only_approval_override(approval_override);
    }

    let mut payload = config.to_documentation_value();
    if let Some(Value::Object(approval_override)) =
        payload.get_mut("optional_trusted_read_only_approval_override")
    {
        approval_override.insert(
            "use_only_after_review".to_string(),
            json!(OPENAI_READ_ONLY_APPROVAL_NOTE),
        );
    }

    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}

fn build_api_parity_status() -> String {
    serde_json::to_string_pretty(&json!({
        "catalog": crate::api_catalog::status(),
        "generic_tools": [
            "api_parity_status",
            "api_find_operations",
            "api_get_operation",
            "api_prepare_call",
            "api_read",
            "api_mutate"
        ],
        "parity_model": "official Cloudflare REST API v4 operations are searchable, inspectable, and callable through guarded generic executor tools",
        "preferred_path": "Use curated tools when api_get_operation reports preferred_tool; use generic tools for uncovered REST v4 operations."
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

fn build_adapter_status(
    adapter: &AdapterStatusView,
    session: Option<&SessionStats>,
    resume_mode: Option<&str>,
) -> String {
    let mut payload = json!({
        "auth": {
            "enabled": adapter.auth_enabled,
            "read_only_mode": adapter.read_only_mode,
            "api_parity_enabled": adapter.api_parity_enabled,
            "elicitation": {
                "enabled": adapter.elicitation_enabled,
                "apply_only": adapter.elicitation_apply_only,
                "required_tools": adapter.elicitation_required_tools.clone(),
            }
        },
        "cloudflare": {
            "has_api_token": adapter.has_api_token,
            "api_token_source": adapter.api_token_source,
            "api_token_header": adapter.api_token_header,
            "default_account_id": adapter.default_account_id,
            "default_zone_id": adapter.default_zone_id,
        },
    });

    payload["verification"] = adapter
        .verification_status
        .as_ref()
        .map(|verification| {
            let freshness_ms = now_unix_ms().saturating_sub(verification.checked_at_unix_ms);
            json!({
                "provenance": verification.source,
                "last_known_gate_state": verification.state,
                "code": verification.code,
                "reason": verification.reason,
                "target": verification.target,
                "status_code": verification.status_code,
                "redirect_location": verification.redirect_location,
                "checked_at_unix_ms": verification.checked_at_unix_ms,
                "freshness_ms": freshness_ms,
                "latency_ms": verification.latency_ms,
                "transport_error": verification.transport_error,
            })
        })
        .unwrap_or_else(|| {
            json!({
                "provenance": "verify_http_gate",
                "last_known_gate_state": "unknown",
                "code": "verification.unknown",
                "reason": "no_probe_recorded",
                "target": null,
                "status_code": null,
                "redirect_location": null,
                "checked_at_unix_ms": null,
                "freshness_ms": null,
                "latency_ms": null,
                "transport_error": null,
            })
        });

    if let Some(stats) = session {
        payload["session"] = json!({
            "active_streams": stats.active_sessions,
            "max_streams": stats.max_sessions,
            "resume_enabled": resume_mode.unwrap_or("off") != "off",
            "resume_mode": resume_mode.unwrap_or("unknown"),
        });
    }

    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}

fn resource_for_text(
    uri: &str,
    name: &str,
    title: &str,
    description: &str,
    mime_type: &str,
    size: Option<usize>,
) -> Resource {
    Annotated::new(
        RawResource {
            uri: uri.to_string(),
            name: name.to_string(),
            title: Some(title.to_string()),
            description: Some(description.to_string()),
            mime_type: Some(mime_type.to_string()),
            size: size.map(|size| size.min(u32::MAX as usize) as u32),
            icons: None,
            meta: None,
        },
        None,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{AdapterStatusView, build_adapter_status, build_openai_tool_search_config};
    use crate::verification::{VerificationState, VerificationStatus, now_unix_ms};

    #[test]
    fn adapter_status_includes_verification_provenance_and_freshness() {
        let checked_at = now_unix_ms().saturating_sub(1000);
        let adapter = AdapterStatusView {
            auth_enabled: true,
            read_only_mode: false,
            api_parity_enabled: true,
            elicitation_enabled: false,
            elicitation_apply_only: true,
            elicitation_required_tools: Vec::new(),
            has_api_token: true,
            api_token_source: "config".to_string(),
            api_token_header: "x-cloudflare-api-token".to_string(),
            default_account_id: Some("acct-1".to_string()),
            default_zone_id: Some("zone-1".to_string()),
            verification_status: Some(VerificationStatus {
                source: "verify_http_gate",
                target: "https://preview.example.com".to_string(),
                state: VerificationState::AccessGated,
                code: "verification.access_gated",
                reason: "access_challenge_detected",
                hint: "Access gate appears active for this endpoint.",
                status_code: Some(302),
                redirect_location: Some(
                    "https://preview.example.com/cdn-cgi/access/login".to_string(),
                ),
                checked_at_unix_ms: checked_at,
                latency_ms: 24,
                transport_error: None,
            }),
        };

        let payload = build_adapter_status(&adapter, None, Some("historyless"));
        let parsed: Value = serde_json::from_str(&payload).expect("json");
        assert_eq!(parsed["auth"]["read_only_mode"], Value::Bool(false));
        assert_eq!(parsed["auth"]["elicitation"]["enabled"], Value::Bool(false));
        assert_eq!(
            parsed["verification"]["provenance"],
            Value::String("verify_http_gate".to_string())
        );
        assert_eq!(
            parsed["verification"]["last_known_gate_state"],
            Value::String("access_gated".to_string())
        );
        assert!(
            parsed["verification"]["freshness_ms"]
                .as_u64()
                .expect("freshness")
                >= 1000
        );
    }

    #[test]
    fn openai_tool_search_config_uses_deferred_loading_and_safe_approval_default() {
        let payload = build_openai_tool_search_config();
        let parsed: Value = serde_json::from_str(&payload).expect("json");

        assert_eq!(parsed["model"], Value::String("gpt-5.5".to_string()));
        assert_eq!(
            parsed["minimum_model_for_tool_search"],
            Value::String("gpt-5.4".to_string())
        );
        assert_eq!(parsed["tools"][0]["type"], Value::String("mcp".to_string()));
        assert_eq!(parsed["tools"][0]["defer_loading"], Value::Bool(true));
        assert!(parsed["tools"][0]["require_approval"].is_null());
        assert_eq!(
            parsed["tools"][1]["type"],
            Value::String("tool_search".to_string())
        );
        let server_description = parsed["tools"][0]["server_description"]
            .as_str()
            .expect("server description");
        assert!(server_description.contains("D1"));
        assert!(server_description.contains("WAF"));
        assert!(server_description.contains("readback verification"));

        let approved = parsed["optional_trusted_read_only_approval_override"]["require_approval"]
            ["never"]["tool_names"]
            .as_array()
            .expect("read-only approval tools");
        assert!(approved.iter().any(|tool| tool == "find_tools"));
        assert!(approved.iter().any(|tool| tool == "api_prepare_call"));
        assert!(!approved.iter().any(|tool| tool == "api_mutate"));
        assert!(!approved.iter().any(|tool| tool == "cache_purge"));
        assert!(!approved.iter().any(|tool| tool == "cache_zone_setting"));
    }
}
