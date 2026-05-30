use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use axum::http::{Request, request::Parts};
use mcp_toolkit_core::notifications::{ToolListTracker, ToolListUpdate};
use mcp_toolkit_core::rmcp_models;
use mcp_toolkit_core::tool_inventory::{
    ToolInventory, ToolInventoryError, ToolInventoryPolicy, ToolOperation,
};
use mcp_toolkit_http::session::BoundedSessionManager;
use mcp_toolkit_observability::{
    sanitize_error_message, sanitize_log_value_opt, sanitize_log_value_with_limit,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CallToolRequestMethod, CallToolRequestParams, CallToolResult, Implementation, JsonObject,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
    ReadResourceRequestParams, ReadResourceResult, ServerCapabilities, ServerInfo,
};
use rmcp::service::{ElicitationError, RequestContext};
use rmcp::transport::common::http_header::HEADER_SESSION_ID;
use rmcp::{RoleServer, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::cloudflare::{CloudflareClient, with_request_api_token_override};
use crate::config::{ApiTokenSource, ElicitationConfig, ResumeMode};
use crate::mutation::MutationApprovalAudit;
use crate::portal::PortalAgentClient;
use crate::resources::{self, AdapterStatusView};
use crate::tool_surface::API_PARITY_FEATURE_FLAG;
use crate::tunnel::ConnectorRuntimeSnapshot;
use crate::verification::VerificationStatus;

const HEADER_X_CORRELATION_ID: &str = "x-correlation-id";
const HEADER_X_REQUEST_ID: &str = "x-request-id";
const MAX_CONTEXT_VALUE_CHARS: usize = 128;
const MAX_ELICITATION_ARGUMENT_KEYS: usize = 12;
const MAX_ELICITATION_ARGUMENT_KEY_CHARS: usize = 64;
const MAX_ELICITATION_ARGUMENT_PREVIEW_CHARS: usize = 512;
const MAX_ELICITATION_REASON_CHARS: usize = 256;
const MAX_ELICITATION_ERROR_CHARS: usize = 256;
const MAX_ELICITATION_DIGEST_CHARS: usize = 128;
const MCP_PROTOCOL_VERSION_LATEST: &str = "2025-11-25";

#[derive(Clone, Debug)]
pub struct ElicitationPolicy {
    pub enabled: bool,
    pub required_tools: HashSet<String>,
    pub apply_only: bool,
    pub timeout: Option<Duration>,
    pub fail_open_unsupported_client: bool,
}

impl ElicitationPolicy {
    pub fn from_config(config: ElicitationConfig) -> Self {
        Self {
            enabled: config.enabled,
            required_tools: config.required_tools.into_iter().collect(),
            apply_only: config.apply_only,
            timeout: config.timeout,
            fail_open_unsupported_client: config.fail_open_unsupported_client,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DangerousCallApproval {
    approve: bool,
    #[serde(default)]
    request_digest: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

rmcp::elicit_safe!(DangerousCallApproval);

#[derive(Clone, Debug)]
struct ElicitationRequestSummary {
    argument_keys: Vec<String>,
    argument_digest: String,
    argument_preview: String,
}

#[derive(Clone)]
pub struct CloudflareMcp {
    pub cloudflare: Arc<CloudflareClient>,
    pub default_account_id: Option<String>,
    pub default_zone_id: Option<String>,
    pub has_api_token: bool,
    pub api_token_source: ApiTokenSource,
    pub api_token_header: String,
    pub auth_enabled: bool,
    pub read_only_mode: bool,
    pub api_parity_enabled: bool,
    pub portal_agent: Arc<PortalAgentClient>,
    pub has_portal_agent_token: bool,
    pub has_portal_access_service_token: bool,
    pub elicitation_policy: ElicitationPolicy,
    tool_router: ToolRouter<CloudflareMcp>,
    pub(crate) tool_inventory: ToolInventory,
    pub(crate) tool_inventory_policy: ToolInventoryPolicy,
    tool_list_tracker: Arc<ToolListTracker>,
    session_manager: Arc<BoundedSessionManager>,
    resume_mode: ResumeMode,
    pub connector_runtime: Arc<Mutex<BTreeMap<String, ConnectorRuntimeSnapshot>>>,
    pub verification_status: Arc<Mutex<Option<VerificationStatus>>>,
}

impl CloudflareMcp {
    pub fn new(
        cloudflare: Arc<CloudflareClient>,
        default_account_id: Option<String>,
        default_zone_id: Option<String>,
        has_api_token: bool,
        api_token_source: ApiTokenSource,
        api_token_header: String,
        auth_enabled: bool,
        read_only_mode: bool,
        api_parity_enabled: bool,
        portal_agent: Arc<PortalAgentClient>,
        elicitation_config: ElicitationConfig,
        tool_list_tracker: Arc<ToolListTracker>,
        session_manager: Arc<BoundedSessionManager>,
        resume_mode: ResumeMode,
    ) -> Self {
        let tool_router = Self::tool_router_cloudflare();
        let tool_inventory = build_tool_inventory()
            .expect("cloudflare-mcp tool inventory registration must remain valid");
        let tool_inventory_policy = if api_parity_enabled {
            ToolInventoryPolicy::strict()
                .with_read_only_only(read_only_mode)
                .with_feature_flags([API_PARITY_FEATURE_FLAG])
        } else {
            ToolInventoryPolicy::strict().with_read_only_only(read_only_mode)
        };
        let has_portal_agent_token = portal_agent.has_agent_token();
        let has_portal_access_service_token = portal_agent.has_access_service_token();
        Self {
            cloudflare,
            default_account_id,
            default_zone_id,
            has_api_token,
            api_token_source,
            api_token_header,
            auth_enabled,
            read_only_mode,
            api_parity_enabled,
            portal_agent,
            has_portal_agent_token,
            has_portal_access_service_token,
            elicitation_policy: ElicitationPolicy::from_config(elicitation_config),
            tool_router,
            tool_inventory,
            tool_inventory_policy,
            tool_list_tracker,
            session_manager,
            resume_mode,
            connector_runtime: Arc::new(Mutex::new(BTreeMap::new())),
            verification_status: Arc::new(Mutex::new(None)),
        }
    }

    fn resume_mode_label(&self) -> &'static str {
        match self.resume_mode {
            ResumeMode::Off => "off",
            ResumeMode::Historyless => "historyless",
        }
    }

    fn adapter_status_view(&self) -> AdapterStatusView {
        let verification_status = self
            .verification_status
            .lock()
            .ok()
            .and_then(|status| status.clone());
        let mut elicitation_required_tools = self
            .elicitation_policy
            .required_tools
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        elicitation_required_tools.sort();
        AdapterStatusView {
            auth_enabled: self.auth_enabled,
            read_only_mode: self.read_only_mode,
            api_parity_enabled: self.api_parity_enabled,
            elicitation_enabled: self.elicitation_policy.enabled,
            elicitation_apply_only: self.elicitation_policy.apply_only,
            elicitation_required_tools,
            has_api_token: self.has_api_token,
            api_token_source: self.api_token_source.as_str().to_string(),
            api_token_header: self.api_token_header.clone(),
            default_account_id: self.default_account_id.clone(),
            default_zone_id: self.default_zone_id.clone(),
            verification_status,
        }
    }

    pub fn tool_names(&self) -> Vec<String> {
        self.tool_inventory
            .filter_tools(
                self.tool_router.list_all(),
                ToolOperation::List,
                &self.tool_inventory_policy,
                |tool| tool.name.as_ref(),
            )
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }

    async fn maybe_notify_tool_list_changed(
        &self,
        session_id: Option<&str>,
        peer: &rmcp::service::Peer<RoleServer>,
    ) {
        let session_id = session_id.map(str::trim).filter(|value| !value.is_empty());
        let Some(session_id) = session_id else {
            return;
        };
        let tool_names = self
            .tool_inventory
            .filter_tools(
                self.tool_router.list_all(),
                ToolOperation::List,
                &self.tool_inventory_policy,
                |tool| tool.name.as_ref(),
            )
            .into_iter()
            .map(|tool| tool.name);
        let update = self.tool_list_tracker.observe(session_id, tool_names);
        if matches!(update, ToolListUpdate::Changed { .. }) {
            if let Err(err) = peer.notify_tool_list_changed().await {
                tracing::debug!(error = %err, session_id, "tool list_changed notification failed");
            }
        }
    }

    fn call_requires_elicitation(&self, request: &CallToolRequestParams) -> bool {
        if !self.elicitation_policy.enabled {
            return false;
        }
        if !self
            .elicitation_policy
            .required_tools
            .contains(request.name.as_ref())
        {
            return false;
        }
        if request_is_read_only_elicitation_action(
            request.name.as_ref(),
            request.arguments.as_ref(),
        ) {
            return false;
        }
        if self.elicitation_policy.apply_only && request_is_dry_run(request.arguments.as_ref()) {
            return false;
        }
        true
    }

    async fn enforce_call_elicitation(
        &self,
        request: &CallToolRequestParams,
        context: &mut RequestContext<RoleServer>,
    ) -> Option<CallToolResult> {
        if !self.call_requires_elicitation(request) {
            return None;
        }

        let correlation = correlation_headers_from_context(context);
        let dry_run = request_is_dry_run(request.arguments.as_ref());
        let tool_name = request.name.as_ref();
        let request_summary = summarize_elicitation_request(request.arguments.as_ref());
        let request_digest = Some(request_summary.argument_digest.clone());

        if context.peer.supported_elicitation_modes().is_empty() {
            if self.elicitation_policy.fail_open_unsupported_client {
                attach_mutation_approval_audit_marker(
                    context,
                    MutationApprovalAudit {
                        required: true,
                        decision: "bypassed_unsupported_client",
                        request_digest: request_summary.argument_digest,
                        client_supports_elicitation: false,
                        fail_open_unsupported_client: true,
                    },
                );
                tracing::warn!(
                    tool = %request.name,
                    dry_run,
                    "elicitation required but client does not declare elicitation capability; fail-open is enabled"
                );
                return None;
            }
            return Some(approval_denied_result(
                request.name.as_ref(),
                dry_run,
                "approval.client_capability_missing",
                "tool execution requires human approval, but the client does not support MCP elicitation",
                "Use a client with elicitation support, or disable elicitation gating for this server profile.",
                correlation,
                None,
                request_digest,
                None,
            ));
        }

        let prompt = build_elicitation_prompt(tool_name, dry_run, &request_summary, &correlation);
        let decision = context
            .peer
            .elicit_with_timeout::<DangerousCallApproval>(prompt, self.elicitation_policy.timeout)
            .await;

        match decision {
            Ok(Some(answer)) if answer.approve => {
                let provided_digest = sanitized_approval_digest(answer.request_digest.as_deref());
                if !approval_digest_matches(
                    provided_digest.as_deref(),
                    request_summary.argument_digest.as_str(),
                ) {
                    return Some(approval_denied_result(
                        tool_name,
                        dry_run,
                        "approval.digest_mismatch",
                        "human approval response did not match the request digest for this tool call",
                        "Retry and provide the exact request_digest from the elicitation prompt.",
                        correlation,
                        sanitized_elicitation_reason(answer.reason),
                        Some(request_summary.argument_digest),
                        provided_digest,
                    ));
                }
                attach_mutation_approval_audit_marker(
                    context,
                    MutationApprovalAudit {
                        required: true,
                        decision: "approved",
                        request_digest: request_summary.argument_digest,
                        client_supports_elicitation: true,
                        fail_open_unsupported_client: self
                            .elicitation_policy
                            .fail_open_unsupported_client,
                    },
                );
                None
            }
            Ok(Some(answer)) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.declined",
                "human approval declined for dangerous tool execution",
                "Approve the elicitation request to continue, or run dry_run first.",
                correlation,
                sanitized_elicitation_reason(answer.reason),
                request_digest,
                sanitized_approval_digest(answer.request_digest.as_deref()),
            )),
            Ok(None) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.no_content",
                "human approval response did not include required content",
                "Retry the request and provide an explicit approval decision.",
                correlation,
                None,
                request_digest,
                None,
            )),
            Err(ElicitationError::UserDeclined) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.user_declined",
                "human approval declined for dangerous tool execution",
                "Approve the elicitation request to continue.",
                correlation,
                None,
                request_digest,
                None,
            )),
            Err(ElicitationError::UserCancelled) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.user_cancelled",
                "human approval was cancelled",
                "Retry and explicitly approve to continue.",
                correlation,
                None,
                request_digest,
                None,
            )),
            Err(ElicitationError::CapabilityNotSupported) => {
                if self.elicitation_policy.fail_open_unsupported_client {
                    attach_mutation_approval_audit_marker(
                        context,
                        MutationApprovalAudit {
                            required: true,
                            decision: "bypassed_unsupported_client",
                            request_digest: request_summary.argument_digest,
                            client_supports_elicitation: false,
                            fail_open_unsupported_client: true,
                        },
                    );
                    tracing::warn!(
                        tool = %tool_name,
                        "elicitation capability missing during approval; fail-open is enabled"
                    );
                    None
                } else {
                    Some(approval_denied_result(
                        tool_name,
                        dry_run,
                        "approval.client_capability_missing",
                        "tool execution requires human approval, but the client does not support MCP elicitation",
                        "Use a client with elicitation support, or disable elicitation gating for this server profile.",
                        correlation,
                        None,
                        request_digest,
                        None,
                    ))
                }
            }
            Err(ElicitationError::NoContent) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.no_content",
                "human approval response did not include required content",
                "Retry the request and provide an explicit approval decision.",
                correlation,
                None,
                request_digest,
                None,
            )),
            Err(ElicitationError::ParseError { error, .. }) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.parse_error",
                format!(
                    "human approval response could not be parsed: {}",
                    sanitize_error_message(&error.to_string(), MAX_ELICITATION_ERROR_CHARS)
                ),
                "Retry and provide a valid approval response.",
                correlation,
                None,
                request_digest,
                None,
            )),
            Err(ElicitationError::Service(err)) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.service_error",
                format!(
                    "human approval request failed: {}",
                    sanitize_error_message(&err.to_string(), MAX_ELICITATION_ERROR_CHARS)
                ),
                "Retry the request; if this persists, inspect client/server transport logs.",
                correlation,
                None,
                request_digest,
                None,
            )),
            Err(err) => Some(approval_denied_result(
                tool_name,
                dry_run,
                "approval.elicitation_error",
                format!(
                    "human approval request failed: {}",
                    sanitize_error_message(&err.to_string(), MAX_ELICITATION_ERROR_CHARS)
                ),
                "Retry the request; if this persists, inspect client/server transport logs.",
                correlation,
                None,
                request_digest,
                None,
            )),
        }
    }
}

fn session_id_from_context(context: &RequestContext<RoleServer>) -> Option<String> {
    context.extensions.get::<Parts>().and_then(|parts| {
        parts
            .headers
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn api_token_override_from_context(
    context: &RequestContext<RoleServer>,
    source: ApiTokenSource,
    header_name: &str,
) -> Option<String> {
    if !source.uses_request_header() {
        return None;
    }
    context.extensions.get::<Parts>().and_then(|parts| {
        parts
            .headers
            .get(header_name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn ensure_request_parts_extension(extensions: &mut rmcp::model::Extensions) {
    if extensions.get::<Parts>().is_some() {
        return;
    }

    let (parts, _) = Request::builder()
        .uri("mcp://tool-call")
        .body(())
        .expect("static fallback request parts must be valid")
        .into_parts();
    extensions.insert(parts);
}

fn request_is_dry_run(arguments: Option<&JsonObject>) -> bool {
    arguments
        .and_then(|object| object.get("dry_run"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn request_is_read_only_elicitation_action(
    tool_name: &str,
    arguments: Option<&JsonObject>,
) -> bool {
    if tool_name != "account_api_tokens" {
        return false;
    }
    let action = arguments
        .and_then(|object| object.get("action"))
        .and_then(serde_json::Value::as_str)
        .map(normalize_action_name);
    matches!(
        action.as_deref(),
        Some(
            "list_permission_groups"
                | "permission_groups"
                | "list"
                | "list_tokens"
                | "get"
                | "details"
                | "token_details"
                | "verify"
        )
    )
}

fn normalize_action_name(action: &str) -> String {
    action.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

#[derive(Clone, Debug, Default)]
struct CorrelationHeaders {
    correlation_id: Option<String>,
    request_id: Option<String>,
}

fn correlation_headers_from_context(context: &RequestContext<RoleServer>) -> CorrelationHeaders {
    let Some(parts) = context.extensions.get::<Parts>() else {
        return CorrelationHeaders::default();
    };
    let correlation_id = sanitized_header(parts, HEADER_X_CORRELATION_ID);
    let request_id = sanitized_header(parts, HEADER_X_REQUEST_ID);
    CorrelationHeaders {
        correlation_id,
        request_id,
    }
}

fn request_argument_keys(arguments: Option<&JsonObject>) -> Vec<String> {
    let mut keys = arguments
        .into_iter()
        .flat_map(|args| {
            args.keys()
                .map(|key| sanitize_log_value_with_limit(key, MAX_ELICITATION_ARGUMENT_KEY_CHARS))
        })
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn summarize_elicitation_request(arguments: Option<&JsonObject>) -> ElicitationRequestSummary {
    let argument_keys = request_argument_keys(arguments);
    let canonical_value = canonicalize_json_value(
        arguments
            .map(|value| Value::Object(value.clone()))
            .unwrap_or_else(|| Value::Object(serde_json::Map::new())),
    );
    let canonical_json =
        serde_json::to_string(&canonical_value).unwrap_or_else(|_| "{}".to_string());
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    let argument_digest = format!("{:x}", hasher.finalize());
    let argument_preview =
        sanitize_log_value_with_limit(&canonical_json, MAX_ELICITATION_ARGUMENT_PREVIEW_CHARS);
    ElicitationRequestSummary {
        argument_keys,
        argument_digest,
        argument_preview,
    }
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut normalized = serde_json::Map::new();
            for (key, nested) in entries {
                normalized.insert(key, canonicalize_json_value(nested));
            }
            Value::Object(normalized)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize_json_value).collect())
        }
        primitive => primitive,
    }
}

fn build_elicitation_prompt(
    tool_name: &str,
    dry_run: bool,
    request_summary: &ElicitationRequestSummary,
    correlation: &CorrelationHeaders,
) -> String {
    let mut message = format!(
        "Approve execution of dangerous Cloudflare MCP tool '{tool_name}'? dry_run={dry_run}."
    );
    if !request_summary.argument_keys.is_empty() {
        let displayed = request_summary
            .argument_keys
            .iter()
            .take(MAX_ELICITATION_ARGUMENT_KEYS)
            .cloned()
            .collect::<Vec<_>>();
        let hidden = request_summary
            .argument_keys
            .len()
            .saturating_sub(displayed.len());
        message.push_str(&format!(
            " Request argument keys: {}.",
            displayed.join(", ")
        ));
        if hidden > 0 {
            message.push_str(&format!(
                " ({} additional argument key(s) omitted for brevity.)",
                hidden
            ));
        }
    }
    message.push_str(&format!(
        " Request digest (sha256): {}.",
        request_summary.argument_digest
    ));
    message.push_str(&format!(
        " Canonical arguments preview: {}.",
        request_summary.argument_preview
    ));
    if let Some(correlation_id) = correlation.correlation_id.as_deref() {
        message.push_str(&format!(" Correlation ID: {correlation_id}."));
    } else if let Some(request_id) = correlation.request_id.as_deref() {
        message.push_str(&format!(" Request ID: {request_id}."));
    }
    message.push_str(
        " Respond with {\"approve\": true|false, \"request_digest\": \"copy digest from prompt\", \"reason\": \"optional operator rationale\"}.",
    );
    message
}

fn approval_digest_matches(provided: Option<&str>, expected: &str) -> bool {
    provided.is_some_and(|provided| provided == expected)
}

fn approval_denied_result(
    tool_name: &str,
    dry_run: bool,
    code: impl Into<String>,
    message: impl Into<String>,
    hint: impl Into<String>,
    correlation: CorrelationHeaders,
    reason: Option<String>,
    request_digest: Option<String>,
    provided_request_digest: Option<String>,
) -> CallToolResult {
    let payload = json!({
        "ok": false,
        "operation": tool_name,
        "dry_run": dry_run,
        "audit": {
            "operation": tool_name,
            "outcome": "denied_pre_execution",
            "correlation": {
                "correlation_id": correlation.correlation_id,
                "request_id": correlation.request_id,
            },
        },
        "approval": {
            "required": true,
            "approved": false,
            "reason": reason,
            "request_digest": request_digest,
            "provided_request_digest": provided_request_digest,
            "correlation": {
                "correlation_id": correlation.correlation_id,
                "request_id": correlation.request_id,
            },
        },
        "error": {
            "code": code.into(),
            "message": message.into(),
            "hint": hint.into(),
        }
    });
    CallToolResult::structured_error(payload)
}

fn sanitized_header(parts: &Parts, header: &str) -> Option<String> {
    parts
        .headers
        .get(header)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| sanitize_log_value_opt(Some(value), MAX_CONTEXT_VALUE_CHARS))
}

fn sanitized_elicitation_reason(reason: Option<String>) -> Option<String> {
    reason
        .as_deref()
        .and_then(|value| sanitize_log_value_opt(Some(value), MAX_ELICITATION_REASON_CHARS))
}

fn sanitized_approval_digest(digest: Option<&str>) -> Option<String> {
    digest.and_then(|value| sanitize_log_value_opt(Some(value), MAX_ELICITATION_DIGEST_CHARS))
}

fn attach_mutation_approval_audit_marker(
    context: &mut RequestContext<RoleServer>,
    marker: MutationApprovalAudit,
) {
    let Some(parts) = context.extensions.get_mut::<Parts>() else {
        tracing::warn!(
            "unable to attach mutation approval audit marker because request Parts extension is unavailable"
        );
        return;
    };
    parts.extensions.insert(marker);
}

fn latest_protocol_version() -> ProtocolVersion {
    serde_json::from_value::<ProtocolVersion>(Value::String(
        MCP_PROTOCOL_VERSION_LATEST.to_string(),
    ))
    .unwrap_or(ProtocolVersion::V_2025_06_18)
}

pub(crate) fn build_tool_inventory() -> Result<ToolInventory, ToolInventoryError> {
    crate::tool_surface::build_tool_inventory()
}

impl ServerHandler for CloudflareMcp {
    fn get_info(&self) -> ServerInfo {
        rmcp_models::server_info(
            latest_protocol_version(),
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_tool_list_changed()
                .build(),
            Implementation::from_build_env(),
            Some(
                "Cloudflare MCP. Target parity is cloudflared workflow with private-by-default guardrails."
                    .to_string(),
            ),
        )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        let tools = self.tool_inventory.filter_tools(
            self.tool_router.list_all(),
            ToolOperation::List,
            &self.tool_inventory_policy,
            |tool| tool.name.as_ref(),
        );
        if let Some(session_id) = session_id_from_context(&_context) {
            let _ = self
                .tool_list_tracker
                .observe(&session_id, tools.iter().map(|tool| tool.name.as_ref()));
        }
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            tools,
            next_cursor: None,
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        let call_allowed = self.tool_inventory.is_allowed(
            &request.name,
            ToolOperation::Call,
            &self.tool_inventory_policy,
        );
        let mut context = context;
        ensure_request_parts_extension(&mut context.extensions);
        let session_id = session_id_from_context(&context);
        let peer = context.peer.clone();
        let approval_request = request.clone();
        async move {
            if !call_allowed {
                return Err(rmcp::ErrorData::method_not_found::<CallToolRequestMethod>());
            }
            if let Some(denied) = self
                .enforce_call_elicitation(&approval_request, &mut context)
                .await
            {
                return Ok(denied);
            }
            let request_api_token = api_token_override_from_context(
                &context,
                self.api_token_source,
                &self.api_token_header,
            );
            let tool_context = ToolCallContext::new(self, request, context);
            let result = with_request_api_token_override(
                request_api_token,
                self.tool_router.call(tool_context),
            )
            .await;
            if let Ok(payload) = &result {
                let is_error = payload.is_error.unwrap_or(false);
                if !is_error {
                    self.maybe_notify_tool_list_changed(session_id.as_deref(), &peer)
                        .await;
                }
            }
            result
        }
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, rmcp::ErrorData>> + Send + '_ {
        let session_manager = self.session_manager.clone();
        let adapter = self.adapter_status_view();
        async move {
            let stats = session_manager.stats().await;
            let resources =
                resources::list_resources(&adapter, Some(&stats), Some(self.resume_mode_label()));
            Ok(ListResourcesResult {
                resources,
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResult, rmcp::ErrorData>> + Send + '_ {
        let session_manager = self.session_manager.clone();
        let adapter = self.adapter_status_view();
        async move {
            let stats = session_manager.stats().await;
            resources::read_resource(
                &adapter,
                &request.uri,
                Some(&stats),
                Some(self.resume_mode_label()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::{Request, request::Parts};
    use mcp_toolkit_core::notifications::ToolListTracker;
    use mcp_toolkit_core::tool_inventory::ToolInventoryPolicy;
    use mcp_toolkit_http::session::{BoundedSessionManager, SessionLifecycleConfig};
    use rmcp::ServerHandler;
    use rmcp::model::{CallToolRequestParams, Extensions};
    use rmcp::transport::streamable_http_server::session::local::{
        LocalSessionManager, SessionConfig,
    };
    use serde_json::json;

    use super::{CloudflareMcp, build_tool_inventory, ensure_request_parts_extension};
    use crate::cloudflare::CloudflareClient;
    use crate::config::{
        ApiTokenSource, CloudflareApiConfig, ElicitationConfig, PortalAgentConfig, ResumeMode,
    };
    use crate::portal::PortalAgentClient;

    fn fixture_material(label: &str) -> String {
        let mut value = String::from("fixture-");
        value.push_str(label);
        value.push_str("-value");
        value
    }

    fn test_server_with_elicitation(
        read_only_mode: bool,
        elicitation_config: ElicitationConfig,
    ) -> CloudflareMcp {
        let client = Arc::new(
            CloudflareClient::new(CloudflareApiConfig {
                api_base_url: "http://127.0.0.1:9520".to_string(),
                api_token: Some(fixture_material("api")),
                api_token_source: ApiTokenSource::Config,
                api_token_header: "x-cloudflare-api-token".to_string(),
                r2_access_key_id: Some(fixture_material("r2-id")),
                r2_secret_access_key: Some(fixture_material("r2-material")),
                r2_endpoint: None,
                default_account_id: Some("acct-1".to_string()),
                default_zone_id: Some("zone-1".to_string()),
                request_timeout: Duration::from_secs(1),
                max_retries: 0,
                retry_base_delay: Duration::from_millis(1),
                retry_max_delay: Duration::from_millis(1),
                user_agent: "cloudflare-mcp-test".to_string(),
            })
            .expect("client"),
        );
        let session_manager = Arc::new(BoundedSessionManager::new_with_lifecycle(
            LocalSessionManager::default(),
            8,
            false,
            {
                let mut session_config = SessionConfig::default();
                session_config.channel_capacity = 8;
                session_config.keep_alive = None;
                session_config
            },
            SessionLifecycleConfig::default(),
        ));
        let portal_agent = Arc::new(
            PortalAgentClient::new(PortalAgentConfig {
                allowed_url_prefixes: vec!["https://staff.example.com/api/agent/".to_string()],
                agent_token: Some(fixture_material("portal-agent")),
                access_client_id: Some("access-client-id".to_string()),
                access_client_secret: Some(fixture_material("access-material")),
                request_timeout: Duration::from_secs(1),
                user_agent: "cloudflare-mcp-test".to_string(),
            })
            .expect("portal client"),
        );
        CloudflareMcp::new(
            client,
            Some("acct-1".to_string()),
            Some("zone-1".to_string()),
            true,
            ApiTokenSource::Config,
            "x-cloudflare-api-token".to_string(),
            true,
            read_only_mode,
            true,
            portal_agent,
            elicitation_config,
            Arc::new(ToolListTracker::default()),
            session_manager,
            ResumeMode::Historyless,
        )
    }

    fn test_server(read_only_mode: bool) -> CloudflareMcp {
        test_server_with_elicitation(
            read_only_mode,
            ElicitationConfig {
                enabled: false,
                required_tools: Vec::new(),
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
        )
    }

    fn test_server_curated_only() -> CloudflareMcp {
        let mut server = test_server(false);
        server.api_parity_enabled = false;
        server.tool_inventory_policy = ToolInventoryPolicy::strict();
        server
    }

    fn test_parts_with_headers(headers: &[(&str, &str)]) -> Parts {
        let mut request = Request::builder().uri("http://localhost/mcp");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let (parts, _) = request.body(()).expect("request").into_parts();
        parts
    }

    #[test]
    fn fallback_request_parts_are_available_for_stdio_tool_calls() {
        let mut extensions = Extensions::default();

        ensure_request_parts_extension(&mut extensions);

        let parts = extensions
            .get::<Parts>()
            .expect("fallback request parts should be attached");
        assert_eq!(parts.uri.to_string(), "mcp://tool-call/");
    }

    #[test]
    fn existing_request_parts_are_preserved_for_http_tool_calls() {
        let mut extensions = Extensions::default();
        extensions.insert(test_parts_with_headers(&[("x-request-id", "req-123")]));

        ensure_request_parts_extension(&mut extensions);

        let parts = extensions
            .get::<Parts>()
            .expect("existing request parts should remain attached");
        assert_eq!(
            parts
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("req-123")
        );
    }

    #[test]
    fn strict_inventory_denies_unregistered_tools() {
        let server = test_server(false);
        assert!(!server.tool_inventory_policy.include_unregistered);
        assert!(!server.tool_inventory.is_allowed(
            "unknown_tool",
            mcp_toolkit_core::tool_inventory::ToolOperation::List,
            &server.tool_inventory_policy,
        ));
        assert!(!server.tool_inventory.is_allowed(
            "unknown_tool",
            mcp_toolkit_core::tool_inventory::ToolOperation::Call,
            &server.tool_inventory_policy,
        ));
    }

    #[test]
    fn advertises_latest_mcp_protocol_version() {
        let server = test_server(false);
        assert_eq!(server.get_info().protocol_version.to_string(), "2025-11-25");
    }

    #[test]
    fn inventory_registration_covers_router_surface() {
        let server = test_server(false);
        let inventory = build_tool_inventory().expect("inventory");
        let expected = inventory
            .filter_tools(
                server.tool_router.list_all(),
                mcp_toolkit_core::tool_inventory::ToolOperation::List,
                &server.tool_inventory_policy,
                |tool| tool.name.as_ref(),
            )
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect::<HashSet<_>>();
        let actual = server.tool_names().into_iter().collect::<HashSet<_>>();
        assert_eq!(actual, expected);
        for name in &actual {
            assert!(server.tool_inventory.is_allowed(
                name,
                mcp_toolkit_core::tool_inventory::ToolOperation::Call,
                &server.tool_inventory_policy,
            ));
        }
    }

    #[test]
    fn restored_recovery_tool_contract_stays_present() {
        let server = test_server(false);
        let tools = server.tool_names().into_iter().collect::<HashSet<_>>();
        let required = [
            "access_get_app",
            "analytics_engine_describe_schema",
            "analytics_engine_list_datasets",
            "analytics_engine_query",
            "analytics_engine_validate_query",
            "access_verify_hostname_gate",
            "apply_access_allowlist",
            "bindings_discover",
            "bulk_redirects_attach_list_to_ruleset",
            "bulk_redirects_create_list",
            "bulk_redirects_get_list",
            "bulk_redirects_get_operation",
            "bulk_redirects_get_ruleset",
            "bulk_redirects_import_items",
            "bulk_redirects_list_items",
            "bulk_redirects_list_lists",
            "bulk_redirects_update_list",
            "capabilities_check",
            "connector_control",
            "d1_apply_migrations",
            "d1_delete_database",
            "d1_execute_write",
            "d1_get_database",
            "d1_inspect_schema",
            "d1_list_databases",
            "d1_query_read_only",
            "d1_rename_database",
            "d1_validate_query",
            "email_routing_get_address",
            "email_routing_get_catch_all",
            "email_routing_get_dns",
            "email_routing_get_rule",
            "email_routing_get_settings",
            "email_routing_list_addresses",
            "email_routing_list_rules",
            "emergency_unpublish",
            "ensure_tunnel",
            "generate_tunnel_ingress",
            "health",
            "list_access_apps",
            "list_access_policies",
            "list_dns_records",
            "list_tunnels",
            "lock_first_publish",
            "pages_deploy_directory",
            "pages_ensure_domain",
            "pages_get_deployment",
            "pages_get_domain",
            "pages_get_project",
            "pages_list_deployments",
            "pages_list_domains",
            "pages_list_projects",
            "pages_retry_deployment",
            "pages_retry_domain_validation",
            "pages_rollback_deployment",
            "pages_trigger_deployment",
            "pages_update_project",
            "publish_preflight",
            "queues_get",
            "queues_get_metrics",
            "queues_health",
            "queues_list_consumers",
            "queues_list",
            "replace_access_policies",
            "upsert_access_app",
            "upsert_dns_cname",
            "verify_dns_route",
            "verify_http_gate",
            "workers_get_script_settings",
            "workers_list_scripts",
            "workers_list_tails",
            "workers_observability_list_keys",
            "workers_observability_list_values",
            "workers_observability_query_events",
        ];
        for name in required {
            assert!(tools.contains(name), "{name} missing from tool inventory");
        }
    }

    #[test]
    fn read_only_policy_hides_mutating_tools() {
        let server = test_server(true);
        assert!(server.tool_inventory_policy.read_only_only);
        assert!(server.tool_inventory.is_allowed(
            "list_tunnels",
            mcp_toolkit_core::tool_inventory::ToolOperation::List,
            &server.tool_inventory_policy,
        ));
        assert!(!server.tool_inventory.is_allowed(
            "ensure_tunnel",
            mcp_toolkit_core::tool_inventory::ToolOperation::List,
            &server.tool_inventory_policy,
        ));
        assert!(!server.tool_inventory.is_allowed(
            "ensure_tunnel",
            mcp_toolkit_core::tool_inventory::ToolOperation::Call,
            &server.tool_inventory_policy,
        ));
    }

    #[test]
    fn curated_only_policy_hides_api_parity_tools() {
        let server = test_server_curated_only();
        assert!(!server.api_parity_enabled);
        assert!(
            !server
                .tool_names()
                .iter()
                .any(|name| name.starts_with("api_"))
        );
        assert!(!server.tool_inventory.is_allowed(
            "api_read",
            mcp_toolkit_core::tool_inventory::ToolOperation::List,
            &server.tool_inventory_policy,
        ));
        assert!(!server.tool_inventory.is_allowed(
            "api_read",
            mcp_toolkit_core::tool_inventory::ToolOperation::Call,
            &server.tool_inventory_policy,
        ));
        assert!(server.tool_inventory.is_allowed(
            "r2_get_object",
            mcp_toolkit_core::tool_inventory::ToolOperation::List,
            &server.tool_inventory_policy,
        ));
    }

    #[test]
    fn elicitation_policy_targets_configured_tools_only() {
        let server = test_server_with_elicitation(
            false,
            ElicitationConfig {
                enabled: true,
                required_tools: vec!["lock_first_publish".to_string()],
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
        );
        assert!(
            server.call_requires_elicitation(
                &CallToolRequestParams::new("lock_first_publish").with_arguments(
                    serde_json::from_value(json!({
                        "hostname": "preview.example.com",
                        "target": "abc.cfargotunnel.com",
                        "dry_run": false,
                    }))
                    .expect("args"),
                )
            )
        );
        assert!(
            !server.call_requires_elicitation(
                &CallToolRequestParams::new("list_dns_records").with_arguments(
                    serde_json::from_value(json!({
                        "zone_id": "zone-1",
                    }))
                    .expect("args"),
                )
            )
        );
    }

    #[test]
    fn elicitation_apply_only_skips_dry_run_calls() {
        let server = test_server_with_elicitation(
            false,
            ElicitationConfig {
                enabled: true,
                required_tools: vec!["lock_first_publish".to_string()],
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
        );
        assert!(
            !server.call_requires_elicitation(
                &CallToolRequestParams::new("lock_first_publish").with_arguments(
                    serde_json::from_value(json!({
                        "hostname": "preview.example.com",
                        "target": "abc.cfargotunnel.com",
                        "dry_run": true,
                    }))
                    .expect("args"),
                )
            )
        );
    }

    #[test]
    fn elicitation_gates_account_api_token_apply_but_not_reads() {
        let server = test_server_with_elicitation(
            false,
            ElicitationConfig {
                enabled: true,
                required_tools: vec!["account_api_tokens".to_string()],
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
        );
        assert!(
            !server.call_requires_elicitation(
                &CallToolRequestParams::new("account_api_tokens").with_arguments(
                    serde_json::from_value(json!({
                        "action": "list_permission_groups",
                    }))
                    .expect("args"),
                )
            )
        );
        assert!(
            !server.call_requires_elicitation(
                &CallToolRequestParams::new("account_api_tokens").with_arguments(
                    serde_json::from_value(json!({
                        "action": "create",
                        "body": {"name": "deploy-token", "policies": []},
                        "dry_run": true,
                    }))
                    .expect("args"),
                )
            )
        );
        assert!(
            server.call_requires_elicitation(
                &CallToolRequestParams::new("account_api_tokens").with_arguments(
                    serde_json::from_value(json!({
                        "action": "create",
                        "body": {"name": "deploy-token", "policies": []},
                        "dry_run": false,
                    }))
                    .expect("args"),
                )
            )
        );
    }

    #[test]
    fn sanitized_header_trims_and_limits_context_values() {
        let long_value = "x".repeat(300);
        let parts = test_parts_with_headers(&[("x-correlation-id", &long_value)]);
        let sanitized =
            super::sanitized_header(&parts, "x-correlation-id").expect("sanitized header");
        assert!(sanitized.len() <= super::MAX_CONTEXT_VALUE_CHARS);
    }

    #[test]
    fn request_argument_keys_sanitizes_and_limits_per_key_size() {
        let args: rmcp::model::JsonObject = serde_json::from_value(json!({
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true,
            "safe_key": "value",
            "key\nwith\nnewlines": "value"
        }))
        .expect("args");
        let keys = super::request_argument_keys(Some(&args));
        assert!(keys.iter().all(|value| !value.is_empty()));
        assert!(
            keys.iter()
                .all(|value| value.len() <= super::MAX_ELICITATION_ARGUMENT_KEY_CHARS)
        );
    }

    #[test]
    fn build_elicitation_prompt_omits_excess_argument_keys() {
        let keys = (0..(super::MAX_ELICITATION_ARGUMENT_KEYS + 3))
            .map(|index| format!("key_{index}"))
            .collect::<Vec<_>>();
        let prompt = super::build_elicitation_prompt(
            "lock_first_publish",
            false,
            &super::ElicitationRequestSummary {
                argument_keys: keys,
                argument_digest: "digest-1234".to_string(),
                argument_preview:
                    "{\"hostname\":\"preview.example.com\",\"target\":\"abc.cfargotunnel.com\"}"
                        .to_string(),
            },
            &super::CorrelationHeaders {
                correlation_id: Some("corr-1".to_string()),
                request_id: None,
            },
        );
        assert!(prompt.contains("omitted for brevity"));
    }

    #[test]
    fn summarize_elicitation_request_digest_is_order_stable() {
        let first: rmcp::model::JsonObject = serde_json::from_value(json!({
            "zeta": {
                "beta": [2, 1],
                "alpha": [
                    {"nested": true, "value": 1},
                    {"value": 2, "nested": false},
                ],
            },
            "alpha": "start",
            "nested": {
                "list": [1, 2, 3],
                "flag": true,
            },
        }))
        .expect("args");
        let second: rmcp::model::JsonObject = serde_json::from_value(json!({
            "alpha": "start",
            "nested": {
                "flag": true,
                "list": [1, 2, 3],
            },
            "zeta": {
                "alpha": [
                    {"value": 1, "nested": true},
                    {"nested": false, "value": 2},
                ],
                "beta": [2, 1],
            },
        }))
        .expect("args");

        let summary_a = super::summarize_elicitation_request(Some(&first));
        let summary_b = super::summarize_elicitation_request(Some(&second));

        assert_eq!(summary_a.argument_digest, summary_b.argument_digest);
        assert_eq!(summary_a.argument_keys, summary_b.argument_keys);
    }
}
