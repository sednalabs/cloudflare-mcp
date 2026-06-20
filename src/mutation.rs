use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::request::Parts;
use mcp_toolkit_auth::auth_context_from_parts;
use mcp_toolkit_observability::{
    sanitize_error_message, sanitize_log_value_opt, sanitize_log_value_with_limit,
};
use rmcp::transport::common::http_header::HEADER_SESSION_ID;
use serde::Serialize;
use serde_json::{Value, json};

use crate::policy::AllowlistMutationMode;
use crate::tunnel::ConnectorControlAction;

const HEADER_X_CORRELATION_ID: &str = "x-correlation-id";
const HEADER_X_REQUEST_ID: &str = "x-request-id";
const DEFAULT_UNKNOWN_ACTOR: &str = "unknown";
const MAX_CONTEXT_VALUE_CHARS: usize = 128;
const MAX_ERROR_CODE_CHARS: usize = 80;

static CORRELATION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MutationPlanStep {
    pub ordinal: u8,
    pub action: &'static str,
    pub side_effect: bool,
    pub target: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MutationPlan {
    pub operation: &'static str,
    pub steps: Vec<MutationPlanStep>,
}

impl MutationPlan {
    pub fn new(operation: &'static str) -> Self {
        Self {
            operation,
            steps: Vec::new(),
        }
    }

    pub fn step(mut self, action: &'static str, side_effect: bool, target: Value) -> Self {
        let ordinal = (self.steps.len().saturating_add(1)).min(u8::MAX as usize) as u8;
        self.steps.push(MutationPlanStep {
            ordinal,
            action,
            side_effect,
            target,
        });
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationAuditCorrelation {
    pub correlation_id: String,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MutationApprovalAudit {
    pub required: bool,
    pub decision: &'static str,
    pub request_digest: String,
    pub client_supports_elicitation: bool,
    pub fail_open_unsupported_client: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationAuditRecord {
    pub correlation: MutationAuditCorrelation,
    pub actor: String,
    pub action: &'static str,
    pub target: Value,
    pub started_at_unix_ms: u128,
    pub completed_at_unix_ms: u128,
    pub dry_run: bool,
    pub outcome: &'static str,
    pub error_code: Option<String>,
    pub approval: Option<MutationApprovalAudit>,
}

#[derive(Debug, Clone)]
pub struct MutationAuditSession {
    correlation: MutationAuditCorrelation,
    actor: String,
    action: &'static str,
    target: Value,
    started_at_unix_ms: u128,
    dry_run: bool,
    approval: Option<MutationApprovalAudit>,
}

impl MutationAuditSession {
    pub fn start(
        parts: Option<&Parts>,
        action: &'static str,
        target: Value,
        dry_run: bool,
    ) -> Self {
        let request_id = parts
            .and_then(|parts| sanitized_header(parts, HEADER_X_REQUEST_ID))
            .or_else(|| {
                sanitize_log_value_opt(
                    std::env::var("OPS_REQUEST_ID").ok().as_deref(),
                    MAX_CONTEXT_VALUE_CHARS,
                )
            });
        let correlation_id = parts
            .and_then(|parts| sanitized_header(parts, HEADER_X_CORRELATION_ID))
            .or_else(|| request_id.clone())
            .unwrap_or_else(generated_correlation_id);
        let session_id = parts.and_then(|parts| sanitized_header(parts, HEADER_SESSION_ID));
        let actor = parts
            .and_then(auth_context_from_parts)
            .map(|context| context.actor)
            .or_else(|| std::env::var("OPS_ACTOR_ID").ok())
            .map(|value| sanitize_log_value_with_limit(&value, MAX_CONTEXT_VALUE_CHARS))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_UNKNOWN_ACTOR.to_string());
        let approval = parts.and_then(|parts| {
            parts
                .extensions
                .get::<MutationApprovalAudit>()
                .cloned()
                .map(|approval| MutationApprovalAudit {
                    request_digest: sanitize_log_value_with_limit(
                        &approval.request_digest,
                        MAX_CONTEXT_VALUE_CHARS,
                    ),
                    ..approval
                })
        });

        Self {
            correlation: MutationAuditCorrelation {
                correlation_id,
                request_id,
                session_id,
            },
            actor,
            action,
            target,
            started_at_unix_ms: now_unix_ms(),
            dry_run,
            approval,
        }
    }

    pub fn finish(self, outcome: &'static str, error_code: Option<&str>) -> MutationAuditRecord {
        let error_code = error_code
            .map(|value| sanitize_error_message(value, MAX_ERROR_CODE_CHARS))
            .map(|value| sanitize_log_value_with_limit(&value, MAX_ERROR_CODE_CHARS))
            .filter(|value| !value.is_empty());
        MutationAuditRecord {
            correlation: self.correlation,
            actor: self.actor,
            action: self.action,
            target: self.target,
            started_at_unix_ms: self.started_at_unix_ms,
            completed_at_unix_ms: now_unix_ms(),
            dry_run: self.dry_run,
            outcome,
            error_code,
            approval: self.approval,
        }
    }
}

pub fn emit_mutation_audit_log(record: &MutationAuditRecord) {
    if record.outcome == "error" {
        tracing::warn!(
            correlation_id = %record.correlation.correlation_id,
            request_id = ?record.correlation.request_id,
            session_id = ?record.correlation.session_id,
            actor = %record.actor,
            action = record.action,
            dry_run = record.dry_run,
            outcome = record.outcome,
            error_code = ?record.error_code,
            "cloudflare mutation audit"
        );
        return;
    }

    tracing::info!(
        correlation_id = %record.correlation.correlation_id,
        request_id = ?record.correlation.request_id,
        session_id = ?record.correlation.session_id,
        actor = %record.actor,
        action = record.action,
        dry_run = record.dry_run,
        outcome = record.outcome,
        "cloudflare mutation audit"
    );
}

pub fn plan_upsert_dns_cname(
    account_id: &str,
    zone_id: &str,
    hostname: &str,
    target: &str,
) -> MutationPlan {
    MutationPlan::new("upsert_dns_cname")
        .step(
            "evaluate_publish_gate",
            false,
            json!({
                "account_id": account_id,
                "hostname": hostname,
            }),
        )
        .step(
            "upsert_dns_cname",
            true,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
                "target": target,
            }),
        )
        .step(
            "verify_route_terminal_state",
            false,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
            }),
        )
}

pub fn plan_upsert_access_app(account_id: &str, hostname: &str, app_name: &str) -> MutationPlan {
    MutationPlan::new("upsert_access_app")
        .step(
            "read_existing_access_app",
            false,
            json!({
                "account_id": account_id,
                "hostname": hostname,
            }),
        )
        .step(
            "upsert_access_app",
            true,
            json!({
                "account_id": account_id,
                "hostname": hostname,
                "app_name": app_name,
            }),
        )
        .step(
            "verify_access_app_terminal_state",
            false,
            json!({
                "account_id": account_id,
                "hostname": hostname,
            }),
        )
}

pub fn plan_replace_access_policies(
    account_id: &str,
    app_id: &str,
    policy_count: usize,
) -> MutationPlan {
    MutationPlan::new("replace_access_policies")
        .step(
            "replace_access_policies",
            true,
            json!({
                "account_id": account_id,
                "app_id": app_id,
                "policy_count": policy_count,
            }),
        )
        .step(
            "verify_policy_write",
            false,
            json!({
                "account_id": account_id,
                "app_id": app_id,
            }),
        )
}

pub fn plan_apply_access_allowlist(
    account_id: &str,
    app_id: &str,
    mode: AllowlistMutationMode,
    requested_principals: &[String],
    target_principals: &[String],
) -> MutationPlan {
    MutationPlan::new("apply_access_allowlist")
        .step(
            "read_current_access_policies",
            false,
            json!({
                "account_id": account_id,
                "app_id": app_id,
            }),
        )
        .step(
            "apply_allowlist_mutation",
            true,
            json!({
                "account_id": account_id,
                "app_id": app_id,
                "mode": mode.as_str(),
                "requested_principals": stable_sorted_list(requested_principals),
                "target_principals": stable_sorted_list(target_principals),
            }),
        )
        .step(
            "readback_access_policies",
            false,
            json!({
                "account_id": account_id,
                "app_id": app_id,
            }),
        )
        .step(
            "validate_policy_invariants",
            false,
            json!({
                "mode": mode.as_str(),
            }),
        )
}

pub fn plan_lock_first_publish(
    account_id: &str,
    zone_id: &str,
    hostname: &str,
    target: &str,
) -> MutationPlan {
    MutationPlan::new("lock_first_publish")
        .step(
            "evaluate_publish_gate",
            false,
            json!({
                "account_id": account_id,
                "hostname": hostname,
            }),
        )
        .step(
            "apply_dns_route",
            true,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
                "target": target,
            }),
        )
        .step(
            "verify_publish_terminal_state",
            false,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
            }),
        )
}

pub fn plan_emergency_unpublish(zone_id: &str, hostname: &str) -> MutationPlan {
    MutationPlan::new("emergency_unpublish")
        .step(
            "read_existing_dns_route",
            false,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
            }),
        )
        .step(
            "disable_dns_route",
            true,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
            }),
        )
        .step(
            "verify_unpublished_terminal_state",
            false,
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
            }),
        )
}

pub fn plan_ensure_tunnel(account_id: &str, tunnel_name: &str) -> MutationPlan {
    MutationPlan::new("ensure_tunnel")
        .step(
            "list_tunnels",
            false,
            json!({
                "account_id": account_id,
                "tunnel_name": tunnel_name,
            }),
        )
        .step(
            "create_tunnel_if_missing",
            true,
            json!({
                "account_id": account_id,
                "tunnel_name": tunnel_name,
            }),
        )
        .step(
            "verify_tunnel_identity",
            false,
            json!({
                "account_id": account_id,
                "tunnel_name": tunnel_name,
            }),
        )
}

pub fn plan_connector_control(connector_key: &str, action: ConnectorControlAction) -> MutationPlan {
    MutationPlan::new("connector_control")
        .step(
            "read_connector_runtime_state",
            false,
            json!({
                "connector_key": connector_key,
                "action": action.as_str(),
            }),
        )
        .step(
            "apply_connector_control",
            true,
            json!({
                "connector_key": connector_key,
                "action": action.as_str(),
            }),
        )
        .step(
            "verify_connector_terminal_state",
            false,
            json!({
                "connector_key": connector_key,
                "action": action.as_str(),
            }),
        )
}

pub fn plan_patch_worker_settings(
    account_id: &str,
    script_name: &str,
    patch_keys: &[String],
) -> MutationPlan {
    MutationPlan::new("patch_worker_settings")
        .step(
            "read_current_worker_settings",
            false,
            json!({
                "account_id": account_id,
                "script_name": script_name,
            }),
        )
        .step(
            "patch_worker_settings",
            true,
            json!({
                "account_id": account_id,
                "script_name": script_name,
                "patch_keys": stable_sorted_list(patch_keys),
            }),
        )
        .step(
            "readback_worker_settings",
            false,
            json!({
                "account_id": account_id,
                "script_name": script_name,
            }),
        )
        .step(
            "verify_worker_settings_readback",
            false,
            json!({
                "script_name": script_name,
            }),
        )
}

pub fn plan_upload_worker_script(
    account_id: &str,
    script_name: &str,
    upload: Value,
) -> MutationPlan {
    MutationPlan::new("workers_upload_script")
        .step(
            "prepare_worker_script_upload",
            false,
            json!({
                "account_id": account_id,
                "script_name": script_name,
                "upload": upload,
            }),
        )
        .step(
            "upload_worker_script",
            true,
            json!({
                "account_id": account_id,
                "script_name": script_name,
            }),
        )
        .step(
            "readback_worker_settings",
            false,
            json!({
                "account_id": account_id,
                "script_name": script_name,
            }),
        )
        .step(
            "verify_worker_upload_readback",
            false,
            json!({
                "script_name": script_name,
            }),
        )
}

pub fn plan_cache_mutation(operation: &'static str, zone_id: &str, target: Value) -> MutationPlan {
    MutationPlan::new(operation)
        .step(
            "read_or_prepare_cache_state",
            false,
            json!({
                "zone_id": zone_id,
                "target": target,
            }),
        )
        .step(
            "apply_cache_mutation",
            true,
            json!({
                "zone_id": zone_id,
                "target": target,
            }),
        )
        .step(
            "readback_cache_state",
            false,
            json!({
                "zone_id": zone_id,
                "target": target,
            }),
        )
}

fn stable_sorted_list(values: &[String]) -> Vec<String> {
    let mut normalized = values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn sanitized_header(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| sanitize_log_value_opt(Some(value), MAX_CONTEXT_VALUE_CHARS))
}

fn generated_correlation_id() -> String {
    let sequence = CORRELATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("cfmcp-{}-{sequence}", now_unix_ms())
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use axum::http::{Request, request::Parts};
    use mcp_toolkit_auth::AuthContext;
    use serde_json::json;

    use super::{MutationApprovalAudit, MutationAuditSession, plan_apply_access_allowlist};
    use crate::policy::AllowlistMutationMode;

    fn test_parts() -> Parts {
        let request = Request::builder()
            .uri("http://localhost/mcp")
            .header("x-correlation-id", "corr-1")
            .header("x-request-id", "req-1")
            .body(())
            .expect("request");
        let (mut parts, _) = request.into_parts();
        parts.extensions.insert(AuthContext {
            actor: "agent\ntest".to_string(),
            scopes: Vec::new(),
            roles: Vec::new(),
            claims: json!({}),
            azp: None,
            subject: None,
            token_ref: "ref-1".to_string(),
            raw_token: "raw".to_string(),
        });
        parts
    }

    #[test]
    fn allowlist_plans_have_stable_step_order_for_equivalent_inputs() {
        let plan_a = plan_apply_access_allowlist(
            "acct-1",
            "app-1",
            AllowlistMutationMode::Replace,
            &[
                "beta@example.com".to_string(),
                "alpha@example.com".to_string(),
            ],
            &[
                "alpha@example.com".to_string(),
                "beta@example.com".to_string(),
            ],
        );
        let plan_b = plan_apply_access_allowlist(
            "acct-1",
            "app-1",
            AllowlistMutationMode::Replace,
            &[
                "alpha@example.com".to_string(),
                "beta@example.com".to_string(),
            ],
            &[
                "beta@example.com".to_string(),
                "alpha@example.com".to_string(),
            ],
        );
        assert_eq!(plan_a.steps, plan_b.steps);
    }

    #[test]
    fn audit_context_is_sanitized_and_uses_correlation_header() {
        let parts = test_parts();
        let session = MutationAuditSession::start(
            Some(&parts),
            "lock_first_publish",
            json!({"hostname": "preview.example.com"}),
            true,
        );
        let record = session.finish("planned", None);
        assert_eq!(record.correlation.correlation_id, "corr-1");
        assert_eq!(record.correlation.request_id.as_deref(), Some("req-1"));
        assert_eq!(record.actor, "agenttest");
    }

    #[test]
    fn mutation_audit_session_captures_approval_marker() {
        let mut parts = test_parts();
        parts.extensions.insert(MutationApprovalAudit {
            required: true,
            decision: "approved",
            request_digest: "expected-digest-value".to_string(),
            client_supports_elicitation: true,
            fail_open_unsupported_client: false,
        });

        let session = MutationAuditSession::start(
            Some(&parts),
            "lock_first_publish",
            json!({"hostname": "preview.example.com"}),
            false,
        );
        let record = session.finish("success", None);
        let approval = record.approval.expect("approval marker");

        assert!(approval.required);
        assert_eq!(approval.decision, "approved");
        assert_eq!(approval.request_digest, "expected-digest-value");
        assert!(approval.client_supports_elicitation);
        assert!(!approval.fail_open_unsupported_client);
    }
}
