use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;

use crate::access_app::{
    AccessAppAction, AccessAppConflict, AccessAppValidationError, plan_access_app_upsert,
    validate_access_app_readback,
};
use crate::api_catalog::{
    ApiCatalogError, ApiOperationSearch, find_operation, mutation_confirmation_token,
    operation_allowed_by_default, operation_detail, parse_risk, parse_scope, path_parameter_names,
    query_pairs, render_path, resolved_path_params, search_operations,
    status as api_catalog_status, validate_required_query,
};
use crate::cache::{
    CachePurgePayload, CacheResourceAction, CacheRulePhase, CacheRulesAction, CacheValidationError,
    CacheZoneSettingAction, purge_confirmation_token, replace_rules_confirmation_token,
};
use crate::cloudflare::{
    AccessAppUpsertRequest, AccessPolicyWrite, BulkRedirectItemWrite, CacheRule, CacheRuleset,
    DnsRecordUpsertRequest, PagesDeploymentTriggerRequest,
};
use crate::dns_route::{
    DnsRouteConflict, DnsRouteVerificationState, plan_dns_route_reconciliation, verify_dns_route,
};
use crate::mutation::{
    MutationAuditSession, MutationPlan, emit_mutation_audit_log, plan_apply_access_allowlist,
    plan_cache_mutation, plan_connector_control, plan_emergency_unpublish, plan_ensure_tunnel,
    plan_lock_first_publish, plan_patch_worker_settings, plan_replace_access_policies,
    plan_upload_worker_script, plan_upsert_access_app, plan_upsert_dns_cname,
};
use crate::pages_deploy::{
    MAX_PAGES_ASSET_COUNT_DEFAULT, PagesDirectoryInspectOptions,
    inspect_pages_directory_with_options,
};
use crate::policy::{
    AllowlistMutationMode, build_managed_allowlist_policy, canonicalize_requested_principals,
    evaluate_mutation_invariants, extract_allowlist_principals, plan_target_principals,
};
use crate::portal::PortalAgentError;
use crate::publish::{
    emergency_unpublish_trace, evaluate_publish_gate, lock_first_publish_trace, preflight_trace,
};
use crate::server::CloudflareMcp;
use crate::sql_preflight::{analytics_engine_schema_hints, validate_sql_against_schema};
use crate::tunnel::{
    ConnectorControlAction, IngressRule, apply_connector_control, build_ingress_config,
    select_existing_tunnel, tunnel_identity, tunnel_target,
};
use crate::verification::{
    ExpectedVerificationState, VerificationState, classify_http_result, now_unix_ms,
    timeout_result, transport_error_result,
};
use crate::worker_upload::{
    WorkerUploadBody, WorkerUploadError, WorkerUploadInput, build_worker_upload,
};
use mcp_toolkit_core::tool_inventory::{ToolOperation, ToolSearchFilter, ToolSearchResponse};
use mcp_toolkit_policy_core::{RestrictedSqlError, classify_restricted_sql};

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct HealthArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindToolsArgs {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub include_schema: bool,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct ApiParityStatusArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiFindOperationsArgs {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
    #[serde(default)]
    pub include_deprecated: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiGetOperationArgs {
    pub operation_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiPrepareCallArgs {
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
    #[serde(default)]
    pub include_deprecated: bool,
    #[serde(default)]
    pub path_params: BTreeMap<String, String>,
    #[serde(default)]
    pub query_params: BTreeMap<String, Value>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiReadArgs {
    pub operation_id: String,
    #[serde(default)]
    pub path_params: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, Value>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiMutateArgs {
    pub operation_id: String,
    #[serde(default)]
    pub path_params: BTreeMap<String, String>,
    #[serde(default)]
    pub query: BTreeMap<String, Value>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccountBillingUsageArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub metric: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WafRulesetSummaryArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub phases: Vec<String>,
    #[serde(default = "default_true")]
    pub include_rules: bool,
    #[serde(default)]
    pub include_raw: bool,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WafSecurityEventsSummaryArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default = "default_waf_window_hours")]
    pub window_hours: u32,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default = "default_waf_group_by")]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default = "default_waf_limit")]
    pub limit: u32,
    #[serde(default = "default_waf_sample_limit")]
    pub sample_limit: u32,
    #[serde(default)]
    pub include_query: bool,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WafRuleActivityArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    pub rule_id: String,
    #[serde(default)]
    pub phases: Vec<String>,
    #[serde(default = "default_waf_window_hours")]
    pub window_hours: u32,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default = "default_waf_sample_limit")]
    pub sample_limit: u32,
    #[serde(default)]
    pub include_query: bool,
    #[serde(default)]
    pub include_raw: bool,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WafRulesetChangeArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub edits: Vec<WafRuleEdit>,
    #[serde(default)]
    pub max_rules: Option<usize>,
    #[serde(default)]
    pub stale_list_refs: Vec<String>,
    #[serde(default)]
    pub empty_list_refs: Vec<String>,
    #[serde(default = "default_true")]
    pub fail_on_stale_lists: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WafRulesetApplyArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub edits: Vec<WafRuleEdit>,
    #[serde(default)]
    pub max_rules: Option<usize>,
    #[serde(default)]
    pub stale_list_refs: Vec<String>,
    #[serde(default)]
    pub empty_list_refs: Vec<String>,
    #[serde(default = "default_true")]
    pub fail_on_stale_lists: bool,
    pub confirmation_token: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default = "default_true")]
    pub readback_security_events: bool,
    #[serde(default = "default_waf_lifecycle_readback_hours")]
    pub readback_window_hours: u32,
    #[serde(default = "default_waf_lifecycle_readback_samples")]
    pub readback_sample_limit: u32,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WafRuleEdit {
    pub operation: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub rule_ref: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub expression: Option<String>,
    #[serde(default)]
    pub rule_action: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub action_parameters: Option<Value>,
    #[serde(default)]
    pub before_rule_id: Option<String>,
    #[serde(default)]
    pub after_rule_id: Option<String>,
    #[serde(default)]
    pub index: Option<usize>,
}

fn default_waf_window_hours() -> u32 {
    24
}

fn default_waf_limit() -> u32 {
    20
}

fn default_waf_sample_limit() -> u32 {
    10
}

fn default_waf_lifecycle_readback_hours() -> u32 {
    24
}

fn default_waf_lifecycle_readback_samples() -> u32 {
    5
}

fn default_waf_group_by() -> Vec<String> {
    ["action", "source", "host", "path", "country", "hour"]
        .iter()
        .map(|value| value.to_string())
        .collect()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GraphqlAnalyticsQueryArgs {
    pub query: String,
    #[serde(default)]
    pub variables: BTreeMap<String, Value>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccountApiTokensArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub action: String,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub query: BTreeMap<String, Value>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccountApiTokenPermissionPlanArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub policy_index: Option<usize>,
    #[serde(default, alias = "add", alias = "add_scopes")]
    pub add_permissions: Vec<String>,
    #[serde(default, alias = "remove", alias = "remove_scopes")]
    pub remove_permissions: Vec<String>,
    #[serde(default)]
    pub current_token: Option<Value>,
    #[serde(default)]
    pub permission_groups: Option<Value>,
    #[serde(default)]
    pub include_catalog: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListTunnelsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDnsRecordsArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1ListDatabasesArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1DatabaseArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1RenameDatabaseArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    pub name: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1DeleteDatabaseArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1InspectSchemaArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    #[serde(default = "default_true")]
    pub include_columns: bool,
    #[serde(default)]
    pub include_tables: Vec<String>,
    #[serde(default)]
    pub include_table_pattern: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1QueryArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    pub sql: String,
    #[serde(default)]
    pub params: Vec<Value>,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1ValidateQueryArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    pub sql: String,
    #[serde(default)]
    pub include_query_plan: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct R2GetObjectArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub bucket_name: String,
    pub object_key: String,
    #[serde(default)]
    pub range: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
    #[serde(default = "default_r2_response_mode")]
    pub response_mode: String,
    #[serde(default)]
    pub output_path: Option<String>,
    #[serde(default)]
    pub persist_output_path: bool,
    #[serde(default)]
    pub create_parent_dirs: bool,
    #[serde(default)]
    pub allow_large_download: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct R2InspectObjectArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub bucket_name: String,
    pub object_key: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct R2PutObjectArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub bucket_name: String,
    pub object_key: String,
    #[serde(default)]
    pub content_text: Option<String>,
    #[serde(default)]
    pub content_base64: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_r2_response_mode() -> String {
    "auto".to_string()
}

const R2_INLINE_DEFAULT_MAX_BYTES: usize = 1024;
const R2_INLINE_HARD_MAX_BYTES: usize = 256 * 1024;
const R2_FILE_DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpsertDnsCnameArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    pub hostname: String,
    pub target: String,
    #[serde(default)]
    pub proxied: Option<bool>,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub override_publish_guard: bool,
    #[serde(default)]
    pub override_reason: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAccessAppsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpsertAccessAppArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub hostname: String,
    pub app_name: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetAccessAppArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub app_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyAccessHostnameGateArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub hostname: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAccessPoliciesArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub app_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReplaceAccessPoliciesArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub app_id: String,
    pub policies: Vec<AccessPolicyWrite>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyAccessAllowlistArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub app_id: String,
    #[serde(default = "default_allowlist_mode")]
    pub mode: String,
    pub requested_principals: Vec<String>,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_allowlist_mode() -> String {
    "replace".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListWorkersArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub tags: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetWorkerSettingsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub script_name: String,
    #[serde(default)]
    pub binding_name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkersUploadScriptArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub script_name: String,
    #[serde(default)]
    pub main_module: Option<String>,
    #[serde(default)]
    pub script_path: Option<String>,
    #[serde(default)]
    pub script_content: Option<String>,
    #[serde(default)]
    pub script_content_base64: Option<String>,
    #[serde(default)]
    pub multipart_path: Option<String>,
    #[serde(default = "default_empty_object")]
    pub metadata: Value,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CapabilitiesCheckArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub expected_account_id: Option<String>,
    #[serde(default)]
    pub expected_zone_id: Option<String>,
    #[serde(default)]
    pub expected_zone_name: Option<String>,
    #[serde(default)]
    pub require_explicit_zone_id: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesListProjectsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesProjectArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesUpdateProjectArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    pub settings: Value,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesListDeploymentsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesDeploymentArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    pub deployment_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesDeploymentActionArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    pub deployment_id: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesTriggerDeploymentArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub commit_hash: Option<String>,
    #[serde(default)]
    pub commit_message: Option<String>,
    #[serde(default)]
    pub commit_dirty: Option<bool>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesDeployDirectoryArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    pub directory: String,
    #[serde(default)]
    pub project_root: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub commit_hash: Option<String>,
    #[serde(default)]
    pub commit_message: Option<String>,
    #[serde(default)]
    pub commit_dirty: Option<bool>,
    #[serde(default)]
    pub skip_caching: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub max_files: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesDomainArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    pub domain_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagesEnsureDomainArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub project_name: String,
    pub domain_name: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1ExecuteWriteArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    pub sql: String,
    #[serde(default)]
    pub params: Vec<Value>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct D1ApplyMigrationsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub database_id: String,
    pub migrations_directory: String,
    #[serde(default)]
    pub migrations_table: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyticsEngineQueryArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub sql: String,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyticsEngineValidateQueryArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub sql: String,
    #[serde(default = "default_true")]
    pub include_dataset_readback: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyticsEngineListDatasetsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueuesListArgs {
    #[serde(default)]
    pub account_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueueArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub queue_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueueHealthArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub queue_id: String,
    #[serde(default = "default_true")]
    pub include_dlq: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkersObservabilityQueryEventsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub script_name: Option<String>,
    #[serde(default)]
    pub datasets: Vec<String>,
    #[serde(default)]
    pub filters: Vec<Value>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub timeframe: Option<WorkersObservabilityTimeframe>,
    #[serde(default)]
    pub lookback_minutes: Option<u64>,
    #[serde(default)]
    pub query_id: Option<String>,
    #[serde(default)]
    pub dry: Option<bool>,
    #[serde(default)]
    pub view: Option<String>,
    #[serde(default)]
    pub needle: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkersObservabilityListKeysArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub script_name: Option<String>,
    #[serde(default)]
    pub datasets: Vec<String>,
    #[serde(default)]
    pub filters: Vec<Value>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub timeframe: Option<WorkersObservabilityTimeframe>,
    #[serde(default)]
    pub lookback_minutes: Option<u64>,
    #[serde(default)]
    pub needle: Option<Value>,
    #[serde(default, rename = "keyNeedle")]
    pub key_needle: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkersObservabilityListValuesArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub key: String,
    #[serde(default)]
    pub script_name: Option<String>,
    #[serde(default)]
    pub datasets: Vec<String>,
    #[serde(default)]
    pub filters: Vec<Value>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default, rename = "type")]
    pub value_type: Option<String>,
    #[serde(default)]
    pub timeframe: Option<WorkersObservabilityTimeframe>,
    #[serde(default)]
    pub lookback_minutes: Option<u64>,
    #[serde(default)]
    pub needle: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct WorkersObservabilityTimeframe {
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkersListTailsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub script_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmailRoutingZoneArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmailRoutingListRulesArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmailRoutingRuleArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub rule_identifier: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmailRoutingListAddressesArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmailRoutingAddressArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub destination_address_identifier: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BindingsDiscoverArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default = "default_true")]
    pub include_workers: bool,
    #[serde(default = "default_true")]
    pub include_pages: bool,
    #[serde(default)]
    pub name_contains: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectsListArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub include_non_redirect: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectListArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub list_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectListItemsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub list_id: String,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectCreateListArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectUpdateListArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub list_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectImportItemsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub list_id: String,
    #[serde(default = "default_bulk_redirect_import_mode")]
    pub mode: String,
    pub redirects: Vec<BulkRedirectItemWrite>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectOperationArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub operation_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectRulesetArgs {
    #[serde(default)]
    pub account_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BulkRedirectAttachListArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub list_name: String,
    #[serde(default)]
    pub rule_description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_bulk_redirect_import_mode() -> String {
    "append".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkerBindingExpectation {
    pub name: String,
    #[serde(default)]
    pub binding_type: Option<String>,
    #[serde(default = "default_binding_field")]
    pub field: String,
    #[serde(default)]
    pub value: Option<Value>,
}

fn default_binding_field() -> String {
    "text".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchWorkerSettingsArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub script_name: String,
    pub settings_patch: Value,
    #[serde(default)]
    pub expect_binding: Option<WorkerBindingExpectation>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CachePurgeArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default)]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub payload: CachePurgePayload,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CacheZoneSettingArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub action: String,
    pub setting_id: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CacheRulesArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    #[serde(default = "default_cache_rules_phase")]
    pub phase: String,
    pub action: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub rule: Option<Value>,
    #[serde(default)]
    pub rules: Option<Vec<Value>>,
    #[serde(default)]
    pub confirmation_token: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_cache_rules_phase() -> String {
    "request".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CacheResourceArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub action: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PublishPreflightArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub override_publish_guard: bool,
    #[serde(default)]
    pub override_reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LockFirstPublishArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub zone_id: Option<String>,
    pub hostname: String,
    pub target: String,
    #[serde(default)]
    pub proxied: Option<bool>,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub override_publish_guard: bool,
    #[serde(default)]
    pub override_reason: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmergencyUnpublishArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EnsureTunnelArgs {
    #[serde(default)]
    pub account_id: Option<String>,
    pub tunnel_name: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngressRuleObjectArgs {
    #[serde(default)]
    pub hostname: Option<String>,
    pub service: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum IngressRuleArgs {
    Object(IngressRuleObjectArgs),
    Text(String),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateTunnelIngressArgs {
    pub tunnel_id: String,
    pub tunnel_name: String,
    pub rules: Vec<IngressRuleArgs>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConnectorControlArgs {
    pub connector_key: String,
    pub action: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyDnsRouteArgs {
    #[serde(default)]
    pub zone_id: Option<String>,
    pub hostname: String,
    pub target: String,
    #[serde(default)]
    pub proxied: Option<bool>,
    #[serde(default)]
    pub ttl: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyHttpGateArgs {
    pub url: String,
    #[serde(default = "default_expected_probe_state")]
    pub expected_state: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortalAgentRequestArgs {
    pub url: String,
    #[serde(default = "default_portal_method")]
    pub method: String,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default = "default_true")]
    pub use_agent_token: bool,
    #[serde(default)]
    pub use_access_service_token: bool,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_portal_method() -> String {
    "POST".to_string()
}

fn default_true() -> bool {
    true
}

fn default_empty_object() -> Value {
    Value::Object(Map::new())
}

fn default_expected_probe_state() -> String {
    "access_gated".to_string()
}

#[tool_router(router = tool_router_cloudflare, vis = "pub")]
impl CloudflareMcp {
    #[tool(
        name = "health",
        description = "Return cloudflare-mcp runtime health summary."
    )]
    async fn cloudflare_health(
        &self,
        Parameters(_): Parameters<HealthArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let mut elicitation_required_tools = self
            .elicitation_policy
            .required_tools
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        elicitation_required_tools.sort();
        Ok(CallToolResult::structured(json!({
            "ok": true,
            "auth_enabled": self.auth_enabled,
            "read_only_mode": self.read_only_mode,
            "api_parity_enabled": self.api_parity_enabled,
            "elicitation": {
                "enabled": self.elicitation_policy.enabled,
                "apply_only": self.elicitation_policy.apply_only,
                "required_tools": elicitation_required_tools,
            },
            "has_api_token": self.has_api_token,
            "portal_agent": {
                "has_agent_token": self.has_portal_agent_token,
                "has_access_service_token": self.has_portal_access_service_token,
                "allowed_url_prefixes": self.portal_agent.allowed_url_prefixes(),
            },
            "default_account_id": self.default_account_id,
            "default_zone_id": self.default_zone_id,
            "parity_target": "cloudflared",
            "non_goal": "third-party cloudflare mcp ecosystem parity"
        })))
    }

    #[tool(
        name = "find_tools",
        description = "Search Cloudflare MCP tools by keyword, group, and read-only status. Use this for non-hosted deferred-loading clients, or to produce a narrow OpenAI allowed_tools list before loading full schemas."
    )]
    async fn cloudflare_find_tools(
        &self,
        Parameters(args): Parameters<FindToolsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let limit = args.limit.unwrap_or(20).clamp(1, 100);
        let filter = ToolSearchFilter {
            query: args.query.clone(),
            group: args.group.clone(),
            read_only: args.read_only,
            limit: Some(limit),
        };
        let mut results =
            self.tool_inventory
                .search(&filter, ToolOperation::List, &self.tool_inventory_policy);
        let api_results = if self.api_parity_enabled
            && args
                .group
                .as_deref()
                .is_none_or(|group| group.eq_ignore_ascii_case("api"))
        {
            let remaining = limit.saturating_sub(results.len()).max(1);
            search_operations(ApiOperationSearch {
                query: args.query.as_deref(),
                tag: None,
                method: None,
                scope: None,
                risk: None,
                include_deprecated: false,
                limit: remaining,
            })
            .into_iter()
            .filter(|operation| {
                args.read_only.is_none_or(|read_only| {
                    operation.method.eq_ignore_ascii_case("GET") == read_only
                })
            })
            .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if args.group.is_none() && query_mentions_waf(args.query.as_deref()) {
            let waf_filter = ToolSearchFilter {
                query: None,
                group: Some("waf".to_string()),
                read_only: args.read_only,
                limit: Some(5),
            };
            for result in self.tool_inventory.search(
                &waf_filter,
                ToolOperation::List,
                &self.tool_inventory_policy,
            ) {
                if !results.iter().any(|existing| existing.name == result.name) {
                    results.push(result);
                }
            }
        }
        let api_executor_tools = api_results
            .iter()
            .map(|operation| {
                if operation.method.eq_ignore_ascii_case("GET") {
                    "api_read"
                } else {
                    "api_mutate"
                }
            })
            .collect::<Vec<_>>();
        let schemas = if args.include_schema {
            let tools = Self::tool_router_cloudflare().list_all();
            let mut schema_map = serde_json::Map::new();
            for result in &results {
                if let Some(tool) = tools.iter().find(|tool| tool.name.as_ref() == result.name) {
                    schema_map.insert(result.name.clone(), json!(tool));
                }
            }
            for tool_name in api_executor_tools.iter().copied().chain([
                "api_find_operations",
                "api_get_operation",
                "api_prepare_call",
            ]) {
                if !schema_map.contains_key(tool_name)
                    && let Some(tool) = tools.iter().find(|tool| tool.name.as_ref() == tool_name)
                {
                    schema_map.insert(tool_name.to_string(), json!(tool));
                }
            }
            Some(Value::Object(schema_map))
        } else {
            None
        };
        let mut companion_allowed_tools = Vec::new();
        if !api_results.is_empty() {
            companion_allowed_tools.extend([
                "api_find_operations",
                "api_get_operation",
                "api_prepare_call",
            ]);
            companion_allowed_tools.extend(api_executor_tools);
        }
        let api_result_values = api_results.iter().map(|operation| {
            let executor = if operation.method.eq_ignore_ascii_case("GET") {
                "api_read"
            } else {
                "api_mutate"
            };
            json!({
                "type": "api_operation",
                "name": executor,
                "group": "api",
                "read_only": operation.method.eq_ignore_ascii_case("GET"),
                "description": format!(
                    "{} {} - {}",
                    operation.method,
                    operation.path,
                    operation.summary.as_deref().unwrap_or(&operation.operation_id)
                ),
                "keywords": [
                    "api",
                    "rest",
                    "cloudflare",
                    operation.tag.as_str(),
                    operation.operation_id.as_str()
                ],
                "api_operation": operation,
            })
        });
        let mut payload =
            ToolSearchResponse::find_tools(args.query, args.group, args.read_only, results)
                .with_schemas(schemas)
                .into_openai_response()
                .with_companion_allowed_tools(companion_allowed_tools)
                .with_extra_results(api_result_values)
                .to_value();
        if let Value::Object(fields) = &mut payload {
            fields.insert("ok".to_string(), json!(true));
            fields.insert("api_operations".to_string(), json!(api_results));
        }

        Ok(CallToolResult::structured(payload))
    }

    #[tool(
        name = "api_parity_status",
        description = "Summarize the local Cloudflare REST API v4 parity catalog and generic executor coverage."
    )]
    async fn cloudflare_api_parity_status(
        &self,
        Parameters(_): Parameters<ApiParityStatusArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "api_parity_status",
            "catalog": api_catalog_status(),
            "executor_tools": {
                "read": "api_read",
                "mutate": "api_mutate",
                "search": "api_find_operations",
                "detail": "api_get_operation"
            },
            "safety": {
                "mutations_require_dry_run_confirmation": true,
                "denied_by_default_operations_apply": false,
                "read_only_mode_denies_api_mutate": self.read_only_mode
            }
        })))
    }

    #[tool(
        name = "api_find_operations",
        description = "Search the official Cloudflare REST API v4 operation catalog by product, method, scope, risk, and keywords."
    )]
    async fn cloudflare_api_find_operations(
        &self,
        Parameters(args): Parameters<ApiFindOperationsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let scope = match parse_scope(args.scope.as_deref()) {
            Ok(scope) => scope,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let risk = match parse_risk(args.risk.as_deref()) {
            Ok(risk) => risk,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let limit = args.limit.unwrap_or(20).clamp(1, 100);
        let results = search_operations(ApiOperationSearch {
            query: args.query.as_deref(),
            tag: args.tag.as_deref(),
            method: args.method.as_deref(),
            scope,
            risk,
            include_deprecated: args.include_deprecated,
            limit,
        });

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "api_find_operations",
            "query": args.query,
            "tag": args.tag,
            "method": args.method,
            "scope": args.scope,
            "risk": args.risk,
            "include_deprecated": args.include_deprecated,
            "results": results,
        })))
    }

    #[tool(
        name = "api_get_operation",
        description = "Inspect one Cloudflare REST API v4 operation and get its call template, parameters, risk class, and preferred curated tool if any."
    )]
    async fn cloudflare_api_get_operation(
        &self,
        Parameters(args): Parameters<ApiGetOperationArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let Some(operation) = find_operation(args.operation_id.trim()) else {
            return Ok(api_catalog_error_result(
                ApiCatalogError::OperationNotFound(args.operation_id),
            ));
        };
        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "api_get_operation",
            "api_operation": operation_detail(operation),
        })))
    }

    #[tool(
        name = "api_prepare_call",
        description = "Resolve a Cloudflare REST API operation from an operation_id or search query and return exact api_read/api_mutate arguments."
    )]
    async fn cloudflare_api_prepare_call(
        &self,
        Parameters(args): Parameters<ApiPrepareCallArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let scope = match parse_scope(args.scope.as_deref()) {
            Ok(scope) => scope,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let risk = match parse_risk(args.risk.as_deref()) {
            Ok(risk) => risk,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let selected = if let Some(operation_id) = args
            .operation_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let Some(operation) = find_operation(operation_id) else {
                return Ok(api_catalog_error_result(
                    ApiCatalogError::OperationNotFound(operation_id.to_string()),
                ));
            };
            operation
        } else {
            let results = search_operations(ApiOperationSearch {
                query: args.query.as_deref(),
                tag: args.tag.as_deref(),
                method: args.method.as_deref(),
                scope,
                risk,
                include_deprecated: args.include_deprecated,
                limit: args.limit.unwrap_or(10).clamp(1, 25),
            });
            if results.is_empty() {
                return Ok(CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "api_prepare_call",
                    "error": {
                        "code": "api_catalog.no_operation_match",
                        "message": "No Cloudflare API operation matched the supplied query.",
                        "hint": "Broaden query/tag/method filters or call api_find_operations.",
                    },
                })));
            }
            if results.len() != 1 {
                return Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "api_prepare_call",
                    "status": "ambiguous",
                    "query": args.query,
                    "candidates": results,
                    "hint": "Narrow query/tag/method/risk or pass operation_id from one candidate.",
                })));
            }
            let operation_id = results[0].operation_id.as_str();
            find_operation(operation_id).expect("search result must refer to catalog operation")
        };

        let resolved_path_params = resolved_path_params(
            selected,
            &args.path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        )
        .ok();
        let rendered_path = render_path(
            selected,
            &args.path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        )
        .ok();
        let missing_path_params = missing_path_params(
            selected,
            &args.path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        );
        let missing_query_params = missing_required_query_params(selected, &args.query_params);
        let executor = if selected.method.eq_ignore_ascii_case("GET") {
            "api_read"
        } else {
            "api_mutate"
        };
        let mut call_arguments = json!({
            "operation_id": selected.operation_id,
            "path_params": resolved_path_params.as_ref().unwrap_or(&args.path_params),
            "query": args.query_params,
        });
        if selected.method.eq_ignore_ascii_case("GET") {
            call_arguments["max_bytes"] = json!(1_048_576);
        } else {
            call_arguments["body"] = args.body.unwrap_or_else(|| json!({}));
            call_arguments["dry_run"] = json!(true);
        }

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "api_prepare_call",
            "status": if missing_path_params.is_empty() && missing_query_params.is_empty() { "ready" } else { "needs_parameters" },
            "api_operation": operation_detail(selected),
            "executor": executor,
            "rendered_path": rendered_path,
            "resolved_path_params": resolved_path_params,
            "missing_path_params": missing_path_params,
            "missing_query_params": missing_query_params,
            "call": {
                "tool": executor,
                "arguments": call_arguments,
            },
            "safety": {
                "mutations_require_dry_run_confirmation": !selected.method.eq_ignore_ascii_case("GET"),
                "apply_tool": if selected.method.eq_ignore_ascii_case("GET") { Value::Null } else { json!("api_mutate") },
            }
        })))
    }

    #[tool(
        name = "api_read",
        description = "Execute a read-only GET operation from the Cloudflare REST API v4 catalog."
    )]
    async fn cloudflare_api_read(
        &self,
        Parameters(args): Parameters<ApiReadArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let Some(operation) = find_operation(args.operation_id.trim()) else {
            return Ok(api_catalog_error_result(
                ApiCatalogError::OperationNotFound(args.operation_id),
            ));
        };
        if !operation.method.eq_ignore_ascii_case("GET") {
            return Ok(api_catalog_error_result(ApiCatalogError::MethodMismatch {
                expected: "GET".into(),
                actual: operation.method.clone(),
            }));
        }
        let path = match render_path(
            operation,
            &args.path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        ) {
            Ok(path) => path,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        if let Err(err) = validate_required_query(operation, &args.query) {
            return Ok(api_catalog_error_result(err));
        }
        let query = match query_pairs(&args.query) {
            Ok(query) => query,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };

        match self
            .cloudflare
            .api_request(
                "cloudflare.api.read",
                reqwest::Method::GET,
                &path,
                &query,
                None,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(truncate_api_payload(
                json!({
                    "ok": true,
                    "operation": "api_read",
                    "api_operation": {
                        "operation_id": operation.operation_id,
                        "method": operation.method,
                        "path": operation.path,
                        "rendered_path": path,
                        "tag": operation.tag,
                        "preferred_tool": operation.preferred_tool,
                    },
                    "result": result,
                }),
                args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
            ))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "account_billing_usage",
        description = "Read account billable usage from Cloudflare billing REST endpoints. Use mode=paygo for PayGo usage or mode=billable_usage for the restricted v2 usage endpoint."
    )]
    async fn cloudflare_account_billing_usage(
        &self,
        Parameters(args): Parameters<AccountBillingUsageArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let mode = normalize_action(args.mode.as_deref().unwrap_or("paygo"));
        let (path, canonical_mode, required_metric) = match mode.as_str() {
            "" | "paygo" | "paygo_usage" => (
                format!("/accounts/{account_id}/paygo-usage"),
                "paygo",
                false,
            ),
            "billable" | "billable_usage" | "usage" | "v2" => (
                format!("/accounts/{account_id}/billable/usage"),
                "billable_usage",
                true,
            ),
            _ => {
                return Ok(invalid_argument_result(
                    "billing_usage.invalid_mode",
                    "mode must be paygo or billable_usage",
                    "Use mode=paygo for PayGo account usage, or mode=billable_usage for Cloudflare's restricted v2 billable usage endpoint.",
                ));
            }
        };

        let mut query = BTreeMap::new();
        if let Some(from) = args
            .from
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            query.insert("from".to_string(), json!(from));
        }
        if let Some(to) = args
            .to
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            query.insert("to".to_string(), json!(to));
        }
        let metric = args
            .metric
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(metric) = metric {
            query.insert("metric".to_string(), json!(metric));
        } else if required_metric {
            return Ok(invalid_argument_result(
                "billing_usage.missing_metric",
                "metric is required for mode=billable_usage",
                "Pass the Cloudflare billable metric identifier or use mode=paygo when an aggregate PayGo usage read is enough.",
            ));
        }

        let query_pairs = match query_pairs(&query) {
            Ok(query_pairs) => query_pairs,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        match self
            .cloudflare
            .api_request(
                "cloudflare.billing.usage",
                reqwest::Method::GET,
                &path,
                &query_pairs,
                None,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(truncate_api_payload(
                json!({
                    "ok": true,
                    "operation": "account_billing_usage",
                    "account_id": account_id,
                    "mode": canonical_mode,
                    "path": path,
                    "query": query,
                    "result": result,
                    "source": {
                        "kind": "cloudflare_rest_billing_usage",
                        "note": "This is the billing REST usage surface. For product analytics and attribution, use graphql_analytics_query.",
                    },
                }),
                args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
            ))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "waf_ruleset_summary",
        description = "Read WAF custom, managed, and rate-limit Rulesets entrypoints at zone or account scope with compact rule summaries."
    )]
    async fn cloudflare_waf_ruleset_summary(
        &self,
        Parameters(args): Parameters<WafRulesetSummaryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let target = match resolve_waf_target(
            self,
            args.scope.as_deref(),
            args.account_id.as_deref(),
            args.zone_id.as_deref(),
        ) {
            Ok(target) => target,
            Err(base) => return Ok(base),
        };
        let phases = match normalize_waf_phases(&args.phases) {
            Ok(phases) => phases,
            Err(base) => return Ok(base),
        };
        let mut rulesets = Vec::new();
        for phase in &phases {
            let path = target.entrypoint_path(phase);
            let result = self
                .cloudflare
                .api_request(
                    "cloudflare.waf.ruleset.entrypoint.read",
                    reqwest::Method::GET,
                    &path,
                    &[],
                    None,
                )
                .await;
            rulesets.push(waf_ruleset_readback_entry(
                &target,
                phase,
                &path,
                result,
                args.include_rules,
                args.include_raw,
            ));
        }

        Ok(CallToolResult::structured(truncate_api_payload(
            json!({
                "ok": true,
                "operation": "waf_ruleset_summary",
                "target": target.to_json(),
                "phases": phases,
                "rulesets": rulesets,
                "source": waf_source_notes(),
            }),
            args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
        )))
    }

    #[tool(
        name = "waf_security_events_summary",
        description = "Run a curated Cloudflare Analytics GraphQL Security Events query over firewallEventsAdaptive with grouped WAF evidence and recent samples."
    )]
    async fn cloudflare_waf_security_events_summary(
        &self,
        Parameters(args): Parameters<WafSecurityEventsSummaryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let window = waf_time_window(
            args.window_hours,
            args.since.as_deref(),
            args.until.as_deref(),
        );
        let group_by = match normalize_waf_group_by(&args.group_by) {
            Ok(group_by) => group_by,
            Err(base) => return Ok(base),
        };
        let limit = args.limit.clamp(1, 100);
        let sample_limit = args.sample_limit.clamp(0, 100);
        let filter = waf_security_events_filter(
            &window,
            WafEventFilterInput {
                action: args.action.as_deref(),
                source: args.source.as_deref(),
                host: args.host.as_deref(),
                path: args.path.as_deref(),
                client_ip: args.client_ip.as_deref(),
                rule_id: args.rule_id.as_deref(),
            },
        );
        let query = build_waf_security_events_query(&group_by, limit, sample_limit);
        let body = json!({
            "query": query,
            "variables": {
                "zoneTag": zone_id,
                "filter": filter,
            },
        });

        match self.cloudflare.graphql_analytics_query(&body).await {
            Ok(result) => {
                let has_graphql_errors = result
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_some_and(|errors| !errors.is_empty());
                let diagnostics = graphql_authz_diagnostics(
                    GraphqlAnalyticsShape::WafSecurityEvents,
                    &body["variables"],
                    &result,
                );
                let payload = truncate_api_payload(
                    with_graphql_diagnostics(
                        json!({
                            "ok": !has_graphql_errors,
                            "operation": "waf_security_events_summary",
                            "zone_id": zone_id,
                            "window_utc": window,
                            "group_by": group_by,
                            "limits": {
                                "groups_per_dimension": limit,
                                "samples": sample_limit,
                            },
                            "filter": body["variables"]["filter"].clone(),
                            "analytics": waf_security_events_projection(&result),
                            "graphql": {
                                "endpoint": "/graphql",
                                "query": if args.include_query { body["query"].clone() } else { Value::Null },
                                "variables": body["variables"].clone(),
                                "result": result,
                            },
                            "source": waf_source_notes(),
                        }),
                        diagnostics,
                    ),
                    args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
                );
                if has_graphql_errors {
                    Ok(CallToolResult::structured_error(payload))
                } else {
                    Ok(CallToolResult::structured(payload))
                }
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "waf_rule_activity",
        description = "Look up a WAF rule in current Rulesets and query recent Security Events for that rule id in one compact response."
    )]
    async fn cloudflare_waf_rule_activity(
        &self,
        Parameters(args): Parameters<WafRuleActivityArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let rule_id = args.rule_id.trim();
        if rule_id.is_empty() {
            return Ok(invalid_argument_result(
                "waf.rule_id_required",
                "rule_id must not be empty",
                "Pass the Cloudflare WAF rule id to inspect.",
            ));
        }
        let target = match resolve_waf_target(
            self,
            args.scope.as_deref(),
            args.account_id.as_deref(),
            args.zone_id.as_deref(),
        ) {
            Ok(target) => target,
            Err(base) => return Ok(base),
        };
        let phases = match normalize_waf_phases(&args.phases) {
            Ok(phases) => phases,
            Err(base) => return Ok(base),
        };
        let window = waf_time_window(
            args.window_hours,
            args.since.as_deref(),
            args.until.as_deref(),
        );
        let sample_limit = args.sample_limit.clamp(1, 100);
        let analytics_zone_id = match args
            .zone_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or(self.default_zone_id.as_deref())
        {
            Some(zone_id) => zone_id,
            None => {
                return Ok(invalid_argument_result(
                    "waf.analytics_zone_required",
                    "zone_id is required for WAF Security Events analytics",
                    "Pass zone_id for the zone-scoped firewallEventsAdaptive GraphQL dataset, even when inspecting account-level WAF rulesets.",
                ));
            }
        };

        let mut rulesets = Vec::new();
        let mut matching_rules = Vec::new();
        for phase in &phases {
            let path = target.entrypoint_path(phase);
            let result = self
                .cloudflare
                .api_request(
                    "cloudflare.waf.ruleset.entrypoint.read",
                    reqwest::Method::GET,
                    &path,
                    &[],
                    None,
                )
                .await;
            if let Ok(result) = &result {
                matching_rules.extend(find_waf_rules(result, rule_id, phase, args.include_raw));
            }
            rulesets.push(waf_ruleset_readback_entry(
                &target,
                phase,
                &path,
                result,
                true,
                args.include_raw,
            ));
        }

        let filter = waf_security_events_filter(
            &window,
            WafEventFilterInput {
                action: None,
                source: None,
                host: None,
                path: None,
                client_ip: None,
                rule_id: Some(rule_id),
            },
        );
        let query = build_waf_rule_activity_query(sample_limit);
        let body = json!({
            "query": query,
            "variables": {
                "zoneTag": analytics_zone_id,
                "filter": filter,
            },
        });

        match self.cloudflare.graphql_analytics_query(&body).await {
            Ok(result) => {
                let has_graphql_errors = result
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_some_and(|errors| !errors.is_empty());
                let diagnostics = graphql_authz_diagnostics(
                    GraphqlAnalyticsShape::WafRuleActivity,
                    &body["variables"],
                    &result,
                );
                let payload = truncate_api_payload(
                    with_graphql_diagnostics(
                        json!({
                            "ok": !has_graphql_errors,
                            "operation": "waf_rule_activity",
                            "target": target.to_json(),
                            "rule_id": rule_id,
                            "window_utc": window,
                            "matching_rules": matching_rules,
                            "rulesets": rulesets,
                            "analytics": waf_security_events_projection(&result),
                            "graphql": {
                                "endpoint": "/graphql",
                                "query": if args.include_query { body["query"].clone() } else { Value::Null },
                                "variables": body["variables"].clone(),
                                "result": result,
                            },
                            "source": waf_source_notes(),
                        }),
                        diagnostics,
                    ),
                    args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
                );
                if has_graphql_errors {
                    Ok(CallToolResult::structured_error(payload))
                } else {
                    Ok(CallToolResult::structured(payload))
                }
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "waf_ruleset_plan_change",
        description = "Plan typed WAF Ruleset rule edits with stable diff, rule-cap checks, stale-list checks, ordering, and a confirmation token for apply."
    )]
    async fn cloudflare_waf_ruleset_plan_change(
        &self,
        Parameters(args): Parameters<WafRulesetChangeArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let plan = match build_waf_lifecycle_plan(
            self,
            args.account_id.as_deref(),
            args.zone_id.as_deref(),
            args.scope.as_deref(),
            args.phase.as_deref(),
            &args.edits,
            args.max_rules,
            &args.stale_list_refs,
            &args.empty_list_refs,
            args.fail_on_stale_lists,
        )
        .await
        {
            Ok(plan) => plan,
            Err(base) => return Ok(base),
        };

        Ok(CallToolResult::structured(truncate_api_payload(
            json!({
                "ok": true,
                "operation": "waf_ruleset_plan_change",
                "target": plan.target.to_json(),
                "phase": plan.phase,
                "planned": true,
                "current_ruleset": plan.current_ruleset,
                "planned_ruleset": plan.planned_ruleset,
                "diff": plan.diff,
                "validation": plan.validation,
                "ordering": plan.ordering,
                "performance_readback": plan.performance_readback,
                "required_confirmation_token": plan.required_confirmation_token,
                "dry_run_note": "No Cloudflare ruleset update applied.",
                "source": waf_source_notes(),
            }),
            args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
        )))
    }

    #[tool(
        name = "waf_ruleset_apply_change",
        description = "Apply a previously planned WAF Ruleset change after confirmation, then read back the Ruleset and optional Security Events context."
    )]
    async fn cloudflare_waf_ruleset_apply_change(
        &self,
        Parameters(args): Parameters<WafRulesetApplyArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let lifecycle = match build_waf_lifecycle_plan(
            self,
            args.account_id.as_deref(),
            args.zone_id.as_deref(),
            args.scope.as_deref(),
            args.phase.as_deref(),
            &args.edits,
            args.max_rules,
            &args.stale_list_refs,
            &args.empty_list_refs,
            args.fail_on_stale_lists,
        )
        .await
        {
            Ok(plan) => plan,
            Err(base) => return Ok(base),
        };
        let mutation_plan = MutationPlan::new("waf_ruleset_apply_change")
            .step(
                "read_waf_ruleset_entrypoint",
                false,
                json!({
                    "target": lifecycle.target.to_json(),
                    "phase": lifecycle.phase,
                    "path": lifecycle.entrypoint_path,
                }),
            )
            .step(
                "apply_waf_ruleset_entrypoint",
                true,
                json!({
                    "target": lifecycle.target.to_json(),
                    "phase": lifecycle.phase,
                    "path": lifecycle.entrypoint_path,
                    "diff": lifecycle.diff,
                }),
            )
            .step(
                "readback_waf_ruleset_entrypoint",
                false,
                json!({
                    "target": lifecycle.target.to_json(),
                    "phase": lifecycle.phase,
                    "path": lifecycle.entrypoint_path,
                }),
            );
        let audit = MutationAuditSession::start(
            Some(&parts),
            "waf_ruleset_apply_change",
            json!({
                "target": lifecycle.target.to_json(),
                "phase": lifecycle.phase,
                "diff": lifecycle.diff,
                "reason": args.reason,
            }),
            false,
        );

        let base = if args.confirmation_token != lifecycle.required_confirmation_token {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "waf_ruleset_apply_change",
                "error": {
                    "code": "waf.confirmation_required",
                    "message": "waf_ruleset_apply_change requires the confirmation token returned by waf_ruleset_plan_change",
                    "hint": "Run waf_ruleset_plan_change with the same edits and echo required_confirmation_token in confirmation_token.",
                },
                "required_confirmation_token": lifecycle.required_confirmation_token,
            }))
        } else {
            match self
                .cloudflare
                .api_request(
                    "cloudflare.waf.ruleset.entrypoint.update",
                    reqwest::Method::PUT,
                    &lifecycle.entrypoint_path,
                    &[],
                    Some(lifecycle.planned_ruleset.clone()),
                )
                .await
            {
                Ok(apply_result) => {
                    let readback_result = self
                        .cloudflare
                        .api_request(
                            "cloudflare.waf.ruleset.entrypoint.readback",
                            reqwest::Method::GET,
                            &lifecycle.entrypoint_path,
                            &[],
                            None,
                        )
                        .await;
                    let readback = waf_ruleset_readback_entry(
                        &lifecycle.target,
                        &lifecycle.phase,
                        &lifecycle.entrypoint_path,
                        readback_result,
                        true,
                        false,
                    );
                    let security_events = if args.readback_security_events {
                        waf_lifecycle_security_events_readback(
                            self,
                            lifecycle.analytics_zone_id.as_deref(),
                            &lifecycle.changed_rule_ids,
                            args.readback_window_hours,
                            args.readback_sample_limit,
                        )
                        .await
                    } else {
                        json!({
                            "enabled": false,
                            "reason": "readback_security_events=false",
                        })
                    };
                    CallToolResult::structured(truncate_api_payload(
                        json!({
                            "ok": readback.get("ok").and_then(Value::as_bool).unwrap_or(false),
                            "operation": "waf_ruleset_apply_change",
                            "target": lifecycle.target.to_json(),
                            "phase": lifecycle.phase,
                            "applied_ruleset": apply_result,
                            "readback": readback,
                            "diff": lifecycle.diff,
                            "validation": lifecycle.validation,
                            "ordering": lifecycle.ordering,
                            "performance_readback": lifecycle.performance_readback,
                            "security_events_readback": security_events,
                        }),
                        args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
                    ))
                }
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &mutation_plan, audit, false))
    }

    #[tool(
        name = "graphql_analytics_query",
        description = "Run a read-only Cloudflare Analytics GraphQL query against /client/v4/graphql for product analytics such as D1 usage attribution."
    )]
    async fn cloudflare_graphql_analytics_query(
        &self,
        Parameters(args): Parameters<GraphqlAnalyticsQueryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let query = args.query.trim();
        if query.is_empty() {
            return Ok(invalid_argument_result(
                "graphql_analytics.empty_query",
                "query must not be empty",
                "Pass a Cloudflare Analytics GraphQL query document.",
            ));
        }
        if graphql_document_has_forbidden_operation(query) {
            return Ok(invalid_argument_result(
                "graphql_analytics.not_read_only",
                "graphql_analytics_query only accepts read-only query operations",
                "Use a GraphQL query operation or an anonymous selection set; mutations and subscriptions are rejected.",
            ));
        }

        let body = json!({
            "query": query,
            "variables": args.variables,
        });
        match self.cloudflare.graphql_analytics_query(&body).await {
            Ok(result) => {
                let has_graphql_errors = result
                    .get("errors")
                    .and_then(Value::as_array)
                    .is_some_and(|errors| !errors.is_empty());
                let diagnostics = graphql_authz_diagnostics(
                    GraphqlAnalyticsShape::Generic,
                    &body["variables"],
                    &result,
                );
                let payload = truncate_api_payload(
                    with_graphql_diagnostics(
                        json!({
                            "ok": !has_graphql_errors,
                            "operation": "graphql_analytics_query",
                            "endpoint": "/graphql",
                            "result": result,
                            "source": {
                                "kind": "cloudflare_graphql_analytics_api",
                                "note": "Cloudflare Analytics GraphQL is useful for product analytics and attribution. Cloudflare documents that GraphQL analytics datasets are not a substitute for billing usage records.",
                            },
                        }),
                        diagnostics,
                    ),
                    args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
                );
                if has_graphql_errors {
                    Ok(CallToolResult::structured_error(payload))
                } else {
                    Ok(CallToolResult::structured(payload))
                }
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "api_mutate",
        description = "Dry-run or execute a guarded mutating operation from the Cloudflare REST API v4 catalog."
    )]
    async fn cloudflare_api_mutate(
        &self,
        Parameters(args): Parameters<ApiMutateArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let Some(operation) = find_operation(args.operation_id.trim()) else {
            return Ok(api_catalog_error_result(
                ApiCatalogError::OperationNotFound(args.operation_id),
            ));
        };
        if operation.method.eq_ignore_ascii_case("GET") {
            return Ok(api_catalog_error_result(ApiCatalogError::MethodMismatch {
                expected: "POST, PUT, PATCH, or DELETE".into(),
                actual: operation.method.clone(),
            }));
        }
        if !operation_allowed_by_default(operation) {
            return Ok(api_catalog_error_result(ApiCatalogError::DeniedByDefault(
                operation.operation_id.clone(),
            )));
        }
        let path = match render_path(
            operation,
            &args.path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        ) {
            Ok(path) => path,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        if let Err(err) = validate_required_query(operation, &args.query) {
            return Ok(api_catalog_error_result(err));
        }
        let query = match query_pairs(&args.query) {
            Ok(query) => query,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let method = match reqwest::Method::from_bytes(operation.method.as_bytes()) {
            Ok(method) => method,
            Err(_) => {
                return Ok(invalid_argument_result(
                    "api_catalog.invalid_method",
                    "catalog operation has an unsupported HTTP method",
                    "Refresh the Cloudflare API catalog from the official OpenAPI schema.",
                ));
            }
        };
        let normalized_body = normalize_json_string_body(args.body.clone());
        let required_token = mutation_confirmation_token(operation, &path, &normalized_body.value);
        let legacy_confirmation_token = normalized_body
            .normalized
            .then(|| mutation_confirmation_token(operation, &path, &args.body));
        let plan = MutationPlan::new("api_mutate")
            .step(
                "validate_api_operation",
                false,
                json!({
                    "operation_id": operation.operation_id,
                    "method": operation.method,
                    "risk": operation.risk,
                }),
            )
            .step(
                "apply_cloudflare_api_request",
                true,
                json!({
                    "path": path,
                    "query": args.query.clone(),
                }),
            );
        let audit = MutationAuditSession::start(
            None,
            "api_mutate",
            json!({
                "operation_id": operation.operation_id,
                "method": operation.method,
                "path": path,
                "risk": operation.risk,
                "reason": args.reason.clone(),
            }),
            args.dry_run,
        );

        let request_plan = json!({
            "method": operation.method,
            "path": path,
            "query": args.query.clone(),
            "body": normalized_body.value.clone(),
            "body_normalized_from_json_string": normalized_body.normalized,
            "headers": {
                "authorization": "Bearer <redacted>",
                "user-agent": "<configured>"
            },
            "required_confirmation_token": required_token,
        });
        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "api_mutate",
                "api_operation": operation_detail(operation),
                "planned": true,
                "request_plan": request_plan,
                "dry_run_note": "No Cloudflare API mutation applied.",
            }))
        } else if !args.confirmation_token.as_deref().is_some_and(|token| {
            token == required_token
                || legacy_confirmation_token
                    .as_deref()
                    .is_some_and(|legacy_token| token == legacy_token)
        }) {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "api_mutate",
                "error": {
                    "code": "api_mutate.confirmation_required",
                    "message": "api_mutate apply requires the confirmation token emitted by dry_run",
                    "hint": "Run api_mutate with dry_run=true and echo required_confirmation_token in confirmation_token.",
                },
                "required_confirmation_token": required_token,
                "request_plan": request_plan,
            }))
        } else {
            match self
                .cloudflare
                .api_request(
                    "cloudflare.api.mutate",
                    method,
                    &path,
                    &query,
                    normalized_body.value.clone(),
                )
                .await
            {
                Ok(result) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "api_mutate",
                    "api_operation": {
                        "operation_id": operation.operation_id,
                        "method": operation.method,
                        "path": operation.path,
                        "rendered_path": path,
                        "tag": operation.tag,
                        "risk": operation.risk,
                        "preferred_tool": operation.preferred_tool,
                    },
                    "result": result,
                })),
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "account_api_tokens",
        description = "Curated account-owned API token management: list permission groups, list/get/verify tokens, and guarded create/update/delete/roll actions."
    )]
    async fn cloudflare_account_api_tokens(
        &self,
        Parameters(args): Parameters<AccountApiTokensArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let action = args.action.trim();
        let Some((operation_id, token_id_required)) = account_api_token_operation(action) else {
            return Ok(invalid_argument_result(
                "account_api_tokens.invalid_action",
                "unsupported account API token action",
                "Use one of: list_permission_groups, list, get, verify, create, update, delete, roll.",
            ));
        };
        let Some(operation) = find_operation(operation_id) else {
            return Ok(api_catalog_error_result(
                ApiCatalogError::OperationNotFound(operation_id.to_string()),
            ));
        };
        let token_id = args
            .token_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if token_id_required && token_id.is_none() {
            return Ok(invalid_argument_result(
                "account_api_tokens.missing_token_id",
                "token_id is required for this account API token action",
                "Pass token_id for get, update, delete, and roll actions.",
            ));
        }
        if operation.has_request_body && args.body.is_none() {
            return Ok(invalid_argument_result(
                "account_api_tokens.missing_body",
                "body is required for this account API token action",
                "Pass the Cloudflare token payload in body; use list_permission_groups to discover permission group ids.",
            ));
        }
        let mut path_params = BTreeMap::from([("account_id".to_string(), account_id.to_string())]);
        if let Some(token_id) = token_id {
            path_params.insert("token_id".to_string(), token_id.to_string());
        }
        let path = match render_path(
            operation,
            &path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        ) {
            Ok(path) => path,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        if let Err(err) = validate_required_query(operation, &args.query) {
            return Ok(api_catalog_error_result(err));
        }
        let query = match query_pairs(&args.query) {
            Ok(query) => query,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let method = match reqwest::Method::from_bytes(operation.method.as_bytes()) {
            Ok(method) => method,
            Err(_) => {
                return Ok(invalid_argument_result(
                    "account_api_tokens.invalid_method",
                    "catalog operation has an unsupported HTTP method",
                    "Refresh the Cloudflare API catalog from the official OpenAPI schema.",
                ));
            }
        };
        let is_read = method == reqwest::Method::GET;
        if is_read {
            return match self
                .cloudflare
                .api_request(
                    "cloudflare.account_api_tokens.read",
                    method,
                    &path,
                    &query,
                    None,
                )
                .await
            {
                Ok(result) => Ok(CallToolResult::structured(truncate_api_payload(
                    json!({
                        "ok": true,
                        "operation": "account_api_tokens",
                        "action": action,
                        "api_operation": {
                            "operation_id": operation.operation_id,
                            "method": operation.method,
                            "path": operation.path,
                            "rendered_path": path,
                            "tag": operation.tag,
                        },
                        "result": result,
                    }),
                    args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
                ))),
                Err(err) => Ok(adapter_error_result(err)),
            };
        }

        let normalized_body = normalize_json_string_body(args.body.clone());
        let required_token = mutation_confirmation_token(operation, &path, &normalized_body.value);
        let legacy_confirmation_token = normalized_body
            .normalized
            .then(|| mutation_confirmation_token(operation, &path, &args.body));
        let plan = MutationPlan::new("account_api_tokens")
            .step(
                "validate_account_api_token_operation",
                false,
                json!({
                    "account_id": account_id,
                    "action": action,
                    "operation_id": operation.operation_id,
                    "method": operation.method,
                    "risk": operation.risk,
                    "reason": args.reason.clone(),
                }),
            )
            .step(
                "apply_cloudflare_account_api_token_request",
                true,
                json!({
                    "path": path,
                    "query": args.query.clone(),
                }),
            );
        let audit = MutationAuditSession::start(
            None,
            "account_api_tokens",
            json!({
                "account_id": account_id,
                "action": action,
                "operation_id": operation.operation_id,
                "method": operation.method,
                "path": path,
                "reason": args.reason.clone(),
            }),
            args.dry_run,
        );
        let request_plan = json!({
            "method": operation.method,
            "path": path,
            "query": args.query.clone(),
            "body": normalized_body.value.clone(),
            "body_normalized_from_json_string": normalized_body.normalized,
            "headers": {
                "authorization": "Bearer <redacted>",
                "user-agent": "<configured>"
            },
            "required_confirmation_token": required_token,
        });
        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "account_api_tokens",
                "action": action,
                "api_operation": operation_detail(operation),
                "planned": true,
                "request_plan": request_plan,
                "dry_run_note": "No Cloudflare account API token mutation applied.",
            }))
        } else if !args.confirmation_token.as_deref().is_some_and(|token| {
            token == required_token
                || legacy_confirmation_token
                    .as_deref()
                    .is_some_and(|legacy_token| token == legacy_token)
        }) {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "account_api_tokens",
                "action": action,
                "error": {
                    "code": "account_api_tokens.confirmation_required",
                    "message": "account API token mutation requires the confirmation token emitted by dry_run",
                    "hint": "Run account_api_tokens with dry_run=true and echo required_confirmation_token in confirmation_token.",
                },
                "required_confirmation_token": required_token,
                "request_plan": request_plan,
            }))
        } else {
            match self
                .cloudflare
                .api_request(
                    "cloudflare.account_api_tokens.mutate",
                    method,
                    &path,
                    &query,
                    normalized_body.value.clone(),
                )
                .await
            {
                Ok(result) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "account_api_tokens",
                    "action": action,
                    "api_operation": {
                        "operation_id": operation.operation_id,
                        "method": operation.method,
                        "path": operation.path,
                        "rendered_path": path,
                        "tag": operation.tag,
                        "risk": operation.risk,
                    },
                    "result": result,
                    "secret_handling_note": "Token create and roll responses may include one-time secret material; store it securely and do not paste it into public logs or issues.",
                })),
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "account_api_token_permission_plan",
        description = "Read-only planner for account API token permission changes. Fetches current token/catalog state, computes add/remove deltas, and returns a safe account_api_tokens update dry-run payload without mutating Cloudflare."
    )]
    async fn cloudflare_account_api_token_permission_plan(
        &self,
        Parameters(args): Parameters<AccountApiTokenPermissionPlanArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let token_id = args
            .token_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if token_id.is_none() && args.current_token.is_none() {
            return Ok(invalid_argument_result(
                "account_api_token_permission_plan.missing_token",
                "token_id or current_token is required",
                "Pass token_id to let the MCP read the current token, or pass current_token from account_api_tokens action=get.",
            ));
        }
        if args.add_permissions.is_empty() && args.remove_permissions.is_empty() {
            return Ok(invalid_argument_result(
                "account_api_token_permission_plan.empty_delta",
                "at least one add_permissions or remove_permissions entry is required",
                "Pass permission group names, ids, or exact scope strings to add/remove.",
            ));
        }

        let current_token_envelope = if let Some(current_token) = args.current_token.clone() {
            current_token
        } else {
            let token_id = token_id.expect("checked above");
            let Some(operation) = find_operation("account-api-tokens-token-details") else {
                return Ok(api_catalog_error_result(
                    ApiCatalogError::OperationNotFound(
                        "account-api-tokens-token-details".to_string(),
                    ),
                ));
            };
            let path = match render_path(
                operation,
                &BTreeMap::from([
                    ("account_id".to_string(), account_id.to_string()),
                    ("token_id".to_string(), token_id.to_string()),
                ]),
                self.default_account_id.as_deref(),
                self.default_zone_id.as_deref(),
            ) {
                Ok(path) => path,
                Err(err) => return Ok(api_catalog_error_result(err)),
            };
            match self
                .cloudflare
                .api_request(
                    "cloudflare.account_api_token_permission_plan.token_read",
                    reqwest::Method::GET,
                    &path,
                    &[],
                    None,
                )
                .await
            {
                Ok(result) => result,
                Err(err) => return Ok(adapter_error_result(err)),
            }
        };

        let permission_groups_envelope =
            if let Some(permission_groups) = args.permission_groups.clone() {
                permission_groups
            } else {
                let Some(operation) = find_operation("account-api-tokens-list-permission-groups")
                else {
                    return Ok(api_catalog_error_result(
                        ApiCatalogError::OperationNotFound(
                            "account-api-tokens-list-permission-groups".to_string(),
                        ),
                    ));
                };
                let path = match render_path(
                    operation,
                    &BTreeMap::from([("account_id".to_string(), account_id.to_string())]),
                    self.default_account_id.as_deref(),
                    self.default_zone_id.as_deref(),
                ) {
                    Ok(path) => path,
                    Err(err) => return Ok(api_catalog_error_result(err)),
                };
                match self
                    .cloudflare
                    .api_request(
                        "cloudflare.account_api_token_permission_plan.permission_groups_read",
                        reqwest::Method::GET,
                        &path,
                        &[],
                        None,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(err) => return Ok(adapter_error_result(err)),
                }
            };

        let token = cloudflare_result_value(&current_token_envelope).clone();
        let catalog_groups = extract_permission_group_summaries(&permission_groups_envelope);
        if catalog_groups.is_empty() {
            return Ok(invalid_argument_result(
                "account_api_token_permission_plan.empty_permission_catalog",
                "permission group catalog is empty or not in a recognized shape",
                "Pass permission_groups from account_api_tokens action=list_permission_groups, or allow the MCP to read the catalog.",
            ));
        }

        let policies = match token.get("policies").and_then(Value::as_array) {
            Some(policies) if !policies.is_empty() => policies,
            _ => {
                return Ok(invalid_argument_result(
                    "account_api_token_permission_plan.missing_policies",
                    "current token does not include a non-empty policies array",
                    "Pass current_token from account_api_tokens action=get, or verify the token details endpoint returned full token metadata.",
                ));
            }
        };
        let policy_index = match args.policy_index {
            Some(index) if index < policies.len() => index,
            Some(_) => {
                return Ok(invalid_argument_result(
                    "account_api_token_permission_plan.invalid_policy_index",
                    "policy_index is outside the current token policies array",
                    "Inspect policy_summaries in the token details and choose a valid zero-based policy_index.",
                ));
            }
            None if policies.len() == 1 => 0,
            None => {
                return Ok(CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "account_api_token_permission_plan",
                    "error": {
                        "code": "account_api_token_permission_plan.ambiguous_policy",
                        "message": "token has multiple policies; choose policy_index before planning permission changes",
                        "hint": "Pass policy_index for the policy whose resources should receive the add/remove permission groups."
                    },
                    "account_id": account_id,
                    "token_id": token_id,
                    "policy_summaries": summarize_token_policies(policies),
                })));
            }
        };

        let selected_policy = &policies[policy_index];
        let current_groups =
            extract_permission_group_summaries_from_array(selected_policy.get("permission_groups"));
        if current_groups
            .iter()
            .any(|group| group.id.trim().is_empty())
        {
            return Ok(invalid_argument_result(
                "account_api_token_permission_plan.invalid_current_permission_group",
                "selected policy has a permission group without an id",
                "Refresh token details before planning the update; the MCP preserves permission groups by id.",
            ));
        }

        let add_resolution = match resolve_permission_selectors(
            &args.add_permissions,
            &catalog_groups,
            &current_groups,
            PermissionSelectorMode::Add,
        ) {
            Ok(resolution) => resolution,
            Err(error) => return Ok(error),
        };
        let remove_resolution = match resolve_permission_selectors(
            &args.remove_permissions,
            &catalog_groups,
            &current_groups,
            PermissionSelectorMode::Remove,
        ) {
            Ok(resolution) => resolution,
            Err(error) => return Ok(error),
        };

        let mut resulting_by_id: BTreeMap<String, PermissionGroupSummary> = current_groups
            .iter()
            .cloned()
            .map(|group| (group.id.clone(), group))
            .collect();
        for group in &remove_resolution.to_change {
            resulting_by_id.remove(&group.id);
        }
        for group in &add_resolution.to_change {
            resulting_by_id.insert(group.id.clone(), group.clone());
        }
        let resulting_groups: Vec<PermissionGroupSummary> =
            resulting_by_id.values().cloned().collect();

        let mut update_body = match build_account_api_token_update_body(&token) {
            Ok(body) => body,
            Err(error) => return Ok(error),
        };
        if let Some(policy) = update_body
            .get_mut("policies")
            .and_then(Value::as_array_mut)
            .and_then(|policies| policies.get_mut(policy_index))
        {
            policy["permission_groups"] = json!(
                resulting_groups
                    .iter()
                    .map(|group| json!({ "id": group.id }))
                    .collect::<Vec<_>>()
            );
        }

        let no_changes_required =
            add_resolution.to_change.is_empty() && remove_resolution.to_change.is_empty();
        let resolved_token_id = token_id
            .or_else(|| token.get("id").and_then(Value::as_str))
            .map(str::to_string);
        if !no_changes_required && resolved_token_id.is_none() {
            return Ok(invalid_argument_result(
                "account_api_token_permission_plan.missing_update_token_id",
                "permission changes were planned, but no token id is available for the update call",
                "Pass token_id, or include id in current_token from account_api_tokens action=get.",
            ));
        }
        let next_call = if no_changes_required {
            Value::Null
        } else {
            json!({
                "tool": "account_api_tokens",
                "arguments": {
                    "account_id": account_id,
                    "action": "update",
                    "token_id": resolved_token_id,
                    "body": update_body,
                    "dry_run": true,
                    "reason": args.reason.clone().unwrap_or_else(|| "permission delta planned by account_api_token_permission_plan".to_string()),
                }
            })
        };

        let mut payload = json!({
            "ok": true,
            "operation": "account_api_token_permission_plan",
            "read_only": true,
            "account_id": account_id,
            "token_id": resolved_token_id,
            "token_name": token.get("name").cloned().unwrap_or(Value::Null),
            "policy": {
                "index": policy_index,
                "effect": selected_policy.get("effect").cloned().unwrap_or(Value::Null),
                "resources": selected_policy.get("resources").cloned().unwrap_or(Value::Null),
                "current_permission_count": current_groups.len(),
                "resulting_permission_count": resulting_groups.len(),
            },
            "requested": {
                "add_permissions": args.add_permissions,
                "remove_permissions": args.remove_permissions,
            },
            "delta": {
                "permissions_to_add": add_resolution.to_change,
                "permissions_to_remove": remove_resolution.to_change,
                "already_present": add_resolution.noops,
                "not_present": remove_resolution.noops,
            },
            "no_changes_required": no_changes_required,
            "resulting_permission_groups": resulting_groups,
            "update_body": next_call.get("arguments").and_then(|arguments| arguments.get("body")).cloned().unwrap_or(Value::Null),
            "next_call": next_call,
            "safety_notes": [
                "This helper is read-only and does not mutate Cloudflare.",
                "Run the returned account_api_tokens update payload with dry_run=true first, then apply only with the emitted confirmation token.",
                "Existing permission groups on the selected policy are preserved unless explicitly listed in remove_permissions."
            ],
        });
        if args.include_catalog {
            payload["permission_group_catalog"] = json!(catalog_groups);
        }
        Ok(CallToolResult::structured(truncate_api_payload(
            payload,
            args.max_bytes.unwrap_or(1_048_576).clamp(1, 10_485_760),
        )))
    }

    #[tool(
        name = "list_tunnels",
        description = "List Cloudflare tunnels for an account."
    )]
    async fn cloudflare_list_tunnels(
        &self,
        Parameters(args): Parameters<ListTunnelsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let page = args.page.unwrap_or(1).max(1);
        let per_page = args.per_page.unwrap_or(50).clamp(1, 100);

        match self
            .cloudflare
            .list_tunnels(account_id, page, per_page)
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "page": result,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "ensure_tunnel",
        description = "Idempotently ensure tunnel exists by (account_id,tunnel_name): reuse existing or create."
    )]
    async fn cloudflare_ensure_tunnel(
        &self,
        Parameters(args): Parameters<EnsureTunnelArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let Some(identity) = tunnel_identity(account_id, &args.tunnel_name) else {
            return Ok(invalid_argument_result(
                "tunnel.invalid_tunnel_name",
                "tunnel_name must not be empty",
                "Provide a non-empty tunnel_name.",
            ));
        };
        let plan = plan_ensure_tunnel(account_id, &identity.tunnel_name);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "ensure_tunnel",
            json!({
                "account_id": account_id,
                "tunnel_name": &identity.tunnel_name,
                "identity_key": &identity.identity_key,
            }),
            args.dry_run,
        );

        let base = match self.cloudflare.list_tunnels(account_id, 1, 100).await {
            Ok(page) => match select_existing_tunnel(&page.items, &identity.tunnel_name) {
                Ok(Some(existing)) => CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "identity": identity,
                    "action": "reused",
                    "tunnel": existing.clone(),
                    "tunnel_target": tunnel_target(&existing.id),
                })),
                Ok(None) if args.dry_run => CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "identity": identity,
                    "action": "create",
                    "planned": true,
                    "tunnel_target_format": "<tunnel-id>.cfargotunnel.com",
                    "dry_run_note": "No Cloudflare mutation applied.",
                })),
                Ok(None) => match self
                    .cloudflare
                    .create_tunnel(account_id, &identity.tunnel_name)
                    .await
                {
                    Ok(created) => match self.cloudflare.list_tunnels(account_id, 1, 100).await {
                        Ok(readback_page) => {
                            match select_existing_tunnel(
                                &readback_page.items,
                                &identity.tunnel_name,
                            ) {
                                Ok(Some(readback)) => CallToolResult::structured(json!({
                                    "ok": true,
                                    "account_id": account_id,
                                    "identity": identity,
                                    "action": "created",
                                    "tunnel": readback.clone(),
                                    "created_tunnel_id": created.id,
                                    "tunnel_target": tunnel_target(&readback.id),
                                })),
                                Ok(None) => CallToolResult::structured_error(json!({
                                    "ok": false,
                                    "error": {
                                        "code": "tunnel.readback_missing",
                                        "message": "tunnel create succeeded but readback did not find requested tunnel",
                                        "hint": "Retry list/ensure and inspect Cloudflare tunnel consistency for this account.",
                                    },
                                    "identity": identity,
                                })),
                                Err(conflict) => tunnel_conflict_result(conflict),
                            }
                        }
                        Err(err) => adapter_error_result(err),
                    },
                    Err(err) => adapter_error_result(err),
                },
                Err(conflict) => tunnel_conflict_result(conflict),
            },
            Err(err) => adapter_error_result(err),
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "generate_tunnel_ingress",
        description = "Generate deterministic cloudflared-style ingress config for a tunnel and validate rule set."
    )]
    async fn cloudflare_generate_tunnel_ingress(
        &self,
        Parameters(args): Parameters<GenerateTunnelIngressArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let rules = args
            .rules
            .iter()
            .map(normalize_ingress_rule_arg)
            .collect::<Vec<_>>();
        match build_ingress_config(&args.tunnel_id, &args.tunnel_name, &rules) {
            Ok(config) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "config": config,
            }))),
            Err(err) => Ok(CallToolResult::structured_error(json!({
                "ok": false,
                "error": err,
            }))),
        }
    }

    #[tool(
        name = "connector_control",
        description = "Idempotent connector run-control hook for tunnel runtime state (start/stop/restart)."
    )]
    async fn cloudflare_connector_control(
        &self,
        Parameters(args): Parameters<ConnectorControlArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let connector_key = args.connector_key.trim();
        if connector_key.is_empty() {
            return Ok(invalid_argument_result(
                "connector.invalid_key",
                "connector_key must not be empty",
                "Provide a non-empty connector_key.",
            ));
        }
        let action = match ConnectorControlAction::parse(&args.action) {
            Ok(action) => action,
            Err(err) => {
                return Ok(invalid_argument_result(
                    "connector.invalid_action",
                    err,
                    "Use action='start', 'stop', or 'restart'.",
                ));
            }
        };
        let plan = plan_connector_control(connector_key, action);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "connector_control",
            json!({
                "connector_key": connector_key,
                "action": action.as_str(),
            }),
            args.dry_run,
        );

        let base = match self.connector_runtime.lock() {
            Ok(mut state) => {
                let current = state.get(connector_key).cloned();
                let outcome = apply_connector_control(current.as_ref(), connector_key, action);
                if !args.dry_run {
                    state.insert(connector_key.to_string(), outcome.connector.clone());
                }
                CallToolResult::structured(json!({
                    "ok": true,
                    "connector_key": connector_key,
                    "action": action.as_str(),
                    "current": current,
                    "result": outcome,
                    "dry_run_note": args.dry_run.then_some("No connector state mutation applied."),
                }))
            }
            Err(_) => CallToolResult::structured_error(json!({
                "ok": false,
                "error": {
                    "code": "connector.runtime_state_unavailable",
                    "message": "connector runtime state lock is unavailable",
                    "hint": "Retry connector control operation.",
                }
            })),
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "list_dns_records",
        description = "List Cloudflare CNAME DNS records for a zone."
    )]
    async fn cloudflare_list_dns_records(
        &self,
        Parameters(args): Parameters<ListDnsRecordsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;

        match self
            .cloudflare
            .list_dns_records(zone_id, args.hostname.as_deref())
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "zone_id": zone_id,
                "page": result,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_list_databases",
        description = "List Cloudflare D1 databases for an account. Read-only."
    )]
    async fn cloudflare_d1_list_databases(
        &self,
        Parameters(args): Parameters<D1ListDatabasesArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let page = args.page.unwrap_or(1).max(1);
        let per_page = args.per_page.unwrap_or(50).clamp(1, 100);

        match self
            .cloudflare
            .list_d1_databases(account_id, page, per_page, args.name.as_deref())
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "page": result,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_get_database",
        description = "Get Cloudflare D1 database metadata by database_id. Read-only."
    )]
    async fn cloudflare_d1_get_database(
        &self,
        Parameters(args): Parameters<D1DatabaseArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_d1_database(account_id, &args.database_id)
            .await
        {
            Ok(database) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "database": database,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_rename_database",
        description = "Rename a Cloudflare D1 database through the curated partial-update endpoint. Supports dry-run planning."
    )]
    async fn cloudflare_d1_rename_database(
        &self,
        Parameters(args): Parameters<D1RenameDatabaseArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let name = args.name.trim();
        if name.is_empty() {
            return Ok(invalid_argument_result(
                "d1.invalid_database_name",
                "D1 database rename requires a non-empty name",
                "Pass the desired database name in the name argument.",
            ));
        }
        let plan = MutationPlan::new("d1_rename_database")
            .step(
                "validate_d1_database_rename",
                false,
                json!({
                    "account_id": account_id,
                    "database_id": &args.database_id,
                    "new_name": name,
                }),
            )
            .step(
                "apply_d1_database_patch",
                true,
                json!({
                    "method": "PATCH",
                    "path": "/accounts/{account_id}/d1/database/{database_id}",
                    "body": {"name": name},
                }),
            );
        let audit = MutationAuditSession::start(
            None,
            "d1_rename_database",
            json!({
                "account_id": account_id,
                "database_id": &args.database_id,
                "new_name": name,
            }),
            args.dry_run,
        );

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "d1_rename_database",
                "planned": true,
                "account_id": account_id,
                "database_id": &args.database_id,
                "new_name": name,
                "dry_run_note": "No D1 database rename applied.",
            }))
        } else {
            match self
                .cloudflare
                .rename_d1_database(account_id, &args.database_id, name)
                .await
            {
                Ok(database) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "d1_rename_database",
                    "account_id": account_id,
                    "database_id": &args.database_id,
                    "new_name": name,
                    "database": database,
                })),
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "d1_delete_database",
        description = "Delete a Cloudflare D1 database through the curated high-risk endpoint. Dry-run emits a required confirmation token."
    )]
    async fn cloudflare_d1_delete_database(
        &self,
        Parameters(args): Parameters<D1DeleteDatabaseArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let operation = find_operation("d1-delete-database").expect("D1 delete catalog operation");
        let path_params = BTreeMap::from([
            ("account_id".to_string(), account_id.to_string()),
            ("database_id".to_string(), args.database_id.clone()),
        ]);
        let path = match render_path(
            operation,
            &path_params,
            self.default_account_id.as_deref(),
            self.default_zone_id.as_deref(),
        ) {
            Ok(path) => path,
            Err(err) => return Ok(api_catalog_error_result(err)),
        };
        let required_token = mutation_confirmation_token(operation, &path, &None);
        let plan = MutationPlan::new("d1_delete_database")
            .step(
                "validate_d1_database_delete",
                false,
                json!({
                    "account_id": account_id,
                    "database_id": &args.database_id,
                    "reason": args.reason.clone(),
                }),
            )
            .step(
                "apply_d1_database_delete",
                true,
                json!({
                    "method": "DELETE",
                    "path": path,
                }),
            );
        let audit = MutationAuditSession::start(
            None,
            "d1_delete_database",
            json!({
                "account_id": account_id,
                "database_id": &args.database_id,
                "reason": args.reason.clone(),
            }),
            args.dry_run,
        );

        let request_plan = json!({
            "method": "DELETE",
            "path": path,
            "body": null,
            "headers": {
                "authorization": "Bearer <redacted>",
                "user-agent": "<configured>"
            },
            "required_confirmation_token": required_token,
        });

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "d1_delete_database",
                "planned": true,
                "account_id": account_id,
                "database_id": &args.database_id,
                "request_plan": request_plan,
                "required_confirmation_token": required_token,
                "dry_run_note": "No D1 database delete applied.",
            }))
        } else if args.confirmation_token.as_deref() != Some(required_token.as_str()) {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "d1_delete_database",
                "error": {
                    "code": "d1.delete_confirmation_required",
                    "message": "d1_delete_database apply requires the confirmation token emitted by dry_run",
                    "hint": "Run d1_delete_database with dry_run=true and echo required_confirmation_token in confirmation_token.",
                },
                "required_confirmation_token": required_token,
                "request_plan": request_plan,
            }))
        } else {
            match self
                .cloudflare
                .delete_d1_database(account_id, &args.database_id)
                .await
            {
                Ok(result) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "d1_delete_database",
                    "account_id": account_id,
                    "database_id": &args.database_id,
                    "result": result,
                })),
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "d1_inspect_schema",
        description = "Inspect D1 application tables, indexes, views, and columns using read-only SQLite catalog queries; supports targeted include filters and skips Cloudflare internal _cf_* objects."
    )]
    async fn cloudflare_d1_inspect_schema(
        &self,
        Parameters(args): Parameters<D1InspectSchemaArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .inspect_d1_schema(
                account_id,
                &args.database_id,
                args.include_columns,
                &args.include_tables,
                args.include_table_pattern.as_deref(),
            )
            .await
        {
            Ok(schema) => {
                let ok = schema
                    .get("application_schema_available")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let payload = json!({
                    "ok": ok,
                    "account_id": account_id,
                    "database_id": &args.database_id,
                    "schema": schema,
                });
                if ok {
                    Ok(CallToolResult::structured(payload))
                } else {
                    Ok(CallToolResult::structured_error(payload))
                }
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_query_read_only",
        description = "Run or execute one read-only Cloudflare D1 SQL SELECT/query statement against a database after the shared restricted-SQL classifier approves it, returning rows."
    )]
    async fn cloudflare_d1_query_read_only(
        &self,
        Parameters(args): Parameters<D1QueryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if let Err(result) = validate_d1_read_only_sql(&args.sql) {
            return Ok(result);
        }
        let max_rows = args.max_rows.unwrap_or(100).clamp(1, 1000);
        match self
            .cloudflare
            .query_d1_database_read_only(account_id, &args.database_id, &args.sql, &args.params)
            .await
        {
            Ok(result) => {
                let (result, truncated) = limit_d1_result_rows(result, max_rows);
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "database_id": &args.database_id,
                    "policy": {
                        "restricted_sql": true,
                        "contract": "mcp-toolkit-policy-core/restricted-sql",
                        "max_rows": max_rows,
                    },
                    "truncated": truncated,
                    "result": result,
                })))
            }
            Err(err) if is_d1_no_such_column_error(&err) => {
                Ok(d1_no_such_column_result(err, &args.database_id))
            }
            Err(err) if is_d1_no_such_table_error(&err) => {
                Ok(d1_no_such_table_result(err, &args.database_id))
            }
            Err(err) if crate::cloudflare::client::is_d1_sqlite_auth_error(&err) => {
                Ok(d1_sqlite_auth_result(err))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_validate_query",
        description = "Validate one read-only D1 SQL statement against application schema metadata without executing the statement."
    )]
    async fn cloudflare_d1_validate_query(
        &self,
        Parameters(args): Parameters<D1ValidateQueryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if let Err(result) = validate_d1_read_only_sql(&args.sql) {
            return Ok(result);
        }
        let schema = match self
            .cloudflare
            .inspect_d1_schema(account_id, &args.database_id, true, &[], None)
            .await
        {
            Ok(schema) => schema,
            Err(err) if is_d1_no_such_table_error(&err) => {
                return Ok(d1_no_such_table_result(err, &args.database_id));
            }
            Err(err) if is_d1_no_such_column_error(&err) => {
                return Ok(d1_no_such_column_result(err, &args.database_id));
            }
            Err(err) if crate::cloudflare::client::is_d1_sqlite_auth_error(&err) => {
                return Ok(d1_sqlite_auth_result(err));
            }
            Err(err) => return Ok(adapter_error_result(err)),
        };
        let validation = validate_sql_against_schema(&args.sql, &schema, "d1");
        let query_plan = if args.include_query_plan && validation["ok"] == json!(true) {
            let explain_sql = format!("EXPLAIN QUERY PLAN {}", args.sql.trim());
            match self
                .cloudflare
                .query_d1_database_read_only(account_id, &args.database_id, &explain_sql, &[])
                .await
            {
                Ok(plan) => json!({
                    "available": true,
                    "source": "EXPLAIN QUERY PLAN",
                    "result": plan,
                    "estimated_rows": null,
                    "estimated_read_bytes": null,
                }),
                Err(err) if is_d1_no_such_table_error(&err) => json!({
                    "available": false,
                    "reason": "d1.no_such_table",
                    "error": err.payload(),
                }),
                Err(err) if is_d1_no_such_column_error(&err) => json!({
                    "available": false,
                    "reason": "d1.no_such_column",
                    "error": err.payload(),
                }),
                Err(err) if crate::cloudflare::client::is_d1_sqlite_auth_error(&err) => json!({
                    "available": false,
                    "reason": "not_allowed",
                    "error": err.payload(),
                }),
                Err(err) => json!({
                    "available": false,
                    "reason": "plan_query_failed",
                    "error": err.payload(),
                }),
            }
        } else {
            json!({
                "available": false,
                "reason": if args.include_query_plan { "validation_failed" } else { "not_requested" },
                "estimated_rows": null,
                "estimated_read_bytes": null,
            })
        };
        let is_ok = validation["ok"].as_bool().unwrap_or(false);
        let response = json!({
            "ok": is_ok,
            "account_id": account_id,
            "database_id": &args.database_id,
            "mode": "schema_preflight",
            "executed_user_query": false,
            "schema": schema,
            "validation": validation,
            "query_plan": query_plan,
        });
        if is_ok {
            Ok(CallToolResult::structured(response))
        } else {
            Ok(CallToolResult::structured_error(response))
        }
    }

    #[tool(
        name = "analytics_engine_query",
        description = "Run one read-only Workers Analytics Engine SQL statement."
    )]
    async fn cloudflare_analytics_engine_query(
        &self,
        Parameters(args): Parameters<AnalyticsEngineQueryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if let Err(result) = validate_analytics_engine_sql(&args.sql) {
            return Ok(result);
        }
        let max_rows = args.max_rows.unwrap_or(100).clamp(1, 1000);
        match self
            .cloudflare
            .query_analytics_engine(account_id, &args.sql)
            .await
        {
            Ok(result) => {
                let (result, truncated) = limit_analytics_engine_result_rows(result, max_rows);
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "policy": {
                        "restricted_sql": true,
                        "contract": "mcp-toolkit-policy-core/restricted-sql",
                        "max_rows": max_rows,
                    },
                    "truncated": truncated,
                    "result": result,
                })))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "analytics_engine_describe_schema",
        description = "Describe Workers Analytics Engine dataset schema hints, including canonical blob/double/index columns."
    )]
    async fn cloudflare_analytics_engine_describe_schema(
        &self,
        Parameters(args): Parameters<AnalyticsEngineListDatasetsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let max_rows = args.max_rows.unwrap_or(100).clamp(1, 1000);
        match self
            .cloudflare
            .query_analytics_engine(account_id, "SHOW TABLES")
            .await
        {
            Ok(result) => {
                let (datasets, truncated) = limit_analytics_engine_result_rows(result, max_rows);
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "schema": analytics_engine_schema_hints(Some(datasets.clone())),
                    "dataset_readback": {
                        "query": "SHOW TABLES",
                        "truncated": truncated,
                        "datasets": datasets,
                    },
                })))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "analytics_engine_validate_query",
        description = "Validate one read-only Workers Analytics Engine SQL statement against dataset and column schema hints without executing the statement."
    )]
    async fn cloudflare_analytics_engine_validate_query(
        &self,
        Parameters(args): Parameters<AnalyticsEngineValidateQueryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if let Err(result) = validate_analytics_engine_sql(&args.sql) {
            return Ok(result);
        }
        let dataset_readback = if args.include_dataset_readback {
            match self
                .cloudflare
                .query_analytics_engine(account_id, "SHOW TABLES")
                .await
            {
                Ok(result) => Some(result),
                Err(err) => {
                    return Ok(adapter_error_result(err));
                }
            }
        } else {
            None
        };
        let schema = analytics_engine_schema_hints(dataset_readback.clone());
        let validation = validate_sql_against_schema(&args.sql, &schema, "analytics_engine");
        let is_ok = validation["ok"].as_bool().unwrap_or(false);
        let response = json!({
            "ok": is_ok,
            "account_id": account_id,
            "mode": "schema_preflight",
            "executed_user_query": false,
            "schema": schema,
            "validation": validation,
            "query_plan": {
                "available": false,
                "reason": "analytics_engine_sql_api_does_not_expose_pre_execution_plan",
                "estimated_rows": null,
                "estimated_read_bytes": null,
            },
            "dataset_readback": dataset_readback.map(|datasets| json!({
                "query": "SHOW TABLES",
                "datasets": datasets,
            })),
        });
        if is_ok {
            Ok(CallToolResult::structured(response))
        } else {
            Ok(CallToolResult::structured_error(response))
        }
    }

    #[tool(
        name = "analytics_engine_list_datasets",
        description = "List Workers Analytics Engine datasets using SHOW TABLES."
    )]
    async fn cloudflare_analytics_engine_list_datasets(
        &self,
        Parameters(args): Parameters<AnalyticsEngineListDatasetsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let max_rows = args.max_rows.unwrap_or(100).clamp(1, 1000);
        match self
            .cloudflare
            .query_analytics_engine(account_id, "SHOW TABLES")
            .await
        {
            Ok(result) => {
                let (datasets, truncated) = limit_analytics_engine_result_rows(result, max_rows);
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "query": "SHOW TABLES",
                    "truncated": truncated,
                    "datasets": datasets,
                })))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_execute_write",
        description = "Execute one audited D1 row-write SQL statement with dry-run safety. Allows INSERT, UPDATE, DELETE, or REPLACE only."
    )]
    async fn cloudflare_d1_execute_write(
        &self,
        Parameters(args): Parameters<D1ExecuteWriteArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let statement_kind = match classify_d1_write_sql(&args.sql) {
            Ok(kind) => kind,
            Err(result) => return Ok(result),
        };
        let max_rows = args.max_rows.unwrap_or(100).clamp(1, 1000);
        let plan = json!({
            "operation": "d1_execute_write",
            "account_id": account_id,
            "database_id": &args.database_id,
            "statement_kind": statement_kind,
            "sql_sha256": sha256_hex(args.sql.trim()),
            "dry_run": args.dry_run,
        });
        if args.dry_run {
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "d1_execute_write",
                "plan": plan,
                "policy": {
                    "d1_write_sql": true,
                    "allowed_statement_kinds": D1_WRITE_ALLOWED_KINDS,
                    "single_statement": true,
                    "max_rows": max_rows,
                },
            })));
        }
        match self
            .cloudflare
            .execute_d1_database_write(account_id, &args.database_id, &args.sql, &args.params)
            .await
        {
            Ok(result) => {
                let (result, truncated) = limit_d1_result_rows(result, max_rows);
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "d1_execute_write",
                    "plan": plan,
                    "policy": {
                        "d1_write_sql": true,
                        "allowed_statement_kinds": D1_WRITE_ALLOWED_KINDS,
                        "single_statement": true,
                        "max_rows": max_rows,
                    },
                    "truncated": truncated,
                    "result": result,
                })))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "d1_apply_migrations",
        description = "Apply local Wrangler-style D1 SQL migration files in lexical order with dry-run safety."
    )]
    async fn cloudflare_d1_apply_migrations(
        &self,
        Parameters(args): Parameters<D1ApplyMigrationsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let migrations_table = match normalize_d1_migrations_table(args.migrations_table.as_deref())
        {
            Ok(table) => table,
            Err(result) => return Ok(result),
        };
        let migrations = match inspect_d1_migration_files(&args.migrations_directory) {
            Ok(migrations) => migrations,
            Err(result) => return Ok(result),
        };
        let max_rows = args.max_rows.unwrap_or(100).clamp(1, 1000);
        if args.dry_run {
            let applied_names = match self
                .cloudflare
                .query_d1_database(
                    account_id,
                    &args.database_id,
                    &d1_applied_migrations_sql(&migrations_table),
                    &[],
                )
                .await
            {
                Ok(result) => collect_d1_migration_names(&result),
                Err(err) => {
                    return Ok(d1_migration_unknown_ledger_result(
                        account_id,
                        &args.database_id,
                        &migrations_table,
                        &migrations,
                        err.payload(),
                    ));
                }
            };
            let skipped = d1_skipped_migrations(&migrations, &applied_names);
            let pending = d1_pending_migrations(&migrations, &applied_names);
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "d1_apply_migrations",
                "account_id": account_id,
                "database_id": &args.database_id,
                "migrations_table": migrations_table,
                "migration_count": migrations.len(),
                "already_applied": applied_names.iter().cloned().collect::<Vec<_>>(),
                "skipped_migrations": skipped,
                "pending_count": pending.len(),
                "pending_migrations": pending.iter().map(d1_migration_summary).collect::<Vec<_>>(),
                "candidate_migrations": d1_migration_summaries(&migrations),
                "ledger_checked": true,
                "unknown_ledger": false,
                "max_rows": max_rows,
                "dry_run_note": "No D1 writes applied; remote migration ledger was read to classify already-applied and pending migrations.",
            })));
        }

        if let Err(err) = self
            .cloudflare
            .execute_d1_database_write(
                account_id,
                &args.database_id,
                &d1_migrations_table_init_sql(&migrations_table),
                &[],
            )
            .await
        {
            return Ok(adapter_error_result(err));
        }

        let applied_names = match self
            .cloudflare
            .query_d1_database(
                account_id,
                &args.database_id,
                &d1_applied_migrations_sql(&migrations_table),
                &[],
            )
            .await
        {
            Ok(result) => collect_d1_migration_names(&result),
            Err(err) => {
                return Ok(d1_migration_unknown_ledger_result(
                    account_id,
                    &args.database_id,
                    &migrations_table,
                    &migrations,
                    err.payload(),
                ));
            }
        };
        let skipped = d1_skipped_migrations(&migrations, &applied_names);
        let pending = d1_pending_migrations(&migrations, &applied_names);
        let mut applied = Vec::new();
        for migration in &pending {
            let sql = match read_d1_migration_sql(migration) {
                Ok(sql) => sql,
                Err(result) => {
                    let error = d1_call_tool_error_value(result);
                    return Ok(CallToolResult::structured_error(json!({
                        "ok": false,
                        "operation": "d1_apply_migrations",
                        "error": error,
                        "migration": d1_migration_summary(migration),
                        "already_applied": applied_names.iter().cloned().collect::<Vec<_>>(),
                        "skipped_migrations": skipped,
                        "pending_migrations": pending.iter().map(d1_migration_summary).collect::<Vec<_>>(),
                        "applied_migrations": applied,
                        "unknown_ledger": false,
                    })));
                }
            };
            match self
                .cloudflare
                .execute_d1_database_write(
                    account_id,
                    &args.database_id,
                    &d1_migration_apply_sql(&sql, &migrations_table, &migration.name),
                    &[],
                )
                .await
            {
                Ok(result) => {
                    let (result, truncated) = limit_d1_result_rows(result, max_rows);
                    applied.push(json!({
                        "name": &migration.name,
                        "size_bytes": migration.size_bytes,
                        "sql_sha256": &migration.sql_sha256,
                        "truncated": truncated,
                        "result": result,
                    }));
                }
                Err(err) => {
                    return Ok(CallToolResult::structured_error(json!({
                        "ok": false,
                        "operation": "d1_apply_migrations",
                        "error": err.payload(),
                        "migration": d1_migration_summary(migration),
                        "already_applied": applied_names.iter().cloned().collect::<Vec<_>>(),
                        "skipped_migrations": skipped,
                        "pending_migrations": pending.iter().map(d1_migration_summary).collect::<Vec<_>>(),
                        "applied_migrations": applied,
                        "unknown_ledger": false,
                    })));
                }
            }
        }
        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "d1_apply_migrations",
            "account_id": account_id,
            "database_id": &args.database_id,
            "migrations_table": migrations_table,
            "migration_count": migrations.len(),
            "already_applied": applied_names.iter().cloned().collect::<Vec<_>>(),
            "skipped_migrations": skipped,
            "pending_count": pending.len(),
            "pending_migrations": pending.iter().map(d1_migration_summary).collect::<Vec<_>>(),
            "applied_migrations": applied,
            "ledger_checked": true,
            "unknown_ledger": false,
            "max_rows": max_rows,
        })))
    }

    #[tool(
        name = "capabilities_check",
        description = "Read-only Cloudflare API capability probe for configured DNS, Tunnel, Access, Pages, D1, Queues, Workers, and redirect surfaces."
    )]
    async fn cloudflare_capabilities_check(
        &self,
        Parameters(args): Parameters<CapabilitiesCheckArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id_source = resolved_identifier_source(
            args.account_id.as_deref(),
            self.default_account_id.as_deref(),
        );
        let zone_id_source =
            resolved_identifier_source(args.zone_id.as_deref(), self.default_zone_id.as_deref());
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let capabilities = self
            .cloudflare
            .check_capabilities(Some(account_id), Some(zone_id))
            .await;
        let cloudflare_api_ok = capabilities
            .iter()
            .all(|probe| !capability_probe_blocks_preflight(probe));

        let mut findings = Vec::new();
        if !cloudflare_api_ok {
            findings.push(json!({
                "code": "cloudflare.capability_probe_failed",
                "severity": "error",
                "message": "One or more Cloudflare API capability probes failed.",
            }));
        }
        if args.require_explicit_zone_id && zone_id_source != "argument" {
            findings.push(json!({
                "code": "target.zone_id_from_default",
                "severity": "error",
                "message": "zone_id came from CLOUDFLARE_MCP_DEFAULT_ZONE_ID while explicit zone targeting was required.",
            }));
        }
        if let Some(expected_account_id) = normalized_non_empty(args.expected_account_id.as_deref())
        {
            if expected_account_id != account_id {
                findings.push(json!({
                    "code": "target.account_id_mismatch",
                    "severity": "error",
                    "expected": expected_account_id,
                    "observed": account_id,
                }));
            }
        }
        if let Some(expected_zone_id) = normalized_non_empty(args.expected_zone_id.as_deref()) {
            if expected_zone_id != zone_id {
                findings.push(json!({
                    "code": "target.zone_id_mismatch",
                    "severity": "error",
                    "expected": expected_zone_id,
                    "observed": zone_id,
                }));
            }
        }

        let mut observed_zone_name = None;
        let mut observed_zone_account_id = None;
        let mut zone_identity_ok = false;
        let zone_identity = match self.cloudflare.get_zone_identity(zone_id).await {
            Ok(identity) => {
                zone_identity_ok = true;
                observed_zone_name = identity.name.clone();
                observed_zone_account_id = identity
                    .account
                    .as_ref()
                    .and_then(|account| account.id.clone());
                json!({
                    "checked": true,
                    "ok": true,
                    "id": identity.id,
                    "name": identity.name,
                    "account": identity.account,
                })
            }
            Err(err) => {
                if args.expected_zone_name.as_deref().is_some_and(|value| {
                    normalized_zone_name(Some(value))
                        .map(|normalized| !normalized.is_empty())
                        .unwrap_or(false)
                }) {
                    findings.push(json!({
                        "code": "target.zone_identity_unavailable",
                        "severity": "error",
                        "message": "Expected zone name was provided, but Cloudflare zone identity readback failed.",
                    }));
                }
                json!({
                    "checked": true,
                    "ok": false,
                    "error": err.payload(),
                })
            }
        };
        if let Some(zone_account_id) = observed_zone_account_id.as_deref() {
            if zone_account_id != account_id {
                findings.push(json!({
                    "code": "target.zone_account_mismatch",
                    "severity": "error",
                    "message": "The effective zone belongs to a different account than the effective account_id.",
                    "zone_account_id": zone_account_id,
                    "account_id": account_id,
                }));
            }
        }
        if zone_identity_ok
            && let Some(expected_zone_name) =
                normalized_zone_name(args.expected_zone_name.as_deref())
        {
            let observed = observed_zone_name
                .as_deref()
                .and_then(|name| normalized_zone_name(Some(name)));
            if observed.as_deref() != Some(expected_zone_name.as_str()) {
                findings.push(json!({
                    "code": "target.zone_name_mismatch",
                    "severity": "error",
                    "expected": expected_zone_name,
                    "observed": observed_zone_name,
                }));
            }
        }

        let preflight_ok = findings.is_empty();
        Ok(CallToolResult::structured(json!({
            "ok": preflight_ok,
            "account_id": account_id,
            "zone_id": zone_id,
            "preflight": {
                "ok": preflight_ok,
                "mcp": {
                    "session_initialized": true,
                    "tool_call_reached_handler": true,
                    "auth_enabled": self.auth_enabled,
                    "proof": "This payload is produced inside a normal MCP tools/call handler after initialize and tool-call dispatch."
                },
                "target": {
                    "account_id": account_id,
                    "account_id_source": account_id_source,
                    "zone_id": zone_id,
                    "zone_id_source": zone_id_source,
                    "zone_identity": zone_identity,
                },
                "cloudflare_api": {
                    "ok": cloudflare_api_ok,
                    "probe_count": capabilities.len(),
                },
                "findings": findings,
            },
            "capabilities": capabilities,
        })))
    }

    #[tool(
        name = "pages_list_projects",
        description = "List Cloudflare Pages projects."
    )]
    async fn cloudflare_pages_list_projects(
        &self,
        Parameters(args): Parameters<PagesListProjectsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let page = args.page.unwrap_or(1).max(1);
        let per_page = args.per_page.unwrap_or(50).clamp(1, 100);
        match self
            .cloudflare
            .list_pages_projects(account_id, page, per_page)
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_get_project",
        description = "Get a Cloudflare Pages project."
    )]
    async fn cloudflare_pages_get_project(
        &self,
        Parameters(args): Parameters<PagesProjectArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_pages_project(account_id, &args.project_name)
            .await
        {
            Ok(project) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "project": project}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_update_project",
        description = "Update Cloudflare Pages project settings with dry-run support."
    )]
    async fn cloudflare_pages_update_project(
        &self,
        Parameters(args): Parameters<PagesUpdateProjectArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if args.dry_run {
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "pages_update_project",
                "dry_run": true,
                "account_id": account_id,
                "project_name": args.project_name,
                "settings": args.settings,
                "deployment_snapshot_note": pages_project_update_snapshot_note(),
            })));
        }
        match self
            .cloudflare
            .update_pages_project(account_id, &args.project_name, &args.settings)
            .await
        {
            Ok(project) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "project": project,
                "deployment_snapshot_note": pages_project_update_snapshot_note(),
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_list_deployments",
        description = "List Cloudflare Pages deployments."
    )]
    async fn cloudflare_pages_list_deployments(
        &self,
        Parameters(args): Parameters<PagesListDeploymentsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let page = args.page.unwrap_or(1).max(1);
        let per_page = args.per_page.unwrap_or(50).clamp(1, 100);
        match self
            .cloudflare
            .list_pages_deployments(
                account_id,
                &args.project_name,
                args.environment.as_deref(),
                page,
                per_page,
            )
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_get_deployment",
        description = "Get a Cloudflare Pages deployment."
    )]
    async fn cloudflare_pages_get_deployment(
        &self,
        Parameters(args): Parameters<PagesDeploymentArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_pages_deployment(account_id, &args.project_name, &args.deployment_id)
            .await
        {
            Ok(deployment) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "deployment": deployment}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_trigger_deployment",
        description = "Trigger a Git-backed Cloudflare Pages deployment with dry-run support. Use pages_deploy_directory for direct-upload projects."
    )]
    async fn cloudflare_pages_trigger_deployment(
        &self,
        Parameters(args): Parameters<PagesTriggerDeploymentArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let request = PagesDeploymentTriggerRequest {
            branch: args.branch,
            commit_hash: args.commit_hash,
            commit_message: args.commit_message,
            commit_dirty: args.commit_dirty,
        };
        if args.dry_run {
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "pages_trigger_deployment",
                "dry_run": true,
                "account_id": account_id,
                "project_name": args.project_name,
                "request": request,
                "direct_upload_note": "This tool triggers Git-backed Pages deployments. Use pages_deploy_directory for direct-upload projects.",
            })));
        }
        match self
            .cloudflare
            .get_pages_project(account_id, &args.project_name)
            .await
        {
            Ok(project) if !pages_project_has_git_source(&project.source) => {
                return Ok(pages_trigger_requires_git_source_result(
                    account_id,
                    &args.project_name,
                    request,
                ));
            }
            Ok(_) => {}
            Err(_) => {}
        }
        match self
            .cloudflare
            .trigger_pages_deployment(account_id, &args.project_name, &request)
            .await
        {
            Ok(deployment) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "deployment": deployment}),
            )),
            Err(err) if is_pages_manifest_required_error(&err) => Ok(
                pages_direct_upload_manifest_required_result(account_id, &args.project_name),
            ),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_deploy_directory",
        description = "Inspect and direct-upload a local Pages output directory, including static assets, advanced-mode _worker.js, and Wrangler-built Pages Functions _worker.bundle payloads, as a Cloudflare Pages deployment."
    )]
    async fn cloudflare_pages_deploy_directory(
        &self,
        Parameters(args): Parameters<PagesDeployDirectoryArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let max_files = args
            .max_files
            .unwrap_or(MAX_PAGES_ASSET_COUNT_DEFAULT)
            .clamp(1, MAX_PAGES_ASSET_COUNT_DEFAULT);
        let package = match inspect_pages_directory_with_options(
            &args.directory,
            max_files,
            PagesDirectoryInspectOptions {
                project_root: args.project_root.clone(),
                wrangler_bin: None,
            },
        ) {
            Ok(package) => package,
            Err(err) => {
                return Ok(CallToolResult::structured_error(json!({
                    "ok": false,
                    "error": err.payload(),
                })));
            }
        };
        let request = PagesDeploymentTriggerRequest {
            branch: args.branch,
            commit_hash: args.commit_hash,
            commit_message: args.commit_message,
            commit_dirty: args.commit_dirty,
        };
        if args.dry_run {
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "pages_deploy_directory",
                "account_id": account_id,
                "project_name": args.project_name,
                "directory": package.summary(),
                "request": request,
                "upload": {
                    "skip_caching": args.skip_caching,
                    "uploaded_asset_count": 0,
                    "cached_asset_count": 0,
                    "batch_count": 0,
                },
                "dry_run_note": "No Cloudflare API calls or mutations applied.",
            })));
        }
        match self
            .cloudflare
            .deploy_pages_directory_direct_upload(
                account_id,
                &args.project_name,
                &package,
                &request,
                args.skip_caching,
            )
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "pages_deploy_directory",
                "account_id": account_id,
                "project_name": args.project_name,
                "directory": package.summary(),
                "request": request,
                "upload": result.upload,
                "deployment": result.deployment,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_retry_deployment",
        description = "Retry a Cloudflare Pages deployment with dry-run support."
    )]
    async fn cloudflare_pages_retry_deployment(
        &self,
        Parameters(args): Parameters<PagesDeploymentActionArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        pages_deployment_action(self, args, "retry").await
    }

    #[tool(
        name = "pages_rollback_deployment",
        description = "Rollback to a Cloudflare Pages deployment with dry-run support."
    )]
    async fn cloudflare_pages_rollback_deployment(
        &self,
        Parameters(args): Parameters<PagesDeploymentActionArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        pages_deployment_action(self, args, "rollback").await
    }

    #[tool(
        name = "pages_list_domains",
        description = "List custom domains for a Cloudflare Pages project."
    )]
    async fn cloudflare_pages_list_domains(
        &self,
        Parameters(args): Parameters<PagesProjectArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .list_pages_domains(account_id, &args.project_name)
            .await
        {
            Ok(domains) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "domains": domains}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_get_domain",
        description = "Get a custom domain for a Cloudflare Pages project."
    )]
    async fn cloudflare_pages_get_domain(
        &self,
        Parameters(args): Parameters<PagesDomainArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_pages_domain(account_id, &args.project_name, &args.domain_name)
            .await
        {
            Ok(domain) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "domain": domain}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_ensure_domain",
        description = "Attach a custom domain to a Cloudflare Pages project with dry-run support."
    )]
    async fn cloudflare_pages_ensure_domain(
        &self,
        Parameters(args): Parameters<PagesEnsureDomainArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if args.dry_run {
            return Ok(CallToolResult::structured(
                json!({"ok": true, "operation": "pages_ensure_domain", "dry_run": true, "account_id": account_id, "project_name": args.project_name, "domain_name": args.domain_name}),
            ));
        }
        match self
            .cloudflare
            .add_pages_domain(account_id, &args.project_name, &args.domain_name)
            .await
        {
            Ok(domain) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "domain": domain}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "pages_retry_domain_validation",
        description = "Retry validation for a Cloudflare Pages custom domain."
    )]
    async fn cloudflare_pages_retry_domain_validation(
        &self,
        Parameters(args): Parameters<PagesEnsureDomainArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if args.dry_run {
            return Ok(CallToolResult::structured(
                json!({"ok": true, "operation": "pages_retry_domain_validation", "dry_run": true, "account_id": account_id, "project_name": args.project_name, "domain_name": args.domain_name}),
            ));
        }
        match self
            .cloudflare
            .retry_pages_domain_validation(account_id, &args.project_name, &args.domain_name)
            .await
        {
            Ok(domain) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "domain": domain}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "r2_get_object",
        description = "Read or download a private Cloudflare R2 object through the signed S3-compatible API."
    )]
    async fn cloudflare_r2_get_object(
        &self,
        Parameters(args): Parameters<R2GetObjectArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let max_bytes = args
            .max_bytes
            .map(|value| value.clamp(1, R2_INLINE_HARD_MAX_BYTES));
        let inline_max_bytes = max_bytes.unwrap_or(R2_INLINE_DEFAULT_MAX_BYTES);
        let response_mode = args.response_mode.trim().to_ascii_lowercase();
        if !matches!(response_mode.as_str(), "auto" | "text" | "base64" | "file") {
            return Ok(invalid_argument_result(
                "r2.invalid_response_mode",
                "response_mode must be auto, text, base64, or file",
                "Use response_mode='file' with output_path for large objects.",
            ));
        }
        let output_path_arg = args
            .output_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        if args.persist_output_path {
            let Some(output_path) = output_path_arg.as_deref() else {
                return Ok(invalid_argument_result(
                    "r2.output_path_required",
                    "output_path is required when persist_output_path=true",
                    "Provide output_path to persist it for future R2 downloads.",
                ));
            };
            if let Err(result) = persist_r2_output_path(output_path) {
                return Ok(result);
            }
        }
        let persisted_output_path =
            if output_path_arg.is_none() && matches!(response_mode.as_str(), "auto" | "file") {
                match load_persisted_r2_output_path() {
                    Ok(path) => path,
                    Err(result) => return Ok(result),
                }
            } else {
                None
            };
        let effective_output_path = output_path_arg
            .as_deref()
            .or(persisted_output_path.as_deref());
        let output_path_source = if output_path_arg.is_some() {
            Some("argument")
        } else if persisted_output_path.is_some() {
            Some("persisted")
        } else {
            None
        };
        let persisted_output_path_active =
            args.persist_output_path || output_path_source == Some("persisted");
        let metadata = match self
            .cloudflare
            .inspect_r2_object(account_id, &args.bucket_name, &args.object_key)
            .await
        {
            Ok(metadata) => metadata,
            Err(err) => return Ok(adapter_error_result(err)),
        };

        let declared_too_large_for_inline = metadata
            .content_length
            .is_some_and(|length| length > inline_max_bytes as u64);
        let content_type_is_binary = metadata
            .content_type
            .as_deref()
            .is_some_and(r2_content_type_is_binary);
        let use_file = response_mode == "file"
            || (response_mode == "auto"
                && (declared_too_large_for_inline || content_type_is_binary)
                && effective_output_path.is_some());

        if response_mode == "auto" && content_type_is_binary && !use_file {
            return Ok(r2_download_too_large_result(
                &metadata,
                inline_max_bytes as u64,
                "r2.binary_auto_requires_output_path",
                "R2 object appears to be binary; auto mode will not inline binary content",
                "Provide output_path so response_mode='auto' can write the object to a local file, or use response_mode='base64' explicitly for a capped inline read.",
            ));
        }

        if response_mode == "auto" && declared_too_large_for_inline && !use_file {
            return Ok(r2_download_too_large_result(
                &metadata,
                inline_max_bytes as u64,
                "r2.object_too_large_for_auto_inline",
                "R2 object is too large for inline auto response and no output_path was provided",
                "Provide response_mode='file' and output_path, or provide output_path with response_mode='auto' so the object is written locally.",
            ));
        }

        if matches!(response_mode.as_str(), "text" | "base64")
            && declared_too_large_for_inline
            && max_bytes.is_none()
            && !args.allow_large_download
            && args.range.is_none()
        {
            return Ok(r2_download_too_large_result(
                &metadata,
                inline_max_bytes as u64,
                "r2.object_too_large_for_inline",
                "R2 object is too large for inline response",
                "Use response_mode='file' with output_path, provide max_bytes for an explicit partial inline read, or provide a byte range.",
            ));
        }

        if use_file {
            let output_path =
                match prepare_r2_output_path(effective_output_path, args.create_parent_dirs) {
                    Ok(path) => path,
                    Err(result) => return Ok(result),
                };
            if metadata
                .content_length
                .is_some_and(|length| length > R2_FILE_DEFAULT_MAX_BYTES)
                && max_bytes.is_none()
                && !args.allow_large_download
                && args.range.is_none()
            {
                return Ok(r2_download_too_large_result(
                    &metadata,
                    R2_FILE_DEFAULT_MAX_BYTES,
                    "r2.object_too_large_for_file",
                    "R2 object is too large for default local-file download",
                    "Set allow_large_download=true to download the full object, provide max_bytes for a capped local file, or provide a byte range.",
                ));
            }
            let download = match self
                .cloudflare
                .download_r2_object_to_file(
                    account_id,
                    &args.bucket_name,
                    &args.object_key,
                    args.range.as_deref(),
                    &output_path,
                    max_bytes.map(|value| value as u64),
                )
                .await
            {
                Ok(download) => download,
                Err(err) => return Ok(adapter_error_result(err)),
            };
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "r2_get_object",
                "account_id": account_id,
                "bucket_name": download.bucket_name,
                "object_key": download.object_key,
                "status": download.status,
                "encoding": "file",
                "output_path": download.output_path,
                "bytes_written": download.bytes_written,
                "sha256": download.sha256,
                "content_type": download.content_type,
                "content_length": download.content_length,
                "etag": download.etag,
                "last_modified": download.last_modified,
                "range": download.range,
                "truncated": download.truncated,
                "max_bytes": max_bytes,
                "auto_switched_to_file": response_mode == "auto",
                "output_path_source": output_path_source,
                "persisted_output_path": persisted_output_path_active,
            })));
        }

        let effective_range = if args.range.is_none() && declared_too_large_for_inline {
            Some(format!("bytes=0-{}", inline_max_bytes.saturating_sub(1)))
        } else {
            args.range.clone()
        };

        let object = match self
            .cloudflare
            .get_r2_object(
                account_id,
                &args.bucket_name,
                &args.object_key,
                effective_range.as_deref(),
            )
            .await
        {
            Ok(object) => object,
            Err(err) => return Ok(adapter_error_result(err)),
        };

        let truncated = object.body.len() > inline_max_bytes || declared_too_large_for_inline;
        let body = if truncated {
            &object.body[..std::cmp::min(object.body.len(), inline_max_bytes)]
        } else {
            &object.body
        };
        let utf8_body = std::str::from_utf8(body).ok();
        if response_mode == "auto" && utf8_body.is_none() {
            if effective_output_path.is_some() {
                let output_path =
                    match prepare_r2_output_path(effective_output_path, args.create_parent_dirs) {
                        Ok(path) => path,
                        Err(result) => return Ok(result),
                    };
                return Ok(write_r2_inline_body_to_file_result(
                    account_id,
                    &object,
                    body,
                    &output_path,
                    inline_max_bytes,
                    truncated,
                    true,
                    output_path_source,
                    persisted_output_path_active,
                ));
            }
            return Ok(CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "r2_get_object",
                "error": {
                    "code": "r2.binary_auto_requires_output_path",
                    "message": "R2 object body is not valid UTF-8; auto mode will not inline binary content",
                    "hint": "Provide output_path so response_mode='auto' can write the object to a local file, or use response_mode='base64' explicitly for a capped inline read.",
                },
                "bucket_name": object.bucket_name,
                "object_key": object.object_key,
                "content_type": object.content_type,
                "content_length": object.content_length,
                "etag": object.etag,
                "last_modified": object.last_modified,
                "range": object.range,
                "bytes_read": body.len(),
                "truncated": truncated,
                "max_bytes": inline_max_bytes,
            })));
        }
        let encoding = match response_mode.as_str() {
            "text" if utf8_body.is_none() => {
                return Ok(CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "r2_get_object",
                    "error": {
                        "code": "r2.body_not_utf8",
                        "message": "R2 object body is not valid UTF-8 text",
                        "hint": "Retry with response_mode='base64' or response_mode='auto'.",
                    },
                    "bucket_name": object.bucket_name,
                    "object_key": object.object_key,
                    "content_type": object.content_type,
                    "content_length": object.content_length,
                    "etag": object.etag,
                    "last_modified": object.last_modified,
                    "range": object.range,
                    "bytes_read": body.len(),
                    "truncated": truncated,
                })));
            }
            "text" => "text",
            "base64" => "base64",
            _ if utf8_body.is_some() => "text",
            _ => "base64",
        };
        let content = if encoding == "text" {
            json!(utf8_body.unwrap_or_default())
        } else {
            json!(BASE64_STANDARD.encode(body))
        };

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "r2_get_object",
            "account_id": account_id,
            "bucket_name": object.bucket_name,
            "object_key": object.object_key,
            "status": object.status,
            "content_type": object.content_type,
            "content_length": object.content_length,
            "etag": object.etag,
            "last_modified": object.last_modified,
            "range": object.range,
            "encoding": encoding,
            "content": content,
            "bytes_read": body.len(),
            "object_bytes": object.body.len(),
            "truncated": truncated,
            "max_bytes": inline_max_bytes,
            "download_range": effective_range,
            "output_path": effective_output_path,
            "output_path_source": output_path_source,
            "persisted_output_path": persisted_output_path_active,
        })))
    }

    #[tool(
        name = "r2_inspect_object",
        description = "Inspect private Cloudflare R2 object metadata through a signed S3-compatible HEAD request."
    )]
    async fn cloudflare_r2_inspect_object(
        &self,
        Parameters(args): Parameters<R2InspectObjectArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .inspect_r2_object(account_id, &args.bucket_name, &args.object_key)
            .await
        {
            Ok(metadata) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "r2_inspect_object",
                "account_id": account_id,
                "bucket_name": metadata.bucket_name,
                "object_key": metadata.object_key,
                "status": metadata.status,
                "content_type": metadata.content_type,
                "content_length": metadata.content_length,
                "etag": metadata.etag,
                "last_modified": metadata.last_modified,
                "range": metadata.range,
                "metadata": metadata.custom_metadata,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "r2_put_object",
        description = "Write a private Cloudflare R2 object through the signed S3-compatible API."
    )]
    async fn cloudflare_r2_put_object(
        &self,
        Parameters(args): Parameters<R2PutObjectArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let body = match r2_write_body(args.content_text.as_deref(), args.content_base64.as_deref())
        {
            Ok(body) => body,
            Err(base) => return Ok(base),
        };
        let metadata = args
            .metadata
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        let body_len = body.len();
        let plan = plan_r2_put_object(
            account_id,
            &args.bucket_name,
            &args.object_key,
            body_len,
            args.content_type.as_deref(),
            metadata.len(),
        );
        let audit = MutationAuditSession::start(
            Some(&parts),
            "r2_put_object",
            json!({
                "account_id": account_id,
                "bucket_name": &args.bucket_name,
                "object_key": &args.object_key,
                "bytes": body_len,
                "content_type": args.content_type.clone(),
                "metadata_keys": metadata.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            }),
            args.dry_run,
        );

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "r2_put_object",
                "account_id": account_id,
                "bucket_name": args.bucket_name,
                "object_key": args.object_key,
                "bytes": body_len,
                "content_type": args.content_type.clone(),
                "metadata_keys": metadata.iter().map(|(key, _)| key).collect::<Vec<_>>(),
                "dry_run_note": "No R2 object write applied.",
            }))
        } else {
            match self
                .cloudflare
                .put_r2_object(
                    account_id,
                    &args.bucket_name,
                    &args.object_key,
                    body,
                    args.content_type.as_deref(),
                    &metadata,
                )
                .await
            {
                Ok(result) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "r2_put_object",
                    "account_id": account_id,
                    "bucket_name": result.bucket_name,
                    "object_key": result.object_key,
                    "status": result.status,
                    "content_type": result.content_type,
                    "content_length": result.content_length,
                    "etag": result.etag,
                    "version_id": result.version_id,
                    "bytes_written": body_len,
                })),
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "verify_dns_route",
        description = "Verify observed DNS CNAME route state against desired hostname/target/proxied/ttl intent."
    )]
    async fn cloudflare_verify_dns_route(
        &self,
        Parameters(args): Parameters<VerifyDnsRouteArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let request = DnsRecordUpsertRequest {
            hostname: args.hostname,
            target: args.target,
            proxied: args.proxied,
            ttl: args.ttl,
        };
        let routes = match self
            .cloudflare
            .list_dns_records(zone_id, Some(&request.hostname))
            .await
        {
            Ok(page) => page.items,
            Err(err) => return Ok(adapter_error_result(err)),
        };
        let verification = verify_dns_route(&routes, &request);
        let plan = plan_dns_route_reconciliation(&routes, &request);
        let payload = json!({
            "ok": verification.state == DnsRouteVerificationState::Matched,
            "operation": "verify_dns_route",
            "zone_id": zone_id,
            "request": request,
            "verification": verification,
            "reconciliation_plan": plan.as_ref().ok(),
            "reconciliation_conflict": plan.as_ref().err(),
        });
        if payload["ok"] == json!(true) {
            Ok(CallToolResult::structured(payload))
        } else {
            Ok(CallToolResult::structured_error(payload))
        }
    }

    #[tool(
        name = "verify_http_gate",
        description = "Probe URL and classify verification state as access_gated, origin_reachable, misconfigured, timeout, or transport_error."
    )]
    async fn cloudflare_verify_http_gate(
        &self,
        Parameters(args): Parameters<VerifyHttpGateArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let parsed = match Url::parse(&args.url) {
            Ok(url) => url,
            Err(err) => {
                return Ok(invalid_argument_result(
                    "verification.invalid_url",
                    format!("invalid probe url: {err}"),
                    "Provide an absolute http(s) URL.",
                ));
            }
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            return Ok(invalid_argument_result(
                "verification.invalid_scheme",
                "probe url must use http or https",
                "Use an absolute http(s) URL for verification probe.",
            ));
        }
        let expected_state = match ExpectedVerificationState::parse(&args.expected_state) {
            Ok(expected) => expected,
            Err(err) => {
                return Ok(invalid_argument_result(
                    "verification.invalid_expected_state",
                    err,
                    "Use expected_state='access_gated', 'origin_reachable', or 'any'.",
                ));
            }
        };
        let timeout_ms = args.timeout_ms.unwrap_or(5_000).clamp(250, 30_000);
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                return Ok(CallToolResult::structured_error(json!({
                    "ok": false,
                    "error": {
                        "code": "verification.probe_client_init_failed",
                        "message": format!("failed to initialize probe client: {err}"),
                        "hint": "Retry probe; if persistent, inspect runtime TLS/network stack.",
                    }
                })));
            }
        };

        let started = now_unix_ms();
        let verification = match client.get(parsed.as_str()).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let redirect_location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                classify_http_result(
                    parsed.as_str(),
                    status,
                    redirect_location,
                    now_unix_ms().saturating_sub(started),
                )
            }
            Err(err) if err.is_timeout() => {
                timeout_result(parsed.as_str(), now_unix_ms().saturating_sub(started))
            }
            Err(err) => transport_error_result(
                parsed.as_str(),
                now_unix_ms().saturating_sub(started),
                err.to_string(),
            ),
        };

        if let Ok(mut status) = self.verification_status.lock() {
            *status = Some(verification.clone());
        }
        tracing::info!(
            probe_host = ?parsed.host_str(),
            expected_state = expected_state.as_str(),
            observed_state = verification.state.as_str(),
            status_code = ?verification.status_code,
            code = verification.code,
            "cloudflare verification probe"
        );

        if expected_state.matches(verification.state) {
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "verify_http_gate",
                "expected_state": expected_state.as_str(),
                "verification": verification,
            })));
        }

        let severity_hint = if matches!(
            verification.state,
            VerificationState::OriginReachable | VerificationState::Misconfigured
        ) {
            "Treat as potential exposure/configuration incident until confirmed otherwise."
        } else {
            "Probe did not match expected state; inspect diagnostics and retry."
        };
        Ok(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "verify_http_gate",
            "error": {
                "code": "verification.unexpected_state",
                "message": format!(
                    "expected state {:?} but observed {:?}",
                    expected_state.as_str(),
                    verification.state.as_str()
                ),
                "hint": severity_hint,
                "expected_state": expected_state.as_str(),
                "observed_state": verification.state.as_str(),
            },
            "verification": verification,
        })))
    }

    #[tool(
        name = "portal_agent_request",
        description = "Call an allowlisted portal agent endpoint with configured server-side agent and optional Cloudflare Access service credentials. Secret values are never returned."
    )]
    async fn cloudflare_portal_agent_request(
        &self,
        Parameters(args): Parameters<PortalAgentRequestArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let parsed_url = match self.portal_agent.validate_request_url(&args.url) {
            Ok(url) => url,
            Err(err) => {
                let plan = portal_agent_request_plan(&args.url, &args.method, false);
                let audit = MutationAuditSession::start(
                    Some(&parts),
                    "portal_agent_request",
                    portal_audit_target(&args.url, &args.method, None),
                    args.dry_run,
                );
                let base = portal_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let plan = portal_agent_request_plan(parsed_url.as_str(), &args.method, true);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "portal_agent_request",
            portal_audit_target(&args.url, &args.method, Some(&parsed_url)),
            args.dry_run,
        );

        if let Err(err) = crate::portal::parse_method(&args.method) {
            let base = portal_error_result(err);
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        }

        let body_kind = args.body.as_ref().map(classify_json_body);
        let method = args.method.trim().to_ascii_uppercase();
        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "portal_agent_request",
                "planned": true,
                "url": safe_url_label(&parsed_url),
                "method": method,
                "body_kind": body_kind,
                "auth": {
                    "agent_token_attached": args.use_agent_token,
                    "access_service_token_attached": args.use_access_service_token,
                    "has_configured_agent_token": self.has_portal_agent_token,
                    "has_configured_access_service_token": self.has_portal_access_service_token,
                },
                "allowed_url_prefixes": self.portal_agent.allowed_url_prefixes(),
                "dry_run_note": "No portal request sent.",
            }))
        } else {
            match self
                .portal_agent
                .send(
                    &parsed_url,
                    &args.method,
                    args.body,
                    args.use_agent_token,
                    args.use_access_service_token,
                )
                .await
            {
                Ok(response) => portal_http_response_result(
                    response,
                    body_kind,
                    args.use_agent_token,
                    args.use_access_service_token,
                    self.has_portal_agent_token,
                    self.has_portal_access_service_token,
                ),
                Err(err) => portal_error_result_with_auth(
                    err,
                    args.use_agent_token,
                    args.use_access_service_token,
                    self.has_portal_agent_token,
                    self.has_portal_access_service_token,
                ),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "upsert_dns_cname",
        description = "Create/update a CNAME record for a hostname. Enforces publish preflight by default."
    )]
    async fn cloudflare_upsert_dns_cname(
        &self,
        Parameters(args): Parameters<UpsertDnsCnameArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let plan = plan_upsert_dns_cname(account_id, zone_id, &args.hostname, &args.target);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "upsert_dns_cname",
            json!({
                "account_id": account_id,
                "zone_id": zone_id,
                "hostname": &args.hostname,
                "target": &args.target,
            }),
            args.dry_run,
        );

        let request = DnsRecordUpsertRequest {
            hostname: args.hostname.clone(),
            target: args.target.clone(),
            proxied: args.proxied,
            ttl: args.ttl,
        };
        let existing_routes = match self
            .cloudflare
            .list_dns_records(zone_id, Some(&request.hostname))
            .await
        {
            Ok(page) => page.items,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let route_plan = match plan_dns_route_reconciliation(&existing_routes, &request) {
            Ok(plan) => plan,
            Err(conflict) => {
                let base = dns_route_conflict_result(conflict);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };

        let gate = match evaluate_publish_gate(
            &self.cloudflare,
            account_id,
            &args.hostname,
            args.override_publish_guard,
            args.override_reason.as_deref(),
        )
        .await
        {
            Ok(gate) => gate,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };

        if !gate.decision.allow {
            let base = publish_gate_denied_result("upsert_dns_cname", &gate);
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        }
        if gate.evidence.override_used {
            tracing::warn!(
                account_id = %account_id,
                hostname = %args.hostname,
                override_reason = ?gate.evidence.override_reason,
                "publish guard override accepted for direct DNS upsert"
            );
        }

        let request = DnsRecordUpsertRequest {
            hostname: args.hostname.clone(),
            target: args.target.clone(),
            proxied: args.proxied,
            ttl: args.ttl,
        };

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "upsert_dns_cname",
                "account_id": account_id,
                "zone_id": zone_id,
                "request": request,
                "route_reconciliation": route_plan,
                "route_verification": verify_dns_route(&existing_routes, &request),
                "policy_gate": gate,
                "state_machine": preflight_trace(&gate),
                "dry_run_note": "No Cloudflare mutation applied.",
            }))
        } else if route_plan.action == crate::dns_route::DnsRouteAction::Noop {
            let verification = verify_dns_route(&existing_routes, &request);
            if verification.state == DnsRouteVerificationState::Matched {
                CallToolResult::structured(json!({
                    "ok": true,
                    "zone_id": zone_id,
                    "account_id": account_id,
                    "action": "noop",
                    "route_reconciliation": route_plan,
                    "route_verification": verification,
                    "policy_gate": gate,
                    "state_machine": lock_first_publish_trace(&gate, true),
                }))
            } else {
                dns_route_verification_failed_result(verification)
            }
        } else {
            match self.cloudflare.upsert_dns_cname(zone_id, &request).await {
                Ok(record) => match self
                    .cloudflare
                    .list_dns_records(zone_id, Some(&request.hostname))
                    .await
                {
                    Ok(readback) => {
                        let verification = verify_dns_route(&readback.items, &request);
                        if verification.state == DnsRouteVerificationState::Matched {
                            CallToolResult::structured(json!({
                                "ok": true,
                                "zone_id": zone_id,
                                "account_id": account_id,
                                "record": record,
                                "route_reconciliation": route_plan,
                                "route_verification": verification,
                                "policy_gate": gate,
                                "state_machine": lock_first_publish_trace(&gate, true),
                            }))
                        } else {
                            dns_route_verification_failed_result(verification)
                        }
                    }
                    Err(err) => adapter_error_result(err),
                },
                Err(err) => publish_operation_error_result("upsert_dns_cname", &gate, err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "list_access_apps",
        description = "List Cloudflare Access applications."
    )]
    async fn cloudflare_list_access_apps(
        &self,
        Parameters(args): Parameters<ListAccessAppsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;

        match self
            .cloudflare
            .list_access_apps(account_id, args.hostname.as_deref())
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "page": result,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "access_get_app",
        description = "Get a Cloudflare Access application by app_id."
    )]
    async fn cloudflare_access_get_app(
        &self,
        Parameters(args): Parameters<GetAccessAppArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let path = format!(
            "/accounts/{account_id}/access/apps/{}",
            url_path_segment(&args.app_id)
        );
        match self
            .cloudflare
            .api_request(
                "cloudflare.access.apps.get",
                reqwest::Method::GET,
                &path,
                &[],
                None,
            )
            .await
        {
            Ok(app) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "app": app}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "access_verify_hostname_gate",
        description = "Verify a hostname has exactly one Access app and at least one Access policy before public exposure."
    )]
    async fn cloudflare_access_verify_hostname_gate(
        &self,
        Parameters(args): Parameters<VerifyAccessHostnameGateArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let hostname = args.hostname.trim();
        if hostname.is_empty() {
            return Ok(invalid_argument_result(
                "access.invalid_hostname",
                "hostname must not be empty",
                "Provide the hostname to verify.",
            ));
        }
        let apps = match self
            .cloudflare
            .list_access_apps(account_id, Some(hostname))
            .await
        {
            Ok(page) => page.items,
            Err(err) => return Ok(adapter_error_result(err)),
        };
        let matching_apps = apps
            .into_iter()
            .filter(|app| {
                app.domain
                    .as_deref()
                    .map(|domain| domain.eq_ignore_ascii_case(hostname))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if matching_apps.len() != 1 {
            return Ok(CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "access_verify_hostname_gate",
                "account_id": account_id,
                "hostname": hostname,
                "state": if matching_apps.is_empty() { "missing_access_app" } else { "ambiguous_access_apps" },
                "matching_app_count": matching_apps.len(),
            })));
        }
        let app = &matching_apps[0];
        let policies = match self
            .cloudflare
            .list_access_policies(account_id, &app.id)
            .await
        {
            Ok(policies) => policies,
            Err(err) => return Ok(adapter_error_result(err)),
        };
        if policies.is_empty() {
            return Ok(CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "access_verify_hostname_gate",
                "account_id": account_id,
                "hostname": hostname,
                "state": "missing_access_policies",
                "app": app,
            })));
        }
        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "access_verify_hostname_gate",
            "account_id": account_id,
            "hostname": hostname,
            "state": "access_gated",
            "app": app,
            "policy_count": policies.len(),
            "policies": policies,
        })))
    }

    #[tool(
        name = "upsert_access_app",
        description = "Create/update an Access app for a hostname."
    )]
    async fn cloudflare_upsert_access_app(
        &self,
        Parameters(args): Parameters<UpsertAccessAppArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let plan = plan_upsert_access_app(account_id, &args.hostname, &args.app_name);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "upsert_access_app",
            json!({
                "account_id": account_id,
                "hostname": &args.hostname,
                "app_name": &args.app_name,
            }),
            args.dry_run,
        );
        let request = AccessAppUpsertRequest {
            hostname: args.hostname.clone(),
            app_name: args.app_name.clone(),
        };

        let existing_page = match self
            .cloudflare
            .list_access_apps(account_id, Some(&request.hostname))
            .await
        {
            Ok(page) => page,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let app_plan = match plan_access_app_upsert(
            &existing_page.items,
            &request.hostname,
            &request.app_name,
        ) {
            Ok(plan) => plan,
            Err(conflict) => {
                let base = access_app_conflict_result(conflict);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "upsert_access_app",
                "account_id": account_id,
                "request": request,
                "upsert_plan": app_plan,
                "dry_run_note": "No Cloudflare mutation applied.",
            }))
        } else {
            let apply_result = match app_plan.action {
                AccessAppAction::Noop => app_plan.existing_app.clone().ok_or_else(|| {
                    CallToolResult::structured_error(json!({
                        "ok": false,
                        "error": {
                            "code": "access_app.noop_missing_existing",
                            "message": "planned noop expected existing app but none was present",
                            "hint": "Retry upsert after refreshing app inventory.",
                        },
                        "upsert_plan": app_plan.clone(),
                    }))
                }),
                AccessAppAction::Create | AccessAppAction::Update => self
                    .cloudflare
                    .upsert_access_app(account_id, &request)
                    .await
                    .map_err(adapter_error_result),
            };

            match apply_result {
                Ok(applied_app) => match self
                    .cloudflare
                    .list_access_apps(account_id, Some(&request.hostname))
                    .await
                {
                    Ok(readback) => match validate_access_app_readback(
                        &readback.items,
                        &request.hostname,
                        &request.app_name,
                    ) {
                        Ok(validated) => CallToolResult::structured(json!({
                            "ok": true,
                            "account_id": account_id,
                            "action": access_app_action_label(app_plan.action),
                            "upsert_plan": app_plan,
                            "applied_app": applied_app,
                            "validated_app": validated,
                        })),
                        Err(err) => access_app_validation_result(err),
                    },
                    Err(err) => adapter_error_result(err),
                },
                Err(err_result) => err_result,
            }
        };
        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "list_access_policies",
        description = "List Access policies for an app."
    )]
    async fn cloudflare_list_access_policies(
        &self,
        Parameters(args): Parameters<ListAccessPoliciesArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .list_access_policies(account_id, &args.app_id)
            .await
        {
            Ok(policies) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "app_id": args.app_id,
                "policies": policies,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "list_workers",
        description = "List Cloudflare Workers scripts for an account."
    )]
    async fn cloudflare_list_workers(
        &self,
        Parameters(args): Parameters<ListWorkersArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;

        match self
            .cloudflare
            .list_workers(account_id, args.tags.as_deref())
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "account_id": account_id,
                "page": result,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "get_worker_settings",
        description = "Read Worker script settings, including bindings, for deploy verification."
    )]
    async fn cloudflare_get_worker_settings(
        &self,
        Parameters(args): Parameters<GetWorkerSettingsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let script_name = args.script_name.trim();
        if script_name.is_empty() {
            return Ok(invalid_argument_result(
                "workers.invalid_script_name",
                "script_name must not be empty",
                "Provide the Worker script name shown by Cloudflare.",
            ));
        }

        match self
            .cloudflare
            .get_worker_settings(account_id, script_name)
            .await
        {
            Ok(settings) => {
                let binding_readback = args
                    .binding_name
                    .as_deref()
                    .map(|name| worker_binding_presence(settings.bindings.as_deref(), name));
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "get_worker_settings",
                    "account_id": account_id,
                    "script_name": script_name,
                    "settings": settings,
                    "binding_readback": binding_readback,
                })))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(name = "queues_list", description = "List Cloudflare Queues.")]
    async fn cloudflare_queues_list(
        &self,
        Parameters(args): Parameters<QueuesListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self.cloudflare.list_queues(account_id).await {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(name = "queues_get", description = "Get Cloudflare Queue details.")]
    async fn cloudflare_queues_get(
        &self,
        Parameters(args): Parameters<QueueArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self.cloudflare.get_queue(account_id, &args.queue_id).await {
            Ok(queue) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "queue": queue}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "queues_get_metrics",
        description = "Get Cloudflare Queue backlog metrics, including depth and oldest message timestamp."
    )]
    async fn cloudflare_queues_get_metrics(
        &self,
        Parameters(args): Parameters<QueueArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_queue_metrics(account_id, &args.queue_id)
            .await
        {
            Ok(metrics) => {
                let oldest_message_age_ms =
                    queue_oldest_message_age_ms(metrics.oldest_message_timestamp_ms);
                Ok(CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "queues_get_metrics",
                    "account_id": account_id,
                    "queue_id": args.queue_id,
                    "metrics": metrics,
                    "oldest_message_age_ms": oldest_message_age_ms,
                    "source": "cloudflare_queues_rest_metrics",
                })))
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "queues_list_consumers",
        description = "List consumers for a Cloudflare Queue, including Worker and pull consumer settings."
    )]
    async fn cloudflare_queues_list_consumers(
        &self,
        Parameters(args): Parameters<QueueArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .list_queue_consumers(account_id, &args.queue_id)
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "queues_list_consumers",
                "account_id": account_id,
                "queue_id": args.queue_id,
                "page": page,
            }))),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "queues_health",
        description = "Read Queue health: backlog depth, message age, delivery pause state, consumers, purge status, and configured DLQ backlog."
    )]
    async fn cloudflare_queues_health(
        &self,
        Parameters(args): Parameters<QueueHealthArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let queue = match self.cloudflare.get_queue(account_id, &args.queue_id).await {
            Ok(queue) => queue,
            Err(err) => return Ok(adapter_error_result(err)),
        };
        let metrics = match self
            .cloudflare
            .get_queue_metrics(account_id, &args.queue_id)
            .await
        {
            Ok(metrics) => metrics,
            Err(err) => return Ok(adapter_error_result(err)),
        };
        let consumers_page = match self
            .cloudflare
            .list_queue_consumers(account_id, &args.queue_id)
            .await
        {
            Ok(page) => page,
            Err(err) => return Ok(adapter_error_result(err)),
        };
        let purge_status = match self
            .cloudflare
            .get_queue_purge_status(account_id, &args.queue_id)
            .await
        {
            Ok(status) => Some(status),
            Err(_) => None,
        };
        let dlq = if args.include_dlq {
            queue_dlq_readback(self, account_id, &consumers_page.items).await
        } else {
            json!({"checked": false})
        };
        let delivery_paused = queue_delivery_paused(queue.settings.as_ref());
        let oldest_message_age_ms =
            queue_oldest_message_age_ms(metrics.oldest_message_timestamp_ms);
        let consumer_status = queue_consumer_status(delivery_paused, &consumers_page.items);

        Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": "queues_health",
            "account_id": account_id,
            "queue_id": args.queue_id,
            "queue": queue,
            "metrics": {
                "backlog_bytes": metrics.backlog_bytes,
                "backlog_count": metrics.backlog_count,
                "oldest_message_timestamp_ms": metrics.oldest_message_timestamp_ms,
                "oldest_message_age_ms": oldest_message_age_ms,
            },
            "consumer_status": consumer_status,
            "consumers": consumers_page,
            "delivery_paused": delivery_paused,
            "purge_status": purge_status,
            "dlq": dlq,
            "retry_failure_counts": {
                "available": false,
                "source": "Cloudflare Queues GraphQL analytics",
                "hint": "Cloudflare exposes retry/failure operation history in queueOperationsAdaptiveGroups; this REST health readback reports realtime backlog and configured DLQ backlog.",
            },
        })))
    }

    #[tool(
        name = "workers_list_scripts",
        description = "List Cloudflare Worker scripts."
    )]
    async fn cloudflare_workers_list_scripts(
        &self,
        Parameters(args): Parameters<QueuesListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self.cloudflare.list_workers(account_id, None).await {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "workers_get_script_settings",
        description = "Get Cloudflare Worker script settings."
    )]
    async fn cloudflare_workers_get_script_settings(
        &self,
        Parameters(args): Parameters<GetWorkerSettingsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        self.cloudflare_get_worker_settings(Parameters(args)).await
    }

    #[tool(
        name = "workers_upload_script",
        description = "Upload a Cloudflare Worker module script or prebuilt multipart bundle with dry-run planning, confirmation-token apply, and settings readback."
    )]
    async fn cloudflare_workers_upload_script(
        &self,
        Parameters(args): Parameters<WorkersUploadScriptArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let script_name = args.script_name.trim();
        if script_name.is_empty() {
            let plan = MutationPlan::new("workers_upload_script");
            let audit = MutationAuditSession::start(
                Some(&parts),
                "workers_upload_script",
                json!({
                    "account_id": account_id,
                    "script_name": script_name,
                }),
                args.dry_run,
            );
            return Ok(finalize_mutation_result(
                worker_upload_error_result(WorkerUploadError {
                    code: "workers.invalid_script_name",
                    message: "script_name must not be empty".to_string(),
                    hint: "Provide the Worker script name shown by Cloudflare.",
                }),
                &plan,
                audit,
                args.dry_run,
            ));
        }
        let upload_operation =
            find_operation("worker-script-upload-worker-module").ok_or_else(|| {
                crate::McpError::internal_error(
                    "missing Worker upload operation catalog entry",
                    None,
                )
            })?;
        let mut path_params = BTreeMap::new();
        path_params.insert("account_id".to_string(), account_id.to_string());
        path_params.insert("script_name".to_string(), script_name.to_string());
        let rendered_path = render_path(
            upload_operation,
            &path_params,
            Some(account_id),
            self.default_zone_id.as_deref(),
        )
        .map_err(|err| crate::McpError::invalid_params(format!("{err:?}"), None))?;

        let upload = match build_worker_upload(WorkerUploadInput {
            script_path: args.script_path.as_deref(),
            script_content: args.script_content.as_deref(),
            script_content_base64: args.script_content_base64.as_deref(),
            multipart_path: args.multipart_path.as_deref(),
            main_module: args.main_module.as_deref(),
            metadata: &args.metadata,
            content_type: args.content_type.as_deref(),
        }) {
            Ok(upload) => upload,
            Err(err) => {
                let plan = MutationPlan::new("workers_upload_script");
                let audit = MutationAuditSession::start(
                    Some(&parts),
                    "workers_upload_script",
                    json!({
                        "account_id": account_id,
                        "script_name": script_name,
                    }),
                    args.dry_run,
                );
                return Ok(finalize_mutation_result(
                    worker_upload_error_result(err),
                    &plan,
                    audit,
                    args.dry_run,
                ));
            }
        };

        let upload_summary = json!(upload.summary);
        let token_body = Some(json!({
            "script_name": script_name,
            "upload": upload_summary,
        }));
        let required_confirmation_token =
            mutation_confirmation_token(upload_operation, &rendered_path, &token_body);
        let plan = plan_upload_worker_script(account_id, script_name, upload_summary.clone());
        let audit = MutationAuditSession::start(
            Some(&parts),
            "workers_upload_script",
            json!({
                "account_id": account_id,
                "script_name": script_name,
                "source_kind": upload.summary.source_kind,
                "source_label": upload.summary.source_label,
                "sha256": upload.summary.sha256,
                "reason": args.reason.as_deref().map(str::trim),
            }),
            args.dry_run,
        );

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "planned": true,
                "operation": "workers_upload_script",
                "account_id": account_id,
                "script_name": script_name,
                "request_path": rendered_path,
                "upload": upload_summary,
                "required_confirmation_token": required_confirmation_token,
                "dry_run_note": "No Worker script upload applied.",
            }))
        } else if args.confirmation_token.as_deref() != Some(required_confirmation_token.as_str()) {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "workers_upload_script",
                "error": {
                    "code": "workers.upload_confirmation_required",
                    "message": "Worker script upload requires the confirmation token returned by dry-run",
                    "hint": "Run workers_upload_script with dry_run=true and echo required_confirmation_token in confirmation_token.",
                },
                "account_id": account_id,
                "script_name": script_name,
                "upload": upload_summary,
                "required_confirmation_token": required_confirmation_token,
            }))
        } else {
            let uploaded = match upload.body {
                WorkerUploadBody::Module {
                    metadata,
                    module_name,
                    file_name,
                    content_type,
                    bytes,
                } => {
                    self.cloudflare
                        .upload_worker_module(
                            account_id,
                            script_name,
                            &metadata,
                            &module_name,
                            &file_name,
                            &content_type,
                            bytes,
                        )
                        .await
                }
                WorkerUploadBody::Multipart {
                    content_type,
                    bytes,
                } => {
                    self.cloudflare
                        .upload_worker_multipart(account_id, script_name, &content_type, bytes)
                        .await
                }
            };
            match uploaded {
                Ok(script) => match self
                    .cloudflare
                    .get_worker_settings(account_id, script_name)
                    .await
                {
                    Ok(readback_settings) => {
                        let readback_verification =
                            verify_worker_upload_readback(&upload_summary, &readback_settings);
                        let ok = readback_verification
                            .get("matched")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        if ok {
                            CallToolResult::structured(json!({
                                "ok": true,
                                "operation": "workers_upload_script",
                                "account_id": account_id,
                                "script_name": script_name,
                                "upload": upload_summary,
                                "script": script,
                                "readback_settings": readback_settings,
                                "readback_verification": readback_verification,
                            }))
                        } else {
                            CallToolResult::structured_error(json!({
                                "ok": false,
                                "operation": "workers_upload_script",
                                "error": {
                                    "code": "workers.upload_readback_mismatch",
                                    "message": "Worker script upload returned success, but settings readback did not match the requested module.",
                                    "hint": "Inspect readback_settings.main_module and rerun the upload or use the documented Wrangler deployment path if the Worker bundle owns the module graph.",
                                },
                                "account_id": account_id,
                                "script_name": script_name,
                                "upload": upload_summary,
                                "script": script,
                                "readback_settings": readback_settings,
                                "readback_verification": readback_verification,
                            }))
                        }
                    }
                    Err(err) => CallToolResult::structured_error(json!({
                        "ok": false,
                        "operation": "workers_upload_script",
                        "error": {
                            "code": "workers.upload_readback_failed",
                            "message": "Worker script upload returned success, but settings readback failed",
                            "hint": "Inspect the uploaded script in Cloudflare and rerun workers_get_script_settings.",
                            "readback_error": err.payload(),
                        },
                        "account_id": account_id,
                        "script_name": script_name,
                        "upload": upload_summary,
                        "script": script,
                    })),
                },
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "workers_list_tails",
        description = "List Worker tail consumers for a script."
    )]
    async fn cloudflare_workers_list_tails(
        &self,
        Parameters(args): Parameters<WorkersListTailsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .list_worker_tails(account_id, &args.script_name)
            .await
        {
            Ok(tails) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "tails": tails}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "workers_observability_query_events",
        description = "Query Workers Observability events."
    )]
    async fn cloudflare_workers_observability_query_events(
        &self,
        Parameters(args): Parameters<WorkersObservabilityQueryEventsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let limit = args.limit.unwrap_or(100).clamp(1, 1000);
        let timeframe = workers_observability_timeframe(args.timeframe, args.lookback_minutes);
        let body = workers_observability_query_body(
            args.script_name.as_deref(),
            &args.datasets,
            &args.filters,
            limit,
            timeframe,
            args.query_id.as_deref(),
            args.dry.unwrap_or(true),
            args.view.as_deref(),
            args.needle,
        );
        match self
            .cloudflare
            .query_workers_observability(account_id, &body)
            .await
        {
            Ok(result) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "result": result}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "workers_observability_list_keys",
        description = "List Workers Observability event keys."
    )]
    async fn cloudflare_workers_observability_list_keys(
        &self,
        Parameters(args): Parameters<WorkersObservabilityListKeysArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let body = workers_observability_discovery_body(
            args.script_name.as_deref(),
            &args.datasets,
            &args.filters,
            args.limit.unwrap_or(100).clamp(1, 1000),
            workers_observability_timeframe(args.timeframe, args.lookback_minutes),
            args.needle,
            args.key_needle,
        );
        match self
            .cloudflare
            .list_workers_observability_keys(account_id, &body)
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "workers_observability_list_values",
        description = "List values for a Workers Observability event key."
    )]
    async fn cloudflare_workers_observability_list_values(
        &self,
        Parameters(args): Parameters<WorkersObservabilityListValuesArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let body = workers_observability_values_body(
            &args.key,
            args.value_type.as_deref().unwrap_or("string"),
            args.script_name.as_deref(),
            &args.datasets,
            &args.filters,
            args.limit.unwrap_or(100).clamp(1, 1000),
            workers_observability_timeframe(args.timeframe, args.lookback_minutes),
            args.needle,
        );
        match self
            .cloudflare
            .list_workers_observability_values(account_id, &body)
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bindings_discover",
        description = "Discover D1, Queues, Worker, and Pages resources that may be used as application bindings."
    )]
    async fn cloudflare_bindings_discover(
        &self,
        Parameters(args): Parameters<BindingsDiscoverArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let name_filter = args
            .name_contains
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        let mut errors = Vec::new();
        let (d1_databases, d1_page_info) = match self
            .cloudflare
            .list_d1_databases(account_id, 1, 100, name_filter.as_deref())
            .await
        {
            Ok(page) => (page.items, page.page_info),
            Err(err) => {
                errors.push(json!({"surface": "d1", "error": err.payload()}));
                (Vec::new(), None)
            }
        };
        let (queues, queues_page_info) = match self.cloudflare.list_queues(account_id).await {
            Ok(page) => (page.items, page.page_info),
            Err(err) => {
                errors.push(json!({"surface": "queues", "error": err.payload()}));
                (Vec::new(), None)
            }
        };
        let workers = if args.include_workers {
            match self.cloudflare.list_workers(account_id, None).await {
                Ok(page) => page.items,
                Err(err) => {
                    errors.push(json!({"surface": "workers", "error": err.payload()}));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let pages = if args.include_pages {
            match self
                .cloudflare
                .list_pages_projects(account_id, 1, 100)
                .await
            {
                Ok(page) => page.items,
                Err(err) => {
                    errors.push(json!({"surface": "pages", "error": err.payload()}));
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        let attempted_surfaces =
            2 + usize::from(args.include_workers) + usize::from(args.include_pages);
        let successful_surfaces = attempted_surfaces.saturating_sub(errors.len());
        let status = if errors.is_empty() {
            "complete"
        } else if successful_surfaces > 0 {
            "partial"
        } else {
            "failed"
        };
        Ok(CallToolResult::structured(json!({
            "ok": successful_surfaces > 0,
            "status": status,
            "partial": status == "partial",
            "account_id": account_id,
            "inventory": {
                "d1_databases": d1_databases,
                "queues": queues,
            },
            "workers": workers,
            "pages": pages,
            "surfaces": {
                "d1": binding_surface_status(&errors, "d1", d1_databases.len(), false),
                "queues": binding_surface_status(&errors, "queues", queues.len(), false),
                "workers": binding_surface_status(&errors, "workers", workers.len(), !args.include_workers),
                "pages": binding_surface_status(&errors, "pages", pages.len(), !args.include_pages),
            },
            "completeness": {
                "sampled_first_page": true,
                "d1_page_info": d1_page_info,
                "queues_page_info": queues_page_info,
            },
            "errors": errors,
        })))
    }

    #[tool(
        name = "email_routing_get_settings",
        description = "Get Email Routing settings for a zone."
    )]
    async fn cloudflare_email_routing_get_settings(
        &self,
        Parameters(args): Parameters<EmailRoutingZoneArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        match self.cloudflare.get_email_routing_settings(zone_id).await {
            Ok(result) => Ok(CallToolResult::structured(
                json!({"ok": true, "zone_id": zone_id, "result": result}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "email_routing_get_dns",
        description = "Get Email Routing DNS status for a zone."
    )]
    async fn cloudflare_email_routing_get_dns(
        &self,
        Parameters(args): Parameters<EmailRoutingZoneArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        match self.cloudflare.get_email_routing_dns(zone_id).await {
            Ok(result) => Ok(CallToolResult::structured(
                json!({"ok": true, "zone_id": zone_id, "result": result}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "email_routing_list_rules",
        description = "List Email Routing rules for a zone."
    )]
    async fn cloudflare_email_routing_list_rules(
        &self,
        Parameters(args): Parameters<EmailRoutingListRulesArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        match self
            .cloudflare
            .list_email_routing_rules(
                zone_id,
                args.page.unwrap_or(1).max(1),
                args.per_page.unwrap_or(50).clamp(1, 100),
            )
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "zone_id": zone_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "email_routing_get_rule",
        description = "Get an Email Routing rule."
    )]
    async fn cloudflare_email_routing_get_rule(
        &self,
        Parameters(args): Parameters<EmailRoutingRuleArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        match self
            .cloudflare
            .get_email_routing_rule(zone_id, &args.rule_identifier)
            .await
        {
            Ok(rule) => Ok(CallToolResult::structured(
                json!({"ok": true, "zone_id": zone_id, "rule": rule}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "email_routing_get_catch_all",
        description = "Get Email Routing catch-all rule."
    )]
    async fn cloudflare_email_routing_get_catch_all(
        &self,
        Parameters(args): Parameters<EmailRoutingZoneArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        match self.cloudflare.get_email_routing_catch_all(zone_id).await {
            Ok(rule) => Ok(CallToolResult::structured(
                json!({"ok": true, "zone_id": zone_id, "rule": rule}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "email_routing_list_addresses",
        description = "List Email Routing destination addresses."
    )]
    async fn cloudflare_email_routing_list_addresses(
        &self,
        Parameters(args): Parameters<EmailRoutingListAddressesArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .list_email_routing_addresses(
                account_id,
                args.page.unwrap_or(1).max(1),
                args.per_page.unwrap_or(50).clamp(1, 100),
            )
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "email_routing_get_address",
        description = "Get an Email Routing destination address."
    )]
    async fn cloudflare_email_routing_get_address(
        &self,
        Parameters(args): Parameters<EmailRoutingAddressArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_email_routing_address(account_id, &args.destination_address_identifier)
            .await
        {
            Ok(address) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "address": address}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_list_lists",
        description = "List account Rules Lists, optionally redirect lists only."
    )]
    async fn cloudflare_bulk_redirects_list_lists(
        &self,
        Parameters(args): Parameters<BulkRedirectsListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self.cloudflare.list_rules_lists(account_id).await {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_get_list",
        description = "Get an account Rules List."
    )]
    async fn cloudflare_bulk_redirects_get_list(
        &self,
        Parameters(args): Parameters<BulkRedirectListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_rules_list(account_id, &args.list_id)
            .await
        {
            Ok(list) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "list": list}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_list_items",
        description = "List items in an account Rules List."
    )]
    async fn cloudflare_bulk_redirects_list_items(
        &self,
        Parameters(args): Parameters<BulkRedirectListItemsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let per_page = args.per_page.unwrap_or(100).clamp(1, 500);
        match self
            .cloudflare
            .list_rules_list_items(
                account_id,
                &args.list_id,
                args.cursor.as_deref(),
                Some(per_page),
            )
            .await
        {
            Ok(page) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "page": page}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_create_list",
        description = "Create a Bulk Redirect Rules List with dry-run support."
    )]
    async fn cloudflare_bulk_redirects_create_list(
        &self,
        Parameters(args): Parameters<BulkRedirectCreateListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if args.dry_run {
            return Ok(CallToolResult::structured(
                json!({"ok": true, "operation": "bulk_redirects_create_list", "dry_run": true, "account_id": account_id, "name": args.name, "description": args.description}),
            ));
        }
        match self
            .cloudflare
            .create_redirect_list(account_id, &args.name, args.description.as_deref())
            .await
        {
            Ok(list) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "list": list}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_update_list",
        description = "Update a Bulk Redirect Rules List with dry-run support."
    )]
    async fn cloudflare_bulk_redirects_update_list(
        &self,
        Parameters(args): Parameters<BulkRedirectUpdateListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        if args.dry_run {
            return Ok(CallToolResult::structured(
                json!({"ok": true, "operation": "bulk_redirects_update_list", "dry_run": true, "account_id": account_id, "list_id": args.list_id, "name": args.name, "description": args.description}),
            ));
        }
        match self
            .cloudflare
            .update_rules_list(account_id, &args.list_id, args.description.as_deref())
            .await
        {
            Ok(list) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "list": list}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_import_items",
        description = "Import Bulk Redirect items with dry-run support."
    )]
    async fn cloudflare_bulk_redirects_import_items(
        &self,
        Parameters(args): Parameters<BulkRedirectImportItemsArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let mode = match args.mode.trim().to_ascii_lowercase().as_str() {
            "append" => crate::cloudflare::bulk_redirects::BulkRedirectImportMode::Append,
            "replace" => crate::cloudflare::bulk_redirects::BulkRedirectImportMode::Replace,
            _ => {
                return Ok(CallToolResult::structured_error(json!({
                    "ok": false,
                    "error": {
                        "code": "bulk_redirects.invalid_import_mode",
                        "message": "mode must be append or replace",
                        "hint": "Use append to add items or replace to replace list contents.",
                    },
                })));
            }
        };
        if args.dry_run {
            return Ok(CallToolResult::structured(
                json!({"ok": true, "operation": "bulk_redirects_import_items", "dry_run": true, "account_id": account_id, "list_id": args.list_id, "mode": args.mode, "item_count": args.redirects.len()}),
            ));
        }
        match self
            .cloudflare
            .import_redirect_list_items(account_id, &args.list_id, &args.redirects, mode)
            .await
        {
            Ok(operation) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "operation_result": operation}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_get_operation",
        description = "Get a Bulk Redirect list operation status."
    )]
    async fn cloudflare_bulk_redirects_get_operation(
        &self,
        Parameters(args): Parameters<BulkRedirectOperationArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_rules_list_operation(account_id, &args.operation_id)
            .await
        {
            Ok(operation) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "operation_result": operation}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_get_ruleset",
        description = "Get the account Bulk Redirect Ruleset."
    )]
    async fn cloudflare_bulk_redirects_get_ruleset(
        &self,
        Parameters(args): Parameters<BulkRedirectRulesetArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        match self
            .cloudflare
            .get_account_redirect_ruleset(account_id)
            .await
        {
            Ok(ruleset) => Ok(CallToolResult::structured(
                json!({"ok": true, "account_id": account_id, "ruleset": ruleset}),
            )),
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "bulk_redirects_attach_list_to_ruleset",
        description = "Create or update the account redirect ruleset so it enables a Bulk Redirect list."
    )]
    async fn cloudflare_bulk_redirects_attach_list_to_ruleset(
        &self,
        Parameters(args): Parameters<BulkRedirectAttachListArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let list_name = args.list_name.trim();
        if list_name.is_empty() {
            return Ok(invalid_argument_result(
                "bulk_redirects.invalid_list_name",
                "list_name must not be empty",
                "Provide the Cloudflare Rules List name to attach.",
            ));
        }
        let new_rule = crate::cloudflare::bulk_redirects::redirect_rule_for_list(
            list_name,
            args.rule_description.as_deref(),
            args.enabled,
        );
        if args.dry_run {
            return Ok(CallToolResult::structured(json!({
                "ok": true,
                "operation": "bulk_redirects_attach_list_to_ruleset",
                "dry_run": true,
                "account_id": account_id,
                "list_name": list_name,
                "new_rule": new_rule,
            })));
        }
        match self
            .cloudflare
            .get_account_redirect_ruleset(account_id)
            .await
        {
            Ok(ruleset) => {
                let mut rules = ruleset.rules.clone();
                rules.retain(|rule| {
                    rule.pointer("/action_parameters/from_list/name")
                        .and_then(Value::as_str)
                        .map(|name| name != list_name)
                        .unwrap_or(true)
                });
                rules.push(new_rule);
                match self
                    .cloudflare
                    .update_account_redirect_ruleset(account_id, &ruleset, rules)
                    .await
                {
                    Ok(updated) => Ok(CallToolResult::structured(json!({
                        "ok": true,
                        "operation": "bulk_redirects_attach_list_to_ruleset",
                        "account_id": account_id,
                        "action": "updated_ruleset",
                        "ruleset": updated,
                    }))),
                    Err(err) => Ok(adapter_error_result(err)),
                }
            }
            Err(err) if err.code == "cloudflare.http_not_found" => {
                match self
                    .cloudflare
                    .create_account_redirect_ruleset(account_id, vec![new_rule])
                    .await
                {
                    Ok(ruleset) => Ok(CallToolResult::structured(json!({
                        "ok": true,
                        "operation": "bulk_redirects_attach_list_to_ruleset",
                        "account_id": account_id,
                        "action": "created_ruleset",
                        "ruleset": ruleset,
                    }))),
                    Err(err) => Ok(adapter_error_result(err)),
                }
            }
            Err(err) => Ok(adapter_error_result(err)),
        }
    }

    #[tool(
        name = "patch_worker_settings",
        description = "Patch Worker script settings with dry-run planning and readback verification."
    )]
    async fn cloudflare_patch_worker_settings(
        &self,
        Parameters(args): Parameters<PatchWorkerSettingsArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let script_name = args.script_name.trim();
        if script_name.is_empty() {
            let plan = MutationPlan::new("patch_worker_settings");
            let audit = MutationAuditSession::start(
                Some(&parts),
                "patch_worker_settings",
                json!({
                    "account_id": account_id,
                    "script_name": script_name,
                }),
                args.dry_run,
            );
            let base = invalid_argument_result(
                "workers.invalid_script_name",
                "script_name must not be empty",
                "Provide the Worker script name shown by Cloudflare.",
            );
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        }
        let Some(settings_patch) = args.settings_patch.as_object() else {
            let plan = MutationPlan::new("patch_worker_settings");
            let audit = MutationAuditSession::start(
                Some(&parts),
                "patch_worker_settings",
                json!({
                    "account_id": account_id,
                    "script_name": script_name,
                }),
                args.dry_run,
            );
            let base = invalid_argument_result(
                "workers.invalid_settings_patch",
                "settings_patch must be a JSON object",
                "Provide a JSON object accepted by the Cloudflare Worker settings endpoint.",
            );
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        };
        let patch_keys = settings_patch.keys().cloned().collect::<Vec<_>>();
        let plan = plan_patch_worker_settings(account_id, script_name, &patch_keys);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "patch_worker_settings",
            json!({
                "account_id": account_id,
                "script_name": script_name,
                "patch_keys": patch_keys,
                "expect_binding": args.expect_binding.as_ref().map(worker_binding_expectation_label),
            }),
            args.dry_run,
        );

        let before = match self
            .cloudflare
            .get_worker_settings(account_id, script_name)
            .await
        {
            Ok(settings) => settings,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let before_binding = args
            .expect_binding
            .as_ref()
            .map(|expectation| verify_worker_binding(before.bindings.as_deref(), expectation));

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "patch_worker_settings",
                "account_id": account_id,
                "script_name": script_name,
                "patch_keys": patch_keys,
                "before_binding": before_binding,
                "dry_run_note": "No Cloudflare mutation applied.",
            }))
        } else {
            match self
                .cloudflare
                .patch_worker_settings(account_id, script_name, &args.settings_patch)
                .await
            {
                Ok(patched) => match self
                    .cloudflare
                    .get_worker_settings(account_id, script_name)
                    .await
                {
                    Ok(readback) => {
                        let binding_verification =
                            args.expect_binding.as_ref().map(|expectation| {
                                verify_worker_binding(readback.bindings.as_deref(), expectation)
                            });
                        let ok = binding_verification
                            .as_ref()
                            .and_then(|value| value.get("matched"))
                            .and_then(Value::as_bool)
                            .unwrap_or(true);
                        let payload = json!({
                            "ok": ok,
                            "operation": "patch_worker_settings",
                            "account_id": account_id,
                            "script_name": script_name,
                            "patch_keys": patch_keys,
                            "patched_settings": patched,
                            "readback_settings": readback,
                            "binding_verification": binding_verification,
                        });
                        if ok {
                            CallToolResult::structured(payload)
                        } else {
                            CallToolResult::structured_error(json!({
                                "ok": false,
                                "operation": "patch_worker_settings",
                                "error": {
                                    "code": "workers.binding_verification_failed",
                                    "message": "Worker settings patch applied but binding readback did not match expectation",
                                    "hint": "Inspect readback_settings.bindings and rerun patch or deploy with Wrangler if the Worker bundle owns the setting.",
                                },
                                "account_id": account_id,
                                "script_name": script_name,
                                "patch_keys": patch_keys,
                                "patched_settings": payload["patched_settings"].clone(),
                                "readback_settings": payload["readback_settings"].clone(),
                                "binding_verification": payload["binding_verification"].clone(),
                            }))
                        }
                    }
                    Err(err) => adapter_error_result(err),
                },
                Err(err) if is_pages_generated_worker_settings_error(&err) => {
                    pages_generated_worker_settings_result(
                        err,
                        account_id,
                        script_name,
                        &patch_keys,
                        before_binding.clone(),
                    )
                }
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "cache_purge",
        description = "Purge Cloudflare cache by everything, files, URL headers, tags, hosts, or prefixes."
    )]
    async fn cloudflare_cache_purge(
        &self,
        Parameters(args): Parameters<CachePurgeArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let mode = match args.payload.mode() {
            Ok(mode) => mode,
            Err(err) => return Ok(cache_validation_result(err)),
        };
        let request_body = match args.payload.request_body() {
            Ok(body) => body,
            Err(err) => return Ok(cache_validation_result(err)),
        };
        let required_token = (mode == "everything")
            .then(|| purge_confirmation_token(zone_id, args.environment_id.as_deref()));
        let plan = plan_cache_mutation(
            "cache_purge",
            zone_id,
            json!({
                "mode": mode,
                "environment_id": args.environment_id,
            }),
        );
        let audit = MutationAuditSession::start(
            Some(&parts),
            "cache_purge",
            json!({
                "zone_id": zone_id,
                "mode": mode,
                "environment_id": args.environment_id,
            }),
            args.dry_run,
        );

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "cache_purge",
                "zone_id": zone_id,
                "mode": mode,
                "request_body": request_body,
                "required_confirmation_token": required_token,
                "dry_run_note": "No Cloudflare cache purge applied.",
            }))
        } else if let Some(required_token) = required_token.as_ref()
            && args.confirmation_token.as_deref() != Some(required_token.as_str())
        {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "cache_purge",
                "error": {
                    "code": "cache.confirmation_required",
                    "message": "purge_everything requires the confirmation token returned by dry-run",
                    "hint": "Run cache_purge with dry_run=true and echo required_confirmation_token in confirmation_token.",
                },
                "required_confirmation_token": required_token,
            }))
        } else {
            match self
                .cloudflare
                .purge_cache(zone_id, args.environment_id.as_deref(), &request_body)
                .await
            {
                Ok(result) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "cache_purge",
                    "zone_id": zone_id,
                    "mode": mode,
                    "result": result,
                })),
                Err(err) => adapter_error_result(err),
            }
        };
        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "cache_zone_setting",
        description = "Read or update zone-level cache settings such as browser TTL, cache level, development mode, and origin cache control."
    )]
    async fn cloudflare_cache_zone_setting(
        &self,
        Parameters(args): Parameters<CacheZoneSettingArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let action = match CacheZoneSettingAction::parse(&args.action) {
            Ok(action) => action,
            Err(err) => return Ok(cache_validation_result(err)),
        };
        let setting_id = args.setting_id.trim();
        if setting_id.is_empty() {
            return Ok(invalid_argument_result(
                "cache.invalid_setting_id",
                "setting_id must not be empty",
                "Provide a Cloudflare cache-related zone setting id.",
            ));
        }
        let plan = plan_cache_mutation(
            "cache_zone_setting",
            zone_id,
            json!({ "action": action.as_str(), "setting_id": setting_id }),
        );
        let audit = MutationAuditSession::start(
            Some(&parts),
            "cache_zone_setting",
            json!({ "zone_id": zone_id, "action": action.as_str(), "setting_id": setting_id }),
            args.dry_run,
        );

        let base = match action {
            CacheZoneSettingAction::Get => {
                match self.cloudflare.get_zone_setting(zone_id, setting_id).await {
                    Ok(setting) => CallToolResult::structured(json!({
                        "ok": true,
                        "operation": "cache_zone_setting",
                        "zone_id": zone_id,
                        "action": action.as_str(),
                        "setting": setting,
                    })),
                    Err(err) => adapter_error_result(err),
                }
            }
            CacheZoneSettingAction::Set if args.dry_run => CallToolResult::structured(json!({
                "ok": true,
                "operation": "cache_zone_setting",
                "zone_id": zone_id,
                "action": action.as_str(),
                "setting_id": setting_id,
                "value": args.value,
                "dry_run_note": "No Cloudflare zone setting update applied.",
            })),
            CacheZoneSettingAction::Set => {
                let Some(value) = args.value else {
                    let base = invalid_argument_result(
                        "cache.setting_value_required",
                        "value is required when action=set",
                        "Provide the Cloudflare zone setting value to apply.",
                    );
                    return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
                };
                match self
                    .cloudflare
                    .update_zone_setting(zone_id, setting_id, value)
                    .await
                {
                    Ok(setting) => CallToolResult::structured(json!({
                        "ok": true,
                        "operation": "cache_zone_setting",
                        "zone_id": zone_id,
                        "action": action.as_str(),
                        "setting": setting,
                    })),
                    Err(err) => adapter_error_result(err),
                }
            }
        };
        Ok(finalize_mutation_result(
            base,
            &plan,
            audit,
            args.dry_run || !action.mutates(),
        ))
    }

    #[tool(
        name = "cache_rules",
        description = "Manage Cache Rules and Cache Response Rules through Cloudflare Rulesets entrypoint phases."
    )]
    async fn cloudflare_cache_rules(
        &self,
        Parameters(args): Parameters<CacheRulesArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let phase = match CacheRulePhase::parse(&args.phase) {
            Ok(phase) => phase,
            Err(err) => return Ok(cache_validation_result(err)),
        };
        let action = match CacheRulesAction::parse(&args.action) {
            Ok(action) => action,
            Err(err) => return Ok(cache_validation_result(err)),
        };
        let required_token = (action == CacheRulesAction::ReplaceAll)
            .then(|| replace_rules_confirmation_token(zone_id, phase));
        let plan = plan_cache_mutation(
            "cache_rules",
            zone_id,
            json!({ "action": action.as_str(), "phase": phase.cloudflare_name() }),
        );
        let audit = MutationAuditSession::start(
            Some(&parts),
            "cache_rules",
            json!({ "zone_id": zone_id, "action": action.as_str(), "phase": phase.cloudflare_name() }),
            args.dry_run,
        );

        let current = match self
            .cloudflare
            .get_cache_ruleset(zone_id, phase.cloudflare_name())
            .await
        {
            Ok(ruleset) => ruleset,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };

        let next = match mutate_cache_ruleset(
            current.clone(),
            action,
            args.rule_id.as_deref(),
            args.rule,
            args.rules,
        ) {
            Ok(Some(next)) => next,
            Ok(None) => {
                let payload = json!({
                    "ok": true,
                    "operation": "cache_rules",
                    "zone_id": zone_id,
                    "phase": phase.label(),
                    "phase_name": phase.cloudflare_name(),
                    "action": action.as_str(),
                    "ruleset": current,
                });
                return Ok(finalize_mutation_result(
                    CallToolResult::structured(payload),
                    &plan,
                    audit,
                    true,
                ));
            }
            Err(base) => return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run)),
        };

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "cache_rules",
                "zone_id": zone_id,
                "phase": phase.label(),
                "phase_name": phase.cloudflare_name(),
                "action": action.as_str(),
                "current_ruleset": current,
                "planned_ruleset": next,
                "required_confirmation_token": required_token,
                "dry_run_note": "No Cloudflare ruleset update applied.",
            }))
        } else if let Some(required_token) = required_token.as_ref()
            && args.confirmation_token.as_deref() != Some(required_token.as_str())
        {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "cache_rules",
                "error": {
                    "code": "cache.confirmation_required",
                    "message": "replace_all requires the confirmation token returned by dry-run",
                    "hint": "Run cache_rules with dry_run=true and echo required_confirmation_token in confirmation_token.",
                },
                "required_confirmation_token": required_token,
            }))
        } else {
            match self
                .cloudflare
                .update_cache_ruleset(zone_id, phase.cloudflare_name(), &next)
                .await
            {
                Ok(readback) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "cache_rules",
                    "zone_id": zone_id,
                    "phase": phase.label(),
                    "phase_name": phase.cloudflare_name(),
                    "action": action.as_str(),
                    "ruleset": readback,
                })),
                Err(err) => adapter_error_result(err),
            }
        };
        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "cache_reserve",
        description = "Read, update, clear, and inspect Cloudflare Cache Reserve state."
    )]
    async fn cloudflare_cache_reserve(
        &self,
        Parameters(args): Parameters<CacheResourceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        handle_cache_resource(self, "cache_reserve", "cache/cache_reserve", args, parts).await
    }

    #[tool(
        name = "cache_tiered",
        description = "Read, update, or delete Smart Tiered Cache and Regional Tiered Cache settings."
    )]
    async fn cloudflare_cache_tiered(
        &self,
        Parameters(args): Parameters<CacheResourceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        handle_cache_resource(
            self,
            "cache_tiered",
            "cache/tiered_cache_smart_topology_enable",
            args,
            parts,
        )
        .await
    }

    #[tool(
        name = "cache_variants",
        description = "Read, update, or delete Cloudflare cache variants settings."
    )]
    async fn cloudflare_cache_variants(
        &self,
        Parameters(args): Parameters<CacheResourceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        handle_cache_resource(self, "cache_variants", "cache/variants", args, parts).await
    }

    #[tool(
        name = "cache_origin_regions",
        description = "Manage deprecated origin cloud-region cache mappings where Cloudflare still exposes the API."
    )]
    async fn cloudflare_cache_origin_regions(
        &self,
        Parameters(args): Parameters<CacheResourceArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        handle_cache_resource(
            self,
            "cache_origin_regions",
            "cache/origin_cache_control",
            args,
            parts,
        )
        .await
    }

    #[tool(
        name = "replace_access_policies",
        description = "Low-level replacement of Access policies for an app (no invariant guardrails)."
    )]
    async fn cloudflare_replace_access_policies(
        &self,
        Parameters(args): Parameters<ReplaceAccessPoliciesArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let plan = plan_replace_access_policies(account_id, &args.app_id, args.policies.len());
        let audit = MutationAuditSession::start(
            Some(&parts),
            "replace_access_policies",
            json!({
                "account_id": account_id,
                "app_id": &args.app_id,
                "policy_count": args.policies.len(),
            }),
            args.dry_run,
        );

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "replace_access_policies",
                "account_id": account_id,
                "app_id": &args.app_id,
                "planned_policies": &args.policies,
                "dry_run_note": "No Cloudflare mutation applied.",
            }))
        } else {
            match self
                .cloudflare
                .replace_access_policies(account_id, &args.app_id, &args.policies)
                .await
            {
                Ok(policies) => CallToolResult::structured(json!({
                    "ok": true,
                    "account_id": account_id,
                    "app_id": &args.app_id,
                    "policies": policies,
                })),
                Err(err) => adapter_error_result(err),
            }
        };
        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "apply_access_allowlist",
        description = "Mutate Access allowlist using replace/additive modes with post-apply invariant validation."
    )]
    async fn cloudflare_apply_access_allowlist(
        &self,
        Parameters(args): Parameters<ApplyAccessAllowlistArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let mode = match AllowlistMutationMode::parse(&args.mode) {
            Ok(mode) => mode,
            Err(err) => {
                let plan = MutationPlan::new("apply_access_allowlist");
                let audit = MutationAuditSession::start(
                    Some(&parts),
                    "apply_access_allowlist",
                    json!({
                        "account_id": account_id,
                        "app_id": &args.app_id,
                    }),
                    args.dry_run,
                );
                let base = invalid_argument_result(
                    "access_policy.invalid_mode",
                    err,
                    "Use mode='replace' or mode='additive'.",
                );
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let requested_principals =
            match canonicalize_requested_principals(&args.requested_principals) {
                Ok(principals) => principals,
                Err(violation) => {
                    let plan = MutationPlan::new("apply_access_allowlist");
                    let audit = MutationAuditSession::start(
                        Some(&parts),
                        "apply_access_allowlist",
                        json!({
                            "account_id": account_id,
                            "app_id": &args.app_id,
                        }),
                        args.dry_run,
                    );
                    let base = policy_violation_result(violation);
                    return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
                }
            };

        let before_policies = match self
            .cloudflare
            .list_access_policies(account_id, &args.app_id)
            .await
        {
            Ok(policies) => policies,
            Err(err) => {
                let plan = MutationPlan::new("apply_access_allowlist");
                let audit = MutationAuditSession::start(
                    Some(&parts),
                    "apply_access_allowlist",
                    json!({
                        "account_id": account_id,
                        "app_id": &args.app_id,
                    }),
                    args.dry_run,
                );
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let before_principals = extract_allowlist_principals(&before_policies);
        let target_principals =
            plan_target_principals(mode, &before_principals, &requested_principals);
        let requested_principals_list: Vec<String> = requested_principals.iter().cloned().collect();
        let target_principals_list: Vec<String> = target_principals.iter().cloned().collect();
        let plan = plan_apply_access_allowlist(
            account_id,
            &args.app_id,
            mode,
            &requested_principals_list,
            &target_principals_list,
        );
        let audit = MutationAuditSession::start(
            Some(&parts),
            "apply_access_allowlist",
            json!({
                "account_id": account_id,
                "app_id": &args.app_id,
                "mode": mode.as_str(),
                "requested_principal_count": requested_principals_list.len(),
                "target_principal_count": target_principals_list.len(),
            }),
            args.dry_run,
        );
        let mutation_payload = vec![build_managed_allowlist_policy(&target_principals)];

        if args.dry_run {
            let base = CallToolResult::structured(json!({
                "ok": true,
                "operation": "apply_access_allowlist",
                "account_id": account_id,
                "app_id": &args.app_id,
                "mode": mode.as_str(),
                "before_principal_count": before_principals.len(),
                "requested_principals": requested_principals_list,
                "target_principals": target_principals_list,
                "planned_policies": mutation_payload,
                "dry_run_note": "No Cloudflare mutation applied.",
            }));
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        }

        let base = if let Err(err) = self
            .cloudflare
            .replace_access_policies(account_id, &args.app_id, &mutation_payload)
            .await
        {
            adapter_error_result(err)
        } else {
            match self
                .cloudflare
                .list_access_policies(account_id, &args.app_id)
                .await
            {
                Ok(after_policies) => {
                    let after_principals = extract_allowlist_principals(&after_policies);
                    match evaluate_mutation_invariants(
                        mode,
                        &before_principals,
                        &requested_principals,
                        &after_principals,
                    ) {
                        Ok(evidence) => CallToolResult::structured(json!({
                            "ok": true,
                            "account_id": account_id,
                            "app_id": &args.app_id,
                            "mode": mode.as_str(),
                            "decision": {
                                "allow": true,
                                "code": "ALLOW",
                                "reason": "policy_invariants_validated",
                            },
                            "evidence": evidence,
                            "resulting_policy_count": after_policies.len(),
                            "resulting_policies": after_policies,
                        })),
                        Err(violation) => policy_violation_result(violation),
                    }
                }
                Err(err) => adapter_error_result(err),
            }
        };

        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "publish_preflight",
        description = "Evaluate publish policy gate for a hostname without performing mutations."
    )]
    async fn cloudflare_publish_preflight(
        &self,
        Parameters(args): Parameters<PublishPreflightArgs>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let gate = match evaluate_publish_gate(
            &self.cloudflare,
            account_id,
            &args.hostname,
            args.override_publish_guard,
            args.override_reason.as_deref(),
        )
        .await
        {
            Ok(gate) => gate,
            Err(err) => return Ok(adapter_error_result(err)),
        };

        let payload = json!({
            "ok": gate.decision.allow,
            "operation": "publish_preflight",
            "policy_gate": gate,
            "state_machine": preflight_trace(&gate),
        });
        if payload["ok"] == json!(true) {
            Ok(CallToolResult::structured(payload))
        } else {
            Ok(CallToolResult::structured_error(payload))
        }
    }

    #[tool(
        name = "lock_first_publish",
        description = "Policy-gated lock-first publish path: preflight gate then DNS route mutation."
    )]
    async fn cloudflare_lock_first_publish(
        &self,
        Parameters(args): Parameters<LockFirstPublishArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let account_id = resolve_account_id(self, args.account_id.as_deref())?;
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let plan = plan_lock_first_publish(account_id, zone_id, &args.hostname, &args.target);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "lock_first_publish",
            json!({
                "account_id": account_id,
                "zone_id": zone_id,
                "hostname": &args.hostname,
                "target": &args.target,
            }),
            args.dry_run,
        );

        let gate = match evaluate_publish_gate(
            &self.cloudflare,
            account_id,
            &args.hostname,
            args.override_publish_guard,
            args.override_reason.as_deref(),
        )
        .await
        {
            Ok(gate) => gate,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };

        if !gate.decision.allow {
            let base = publish_gate_denied_result("lock_first_publish", &gate);
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        }
        if gate.evidence.override_used {
            tracing::warn!(
                account_id = %account_id,
                hostname = %args.hostname,
                override_reason = ?gate.evidence.override_reason,
                "lock-first publish guard override accepted"
            );
        }

        let request = DnsRecordUpsertRequest {
            hostname: args.hostname.clone(),
            target: args.target.clone(),
            proxied: args.proxied,
            ttl: args.ttl,
        };
        let existing_routes = match self
            .cloudflare
            .list_dns_records(zone_id, Some(&request.hostname))
            .await
        {
            Ok(page) => page.items,
            Err(err) => {
                let base = adapter_error_result(err);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };
        let route_plan = match plan_dns_route_reconciliation(&existing_routes, &request) {
            Ok(plan) => plan,
            Err(conflict) => {
                let base = dns_route_conflict_result(conflict);
                return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
            }
        };

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "lock_first_publish",
                "account_id": account_id,
                "zone_id": zone_id,
                "hostname": &args.hostname,
                "target": &args.target,
                "policy_gate": gate,
                "request": request,
                "route_reconciliation": route_plan,
                "route_verification": verify_dns_route(&existing_routes, &request),
                "state_machine": preflight_trace(&gate),
                "dry_run_note": "No Cloudflare mutation applied.",
            }))
        } else if route_plan.action == crate::dns_route::DnsRouteAction::Noop {
            let verification = verify_dns_route(&existing_routes, &request);
            if verification.state == DnsRouteVerificationState::Matched {
                CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "lock_first_publish",
                    "account_id": account_id,
                    "zone_id": zone_id,
                    "hostname": &args.hostname,
                    "target": &args.target,
                    "policy_gate": gate,
                    "route_reconciliation": route_plan,
                    "route_verification": verification,
                    "state_machine": lock_first_publish_trace(&gate, true),
                }))
            } else {
                dns_route_verification_failed_result(verification)
            }
        } else {
            match self.cloudflare.upsert_dns_cname(zone_id, &request).await {
                Ok(record) => match self
                    .cloudflare
                    .list_dns_records(zone_id, Some(&request.hostname))
                    .await
                {
                    Ok(readback) => {
                        let verification = verify_dns_route(&readback.items, &request);
                        if verification.state == DnsRouteVerificationState::Matched {
                            CallToolResult::structured(json!({
                                "ok": true,
                                "operation": "lock_first_publish",
                                "account_id": account_id,
                                "zone_id": zone_id,
                                "hostname": &args.hostname,
                                "target": &args.target,
                                "policy_gate": gate,
                                "route": record,
                                "route_reconciliation": route_plan,
                                "route_verification": verification,
                                "state_machine": lock_first_publish_trace(&gate, true),
                            }))
                        } else {
                            dns_route_verification_failed_result(verification)
                        }
                    }
                    Err(err) => adapter_error_result(err),
                },
                Err(err) => publish_operation_error_result("lock_first_publish", &gate, err),
            }
        };
        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }

    #[tool(
        name = "emergency_unpublish",
        description = "Emergency unpublish path: disable public DNS route for a hostname (idempotent)."
    )]
    async fn cloudflare_emergency_unpublish(
        &self,
        Parameters(args): Parameters<EmergencyUnpublishArgs>,
        Extension(parts): Extension<Parts>,
    ) -> Result<CallToolResult, crate::McpError> {
        let zone_id = resolve_zone_id(self, args.zone_id.as_deref())?;
        let hostname = args.hostname.trim();
        let plan = plan_emergency_unpublish(zone_id, hostname);
        let audit = MutationAuditSession::start(
            Some(&parts),
            "emergency_unpublish",
            json!({
                "zone_id": zone_id,
                "hostname": hostname,
                "reason": &args.reason,
            }),
            args.dry_run,
        );
        if hostname.is_empty() {
            let base = invalid_argument_result(
                "publish.invalid_hostname",
                "hostname must not be empty",
                "Provide a non-empty hostname for emergency unpublish.",
            );
            return Ok(finalize_mutation_result(base, &plan, audit, args.dry_run));
        }

        let base = if args.dry_run {
            CallToolResult::structured(json!({
                "ok": true,
                "operation": "emergency_unpublish",
                "zone_id": zone_id,
                "hostname": hostname,
                "reason": &args.reason,
                "state_machine": emergency_unpublish_trace(false),
                "dry_run_note": "No Cloudflare mutation applied.",
            }))
        } else {
            match self.cloudflare.disable_dns_cname(zone_id, hostname).await {
                Ok(result) => CallToolResult::structured(json!({
                    "ok": true,
                    "operation": "emergency_unpublish",
                    "zone_id": zone_id,
                    "hostname": hostname,
                    "reason": &args.reason,
                    "result": result,
                    "state_machine": emergency_unpublish_trace(!result.already_absent),
                })),
                Err(err) => adapter_error_result(err),
            }
        };
        Ok(finalize_mutation_result(base, &plan, audit, args.dry_run))
    }
}

fn resolve_account_id<'a>(
    server: &'a CloudflareMcp,
    provided: Option<&'a str>,
) -> Result<&'a str, crate::McpError> {
    provided
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| server.default_account_id.as_deref())
        .ok_or_else(|| {
            crate::McpError::invalid_params(
                "account_id is required (arg or CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID)",
                None,
            )
        })
}

fn resolve_zone_id<'a>(
    server: &'a CloudflareMcp,
    provided: Option<&'a str>,
) -> Result<&'a str, crate::McpError> {
    provided
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| server.default_zone_id.as_deref())
        .ok_or_else(|| {
            crate::McpError::invalid_params(
                "zone_id is required (arg or CLOUDFLARE_MCP_DEFAULT_ZONE_ID)",
                None,
            )
        })
}

fn resolved_identifier_source(provided: Option<&str>, default: Option<&str>) -> &'static str {
    if provided
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        "argument"
    } else if default
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        "server_default"
    } else {
        "missing"
    }
}

fn normalized_non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn normalized_zone_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .map(|value| value.trim_end_matches('.'))
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn capability_probe_blocks_preflight(probe: &crate::cloudflare::model::CapabilityProbe) -> bool {
    if probe.code.as_deref() == Some("capability.not_probed_without_mutation") {
        return false;
    }
    !probe.ok
}

fn adapter_error_result(err: crate::cloudflare::AdapterError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": err.payload(),
    }))
}

#[derive(Debug, Clone, Copy)]
enum GraphqlAnalyticsShape {
    Generic,
    WafSecurityEvents,
    WafRuleActivity,
}

fn with_graphql_diagnostics(mut payload: Value, diagnostics: Option<Value>) -> Value {
    if let (Some(diagnostics), Value::Object(map)) = (diagnostics, &mut payload) {
        map.insert("diagnostics".to_string(), diagnostics);
    }
    payload
}

fn graphql_authz_diagnostics(
    shape: GraphqlAnalyticsShape,
    variables: &Value,
    result: &Value,
) -> Option<Value> {
    let error_messages = graphql_error_messages(result);
    let error_paths = graphql_error_paths(result);
    let zone_filter_applied = variables
        .get("zoneTag")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let account_filter_applied = variables
        .get("accountTag")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let empty_zones = zone_filter_applied
        && result
            .pointer("/data/viewer/zones")
            .and_then(Value::as_array)
            .is_some_and(|zones| zones.is_empty());
    let empty_accounts = account_filter_applied
        && result
            .pointer("/data/viewer/accounts")
            .and_then(Value::as_array)
            .is_some_and(|accounts| accounts.is_empty());
    let raw_path_worked = match shape {
        GraphqlAnalyticsShape::Generic => false,
        GraphqlAnalyticsShape::WafSecurityEvents => {
            path_pointer_is_nonempty(result, "/data/viewer/zones/0/samples")
        }
        GraphqlAnalyticsShape::WafRuleActivity => {
            path_pointer_is_nonempty(result, "/data/viewer/zones/0/samples")
        }
    };
    let grouped_path_worked = match shape {
        GraphqlAnalyticsShape::Generic => false,
        GraphqlAnalyticsShape::WafSecurityEvents => {
            path_pointer_is_nonempty(result, "/data/viewer/zones/0/byAction")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/bySource")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/byHost")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/byPath")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/byCountry")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/byHour")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/byIp")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/byRule")
        }
        GraphqlAnalyticsShape::WafRuleActivity => {
            path_pointer_is_nonempty(result, "/data/viewer/zones/0/byAction")
                || path_pointer_is_nonempty(result, "/data/viewer/zones/0/bySource")
        }
    };
    let grouped_path_mentioned =
        graphql_authz_error_mentions_grouped_node(&error_paths, &error_messages);
    let path_authz_denied = graphql_error_indicates_path_authz(&error_messages);
    let partial_data_available = match shape {
        GraphqlAnalyticsShape::Generic => {
            result
                .pointer("/data/viewer/accounts/0")
                .is_some_and(graphql_object_has_non_grouped_payload)
                || result
                    .pointer("/data/viewer/zones/0")
                    .is_some_and(graphql_object_has_non_grouped_payload)
        }
        GraphqlAnalyticsShape::WafSecurityEvents | GraphqlAnalyticsShape::WafRuleActivity => false,
    };
    let mut evidence = Map::new();
    evidence.insert(
        "zone_filter_applied".to_string(),
        json!(zone_filter_applied),
    );
    evidence.insert(
        "account_filter_applied".to_string(),
        json!(account_filter_applied),
    );
    evidence.insert("raw_path_worked".to_string(), json!(raw_path_worked));
    evidence.insert(
        "grouped_path_worked".to_string(),
        json!(grouped_path_worked),
    );
    evidence.insert(
        "grouped_path_mentioned".to_string(),
        json!(grouped_path_mentioned),
    );
    evidence.insert(
        "partial_data_available".to_string(),
        json!(partial_data_available),
    );

    if empty_zones || empty_accounts {
        return Some(graphql_authz_diagnostic_payload(
            "wrong_account_or_zone_context",
            "Verify the accountTag or zoneTag filter values before retrying the same GraphQL query.",
            error_messages,
            error_paths,
            evidence,
        ));
    }

    if matches!(shape, GraphqlAnalyticsShape::Generic)
        && path_authz_denied
        && grouped_path_mentioned
        && partial_data_available
    {
        return Some(graphql_authz_diagnostic_payload(
            "grouped_path_blocked_partial_success",
            "The GraphQL query returned other fields successfully while a grouped node was denied. Use the successful sibling data as context and treat the grouped node as degraded or entitlement-restricted until Cloudflare restores access.",
            error_messages,
            error_paths,
            evidence,
        ));
    }

    if path_authz_denied && raw_path_worked && grouped_path_mentioned {
        return Some(graphql_authz_diagnostic_payload(
            "grouped_path_blocked_raw_path_works",
            "Keep the same token and context, fall back to the raw analytics path, and treat grouped analytics as provider-side degradation until Cloudflare restores access.",
            error_messages,
            error_paths,
            evidence,
        ));
    }

    if path_authz_denied {
        return Some(graphql_authz_diagnostic_payload(
            "likely_entitlement_or_product_restriction",
            "Verify the token with account_api_tokens action=verify, then compare the same account or zone on a known raw analytics path before treating this as a Cloudflare entitlement or product restriction.",
            error_messages,
            error_paths,
            evidence,
        ));
    }

    None
}

fn graphql_authz_diagnostic_payload(
    code: &str,
    next_step: &str,
    error_messages: Vec<String>,
    error_paths: Vec<String>,
    mut evidence: Map<String, Value>,
) -> Value {
    evidence.insert(
        "graphql_error_count".to_string(),
        json!(error_messages.len()),
    );
    evidence.insert("graphql_error_messages".to_string(), json!(error_messages));
    evidence.insert("graphql_error_paths".to_string(), json!(error_paths));
    json!({
        "authz_classification": {
            "code": code,
            "next_step": next_step,
            "evidence": Value::Object(evidence),
        }
    })
}

fn graphql_error_messages(result: &Value) -> Vec<String> {
    result
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|error| error.get("message").and_then(Value::as_str))
        .map(|message| message.trim().to_string())
        .filter(|message| !message.is_empty())
        .collect()
}

fn graphql_error_paths(result: &Value) -> Vec<String> {
    result
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|error| error.get("path").and_then(Value::as_array))
        .map(|path| graphql_error_path_string(path))
        .filter(|path| !path.is_empty())
        .collect()
}

fn graphql_error_path_string(path: &[Value]) -> String {
    path.iter()
        .filter_map(|segment| match segment {
            Value::String(value) => Some(value.trim().to_string()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(".")
}

fn graphql_error_indicates_path_authz(messages: &[String]) -> bool {
    messages.iter().any(|message| {
        let lower = message.to_ascii_lowercase();
        lower.contains("does not have access to the path")
            || lower.contains("access to the path")
            || lower.contains("authorization")
    })
}

fn graphql_authz_error_mentions_grouped_node(paths: &[String], messages: &[String]) -> bool {
    const GROUP_ALIASES: [&str; 8] = [
        "byAction",
        "bySource",
        "byHost",
        "byPath",
        "byCountry",
        "byHour",
        "byIp",
        "byRule",
    ];
    paths.iter().any(|path| {
        path.contains("Groups")
            || GROUP_ALIASES
                .iter()
                .any(|alias| path.split('.').any(|segment| segment == *alias))
    }) || messages.iter().any(|message| {
        let lower = message.to_ascii_lowercase();
        lower.contains("groups") || lower.contains("grouped")
    })
}

fn graphql_object_has_non_grouped_payload(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object
        .iter()
        .any(|(key, value)| !graphql_key_looks_grouped(key) && json_value_is_nonempty(value))
}

fn graphql_key_looks_grouped(key: &str) -> bool {
    key.ends_with("Groups")
        || matches!(
            key,
            "byAction"
                | "bySource"
                | "byHost"
                | "byPath"
                | "byCountry"
                | "byHour"
                | "byIp"
                | "byRule"
        )
}

fn path_pointer_is_nonempty(value: &Value, pointer: &str) -> bool {
    value.pointer(pointer).is_some_and(json_value_is_nonempty)
}

fn json_value_is_nonempty(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) => true,
        Value::Number(_) => true,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
    }
}

fn pages_project_has_git_source(source: &Option<Value>) -> bool {
    match source {
        Some(Value::Object(source)) if !source.is_empty() => source
            .get("type")
            .and_then(Value::as_str)
            .map(|kind| {
                let kind = kind.trim();
                !kind.is_empty()
                    && !kind.eq_ignore_ascii_case("direct_upload")
                    && !kind.eq_ignore_ascii_case("direct-upload")
            })
            .unwrap_or(true),
        _ => false,
    }
}

fn is_pages_manifest_required_error(err: &crate::cloudflare::AdapterError) -> bool {
    err.cloudflare_api_error_code() == Some(8_000_096)
        || err
            .cloudflare_api_error_message()
            .map(|message| message.to_ascii_lowercase().contains("manifest"))
            .unwrap_or(false)
        || err.message.to_ascii_lowercase().contains("manifest")
}

fn pages_trigger_requires_git_source_result(
    account_id: &str,
    project_name: &str,
    request: PagesDeploymentTriggerRequest,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "pages_trigger_deployment",
        "account_id": account_id,
        "project_name": project_name,
        "request": request,
        "error": {
            "code": "pages.trigger_requires_git_source",
            "message": "pages_trigger_deployment can only trigger Git-backed Pages projects.",
            "hint": "Use pages_deploy_directory for direct-upload Pages projects.",
        },
    }))
}

fn pages_direct_upload_manifest_required_result(
    account_id: &str,
    project_name: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "pages_trigger_deployment",
        "account_id": account_id,
        "project_name": project_name,
        "error": {
            "code": "pages.direct_upload_manifest_required",
            "message": "Cloudflare requires a manifest for this Pages deployment.",
            "hint": "Use pages_deploy_directory so the MCP uploads assets and sends the required direct-upload manifest.",
        },
    }))
}

fn pages_project_update_snapshot_note() -> Value {
    json!({
        "applies_to": "future_deployments",
        "message": "Pages project settings/env updates do not mutate an already-live deployment snapshot.",
        "next_step": "Create a new deployment after updating project settings. For direct-upload projects, use pages_deploy_directory with the build output directory so env/bindings are resnapshotted.",
    })
}

fn is_pages_direct_upload_retry_error(err: &crate::cloudflare::AdapterError) -> bool {
    let message = err
        .cloudflare_api_error_message()
        .unwrap_or(&err.message)
        .to_ascii_lowercase();
    message.contains("direct upload") && message.contains("retr")
}

fn pages_direct_upload_retry_result(
    err: crate::cloudflare::AdapterError,
    account_id: &str,
    project_name: &str,
    deployment_id: &str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "pages_retry_deployment",
        "account_id": account_id,
        "project_name": project_name,
        "deployment_id": deployment_id,
        "error": {
            "code": "pages.direct_upload_retry_unsupported",
            "message": err.payload().message,
            "hint": "Cloudflare cannot retry Direct Upload deployments. Recreate the deployment with pages_deploy_directory so project env/bindings are snapshotted again.",
            "retryable": false,
            "status": err.payload().status,
            "upstream": err.payload(),
        },
        "next_step": {
            "tool": "pages_deploy_directory",
            "reason": "Direct Upload projects need a fresh upload/deployment rather than retrying the old deployment.",
        },
    }))
}

fn is_pages_already_production_rollback_error(err: &crate::cloudflare::AdapterError) -> bool {
    err.cloudflare_api_error_code() == Some(8_000_039)
        || err
            .cloudflare_api_error_message()
            .unwrap_or(&err.message)
            .to_ascii_lowercase()
            .contains("currently in production")
}

async fn pages_rollback_already_production_result(
    server: &CloudflareMcp,
    err: crate::cloudflare::AdapterError,
    account_id: &str,
    project_name: &str,
    deployment_id: &str,
) -> CallToolResult {
    let readback = server
        .cloudflare
        .get_pages_project(account_id, project_name)
        .await;
    match readback {
        Ok(project) => {
            let latest_matches = project
                .latest_deployment
                .as_ref()
                .is_some_and(|deployment| deployment.id == deployment_id);
            let canonical_matches = project
                .canonical_deployment
                .as_ref()
                .is_some_and(|deployment| deployment.id == deployment_id);
            let ok = latest_matches || canonical_matches;
            let payload = json!({
                "ok": ok,
                "operation": "pages_rollback_deployment",
                "account_id": account_id,
                "project_name": project_name,
                "deployment_id": deployment_id,
                "action": "already_current_production_readback",
                "latest_matches": latest_matches,
                "canonical_matches": canonical_matches,
                "project": project,
                "upstream_error": err.payload(),
            });
            if ok {
                CallToolResult::structured(payload)
            } else {
                CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "pages_rollback_deployment",
                    "account_id": account_id,
                    "project_name": project_name,
                    "deployment_id": deployment_id,
                    "error": {
                        "code": "pages.rollback_already_production_readback_mismatch",
                        "message": "Cloudflare reported the rollback target is already production, but Pages project readback did not show that deployment as latest or canonical.",
                        "hint": "Refresh Pages deployments/project state before retrying rollback.",
                        "upstream": err.payload(),
                    },
                    "readback": payload,
                }))
            }
        }
        Err(readback_err) => CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "pages_rollback_deployment",
            "account_id": account_id,
            "project_name": project_name,
            "deployment_id": deployment_id,
            "error": {
                "code": "pages.rollback_already_production_readback_failed",
                "message": "Cloudflare reported the rollback target is already production, but MCP could not verify Pages project readback.",
                "hint": "Refresh Pages deployments/project state before retrying rollback.",
                "upstream": err.payload(),
                "readback_error": readback_err.payload(),
            },
        })),
    }
}

fn account_api_token_operation(action: &str) -> Option<(&'static str, bool)> {
    match normalize_action(action).as_str() {
        "list_permission_groups" | "permission_groups" => {
            Some(("account-api-tokens-list-permission-groups", false))
        }
        "list" | "list_tokens" => Some(("account-api-tokens-list-tokens", false)),
        "get" | "details" | "token_details" => Some(("account-api-tokens-token-details", true)),
        "verify" => Some(("account-api-tokens-verify-token", false)),
        "create" | "create_token" => Some(("account-api-tokens-create-token", false)),
        "update" | "update_token" => Some(("account-api-tokens-update-token", true)),
        "delete" | "delete_token" => Some(("account-api-tokens-delete-token", true)),
        "roll" | "rotate" | "roll_token" | "rotate_token" => {
            Some(("account-api-tokens-roll-token", true))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PermissionGroupSummary {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum PermissionSelectorMode {
    Add,
    Remove,
}

#[derive(Debug)]
struct PermissionSelectorResolution {
    to_change: Vec<PermissionGroupSummary>,
    noops: Vec<PermissionGroupSummary>,
}

fn cloudflare_result_value(value: &Value) -> &Value {
    value.get("result").unwrap_or(value)
}

fn extract_permission_group_summaries(value: &Value) -> Vec<PermissionGroupSummary> {
    let result = cloudflare_result_value(value);
    if let Some(groups) = result.as_array() {
        return extract_permission_group_summaries_from_values(groups);
    }
    for field in ["permission_groups", "groups", "data"] {
        if let Some(groups) = result.get(field).and_then(Value::as_array) {
            return extract_permission_group_summaries_from_values(groups);
        }
    }
    Vec::new()
}

fn extract_permission_group_summaries_from_array(
    value: Option<&Value>,
) -> Vec<PermissionGroupSummary> {
    value
        .and_then(Value::as_array)
        .map(|groups| extract_permission_group_summaries_from_values(groups))
        .unwrap_or_default()
}

fn extract_permission_group_summaries_from_values(groups: &[Value]) -> Vec<PermissionGroupSummary> {
    groups.iter().filter_map(permission_group_summary).collect()
}

fn permission_group_summary(value: &Value) -> Option<PermissionGroupSummary> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())?
        .to_string();
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    let scopes = value
        .get("scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Some(PermissionGroupSummary { id, name, scopes })
}

fn resolve_permission_selectors(
    selectors: &[String],
    catalog_groups: &[PermissionGroupSummary],
    current_groups: &[PermissionGroupSummary],
    mode: PermissionSelectorMode,
) -> Result<PermissionSelectorResolution, CallToolResult> {
    let current_ids: BTreeSet<&str> = current_groups
        .iter()
        .map(|group| group.id.as_str())
        .collect();
    let mut by_change_id = BTreeMap::new();
    let mut by_noop_id = BTreeMap::new();
    for selector in selectors {
        let selector = selector.trim();
        if selector.is_empty() {
            continue;
        }
        let group = match resolve_permission_selector(selector, catalog_groups, current_groups) {
            Ok(group) => group,
            Err(error) => return Err(error),
        };
        let is_present = current_ids.contains(group.id.as_str());
        match (mode, is_present) {
            (PermissionSelectorMode::Add, true) => {
                by_noop_id.insert(group.id.clone(), group);
            }
            (PermissionSelectorMode::Add, false) => {
                by_change_id.insert(group.id.clone(), group);
            }
            (PermissionSelectorMode::Remove, true) => {
                by_change_id.insert(group.id.clone(), group);
            }
            (PermissionSelectorMode::Remove, false) => {
                by_noop_id.insert(group.id.clone(), group);
            }
        }
    }
    Ok(PermissionSelectorResolution {
        to_change: by_change_id.into_values().collect(),
        noops: by_noop_id.into_values().collect(),
    })
}

fn resolve_permission_selector(
    selector: &str,
    catalog_groups: &[PermissionGroupSummary],
    current_groups: &[PermissionGroupSummary],
) -> Result<PermissionGroupSummary, CallToolResult> {
    let mut matches: BTreeMap<String, PermissionGroupSummary> = BTreeMap::new();
    for group in current_groups.iter().chain(catalog_groups.iter()) {
        if permission_group_matches_selector(group, selector) {
            matches.insert(group.id.clone(), group.clone());
        }
    }
    match matches.len() {
        0 => Err(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "account_api_token_permission_plan",
            "error": {
                "code": "account_api_token_permission_plan.permission_not_found",
                "message": "permission selector did not match a permission group id, name, or exact scope",
                "hint": "Use account_api_tokens action=list_permission_groups, then pass an exact permission group id or name.",
                "selector": selector,
            },
            "catalog_sample": catalog_groups.iter().take(25).collect::<Vec<_>>(),
        }))),
        1 => Ok(matches.into_values().next().expect("one match")),
        _ => Err(CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "account_api_token_permission_plan",
            "error": {
                "code": "account_api_token_permission_plan.ambiguous_permission",
                "message": "permission selector matched multiple permission groups",
                "hint": "Pass the exact permission group id to disambiguate.",
                "selector": selector,
            },
            "matches": matches.into_values().collect::<Vec<_>>(),
        }))),
    }
}

fn permission_group_matches_selector(group: &PermissionGroupSummary, selector: &str) -> bool {
    let normalized_selector = normalize_permission_selector(selector);
    group.id.eq_ignore_ascii_case(selector)
        || group
            .name
            .as_ref()
            .is_some_and(|name| normalize_permission_selector(name) == normalized_selector)
        || group
            .scopes
            .iter()
            .any(|scope| normalize_permission_selector(scope) == normalized_selector)
}

fn normalize_permission_selector(value: &str) -> String {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

fn summarize_token_policies(policies: &[Value]) -> Vec<Value> {
    policies
        .iter()
        .enumerate()
        .map(|(index, policy)| {
            json!({
                "index": index,
                "effect": policy.get("effect").cloned().unwrap_or(Value::Null),
                "resources": policy.get("resources").cloned().unwrap_or(Value::Null),
                "permission_groups": extract_permission_group_summaries_from_array(policy.get("permission_groups")),
            })
        })
        .collect()
}

fn build_account_api_token_update_body(token: &Value) -> Result<Value, CallToolResult> {
    let Some(token_object) = token.as_object() else {
        return Err(invalid_argument_result(
            "account_api_token_permission_plan.invalid_current_token",
            "current token is not a JSON object",
            "Pass current_token from account_api_tokens action=get or let the MCP fetch token details by token_id.",
        ));
    };
    let mut body = Map::new();
    for field in ["name", "policies", "condition", "expires_on", "not_before"] {
        if let Some(value) = token_object.get(field) {
            body.insert(field.to_string(), value.clone());
        }
    }
    if !body.contains_key("name") {
        return Err(invalid_argument_result(
            "account_api_token_permission_plan.missing_token_name",
            "current token does not include name",
            "Refresh token details before planning an update; Cloudflare token updates require preserving the token name.",
        ));
    }
    if !body.contains_key("policies") {
        return Err(invalid_argument_result(
            "account_api_token_permission_plan.missing_token_policies",
            "current token does not include policies",
            "Refresh token details before planning an update; the helper preserves existing policies and only changes permission_groups.",
        ));
    }
    Ok(Value::Object(body))
}

fn normalize_ingress_rule_arg(rule: &IngressRuleArgs) -> IngressRule {
    match rule {
        IngressRuleArgs::Object(rule) => IngressRule {
            hostname: rule.hostname.clone(),
            service: rule.service.clone(),
        },
        IngressRuleArgs::Text(raw) => parse_ingress_rule_text(raw),
    }
}

fn parse_ingress_rule_text(raw: &str) -> IngressRule {
    let trimmed = raw.trim();
    for separator in ["->", "=>"] {
        if let Some((hostname, service)) = trimmed.split_once(separator) {
            return IngressRule {
                hostname: Some(hostname.trim().to_string()),
                service: service.trim().to_string(),
            };
        }
    }
    if !trimmed.starts_with("http_status:") {
        return IngressRule {
            hostname: Some(trimmed.to_string()),
            service: String::new(),
        };
    }
    IngressRule {
        hostname: None,
        service: trimmed.to_string(),
    }
}

fn normalize_action(action: &str) -> String {
    action.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn query_mentions_waf(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    let query = query.to_ascii_lowercase();
    query.contains("waf")
        || query.contains("firewall")
        || query.contains("security event")
        || query.contains("security_events")
        || query.contains("firewalleventsadaptive")
        || query.contains("blocked request")
}

const DEFAULT_WAF_PHASES: &[&str] = &[
    "http_request_firewall_custom",
    "http_request_firewall_managed",
    "http_ratelimit",
];

#[derive(Debug, Clone)]
struct WafTarget {
    scope: &'static str,
    identifier: String,
}

impl WafTarget {
    fn entrypoint_path(&self, phase: &str) -> String {
        match self.scope {
            "account" => format!(
                "/accounts/{}/rulesets/phases/{}/entrypoint",
                self.identifier, phase
            ),
            _ => format!(
                "/zones/{}/rulesets/phases/{}/entrypoint",
                self.identifier, phase
            ),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "scope": self.scope,
            "id": self.identifier,
        })
    }
}

struct WafLifecyclePlan {
    target: WafTarget,
    phase: String,
    entrypoint_path: String,
    current_ruleset: Value,
    planned_ruleset: Value,
    diff: Value,
    validation: Value,
    ordering: Value,
    performance_readback: Value,
    required_confirmation_token: String,
    changed_rule_ids: Vec<String>,
    analytics_zone_id: Option<String>,
}

async fn build_waf_lifecycle_plan(
    server: &CloudflareMcp,
    account_id: Option<&str>,
    zone_id: Option<&str>,
    scope: Option<&str>,
    phase: Option<&str>,
    edits: &[WafRuleEdit],
    max_rules: Option<usize>,
    stale_list_refs: &[String],
    empty_list_refs: &[String],
    fail_on_stale_lists: bool,
) -> Result<WafLifecyclePlan, CallToolResult> {
    if edits.is_empty() {
        return Err(invalid_argument_result(
            "waf.edits_required",
            "at least one WAF rule edit is required",
            "Pass edits with operation=add, update, delete, enable, disable, or move.",
        ));
    }
    let target = resolve_waf_target(server, scope, account_id, zone_id)?;
    let phase = normalize_single_waf_phase(phase)?;
    let entrypoint_path = target.entrypoint_path(&phase);
    let current_ruleset = server
        .cloudflare
        .api_request(
            "cloudflare.waf.ruleset.entrypoint.read",
            reqwest::Method::GET,
            &entrypoint_path,
            &[],
            None,
        )
        .await
        .map_err(adapter_error_result)?;

    let planned = plan_waf_ruleset_changes(
        &current_ruleset,
        edits,
        max_rules,
        stale_list_refs,
        empty_list_refs,
        fail_on_stale_lists,
    )?;
    let required_confirmation_token =
        waf_ruleset_confirmation_token(&entrypoint_path, &planned.planned_ruleset);
    let analytics_zone_id = zone_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| server.default_zone_id.clone())
        .filter(|_| {
            target.scope == "zone" || zone_id.is_some() || server.default_zone_id.is_some()
        });
    let performance_readback = json!({
        "ruleset_readback": true,
        "security_events_readback_available": analytics_zone_id.is_some(),
        "security_events_dataset": "firewallEventsAdaptive",
        "changed_rule_ids": planned.changed_rule_ids,
        "note": "Security Events readback is contextual and may lag; ruleset readback remains the apply source of truth.",
    });

    Ok(WafLifecyclePlan {
        target,
        phase,
        entrypoint_path,
        current_ruleset,
        planned_ruleset: planned.planned_ruleset,
        diff: planned.diff,
        validation: planned.validation,
        ordering: planned.ordering,
        performance_readback,
        required_confirmation_token,
        changed_rule_ids: planned.changed_rule_ids,
        analytics_zone_id,
    })
}

struct PlannedWafRuleset {
    planned_ruleset: Value,
    diff: Value,
    validation: Value,
    ordering: Value,
    changed_rule_ids: Vec<String>,
}

fn plan_waf_ruleset_changes(
    current_ruleset: &Value,
    edits: &[WafRuleEdit],
    max_rules: Option<usize>,
    stale_list_refs: &[String],
    empty_list_refs: &[String],
    fail_on_stale_lists: bool,
) -> Result<PlannedWafRuleset, CallToolResult> {
    let mut planned_ruleset = current_ruleset.clone();
    let rules = planned_ruleset
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            invalid_argument_result(
                "waf.rules_missing",
                "current WAF ruleset does not contain a rules array",
                "Verify the WAF Rulesets API response before planning mutations.",
            )
        })?;
    let before_order = waf_rule_order(rules);
    let mut changes = Vec::new();
    let mut changed_rule_ids = BTreeSet::new();
    let mut action_change_warnings = Vec::new();

    for edit in edits {
        let op = normalize_action(&edit.operation);
        match op.as_str() {
            "add" | "create" => {
                let mut rule = waf_rule_from_add_edit(edit)?;
                place_waf_rule(rules, &mut rule, edit)?;
                let label = waf_rule_label(&rule);
                changed_rule_ids.insert(label.clone());
                changes.push(json!({
                    "operation": "add",
                    "rule": compact_waf_rule(&rule, false),
                    "position": waf_edit_position(edit),
                }));
            }
            "update" | "patch" => {
                let index = find_waf_rule_index(rules, edit).ok_or_else(|| {
                    invalid_argument_result(
                        "waf.rule_not_found",
                        "cannot update WAF rule because no rule matched rule_id or rule_ref",
                        "Pass the existing Cloudflare rule id or stable ref.",
                    )
                })?;
                let before = rules[index].clone();
                apply_waf_rule_update(&mut rules[index], edit)?;
                if let Some(position) = waf_requested_position(edit) {
                    let mut rule = rules.remove(index);
                    place_waf_rule_with_position(rules, &mut rule, position)?;
                }
                let after_index = find_waf_rule_index(rules, edit)
                    .unwrap_or(index.min(rules.len().saturating_sub(1)));
                let after = rules[after_index].clone();
                if before.get("action") != after.get("action") {
                    action_change_warnings.push(waf_action_change_warning(&before, &after));
                }
                let label = waf_rule_label(&after);
                changed_rule_ids.insert(label);
                changes.push(json!({
                    "operation": "update",
                    "before": compact_waf_rule(&before, false),
                    "after": compact_waf_rule(&after, false),
                    "position": waf_edit_position(edit),
                }));
            }
            "delete" | "remove" => {
                let index = find_waf_rule_index(rules, edit).ok_or_else(|| {
                    invalid_argument_result(
                        "waf.rule_not_found",
                        "cannot delete WAF rule because no rule matched rule_id or rule_ref",
                        "Pass the existing Cloudflare rule id or stable ref.",
                    )
                })?;
                let removed = rules.remove(index);
                changed_rule_ids.insert(waf_rule_label(&removed));
                changes.push(json!({
                    "operation": "delete",
                    "rule": compact_waf_rule(&removed, false),
                }));
            }
            "enable" | "disable" => {
                let index = find_waf_rule_index(rules, edit).ok_or_else(|| {
                    invalid_argument_result(
                        "waf.rule_not_found",
                        "cannot change WAF rule enabled state because no rule matched rule_id or rule_ref",
                        "Pass the existing Cloudflare rule id or stable ref.",
                    )
                })?;
                let before = rules[index].clone();
                rules[index]["enabled"] = json!(op == "enable");
                let after = rules[index].clone();
                changed_rule_ids.insert(waf_rule_label(&after));
                changes.push(json!({
                    "operation": op,
                    "before": compact_waf_rule(&before, false),
                    "after": compact_waf_rule(&after, false),
                }));
            }
            "move" | "reorder" => {
                let index = find_waf_rule_index(rules, edit).ok_or_else(|| {
                    invalid_argument_result(
                        "waf.rule_not_found",
                        "cannot move WAF rule because no rule matched rule_id or rule_ref",
                        "Pass the existing Cloudflare rule id or stable ref.",
                    )
                })?;
                let mut rule = rules.remove(index);
                let label = waf_rule_label(&rule);
                place_waf_rule(rules, &mut rule, edit)?;
                changed_rule_ids.insert(label.clone());
                changes.push(json!({
                    "operation": "move",
                    "rule": label,
                    "position": waf_edit_position(edit),
                }));
            }
            _ => {
                return Err(invalid_argument_result(
                    "waf.invalid_edit_operation",
                    format!("unsupported WAF edit operation {:?}", edit.operation),
                    "Use add, update, delete, enable, disable, or move.",
                ));
            }
        }
    }

    if let Some(max_rules) = max_rules
        && rules.len() > max_rules
    {
        return Err(invalid_argument_result(
            "waf.rule_cap_exceeded",
            format!(
                "planned WAF ruleset has {} rules, exceeding max_rules={max_rules}",
                rules.len()
            ),
            "Increase max_rules only after confirming the account or zone rule cap.",
        ));
    }

    let list_validation =
        validate_waf_list_references(rules, stale_list_refs, empty_list_refs, fail_on_stale_lists)?;
    let planned_rule_count = rules.len();
    let within_cap = max_rules.is_none_or(|max| planned_rule_count <= max);
    let after_order = waf_rule_order(rules);
    let changed_rule_ids = changed_rule_ids.into_iter().collect::<Vec<_>>();
    Ok(PlannedWafRuleset {
        planned_ruleset,
        diff: json!({
            "change_count": changes.len(),
            "changes": changes,
            "action_change_warnings": action_change_warnings,
        }),
        validation: json!({
            "rule_cap": {
                "max_rules": max_rules,
                "planned_rule_count": planned_rule_count,
                "within_cap": within_cap,
            },
            "lists": list_validation,
        }),
        ordering: json!({
            "before": before_order,
            "after": after_order,
        }),
        changed_rule_ids,
    })
}

fn normalize_single_waf_phase(phase: Option<&str>) -> Result<String, CallToolResult> {
    let values = phase
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| vec![value.to_string()])
        .unwrap_or_else(|| vec!["custom".to_string()]);
    let phases = normalize_waf_phases(&values)?;
    if phases.len() != 1 {
        return Err(invalid_argument_result(
            "waf.single_phase_required",
            "WAF lifecycle mutation requires exactly one phase",
            "Pass phase=custom, managed, ratelimit, ddos_l7, or an explicit Ruleset Engine phase.",
        ));
    }
    Ok(phases[0].clone())
}

fn waf_rule_from_add_edit(edit: &WafRuleEdit) -> Result<Value, CallToolResult> {
    let expression = required_edit_string(edit.expression.as_deref(), "expression")?;
    let description = required_edit_string(edit.description.as_deref(), "description")?;
    let rule_action = required_edit_string(edit.rule_action.as_deref(), "rule_action")?;
    validate_waf_rule_action(rule_action)?;
    let mut rule = Map::new();
    rule.insert("description".to_string(), json!(description));
    rule.insert("expression".to_string(), json!(expression));
    rule.insert("action".to_string(), json!(rule_action));
    rule.insert("enabled".to_string(), json!(edit.enabled.unwrap_or(true)));
    if let Some(rule_ref) = edit
        .rule_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        rule.insert("ref".to_string(), json!(rule_ref));
    }
    if let Some(action_parameters) = edit.action_parameters.clone() {
        rule.insert("action_parameters".to_string(), action_parameters);
    }
    Ok(Value::Object(rule))
}

fn apply_waf_rule_update(rule: &mut Value, edit: &WafRuleEdit) -> Result<(), CallToolResult> {
    let Some(object) = rule.as_object_mut() else {
        return Err(invalid_argument_result(
            "waf.invalid_rule_shape",
            "matched WAF rule is not an object",
            "Verify the Rulesets API response before planning mutations.",
        ));
    };
    if let Some(description) = edit
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        object.insert("description".to_string(), json!(description));
    }
    if let Some(expression) = edit
        .expression
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        object.insert("expression".to_string(), json!(expression));
    }
    if let Some(rule_action) = edit
        .rule_action
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        validate_waf_rule_action(rule_action)?;
        object.insert("action".to_string(), json!(rule_action));
    }
    if let Some(enabled) = edit.enabled {
        object.insert("enabled".to_string(), json!(enabled));
    }
    if let Some(action_parameters) = edit.action_parameters.clone() {
        object.insert("action_parameters".to_string(), action_parameters);
    }
    Ok(())
}

fn required_edit_string<'a>(
    value: Option<&'a str>,
    field: &str,
) -> Result<&'a str, CallToolResult> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid_argument_result(
                "waf.required_edit_field",
                format!("{field} is required for this WAF rule edit"),
                "For add operations pass description, expression, and rule_action.",
            )
        })
}

fn validate_waf_rule_action(action: &str) -> Result<(), CallToolResult> {
    match normalize_action(action).as_str() {
        "block" | "challenge" | "js_challenge" | "managed_challenge" | "log" | "skip"
        | "execute" | "rewrite" | "redirect" | "set_config" => Ok(()),
        _ => Err(invalid_argument_result(
            "waf.invalid_rule_action",
            format!("unsupported WAF rule action {action:?}"),
            "Use a Cloudflare Rulesets action such as block, managed_challenge, log, skip, or execute.",
        )),
    }
}

fn find_waf_rule_index(rules: &[Value], edit: &WafRuleEdit) -> Option<usize> {
    let rule_id = edit
        .rule_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let rule_ref = edit
        .rule_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    rules.iter().position(|rule| {
        rule_id.is_some_and(|id| rule.get("id").and_then(Value::as_str) == Some(id))
            || rule_ref
                .is_some_and(|reference| rule.get("ref").and_then(Value::as_str) == Some(reference))
    })
}

fn place_waf_rule(
    rules: &mut Vec<Value>,
    rule: &mut Value,
    edit: &WafRuleEdit,
) -> Result<(), CallToolResult> {
    let position = waf_requested_position(edit).unwrap_or(WafRulePosition::End);
    place_waf_rule_with_position(rules, rule, position)
}

fn place_waf_rule_with_position(
    rules: &mut Vec<Value>,
    rule: &mut Value,
    position: WafRulePosition,
) -> Result<(), CallToolResult> {
    match position {
        WafRulePosition::End => rules.push(rule.clone()),
        WafRulePosition::Index(index) => {
            let index = index.min(rules.len());
            rules.insert(index, rule.clone());
        }
        WafRulePosition::Before(rule_id) => {
            let index = rules
                .iter()
                .position(|rule| waf_rule_matches_label(rule, &rule_id))
                .ok_or_else(|| {
                    invalid_argument_result(
                        "waf.position_rule_not_found",
                        "before_rule_id did not match an existing WAF rule",
                        "Pass an existing rule id or ref for ordering.",
                    )
                })?;
            rules.insert(index, rule.clone());
        }
        WafRulePosition::After(rule_id) => {
            let index = rules
                .iter()
                .position(|rule| waf_rule_matches_label(rule, &rule_id))
                .ok_or_else(|| {
                    invalid_argument_result(
                        "waf.position_rule_not_found",
                        "after_rule_id did not match an existing WAF rule",
                        "Pass an existing rule id or ref for ordering.",
                    )
                })?;
            rules.insert(index.saturating_add(1), rule.clone());
        }
    }
    Ok(())
}

enum WafRulePosition {
    End,
    Index(usize),
    Before(String),
    After(String),
}

fn waf_requested_position(edit: &WafRuleEdit) -> Option<WafRulePosition> {
    if let Some(index) = edit.index {
        return Some(WafRulePosition::Index(index));
    }
    if let Some(rule_id) = edit
        .before_rule_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(WafRulePosition::Before(rule_id.to_string()));
    }
    if let Some(rule_id) = edit
        .after_rule_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(WafRulePosition::After(rule_id.to_string()));
    }
    None
}

fn waf_edit_position(edit: &WafRuleEdit) -> Value {
    json!({
        "index": edit.index,
        "before_rule_id": edit.before_rule_id,
        "after_rule_id": edit.after_rule_id,
    })
}

fn waf_rule_matches_label(rule: &Value, label: &str) -> bool {
    rule.get("id").and_then(Value::as_str) == Some(label)
        || rule.get("ref").and_then(Value::as_str) == Some(label)
}

fn waf_rule_label(rule: &Value) -> String {
    rule.get("id")
        .and_then(Value::as_str)
        .or_else(|| rule.get("ref").and_then(Value::as_str))
        .or_else(|| rule.get("description").and_then(Value::as_str))
        .unwrap_or("unnamed-rule")
        .to_string()
}

fn waf_rule_order(rules: &[Value]) -> Vec<Value> {
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            json!({
                "index": index,
                "id": rule.get("id").cloned().unwrap_or(Value::Null),
                "ref": rule.get("ref").cloned().unwrap_or(Value::Null),
                "description": rule.get("description").cloned().unwrap_or(Value::Null),
                "enabled": rule.get("enabled").cloned().unwrap_or(json!(true)),
                "action": rule.get("action").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn waf_action_change_warning(before: &Value, after: &Value) -> Value {
    let before_action = before.get("action").and_then(Value::as_str).unwrap_or("");
    let after_action = after.get("action").and_then(Value::as_str).unwrap_or("");
    let severity = match (
        normalize_action(before_action).as_str(),
        normalize_action(after_action).as_str(),
    ) {
        (_, "block") => "high",
        ("block", "managed_challenge" | "challenge" | "js_challenge") => "medium",
        ("managed_challenge" | "challenge" | "js_challenge", "log") => "medium",
        _ => "info",
    };
    json!({
        "rule": waf_rule_label(after),
        "from": before_action,
        "to": after_action,
        "severity": severity,
        "note": "Review false-positive risk before changing WAF enforcement action.",
    })
}

fn validate_waf_list_references(
    rules: &[Value],
    stale_list_refs: &[String],
    empty_list_refs: &[String],
    fail_on_stale_lists: bool,
) -> Result<Value, CallToolResult> {
    let stale = normalized_set(stale_list_refs);
    let empty = normalized_set(empty_list_refs);
    let mut referenced = BTreeSet::new();
    let mut stale_hits = Vec::new();
    let mut empty_hits = Vec::new();
    for rule in rules {
        let expression = rule.get("expression").and_then(Value::as_str).unwrap_or("");
        for list_ref in extract_waf_list_refs(expression) {
            referenced.insert(list_ref.clone());
            if stale.contains(&list_ref) {
                stale_hits.push(json!({
                    "rule": waf_rule_label(rule),
                    "list": list_ref,
                    "status": "stale",
                }));
            } else if empty.contains(&list_ref) {
                empty_hits.push(json!({
                    "rule": waf_rule_label(rule),
                    "list": list_ref,
                    "status": "empty",
                }));
            }
        }
    }
    if fail_on_stale_lists && (!stale_hits.is_empty() || !empty_hits.is_empty()) {
        return Err(invalid_argument_result(
            "waf.stale_list_reference",
            "planned WAF ruleset references stale or empty lists",
            "Clean up the list or remove it from expressions before applying the WAF change.",
        ));
    }
    Ok(json!({
        "referenced_lists": referenced.into_iter().collect::<Vec<_>>(),
        "stale_hits": stale_hits,
        "empty_hits": empty_hits,
        "fail_on_stale_lists": fail_on_stale_lists,
    }))
}

fn normalized_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim().trim_start_matches('$').to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn extract_waf_list_refs(expression: &str) -> Vec<String> {
    let chars = expression.chars().collect::<Vec<_>>();
    let mut refs = BTreeSet::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '$' {
            let mut end = index + 1;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            if end > index + 1 {
                refs.insert(
                    chars[index + 1..end]
                        .iter()
                        .collect::<String>()
                        .to_ascii_lowercase(),
                );
            }
            index = end;
        } else {
            index += 1;
        }
    }
    refs.into_iter().collect()
}

fn waf_ruleset_confirmation_token(path: &str, body: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"waf_ruleset_apply_change\n");
    hasher.update(path.as_bytes());
    hasher.update(b"\n");
    hasher.update(serde_json::to_vec(body).unwrap_or_default());
    format!("waf-ruleset:{}", hex_prefix_local(&hasher.finalize(), 16))
}

fn hex_prefix_local(bytes: &[u8], nibbles: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(nibbles);
    for byte in bytes {
        if out.len() >= nibbles {
            break;
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        if out.len() >= nibbles {
            break;
        }
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn waf_lifecycle_security_events_readback(
    server: &CloudflareMcp,
    zone_id: Option<&str>,
    changed_rule_ids: &[String],
    window_hours: u32,
    sample_limit: u32,
) -> Value {
    let Some(zone_id) = zone_id else {
        return json!({
            "enabled": false,
            "reason": "zone_id is required for firewallEventsAdaptive readback",
        });
    };
    if changed_rule_ids.is_empty() {
        return json!({
            "enabled": false,
            "reason": "no changed rule ids or refs were available for readback",
        });
    }
    let window = waf_time_window(window_hours, None, None);
    let sample_limit = sample_limit.clamp(1, 20);
    let mut results = Vec::new();
    for rule_id in changed_rule_ids.iter().take(5) {
        let filter = waf_security_events_filter(
            &window,
            WafEventFilterInput {
                action: None,
                source: None,
                host: None,
                path: None,
                client_ip: None,
                rule_id: Some(rule_id),
            },
        );
        let body = json!({
            "query": build_waf_rule_activity_query(sample_limit),
            "variables": {
                "zoneTag": zone_id,
                "filter": filter,
            },
        });
        let result = match server.cloudflare.graphql_analytics_query(&body).await {
            Ok(result) => {
                let diagnostics = graphql_authz_diagnostics(
                    GraphqlAnalyticsShape::WafRuleActivity,
                    &body["variables"],
                    &result,
                );
                with_graphql_diagnostics(
                    json!({
                        "rule": rule_id,
                        "ok": !result.get("errors").and_then(Value::as_array).is_some_and(|errors| !errors.is_empty()),
                        "analytics": waf_security_events_projection(&result),
                    }),
                    diagnostics,
                )
            }
            Err(err) => json!({
                "rule": rule_id,
                "ok": false,
                "error": err.payload(),
            }),
        };
        results.push(result);
    }
    json!({
        "enabled": true,
        "zone_id": zone_id,
        "window_utc": window,
        "sample_limit": sample_limit,
        "results": results,
    })
}

#[derive(Debug, Clone, Serialize)]
struct WafTimeWindow {
    start: String,
    end: String,
    window_hours: u32,
}

#[derive(Debug, Clone, Copy)]
struct WafEventFilterInput<'a> {
    action: Option<&'a str>,
    source: Option<&'a str>,
    host: Option<&'a str>,
    path: Option<&'a str>,
    client_ip: Option<&'a str>,
    rule_id: Option<&'a str>,
}

fn resolve_waf_target(
    server: &CloudflareMcp,
    scope: Option<&str>,
    account_id: Option<&str>,
    zone_id: Option<&str>,
) -> Result<WafTarget, CallToolResult> {
    let normalized = normalize_action(scope.unwrap_or("auto"));
    match normalized.as_str() {
        "" | "auto" => {
            if let Some(zone_id) = zone_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .or_else(|| server.default_zone_id.as_deref())
            {
                Ok(WafTarget {
                    scope: "zone",
                    identifier: zone_id.to_string(),
                })
            } else if let Some(account_id) = account_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .or_else(|| server.default_account_id.as_deref())
            {
                Ok(WafTarget {
                    scope: "account",
                    identifier: account_id.to_string(),
                })
            } else {
                Err(invalid_argument_result(
                    "waf.target_required",
                    "zone_id or account_id is required for WAF ruleset reads",
                    "Pass zone_id/account_id or configure CLOUDFLARE_MCP_DEFAULT_ZONE_ID/CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID.",
                ))
            }
        }
        "zone" => {
            let zone_id = zone_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .or_else(|| server.default_zone_id.as_deref())
                .ok_or_else(|| {
                    invalid_argument_result(
                        "waf.zone_id_required",
                        "zone_id is required when scope=zone",
                        "Pass zone_id or configure CLOUDFLARE_MCP_DEFAULT_ZONE_ID.",
                    )
                })?;
            Ok(WafTarget {
                scope: "zone",
                identifier: zone_id.to_string(),
            })
        }
        "account" => {
            let account_id = account_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .or_else(|| server.default_account_id.as_deref())
                .ok_or_else(|| {
                    invalid_argument_result(
                        "waf.account_id_required",
                        "account_id is required when scope=account",
                        "Pass account_id or configure CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID.",
                    )
                })?;
            Ok(WafTarget {
                scope: "account",
                identifier: account_id.to_string(),
            })
        }
        _ => Err(invalid_argument_result(
            "waf.invalid_scope",
            "scope must be auto, zone, or account",
            "Use scope=zone for zone WAF rules, scope=account for account WAF rulesets, or omit scope to prefer a configured/provided zone.",
        )),
    }
}

fn normalize_waf_phases(values: &[String]) -> Result<Vec<String>, CallToolResult> {
    let raw: Vec<&str> = if values.is_empty() {
        DEFAULT_WAF_PHASES.to_vec()
    } else {
        values.iter().map(String::as_str).collect()
    };
    let mut phases = Vec::new();
    for value in raw {
        let normalized = normalize_action(value);
        let phase = match normalized.as_str() {
            "custom" | "custom_rules" | "firewall_custom" | "waf_custom" => {
                "http_request_firewall_custom"
            }
            "managed" | "managed_rules" | "firewall_managed" | "waf_managed" => {
                "http_request_firewall_managed"
            }
            "ratelimit" | "rate_limit" | "rate_limiting" | "waf_rate_limit" => "http_ratelimit",
            "http_request_firewall_custom"
            | "http_request_firewall_managed"
            | "http_ratelimit"
            | "ddos_l7" => normalized.as_str(),
            _ => {
                return Err(invalid_argument_result(
                    "waf.invalid_phase",
                    format!("Unsupported WAF phase {value:?}"),
                    "Use custom, managed, ratelimit, ddos_l7, or an explicit WAF Ruleset Engine phase.",
                ));
            }
        };
        if !phases.iter().any(|existing| existing == phase) {
            phases.push(phase.to_string());
        }
    }
    Ok(phases)
}

fn normalize_waf_group_by(values: &[String]) -> Result<Vec<String>, CallToolResult> {
    let raw: Vec<&str> = if values.is_empty() {
        vec!["action", "source", "host", "path", "country", "hour"]
    } else {
        values.iter().map(String::as_str).collect()
    };
    let mut group_by = Vec::new();
    for value in raw {
        let normalized = normalize_action(value);
        let dimension = match normalized.as_str() {
            "action" | "source" | "host" | "path" | "country" | "hour" | "ip" | "rule" => {
                normalized.as_str()
            }
            "client_ip" | "clientip" => "ip",
            "hostname" => "host",
            "rule_id" | "ruleid" => "rule",
            "datetime_hour" | "datetimehour" => "hour",
            _ => {
                return Err(invalid_argument_result(
                    "waf.invalid_group_by",
                    format!("Unsupported WAF group_by dimension {value:?}"),
                    "Use action, source, host, path, country, hour, ip, or rule.",
                ));
            }
        };
        if !group_by.iter().any(|existing| existing == dimension) {
            group_by.push(dimension.to_string());
        }
    }
    Ok(group_by)
}

fn waf_time_window(window_hours: u32, since: Option<&str>, until: Option<&str>) -> WafTimeWindow {
    let hours = window_hours.clamp(1, 24 * 31);
    let end = until
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format_utc_second(OffsetDateTime::now_utc()));
    let start = since
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format_utc_second(OffsetDateTime::now_utc() - TimeDuration::hours(hours as i64))
        });
    WafTimeWindow {
        start,
        end,
        window_hours: hours,
    }
}

fn format_utc_second(dt: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn waf_security_events_filter(window: &WafTimeWindow, input: WafEventFilterInput<'_>) -> Value {
    let mut filter = Map::new();
    filter.insert("datetime_geq".to_string(), json!(window.start));
    filter.insert("datetime_leq".to_string(), json!(window.end));
    insert_non_empty(&mut filter, "action", input.action);
    insert_non_empty(&mut filter, "source", input.source);
    insert_non_empty(&mut filter, "clientRequestHTTPHost", input.host);
    insert_non_empty(&mut filter, "clientRequestPath", input.path);
    insert_non_empty(&mut filter, "clientIP", input.client_ip);
    insert_non_empty(&mut filter, "ruleId", input.rule_id);
    Value::Object(filter)
}

fn insert_non_empty(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        map.insert(key.to_string(), json!(value));
    }
}

fn build_waf_security_events_query(group_by: &[String], limit: u32, sample_limit: u32) -> String {
    let mut group_nodes = String::new();
    for dimension in group_by {
        if let Some((alias, field)) = waf_group_dimension_field(dimension) {
            group_nodes.push_str(&format!(
                "{alias}: firewallEventsAdaptiveGroups(filter: $filter, limit: {limit}, orderBy: [count_DESC]) {{ count dimensions {{ {field} }} }}\n"
            ));
        }
    }
    let samples = if sample_limit == 0 {
        String::new()
    } else {
        format!(
            "samples: firewallEventsAdaptive(filter: $filter, limit: {sample_limit}, orderBy: [datetime_DESC]) {{ action clientAsn clientCountryName clientIP clientRequestHTTPHost clientRequestPath clientRequestQuery datetime source userAgent ruleId rulesetId rayName }}\n"
        )
    };
    format!(
        "query WafSecurityEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {{ viewer {{ zones(filter: {{ zoneTag: $zoneTag }}) {{ settings {{ firewallEventsAdaptive {{ maxDuration maxPageSize notOlderThan }} }} {group_nodes}{samples} }} }} }}"
    )
}

fn build_waf_rule_activity_query(sample_limit: u32) -> String {
    format!(
        "query WafRuleActivity($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {{ viewer {{ zones(filter: {{ zoneTag: $zoneTag }}) {{ byAction: firewallEventsAdaptiveGroups(filter: $filter, limit: 20, orderBy: [count_DESC]) {{ count dimensions {{ action }} }} bySource: firewallEventsAdaptiveGroups(filter: $filter, limit: 20, orderBy: [count_DESC]) {{ count dimensions {{ source }} }} samples: firewallEventsAdaptive(filter: $filter, limit: {sample_limit}, orderBy: [datetime_DESC]) {{ action clientAsn clientCountryName clientIP clientRequestHTTPHost clientRequestPath clientRequestQuery datetime source userAgent ruleId rulesetId rayName }} }} }} }}"
    )
}

fn waf_group_dimension_field(dimension: &str) -> Option<(&'static str, &'static str)> {
    match dimension {
        "action" => Some(("byAction", "action")),
        "source" => Some(("bySource", "source")),
        "host" => Some(("byHost", "clientRequestHTTPHost")),
        "path" => Some(("byPath", "clientRequestPath")),
        "country" => Some(("byCountry", "clientCountryName")),
        "hour" => Some(("byHour", "datetimeHour")),
        "ip" => Some(("byIp", "clientIP")),
        "rule" => Some(("byRule", "ruleId")),
        _ => None,
    }
}

fn waf_ruleset_readback_entry(
    target: &WafTarget,
    phase: &str,
    path: &str,
    result: Result<Value, crate::cloudflare::AdapterError>,
    include_rules: bool,
    include_raw: bool,
) -> Value {
    match result {
        Ok(result) => {
            let rules = result
                .get("rules")
                .and_then(Value::as_array)
                .map(|rules| {
                    rules
                        .iter()
                        .map(|rule| compact_waf_rule(rule, include_raw))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let enabled_rules = rules
                .iter()
                .filter(|rule| rule.get("enabled").and_then(Value::as_bool).unwrap_or(true))
                .count();
            let disabled_rules = rules.len().saturating_sub(enabled_rules);
            let mut payload = json!({
                "ok": true,
                "scope": target.scope,
                "phase": phase,
                "path": path,
                "ruleset": {
                    "id": result.get("id").cloned().unwrap_or(Value::Null),
                    "name": result.get("name").cloned().unwrap_or(Value::Null),
                    "kind": result.get("kind").cloned().unwrap_or(Value::Null),
                    "version": result.get("version").cloned().unwrap_or(Value::Null),
                    "last_updated": result.get("last_updated").cloned().unwrap_or(Value::Null),
                    "rule_count": rules.len(),
                    "enabled_rule_count": enabled_rules,
                    "disabled_rule_count": disabled_rules,
                },
            });
            if include_rules {
                payload["rules"] = Value::Array(rules);
            }
            if include_raw {
                payload["raw"] = result;
            }
            payload
        }
        Err(err) => json!({
            "ok": false,
            "scope": target.scope,
            "phase": phase,
            "path": path,
            "error": err.payload(),
        }),
    }
}

fn compact_waf_rule(rule: &Value, include_raw: bool) -> Value {
    let mut payload = json!({
        "id": rule.get("id").cloned().unwrap_or(Value::Null),
        "version": rule.get("version").cloned().unwrap_or(Value::Null),
        "description": rule.get("description").cloned().unwrap_or(Value::Null),
        "action": rule.get("action").cloned().unwrap_or(Value::Null),
        "enabled": rule.get("enabled").cloned().unwrap_or(json!(true)),
        "expression": rule.get("expression").cloned().unwrap_or(Value::Null),
        "ref": rule.get("ref").cloned().unwrap_or(Value::Null),
        "categories": rule.get("categories").cloned().unwrap_or(Value::Null),
        "last_updated": rule.get("last_updated").cloned().unwrap_or(Value::Null),
    });
    if let Some(action_parameters) = rule.get("action_parameters") {
        payload["action_parameters"] = summarize_waf_action_parameters(action_parameters);
    }
    if let Some(overrides) = rule.get("overrides") {
        payload["overrides"] = overrides.clone();
    }
    if include_raw {
        payload["raw"] = rule.clone();
    }
    payload
}

fn summarize_waf_action_parameters(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    json!({
        "id": object.get("id").cloned().unwrap_or(Value::Null),
        "version": object.get("version").cloned().unwrap_or(Value::Null),
        "ruleset": object.get("ruleset").cloned().unwrap_or(Value::Null),
        "products": object.get("products").cloned().unwrap_or(Value::Null),
        "phases": object.get("phases").cloned().unwrap_or(Value::Null),
        "overrides": object.get("overrides").cloned().unwrap_or(Value::Null),
    })
}

fn find_waf_rules(ruleset: &Value, rule_id: &str, phase: &str, include_raw: bool) -> Vec<Value> {
    ruleset
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| {
                    rule.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|value| value == rule_id)
                        || rule
                            .get("ref")
                            .and_then(Value::as_str)
                            .is_some_and(|value| value == rule_id)
                })
                .map(|rule| {
                    let mut compact = compact_waf_rule(rule, include_raw);
                    compact["phase"] = json!(phase);
                    compact["ruleset_id"] = ruleset.get("id").cloned().unwrap_or(Value::Null);
                    compact["ruleset_name"] = ruleset.get("name").cloned().unwrap_or(Value::Null);
                    compact
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn waf_security_events_projection(result: &Value) -> Value {
    let Some(zone) = result
        .pointer("/data/viewer/zones/0")
        .and_then(Value::as_object)
    else {
        return json!({
            "zones_returned": 0,
            "groups": {},
            "samples": [],
        });
    };
    let mut groups = Map::new();
    for (key, value) in zone {
        if key.starts_with("by") {
            groups.insert(key.clone(), value.clone());
        }
    }
    json!({
        "zones_returned": result
            .pointer("/data/viewer/zones")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        "settings": zone.get("settings").cloned().unwrap_or(Value::Null),
        "groups": groups,
        "samples": zone.get("samples").cloned().unwrap_or_else(|| json!([])),
    })
}

fn waf_source_notes() -> Value {
    json!({
        "kind": "cloudflare_waf_rulesets_and_security_events",
        "ruleset_phases": DEFAULT_WAF_PHASES,
        "rulesets_reference": "https://developers.cloudflare.com/ruleset-engine/reference/phases-list/",
        "analytics_dataset": "firewallEventsAdaptive",
        "analytics_reference": "https://developers.cloudflare.com/waf/analytics/security-events/",
        "notes": [
            "WAF custom, managed, and rate limiting rules are Ruleset Engine phases.",
            "Security Events are individual events; one HTTP request can trigger more than one security event.",
            "Cloudflare may sample Security Events; use narrower windows when investigating spikes."
        ],
    })
}

fn graphql_document_has_forbidden_operation(query: &str) -> bool {
    let bytes = query.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        match bytes[offset] {
            b'#' => {
                offset += 1;
                while offset < bytes.len() && bytes[offset] != b'\n' {
                    offset += 1;
                }
            }
            b'"' => {
                offset = skip_graphql_string(query, offset);
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = offset;
                offset += 1;
                while offset < bytes.len()
                    && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
                {
                    offset += 1;
                }
                let token = &query[start..offset];
                if token.eq_ignore_ascii_case("mutation")
                    || token.eq_ignore_ascii_case("subscription")
                {
                    return true;
                }
            }
            _ => offset += 1,
        }
    }
    false
}

fn skip_graphql_string(query: &str, start: usize) -> usize {
    let bytes = query.as_bytes();
    if bytes
        .get(start..start.saturating_add(3))
        .is_some_and(|prefix| prefix == b"\"\"\"")
    {
        let mut offset = start + 3;
        while offset + 2 < bytes.len() {
            if &bytes[offset..offset + 3] == b"\"\"\"" {
                return offset + 3;
            }
            offset += 1;
        }
        return bytes.len();
    }

    let mut offset = start + 1;
    while offset < bytes.len() {
        match bytes[offset] {
            b'\\' => offset = offset.saturating_add(2),
            b'"' => return offset + 1,
            _ => offset += 1,
        }
    }
    bytes.len()
}

fn api_catalog_error_result(err: ApiCatalogError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": err.code(),
            "message": err.message(),
            "hint": err.hint(),
        }
    }))
}

fn r2_write_body(
    content_text: Option<&str>,
    content_base64: Option<&str>,
) -> Result<Vec<u8>, CallToolResult> {
    match (
        content_text.filter(|value| !value.is_empty()),
        content_base64.filter(|value| !value.is_empty()),
    ) {
        (Some(_), Some(_)) => Err(invalid_argument_result(
            "r2.invalid_write_body",
            "Provide either content_text or content_base64, not both",
            "Use content_text for UTF-8 text and content_base64 for binary object content.",
        )),
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(encoded)) => BASE64_STANDARD.decode(encoded).map_err(|err| {
            invalid_argument_result(
                "r2.invalid_base64",
                format!("content_base64 is not valid base64: {err}"),
                "Provide standard base64-encoded object bytes.",
            )
        }),
        (None, None) => Err(invalid_argument_result(
            "r2.missing_write_body",
            "Provide content_text or content_base64",
            "Use content_text for UTF-8 text and content_base64 for binary object content.",
        )),
    }
}

fn plan_r2_put_object(
    account_id: &str,
    bucket_name: &str,
    object_key: &str,
    bytes: usize,
    content_type: Option<&str>,
    metadata_count: usize,
) -> MutationPlan {
    MutationPlan::new("r2_put_object")
        .step(
            "prepare_r2_put_request",
            false,
            json!({
                "account_id": account_id,
                "bucket_name": bucket_name,
                "object_key": object_key,
                "bytes": bytes,
                "content_type": content_type,
                "metadata_count": metadata_count,
            }),
        )
        .step(
            "write_r2_object",
            true,
            json!({
                "bucket_name": bucket_name,
                "object_key": object_key,
            }),
        )
}

fn truncate_api_payload(mut payload: Value, max_bytes: usize) -> Value {
    let encoded = serde_json::to_vec(&payload).unwrap_or_default();
    if encoded.len() <= max_bytes {
        if let Some(object) = payload.as_object_mut() {
            object.insert(
                "response_size".to_string(),
                json!({ "bytes": encoded.len(), "truncated": false }),
            );
        }
        return payload;
    }

    let summary = json!({
        "ok": true,
        "operation": payload.get("operation").cloned().unwrap_or_else(|| json!("api_read")),
        "api_operation": payload.get("api_operation").cloned(),
        "response_size": {
            "bytes": encoded.len(),
            "max_bytes": max_bytes,
            "truncated": true,
        },
        "truncation_note": "Cloudflare API response exceeded max_bytes; rerun with narrower query filters or pagination.",
    });
    summary
}

fn policy_violation_result(violation: crate::policy::PolicyInvariantViolation) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": violation,
    }))
}

fn invalid_argument_result(
    code: &'static str,
    message: impl Into<String>,
    hint: &'static str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message.into(),
            "hint": hint,
        }
    }))
}

fn worker_upload_error_result(err: WorkerUploadError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": err.payload(),
    }))
}

fn publish_gate_denied_result(
    operation: &'static str,
    report: &crate::publish::PublishGateReport,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "error": {
            "code": "publish.policy_gate_denied",
            "message": "publish blocked by policy preflight gate",
            "hint": "Create/validate Access app + allow policies, or pass explicit override flag with reason.",
            "decision": report.decision,
        },
        "policy_gate": report,
        "state_machine": preflight_trace(report),
    }))
}

fn publish_operation_error_result(
    operation: &'static str,
    report: &crate::publish::PublishGateReport,
    err: crate::cloudflare::AdapterError,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": operation,
        "error": err.payload(),
        "policy_gate": report,
        "state_machine": lock_first_publish_trace(report, false),
    }))
}

fn tunnel_conflict_result(conflict: crate::tunnel::TunnelConflict) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": conflict.code,
            "message": conflict.message,
            "hint": conflict.hint,
        },
        "conflict": conflict,
    }))
}

fn dns_route_conflict_result(conflict: DnsRouteConflict) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": conflict.code,
            "message": conflict.message,
            "hint": conflict.hint,
        },
        "route_conflict": conflict,
    }))
}

fn dns_route_verification_failed_result(
    verification: crate::dns_route::DnsRouteVerification,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": verification.code,
            "message": format!("dns route verification failed: {}", verification.reason),
            "hint": verification.hint,
        },
        "route_verification": verification,
    }))
}

fn access_app_conflict_result(conflict: AccessAppConflict) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": conflict.code,
            "message": conflict.message,
            "hint": conflict.hint,
        },
        "upsert_conflict": conflict,
    }))
}

fn access_app_validation_result(err: AccessAppValidationError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": err.code,
            "message": err.message,
            "hint": err.hint,
        },
        "validation": err,
    }))
}

fn access_app_action_label(action: AccessAppAction) -> &'static str {
    match action {
        AccessAppAction::Create => "create",
        AccessAppAction::Update => "update",
        AccessAppAction::Noop => "noop",
    }
}

fn cache_validation_result(err: CacheValidationError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": err,
    }))
}

fn parse_cache_rule(value: Value) -> Result<CacheRule, CallToolResult> {
    serde_json::from_value(value).map_err(|err| {
        invalid_argument_result(
            "cache.invalid_rule_payload",
            format!("rule must match Cloudflare ruleset rule shape: {err}"),
            "Provide a JSON object accepted by Cloudflare Rulesets for the selected cache phase.",
        )
    })
}

fn mutate_cache_ruleset(
    mut current: CacheRuleset,
    action: CacheRulesAction,
    rule_id: Option<&str>,
    rule: Option<Value>,
    rules: Option<Vec<Value>>,
) -> Result<Option<CacheRuleset>, CallToolResult> {
    match action {
        CacheRulesAction::Get => Ok(None),
        CacheRulesAction::Append => {
            let Some(rule) = rule else {
                return Err(invalid_argument_result(
                    "cache.rule_required",
                    "rule is required when action=append",
                    "Provide one Cloudflare Rulesets rule object.",
                ));
            };
            current.rules.push(parse_cache_rule(rule)?);
            Ok(Some(current))
        }
        CacheRulesAction::Upsert => {
            let Some(rule_value) = rule else {
                return Err(invalid_argument_result(
                    "cache.rule_required",
                    "rule is required when action=upsert",
                    "Provide one Cloudflare Rulesets rule object.",
                ));
            };
            let rule = parse_cache_rule(rule_value)?;
            let target_id = rule
                .id
                .as_deref()
                .or(rule_id)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(target_id) = target_id
                && let Some(existing) = current
                    .rules
                    .iter_mut()
                    .find(|existing| existing.id.as_deref() == Some(target_id))
            {
                *existing = rule;
                return Ok(Some(current));
            }
            current.rules.push(rule);
            Ok(Some(current))
        }
        CacheRulesAction::Delete => {
            let Some(rule_id) = rule_id.map(str::trim).filter(|value| !value.is_empty()) else {
                return Err(invalid_argument_result(
                    "cache.rule_id_required",
                    "rule_id is required when action=delete",
                    "Provide the Cloudflare Rulesets rule id to delete.",
                ));
            };
            current
                .rules
                .retain(|rule| rule.id.as_deref() != Some(rule_id));
            Ok(Some(current))
        }
        CacheRulesAction::ReplaceAll => {
            let mut parsed_rules = Vec::new();
            for rule in rules.unwrap_or_default() {
                parsed_rules.push(parse_cache_rule(rule)?);
            }
            current.rules = parsed_rules;
            Ok(Some(current))
        }
    }
}

async fn handle_cache_resource(
    server: &CloudflareMcp,
    operation: &'static str,
    base_path: &'static str,
    args: CacheResourceArgs,
    parts: Parts,
) -> Result<CallToolResult, crate::McpError> {
    let zone_id = resolve_zone_id(server, args.zone_id.as_deref())?;
    let action = match CacheResourceAction::parse(&args.action) {
        Ok(action) => action,
        Err(err) => return Ok(cache_validation_result(err)),
    };
    let path = match cache_resource_path(base_path, operation, action, args.resource.as_deref()) {
        Ok(path) => path,
        Err(base) => return Ok(base),
    };
    let plan = plan_cache_mutation(
        operation,
        zone_id,
        json!({ "action": action.as_str(), "path": path }),
    );
    let audit = MutationAuditSession::start(
        Some(&parts),
        operation,
        json!({ "zone_id": zone_id, "action": action.as_str(), "path": path }),
        args.dry_run,
    );

    let base = if args.dry_run && action.mutates() {
        CallToolResult::structured(json!({
            "ok": true,
            "operation": operation,
            "zone_id": zone_id,
            "action": action.as_str(),
            "path": path,
            "payload": args.payload,
            "dry_run_note": "No Cloudflare cache resource mutation applied.",
        }))
    } else {
        let result = match action {
            CacheResourceAction::Get | CacheResourceAction::Status | CacheResourceAction::List => {
                server.cloudflare.cache_get(zone_id, &path).await
            }
            CacheResourceAction::Delete | CacheResourceAction::BatchDelete => {
                server.cloudflare.cache_delete(zone_id, &path).await
            }
            CacheResourceAction::Update
            | CacheResourceAction::StartClear
            | CacheResourceAction::Upsert
            | CacheResourceAction::BatchUpsert => {
                server
                    .cloudflare
                    .cache_update(zone_id, &path, args.payload.unwrap_or_else(|| json!({})))
                    .await
            }
        };
        match result {
            Ok(result) => CallToolResult::structured(json!({
                "ok": true,
                "operation": operation,
                "zone_id": zone_id,
                "action": action.as_str(),
                "path": path,
                "result": result,
                "deprecated": operation == "cache_origin_regions",
            })),
            Err(err) => adapter_error_result(err),
        }
    };

    Ok(finalize_mutation_result(
        base,
        &plan,
        audit,
        args.dry_run || !action.mutates(),
    ))
}

fn cache_resource_path(
    base_path: &'static str,
    operation: &'static str,
    action: CacheResourceAction,
    resource: Option<&str>,
) -> Result<String, CallToolResult> {
    if let Some(resource) = resource.map(str::trim).filter(|value| !value.is_empty()) {
        if resource.contains("..") || resource.starts_with('/') || resource.contains('?') {
            return Err(invalid_argument_result(
                "cache.invalid_resource",
                "resource must be a relative cache API path segment",
                "Use a resource selector such as smart, regional, variants, reserve, clear, regions, or a cache/... path.",
            ));
        }
        if resource.starts_with("cache/") {
            return Ok(resource.to_string());
        }
        return Ok(match (operation, resource) {
            ("cache_tiered", "smart") => "cache/tiered_cache_smart_topology_enable".to_string(),
            ("cache_tiered", "regional") => "cache/regional_tiered_cache".to_string(),
            ("cache_reserve", "reserve") => "cache/cache_reserve".to_string(),
            ("cache_reserve", "clear") => "cache/cache_reserve_clear".to_string(),
            ("cache_variants", "variants") => "cache/variants".to_string(),
            ("cache_origin_regions", "regions") => "cache/origin_cache_control".to_string(),
            _ => format!("cache/{resource}"),
        });
    }
    Ok(match action {
        CacheResourceAction::Status | CacheResourceAction::StartClear
            if operation == "cache_reserve" =>
        {
            "cache/cache_reserve_clear".to_string()
        }
        _ => base_path.to_string(),
    })
}

fn worker_binding_expectation_label(expectation: &WorkerBindingExpectation) -> Value {
    json!({
        "name": expectation.name.trim(),
        "binding_type": expectation.binding_type.as_deref().map(str::trim),
        "field": expectation.field.trim(),
        "expects_value": expectation.value.is_some(),
    })
}

fn worker_binding_presence(bindings: Option<&[Value]>, binding_name: &str) -> Value {
    let expectation = WorkerBindingExpectation {
        name: binding_name.to_string(),
        binding_type: None,
        field: default_binding_field(),
        value: None,
    };
    verify_worker_binding(bindings, &expectation)
}

fn verify_worker_upload_readback(
    upload_summary: &Value,
    readback: &crate::cloudflare::model::WorkerSettings,
) -> Value {
    let expected_main_module = upload_summary
        .get("main_module")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(expected_main_module) = expected_main_module else {
        return json!({
            "matched": true,
            "code": "workers.upload_readback_not_applicable",
            "message": "upload summary did not declare a main module, so module readback verification was skipped",
        });
    };

    match readback.main_module.as_deref().map(str::trim) {
        Some(observed) if observed == expected_main_module => json!({
            "matched": true,
            "code": "workers.upload_main_module_matched",
            "main_module": expected_main_module,
        }),
        Some(observed) if !observed.is_empty() => json!({
            "matched": false,
            "code": "workers.upload_main_module_mismatch",
            "expected_main_module": expected_main_module,
            "observed_main_module": observed,
            "message": "Worker settings readback reported a different main_module than the upload request",
        }),
        _ => json!({
            "matched": false,
            "code": "workers.upload_main_module_absent",
            "expected_main_module": expected_main_module,
            "message": "Worker settings readback did not include main_module",
        }),
    }
}

fn is_pages_generated_worker_settings_error(err: &crate::cloudflare::AdapterError) -> bool {
    let message = err
        .cloudflare_api_error_message()
        .unwrap_or(&err.message)
        .to_ascii_lowercase();
    message.contains("no versions") && message.contains("versioned settings")
}

fn pages_generated_worker_settings_result(
    err: crate::cloudflare::AdapterError,
    account_id: &str,
    script_name: &str,
    patch_keys: &[String],
    before_binding: Option<Value>,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "patch_worker_settings",
        "account_id": account_id,
        "script_name": script_name,
        "patch_keys": patch_keys,
        "before_binding": before_binding,
        "error": {
            "code": "workers.pages_generated_worker_settings_immutable",
            "message": err.payload().message,
            "hint": "This looks like a Pages-generated Worker whose env/bindings are owned by the Pages deployment snapshot. Update the Pages project settings, then create a new Pages deployment with pages_deploy_directory instead of patching the generated Worker in place.",
            "retryable": false,
            "status": err.payload().status,
            "upstream": err.payload(),
        },
        "next_step": {
            "tool": "pages_deploy_directory",
            "reason": "Pages-generated Worker settings are resnapshotted by a new Pages deployment.",
        },
    }))
}

fn verify_worker_binding(
    bindings: Option<&[Value]>,
    expectation: &WorkerBindingExpectation,
) -> Value {
    let requested_name = expectation.name.trim();
    let requested_type = expectation
        .binding_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let requested_field = expectation.field.trim();

    if requested_name.is_empty() {
        return json!({
            "matched": false,
            "code": "workers.invalid_binding_name",
            "message": "binding expectation name must not be empty",
        });
    }
    if requested_field.is_empty() {
        return json!({
            "matched": false,
            "code": "workers.invalid_binding_field",
            "message": "binding expectation field must not be empty",
        });
    }

    let Some(bindings) = bindings else {
        return json!({
            "matched": false,
            "code": "workers.bindings_absent",
            "name": requested_name,
            "binding_type": requested_type,
            "field": requested_field,
            "message": "Worker settings did not include a bindings array",
        });
    };
    let candidates = bindings
        .iter()
        .filter(|binding| {
            binding
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name == requested_name)
        })
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return json!({
            "matched": false,
            "code": "workers.binding_missing",
            "name": requested_name,
            "binding_type": requested_type,
            "field": requested_field,
            "message": "Worker binding was not present in readback settings",
        });
    }

    let typed_candidates = candidates
        .iter()
        .copied()
        .filter(|binding| {
            requested_type.is_none_or(|expected_type| {
                binding
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|observed_type| observed_type == expected_type)
            })
        })
        .collect::<Vec<_>>();
    if typed_candidates.is_empty() {
        let observed_types = candidates
            .iter()
            .filter_map(|binding| binding.get("type").and_then(Value::as_str))
            .collect::<Vec<_>>();
        return json!({
            "matched": false,
            "code": "workers.binding_type_mismatch",
            "name": requested_name,
            "binding_type": requested_type,
            "observed_types": observed_types,
            "field": requested_field,
            "message": "Worker binding name exists but type did not match expectation",
        });
    }

    let binding = typed_candidates[0];
    let observed_value = binding.get(requested_field);
    let value_matched = expectation
        .value
        .as_ref()
        .is_none_or(|expected| observed_value.is_some_and(|observed| observed == expected));
    json!({
        "matched": value_matched,
        "code": if value_matched { "workers.binding_matched" } else { "workers.binding_value_mismatch" },
        "name": requested_name,
        "binding_type": requested_type.or_else(|| binding.get("type").and_then(Value::as_str)),
        "field": requested_field,
        "field_present": observed_value.is_some(),
        "expected_value": expectation.value,
        "observed_value": observed_value,
    })
}

fn validate_d1_read_only_sql(sql: &str) -> Result<(), CallToolResult> {
    classify_restricted_sql(sql).map_err(d1_sql_policy_result)
}

fn validate_analytics_engine_sql(sql: &str) -> Result<(), CallToolResult> {
    classify_restricted_sql(sql).map_err(analytics_engine_sql_policy_result)
}

fn workers_observability_timeframe(
    timeframe: Option<WorkersObservabilityTimeframe>,
    lookback_minutes: Option<u64>,
) -> Value {
    match timeframe {
        Some(timeframe) => json!({
            "from": timeframe.from,
            "to": timeframe.to,
        }),
        None => {
            let to = u64::try_from(now_unix_ms()).unwrap_or(u64::MAX);
            let lookback_ms = lookback_minutes.unwrap_or(60).clamp(1, 14 * 24 * 60) * 60 * 1000;
            json!({
                "from": to.saturating_sub(lookback_ms),
                "to": to,
            })
        }
    }
}

fn workers_observability_datasets(datasets: &[String]) -> Vec<Value> {
    let datasets = datasets
        .iter()
        .map(|dataset| dataset.trim())
        .filter(|dataset| !dataset.is_empty())
        .map(|dataset| Value::String(dataset.to_string()))
        .collect::<Vec<_>>();
    if datasets.is_empty() {
        vec![json!("workers")]
    } else {
        datasets
    }
}

fn workers_observability_filters(script_name: Option<&str>, filters: &[Value]) -> Vec<Value> {
    let mut all_filters = script_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|script_name| {
            vec![json!({
                "key": "$workers.scriptName",
                "operation": "eq",
                "type": "string",
                "value": script_name,
            })]
        })
        .unwrap_or_default();
    all_filters.extend(filters.iter().cloned());
    all_filters
}

fn workers_observability_query_body(
    script_name: Option<&str>,
    datasets: &[String],
    filters: &[Value],
    limit: u32,
    timeframe: Value,
    query_id: Option<&str>,
    dry: bool,
    view: Option<&str>,
    needle: Option<Value>,
) -> Value {
    let query_id = query_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("mcp-workers-observability-events");
    let mut parameters = Map::new();
    parameters.insert(
        "datasets".to_string(),
        Value::Array(workers_observability_datasets(datasets)),
    );
    parameters.insert(
        "filters".to_string(),
        Value::Array(workers_observability_filters(script_name, filters)),
    );
    parameters.insert("filterCombination".to_string(), json!("and"));
    parameters.insert("limit".to_string(), json!(limit.min(1000)));
    parameters.insert(
        "view".to_string(),
        json!(
            view.map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("events")
        ),
    );
    if let Some(needle) = needle {
        parameters.insert("needle".to_string(), needle);
    }

    json!({
        "queryId": query_id,
        "timeframe": timeframe,
        "dry": dry,
        "limit": limit.min(1000),
        "parameters": parameters,
    })
}

fn workers_observability_discovery_body(
    script_name: Option<&str>,
    datasets: &[String],
    filters: &[Value],
    limit: u32,
    timeframe: Value,
    needle: Option<Value>,
    key_needle: Option<Value>,
) -> Value {
    let mut body = Map::new();
    body.insert(
        "datasets".to_string(),
        Value::Array(workers_observability_datasets(datasets)),
    );
    body.insert(
        "filters".to_string(),
        Value::Array(workers_observability_filters(script_name, filters)),
    );
    body.insert("limit".to_string(), json!(limit));
    if let Some(from) = timeframe.get("from").cloned() {
        body.insert("from".to_string(), from);
    }
    if let Some(to) = timeframe.get("to").cloned() {
        body.insert("to".to_string(), to);
    }
    if let Some(needle) = needle {
        body.insert("needle".to_string(), needle);
    }
    if let Some(key_needle) = key_needle {
        body.insert("keyNeedle".to_string(), key_needle);
    }
    Value::Object(body)
}

fn workers_observability_values_body(
    key: &str,
    value_type: &str,
    script_name: Option<&str>,
    datasets: &[String],
    filters: &[Value],
    limit: u32,
    timeframe: Value,
    needle: Option<Value>,
) -> Value {
    let mut body = Map::new();
    body.insert("key".to_string(), json!(key));
    body.insert("type".to_string(), json!(value_type));
    body.insert("timeframe".to_string(), timeframe);
    body.insert(
        "datasets".to_string(),
        Value::Array(workers_observability_datasets(datasets)),
    );
    body.insert(
        "filters".to_string(),
        Value::Array(workers_observability_filters(script_name, filters)),
    );
    body.insert("limit".to_string(), json!(limit));
    if let Some(needle) = needle {
        body.insert("needle".to_string(), needle);
    }
    Value::Object(body)
}

fn missing_path_params(
    operation: &crate::api_catalog::ApiOperation,
    path_params: &BTreeMap<String, String>,
    default_account_id: Option<&str>,
    default_zone_id: Option<&str>,
) -> Vec<String> {
    path_parameter_names(operation)
        .iter()
        .filter(|name| {
            path_params
                .get(*name)
                .map(String::as_str)
                .or_else(|| match name.as_str() {
                    "account_id" => default_account_id,
                    "zone_id" => default_zone_id,
                    _ => None,
                })
                .map(str::trim)
                .is_none_or(str::is_empty)
        })
        .cloned()
        .collect()
}

fn missing_required_query_params(
    operation: &crate::api_catalog::ApiOperation,
    query: &BTreeMap<String, Value>,
) -> Vec<String> {
    operation
        .required_query_params
        .iter()
        .filter(|name| match query.get(*name) {
            Some(Value::Null) | None => true,
            Some(Value::String(value)) => value.trim().is_empty(),
            Some(_) => false,
        })
        .cloned()
        .collect()
}

fn binding_surface_status(errors: &[Value], surface: &str, count: usize, skipped: bool) -> Value {
    if skipped {
        return json!({
            "ok": true,
            "skipped": true,
            "count": 0,
        });
    }
    if let Some(error) = errors.iter().find(|error| {
        error
            .get("surface")
            .and_then(Value::as_str)
            .is_some_and(|value| value == surface)
    }) {
        return json!({
            "ok": false,
            "skipped": false,
            "count": count,
            "error": error.get("error").cloned().unwrap_or(Value::Null),
        });
    }
    json!({
        "ok": true,
        "skipped": false,
        "count": count,
    })
}

fn queue_delivery_paused(settings: Option<&Value>) -> Option<bool> {
    settings
        .and_then(|settings| settings.get("delivery_paused"))
        .and_then(Value::as_bool)
}

fn queue_oldest_message_age_ms(timestamp_ms: Option<f64>) -> Option<u64> {
    let timestamp_ms = timestamp_ms?;
    if timestamp_ms <= 0.0 {
        return None;
    }
    let now = now_unix_ms();
    let timestamp_ms = timestamp_ms as u128;
    if now <= timestamp_ms {
        return Some(0);
    }
    u64::try_from(now - timestamp_ms).ok()
}

fn queue_consumer_status(delivery_paused: Option<bool>, consumers: &[Value]) -> Value {
    let configured_count = consumers.len();
    let state = if delivery_paused == Some(true) {
        "delivery_paused"
    } else if configured_count == 0 {
        "no_consumers"
    } else {
        "configured"
    };
    json!({
        "state": state,
        "configured_count": configured_count,
        "delivery_paused": delivery_paused,
    })
}

async fn queue_dlq_readback(
    server: &CloudflareMcp,
    account_id: &str,
    consumers: &[Value],
) -> Value {
    let configured = consumers
        .iter()
        .filter_map(queue_consumer_dlq_name)
        .collect::<Vec<_>>();
    if configured.is_empty() {
        return json!({
            "checked": true,
            "configured": [],
            "resolved": [],
            "backlog_count": 0,
        });
    }

    let queues = match server.cloudflare.list_queues(account_id).await {
        Ok(page) => page.items,
        Err(err) => {
            return json!({
                "checked": true,
                "configured": configured,
                "resolved": [],
                "error": err.payload(),
            });
        }
    };
    let mut resolved = Vec::new();
    let mut total_backlog = 0.0f64;
    for name in &configured {
        let Some(queue) = queues.iter().find(|queue| {
            queue
                .queue_name
                .as_deref()
                .is_some_and(|queue_name| queue_name == name)
        }) else {
            resolved.push(json!({
                "queue_name": name,
                "resolved": false,
            }));
            continue;
        };
        let Some(queue_id) = queue.queue_id.as_deref() else {
            resolved.push(json!({
                "queue_name": name,
                "resolved": false,
                "reason": "missing_queue_id",
            }));
            continue;
        };
        match server
            .cloudflare
            .get_queue_metrics(account_id, queue_id)
            .await
        {
            Ok(metrics) => {
                total_backlog += metrics.backlog_count.unwrap_or(0.0);
                resolved.push(json!({
                    "queue_name": name,
                    "queue_id": queue_id,
                    "resolved": true,
                    "metrics": {
                        "backlog_bytes": metrics.backlog_bytes,
                        "backlog_count": metrics.backlog_count,
                        "oldest_message_timestamp_ms": metrics.oldest_message_timestamp_ms,
                        "oldest_message_age_ms": queue_oldest_message_age_ms(metrics.oldest_message_timestamp_ms),
                    },
                }));
            }
            Err(err) => resolved.push(json!({
                "queue_name": name,
                "queue_id": queue_id,
                "resolved": true,
                "error": err.payload(),
            })),
        }
    }

    json!({
        "checked": true,
        "configured": configured,
        "resolved": resolved,
        "backlog_count": total_backlog,
    })
}

fn queue_consumer_dlq_name(consumer: &Value) -> Option<String> {
    consumer
        .get("dead_letter_queue")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

const D1_WRITE_ALLOWED_KINDS: &[&str] = &["INSERT", "UPDATE", "DELETE", "REPLACE"];
const DEFAULT_D1_MIGRATIONS_TABLE: &str = "d1_migrations";
const MAX_D1_MIGRATION_BYTES: u64 = 5 * 1024 * 1024;
const MAX_D1_MIGRATION_COUNT: usize = 1_000;

#[derive(Debug, Clone)]
struct D1MigrationFile {
    name: String,
    path: PathBuf,
    size_bytes: u64,
    sql_sha256: String,
}

fn classify_d1_write_sql(sql: &str) -> Result<&'static str, CallToolResult> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(d1_write_policy_result(
            "EMPTY_SQL",
            "SQL must not be empty.",
        ));
    }
    if trimmed.trim_end_matches(';').contains(';') {
        return Err(d1_write_policy_result(
            "MULTI_STATEMENT",
            "Submit exactly one D1 write statement.",
        ));
    }
    let first = trimmed
        .split(|ch: char| ch.is_whitespace() || ch == '(')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    match first.as_str() {
        "INSERT" => Ok("INSERT"),
        "UPDATE" => Ok("UPDATE"),
        "DELETE" => Ok("DELETE"),
        "REPLACE" => Ok("REPLACE"),
        _ => Err(d1_write_policy_result(
            "UNSUPPORTED_STATEMENT",
            "D1 write SQL must start with INSERT, UPDATE, DELETE, or REPLACE.",
        )),
    }
}

fn d1_write_policy_result(code: &'static str, message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": "d1.write_policy_denied",
            "message": message,
            "hint": "Submit exactly one row-write D1 SQL statement, or use d1_query_read_only for reads.",
            "classifier_code": code,
        },
        "policy": {
            "d1_write_sql": true,
            "allowed_statement_kinds": D1_WRITE_ALLOWED_KINDS,
        },
    }))
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_bytes_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn prepare_r2_output_path(
    output_path: Option<&str>,
    create_parent_dirs: bool,
) -> Result<PathBuf, CallToolResult> {
    let output_path = output_path.map(str::trim).filter(|value| !value.is_empty());
    let Some(output_path) = output_path else {
        return Err(invalid_argument_result(
            "r2.output_path_required",
            "output_path is required when response_mode is file or auto switches to file",
            "Provide a local output_path for the downloaded object.",
        ));
    };
    let path = PathBuf::from(output_path);
    if path.exists() && path.is_dir() {
        return Err(invalid_argument_result(
            "r2.output_path_is_directory",
            "output_path points to a directory",
            "Provide a full file path, not a directory.",
        ));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if parent.exists() {
            if !parent.is_dir() {
                return Err(invalid_argument_result(
                    "r2.output_parent_not_directory",
                    "output_path parent exists but is not a directory",
                    "Choose an output_path below an existing directory.",
                ));
            }
        } else if create_parent_dirs {
            fs::create_dir_all(parent).map_err(|err| {
                CallToolResult::structured_error(json!({
                    "ok": false,
                    "operation": "r2_get_object",
                    "error": {
                        "code": "r2.output_parent_create_failed",
                        "message": format!("failed creating output_path parent directories: {err}"),
                        "hint": "Check permissions or create the parent directory manually.",
                    },
                }))
            })?;
        } else {
            return Err(invalid_argument_result(
                "r2.output_parent_missing",
                "output_path parent directory does not exist",
                "Create the parent directory first, or set create_parent_dirs=true.",
            ));
        }
    }
    Ok(path)
}

fn persist_r2_output_path(output_path: &str) -> Result<(), CallToolResult> {
    let path = r2_output_path_state_file().map_err(|err| {
        CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "r2_get_object",
            "error": {
                "code": "r2.output_path_state_unavailable",
                "message": format!("failed resolving R2 output path state file: {err}"),
                "hint": "Set CLOUDFLARE_MCP_R2_OUTPUT_PATH_STATE_FILE or HOME/XDG_STATE_HOME to a writable location.",
            },
        }))
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "r2_get_object",
                "error": {
                    "code": "r2.output_path_state_write_failed",
                    "message": format!("failed creating R2 output path state directory: {err}"),
                    "hint": "Check permissions for the MCP state directory.",
                },
            }))
        })?;
    }
    let payload = json!({ "output_path": output_path });
    fs::write(
        &path,
        serde_json::to_vec_pretty(&payload).expect("serialize output path state"),
    )
    .map_err(|err| {
        CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "r2_get_object",
            "error": {
                "code": "r2.output_path_state_write_failed",
                "message": format!("failed writing persisted R2 output path: {err}"),
                "hint": "Check permissions for the MCP state directory.",
            },
        }))
    })
}

fn load_persisted_r2_output_path() -> Result<Option<String>, CallToolResult> {
    let path = r2_output_path_state_file().map_err(|err| {
        CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "r2_get_object",
            "error": {
                "code": "r2.output_path_state_unavailable",
                "message": format!("failed resolving R2 output path state file: {err}"),
                "hint": "Set CLOUDFLARE_MCP_R2_OUTPUT_PATH_STATE_FILE or HOME/XDG_STATE_HOME to a writable location.",
            },
        }))
    })?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(CallToolResult::structured_error(json!({
                "ok": false,
                "operation": "r2_get_object",
                "error": {
                    "code": "r2.output_path_state_read_failed",
                    "message": format!("failed reading persisted R2 output path: {err}"),
                    "hint": "Check the state file permissions or remove the corrupt state file.",
                },
            })));
        }
    };
    let value = serde_json::from_str::<Value>(&text).map_err(|err| {
        CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "r2_get_object",
            "error": {
                "code": "r2.output_path_state_invalid",
                "message": format!("persisted R2 output path state is invalid JSON: {err}"),
                "hint": "Remove or rewrite the R2 output path state file.",
            },
        }))
    })?;
    Ok(value
        .get("output_path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string))
}

fn r2_output_path_state_file() -> std::io::Result<PathBuf> {
    if let Ok(path) = std::env::var("CLOUDFLARE_MCP_R2_OUTPUT_PATH_STATE_FILE")
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path.trim()));
    }
    if let Ok(path) = std::env::var("XDG_STATE_HOME")
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path.trim())
            .join("cloudflare-mcp")
            .join("r2-output-path.json"));
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return Ok(
            PathBuf::from(home.trim()).join(".local/state/cloudflare-mcp/r2-output-path.json")
        );
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "HOME and XDG_STATE_HOME are not set",
    ))
}

fn r2_content_type_is_binary(content_type: &str) -> bool {
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if content_type.is_empty() {
        return false;
    }
    if content_type.starts_with("text/") {
        return false;
    }
    if matches!(
        content_type.as_str(),
        "application/json"
            | "application/ld+json"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/javascript"
            | "application/x-javascript"
            | "application/sql"
            | "application/x-ndjson"
            | "application/csv"
            | "application/yaml"
            | "application/x-yaml"
            | "image/svg+xml"
    ) || content_type.ends_with("+json")
        || content_type.ends_with("+xml")
    {
        return false;
    }
    true
}

fn write_r2_inline_body_to_file_result(
    account_id: &str,
    object: &crate::cloudflare::client::R2Object,
    body: &[u8],
    output_path: &Path,
    max_bytes: usize,
    truncated: bool,
    auto_switched_to_file: bool,
    output_path_source: Option<&str>,
    persisted_output_path: bool,
) -> CallToolResult {
    if let Err(err) = fs::write(output_path, body) {
        return CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "r2_get_object",
            "error": {
                "code": "r2.output_write_failed",
                "message": format!("failed writing output_path: {err}"),
                "hint": "Check output_path permissions and available disk space.",
            },
        }));
    }
    let mut hasher = Sha256::new();
    hasher.update(body);
    CallToolResult::structured(json!({
        "ok": true,
        "operation": "r2_get_object",
        "account_id": account_id,
        "bucket_name": object.bucket_name,
        "object_key": object.object_key,
        "status": object.status,
        "encoding": "file",
        "output_path": output_path.display().to_string(),
        "bytes_written": body.len(),
        "sha256": format!("{:x}", hasher.finalize()),
        "content_type": object.content_type,
        "content_length": object.content_length,
        "etag": object.etag,
        "last_modified": object.last_modified,
        "range": object.range,
        "truncated": truncated,
        "max_bytes": max_bytes,
        "auto_switched_to_file": auto_switched_to_file,
        "output_path_source": output_path_source,
        "persisted_output_path": persisted_output_path,
    }))
}

fn r2_download_too_large_result(
    metadata: &crate::cloudflare::client::R2ObjectMetadata,
    safe_limit_bytes: u64,
    code: &'static str,
    message: &'static str,
    hint: &'static str,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "r2_get_object",
        "error": {
            "code": code,
            "message": message,
            "hint": hint,
        },
        "bucket_name": metadata.bucket_name,
        "object_key": metadata.object_key,
        "content_type": metadata.content_type,
        "content_length": metadata.content_length,
        "etag": metadata.etag,
        "last_modified": metadata.last_modified,
        "range": metadata.range,
        "safe_limit_bytes": safe_limit_bytes,
    }))
}

fn normalize_d1_migrations_table(value: Option<&str>) -> Result<String, CallToolResult> {
    let table = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_D1_MIGRATIONS_TABLE);
    let mut chars = table.chars();
    let valid = matches!(chars.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && table.len() <= 64;
    if valid {
        Ok(table.to_string())
    } else {
        Err(invalid_argument_result(
            "d1.invalid_migrations_table",
            "migrations_table must be an ASCII SQL identifier with at most 64 characters",
            "Use a simple table name such as d1_migrations.",
        ))
    }
}

fn inspect_d1_migration_files(directory: &str) -> Result<Vec<D1MigrationFile>, CallToolResult> {
    let directory = directory.trim();
    if directory.is_empty() {
        return Err(invalid_argument_result(
            "d1.invalid_migrations_directory",
            "migrations_directory must not be empty",
            "Provide a local directory containing .sql migration files.",
        ));
    }
    let root = fs::canonicalize(directory).map_err(|err| {
        invalid_argument_result(
            "d1.invalid_migrations_directory",
            format!("failed resolving migrations_directory: {err}"),
            "Provide an existing readable directory containing .sql files.",
        )
    })?;
    let metadata = fs::metadata(&root).map_err(|err| {
        invalid_argument_result(
            "d1.invalid_migrations_directory",
            format!("failed statting migrations_directory: {err}"),
            "Check the migrations directory path and permissions.",
        )
    })?;
    if !metadata.is_dir() {
        return Err(invalid_argument_result(
            "d1.invalid_migrations_directory",
            "migrations_directory must point to a local directory",
            "Provide a directory, not an individual SQL file.",
        ));
    }
    let entries = fs::read_dir(&root).map_err(|err| {
        invalid_argument_result(
            "d1.migrations_directory_read_failed",
            format!("failed reading migrations_directory: {err}"),
            "Check directory permissions and retry.",
        )
    })?;
    let mut migrations = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| {
            invalid_argument_result(
                "d1.migrations_directory_read_failed",
                format!("failed reading migration directory entry: {err}"),
                "Check directory permissions and retry.",
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|err| {
            invalid_argument_result(
                "d1.migration_metadata_failed",
                format!("failed reading migration file metadata: {err}"),
                "Check migration file permissions and retry.",
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("sql") {
            continue;
        }
        if metadata.len() > MAX_D1_MIGRATION_BYTES {
            return Err(invalid_argument_result(
                "d1.migration_too_large",
                format!(
                    "migration file {} is {} bytes, above the MCP limit",
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("<invalid-name>"),
                    metadata.len()
                ),
                "Split very large D1 migrations into smaller .sql files.",
            ));
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                invalid_argument_result(
                    "d1.invalid_migration_name",
                    "migration filename must be valid UTF-8",
                    "Rename the migration file using a UTF-8 filename ending in .sql.",
                )
            })?
            .to_string();
        let bytes = fs::read(&path).map_err(|err| {
            invalid_argument_result(
                "d1.migration_read_failed",
                format!("failed reading migration file {name}: {err}"),
                "Check migration file permissions and retry.",
            )
        })?;
        migrations.push(D1MigrationFile {
            name,
            path,
            size_bytes: metadata.len(),
            sql_sha256: sha256_bytes_hex(&bytes),
        });
    }
    migrations.sort_by(|left, right| left.name.cmp(&right.name));
    if migrations.len() > MAX_D1_MIGRATION_COUNT {
        return Err(invalid_argument_result(
            "d1.too_many_migrations",
            format!(
                "migrations_directory contains {} .sql files, above the MCP limit {MAX_D1_MIGRATION_COUNT}",
                migrations.len()
            ),
            "Apply migrations in smaller batches or reduce stale files in the directory.",
        ));
    }
    Ok(migrations)
}

fn read_d1_migration_sql(migration: &D1MigrationFile) -> Result<String, CallToolResult> {
    let bytes = fs::read(&migration.path).map_err(|err| {
        invalid_argument_result(
            "d1.migration_read_failed",
            format!("failed reading migration file {}: {err}", migration.name),
            "Check migration file permissions and retry.",
        )
    })?;
    if bytes.starts_with(b"SQLite format 3") {
        return Err(invalid_argument_result(
            "d1.migration_binary_sqlite",
            format!(
                "migration file {} appears to be a binary SQLite database",
                migration.name
            ),
            "Provide SQL text migration files, not a SQLite database file.",
        ));
    }
    String::from_utf8(bytes).map_err(|err| {
        invalid_argument_result(
            "d1.migration_invalid_utf8",
            format!(
                "migration file {} is not valid UTF-8: {err}",
                migration.name
            ),
            "Save the migration as UTF-8 SQL text.",
        )
    })
}

fn d1_migrations_table_init_sql(table: &str) -> String {
    let table = quote_sql_identifier(table);
    format!(
        "CREATE TABLE IF NOT EXISTS {table}(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);"
    )
}

fn d1_applied_migrations_sql(table: &str) -> String {
    format!("SELECT * FROM {} ORDER BY id", quote_sql_identifier(table))
}

fn d1_migration_apply_sql(sql: &str, table: &str, migration_name: &str) -> String {
    let table = quote_sql_identifier(table);
    let migration_name = quote_sql_string(migration_name);
    format!(
        "{sql}

INSERT INTO {table} (name) VALUES ({migration_name});"
    )
}

fn quote_sql_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn collect_d1_migration_names(value: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_d1_migration_names_in_value(value, &mut names);
    names
}

fn collect_d1_migration_names_in_value(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_d1_migration_names_in_value(item, names);
            }
        }
        Value::Object(object) => {
            if let Some(Value::Array(rows)) = object.get("results") {
                for row in rows {
                    if let Some(name) = row.get("name").and_then(Value::as_str) {
                        names.insert(name.to_string());
                    }
                }
            }
            for (key, nested) in object {
                if key.as_str() != "results" {
                    collect_d1_migration_names_in_value(nested, names);
                }
            }
        }
        _ => {}
    }
}

fn d1_migration_summary(migration: &D1MigrationFile) -> Value {
    json!({
        "name": &migration.name,
        "size_bytes": migration.size_bytes,
        "sql_sha256": &migration.sql_sha256,
    })
}

fn d1_migration_summaries(migrations: &[D1MigrationFile]) -> Vec<Value> {
    migrations.iter().map(d1_migration_summary).collect()
}

fn d1_skipped_migrations(
    migrations: &[D1MigrationFile],
    applied_names: &BTreeSet<String>,
) -> Vec<Value> {
    migrations
        .iter()
        .filter(|migration| applied_names.contains(&migration.name))
        .map(d1_migration_summary)
        .collect()
}

fn d1_pending_migrations(
    migrations: &[D1MigrationFile],
    applied_names: &BTreeSet<String>,
) -> Vec<D1MigrationFile> {
    let mut pending = migrations
        .iter()
        .filter(|migration| !applied_names.contains(&migration.name))
        .cloned()
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| {
        match (
            d1_migration_numeric_prefix(&left.name),
            d1_migration_numeric_prefix(&right.name),
        ) {
            (Some(left), Some(right)) => left.cmp(&right),
            _ => std::cmp::Ordering::Equal,
        }
    });
    pending
}

fn d1_migration_numeric_prefix(name: &str) -> Option<u64> {
    name.split('_').next()?.parse::<u64>().ok()
}

fn d1_call_tool_error_value(result: CallToolResult) -> Value {
    result
        .structured_content
        .and_then(|value| value.get("error").cloned())
        .unwrap_or_else(|| {
            json!({
                "code": "d1.migration_error",
                "message": "migration operation failed",
                "hint": "Inspect the MCP response for details.",
            })
        })
}

fn d1_migration_unknown_ledger_result(
    account_id: &str,
    database_id: &str,
    migrations_table: &str,
    migrations: &[D1MigrationFile],
    error: crate::cloudflare::AdapterErrorPayload,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "operation": "d1_apply_migrations",
        "account_id": account_id,
        "database_id": database_id,
        "migrations_table": migrations_table,
        "migration_count": migrations.len(),
        "candidate_migrations": d1_migration_summaries(migrations),
        "ledger_checked": true,
        "unknown_ledger": true,
        "error": {
            "code": "d1.migration_ledger_unreadable",
            "message": "could not read the D1 migration ledger; refusing to execute migration SQL",
            "hint": "Verify the Wrangler migration table name and D1 read permissions before applying migrations.",
            "cause": error,
        },
    }))
}

fn url_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn pages_deployment_action(
    server: &CloudflareMcp,
    args: PagesDeploymentActionArgs,
    action: &'static str,
) -> Result<CallToolResult, crate::McpError> {
    let account_id = resolve_account_id(server, args.account_id.as_deref())?;
    if args.dry_run {
        return Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": format!("pages_{action}_deployment"),
            "dry_run": true,
            "account_id": account_id,
            "project_name": args.project_name,
            "deployment_id": args.deployment_id,
        })));
    }
    let result = match action {
        "retry" => {
            server
                .cloudflare
                .retry_pages_deployment(account_id, &args.project_name, &args.deployment_id)
                .await
        }
        "rollback" => {
            server
                .cloudflare
                .rollback_pages_deployment(account_id, &args.project_name, &args.deployment_id)
                .await
        }
        _ => unreachable!("validated pages deployment action"),
    };
    match result {
        Ok(deployment) => Ok(CallToolResult::structured(json!({
            "ok": true,
            "operation": format!("pages_{action}_deployment"),
            "account_id": account_id,
            "deployment": deployment,
        }))),
        Err(err) if action == "retry" && is_pages_direct_upload_retry_error(&err) => {
            Ok(pages_direct_upload_retry_result(
                err,
                account_id,
                &args.project_name,
                &args.deployment_id,
            ))
        }
        Err(err) if action == "rollback" && is_pages_already_production_rollback_error(&err) => {
            Ok(pages_rollback_already_production_result(
                server,
                err,
                account_id,
                &args.project_name,
                &args.deployment_id,
            )
            .await)
        }
        Err(err) => Ok(adapter_error_result(err)),
    }
}

fn d1_sql_policy_result(err: RestrictedSqlError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": "d1.sql_policy_denied",
            "message": err.message,
            "hint": "Submit exactly one read-only D1 SQL statement, or use d1_inspect_schema for schema discovery.",
            "classifier_code": err.code.as_str(),
        },
        "policy": {
            "restricted_sql": true,
            "contract": "mcp-toolkit-policy-core/restricted-sql",
        },
    }))
}

fn analytics_engine_sql_policy_result(err: RestrictedSqlError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": "analytics_engine.sql_policy_denied",
            "message": err.message,
            "hint": "Submit exactly one read-only Workers Analytics Engine SQL statement.",
            "classifier_code": err.code.as_str(),
        },
        "policy": {
            "restricted_sql": true,
            "contract": "mcp-toolkit-policy-core/restricted-sql",
        },
    }))
}

fn d1_sqlite_auth_result(err: crate::cloudflare::AdapterError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": {
            "code": "d1.sqlite_auth",
            "message": err.payload().message,
            "hint": "Cloudflare D1 denied this read at the SQLite authorization layer. Use d1_inspect_schema for schema discovery, or query an application table allowed by D1.",
            "retryable": false,
            "status": err.payload().status,
        },
    }))
}

fn is_d1_no_such_column_error(err: &crate::cloudflare::AdapterError) -> bool {
    d1_error_message_matches(err, "no such column")
}

fn is_d1_no_such_table_error(err: &crate::cloudflare::AdapterError) -> bool {
    d1_error_message_matches(err, "no such table")
}

fn d1_error_message_matches(err: &crate::cloudflare::AdapterError, needle: &str) -> bool {
    fn message_matches(message: &str, needle: &str) -> bool {
        message.to_ascii_lowercase().contains(needle)
    }

    message_matches(&err.message, needle)
        || err
            .cloudflare_api_error_message()
            .is_some_and(|message| message_matches(message, needle))
}

fn d1_no_such_column_result(
    err: crate::cloudflare::AdapterError,
    database_id: &str,
) -> CallToolResult {
    let payload = err.payload();
    CallToolResult::structured_error(json!({
        "ok": false,
        "database_id": database_id,
        "error": {
            "code": "d1.no_such_column",
            "message": payload.message,
            "hint": "Validate the specific SQL with d1_validate_query, or inspect the specific target table with d1_inspect_schema include_tables/include_table_pattern. Avoid a broad full-database schema sweep for a no-such-column error.",
            "retryable": false,
            "status": payload.status,
        },
        "recommended_next_steps": [
            {
                "tool": "d1_validate_query",
                "why": "Checks the exact SQL against application tables and columns without executing the user query."
            },
            {
                "tool": "d1_inspect_schema",
                "why": "Use include_tables or include_table_pattern to inspect only the suspected table or view."
            }
        ],
    }))
}

fn d1_no_such_table_result(
    err: crate::cloudflare::AdapterError,
    database_id: &str,
) -> CallToolResult {
    let payload = err.payload();
    CallToolResult::structured_error(json!({
        "ok": false,
        "database_id": database_id,
        "error": {
            "code": "d1.no_such_table",
            "message": payload.message,
            "hint": "Validate the specific SQL with d1_validate_query, or inspect the database with d1_inspect_schema include_tables/include_table_pattern for the expected application table or view.",
            "retryable": false,
            "status": payload.status,
        },
        "recommended_next_steps": [
            {
                "tool": "d1_validate_query",
                "why": "Checks the exact SQL against application tables and columns without executing the user query."
            },
            {
                "tool": "d1_inspect_schema",
                "why": "Confirm the expected table or view exists before retrying the query."
            }
        ],
    }))
}

fn limit_d1_result_rows(mut result: Value, max_rows: usize) -> (Value, bool) {
    let truncated = truncate_d1_results_in_value(&mut result, max_rows);
    (result, truncated)
}

fn limit_analytics_engine_result_rows(mut result: Value, max_rows: usize) -> (Value, bool) {
    let truncated = truncate_analytics_engine_rows(&mut result, max_rows);
    (result, truncated)
}

fn truncate_analytics_engine_rows(value: &mut Value, max_rows: usize) -> bool {
    match value {
        Value::Array(items) if items.len() > max_rows => {
            let original = items.len();
            items.truncate(max_rows);
            items.push(json!({
                "truncated": true,
                "original_result_count": original,
            }));
            true
        }
        Value::Object(object) => object.values_mut().fold(false, |truncated, value| {
            truncate_analytics_engine_rows(value, max_rows) || truncated
        }),
        Value::Array(items) => items.iter_mut().fold(false, |truncated, item| {
            truncate_analytics_engine_rows(item, max_rows) || truncated
        }),
        _ => false,
    }
}

fn truncate_d1_results_in_value(value: &mut Value, max_rows: usize) -> bool {
    match value {
        Value::Array(items) => items.iter_mut().fold(false, |truncated, item| {
            truncate_d1_results_in_value(item, max_rows) || truncated
        }),
        Value::Object(object) => {
            let original_len = object
                .get("results")
                .and_then(Value::as_array)
                .map(Vec::len);
            let mut truncated_here = false;
            if let Some(Value::Array(rows)) = object.get_mut("results")
                && rows.len() > max_rows
            {
                rows.truncate(max_rows);
                truncated_here = true;
            }
            if truncated_here {
                object.insert("results_truncated".to_string(), json!(true));
                if let Some(original_len) = original_len {
                    object.insert("original_result_count".to_string(), json!(original_len));
                }
            }

            let truncated_nested = object
                .iter_mut()
                .filter(|(key, _)| key.as_str() != "results")
                .fold(false, |truncated, (_, nested)| {
                    truncate_d1_results_in_value(nested, max_rows) || truncated
                });
            truncated_here || truncated_nested
        }
        _ => false,
    }
}

fn portal_agent_request_plan(url: &str, method: &str, url_allowed: bool) -> MutationPlan {
    let url = redacted_url_for_output(url);
    MutationPlan::new("portal_agent_request")
        .step(
            "validate_url_allowlist",
            false,
            json!({
                "url": url,
                "allowed": url_allowed,
            }),
        )
        .step(
            "send_portal_request",
            true,
            json!({
                "url": url,
                "method": method.trim().to_ascii_uppercase(),
            }),
        )
}

fn portal_audit_target(url: &str, method: &str, parsed_url: Option<&Url>) -> serde_json::Value {
    json!({
        "method": method.trim().to_ascii_uppercase(),
        "url": parsed_url.map(safe_url_label).unwrap_or_else(|| redacted_url_for_output(url)),
        "host": parsed_url.and_then(Url::host_str),
        "path": parsed_url.map(Url::path),
    })
}

fn redacted_url_for_output(url: &str) -> String {
    Url::parse(url)
        .map(|parsed| safe_url_label(&parsed))
        .unwrap_or_else(|_| "<invalid-url>".to_string())
}

fn safe_url_label(url: &Url) -> String {
    let mut safe = url.clone();
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn classify_json_body(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

struct NormalizedJsonBody {
    value: Option<Value>,
    normalized: bool,
}

fn normalize_json_string_body(body: Option<Value>) -> NormalizedJsonBody {
    let Some(Value::String(raw)) = body.as_ref() else {
        return NormalizedJsonBody {
            value: body,
            normalized: false,
        };
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return NormalizedJsonBody {
            value: body,
            normalized: false,
        };
    }
    match serde_json::from_str::<Value>(trimmed) {
        Ok(parsed) => NormalizedJsonBody {
            value: Some(parsed),
            normalized: true,
        },
        Err(_) => NormalizedJsonBody {
            value: body,
            normalized: false,
        },
    }
}

fn portal_error_result(err: PortalAgentError) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": err.payload(),
    }))
}

fn portal_auth_diagnostics(
    agent_token_requested: bool,
    access_service_token_requested: bool,
    has_configured_agent_token: bool,
    has_configured_access_service_token: bool,
) -> Value {
    json!({
        "agent_token_requested": agent_token_requested,
        "access_service_token_requested": access_service_token_requested,
        "has_configured_agent_token": has_configured_agent_token,
        "has_configured_access_service_token": has_configured_access_service_token,
        "diagnostic": "These booleans reflect the running MCP process configuration only; secret values are never returned.",
    })
}

fn portal_http_error_auth(
    agent_token_attached: bool,
    access_service_token_attached: bool,
    has_configured_agent_token: bool,
    has_configured_access_service_token: bool,
) -> Value {
    let mut auth = portal_auth_diagnostics(
        agent_token_attached,
        access_service_token_attached,
        has_configured_agent_token,
        has_configured_access_service_token,
    );
    if let Some(object) = auth.as_object_mut() {
        object.insert(
            "agent_token_attached".to_string(),
            json!(agent_token_attached),
        );
        object.insert(
            "access_service_token_attached".to_string(),
            json!(access_service_token_attached),
        );
    }
    auth
}

fn portal_http_response_result(
    response: crate::portal::PortalAgentResponse,
    body_kind: Option<&'static str>,
    agent_token_attached: bool,
    access_service_token_attached: bool,
    has_configured_agent_token: bool,
    has_configured_access_service_token: bool,
) -> CallToolResult {
    let auth = portal_http_error_auth(
        agent_token_attached,
        access_service_token_attached,
        has_configured_agent_token,
        has_configured_access_service_token,
    );
    let payload = json!({
        "ok": response.success,
        "operation": "portal_agent_request",
        "status": response.status,
        "body_kind": body_kind,
        "auth": auth,
        "response": response.response,
    });
    if response.success {
        CallToolResult::structured(payload)
    } else {
        CallToolResult::structured_error(json!({
            "ok": false,
            "operation": "portal_agent_request",
            "status": response.status,
            "error": {
                "code": "portal.http_error",
                "message": "portal endpoint returned a non-success HTTP status",
                "hint": "Inspect sanitized response and portal logs; no secret values are returned.",
            },
            "body_kind": body_kind,
            "response": payload["response"].clone(),
            "auth": payload["auth"].clone(),
        }))
    }
}

fn portal_error_result_with_auth(
    err: PortalAgentError,
    agent_token_requested: bool,
    access_service_token_requested: bool,
    has_configured_agent_token: bool,
    has_configured_access_service_token: bool,
) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "ok": false,
        "error": err.payload(),
        "auth": {
            "agent_token_requested": agent_token_requested,
            "access_service_token_requested": access_service_token_requested,
            "has_configured_agent_token": has_configured_agent_token,
            "has_configured_access_service_token": has_configured_access_service_token,
            "diagnostic": "These booleans reflect the running MCP process configuration only; secret values are never returned.",
        },
    }))
}

fn finalize_mutation_result(
    mut result: CallToolResult,
    plan: &MutationPlan,
    audit: MutationAuditSession,
    dry_run: bool,
) -> CallToolResult {
    let inferred_error = result
        .structured_content
        .as_ref()
        .and_then(|payload| payload.get("ok"))
        .and_then(serde_json::Value::as_bool)
        .map(|ok| !ok)
        .unwrap_or(false);
    let is_error = result.is_error.unwrap_or(inferred_error);

    let mut payload = result
        .structured_content
        .take()
        .unwrap_or_else(|| json!({ "ok": !is_error }));
    if !payload.is_object() {
        payload = json!({
            "ok": !is_error,
            "value": payload,
        });
    }

    let error_code =
        extract_error_code(&payload).or_else(|| is_error.then_some("unknown_error".to_string()));
    let outcome = if is_error {
        "error"
    } else if dry_run {
        "planned"
    } else {
        "success"
    };
    let audit_record = audit.finish(outcome, error_code.as_deref());
    emit_mutation_audit_log(&audit_record);

    if let Some(object) = payload.as_object_mut() {
        object
            .entry("operation".to_string())
            .or_insert_with(|| json!(plan.operation));
        object.insert("dry_run".to_string(), json!(dry_run));
        object.insert("plan".to_string(), json!(plan));
        object.insert("audit".to_string(), json!(audit_record));
    }

    result.is_error = Some(is_error);
    result.structured_content = Some(payload);
    result
}

fn extract_error_code(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            payload
                .get("policy_gate")
                .and_then(|gate| gate.get("decision"))
                .and_then(|decision| decision.get("code"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, Request, StatusCode};
    use axum::routing::{any, get, post};
    use axum::{Json, Router};
    use mcp_toolkit_auth::AuthContext;
    use mcp_toolkit_core::notifications::ToolListTracker;
    use mcp_toolkit_http::session::{BoundedSessionManager, SessionLifecycleConfig};
    use mcp_toolkit_testing::assert_tool_schema_snapshot;
    use rmcp::handler::server::tool::Extension;
    use rmcp::handler::server::wrapper::Parameters;
    use rmcp::transport::streamable_http_server::session::local::{
        LocalSessionManager, SessionConfig,
    };
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::{
        AccountApiTokenPermissionPlanArgs, AccountApiTokensArgs, AccountBillingUsageArgs,
        AnalyticsEngineListDatasetsArgs, AnalyticsEngineQueryArgs,
        AnalyticsEngineValidateQueryArgs, ApiFindOperationsArgs, ApiMutateArgs, ApiPrepareCallArgs,
        ApiReadArgs, ApplyAccessAllowlistArgs, BindingsDiscoverArgs, CapabilitiesCheckArgs,
        CloudflareMcp, ConnectorControlArgs, D1ApplyMigrationsArgs, D1InspectSchemaArgs,
        D1ListDatabasesArgs, D1QueryArgs, D1ValidateQueryArgs, EmergencyUnpublishArgs,
        EnsureTunnelArgs, FindToolsArgs, GenerateTunnelIngressArgs, GraphqlAnalyticsQueryArgs,
        LockFirstPublishArgs, PagesDeploymentActionArgs, PagesUpdateProjectArgs,
        PatchWorkerSettingsArgs, PortalAgentRequestArgs, QueueHealthArgs, UpsertAccessAppArgs,
        UpsertDnsCnameArgs, VerifyHttpGateArgs, WafEventFilterInput, WafSecurityEventsSummaryArgs,
        WafTimeWindow, WorkersObservabilityListKeysArgs, WorkersObservabilityListValuesArgs,
        WorkersObservabilityQueryEventsArgs, WorkersObservabilityTimeframe,
        build_waf_security_events_query, normalize_waf_group_by, normalize_waf_phases,
        query_mentions_waf, waf_security_events_filter,
    };
    use crate::cloudflare::CloudflareClient;
    use crate::config::PortalAgentConfig;
    use crate::config::{ApiTokenSource, CloudflareApiConfig, ElicitationConfig, ResumeMode};
    use crate::portal::PortalAgentClient;

    fn fixture_material(label: &str) -> String {
        let mut value = String::from("fixture-");
        value.push_str(label);
        value.push_str("-value");
        value
    }

    fn test_server(base_url: String) -> CloudflareMcp {
        let client = Arc::new(
            CloudflareClient::new(CloudflareApiConfig {
                api_base_url: base_url,
                api_token: Some(fixture_material("api")),
                api_token_source: ApiTokenSource::Config,
                api_token_header: "x-cloudflare-api-token".to_string(),
                r2_access_key_id: Some(fixture_material("r2-id")),
                r2_secret_access_key: Some(fixture_material("r2-material")),
                r2_endpoint: None,
                default_account_id: Some("acct-1".to_string()),
                default_zone_id: Some("zone-1".to_string()),
                request_timeout: Duration::from_secs(2),
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
            true,
            {
                let mut session_config = SessionConfig::default();
                session_config.channel_capacity = 16;
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
                request_timeout: Duration::from_secs(2),
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
            false,
            true,
            portal_agent,
            ElicitationConfig {
                enabled: false,
                required_tools: Vec::new(),
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
            Arc::new(ToolListTracker::default()),
            session_manager,
            ResumeMode::Historyless,
        )
    }

    fn d1_migration_test_dir(name: &str) -> std::path::PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis();
        let dir = std::env::temp_dir().join(format!(
            "cloudflare-mcp-{name}-{}-{millis}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create migration test dir");
        dir
    }

    async fn spawn_router(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{addr}")
    }

    fn test_tool_parts() -> axum::http::request::Parts {
        let request = Request::builder()
            .uri("http://localhost/mcp")
            .header("x-request-id", "req-test-1")
            .header("x-correlation-id", "corr-test-1")
            .body(())
            .expect("request");
        let (mut parts, _) = request.into_parts();
        parts.extensions.insert(AuthContext {
            actor: "agent-test".to_string(),
            scopes: Vec::new(),
            roles: Vec::new(),
            claims: json!({}),
            azp: None,
            subject: None,
            token_ref: "token-ref".to_string(),
            raw_token: "raw-token".to_string(),
        });
        parts
    }

    #[test]
    fn tool_schema_snapshot_contract_is_stable() {
        let tools = CloudflareMcp::tool_router_cloudflare().list_all();
        let snapshot_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("spec/tool_schema_snapshot.v1.json");
        assert_tool_schema_snapshot(snapshot_path, &tools);
    }

    #[tokio::test]
    async fn capabilities_check_reports_mcp_boundary_and_zone_name_drift() {
        async fn zone_identity() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "zone-1",
                    "name": "example.com",
                    "account": {
                        "id": "acct-1",
                        "name": "Example Account"
                    }
                }
            }))
        }

        async fn ok_envelope() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {}
            }))
        }

        let router = Router::new()
            .route("/zones/zone-1", get(zone_identity))
            .fallback(any(ok_envelope));
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_capabilities_check(Parameters(CapabilitiesCheckArgs {
                account_id: None,
                zone_id: None,
                expected_account_id: Some("acct-1".to_string()),
                expected_zone_id: Some("zone-1".to_string()),
                expected_zone_name: Some("sednalabs.io".to_string()),
                require_explicit_zone_id: true,
            }))
            .await
            .expect("capabilities check");

        let payload = result.structured_content.expect("structured payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(
            payload["preflight"]["mcp"]["tool_call_reached_handler"],
            json!(true)
        );
        assert_eq!(
            payload["preflight"]["target"]["zone_id_source"],
            json!("server_default")
        );
        assert_eq!(
            payload["preflight"]["target"]["zone_identity"]["name"],
            json!("example.com")
        );
        assert_eq!(payload["preflight"]["cloudflare_api"]["ok"], json!(true));

        let findings = payload["preflight"]["findings"]
            .as_array()
            .expect("findings");
        assert!(
            findings
                .iter()
                .any(|finding| { finding["code"] == json!("target.zone_id_from_default") })
        );
        assert!(
            findings
                .iter()
                .any(|finding| { finding["code"] == json!("target.zone_name_mismatch") })
        );
    }

    #[test]
    fn worker_binding_verification_matches_named_field() {
        let bindings = vec![json!({
            "type": "plain_text",
            "name": "DESTINATION",
            "text": "https://example.com",
        })];
        let result = super::verify_worker_binding(
            Some(&bindings),
            &super::WorkerBindingExpectation {
                name: "DESTINATION".to_string(),
                binding_type: Some("plain_text".to_string()),
                field: "text".to_string(),
                value: Some(json!("https://example.com")),
            },
        );

        assert_eq!(result["matched"], json!(true));
        assert_eq!(result["code"], json!("workers.binding_matched"));
    }

    #[test]
    fn worker_upload_readback_verification_detects_main_module_mismatch() {
        let readback = serde_json::from_value(json!({
            "main_module": "unexpected.js",
            "bindings": []
        }))
        .expect("worker settings");
        let result =
            super::verify_worker_upload_readback(&json!({"main_module": "worker.js"}), &readback);

        assert_eq!(result["matched"], json!(false));
        assert_eq!(result["code"], json!("workers.upload_main_module_mismatch"));
        assert_eq!(result["expected_main_module"], json!("worker.js"));
        assert_eq!(result["observed_main_module"], json!("unexpected.js"));
    }

    #[test]
    fn waf_phase_aliases_default_to_operator_phases() {
        assert_eq!(
            normalize_waf_phases(&[]).expect("default phases"),
            vec![
                "http_request_firewall_custom",
                "http_request_firewall_managed",
                "http_ratelimit"
            ]
        );
        assert_eq!(
            normalize_waf_phases(&[
                "custom".to_string(),
                "managed".to_string(),
                "rate-limit".to_string(),
                "custom".to_string(),
            ])
            .expect("phase aliases"),
            vec![
                "http_request_firewall_custom",
                "http_request_firewall_managed",
                "http_ratelimit"
            ]
        );
        assert!(normalize_waf_phases(&["cache".to_string()]).is_err());
    }

    #[test]
    fn waf_group_by_normalizes_dashboard_language() {
        assert_eq!(
            normalize_waf_group_by(&["hostname".to_string(), "client-ip".to_string()])
                .expect("group aliases"),
            vec!["host", "ip"]
        );
        assert!(normalize_waf_group_by(&["colo".to_string()]).is_err());
    }

    #[test]
    fn waf_security_events_query_uses_firewall_events_dataset() {
        let group_by = normalize_waf_group_by(&[
            "action".to_string(),
            "source".to_string(),
            "rule".to_string(),
        ])
        .expect("group_by");
        let query = build_waf_security_events_query(&group_by, 20, 5);
        assert!(query.contains("firewallEventsAdaptiveGroups"));
        assert!(query.contains("firewallEventsAdaptive"));
        assert!(query.contains("ruleId"));
        let filter = waf_security_events_filter(
            &WafTimeWindow {
                start: "2026-06-04T00:00:00Z".to_string(),
                end: "2026-06-04T01:00:00Z".to_string(),
                window_hours: 1,
            },
            WafEventFilterInput {
                action: Some("block"),
                source: Some("waf"),
                host: Some("example.com"),
                path: Some("/admin"),
                client_ip: Some("203.0.113.10"),
                rule_id: Some("rule-1"),
            },
        );
        assert_eq!(filter["datetime_geq"], json!("2026-06-04T00:00:00Z"));
        assert_eq!(filter["action"], json!("block"));
        assert_eq!(filter["clientRequestHTTPHost"], json!("example.com"));
        assert_eq!(filter["ruleId"], json!("rule-1"));
    }

    #[test]
    fn waf_discovery_phrase_is_boosted() {
        assert!(query_mentions_waf(Some(
            "what WAF rule blocked this request security events analytics"
        )));
        assert!(query_mentions_waf(Some(
            "firewallEventsAdaptive top blocked request"
        )));
        assert!(!query_mentions_waf(Some("d1 rows written")));
    }

    #[tokio::test]
    async fn pages_update_project_reports_deployment_snapshot_semantics() {
        async fn update_project() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "project-1",
                    "name": "site",
                    "production_branch": "main"
                }
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/pages/projects/site",
            axum::routing::patch(update_project),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_pages_update_project(Parameters(PagesUpdateProjectArgs {
                account_id: None,
                project_name: "site".to_string(),
                settings: json!({"deployment_configs": {"production": {"env_vars": {"CLOUDFLARE_AI_SEARCH_MODE": {"value": "off"}}}}}),
                dry_run: false,
            }))
            .await
            .expect("pages update");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["deployment_snapshot_note"]["applies_to"],
            json!("future_deployments")
        );
        assert!(
            payload["deployment_snapshot_note"]["next_step"]
                .as_str()
                .unwrap()
                .contains("pages_deploy_directory")
        );
    }

    #[tokio::test]
    async fn pages_retry_deployment_normalizes_direct_upload_retry_error() {
        async fn retry_deployment() -> Json<Value> {
            Json(json!({
                "success": false,
                "errors": [{
                    "code": 8000010,
                    "message": "You cannot retry a Direct Upload deployment. Retries are only possible for builds."
                }],
                "messages": [],
                "result": null
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/pages/projects/site/deployments/deploy-1/retry",
            axum::routing::post(retry_deployment),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_pages_retry_deployment(Parameters(PagesDeploymentActionArgs {
                account_id: None,
                project_name: "site".to_string(),
                deployment_id: "deploy-1".to_string(),
                dry_run: false,
            }))
            .await
            .expect("pages retry");

        let payload = result.structured_content.expect("payload");
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["error"]["code"],
            json!("pages.direct_upload_retry_unsupported")
        );
        assert_eq!(
            payload["next_step"]["tool"],
            json!("pages_deploy_directory")
        );
    }

    #[tokio::test]
    async fn pages_rollback_deployment_treats_already_production_error_as_verified_success() {
        async fn rollback_deployment() -> Json<Value> {
            Json(json!({
                "success": false,
                "errors": [{
                    "code": 8000039,
                    "message": "Cannot roll back to the deployment currently in production."
                }],
                "messages": [],
                "result": null
            }))
        }

        async fn get_project() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "project-1",
                    "name": "site",
                    "production_branch": "main",
                    "latest_deployment": {"id": "deploy-1"},
                    "canonical_deployment": {"id": "deploy-1"}
                }
            }))
        }

        let router = Router::new()
            .route(
                "/accounts/acct-1/pages/projects/site/deployments/deploy-1/rollback",
                axum::routing::post(rollback_deployment),
            )
            .route("/accounts/acct-1/pages/projects/site", get(get_project));
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_pages_rollback_deployment(Parameters(PagesDeploymentActionArgs {
                account_id: None,
                project_name: "site".to_string(),
                deployment_id: "deploy-1".to_string(),
                dry_run: false,
            }))
            .await
            .expect("pages rollback");

        let payload = result.structured_content.expect("payload");
        assert_eq!(result.is_error, Some(false));
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["action"],
            json!("already_current_production_readback")
        );
        assert_eq!(payload["canonical_matches"], json!(true));
    }

    #[tokio::test]
    async fn patch_worker_settings_normalizes_pages_generated_worker_no_versions_error() {
        async fn worker_settings_get() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "bindings": [{
                        "type": "plain_text",
                        "name": "CLOUDFLARE_AI_SEARCH_MODE",
                        "text": "primary"
                    }]
                }
            }))
        }

        async fn worker_settings_patch() -> Json<Value> {
            Json(json!({
                "success": false,
                "errors": [{
                    "code": 1000,
                    "message": "This Worker has no versions, which means this Worker has no content or versioned settings."
                }],
                "messages": [],
                "result": null
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/pages-worker--13414231-production/settings",
            get(worker_settings_get).patch(worker_settings_patch),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_patch_worker_settings(
                Parameters(PatchWorkerSettingsArgs {
                    account_id: None,
                    script_name: "pages-worker--13414231-production".to_string(),
                    settings_patch: json!({
                        "bindings": [{
                            "type": "plain_text",
                            "name": "CLOUDFLARE_AI_SEARCH_MODE",
                            "text": "off"
                        }]
                    }),
                    expect_binding: None,
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("patch worker settings");

        let payload = result.structured_content.expect("payload");
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["error"]["code"],
            json!("workers.pages_generated_worker_settings_immutable")
        );
        assert_eq!(
            payload["next_step"]["tool"],
            json!("pages_deploy_directory")
        );
    }

    #[test]
    fn cache_rules_replace_all_preserves_rule_payloads() {
        let current = crate::cloudflare::CacheRuleset {
            id: Some("ruleset-1".to_string()),
            name: Some("cache rules".to_string()),
            phase: Some("http_request_cache_settings".to_string()),
            kind: Some("zone".to_string()),
            rules: vec![
                serde_json::from_value(json!({
                    "id": "old",
                    "description": "old",
                    "expression": "true",
                    "action": "set_cache_settings"
                }))
                .expect("old rule"),
            ],
            extra: Default::default(),
        };

        let next = super::mutate_cache_ruleset(
            current,
            crate::cache::CacheRulesAction::ReplaceAll,
            None,
            None,
            Some(vec![json!({
                "id": "new",
                "description": "new",
                "expression": "http.host eq \"example.com\"",
                "action": "set_cache_settings",
                "action_parameters": { "cache": true }
            })]),
        )
        .expect("mutate")
        .expect("next");

        assert_eq!(next.rules.len(), 1);
        assert_eq!(next.rules[0].id.as_deref(), Some("new"));
        assert_eq!(
            next.rules[0]
                .action_parameters
                .as_ref()
                .and_then(|v| v.get("cache")),
            Some(&json!(true))
        );
    }

    #[tokio::test]
    async fn find_tools_returns_cache_allowed_tools() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("purge cache".to_string()),
                group: Some("cache".to_string()),
                read_only: Some(false),
                limit: Some(5),
                include_schema: false,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert!(
            payload["openai_allowed_tools"]
                .as_array()
                .expect("allowed tools")
                .iter()
                .any(|tool| tool == "cache_purge")
        );
    }

    #[tokio::test]
    async fn find_tools_returns_worker_upload_for_deploy_phrasing() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("deploy upload worker script module".to_string()),
                group: Some("workers".to_string()),
                read_only: Some(false),
                limit: Some(10),
                include_schema: true,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert!(
            payload["openai_allowed_tools"]
                .as_array()
                .expect("allowed tools")
                .iter()
                .any(|tool| tool == "workers_upload_script")
        );
        assert!(payload["schemas"]["workers_upload_script"].is_object());
    }

    #[tokio::test]
    async fn find_tools_returns_api_operations_for_deferred_loading() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("token api create user tokens wrangler api token".to_string()),
                group: None,
                read_only: None,
                limit: Some(20),
                include_schema: true,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert!(
            payload["api_operations"]
                .as_array()
                .expect("api operations")
                .iter()
                .any(|operation| {
                    operation["operation_id"] == json!("account-api-tokens-create-token")
                        && operation["method"] == json!("POST")
                })
        );
        assert!(
            payload["openai_allowed_tools"]
                .as_array()
                .expect("allowed tools")
                .iter()
                .any(|tool| tool == "api_mutate")
        );
        assert!(
            payload["openai_allowed_tools"]
                .as_array()
                .expect("allowed tools")
                .iter()
                .any(|tool| tool == "api_prepare_call")
        );
        assert!(payload["schemas"]["api_mutate"].is_object());
        assert!(payload["schemas"]["api_prepare_call"].is_object());
        assert_eq!(
            payload["openai_deferred_loading"]["recommended_model"],
            json!("gpt-5.5")
        );
        assert_eq!(
            payload["openai_deferred_loading"]["tool_search"]["type"],
            json!("tool_search")
        );
    }

    #[tokio::test]
    async fn find_tools_returns_usage_investigation_tools() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("billing usage d1 rows written spike graph".to_string()),
                group: None,
                read_only: Some(true),
                limit: Some(20),
                include_schema: true,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        let allowed = payload["openai_allowed_tools"]
            .as_array()
            .expect("allowed tools");

        assert!(allowed.iter().any(|tool| tool == "account_billing_usage"));
        assert!(allowed.iter().any(|tool| tool == "graphql_analytics_query"));
        assert!(payload["schemas"]["account_billing_usage"].is_object());
        assert!(payload["schemas"]["graphql_analytics_query"].is_object());
    }

    #[tokio::test]
    async fn find_tools_returns_curated_account_api_token_tool() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("token api create user tokens wrangler api token".to_string()),
                group: None,
                read_only: None,
                limit: Some(20),
                include_schema: true,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        assert!(
            payload["openai_allowed_tools"]
                .as_array()
                .expect("allowed tools")
                .iter()
                .any(|tool| tool == "account_api_tokens")
        );
        assert!(payload["schemas"]["account_api_tokens"].is_object());
    }

    #[tokio::test]
    async fn find_tools_returns_curated_d1_read_tools() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("d1".to_string()),
                group: Some("d1".to_string()),
                read_only: Some(true),
                limit: Some(20),
                include_schema: true,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        let allowed = payload["openai_allowed_tools"]
            .as_array()
            .expect("allowed tools");
        for tool in [
            "d1_list_databases",
            "d1_get_database",
            "d1_inspect_schema",
            "d1_query_read_only",
        ] {
            assert!(allowed.iter().any(|candidate| candidate == tool), "{tool}");
            assert!(payload["schemas"][tool].is_object(), "{tool} schema");
        }
    }

    #[tokio::test]
    async fn find_tools_surfaces_d1_query_for_natural_read_query_phrasing() {
        let server = test_server("http://127.0.0.1:9".to_string());

        for query in [
            "cloudflare d1 execute query",
            "Cloudflare D1 read only query execute SQL database",
        ] {
            let result = server
                .cloudflare_find_tools(Parameters(FindToolsArgs {
                    query: Some(query.to_string()),
                    group: None,
                    read_only: None,
                    limit: Some(10),
                    include_schema: false,
                }))
                .await
                .expect("find tools");
            let payload = result.structured_content.expect("payload");
            let allowed = payload["openai_allowed_tools"]
                .as_array()
                .expect("allowed tools");

            assert!(
                allowed
                    .iter()
                    .any(|candidate| candidate == "d1_query_read_only"),
                "{query}: {payload}"
            );
        }
    }

    #[tokio::test]
    async fn find_tools_returns_curated_d1_mutating_tools() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_find_tools(Parameters(FindToolsArgs {
                query: Some("d1 database".to_string()),
                group: Some("d1".to_string()),
                read_only: Some(false),
                limit: Some(20),
                include_schema: true,
            }))
            .await
            .expect("find tools");
        let payload = result.structured_content.expect("payload");
        let allowed = payload["openai_allowed_tools"]
            .as_array()
            .expect("allowed tools");
        for tool in [
            "d1_rename_database",
            "d1_delete_database",
            "d1_execute_write",
            "d1_apply_migrations",
        ] {
            assert!(allowed.iter().any(|candidate| candidate == tool), "{tool}");
            assert!(payload["schemas"][tool].is_object(), "{tool} schema");
        }
    }

    #[tokio::test]
    async fn api_find_operations_returns_catalog_matches() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_api_find_operations(Parameters(ApiFindOperationsArgs {
                query: Some("dns records".to_string()),
                tag: None,
                method: Some("GET".to_string()),
                scope: Some("zone".to_string()),
                risk: Some("read".to_string()),
                include_deprecated: false,
                limit: Some(10),
            }))
            .await
            .expect("api find operations");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert!(
            payload["results"]
                .as_array()
                .expect("results")
                .iter()
                .any(|result| result["operation_id"]
                    == json!("dns-records-for-a-zone-list-dns-records")
                    && result["preferred_tool"] == json!("list_dns_records"))
        );
    }

    #[tokio::test]
    async fn api_find_operations_prefers_curated_d1_read_tools() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_api_find_operations(Parameters(ApiFindOperationsArgs {
                query: Some("d1 query database".to_string()),
                tag: Some("D1".to_string()),
                method: None,
                scope: Some("account".to_string()),
                risk: None,
                include_deprecated: false,
                limit: Some(20),
            }))
            .await
            .expect("api find operations");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert!(payload["results"].as_array().expect("results").iter().any(
            |result| result["operation_id"] == json!("d1-query-database")
                && result["preferred_tool"] == json!("d1_query_read_only")
        ));
    }

    #[tokio::test]
    async fn api_find_operations_prefers_curated_d1_delete_and_rename_tools() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_api_find_operations(Parameters(ApiFindOperationsArgs {
                query: Some("d1 database".to_string()),
                tag: Some("D1".to_string()),
                method: None,
                scope: Some("account".to_string()),
                risk: None,
                include_deprecated: false,
                limit: Some(20),
            }))
            .await
            .expect("api find operations");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        let results = payload["results"].as_array().expect("results");
        assert!(results.iter().any(|result| {
            result["operation_id"] == json!("d1-delete-database")
                && result["preferred_tool"] == json!("d1_delete_database")
        }));
        assert!(results.iter().any(|result| {
            result["operation_id"] == json!("d1-update-partial-database")
                && result["preferred_tool"] == json!("d1_rename_database")
        }));
    }

    #[tokio::test]
    async fn account_api_tokens_create_uses_stdio_safe_dry_run_confirmation() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_account_api_tokens(Parameters(AccountApiTokensArgs {
                account_id: Some("acct-1".to_string()),
                action: "create".to_string(),
                token_id: None,
                query: BTreeMap::new(),
                body: Some(json!({
                    "name": "deploy-token",
                    "policies": [{
                        "effect": "allow",
                        "resources": {"com.cloudflare.api.account.acct-1": "*"},
                        "permission_groups": [{"id": "perm-1"}]
                    }]
                })),
                dry_run: true,
                confirmation_token: None,
                reason: Some("test".to_string()),
                max_bytes: None,
            }))
            .await
            .expect("account token dry run");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["operation"], json!("account_api_tokens"));
        assert_eq!(payload["action"], json!("create"));
        assert_eq!(
            payload["api_operation"]["operation_id"],
            json!("account-api-tokens-create-token")
        );
        assert!(
            payload["request_plan"]["required_confirmation_token"]
                .as_str()
                .expect("token")
                .starts_with("cf-api-")
        );
    }

    #[tokio::test]
    async fn account_api_token_permission_plan_preserves_existing_permissions() {
        async fn token_details() -> Json<Value> {
            Json(json!({
                "success": true,
                "result": {
                    "id": "token-1",
                    "name": "deploy-token",
                    "condition": {"request_ip": {"in": ["203.0.113.10"]}},
                    "policies": [{
                        "effect": "allow",
                        "resources": {"com.cloudflare.api.account.acct-1": "*"},
                        "permission_groups": [
                            {"id": "perm-d1-read", "name": "D1 Read"},
                            {"id": "perm-account-analytics-read", "name": "Account Analytics Read"}
                        ]
                    }],
                    "status": "active",
                    "modified_on": "2026-06-04T00:00:00Z"
                }
            }))
        }

        async fn permission_groups() -> Json<Value> {
            Json(json!({
                "success": true,
                "result": [
                    {"id": "perm-d1-read", "name": "D1 Read"},
                    {"id": "perm-account-analytics-read", "name": "Account Analytics Read"},
                    {"id": "perm-workers-scripts-edit", "name": "Workers Scripts Edit", "scopes": ["com.cloudflare.api.account.zone.worker.script.edit"]}
                ]
            }))
        }

        let router = Router::new()
            .route("/accounts/acct-1/tokens/token-1", get(token_details))
            .route(
                "/accounts/acct-1/tokens/permission_groups",
                get(permission_groups),
            );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_account_api_token_permission_plan(Parameters(
                AccountApiTokenPermissionPlanArgs {
                    account_id: Some("acct-1".to_string()),
                    token_id: Some("token-1".to_string()),
                    policy_index: None,
                    add_permissions: vec!["Workers Scripts Edit".to_string()],
                    remove_permissions: vec!["Account Analytics Read".to_string()],
                    current_token: None,
                    permission_groups: None,
                    include_catalog: false,
                    reason: Some("add worker upload permission".to_string()),
                    max_bytes: None,
                },
            ))
            .await
            .expect("permission plan");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["delta"]["permissions_to_add"][0]["id"],
            json!("perm-workers-scripts-edit")
        );
        assert_eq!(
            payload["delta"]["permissions_to_remove"][0]["id"],
            json!("perm-account-analytics-read")
        );
        assert_eq!(
            payload["update_body"]["condition"]["request_ip"]["in"][0],
            json!("203.0.113.10")
        );
        assert_eq!(
            payload["update_body"]["policies"][0]["permission_groups"],
            json!([
                {"id": "perm-d1-read"},
                {"id": "perm-workers-scripts-edit"}
            ])
        );
        assert_eq!(payload["next_call"]["arguments"]["action"], json!("update"));
        assert_eq!(payload["next_call"]["arguments"]["dry_run"], json!(true));
    }

    #[tokio::test]
    async fn account_api_token_permission_plan_requires_policy_index_for_multiple_policies() {
        let server = test_server("http://127.0.0.1:9".to_string());

        let result = server
            .cloudflare_account_api_token_permission_plan(Parameters(
                AccountApiTokenPermissionPlanArgs {
                    account_id: Some("acct-1".to_string()),
                    token_id: Some("token-1".to_string()),
                    policy_index: None,
                    add_permissions: vec!["Workers Scripts Edit".to_string()],
                    remove_permissions: Vec::new(),
                    current_token: Some(json!({
                        "id": "token-1",
                        "name": "deploy-token",
                        "policies": [
                            {
                                "effect": "allow",
                                "resources": {"com.cloudflare.api.account.acct-1": "*"},
                                "permission_groups": [{"id": "perm-d1-read", "name": "D1 Read"}]
                            },
                            {
                                "effect": "allow",
                                "resources": {"com.cloudflare.api.account.acct-2": "*"},
                                "permission_groups": [{"id": "perm-d1-read", "name": "D1 Read"}]
                            }
                        ]
                    })),
                    permission_groups: Some(json!([
                        {"id": "perm-d1-read", "name": "D1 Read"},
                        {"id": "perm-workers-scripts-edit", "name": "Workers Scripts Edit"}
                    ])),
                    include_catalog: false,
                    reason: None,
                    max_bytes: None,
                },
            ))
            .await
            .expect("permission plan");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(
            payload["error"]["code"],
            json!("account_api_token_permission_plan.ambiguous_policy")
        );
        assert_eq!(payload["policy_summaries"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn generate_tunnel_ingress_accepts_shorthand_and_service_only_catch_all() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args: GenerateTunnelIngressArgs = serde_json::from_value(json!({
            "tunnel_id": "6c8cc1ec-96c8-4c9c-999a-90009e3237ec",
            "tunnel_name": "example-urgent-fix-trigger",
            "rules": [
                "urgentfix-trigger.example.com -> http://127.0.0.1:8796",
                "http_status:404"
            ]
        }))
        .expect("shorthand ingress args");

        let result = server
            .cloudflare_generate_tunnel_ingress(Parameters(args))
            .await
            .expect("generate ingress");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["config"]["rules"][0]["hostname"],
            json!("urgentfix-trigger.example.com")
        );
        assert_eq!(
            payload["config"]["rules"][0]["service"],
            json!("http://127.0.0.1:8796")
        );
        assert_eq!(payload["config"]["rules"][1]["hostname"], Value::Null);
        assert_eq!(
            payload["config"]["rules"][1]["service"],
            json!("http_status:404")
        );
        let yaml = payload["config"]["yaml"].as_str().expect("yaml");
        assert!(yaml.contains(
            "ingress:\n  - hostname: urgentfix-trigger.example.com\n    service: http://127.0.0.1:8796\n  - service: http_status:404\n"
        ));
        assert_eq!(yaml.matches("service: http_status:404").count(), 1);
    }

    #[tokio::test]
    async fn generate_tunnel_ingress_accepts_object_without_hostname_as_catch_all() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args: GenerateTunnelIngressArgs = serde_json::from_value(json!({
            "tunnel_id": "tunnel-1",
            "tunnel_name": "preview",
            "rules": [
                {"hostname": "preview.example.com", "service": "http://127.0.0.1:8796"},
                {"service": "http_status:404"}
            ]
        }))
        .expect("object ingress args");

        let result = server
            .cloudflare_generate_tunnel_ingress(Parameters(args))
            .await
            .expect("generate ingress");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["config"]["rules"][1]["hostname"], Value::Null);
        assert_eq!(
            payload["config"]["yaml"]
                .as_str()
                .expect("yaml")
                .matches("service: http_status:404")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn generate_tunnel_ingress_rejects_malformed_shorthand() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args: GenerateTunnelIngressArgs = serde_json::from_value(json!({
            "tunnel_id": "tunnel-1",
            "tunnel_name": "preview",
            "rules": ["preview.example.com http://127.0.0.1:8796"]
        }))
        .expect("shorthand ingress args");

        let result = server
            .cloudflare_generate_tunnel_ingress(Parameters(args))
            .await
            .expect("generate ingress");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(
            payload["error"]["code"],
            json!("tunnel.ingress.invalid_rule_fields")
        );
        assert_eq!(payload["error"]["invalid_rule_indices"], json!([0]));
    }

    #[tokio::test]
    async fn generate_tunnel_ingress_rejects_non_terminal_catch_all() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args: GenerateTunnelIngressArgs = serde_json::from_value(json!({
            "tunnel_id": "tunnel-1",
            "tunnel_name": "preview",
            "rules": [
                "http_status:404",
                "preview.example.com -> http://127.0.0.1:8796"
            ]
        }))
        .expect("shorthand ingress args");

        let result = server
            .cloudflare_generate_tunnel_ingress(Parameters(args))
            .await
            .expect("generate ingress");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(
            payload["error"]["code"],
            json!("tunnel.ingress.invalid_catch_all_order")
        );
        assert_eq!(payload["error"]["invalid_rule_indices"], json!([0]));
    }

    #[tokio::test]
    async fn generate_tunnel_ingress_rejects_blank_object_hostname() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args: GenerateTunnelIngressArgs = serde_json::from_value(json!({
            "tunnel_id": "tunnel-1",
            "tunnel_name": "preview",
            "rules": [{"hostname": " ", "service": "http_status:404"}]
        }))
        .expect("object ingress args");

        let result = server
            .cloudflare_generate_tunnel_ingress(Parameters(args))
            .await
            .expect("generate ingress");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(
            payload["error"]["code"],
            json!("tunnel.ingress.invalid_rule_fields")
        );
        assert_eq!(payload["error"]["invalid_rule_indices"], json!([0]));
    }

    #[tokio::test]
    async fn generate_tunnel_ingress_normalizes_star_hostname_to_service_only_catch_all() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args: GenerateTunnelIngressArgs = serde_json::from_value(json!({
            "tunnel_id": "tunnel-1",
            "tunnel_name": "preview",
            "rules": [
                {"hostname": "preview.example.com", "service": "http://127.0.0.1:8796"},
                {"hostname": "*", "service": "http_status:404"}
            ]
        }))
        .expect("object ingress args");

        let result = server
            .cloudflare_generate_tunnel_ingress(Parameters(args))
            .await
            .expect("generate ingress");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["config"]["rules"][1]["hostname"], Value::Null);
        let yaml = payload["config"]["yaml"].as_str().expect("yaml");
        assert!(yaml.contains(
            "ingress:\n  - hostname: preview.example.com\n    service: http://127.0.0.1:8796\n  - service: http_status:404\n"
        ));
        assert!(!yaml.contains("hostname: *"));
        assert_eq!(yaml.matches("service: http_status:404").count(), 1);
    }

    #[tokio::test]
    async fn account_api_tokens_create_apply_sends_planned_body_object() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn create_token(
            State(state): State<CallState>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "token-1",
                    "name": "deploy-token"
                }
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/tokens", axum::routing::post(create_token))
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);
        let body = json!({
            "name": "deploy-token",
            "policies": [{
                "effect": "allow",
                "resources": {"com.cloudflare.api.account.acct-1": "*"},
                "permission_groups": [{"id": "perm-1"}]
            }]
        });

        let dry_run = server
            .cloudflare_account_api_tokens(Parameters(AccountApiTokensArgs {
                account_id: Some("acct-1".to_string()),
                action: "create".to_string(),
                token_id: None,
                query: BTreeMap::new(),
                body: Some(body.clone()),
                dry_run: true,
                confirmation_token: None,
                reason: Some("test".to_string()),
                max_bytes: None,
            }))
            .await
            .expect("account token dry run");
        let dry_run_payload = dry_run.structured_content.expect("dry-run payload");
        let token = dry_run_payload["request_plan"]["required_confirmation_token"]
            .as_str()
            .expect("token")
            .to_string();

        let result = server
            .cloudflare_account_api_tokens(Parameters(AccountApiTokensArgs {
                account_id: Some("acct-1".to_string()),
                action: "create".to_string(),
                token_id: None,
                query: BTreeMap::new(),
                body: Some(body.clone()),
                dry_run: false,
                confirmation_token: Some(token),
                reason: Some("test".to_string()),
                max_bytes: None,
            }))
            .await
            .expect("account token apply");

        assert_eq!(result.is_error, Some(false));
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 1);
        let posted_body = state.body.lock().expect("body lock").clone().unwrap();
        assert_eq!(posted_body, body);
    }

    #[tokio::test]
    async fn account_api_tokens_normalizes_json_string_body_before_apply() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn create_token(
            State(state): State<CallState>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "token-1",
                    "name": "deploy-token"
                }
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/tokens", axum::routing::post(create_token))
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);
        let body = json!(
            r#"{"name":"deploy-token","policies":[{"effect":"allow","resources":{"com.cloudflare.api.account.acct-1":"*"},"permission_groups":[{"id":"perm-1"}]}]}"#
        );

        let dry_run = server
            .cloudflare_account_api_tokens(Parameters(AccountApiTokensArgs {
                account_id: Some("acct-1".to_string()),
                action: "create".to_string(),
                token_id: None,
                query: BTreeMap::new(),
                body: Some(body.clone()),
                dry_run: true,
                confirmation_token: None,
                reason: Some("test".to_string()),
                max_bytes: None,
            }))
            .await
            .expect("account token dry run");
        let dry_run_payload = dry_run.structured_content.expect("dry-run payload");
        assert_eq!(
            dry_run_payload["request_plan"]["body_normalized_from_json_string"],
            json!(true)
        );
        assert_eq!(
            dry_run_payload["request_plan"]["body"]["name"],
            json!("deploy-token")
        );
        let token = dry_run_payload["request_plan"]["required_confirmation_token"]
            .as_str()
            .expect("token")
            .to_string();

        let result = server
            .cloudflare_account_api_tokens(Parameters(AccountApiTokensArgs {
                account_id: Some("acct-1".to_string()),
                action: "create".to_string(),
                token_id: None,
                query: BTreeMap::new(),
                body: Some(body),
                dry_run: false,
                confirmation_token: Some(token),
                reason: Some("test".to_string()),
                max_bytes: None,
            }))
            .await
            .expect("account token apply");

        assert_eq!(result.is_error, Some(false));
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 1);
        let posted_body = state.body.lock().expect("body lock").clone().unwrap();
        assert!(posted_body.is_object());
        assert_eq!(posted_body["name"], json!("deploy-token"));
        assert_eq!(
            posted_body["policies"][0]["permission_groups"][0]["id"],
            json!("perm-1")
        );
    }

    #[tokio::test]
    async fn api_read_executes_catalog_get_with_default_account() {
        async fn list_accounts() -> Json<Value> {
            Json(json!({
                "success": true,
                "result": [{"id": "acct-1", "name": "Example"}],
            }))
        }

        let router = Router::new().route("/accounts", get(list_accounts));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base_url = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });

        let server = test_server(base_url);
        let result = server
            .cloudflare_api_read(Parameters(ApiReadArgs {
                operation_id: "accounts-list-accounts".to_string(),
                path_params: BTreeMap::new(),
                query: BTreeMap::new(),
                max_bytes: None,
            }))
            .await
            .expect("api read");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["result"][0]["id"], json!("acct-1"));
        assert_eq!(payload["response_size"]["truncated"], json!(false));
    }

    #[tokio::test]
    async fn api_read_accepts_null_errors_and_messages_from_cloudflare() {
        #[derive(Clone)]
        struct CallState {
            query: Arc<Mutex<Option<HashMap<String, String>>>>,
        }

        async fn list_queues(
            State(state): State<CallState>,
            Query(query): Query<HashMap<String, String>>,
        ) -> Json<Value> {
            *state.query.lock().expect("query lock") = Some(query);
            Json(json!({
                "success": true,
                "errors": null,
                "messages": null,
                "result": [{
                    "queue_id": "queue-1",
                    "queue_name": "editor-forwarder",
                    "created_on": "2026-05-10T00:00:00Z",
                    "modified_on": null,
                    "producers_total_count": null,
                    "consumers_total_count": 0
                }],
                "result_info": {
                    "page": 1,
                    "per_page": 50,
                    "count": 1,
                    "total_count": 1,
                    "total_pages": 1
                }
            }))
        }

        let state = CallState {
            query: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/queues", get(list_queues))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_api_read(Parameters(ApiReadArgs {
                operation_id: "queues-list".to_string(),
                path_params: BTreeMap::new(),
                query: BTreeMap::from([("per_page".to_string(), json!(50))]),
                max_bytes: Some(20_000),
            }))
            .await
            .expect("api read");
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["result"][0]["queue_id"], json!("queue-1"));
        assert_eq!(
            state
                .query
                .lock()
                .expect("query lock")
                .as_ref()
                .expect("query")
                .get("per_page"),
            Some(&"50".to_string())
        );
        assert_eq!(payload["response_size"]["truncated"], json!(false));
    }

    #[tokio::test]
    async fn api_read_derives_catalog_path_template_params_for_paygo_usage() {
        async fn paygo_usage(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "ServiceName": "D1",
                    "ConsumedQuantity": 42,
                    "ConsumedUnit": "rows",
                    "ChargePeriodStart": query.get("from").cloned().unwrap_or_default(),
                    "ChargePeriodEnd": query.get("to").cloned().unwrap_or_default()
                }]
            }))
        }

        let router = Router::new().route("/accounts/acct-1/paygo-usage", get(paygo_usage));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_api_read(Parameters(ApiReadArgs {
                operation_id: "billable-usage-get-paygo-account-usage".to_string(),
                path_params: BTreeMap::new(),
                query: BTreeMap::from([
                    ("from".to_string(), json!("2026-06-01T00:00:00Z")),
                    ("to".to_string(), json!("2026-06-02T00:00:00Z")),
                ]),
                max_bytes: Some(20_000),
            }))
            .await
            .expect("api read");
        let payload = result.structured_content.expect("payload");

        assert_eq!(payload["ok"], json!(true), "{payload}");
        assert_eq!(
            payload["api_operation"]["rendered_path"],
            json!("/accounts/acct-1/paygo-usage")
        );
        assert_eq!(payload["result"][0]["ServiceName"], json!("D1"));
    }

    #[tokio::test]
    async fn account_billing_usage_reads_current_paygo_endpoint() {
        async fn paygo_usage(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "ServiceName": "D1",
                    "ConsumedQuantity": 12,
                    "ChargePeriodStart": query.get("from").cloned().unwrap_or_default(),
                    "ChargePeriodEnd": query.get("to").cloned().unwrap_or_default()
                }]
            }))
        }

        let router = Router::new().route("/accounts/acct-1/paygo-usage", get(paygo_usage));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_account_billing_usage(Parameters(AccountBillingUsageArgs {
                account_id: None,
                mode: None,
                from: Some("2026-06-01T00:00:00Z".to_string()),
                to: Some("2026-06-02T00:00:00Z".to_string()),
                metric: None,
                max_bytes: Some(20_000),
            }))
            .await
            .expect("billing usage");
        let payload = result.structured_content.expect("payload");

        assert_eq!(payload["ok"], json!(true), "{payload}");
        assert_eq!(payload["mode"], json!("paygo"));
        assert_eq!(payload["path"], json!("/accounts/acct-1/paygo-usage"));
        assert_eq!(payload["result"][0]["ConsumedQuantity"], json!(12));
    }

    #[tokio::test]
    async fn graphql_analytics_query_posts_raw_graphql_payload() {
        #[derive(Clone)]
        struct CallState {
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn graphql(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
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
            }))
        }

        let state = CallState {
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/graphql", post(graphql))
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead rowsWritten } } } } }".to_string(),
                variables: BTreeMap::from([("accountTag".to_string(), json!("acct-1"))]),
                max_bytes: Some(20_000),
            }))
            .await
            .expect("graphql query");
        let payload = result.structured_content.expect("payload");

        assert_eq!(payload["ok"], json!(true), "{payload}");
        assert_eq!(
            payload["result"]["data"]["viewer"]["accounts"][0]["d1AnalyticsAdaptiveGroups"][0]["sum"]
                ["rowsWritten"],
            json!(4)
        );
        let posted = state
            .body
            .lock()
            .expect("body lock")
            .clone()
            .expect("posted body");
        assert_eq!(posted["variables"]["accountTag"], json!("acct-1"));
    }

    #[tokio::test]
    async fn graphql_analytics_query_rejects_mutations_before_http() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: "mutation { forbidden }".to_string(),
                variables: BTreeMap::new(),
                max_bytes: None,
            }))
            .await
            .expect("graphql rejection");
        let payload = result.structured_content.expect("payload");

        assert_eq!(payload["ok"], json!(false), "{payload}");
        assert_eq!(
            payload["error"]["code"],
            json!("graphql_analytics.not_read_only")
        );
    }

    #[tokio::test]
    async fn graphql_analytics_query_rejects_mutation_after_fragment() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: r#"
                    # comments mentioning mutation are ignored
                    fragment AccountFields on Account { accountTag }
                    mutation HiddenWrite { forbidden }
                "#
                .to_string(),
                variables: BTreeMap::new(),
                max_bytes: None,
            }))
            .await
            .expect("graphql rejection");
        let payload = result.structured_content.expect("payload");

        assert_eq!(payload["ok"], json!(false), "{payload}");
        assert_eq!(
            payload["error"]["code"],
            json!("graphql_analytics.not_read_only")
        );
    }

    #[tokio::test]
    async fn graphql_analytics_query_classifies_wrong_account_context_from_empty_account_match() {
        async fn graphql(Json(body): Json<Value>) -> Json<Value> {
            assert_eq!(body["variables"]["accountTag"], json!("missing-acct"));
            Json(json!({
                "data": {
                    "viewer": {
                        "accounts": []
                    }
                }
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead } } } } }".to_string(),
                variables: BTreeMap::from([("accountTag".to_string(), json!("missing-acct"))]),
                max_bytes: None,
            }))
            .await
            .expect("graphql query");
        let payload = result.structured_content.expect("payload");

        assert_eq!(payload["ok"], json!(true), "{payload}");
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("wrong_account_or_zone_context")
        );
    }

    #[tokio::test]
    async fn graphql_analytics_query_classifies_grouped_authz_without_raw_success_as_entitlement_or_product_restriction()
     {
        async fn graphql() -> Json<Value> {
            Json(json!({
                "data": {
                    "viewer": {
                        "accounts": [{}]
                    }
                },
                "errors": [{
                    "message": "does not have access to the path",
                    "path": ["viewer", "accounts", 0, "d1AnalyticsAdaptiveGroups"]
                }]
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead } } } } }".to_string(),
                variables: BTreeMap::from([("accountTag".to_string(), json!("acct-1"))]),
                max_bytes: None,
            }))
            .await
            .expect("graphql query");
        let payload = result.structured_content.expect("payload");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("likely_entitlement_or_product_restriction")
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn graphql_analytics_query_classifies_grouped_authz_with_partial_account_success() {
        async fn graphql() -> Json<Value> {
            Json(json!({
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
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { accountTag d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead } } } } }".to_string(),
                variables: BTreeMap::from([("accountTag".to_string(), json!("acct-1"))]),
                max_bytes: None,
            }))
            .await
            .expect("graphql query");
        let payload = result.structured_content.expect("payload");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("grouped_path_blocked_partial_success")
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["partial_data_available"],
            json!(true)
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn graphql_analytics_query_treats_false_booleans_as_present_raw_payload() {
        async fn graphql() -> Json<Value> {
            Json(json!({
                "data": {
                    "viewer": {
                        "accounts": [{
                            "ssl": false
                        }]
                    }
                },
                "errors": [{
                    "message": "does not have access to the path",
                    "path": ["viewer", "accounts", 0, "d1AnalyticsAdaptiveGroups"]
                }]
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_graphql_analytics_query(Parameters(GraphqlAnalyticsQueryArgs {
                query: "query D1Usage($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { ssl d1AnalyticsAdaptiveGroups(limit: 1) { sum { rowsRead } } } } }".to_string(),
                variables: BTreeMap::from([("accountTag".to_string(), json!("acct-1"))]),
                max_bytes: None,
            }))
            .await
            .expect("graphql query");
        let payload = result.structured_content.expect("payload");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("grouped_path_blocked_partial_success")
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["partial_data_available"],
            json!(true)
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn waf_security_events_summary_classifies_grouped_authz_when_raw_samples_still_work() {
        async fn graphql() -> Json<Value> {
            Json(json!({
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
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_waf_security_events_summary(Parameters(WafSecurityEventsSummaryArgs {
                zone_id: Some("zone-1".to_string()),
                window_hours: 1,
                since: Some("2026-06-04T00:00:00Z".to_string()),
                until: Some("2026-06-04T01:00:00Z".to_string()),
                group_by: vec!["action".to_string()],
                action: None,
                source: None,
                host: None,
                path: None,
                client_ip: None,
                rule_id: None,
                limit: 20,
                sample_limit: 5,
                include_query: false,
                max_bytes: None,
            }))
            .await
            .expect("waf summary");
        let payload = result.structured_content.expect("payload");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("grouped_path_blocked_raw_path_works")
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
            json!(true)
        );
    }

    #[tokio::test]
    async fn waf_security_events_summary_does_not_treat_settings_only_as_raw_path_success() {
        async fn graphql() -> Json<Value> {
            Json(json!({
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
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_waf_security_events_summary(Parameters(WafSecurityEventsSummaryArgs {
                zone_id: Some("zone-1".to_string()),
                window_hours: 1,
                since: Some("2026-06-04T00:00:00Z".to_string()),
                until: Some("2026-06-04T01:00:00Z".to_string()),
                group_by: vec!["action".to_string()],
                action: None,
                source: None,
                host: None,
                path: None,
                client_ip: None,
                rule_id: None,
                limit: 20,
                sample_limit: 0,
                include_query: false,
                max_bytes: None,
            }))
            .await
            .expect("waf summary");
        let payload = result.structured_content.expect("payload");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("likely_entitlement_or_product_restriction")
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn waf_security_events_summary_requires_grouped_error_signal_for_grouped_only_classification()
     {
        async fn graphql() -> Json<Value> {
            Json(json!({
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
            }))
        }

        let router = Router::new().route("/graphql", post(graphql));
        let server = test_server(spawn_router(router).await);
        let result = server
            .cloudflare_waf_security_events_summary(Parameters(WafSecurityEventsSummaryArgs {
                zone_id: Some("zone-1".to_string()),
                window_hours: 1,
                since: Some("2026-06-04T00:00:00Z".to_string()),
                until: Some("2026-06-04T01:00:00Z".to_string()),
                group_by: vec!["action".to_string()],
                action: None,
                source: None,
                host: None,
                path: None,
                client_ip: None,
                rule_id: None,
                limit: 20,
                sample_limit: 5,
                include_query: false,
                max_bytes: None,
            }))
            .await
            .expect("waf summary");
        let payload = result.structured_content.expect("payload");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["code"],
            json!("likely_entitlement_or_product_restriction")
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["raw_path_worked"],
            json!(true)
        );
        assert_eq!(
            payload["diagnostics"]["authz_classification"]["evidence"]["grouped_path_mentioned"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn api_prepare_call_resolves_best_match_into_executor_arguments() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let result = server
            .cloudflare_api_prepare_call(Parameters(ApiPrepareCallArgs {
                operation_id: None,
                query: Some("queue metrics".to_string()),
                tag: Some("Queue".to_string()),
                method: Some("GET".to_string()),
                scope: Some("account".to_string()),
                risk: Some("read".to_string()),
                include_deprecated: false,
                path_params: BTreeMap::from([("queue_id".to_string(), "queue-1".to_string())]),
                query_params: BTreeMap::new(),
                body: None,
                limit: Some(1),
            }))
            .await
            .expect("api prepare call");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["status"], json!("ready"));
        assert_eq!(payload["executor"], json!("api_read"));
        assert_eq!(
            payload["call"]["arguments"]["operation_id"],
            json!("queues-get-metrics")
        );
        assert_eq!(
            payload["resolved_path_params"],
            json!({"account_id": "acct-1", "queue_id": "queue-1"})
        );
        assert_eq!(
            payload["call"]["arguments"]["path_params"],
            json!({"account_id": "acct-1", "queue_id": "queue-1"})
        );
        assert_eq!(
            payload["rendered_path"],
            json!("/accounts/acct-1/queues/queue-1/metrics")
        );
    }

    #[tokio::test]
    async fn queues_health_reports_backlog_consumers_and_dlq_readback() {
        async fn get_queue(Path(queue_id): Path<String>) -> Json<Value> {
            let queue_name = if queue_id == "queue-1" {
                "editor-forwarder"
            } else {
                "editor-forwarder-dlq"
            };
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "queue_id": queue_id,
                    "queue_name": queue_name,
                    "settings": {"delivery_paused": false},
                    "consumers_total_count": 1
                }
            }))
        }

        async fn get_metrics(Path(queue_id): Path<String>) -> Json<Value> {
            let backlog_count = if queue_id == "queue-1" { 7 } else { 2 };
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "backlog_bytes": backlog_count * 100,
                    "backlog_count": backlog_count,
                    "oldest_message_timestamp_ms": 0
                }
            }))
        }

        async fn list_consumers() -> Json<Value> {
            Json(json!({
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
            }))
        }

        async fn purge_status() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {"completed": "2026-05-21T00:00:00Z"}
            }))
        }

        async fn list_queues() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [
                    {"queue_id": "queue-1", "queue_name": "editor-forwarder"},
                    {"queue_id": "dlq-1", "queue_name": "editor-forwarder-dlq"}
                ]
            }))
        }

        let router = Router::new()
            .route("/accounts/acct-1/queues", get(list_queues))
            .route("/accounts/acct-1/queues/{queue_id}", get(get_queue))
            .route(
                "/accounts/acct-1/queues/{queue_id}/metrics",
                get(get_metrics),
            )
            .route(
                "/accounts/acct-1/queues/{queue_id}/consumers",
                get(list_consumers),
            )
            .route(
                "/accounts/acct-1/queues/{queue_id}/purge",
                get(purge_status),
            );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_queues_health(Parameters(QueueHealthArgs {
                account_id: None,
                queue_id: "queue-1".to_string(),
                include_dlq: true,
            }))
            .await
            .expect("queue health");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["metrics"]["backlog_count"], json!(7.0));
        assert_eq!(payload["consumer_status"]["state"], json!("configured"));
        assert_eq!(
            payload["dlq"]["configured"][0],
            json!("editor-forwarder-dlq")
        );
        assert_eq!(payload["dlq"]["backlog_count"], json!(2.0));
    }

    #[tokio::test]
    async fn d1_list_databases_sends_name_filter_to_cloudflare() {
        #[derive(Clone)]
        struct CallState {
            query: Arc<Mutex<Option<HashMap<String, String>>>>,
        }

        async fn list_d1(
            State(state): State<CallState>,
            Query(query): Query<HashMap<String, String>>,
        ) -> Json<Value> {
            *state.query.lock().expect("query lock") = Some(query);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "uuid": "db-1",
                    "name": "staff-db",
                    "created_at": "2026-05-01T00:00:00Z"
                }],
                "result_info": {"page": 1, "per_page": 3, "count": 1, "total_count": 1, "total_pages": 1}
            }))
        }

        let state = CallState {
            query: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/d1/database", get(list_d1))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_d1_list_databases(Parameters(D1ListDatabasesArgs {
                account_id: None,
                name: Some("staff".to_string()),
                page: Some(1),
                per_page: Some(3),
            }))
            .await
            .expect("d1 list");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["page"]["items"][0]["name"], json!("staff-db"));
        let query = state.query.lock().expect("query lock").clone().unwrap();
        assert_eq!(query.get("name"), Some(&"staff".to_string()));
        assert_eq!(query.get("per_page"), Some(&"3".to_string()));
    }

    #[tokio::test]
    async fn d1_apply_migrations_dry_run_reads_wrangler_ledger_without_writes() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("bodies lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                "SELECT * FROM \"d1_migrations\" ORDER BY id" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"id": 1, "name": "0001_initial.sql", "applied_at": "2026-05-01 00:00:00"}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let dir = d1_migration_test_dir("d1-dry-run-ledger");
        fs::write(
            dir.join("0001_initial.sql"),
            "CREATE TABLE submissions(id TEXT);",
        )
        .expect("write migration 1");
        fs::write(
            dir.join("0002_add_review.sql"),
            "ALTER TABLE submissions ADD COLUMN review TEXT;",
        )
        .expect("write migration 2");
        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_apply_migrations(Parameters(D1ApplyMigrationsArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                migrations_directory: dir.to_string_lossy().to_string(),
                migrations_table: None,
                dry_run: true,
                max_rows: None,
            }))
            .await
            .expect("d1 apply dry run");

        assert_eq!(result.is_error, Some(false));
        let bodies = state.bodies.lock().expect("bodies lock").clone();
        assert_eq!(bodies.len(), 1);
        assert_eq!(
            bodies[0]["sql"],
            json!("SELECT * FROM \"d1_migrations\" ORDER BY id")
        );
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["migrations_table"], json!("d1_migrations"));
        assert_eq!(payload["ledger_checked"], json!(true));
        assert_eq!(payload["unknown_ledger"], json!(false));
        assert_eq!(payload["already_applied"][0], json!("0001_initial.sql"));
        assert_eq!(
            payload["skipped_migrations"][0]["name"],
            json!("0001_initial.sql")
        );
        assert_eq!(
            payload["pending_migrations"][0]["name"],
            json!("0002_add_review.sql")
        );
        let payload_text = serde_json::to_string(&payload).expect("payload json");
        assert!(!payload_text.contains("CREATE TABLE submissions"));
        assert!(!payload_text.contains("ALTER TABLE submissions"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn d1_apply_migrations_applies_only_pending_files_in_wrangler_order() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("bodies lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.starts_with("CREATE TABLE IF NOT EXISTS \"custom_migrations\"") => {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"success": true, "results": [], "meta": {"served_by": "ensure"}}]
                    }))
                }
                "SELECT * FROM \"custom_migrations\" ORDER BY id" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"id": 1, "name": "0001_initial.sql"}],
                        "meta": {"served_by": "ledger"}
                    }]
                })),
                sql if sql.contains("INSERT INTO \"custom_migrations\"") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "results": [{"ok": true}], "meta": {"served_by": "apply"}}]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let dir = d1_migration_test_dir("d1-apply-ledger");
        fs::write(
            dir.join("0001_initial.sql"),
            "CREATE TABLE submissions(id TEXT);",
        )
        .expect("write migration 1");
        fs::write(
            dir.join("10_tenth.sql"),
            "ALTER TABLE submissions ADD COLUMN ten TEXT;",
        )
        .expect("write migration 10");
        fs::write(
            dir.join("2_second.sql"),
            "ALTER TABLE submissions ADD COLUMN two TEXT;",
        )
        .expect("write migration 2");
        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_apply_migrations(Parameters(D1ApplyMigrationsArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                migrations_directory: dir.to_string_lossy().to_string(),
                migrations_table: Some("custom_migrations".to_string()),
                dry_run: false,
                max_rows: Some(5),
            }))
            .await
            .expect("d1 apply");

        assert_eq!(result.is_error, Some(false));
        let bodies = state.bodies.lock().expect("bodies lock").clone();
        assert_eq!(bodies.len(), 4);
        assert!(
            bodies[0]["sql"]
                .as_str()
                .unwrap()
                .contains("CREATE TABLE IF NOT EXISTS \"custom_migrations\"")
        );
        assert_eq!(
            bodies[1]["sql"],
            json!("SELECT * FROM \"custom_migrations\" ORDER BY id")
        );
        let first_apply = bodies[2]["sql"].as_str().unwrap();
        let second_apply = bodies[3]["sql"].as_str().unwrap();
        assert!(first_apply.contains("ADD COLUMN two"));
        assert!(
            first_apply
                .contains("INSERT INTO \"custom_migrations\" (name) VALUES ('2_second.sql')")
        );
        assert!(second_apply.contains("ADD COLUMN ten"));
        assert!(
            second_apply
                .contains("INSERT INTO \"custom_migrations\" (name) VALUES ('10_tenth.sql')")
        );
        assert!(!first_apply.contains("0001_initial"));
        assert!(!second_apply.contains("0001_initial"));

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["already_applied"][0], json!("0001_initial.sql"));
        assert_eq!(
            payload["skipped_migrations"][0]["name"],
            json!("0001_initial.sql")
        );
        assert_eq!(
            payload["pending_migrations"][0]["name"],
            json!("2_second.sql")
        );
        assert_eq!(
            payload["pending_migrations"][1]["name"],
            json!("10_tenth.sql")
        );
        assert_eq!(
            payload["applied_migrations"][0]["name"],
            json!("2_second.sql")
        );
        assert_eq!(
            payload["applied_migrations"][1]["name"],
            json!("10_tenth.sql")
        );
        let payload_text = serde_json::to_string(&payload).expect("payload json");
        assert!(!payload_text.contains("ADD COLUMN two"));
        assert!(!payload_text.contains("ADD COLUMN ten"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn d1_apply_migrations_fails_closed_when_ledger_cannot_be_read() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("bodies lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.starts_with("CREATE TABLE IF NOT EXISTS \"d1_migrations\"") => {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"success": true, "results": []}]
                    }))
                }
                "SELECT * FROM \"d1_migrations\" ORDER BY id" => Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "SQLITE_AUTH: access denied"}],
                    "messages": [],
                    "result": null
                })),
                sql => {
                    panic!("migration SQL should not execute before ledger read succeeds: {sql}")
                }
            }
        }

        let dir = d1_migration_test_dir("d1-ledger-fail");
        fs::write(
            dir.join("0001_initial.sql"),
            "CREATE TABLE submissions(id TEXT);",
        )
        .expect("write migration");
        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_apply_migrations(Parameters(D1ApplyMigrationsArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                migrations_directory: dir.to_string_lossy().to_string(),
                migrations_table: None,
                dry_run: false,
                max_rows: None,
            }))
            .await
            .expect("d1 apply");

        assert_eq!(result.is_error, Some(true));
        let bodies = state.bodies.lock().expect("bodies lock").clone();
        assert_eq!(bodies.len(), 2);
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["unknown_ledger"], json!(true));
        assert_eq!(
            payload["error"]["code"],
            json!("d1.migration_ledger_unreadable")
        );
        assert_eq!(
            payload["candidate_migrations"][0]["name"],
            json!("0001_initial.sql")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn d1_query_read_only_denies_mutating_sql_before_http() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
        }

        async fn query_d1(State(state): State<CallState>) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_d1_query_read_only(Parameters(D1QueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "INSERT INTO users VALUES (1)".to_string(),
                params: Vec::new(),
                max_rows: None,
            }))
            .await
            .expect("d1 query");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["error"]["code"], json!("d1.sql_policy_denied"));
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn d1_query_read_only_posts_params_and_truncates_results() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "success": true,
                    "results": [{"id": 1}, {"id": 2}, {"id": 3}],
                    "meta": {"duration": 1}
                }]
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_d1_query_read_only(Parameters(D1QueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT id FROM users WHERE id > ?".to_string(),
                params: vec![json!(0)],
                max_rows: Some(2),
            }))
            .await
            .expect("d1 query");

        assert_eq!(result.is_error, Some(false));
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 1);
        let body = state.body.lock().expect("body lock").clone().unwrap();
        assert_eq!(body["sql"], json!("SELECT id FROM users WHERE id > ?"));
        assert_eq!(body["params"], json!([0]));

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["truncated"], json!(true));
        assert_eq!(payload["result"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(payload["result"][0]["original_result_count"], json!(3));
    }

    #[tokio::test]
    async fn d1_query_read_only_catalog_falls_back_on_sqlite_auth() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "D1 query rejected by authorization policy"}],
                    "messages": [],
                    "result": null
                })),
                "PRAGMA table_list" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"schema": "main", "name": "submissions", "type": "table"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_query_read_only(Parameters(D1QueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT type, name, tbl_name, sql FROM sqlite_master".to_string(),
                params: vec![],
                max_rows: None,
            }))
            .await
            .expect("d1 query");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["result"][0]["results"][0]["name"],
            json!("submissions")
        );
        assert_eq!(
            payload["result"][0]["meta"]["d1_catalog_fallback"],
            json!(true)
        );
        assert_eq!(
            payload["result"][0]["meta"]["discovery_strategy"],
            json!("pragma_table_list")
        );
        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[1]["sql"], json!("PRAGMA table_list"));
    }

    #[tokio::test]
    async fn d1_query_read_only_non_catalog_sqlite_auth_reports_d1_error() {
        async fn query_d1(Json(_body): Json<Value>) -> (StatusCode, Json<Value>) {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "SQLITE_AUTH: access denied"}],
                    "messages": [],
                    "result": null
                })),
            )
        }

        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            axum::routing::post(query_d1),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_query_read_only(Parameters(D1QueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT id FROM submissions".to_string(),
                params: vec![],
                max_rows: None,
            }))
            .await
            .expect("d1 query");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(payload["error"]["code"], json!("d1.sqlite_auth"));
    }

    #[tokio::test]
    async fn d1_query_read_only_no_such_column_recommends_targeted_validation() {
        async fn query_d1(Json(_body): Json<Value>) -> (StatusCode, Json<Value>) {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "SQLITE_ERROR: no such column: source_type"}],
                    "messages": [],
                    "result": null
                })),
            )
        }

        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            axum::routing::post(query_d1),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_query_read_only(Parameters(D1QueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT source_type FROM submissions".to_string(),
                params: vec![],
                max_rows: None,
            }))
            .await
            .expect("d1 query");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(payload["error"]["code"], json!("d1.no_such_column"));
        assert!(
            payload["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("d1_validate_query")
        );
        assert!(
            payload["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("include_tables")
        );
        assert_eq!(
            payload["recommended_next_steps"][0]["tool"],
            json!("d1_validate_query")
        );
    }

    #[tokio::test]
    async fn d1_query_read_only_no_such_table_does_not_mask_as_sqlite_auth() {
        async fn query_d1(Json(_body): Json<Value>) -> (StatusCode, Json<Value>) {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "SQLITE_ERROR: no such table: missing_table"}],
                    "messages": [],
                    "result": null
                })),
            )
        }

        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            axum::routing::post(query_d1),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_query_read_only(Parameters(D1QueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT id FROM missing_table".to_string(),
                params: vec![],
                max_rows: None,
            }))
            .await
            .expect("d1 query");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(payload["error"]["code"], json!("d1.no_such_table"));
        assert_eq!(
            payload["recommended_next_steps"][0]["tool"],
            json!("d1_validate_query")
        );
    }

    #[tokio::test]
    async fn d1_validate_query_reports_missing_table_without_executing_user_query() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"type": "table", "name": "submissions", "tbl_name": "submissions", "sql": "CREATE TABLE submissions (id TEXT)"}],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"submissions\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_validate_query(Parameters(D1ValidateQueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT id FROM missing_table".to_string(),
                include_query_plan: true,
            }))
            .await
            .expect("d1 validate");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(
            payload["validation"]["error"]["code"],
            json!("d1.table_not_application_schema")
        );
        assert_eq!(payload["executed_user_query"], json!(false));
        assert_eq!(payload["query_plan"]["reason"], json!("validation_failed"));
        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 2);
        assert!(bodies.iter().all(|body| {
            body["sql"].as_str().unwrap_or_default() != "SELECT id FROM missing_table"
        }));
    }

    #[tokio::test]
    async fn d1_validate_query_reports_missing_column_and_can_return_query_plan() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"type": "view", "name": "open_submissions", "tbl_name": "open_submissions", "sql": "CREATE VIEW open_submissions AS SELECT id FROM submissions"}],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"open_submissions\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 0}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql if sql.starts_with("EXPLAIN QUERY PLAN") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"id": 2, "parent": 0, "notused": 0, "detail": "SCAN open_submissions"}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let missing_column = server
            .cloudflare_d1_validate_query(Parameters(D1ValidateQueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT missing_col FROM open_submissions".to_string(),
                include_query_plan: false,
            }))
            .await
            .expect("d1 validate");
        let payload = missing_column.structured_content.expect("payload");
        assert_eq!(missing_column.is_error, Some(true));
        assert_eq!(
            payload["validation"]["error"]["code"],
            json!("d1.column_not_found")
        );
        assert_eq!(
            payload["schema"]["columns"][0]["object_type"],
            json!("view")
        );
        assert_eq!(payload["schema"]["columns"][0]["derived"], json!(true));

        let valid = server
            .cloudflare_d1_validate_query(Parameters(D1ValidateQueryArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                sql: "SELECT id FROM open_submissions".to_string(),
                include_query_plan: true,
            }))
            .await
            .expect("d1 validate");
        let payload = valid.structured_content.expect("payload");
        assert_eq!(valid.is_error, Some(false));
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["query_plan"]["available"], json!(true));
        assert_eq!(
            payload["validation"]["warnings"][0]["code"],
            json!("d1.view_may_be_expensive")
        );
    }

    #[tokio::test]
    async fn d1_inspect_schema_uses_sqlite_master_and_direct_pragmas() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"type": "table", "name": "submissions", "tbl_name": "submissions", "sql": "CREATE TABLE submissions (id TEXT)"},
                            {"type": "view", "name": "open_submissions", "tbl_name": "open_submissions", "sql": "CREATE VIEW open_submissions AS SELECT * FROM submissions"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"submissions\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"open_submissions\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 0}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: true,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["discovery_strategy"],
            json!("sqlite_master")
        );
        assert_eq!(payload["schema"]["columns"][0]["column_name"], json!("id"));
        assert_eq!(
            payload["schema"]["columns"][1]["table_name"],
            json!("open_submissions")
        );
        assert_eq!(
            payload["schema"]["columns"][1]["object_type"],
            json!("view")
        );
        assert_eq!(payload["schema"]["columns"][1]["derived"], json!(true));
        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 3);
        assert!(bodies.iter().all(|body| {
            !body["sql"]
                .as_str()
                .unwrap_or_default()
                .contains("sqlite_schema")
        }));
        assert!(bodies.iter().all(|body| {
            !body["sql"]
                .as_str()
                .unwrap_or_default()
                .contains("pragma_table_info")
        }));
    }

    #[tokio::test]
    async fn d1_inspect_schema_falls_back_to_table_list_on_sqlite_auth_code_7500_and_reports_lossy_fidelity()
     {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "D1 query rejected by authorization policy"}],
                    "messages": [],
                    "result": null
                })),
                "PRAGMA table_list" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"schema": "main", "name": "zeta_table", "type": "table"},
                            {"schema": "main", "name": "sqlite_sequence", "type": "table"},
                            {"schema": "main", "name": "alpha_table", "type": "table"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"alpha_table\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "alpha_id", "type": "TEXT", "notnull": 0, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"zeta_table\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "zeta_id", "type": "INTEGER", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: true,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["discovery_strategy"],
            json!("pragma_table_list")
        );
        assert_eq!(
            payload["schema"]["discovery_fidelity"],
            json!({
                "mode": "lossy",
                "limitations": ["sql_ddl", "indexes", "triggers"]
            })
        );
        assert_eq!(
            payload["schema"]["objects"],
            json!([
                {
                    "type": "table",
                    "name": "alpha_table",
                    "tbl_name": "alpha_table",
                    "sql": null
                },
                {
                    "type": "table",
                    "name": "zeta_table",
                    "tbl_name": "zeta_table",
                    "sql": null
                }
            ])
        );
        assert_eq!(
            payload["schema"]["columns"],
            json!([
                {
                    "table_name": "alpha_table",
                    "object_type": "table",
                    "column_id": 0,
                    "column_name": "alpha_id",
                    "column_type": "TEXT",
                    "not_null": 0,
                    "default_value": null,
                    "primary_key": 1,
                    "derived": false,
                    "source": "pragma_table_info"
                },
                {
                    "table_name": "zeta_table",
                    "object_type": "table",
                    "column_id": 0,
                    "column_name": "zeta_id",
                    "column_type": "INTEGER",
                    "not_null": 1,
                    "default_value": null,
                    "primary_key": 1,
                    "derived": false,
                    "source": "pragma_table_info"
                }
            ])
        );
        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 4);
        assert_eq!(
            bodies[2]["sql"],
            json!("PRAGMA table_info(\"alpha_table\")")
        );
        assert_eq!(bodies[3]["sql"], json!("PRAGMA table_info(\"zeta_table\")"));
    }

    #[tokio::test]
    async fn d1_inspect_schema_returns_partial_columns_when_one_table_info_is_sqlite_auth() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"type": "table", "name": "readable_table", "tbl_name": "readable_table", "sql": "CREATE TABLE readable_table (id TEXT)"},
                            {"type": "table", "name": "denied_table", "tbl_name": "denied_table", "sql": "CREATE TABLE denied_table (id TEXT)"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"denied_table\")" => Json(json!({
                    "success": false,
                    "errors": [{"code": 7500, "message": "not authorized: SQLITE_AUTH"}],
                    "messages": [],
                    "result": null
                })),
                "PRAGMA table_info(\"readable_table\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: true,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["discovery_strategy"],
            json!("sqlite_master")
        );
        assert_eq!(
            payload["schema"]["column_discovery_fidelity"],
            json!({
                "mode": "partial",
                "limitations": ["some_table_columns"]
            })
        );
        assert_eq!(
            payload["schema"]["columns"],
            json!([
                {
                    "table_name": "readable_table",
                    "object_type": "table",
                    "column_id": 0,
                    "column_name": "id",
                    "column_type": "TEXT",
                    "not_null": 1,
                    "default_value": null,
                    "primary_key": 1,
                    "derived": false,
                    "source": "pragma_table_info"
                }
            ])
        );
        assert_eq!(
            payload["schema"]["column_errors"][0]["table_name"],
            "denied_table"
        );
        assert!(matches!(
            payload["schema"]["column_errors"][0]["code"].as_str(),
            Some("cloudflare.api_error") | Some("cloudflare.http_error")
        ));
        assert!(
            payload["schema"]["column_errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains("SQLITE_AUTH")
        );

        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 3);
    }

    #[tokio::test]
    async fn d1_inspect_schema_skips_internal_cloudflare_tables_as_non_errors() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"type": "table", "name": "_cf_KV", "tbl_name": "_cf_KV", "sql": "CREATE TABLE _cf_KV (key TEXT)"},
                            {"type": "table", "name": "submissions", "tbl_name": "submissions", "sql": "CREATE TABLE submissions (id TEXT)"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"submissions\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: true,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["summary"]["message"],
            json!("schema returned for application tables; internal Cloudflare tables skipped")
        );
        assert_eq!(
            payload["schema"]["objects"],
            json!([{
                "type": "table",
                "name": "submissions",
                "tbl_name": "submissions",
                "sql": "CREATE TABLE submissions (id TEXT)"
            }])
        );
        assert_eq!(
            payload["schema"]["skipped_internal_tables"][0]["name"],
            json!("_cf_KV")
        );
        assert!(payload["schema"]["column_errors"].is_null());
        assert!(payload["schema"]["column_discovery_fidelity"].is_null());

        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 2);
        assert!(
            bodies
                .iter()
                .all(|body| { !body["sql"].as_str().unwrap_or_default().contains("_cf_KV") })
        );
    }

    #[tokio::test]
    async fn d1_inspect_schema_include_filters_limit_application_column_probes() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"type": "table", "name": "submissions", "tbl_name": "submissions", "sql": "CREATE TABLE submissions (id TEXT)"},
                            {"type": "table", "name": "submission_events", "tbl_name": "submission_events", "sql": "CREATE TABLE submission_events (id TEXT)"},
                            {"type": "index", "name": "idx_submission_events_submission_id", "tbl_name": "submission_events", "sql": "CREATE INDEX idx_submission_events_submission_id ON submission_events(submission_id)"},
                            {"type": "table", "name": "users", "tbl_name": "users", "sql": "CREATE TABLE users (id TEXT)"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"submissions\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"submission_events\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"cid": 0, "name": "id", "type": "TEXT", "notnull": 1, "dflt_value": null, "pk": 1}],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: true,
                include_tables: vec!["Submissions".to_string()],
                include_table_pattern: Some("submission_*".to_string()),
            }))
            .await
            .expect("d1 schema");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["objects"]
                .as_array()
                .expect("objects")
                .len(),
            3
        );
        assert_eq!(
            payload["schema"]["filter"]["matched_application_objects"],
            json!(3)
        );
        assert_eq!(
            payload["schema"]["filtered_out_tables"][0]["name"],
            json!("users")
        );

        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(bodies.len(), 3);
        assert_eq!(
            bodies[1]["sql"],
            json!("PRAGMA table_info(\"submissions\")")
        );
        assert_eq!(
            bodies[2]["sql"],
            json!("PRAGMA table_info(\"submission_events\")")
        );
    }

    #[tokio::test]
    async fn d1_inspect_schema_falls_back_to_table_list_on_sqlite_auth_message_drift() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": false,
                    "errors": [{"code": 1234, "message": "SQLITE_AUTH: access denied"}],
                    "messages": [],
                    "result": null
                })),
                "PRAGMA table_list" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [
                            {"schema": "main", "name": "submissions", "type": "table"}
                        ],
                        "meta": {"duration": 1}
                    }]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: false,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["discovery_strategy"],
            json!("pragma_table_list")
        );
        assert_eq!(
            payload["schema"]["discovery_fidelity"]["mode"],
            json!("lossy")
        );
        assert_eq!(
            payload["schema"]["objects"],
            json!([
                {
                    "type": "table",
                    "name": "submissions",
                    "tbl_name": "submissions",
                    "sql": null
                }
            ])
        );
        assert_eq!(payload["schema"]["columns"], Value::Null);
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn d1_inspect_schema_escapes_table_identifiers_for_pragma() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body["sql"].as_str().unwrap_or_default() {
                sql if sql.contains("sqlite_master") => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{
                        "success": true,
                        "results": [{"type": "table", "name": "odd \"table\"", "tbl_name": "odd \"table\"", "sql": null}],
                        "meta": {"duration": 1}
                    }]
                })),
                "PRAGMA table_info(\"odd \"\"table\"\"\")" => Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"success": true, "results": [], "meta": {"duration": 1}}]
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: true,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        assert_eq!(result.is_error, Some(false));
        let bodies = state.bodies.lock().expect("body lock");
        assert_eq!(
            bodies[1]["sql"],
            json!("PRAGMA table_info(\"odd \"\"table\"\"\")")
        );
    }

    #[tokio::test]
    async fn d1_inspect_schema_include_columns_false_skips_column_pragmas() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                body["sql"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("sqlite_master")
            );
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "success": true,
                    "results": [{"type": "table", "name": "submissions", "tbl_name": "submissions", "sql": null}],
                    "meta": {"duration": 1}
                }]
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_d1_inspect_schema(Parameters(D1InspectSchemaArgs {
                account_id: None,
                database_id: "db-1".to_string(),
                include_columns: false,
                include_tables: Vec::new(),
                include_table_pattern: None,
            }))
            .await
            .expect("d1 schema");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["schema"]["columns"], Value::Null);
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn workers_observability_list_values_includes_required_timeframe_and_type() {
        #[derive(Clone)]
        struct CallState {
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn values(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"key": "$workers.scriptName", "type": "string", "value": "pages-worker"}]
            }))
        }

        let state = CallState {
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/observability/telemetry/values",
                axum::routing::post(values),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_workers_observability_list_values(Parameters(
                WorkersObservabilityListValuesArgs {
                    account_id: None,
                    key: "$workers.scriptName".to_string(),
                    script_name: Some("pages-worker".to_string()),
                    datasets: Vec::new(),
                    filters: Vec::new(),
                    limit: Some(50),
                    value_type: None,
                    timeframe: None,
                    lookback_minutes: Some(30),
                    needle: None,
                },
            ))
            .await
            .expect("workers observability values");

        assert_eq!(result.is_error, Some(false));
        let body = state.body.lock().expect("body lock").clone().unwrap();
        assert_eq!(body["key"], json!("$workers.scriptName"));
        assert_eq!(body["type"], json!("string"));
        assert!(body["timeframe"]["from"].is_number());
        assert!(body["timeframe"]["to"].is_number());
        assert_eq!(body["datasets"], json!(["workers"]));
        assert_eq!(body["filters"][0]["key"], json!("$workers.scriptName"));
        assert_eq!(body["filters"][0]["value"], json!("pages-worker"));
    }

    #[tokio::test]
    async fn workers_observability_list_keys_uses_top_level_time_bounds() {
        #[derive(Clone)]
        struct CallState {
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn keys(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"key": "$workers.scriptName", "type": "string"}]
            }))
        }

        let state = CallState {
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/observability/telemetry/keys",
                axum::routing::post(keys),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_workers_observability_list_keys(Parameters(
                WorkersObservabilityListKeysArgs {
                    account_id: None,
                    script_name: Some("pages-worker".to_string()),
                    datasets: vec!["workers".to_string()],
                    filters: vec![json!({
                        "key": "$metadata.request.method",
                        "operation": "eq",
                        "type": "string",
                        "value": "GET",
                    })],
                    limit: Some(25),
                    timeframe: Some(WorkersObservabilityTimeframe { from: 10, to: 20 }),
                    lookback_minutes: None,
                    needle: Some(json!({"value": "script"})),
                    key_needle: Some(json!({"value": "$workers"})),
                },
            ))
            .await
            .expect("workers observability keys");

        assert_eq!(result.is_error, Some(false));
        let body = state.body.lock().expect("body lock").clone().unwrap();
        assert_eq!(body["from"], json!(10));
        assert_eq!(body["to"], json!(20));
        assert!(body.get("timeframe").is_none());
        assert_eq!(body["datasets"], json!(["workers"]));
        assert_eq!(body["filters"][0]["value"], json!("pages-worker"));
        assert_eq!(body["filters"][1]["key"], json!("$metadata.request.method"));
        assert_eq!(body["needle"], json!({"value": "script"}));
        assert_eq!(body["keyNeedle"], json!({"value": "$workers"}));
        assert_eq!(body["limit"], json!(25));
    }

    #[tokio::test]
    async fn workers_observability_query_events_builds_documented_timeframed_query() {
        #[derive(Clone)]
        struct CallState {
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn query(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {"events": []}
            }))
        }

        let state = CallState {
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/observability/telemetry/query",
                axum::routing::post(query),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_workers_observability_query_events(Parameters(
                WorkersObservabilityQueryEventsArgs {
                    account_id: None,
                    script_name: Some("pages-worker".to_string()),
                    datasets: Vec::new(),
                    filters: Vec::new(),
                    limit: Some(20),
                    timeframe: Some(WorkersObservabilityTimeframe { from: 1, to: 2 }),
                    lookback_minutes: None,
                    query_id: None,
                    dry: None,
                    view: None,
                    needle: None,
                },
            ))
            .await
            .expect("workers observability query");

        assert_eq!(result.is_error, Some(false));
        let body = state.body.lock().expect("body lock").clone().unwrap();
        assert_eq!(body["timeframe"], json!({"from": 1, "to": 2}));
        assert_eq!(body["queryId"], json!("mcp-workers-observability-events"));
        assert_eq!(body["dry"], json!(true));
        assert_eq!(body["limit"], json!(20));
        assert_eq!(
            body["parameters"]["filters"][0]["value"],
            json!("pages-worker")
        );
        assert_eq!(body["parameters"]["datasets"], json!(["workers"]));
        assert_eq!(body["parameters"]["filterCombination"], json!("and"));
        assert_eq!(body["parameters"]["view"], json!("events"));
        assert_eq!(body["parameters"]["limit"], json!(20));
    }

    #[tokio::test]
    async fn bindings_discover_returns_partial_success_when_pages_fails() {
        async fn list_d1() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"uuid": "db-1", "name": "staff"}],
                "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1}
            }))
        }

        async fn list_queues() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"queue_id": "queue-1", "queue_name": "editor-forwarder"}],
                "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1}
            }))
        }

        async fn list_pages() -> (StatusCode, Json<Value>) {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "errors": [{"code": 7000, "message": "pages unavailable"}],
                    "messages": [],
                    "result": null
                })),
            )
        }

        let router = Router::new()
            .route("/accounts/acct-1/d1/database", get(list_d1))
            .route("/accounts/acct-1/queues", get(list_queues))
            .route("/accounts/acct-1/pages/projects", get(list_pages));
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_bindings_discover(Parameters(BindingsDiscoverArgs {
                account_id: None,
                include_workers: false,
                include_pages: true,
                name_contains: None,
            }))
            .await
            .expect("bindings discover");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["status"], json!("partial"));
        assert_eq!(payload["partial"], json!(true));
        assert_eq!(payload["surfaces"]["d1"]["ok"], json!(true));
        assert_eq!(payload["surfaces"]["queues"]["ok"], json!(true));
        assert_eq!(payload["surfaces"]["pages"]["ok"], json!(false));
        assert_eq!(payload["errors"][0]["surface"], json!("pages"));
    }

    #[tokio::test]
    async fn analytics_engine_query_posts_text_sql_and_truncates_rows() {
        #[derive(Clone)]
        struct CallState {
            body: Arc<Mutex<Option<String>>>,
        }

        async fn analytics(State(state): State<CallState>, body: String) -> Json<Value> {
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "meta": [
                    {"name": "path", "type": "String"},
                    {"name": "views", "type": "UInt64"}
                ],
                "data": [
                    {"path": "/", "views": 2},
                    {"path": "/help", "views": 1}
                ],
                "rows": 2
            }))
        }

        let state = CallState {
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/analytics_engine/sql",
                axum::routing::post(analytics),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_query(Parameters(AnalyticsEngineQueryArgs {
                account_id: None,
                sql: "SELECT blob1 AS path, SUM(_sample_interval) AS views FROM WEB GROUP BY path"
                    .to_string(),
                max_rows: Some(1),
            }))
            .await
            .expect("analytics engine query");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["truncated"], json!(true));
        assert_eq!(payload["result"]["data"].as_array().unwrap().len(), 2);
        assert_eq!(payload["result"]["rows"], json!(2));
        assert_eq!(
            state.body.lock().expect("body lock").clone().unwrap(),
            "SELECT blob1 AS path, SUM(_sample_interval) AS views FROM WEB GROUP BY path"
        );
    }

    #[tokio::test]
    async fn analytics_engine_list_datasets_runs_show_tables() {
        #[derive(Clone)]
        struct CallState {
            body: Arc<Mutex<Option<String>>>,
        }

        async fn analytics(State(state): State<CallState>, body: String) -> Json<Value> {
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "meta": [{"name": "name", "type": "String"}],
                "data": [{"name": "WEB"}],
                "rows": 1
            }))
        }

        let state = CallState {
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/analytics_engine/sql",
                axum::routing::post(analytics),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_list_datasets(Parameters(
                AnalyticsEngineListDatasetsArgs {
                    account_id: None,
                    max_rows: None,
                },
            ))
            .await
            .expect("analytics engine datasets");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["datasets"]["data"][0]["name"], json!("WEB"));
        assert_eq!(
            state.body.lock().expect("body lock").clone().unwrap(),
            "SHOW TABLES"
        );
    }

    #[tokio::test]
    async fn analytics_engine_describe_schema_exposes_blob_double_index_hints() {
        async fn analytics(body: String) -> Json<Value> {
            assert_eq!(body, "SHOW TABLES");
            Json(json!({
                "meta": [{"name": "name", "type": "String"}],
                "data": [{"name": "WEB"}],
                "rows": 1
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/analytics_engine/sql",
            axum::routing::post(analytics),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_describe_schema(Parameters(
                AnalyticsEngineListDatasetsArgs {
                    account_id: None,
                    max_rows: None,
                },
            ))
            .await
            .expect("analytics schema");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["schema"]["schema_version"],
            json!("workers_analytics_engine_sql_v1")
        );
        assert_eq!(payload["schema"]["objects"][0]["name"], json!("WEB"));
        assert_eq!(
            payload["schema"]["blob_mapping"]["columns"][0],
            json!("blob1")
        );
        assert_eq!(
            payload["schema"]["double_mapping"]["columns"][19],
            json!("double20")
        );
        assert_eq!(
            payload["schema"]["index_mapping"]["columns"][0],
            json!("index1")
        );
    }

    #[tokio::test]
    async fn analytics_engine_validate_query_checks_dataset_and_columns_without_executing_user_sql()
    {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<String>>>,
        }

        async fn analytics(State(state): State<CallState>, body: String) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body.as_str() {
                "SHOW TABLES" => Json(json!({
                    "meta": [{"name": "name", "type": "String"}],
                    "data": [{"name": "WEB"}],
                    "rows": 1
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/analytics_engine/sql",
                axum::routing::post(analytics),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_validate_query(Parameters(
                AnalyticsEngineValidateQueryArgs {
                    account_id: None,
                    sql: "SELECT missing_metric FROM WEB".to_string(),
                    include_dataset_readback: true,
                },
            ))
            .await
            .expect("analytics validate");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(
            payload["validation"]["error"]["code"],
            json!("analytics_engine.column_not_found")
        );
        assert_eq!(payload["executed_user_query"], json!(false));
        assert_eq!(
            payload["query_plan"]["reason"],
            json!("analytics_engine_sql_api_does_not_expose_pre_execution_plan")
        );
        assert_eq!(
            state.bodies.lock().expect("body lock").as_slice(),
            ["SHOW TABLES"]
        );
    }

    #[tokio::test]
    async fn analytics_engine_validate_query_treats_function_calls_as_functions_not_columns() {
        async fn analytics(body: String) -> Json<Value> {
            assert_eq!(body, "SHOW TABLES");
            Json(json!({
                "meta": [{"name": "name", "type": "String"}],
                "data": [{"name": "WEB"}],
                "rows": 1
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/analytics_engine/sql",
            axum::routing::post(analytics),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_validate_query(Parameters(
                AnalyticsEngineValidateQueryArgs {
                    account_id: None,
                    sql: "SELECT coalesce(blob1, 'unknown') AS route, quantileExactWeighted(0.95)(double1, _sample_interval) AS p95 FROM WEB WHERE timestamp >= toDateTime('2026-01-01') GROUP BY route".to_string(),
                    include_dataset_readback: true,
                },
            ))
            .await
            .expect("analytics validate");

        let payload = result.structured_content.expect("payload");
        assert_eq!(result.is_error, Some(false));
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["validation"]["referenced_functions"],
            json!(["coalesce", "quantileexactweighted", "todatetime"])
        );
        assert_eq!(
            payload["validation"]["referenced_columns"],
            json!(["_sample_interval", "blob1", "double1", "timestamp"])
        );
    }

    #[tokio::test]
    async fn analytics_engine_validate_query_reports_missing_dataset() {
        async fn analytics(body: String) -> Json<Value> {
            assert_eq!(body, "SHOW TABLES");
            Json(json!({
                "meta": [{"name": "name", "type": "String"}],
                "data": [{"name": "WEB"}],
                "rows": 1
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/analytics_engine/sql",
            axum::routing::post(analytics),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_validate_query(Parameters(
                AnalyticsEngineValidateQueryArgs {
                    account_id: None,
                    sql: "SELECT blob1 FROM MISSING".to_string(),
                    include_dataset_readback: true,
                },
            ))
            .await
            .expect("analytics validate");

        let payload = result.structured_content.expect("payload");
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            payload["validation"]["error"]["code"],
            json!("analytics_engine.table_not_application_schema")
        );
    }

    #[tokio::test]
    async fn analytics_engine_validate_query_accepts_dataset_key_from_show_tables() {
        #[derive(Clone)]
        struct CallState {
            bodies: Arc<Mutex<Vec<String>>>,
        }

        async fn analytics(State(state): State<CallState>, body: String) -> Json<Value> {
            state.bodies.lock().expect("body lock").push(body.clone());
            match body.as_str() {
                "SHOW TABLES" => Json(json!({
                    "meta": [{"name": "dataset", "type": "String"}],
                    "data": [{"dataset": "example_staff_publish_telemetry"}],
                    "rows": 1
                })),
                sql => panic!("unexpected SQL: {sql}"),
            }
        }

        let state = CallState {
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/analytics_engine/sql",
                axum::routing::post(analytics),
            )
            .with_state(state.clone());
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_validate_query(Parameters(
                AnalyticsEngineValidateQueryArgs {
                    account_id: None,
                    sql: "SELECT blob2 AS event_name, blob3 AS source, blob6 AS step, blob7 AS outcome, blob8 AS route, blob9 AS submit_mode, blob15 AS error_code, blob16 AS http_bucket, blob20 AS category, SUM(_sample_interval) AS events, min(timestamp) AS first_seen, max(timestamp) AS last_seen FROM example_staff_publish_telemetry WHERE timestamp >= now() - INTERVAL 3 HOUR AND blob1 = 'publish-confidence.v2' AND (blob7 IN ('failed','timeout','read_failed','blocked') OR blob16 IN ('4xx','5xx') OR blob2 IN ('story_submit_failed','server_submit_failed','story_preview_failed','story_preview_timeout','server_preview_failed','story_publish_recovery','story_publish_diagnosis','story_troubleshooter_result')) GROUP BY event_name, source, step, outcome, route, submit_mode, error_code, http_bucket, category ORDER BY last_seen DESC LIMIT 50".to_string(),
                    include_dataset_readback: true,
                },
            ))
            .await
            .expect("analytics validate");

        let payload = result.structured_content.expect("payload");
        assert_eq!(result.is_error, Some(false));
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(
            payload["validation"]["referenced_tables"],
            json!(["example_staff_publish_telemetry"])
        );
        assert_eq!(payload["executed_user_query"], json!(false));
        assert_eq!(
            payload["schema"]["objects"][0]["name"],
            json!("example_staff_publish_telemetry")
        );
        assert_eq!(
            state.bodies.lock().expect("body lock").as_slice(),
            ["SHOW TABLES"]
        );
    }

    #[tokio::test]
    async fn analytics_engine_query_accepts_legacy_cloudflare_envelope_shape() {
        async fn analytics() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"path": "/", "views": 1}]
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/analytics_engine/sql",
            axum::routing::post(analytics),
        );
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_query(Parameters(AnalyticsEngineQueryArgs {
                account_id: None,
                sql: "SELECT blob1 AS path FROM WEB".to_string(),
                max_rows: None,
            }))
            .await
            .expect("analytics engine query");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        assert_eq!(payload["result"][0]["path"], json!("/"));
    }

    #[tokio::test]
    async fn analytics_engine_query_denies_mutating_sql_before_http() {
        let router = Router::new();
        let server = test_server(spawn_router(router).await);

        let result = server
            .cloudflare_analytics_engine_query(Parameters(AnalyticsEngineQueryArgs {
                account_id: None,
                sql: "INSERT INTO WEB VALUES (1)".to_string(),
                max_rows: None,
            }))
            .await
            .expect("analytics engine query");

        let payload = result.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(false));
        assert_eq!(
            payload["error"]["code"],
            json!("analytics_engine.sql_policy_denied")
        );
    }

    #[tokio::test]
    async fn api_mutate_dry_run_requires_confirmation_before_apply() {
        let server = test_server("http://127.0.0.1:9".to_string());
        let args = ApiMutateArgs {
            operation_id: "dns-records-for-a-zone-create-dns-record".to_string(),
            path_params: BTreeMap::new(),
            query: BTreeMap::new(),
            body: Some(json!({"type": "CNAME", "name": "www", "content": "target"})),
            dry_run: true,
            confirmation_token: None,
            reason: Some("test".to_string()),
        };
        let dry_run = server
            .cloudflare_api_mutate(Parameters(args))
            .await
            .expect("api mutate dry run");
        let payload = dry_run.structured_content.expect("payload");
        assert_eq!(payload["ok"], json!(true));
        let token = payload["request_plan"]["required_confirmation_token"]
            .as_str()
            .expect("token")
            .to_string();
        assert!(token.starts_with("cf-api-"));

        let apply_without_token = server
            .cloudflare_api_mutate(Parameters(ApiMutateArgs {
                operation_id: "dns-records-for-a-zone-create-dns-record".to_string(),
                path_params: BTreeMap::new(),
                query: BTreeMap::new(),
                body: Some(json!({"type": "CNAME", "name": "www", "content": "target"})),
                dry_run: false,
                confirmation_token: None,
                reason: Some("test".to_string()),
            }))
            .await
            .expect("api mutate apply");
        let payload = apply_without_token.structured_content.expect("payload");
        assert_eq!(
            payload["error"]["code"],
            json!("api_mutate.confirmation_required")
        );
    }

    #[tokio::test]
    async fn api_mutate_normalizes_json_string_body_before_apply() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
            body: Arc<Mutex<Option<Value>>>,
        }

        async fn query_d1(State(state): State<CallState>, Json(body): Json<Value>) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            *state.body.lock().expect("body lock") = Some(body);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{"success": true, "meta": {"duration": 1}}]
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
            body: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/d1/database/db-1/query",
                axum::routing::post(query_d1),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);
        let body = json!(
            r#"{"sql":"UPDATE submissions SET status = ? WHERE id = ?","params":["in_progress","sub-1"]}"#
        );

        let dry_run = server
            .cloudflare_api_mutate(Parameters(ApiMutateArgs {
                operation_id: "d1-query-database".to_string(),
                path_params: BTreeMap::from([
                    ("account_id".to_string(), "acct-1".to_string()),
                    ("database_id".to_string(), "db-1".to_string()),
                ]),
                query: BTreeMap::new(),
                body: Some(body.clone()),
                dry_run: true,
                confirmation_token: None,
                reason: Some("acknowledge ticket".to_string()),
            }))
            .await
            .expect("api mutate dry run");
        let dry_run_payload = dry_run.structured_content.expect("dry-run payload");
        assert_eq!(
            dry_run_payload["request_plan"]["body_normalized_from_json_string"],
            json!(true)
        );
        assert_eq!(
            dry_run_payload["request_plan"]["body"]["sql"],
            json!("UPDATE submissions SET status = ? WHERE id = ?")
        );
        let token = dry_run_payload["request_plan"]["required_confirmation_token"]
            .as_str()
            .expect("token")
            .to_string();

        let result = server
            .cloudflare_api_mutate(Parameters(ApiMutateArgs {
                operation_id: "d1-query-database".to_string(),
                path_params: BTreeMap::from([
                    ("account_id".to_string(), "acct-1".to_string()),
                    ("database_id".to_string(), "db-1".to_string()),
                ]),
                query: BTreeMap::new(),
                body: Some(body),
                dry_run: false,
                confirmation_token: Some(token),
                reason: Some("acknowledge ticket".to_string()),
            }))
            .await
            .expect("api mutate apply");

        assert_eq!(result.is_error, Some(false));
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 1);
        let posted_body = state.body.lock().expect("body lock").clone().unwrap();
        assert!(posted_body.is_object());
        assert_eq!(
            posted_body["sql"],
            json!("UPDATE submissions SET status = ? WHERE id = ?")
        );
        assert_eq!(posted_body["params"], json!(["in_progress", "sub-1"]));
    }

    #[tokio::test]
    async fn ensure_tunnel_repeated_runs_converge_to_single_identity() {
        #[derive(Clone)]
        struct CallState {
            create_calls: Arc<AtomicUsize>,
            tunnels: Arc<Mutex<Vec<(String, String)>>>,
        }

        async fn list_tunnels(State(state): State<CallState>) -> Json<Value> {
            let tunnels = state.tunnels.lock().expect("tunnels lock");
            let items = tunnels
                .iter()
                .map(|(id, name)| {
                    json!({
                        "id": id,
                        "name": name,
                        "status": "healthy",
                        "created_at": "2026-02-22T00:00:00Z",
                    })
                })
                .collect::<Vec<_>>();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": items,
                "result_info": {
                    "page": 1,
                    "per_page": 100,
                    "count": items.len(),
                    "total_count": items.len(),
                    "total_pages": 1
                }
            }))
        }

        async fn create_tunnel(
            State(state): State<CallState>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            state.create_calls.fetch_add(1, Ordering::SeqCst);
            let name = body
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let mut tunnels = state.tunnels.lock().expect("tunnels lock");
            let id = if let Some((id, _)) = tunnels
                .iter()
                .find(|(_, existing_name)| existing_name.eq_ignore_ascii_case(&name))
            {
                id.clone()
            } else {
                let id = format!("tun-{}", tunnels.len() + 1);
                tunnels.push((id.clone(), name.clone()));
                id
            };
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": id,
                    "name": name,
                    "status": "healthy",
                    "created_at": "2026-02-22T00:00:00Z",
                }
            }))
        }

        let state = CallState {
            create_calls: Arc::new(AtomicUsize::new(0)),
            tunnels: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/cfd_tunnel",
                get(list_tunnels).post(create_tunnel),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let first = server
            .cloudflare_ensure_tunnel(
                Parameters(EnsureTunnelArgs {
                    account_id: None,
                    tunnel_name: "Preview-Tunnel".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("first ensure");
        let first_payload = first.structured_content.expect("structured payload");
        assert_eq!(first_payload["action"], json!("created"));
        let first_id = first_payload["tunnel"]["id"]
            .as_str()
            .expect("tunnel id")
            .to_string();

        let second = server
            .cloudflare_ensure_tunnel(
                Parameters(EnsureTunnelArgs {
                    account_id: None,
                    tunnel_name: "preview-tunnel".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("second ensure");
        let second_payload = second.structured_content.expect("structured payload");
        assert_eq!(second_payload["action"], json!("reused"));
        assert_eq!(second_payload["tunnel"]["id"], json!(first_id));
        assert_eq!(
            second_payload["tunnel_target"],
            json!(format!(
                "{}.cfargotunnel.com",
                second_payload["tunnel"]["id"].as_str().expect("tunnel id")
            ))
        );
        assert_eq!(state.create_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connector_control_reports_idempotent_start_and_restart_transition() {
        let base_url = spawn_router(Router::new()).await;
        let server = test_server(base_url);

        let started = server
            .cloudflare_connector_control(
                Parameters(ConnectorControlArgs {
                    connector_key: "acct-1::preview".to_string(),
                    action: "start".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("start");
        let started_payload = started.structured_content.expect("structured payload");
        assert_eq!(
            started_payload["result"]["transition"]["idempotent"],
            json!(false)
        );
        assert_eq!(
            started_payload["result"]["connector"]["state"],
            json!("running")
        );
        assert_eq!(
            started_payload["result"]["orphan_processes_detected"],
            json!(0)
        );

        let started_again = server
            .cloudflare_connector_control(
                Parameters(ConnectorControlArgs {
                    connector_key: "acct-1::preview".to_string(),
                    action: "start".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("start again");
        let started_again_payload = started_again
            .structured_content
            .expect("structured payload");
        assert_eq!(
            started_again_payload["result"]["transition"]["idempotent"],
            json!(true)
        );
        assert_eq!(
            started_again_payload["result"]["transition"]["event"],
            json!("already_running")
        );

        let restarted = server
            .cloudflare_connector_control(
                Parameters(ConnectorControlArgs {
                    connector_key: "acct-1::preview".to_string(),
                    action: "restart".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("restart");
        let restarted_payload = restarted.structured_content.expect("structured payload");
        assert_eq!(
            restarted_payload["result"]["transition"]["event"],
            json!("restart")
        );
        assert_eq!(
            restarted_payload["result"]["connector"]["restart_count"],
            json!(1)
        );
        assert_eq!(
            restarted_payload["result"]["orphan_processes_detected"],
            json!(0)
        );
    }

    #[tokio::test]
    async fn upsert_dns_cname_duplicate_route_conflict_is_typed_and_fail_closed() {
        #[derive(Clone)]
        struct CallState {
            post_calls: Arc<AtomicUsize>,
        }

        async fn list_dns_records() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [
                    {
                        "id": "rec-1",
                        "name": "preview.example.com",
                        "type": "CNAME",
                        "content": "a.cfargotunnel.com",
                        "proxied": true,
                        "ttl": 1
                    },
                    {
                        "id": "rec-2",
                        "name": "preview.example.com",
                        "type": "CNAME",
                        "content": "b.cfargotunnel.com",
                        "proxied": true,
                        "ttl": 1
                    }
                ]
            }))
        }

        async fn mutate_dns(State(state): State<CallState>) -> Json<Value> {
            state.post_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {}
            }))
        }

        let state = CallState {
            post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route(
                "/zones/zone-1/dns_records",
                get(list_dns_records).post(mutate_dns),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_upsert_dns_cname(
                Parameters(UpsertDnsCnameArgs {
                    account_id: None,
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    target: "preview.cfargotunnel.com".to_string(),
                    proxied: Some(true),
                    ttl: Some(1),
                    override_publish_guard: false,
                    override_reason: None,
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["error"]["code"],
            json!("dns_route.conflict_multiple_records")
        );
        assert_eq!(
            payload["route_conflict"]["conflicting_record_ids"][0],
            json!("rec-1")
        );
        assert_eq!(state.post_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn upsert_access_app_update_then_repeated_run_is_noop() {
        #[derive(Clone)]
        struct CallState {
            app_name: Arc<Mutex<String>>,
            update_calls: Arc<AtomicUsize>,
        }

        async fn list_access_apps(State(state): State<CallState>) -> Json<Value> {
            let app_name = state.app_name.lock().expect("app_name lock").clone();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "app-1",
                    "name": app_name,
                    "domain": "preview.example.com",
                    "aud": "aud-1"
                }]
            }))
        }

        async fn update_access_app(
            State(state): State<CallState>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            state.update_calls.fetch_add(1, Ordering::SeqCst);
            let app_name = payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            *state.app_name.lock().expect("app_name lock") = app_name.clone();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "app-1",
                    "name": app_name,
                    "domain": "preview.example.com",
                    "aud": "aud-1"
                }
            }))
        }

        let state = CallState {
            app_name: Arc::new(Mutex::new("old-name".to_string())),
            update_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/access/apps", get(list_access_apps))
            .route(
                "/accounts/acct-1/access/apps/app-1",
                get(list_access_apps).put(update_access_app),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let updated = server
            .cloudflare_upsert_access_app(
                Parameters(UpsertAccessAppArgs {
                    account_id: None,
                    hostname: "preview.example.com".to_string(),
                    app_name: "preview-app".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("first upsert");
        let updated_payload = updated.structured_content.expect("structured payload");
        assert_eq!(updated_payload["action"], json!("update"));
        assert_eq!(
            updated_payload["upsert_plan"]["diff"]["name_changed"],
            json!(true)
        );
        assert_eq!(
            updated_payload["validated_app"]["name"],
            json!("preview-app")
        );
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);

        let noop = server
            .cloudflare_upsert_access_app(
                Parameters(UpsertAccessAppArgs {
                    account_id: None,
                    hostname: "preview.example.com".to_string(),
                    app_name: "preview-app".to_string(),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("second upsert");
        let noop_payload = noop.structured_content.expect("structured payload");
        assert_eq!(noop_payload["action"], json!("noop"));
        assert_eq!(
            noop_payload["upsert_plan"]["diff"]["name_changed"],
            json!(false)
        );
        assert_eq!(state.update_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn upsert_dns_cname_blocks_when_policy_gate_fails_without_override() {
        #[derive(Clone)]
        struct CallState {
            dns_get_calls: Arc<AtomicUsize>,
            dns_post_calls: Arc<AtomicUsize>,
        }

        async fn list_access_apps() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        async fn list_dns(State(state): State<CallState>) -> Json<Value> {
            state.dns_get_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        async fn mutate_dns(State(state): State<CallState>) -> Json<Value> {
            state.dns_post_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        let state = CallState {
            dns_get_calls: Arc::new(AtomicUsize::new(0)),
            dns_post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/access/apps", get(list_access_apps))
            .route("/zones/zone-1/dns_records", get(list_dns).post(mutate_dns))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_upsert_dns_cname(
                Parameters(UpsertDnsCnameArgs {
                    account_id: None,
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    target: "target.example.com".to_string(),
                    proxied: Some(true),
                    ttl: Some(1),
                    override_publish_guard: false,
                    override_reason: None,
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["error"]["code"],
            json!("publish.policy_gate_denied")
        );
        assert_eq!(state.dns_get_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.dns_post_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn upsert_dns_cname_dry_run_does_not_call_dns_mutations() {
        #[derive(Clone)]
        struct CallState {
            dns_get_calls: Arc<AtomicUsize>,
            dns_post_calls: Arc<AtomicUsize>,
        }

        async fn list_access_apps() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "app-1",
                    "name": "preview-app",
                    "domain": "preview.example.com",
                    "aud": "aud-1"
                }]
            }))
        }

        async fn list_access_policies() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "pol-1",
                    "name": "allow",
                    "decision": "allow",
                    "include": {
                        "email": {
                            "email": ["agent@example.com"]
                        }
                    }
                }]
            }))
        }

        async fn list_dns(State(state): State<CallState>) -> Json<Value> {
            state.dns_get_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        async fn mutate_dns(State(state): State<CallState>) -> Json<Value> {
            state.dns_post_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        let state = CallState {
            dns_get_calls: Arc::new(AtomicUsize::new(0)),
            dns_post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/access/apps", get(list_access_apps))
            .route(
                "/accounts/acct-1/access/apps/app-1/policies",
                get(list_access_policies),
            )
            .route("/zones/zone-1/dns_records", get(list_dns).post(mutate_dns))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_upsert_dns_cname(
                Parameters(UpsertDnsCnameArgs {
                    account_id: None,
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    target: "target.example.com".to_string(),
                    proxied: Some(true),
                    ttl: Some(1),
                    override_publish_guard: false,
                    override_reason: None,
                    dry_run: true,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(payload["dry_run"], json!(true));
        assert_eq!(payload["route_reconciliation"]["action"], json!("create"));
        assert_eq!(payload["route_verification"]["state"], json!("missing"));
        assert_eq!(
            payload["audit"]["correlation"]["correlation_id"],
            json!("corr-test-1")
        );
        assert_eq!(state.dns_get_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.dns_post_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn portal_agent_request_dry_run_reports_auth_metadata_without_secret_values() {
        let base_url = spawn_router(Router::new()).await;
        let server = test_server(base_url);
        let query_probe = fixture_material("query-probe");
        let payload_probe = fixture_material("payload-probe");

        let result = server
            .cloudflare_portal_agent_request(
                Parameters(PortalAgentRequestArgs {
                    url: format!(
                        "https://staff.example.com/api/agent/assistant/knowledge/import?token={query_probe}"
                    ),
                    method: "POST".to_string(),
                    body: Some(json!({
                        "title": "incident note",
                        "token": payload_probe.clone()
                    })),
                    use_agent_token: true,
                    use_access_service_token: true,
                    dry_run: true,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("portal request dry run");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(payload["dry_run"], json!(true));
        assert_eq!(payload["auth"]["agent_token_attached"], json!(true));
        assert_eq!(
            payload["auth"]["has_configured_access_service_token"],
            json!(true)
        );
        let serialized = serde_json::to_string(&payload).expect("serialize payload");
        assert!(!serialized.contains(&fixture_material("portal-agent")));
        assert!(!serialized.contains(&fixture_material("access-material")));
        assert!(!serialized.contains(&payload_probe));
        assert!(!serialized.contains(&query_probe));
    }

    #[tokio::test]
    async fn portal_agent_request_live_missing_token_reports_process_auth_state() {
        let client = Arc::new(
            CloudflareClient::new(CloudflareApiConfig {
                api_base_url: "http://127.0.0.1:9".to_string(),
                api_token: Some(fixture_material("api")),
                api_token_source: ApiTokenSource::Config,
                api_token_header: "x-cloudflare-api-token".to_string(),
                r2_access_key_id: None,
                r2_secret_access_key: None,
                r2_endpoint: None,
                default_account_id: Some("acct-1".to_string()),
                default_zone_id: Some("zone-1".to_string()),
                request_timeout: Duration::from_secs(2),
                max_retries: 0,
                retry_base_delay: Duration::from_millis(1),
                retry_max_delay: Duration::from_millis(1),
                user_agent: "cloudflare-mcp-test".to_string(),
            })
            .expect("client"),
        );
        let portal_agent = Arc::new(
            PortalAgentClient::new(PortalAgentConfig {
                allowed_url_prefixes: vec!["https://staff.example.com/api/agent/".to_string()],
                agent_token: None,
                access_client_id: Some("access-client-id".to_string()),
                access_client_secret: Some(fixture_material("access-material")),
                request_timeout: Duration::from_secs(2),
                user_agent: "cloudflare-mcp-test".to_string(),
            })
            .expect("portal client"),
        );
        let server = CloudflareMcp::new(
            client,
            Some("acct-1".to_string()),
            Some("zone-1".to_string()),
            true,
            ApiTokenSource::Config,
            "x-cloudflare-api-token".to_string(),
            true,
            false,
            true,
            portal_agent,
            ElicitationConfig {
                enabled: false,
                required_tools: Vec::new(),
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
            Arc::new(ToolListTracker::default()),
            Arc::new(BoundedSessionManager::new_with_lifecycle(
                LocalSessionManager::default(),
                8,
                true,
                SessionConfig::default(),
                SessionLifecycleConfig::default(),
            )),
            ResumeMode::Historyless,
        );

        let result = server
            .cloudflare_portal_agent_request(
                Parameters(PortalAgentRequestArgs {
                    url: "https://staff.example.com/api/agent/queue?kind=feedback&limit=50"
                        .to_string(),
                    method: "GET".to_string(),
                    body: None,
                    use_agent_token: true,
                    use_access_service_token: true,
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("portal request");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["error"]["code"],
            json!("portal.agent_token_missing")
        );
        assert_eq!(payload["auth"]["agent_token_requested"], json!(true));
        assert_eq!(payload["auth"]["has_configured_agent_token"], json!(false));
        assert_eq!(
            payload["auth"]["has_configured_access_service_token"],
            json!(true)
        );
    }

    #[tokio::test]
    async fn portal_agent_request_live_http_error_reports_process_auth_state_without_secret_values()
    {
        let agent_material = fixture_material("portal-agent");
        let access_material = fixture_material("access-material");
        let portal_agent = PortalAgentClient::new(PortalAgentConfig {
            allowed_url_prefixes: vec!["https://staff.example.com/api/agent/".to_string()],
            agent_token: Some(agent_material.clone()),
            access_client_id: Some("access-client-id".to_string()),
            access_client_secret: Some(access_material.clone()),
            request_timeout: Duration::from_secs(2),
            user_agent: "cloudflare-mcp-test".to_string(),
        })
        .expect("portal client");

        let request_probe = fixture_material("request-probe");
        let response_token_probe = fixture_material("response-token-probe");
        let response_material_probe = fixture_material("response-material-probe");

        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            let response_body = json!({
                "error": "forbidden",
                "token": response_token_probe.clone(),
                "nested": {
                    "client_secret": response_material_probe.clone()
                }
            });
            let router = Router::new().route(
                "/api/agent/import",
                axum::routing::post({
                    let response_body = response_body.clone();
                    let expected_agent_header = format!("Bearer {agent_material}");
                    let expected_access_material = access_material.clone();
                    move |headers: HeaderMap| {
                        let response_body = response_body.clone();
                        let expected_agent_header = expected_agent_header.clone();
                        let expected_access_material = expected_access_material.clone();
                        async move {
                            assert_eq!(
                                headers
                                    .get(axum::http::header::AUTHORIZATION)
                                    .and_then(|value| value.to_str().ok()),
                                Some(expected_agent_header.as_str())
                            );
                            assert_eq!(
                                headers
                                    .get("CF-Access-Client-Id")
                                    .and_then(|value| value.to_str().ok()),
                                Some("access-client-id")
                            );
                            assert_eq!(
                                headers
                                    .get("CF-Access-Client-Secret")
                                    .and_then(|value| value.to_str().ok()),
                                Some(expected_access_material.as_str())
                            );
                            (status, Json(response_body))
                        }
                    }
                }),
            );
            let base_url = spawn_router(router).await;
            let url = url::Url::parse(&format!("{base_url}/api/agent/import")).expect("url");
            let response = portal_agent
                .send(
                    &url,
                    "POST",
                    Some(json!({
                        "title": "incident note",
                        "token": request_probe.clone()
                    })),
                    true,
                    true,
                )
                .await
                .expect("portal request");

            assert_eq!(response.status, status.as_u16());
            assert!(!response.success);

            let result = super::portal_http_response_result(
                response,
                Some("object"),
                true,
                true,
                true,
                true,
            );

            assert_eq!(result.is_error, Some(true));
            let payload = result.structured_content.expect("structured payload");
            assert_eq!(payload["ok"], json!(false));
            assert_eq!(payload["error"]["code"], json!("portal.http_error"));
            assert_eq!(payload["auth"]["agent_token_attached"], json!(true));
            assert_eq!(
                payload["auth"]["access_service_token_attached"],
                json!(true)
            );
            assert_eq!(payload["auth"]["agent_token_requested"], json!(true));
            assert_eq!(
                payload["auth"]["access_service_token_requested"],
                json!(true)
            );
            assert_eq!(payload["auth"]["has_configured_agent_token"], json!(true));
            assert_eq!(
                payload["auth"]["has_configured_access_service_token"],
                json!(true)
            );
            assert_eq!(payload["response"]["token"], json!("<redacted>"));
            assert_eq!(
                payload["response"]["nested"]["client_secret"],
                json!("<redacted>")
            );

            let serialized = serde_json::to_string(&payload).expect("serialize payload");
            assert!(!serialized.contains(&agent_material));
            assert!(!serialized.contains(&access_material));
            assert!(!serialized.contains(&request_probe));
            assert!(!serialized.contains(&response_token_probe));
            assert!(!serialized.contains(&response_material_probe));
        }
    }

    #[tokio::test]
    async fn lock_first_publish_succeeds_when_gate_passes_and_route_converges() {
        #[derive(Clone)]
        struct CallState {
            dns_post_calls: Arc<AtomicUsize>,
            dns_records: Arc<Mutex<Vec<Value>>>,
        }

        async fn list_access_apps() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "app-1",
                    "name": "preview-app",
                    "domain": "preview.example.com",
                    "aud": "aud-1"
                }]
            }))
        }

        async fn list_access_policies() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "pol-1",
                    "name": "allow",
                    "decision": "allow",
                    "include": {
                        "email": {
                            "email": ["agent@example.com"]
                        }
                    }
                }]
            }))
        }

        async fn list_dns_records(State(state): State<CallState>) -> Json<Value> {
            let records = state.dns_records.lock().expect("dns_records lock").clone();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": records,
            }))
        }

        async fn upsert_dns_record(
            State(state): State<CallState>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            state.dns_post_calls.fetch_add(1, Ordering::SeqCst);
            let hostname = payload
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let content = payload
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let proxied = payload.get("proxied").and_then(Value::as_bool);
            let ttl = payload
                .get("ttl")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
            let mut records = state.dns_records.lock().expect("dns_records lock");
            let record = json!({
                "id": "rec-1",
                "name": hostname,
                "type": "CNAME",
                "content": content,
                "proxied": proxied,
                "ttl": ttl,
            });
            if let Some(existing) = records.iter_mut().find(|item| {
                item.get("name").and_then(Value::as_str) == Some("preview.example.com")
            }) {
                *existing = record.clone();
            } else {
                records.push(record.clone());
            }
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": record,
            }))
        }

        let state = CallState {
            dns_post_calls: Arc::new(AtomicUsize::new(0)),
            dns_records: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route("/accounts/acct-1/access/apps", get(list_access_apps))
            .route(
                "/accounts/acct-1/access/apps/app-1/policies",
                get(list_access_policies),
            )
            .route(
                "/zones/zone-1/dns_records",
                get(list_dns_records).post(upsert_dns_record),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_lock_first_publish(
                Parameters(LockFirstPublishArgs {
                    account_id: None,
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    target: "tunnel.cfargotunnel.com".to_string(),
                    proxied: Some(true),
                    ttl: Some(1),
                    override_publish_guard: false,
                    override_reason: None,
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["state_machine"]["terminal_state"],
            json!("published")
        );
        assert_eq!(payload["route_verification"]["state"], json!("matched"));
        assert_eq!(state.dns_post_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lock_first_publish_blocks_without_access_gate_and_skips_route_mutation() {
        #[derive(Clone)]
        struct CallState {
            dns_get_calls: Arc<AtomicUsize>,
            dns_post_calls: Arc<AtomicUsize>,
        }

        async fn list_access_apps() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        async fn list_dns(State(state): State<CallState>) -> Json<Value> {
            state.dns_get_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        async fn mutate_dns(State(state): State<CallState>) -> Json<Value> {
            state.dns_post_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {}
            }))
        }

        let state = CallState {
            dns_get_calls: Arc::new(AtomicUsize::new(0)),
            dns_post_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route("/accounts/acct-1/access/apps", get(list_access_apps))
            .route("/zones/zone-1/dns_records", get(list_dns).post(mutate_dns))
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_lock_first_publish(
                Parameters(LockFirstPublishArgs {
                    account_id: None,
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    target: "tunnel.cfargotunnel.com".to_string(),
                    proxied: Some(true),
                    ttl: Some(1),
                    override_publish_guard: false,
                    override_reason: None,
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["error"]["code"],
            json!("publish.policy_gate_denied")
        );
        assert_eq!(state.dns_get_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.dns_post_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verify_http_gate_reports_access_gated_state() {
        async fn gated_probe() -> axum::http::StatusCode {
            axum::http::StatusCode::FORBIDDEN
        }

        let router = Router::new().route("/probe/gated", get(gated_probe));
        let base_url = spawn_router(router).await;
        let server = test_server(base_url.clone());

        let result = server
            .cloudflare_verify_http_gate(Parameters(VerifyHttpGateArgs {
                url: format!("{base_url}/probe/gated"),
                expected_state: "access_gated".to_string(),
                timeout_ms: Some(2_000),
            }))
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(payload["verification"]["state"], json!("access_gated"));
        let last_known = server
            .verification_status
            .lock()
            .expect("verification lock")
            .clone()
            .expect("verification status");
        assert_eq!(last_known.state.as_str(), "access_gated");
    }

    #[tokio::test]
    async fn verify_http_gate_returns_typed_unexpected_state_error() {
        async fn open_probe() -> axum::http::StatusCode {
            axum::http::StatusCode::OK
        }

        let router = Router::new().route("/probe/open", get(open_probe));
        let base_url = spawn_router(router).await;
        let server = test_server(base_url.clone());

        let result = server
            .cloudflare_verify_http_gate(Parameters(VerifyHttpGateArgs {
                url: format!("{base_url}/probe/open"),
                expected_state: "access_gated".to_string(),
                timeout_ms: Some(2_000),
            }))
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["error"]["code"],
            json!("verification.unexpected_state")
        );
        assert_eq!(payload["verification"]["state"], json!("origin_reachable"));
    }

    #[tokio::test]
    async fn emergency_unpublish_is_idempotent_across_repeated_runs() {
        #[derive(Clone)]
        struct CallState {
            dns_delete_calls: Arc<AtomicUsize>,
            dns_records: Arc<Mutex<Vec<Value>>>,
        }

        async fn list_dns_records(State(state): State<CallState>) -> Json<Value> {
            let records = state.dns_records.lock().expect("dns_records lock").clone();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": records,
            }))
        }

        async fn delete_dns_record(
            Path(record_id): Path<String>,
            State(state): State<CallState>,
        ) -> Json<Value> {
            state.dns_delete_calls.fetch_add(1, Ordering::SeqCst);
            let mut records = state.dns_records.lock().expect("dns_records lock");
            records.retain(|record| {
                record.get("id").and_then(Value::as_str) != Some(record_id.as_str())
            });
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {}
            }))
        }

        let state = CallState {
            dns_delete_calls: Arc::new(AtomicUsize::new(0)),
            dns_records: Arc::new(Mutex::new(vec![json!({
                "id": "rec-1",
                "name": "preview.example.com",
                "type": "CNAME",
                "content": "tunnel.cfargotunnel.com",
                "proxied": true,
                "ttl": 1
            })])),
        };
        let router = Router::new()
            .route("/zones/zone-1/dns_records", get(list_dns_records))
            .route(
                "/zones/zone-1/dns_records/{record_id}",
                axum::routing::delete(delete_dns_record),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let first = server
            .cloudflare_emergency_unpublish(
                Parameters(EmergencyUnpublishArgs {
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    reason: Some("containment".to_string()),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("first call");
        assert_eq!(first.is_error, Some(false));
        let first_payload = first.structured_content.expect("structured payload");
        assert_eq!(first_payload["result"]["already_absent"], json!(false));

        let second = server
            .cloudflare_emergency_unpublish(
                Parameters(EmergencyUnpublishArgs {
                    zone_id: None,
                    hostname: "preview.example.com".to_string(),
                    reason: Some("containment".to_string()),
                    dry_run: false,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("second call");
        assert_eq!(second.is_error, Some(false));
        let second_payload = second.structured_content.expect("structured payload");
        assert_eq!(second_payload["result"]["already_absent"], json!(true));
        assert_eq!(state.dns_delete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn apply_access_allowlist_dry_run_has_no_policy_write_side_effect() {
        #[derive(Clone)]
        struct CallState {
            get_calls: Arc<AtomicUsize>,
            put_calls: Arc<AtomicUsize>,
        }

        async fn list_access_policies(State(state): State<CallState>) -> Json<Value> {
            state.get_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "pol-1",
                    "name": "allow",
                    "decision": "allow",
                    "include": {
                        "email": {
                            "email": ["existing@example.com"]
                        }
                    }
                }]
            }))
        }

        async fn replace_access_policies(State(state): State<CallState>) -> Json<Value> {
            state.put_calls.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        let state = CallState {
            get_calls: Arc::new(AtomicUsize::new(0)),
            put_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/access/apps/app-1/policies",
                get(list_access_policies).put(replace_access_policies),
            )
            .with_state(state.clone());
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_apply_access_allowlist(
                Parameters(ApplyAccessAllowlistArgs {
                    account_id: None,
                    app_id: "app-1".to_string(),
                    mode: "additive".to_string(),
                    requested_principals: vec!["new@example.com".to_string()],
                    dry_run: true,
                }),
                Extension(test_tool_parts()),
            )
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(false));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(payload["dry_run"], json!(true));
        assert_eq!(state.get_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.put_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn preflight_override_requires_reason() {
        async fn list_access_apps() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": []
            }))
        }

        let router = Router::new().route("/accounts/acct-1/access/apps", get(list_access_apps));
        let base_url = spawn_router(router).await;
        let server = test_server(base_url);

        let result = server
            .cloudflare_publish_preflight(Parameters(super::PublishPreflightArgs {
                account_id: None,
                hostname: "preview.example.com".to_string(),
                override_publish_guard: true,
                override_reason: None,
            }))
            .await
            .expect("tool call");

        assert_eq!(result.is_error, Some(true));
        let payload = result.structured_content.expect("structured payload");
        assert_eq!(
            payload["policy_gate"]["decision"]["code"],
            json!("PUBLISH_OVERRIDE_REASON_REQUIRED")
        );
    }
}
