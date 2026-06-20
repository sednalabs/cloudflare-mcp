use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

fn null_as_default_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn null_to_default_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    null_as_default_vec(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub count: Option<u32>,
    pub total_count: Option<u32>,
    pub total_pages: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub status: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub proxied: Option<bool>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessApplication {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub aud: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: String,
    pub name: String,
    pub decision: Option<String>,
    pub include: Option<Value>,
    pub exclude: Option<Value>,
    pub require: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecordUpsertRequest {
    pub hostname: String,
    pub target: String,
    pub proxied: Option<bool>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRouteDisableResult {
    pub hostname: String,
    pub removed_record_ids: Vec<String>,
    pub already_absent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAppUpsertRequest {
    pub hostname: String,
    pub app_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AccessPolicyWrite {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub decision: String,
    pub include: Value,
    pub exclude: Option<Value>,
    pub require: Option<Value>,
    pub precedence: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerScript {
    pub id: Option<String>,
    #[serde(default)]
    pub script_name: Option<String>,
    pub created_on: Option<String>,
    pub modified_on: Option<String>,
    pub compatibility_date: Option<String>,
    pub compatibility_flags: Option<Vec<String>>,
    pub usage_model: Option<String>,
    #[serde(default)]
    pub bindings: Option<Vec<Value>>,
    #[serde(default)]
    pub script: Option<Value>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerSettings {
    pub bindings: Option<Vec<Value>>,
    pub compatibility_date: Option<String>,
    pub compatibility_flags: Option<Vec<String>>,
    pub usage_model: Option<String>,
    pub main_module: Option<String>,
    pub logpush: Option<bool>,
    pub placement: Option<Value>,
    pub limits: Option<Value>,
    pub migrations: Option<Value>,
    pub observability: Option<Value>,
    pub tags: Option<Vec<String>>,
    pub tail_consumers: Option<Value>,
    pub annotations: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct D1Database {
    #[serde(default)]
    pub uuid: Option<String>,
    pub name: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub file_size: Option<f64>,
    #[serde(default)]
    pub num_tables: Option<f64>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub read_replication: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagesStage {
    pub name: Option<String>,
    pub status: Option<String>,
    pub started_on: Option<String>,
    pub ended_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagesDeployment {
    pub id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, deserialize_with = "null_to_default_vec")]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub latest_stage: Option<PagesStage>,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default)]
    pub modified_on: Option<String>,
    #[serde(default)]
    pub deployment_trigger: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagesProject {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub subdomain: Option<String>,
    #[serde(default, deserialize_with = "null_to_default_vec")]
    pub domains: Vec<String>,
    #[serde(default)]
    pub production_branch: Option<String>,
    #[serde(default)]
    pub latest_deployment: Option<PagesDeployment>,
    #[serde(default)]
    pub canonical_deployment: Option<PagesDeployment>,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default)]
    pub deployment_configs: Option<Value>,
    #[serde(default)]
    pub build_config: Option<Value>,
    #[serde(default)]
    pub source: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagesDomain {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub domain_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub validation_data: Option<Value>,
    #[serde(default)]
    pub verification_data: Option<Value>,
    #[serde(default)]
    pub zone_tag: Option<String>,
    #[serde(default)]
    pub created_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PagesDeploymentTriggerRequest {
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub commit_hash: Option<String>,
    #[serde(default)]
    pub commit_message: Option<String>,
    #[serde(default)]
    pub commit_dirty: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProbe {
    pub capability: String,
    pub checked: bool,
    pub ok: bool,
    pub status: Option<u16>,
    pub code: Option<String>,
    pub permission_hint: String,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneIdentity {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub account: Option<ZoneIdentityAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneIdentityAccount {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Queue {
    #[serde(default)]
    pub queue_id: Option<String>,
    #[serde(default)]
    pub queue_name: Option<String>,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default)]
    pub modified_on: Option<String>,
    #[serde(default)]
    pub producers_total_count: Option<f64>,
    #[serde(default)]
    pub consumers_total_count: Option<f64>,
    #[serde(default, deserialize_with = "null_to_default_vec")]
    pub producers: Vec<Value>,
    #[serde(default, deserialize_with = "null_to_default_vec")]
    pub consumers: Vec<Value>,
    #[serde(default)]
    pub settings: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMetrics {
    #[serde(default)]
    pub backlog_bytes: Option<f64>,
    #[serde(default)]
    pub backlog_count: Option<f64>,
    #[serde(default)]
    pub oldest_message_timestamp_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesList {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub num_items: Option<f64>,
    #[serde(default)]
    pub num_referencing_filters: Option<f64>,
    #[serde(default)]
    pub created_on: Option<String>,
    #[serde(default)]
    pub modified_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BulkRedirectItemWrite {
    pub source_url: String,
    pub target_url: String,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub preserve_query_string: Option<bool>,
    #[serde(default)]
    pub include_subdomains: Option<bool>,
    #[serde(default)]
    pub subpath_matching: Option<bool>,
    #[serde(default)]
    pub preserve_path_suffix: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesListOperation {
    #[serde(alias = "id")]
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruleset {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub phase: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, deserialize_with = "null_to_default_vec")]
    pub rules: Vec<Value>,
    #[serde(default)]
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRule {
    pub id: Option<String>,
    pub description: Option<String>,
    pub expression: Option<String>,
    pub action: Option<String>,
    pub action_parameters: Option<Value>,
    pub enabled: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRuleset {
    pub id: Option<String>,
    pub name: Option<String>,
    pub phase: Option<String>,
    pub kind: Option<String>,
    #[serde(default)]
    pub rules: Vec<CacheRule>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
