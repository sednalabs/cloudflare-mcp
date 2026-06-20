use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheRulePhase {
    Request,
    Response,
}

impl CacheRulePhase {
    pub fn parse(value: &str) -> Result<Self, CacheValidationError> {
        match value.trim() {
            "request" | "http_request_cache_settings" | "cache_rules" => Ok(Self::Request),
            "response" | "http_response_cache_settings" | "cache_response_rules" => {
                Ok(Self::Response)
            }
            _ => Err(CacheValidationError::new(
                "cache.invalid_rule_phase",
                "phase must be request/http_request_cache_settings or response/http_response_cache_settings",
                "Use phase='request' for Cache Rules or phase='response' for Cache Response Rules.",
            )),
        }
    }

    pub fn cloudflare_name(self) -> &'static str {
        match self {
            Self::Request => "http_request_cache_settings",
            Self::Response => "http_response_cache_settings",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheRulesAction {
    Get,
    Append,
    Upsert,
    Delete,
    ReplaceAll,
}

impl CacheRulesAction {
    pub fn parse(value: &str) -> Result<Self, CacheValidationError> {
        match value.trim() {
            "get" => Ok(Self::Get),
            "append" => Ok(Self::Append),
            "upsert" => Ok(Self::Upsert),
            "delete" => Ok(Self::Delete),
            "replace_all" => Ok(Self::ReplaceAll),
            _ => Err(CacheValidationError::new(
                "cache.invalid_rules_action",
                "action must be get, append, upsert, delete, or replace_all",
                "Choose a supported cache rules operation.",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Append => "append",
            Self::Upsert => "upsert",
            Self::Delete => "delete",
            Self::ReplaceAll => "replace_all",
        }
    }

    pub fn mutates(self) -> bool {
        !matches!(self, Self::Get)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheZoneSettingAction {
    Get,
    Set,
}

impl CacheZoneSettingAction {
    pub fn parse(value: &str) -> Result<Self, CacheValidationError> {
        match value.trim() {
            "get" => Ok(Self::Get),
            "set" | "update" => Ok(Self::Set),
            _ => Err(CacheValidationError::new(
                "cache.invalid_zone_setting_action",
                "action must be get or set",
                "Use get for readback or set for a Cloudflare zone setting update.",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Set => "set",
        }
    }

    pub fn mutates(self) -> bool {
        matches!(self, Self::Set)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CacheResourceAction {
    Get,
    Update,
    Delete,
    StartClear,
    Status,
    List,
    Upsert,
    BatchUpsert,
    BatchDelete,
}

impl CacheResourceAction {
    pub fn parse(value: &str) -> Result<Self, CacheValidationError> {
        match value.trim() {
            "get" => Ok(Self::Get),
            "update" | "set" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "start_clear" | "clear" => Ok(Self::StartClear),
            "status" => Ok(Self::Status),
            "list" => Ok(Self::List),
            "upsert" => Ok(Self::Upsert),
            "batch_upsert" => Ok(Self::BatchUpsert),
            "batch_delete" => Ok(Self::BatchDelete),
            _ => Err(CacheValidationError::new(
                "cache.invalid_resource_action",
                "unsupported cache resource action",
                "Use one of get, update, delete, start_clear, status, list, upsert, batch_upsert, or batch_delete.",
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::StartClear => "start_clear",
            Self::Status => "status",
            Self::List => "list",
            Self::Upsert => "upsert",
            Self::BatchUpsert => "batch_upsert",
            Self::BatchDelete => "batch_delete",
        }
    }

    pub fn mutates(self) -> bool {
        !matches!(self, Self::Get | Self::Status | Self::List)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct CachePurgePayload {
    #[serde(default)]
    pub everything: bool,
    #[serde(default)]
    pub files: Option<Vec<Value>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    #[serde(default)]
    pub prefixes: Option<Vec<String>>,
}

impl CachePurgePayload {
    pub fn mode(&self) -> Result<&'static str, CacheValidationError> {
        let mut modes = Vec::new();
        if self.everything {
            modes.push("everything");
        }
        if has_values(self.files.as_ref()) {
            modes.push("files");
        }
        if has_strings(self.tags.as_ref()) {
            modes.push("tags");
        }
        if has_strings(self.hosts.as_ref()) {
            modes.push("hosts");
        }
        if has_strings(self.prefixes.as_ref()) {
            modes.push("prefixes");
        }

        match modes.as_slice() {
            [mode] => Ok(mode),
            [] => Err(CacheValidationError::new(
                "cache.purge_mode_required",
                "exactly one purge mode is required",
                "Set exactly one of everything, files, tags, hosts, or prefixes.",
            )),
            _ => Err(CacheValidationError::new(
                "cache.purge_mode_conflict",
                "only one purge mode can be used per call",
                "Split mixed purge requests into separate calls.",
            )),
        }
    }

    pub fn request_body(&self) -> Result<Value, CacheValidationError> {
        let mode = self.mode()?;
        match mode {
            "everything" => Ok(json!({ "purge_everything": true })),
            "files" => Ok(json!({ "files": self.files.clone().unwrap_or_default() })),
            "tags" => Ok(json!({ "tags": normalized_strings(self.tags.as_ref()) })),
            "hosts" => Ok(json!({ "hosts": normalized_strings(self.hosts.as_ref()) })),
            "prefixes" => Ok(json!({ "prefixes": normalized_strings(self.prefixes.as_ref()) })),
            _ => unreachable!("validated purge mode"),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CacheValidationError {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
}

impl CacheValidationError {
    pub fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            hint,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolDiscoveryEntry {
    pub name: &'static str,
    pub group: &'static str,
    pub read_only: bool,
    pub description: &'static str,
    pub keywords: &'static [&'static str],
}

pub const TOOL_DISCOVERY: &[ToolDiscoveryEntry] = &[
    ToolDiscoveryEntry {
        name: "find_tools",
        group: "discovery",
        read_only: true,
        description: "Search Cloudflare MCP tools and produce a narrow allowed_tools list plus optional MCP schemas for non-hosted deferred-loading clients.",
        keywords: &["search", "find", "tool_search", "defer_loading", "discover"],
    },
    ToolDiscoveryEntry {
        name: "api_prepare_call",
        group: "api",
        read_only: true,
        description: "Resolve a Cloudflare REST operation from search terms and return exact api_read/api_mutate call arguments.",
        keywords: &[
            "api",
            "rest",
            "prepare",
            "resolve",
            "operation",
            "operation_id",
            "fallback",
            "template",
        ],
    },
    ToolDiscoveryEntry {
        name: "account_billing_usage",
        group: "billing",
        read_only: true,
        description: "Read Cloudflare account PayGo or billable usage records for billing spike investigations.",
        keywords: &[
            "billing", "billable", "usage", "paygo", "cost", "spend", "graph", "d1", "rows",
            "written", "spike",
        ],
    },
    ToolDiscoveryEntry {
        name: "graphql_analytics_query",
        group: "analytics",
        read_only: true,
        description: "Run read-only Cloudflare Analytics GraphQL queries for product metrics such as D1 rows read/written attribution.",
        keywords: &[
            "graphql",
            "analytics",
            "billing",
            "d1",
            "graph",
            "rows",
            "read",
            "written",
            "queries",
            "attribution",
            "usage",
            "metrics",
            "spike",
        ],
    },
    ToolDiscoveryEntry {
        name: "waf_ruleset_summary",
        group: "waf",
        read_only: true,
        description: "Read WAF custom, managed, and rate-limit Rulesets entrypoints with compact rule summaries.",
        keywords: &[
            "waf",
            "firewall",
            "ruleset",
            "rules",
            "managed",
            "custom",
            "rate",
            "limit",
            "http_request_firewall_custom",
            "http_request_firewall_managed",
            "http_ratelimit",
            "security",
        ],
    },
    ToolDiscoveryEntry {
        name: "waf_security_events_summary",
        group: "waf",
        read_only: true,
        description: "Query Cloudflare Security Events via firewallEventsAdaptive and return grouped WAF analytics plus recent samples.",
        keywords: &[
            "waf",
            "firewall",
            "security",
            "events",
            "analytics",
            "graphql",
            "firewallEventsAdaptive",
            "blocked",
            "challenge",
            "managed_challenge",
            "sampled",
            "source",
            "path",
            "rule",
        ],
    },
    ToolDiscoveryEntry {
        name: "waf_rule_activity",
        group: "waf",
        read_only: true,
        description: "Find a WAF rule in current Rulesets and query recent Security Events for that rule id.",
        keywords: &[
            "waf",
            "firewall",
            "rule",
            "rule_id",
            "activity",
            "events",
            "analytics",
            "ruleset",
            "blocked",
            "false_positive",
        ],
    },
    ToolDiscoveryEntry {
        name: "waf_ruleset_plan_change",
        group: "waf",
        read_only: true,
        description: "Plan typed WAF Ruleset edits with stable diff, rule-cap checks, list checks, ordering, and a confirmation token.",
        keywords: &[
            "waf",
            "firewall",
            "ruleset",
            "plan",
            "change",
            "diff",
            "dry_run",
            "rule_cap",
            "stale_list",
            "false_positive",
            "managed_challenge",
            "block",
        ],
    },
    ToolDiscoveryEntry {
        name: "waf_ruleset_apply_change",
        group: "waf",
        read_only: false,
        description: "Apply a planned WAF Ruleset edit with confirmation, ruleset readback, audit metadata, and optional Security Events context.",
        keywords: &[
            "waf",
            "firewall",
            "ruleset",
            "apply",
            "change",
            "confirmation",
            "readback",
            "security_events",
            "audit",
            "operator",
        ],
    },
    ToolDiscoveryEntry {
        name: "cache_purge",
        group: "cache",
        read_only: false,
        description: "Purge Cloudflare cache by everything, files, URL headers, tags, hosts, or prefixes.",
        keywords: &[
            "cache",
            "purge",
            "clear",
            "invalidate",
            "tags",
            "hosts",
            "prefixes",
            "files",
        ],
    },
    ToolDiscoveryEntry {
        name: "r2_get_object",
        group: "r2",
        read_only: true,
        description: "Read or download a private Cloudflare R2 object using signed S3-compatible GET requests.",
        keywords: &[
            "r2", "object", "bucket", "download", "read", "s3", "storage", "get",
        ],
    },
    ToolDiscoveryEntry {
        name: "r2_inspect_object",
        group: "r2",
        read_only: true,
        description: "Inspect private Cloudflare R2 object metadata using signed S3-compatible HEAD requests.",
        keywords: &[
            "r2", "object", "bucket", "inspect", "metadata", "head", "s3", "storage",
        ],
    },
    ToolDiscoveryEntry {
        name: "r2_put_object",
        group: "r2",
        read_only: false,
        description: "Write private Cloudflare R2 objects using signed S3-compatible PUT requests.",
        keywords: &[
            "r2", "object", "bucket", "upload", "write", "put", "s3", "storage",
        ],
    },
    ToolDiscoveryEntry {
        name: "d1_list_databases",
        group: "d1",
        read_only: true,
        description: "List Cloudflare D1 databases for an account.",
        keywords: &["d1", "database", "databases", "list", "sqlite", "read"],
    },
    ToolDiscoveryEntry {
        name: "d1_get_database",
        group: "d1",
        read_only: true,
        description: "Get Cloudflare D1 database metadata by database_id.",
        keywords: &["d1", "database", "metadata", "get", "inspect", "read"],
    },
    ToolDiscoveryEntry {
        name: "d1_rename_database",
        group: "d1",
        read_only: false,
        description: "Rename a Cloudflare D1 database using the curated partial-update endpoint.",
        keywords: &["d1", "database", "rename", "update", "patch", "mutate"],
    },
    ToolDiscoveryEntry {
        name: "d1_delete_database",
        group: "d1",
        read_only: false,
        description: "Delete a Cloudflare D1 database with dry-run confirmation-token safety.",
        keywords: &["d1", "database", "delete", "remove", "drop", "high_risk"],
    },
    ToolDiscoveryEntry {
        name: "d1_inspect_schema",
        group: "d1",
        read_only: true,
        description: "Inspect D1 application tables, indexes, views, and columns using read-only SQLite catalog queries with optional include filters; skips Cloudflare internal _cf_* objects.",
        keywords: &[
            "d1",
            "database",
            "schema",
            "tables",
            "columns",
            "sqlite",
            "inspect",
            "read",
            "include_tables",
            "filter",
            "internal",
        ],
    },
    ToolDiscoveryEntry {
        name: "d1_query_read_only",
        group: "d1",
        read_only: true,
        description: "Run or execute one read-only Cloudflare D1 SQL SELECT/query statement against a database after restricted-SQL policy approval, returning rows.",
        keywords: &[
            "cloudflare",
            "d1",
            "database",
            "query",
            "sql",
            "select",
            "execute",
            "run",
            "read",
            "read-only",
            "read_only",
            "readonly",
            "sqlite",
            "rows",
        ],
    },
    ToolDiscoveryEntry {
        name: "d1_validate_query",
        group: "d1",
        read_only: true,
        description: "Validate one read-only D1 SQL statement against application schema metadata without executing it.",
        keywords: &[
            "d1",
            "database",
            "query",
            "sql",
            "validate",
            "schema",
            "columns",
            "plan",
            "preflight",
        ],
    },
    ToolDiscoveryEntry {
        name: "d1_execute_write",
        group: "d1",
        read_only: false,
        description: "Execute one audited D1 row-write SQL statement with dry-run safety.",
        keywords: &[
            "d1", "database", "write", "sql", "insert", "update", "delete", "replace", "mutate",
        ],
    },
    ToolDiscoveryEntry {
        name: "d1_apply_migrations",
        group: "d1",
        read_only: false,
        description: "Apply local Wrangler-style D1 SQL migration files with dry-run safety.",
        keywords: &[
            "d1",
            "database",
            "migration",
            "migrations",
            "sql",
            "apply",
            "wrangler",
            "mutate",
        ],
    },
    ToolDiscoveryEntry {
        name: "analytics_engine_query",
        group: "analytics_engine",
        read_only: true,
        description: "Run one read-only Workers Analytics Engine SQL statement.",
        keywords: &[
            "analytics",
            "engine",
            "analytics_engine",
            "ae",
            "workers",
            "sql",
            "query",
            "read",
        ],
    },
    ToolDiscoveryEntry {
        name: "analytics_engine_validate_query",
        group: "analytics_engine",
        read_only: true,
        description: "Validate one read-only Workers Analytics Engine SQL statement against dataset and column schema hints without executing it.",
        keywords: &[
            "analytics",
            "engine",
            "analytics_engine",
            "ae",
            "workers",
            "sql",
            "validate",
            "schema",
            "preflight",
        ],
    },
    ToolDiscoveryEntry {
        name: "analytics_engine_describe_schema",
        group: "analytics_engine",
        read_only: true,
        description: "Describe Workers Analytics Engine dataset schema hints, including blob, double, and index mappings.",
        keywords: &[
            "analytics",
            "engine",
            "analytics_engine",
            "ae",
            "workers",
            "schema",
            "datasets",
            "blobs",
            "doubles",
            "indexes",
        ],
    },
    ToolDiscoveryEntry {
        name: "analytics_engine_list_datasets",
        group: "analytics_engine",
        read_only: true,
        description: "List Workers Analytics Engine datasets.",
        keywords: &[
            "analytics",
            "engine",
            "analytics_engine",
            "ae",
            "workers",
            "datasets",
            "tables",
            "show",
        ],
    },
    ToolDiscoveryEntry {
        name: "workers_upload_script",
        group: "workers",
        read_only: false,
        description: "Upload a Worker module script or prebuilt multipart Worker bundle with dry-run safety and settings readback.",
        keywords: &[
            "worker",
            "workers",
            "script",
            "upload",
            "deploy",
            "deployment",
            "module",
            "multipart",
            "wrangler",
            "proof",
            "readback",
        ],
    },
    ToolDiscoveryEntry {
        name: "account_api_tokens",
        group: "api",
        read_only: false,
        description: "Curated account-owned API token management: permission groups, list/get/verify, create/update/delete, and roll.",
        keywords: &[
            "api",
            "token",
            "tokens",
            "user",
            "account",
            "permission",
            "permission_groups",
            "create",
            "roll",
            "rotate",
            "verify",
            "wrangler",
        ],
    },
    ToolDiscoveryEntry {
        name: "account_api_token_permission_plan",
        group: "api",
        read_only: true,
        description: "Read-only account API token permission delta planner that preserves existing scopes and returns the safe update dry-run payload.",
        keywords: &[
            "api",
            "token",
            "tokens",
            "user",
            "account",
            "permission",
            "permissions",
            "permission_groups",
            "scope",
            "scopes",
            "delta",
            "plan",
            "add",
            "remove",
            "least_privilege",
        ],
    },
    ToolDiscoveryEntry {
        name: "queues_list",
        group: "queues",
        read_only: true,
        description: "List Cloudflare Queues.",
        keywords: &["queue", "queues", "list", "bindings", "workers"],
    },
    ToolDiscoveryEntry {
        name: "queues_get",
        group: "queues",
        read_only: true,
        description: "Get Cloudflare Queue details and settings.",
        keywords: &["queue", "queues", "get", "settings", "details", "workers"],
    },
    ToolDiscoveryEntry {
        name: "queues_get_metrics",
        group: "queues",
        read_only: true,
        description: "Get Queue backlog metrics including depth, bytes, and oldest message age.",
        keywords: &[
            "queue",
            "queues",
            "metrics",
            "depth",
            "backlog",
            "message_age",
            "oldest",
            "health",
        ],
    },
    ToolDiscoveryEntry {
        name: "queues_list_consumers",
        group: "queues",
        read_only: true,
        description: "List Queue consumers and their retry/DLQ settings.",
        keywords: &[
            "queue",
            "queues",
            "consumer",
            "consumers",
            "retry",
            "dlq",
            "dead_letter",
            "status",
        ],
    },
    ToolDiscoveryEntry {
        name: "queues_health",
        group: "queues",
        read_only: true,
        description: "Read Queue health across backlog metrics, consumers, delivery pause state, purge status, and configured DLQ backlog.",
        keywords: &[
            "queue",
            "queues",
            "health",
            "readback",
            "depth",
            "backlog",
            "dlq",
            "dead_letter",
            "consumer",
            "retry",
            "failure",
            "message_age",
        ],
    },
    ToolDiscoveryEntry {
        name: "cache_zone_setting",
        group: "cache",
        read_only: false,
        description: "Read or update zone-level cache settings such as browser TTL, cache level, development mode, and origin cache control.",
        keywords: &[
            "cache",
            "zone",
            "settings",
            "browser_cache_ttl",
            "cache_level",
            "development_mode",
            "edge_cache_ttl",
        ],
    },
    ToolDiscoveryEntry {
        name: "cache_rules",
        group: "cache",
        read_only: false,
        description: "Manage Cache Rules and Cache Response Rules through Cloudflare Rulesets entrypoint phases.",
        keywords: &[
            "cache",
            "rules",
            "rulesets",
            "http_request_cache_settings",
            "http_response_cache_settings",
            "ttl",
            "bypass",
        ],
    },
    ToolDiscoveryEntry {
        name: "cache_reserve",
        group: "cache",
        read_only: false,
        description: "Read, update, clear, and inspect Cloudflare Cache Reserve state.",
        keywords: &["cache", "reserve", "clear", "storage"],
    },
    ToolDiscoveryEntry {
        name: "cache_tiered",
        group: "cache",
        read_only: false,
        description: "Read, update, or delete Smart Tiered Cache and Regional Tiered Cache settings.",
        keywords: &["cache", "tiered", "smart", "regional", "upper tier"],
    },
    ToolDiscoveryEntry {
        name: "cache_variants",
        group: "cache",
        read_only: false,
        description: "Read, update, or delete Cloudflare cache variants settings.",
        keywords: &[
            "cache",
            "variants",
            "variant",
            "image",
            "content negotiation",
        ],
    },
    ToolDiscoveryEntry {
        name: "cache_origin_regions",
        group: "cache",
        read_only: false,
        description: "Manage deprecated origin cloud-region cache mappings where Cloudflare still exposes the API.",
        keywords: &[
            "cache",
            "origin",
            "regions",
            "cloud",
            "deprecated",
            "regional",
        ],
    },
];

pub fn discovery_entry(name: &str) -> Option<&'static ToolDiscoveryEntry> {
    TOOL_DISCOVERY.iter().find(|entry| entry.name == name)
}

pub fn purge_confirmation_token(zone_id: &str, environment_id: Option<&str>) -> String {
    short_token(
        "purge_everything",
        zone_id,
        environment_id.unwrap_or("zone"),
    )
}

pub fn replace_rules_confirmation_token(zone_id: &str, phase: CacheRulePhase) -> String {
    short_token("replace_all_cache_rules", zone_id, phase.cloudflare_name())
}

fn short_token(kind: &str, scope: &str, detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(scope.as_bytes());
    hasher.update(b"\0");
    hasher.update(detail.as_bytes());
    let digest = hasher.finalize();
    format!("{kind}:{}", hex_prefix(&digest, 12))
}

fn hex_prefix(bytes: &[u8], nibbles: usize) -> String {
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

fn has_values(values: Option<&Vec<Value>>) -> bool {
    values.is_some_and(|values| !values.is_empty())
}

fn has_strings(values: Option<&Vec<String>>) -> bool {
    values.is_some_and(|values| values.iter().any(|value| !value.trim().is_empty()))
}

fn normalized_strings(values: Option<&Vec<String>>) -> Vec<String> {
    values
        .into_iter()
        .flatten()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CachePurgePayload, CacheRulePhase, purge_confirmation_token,
        replace_rules_confirmation_token,
    };

    #[test]
    fn purge_payload_requires_exactly_one_mode() {
        let missing = CachePurgePayload {
            everything: false,
            files: None,
            tags: None,
            hosts: None,
            prefixes: None,
        };
        assert_eq!(
            missing.mode().unwrap_err().code,
            "cache.purge_mode_required"
        );

        let mixed = CachePurgePayload {
            everything: true,
            files: Some(vec![json!("https://example.com/a")]),
            tags: None,
            hosts: None,
            prefixes: None,
        };
        assert_eq!(mixed.mode().unwrap_err().code, "cache.purge_mode_conflict");
    }

    #[test]
    fn purge_payload_supports_file_header_objects() {
        let payload = CachePurgePayload {
            everything: false,
            files: Some(vec![json!({
                "url": "https://example.com/a",
                "headers": { "CF-Device-Type": "mobile" }
            })]),
            tags: None,
            hosts: None,
            prefixes: None,
        };
        assert_eq!(
            payload.request_body().unwrap()["files"][0]["headers"]["CF-Device-Type"],
            "mobile"
        );
    }

    #[test]
    fn destructive_confirmation_tokens_are_stable() {
        assert_eq!(
            purge_confirmation_token("zone-1", None),
            purge_confirmation_token("zone-1", None)
        );
        assert_ne!(
            replace_rules_confirmation_token("zone-1", CacheRulePhase::Request),
            replace_rules_confirmation_token("zone-1", CacheRulePhase::Response)
        );
    }
}
