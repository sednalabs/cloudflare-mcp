use std::cmp;
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

use crate::cloudflare::model::{
    AccessAppUpsertRequest, AccessApplication, AccessPolicy, AccessPolicyWrite, CacheRuleset,
    D1Database, DnsRecord, DnsRecordUpsertRequest, DnsRouteDisableResult, Page, PageInfo, Tunnel,
    WorkerScript, WorkerSettings, ZoneIdentity,
};
use crate::config::{ApiTokenSource, CloudflareApiConfig};
use mcp_toolkit_observability::sanitize_error_message;

#[derive(Debug, Clone, Serialize)]
pub struct AdapterErrorPayload {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub retryable: bool,
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<ErrorClassificationPayload>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ErrorClassificationPayload {
    pub code: &'static str,
    pub next_step: &'static str,
}

#[derive(Debug, Clone, Error)]
#[error("{code}: {message}")]
pub struct AdapterError {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub retryable: bool,
    pub status: Option<u16>,
    cloudflare_api_error: Option<CloudflareApiError>,
    classification: Option<ErrorClassificationPayload>,
}

impl AdapterError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: sanitize_error_message(&message.into(), 512),
            hint,
            retryable: false,
            status: None,
            cloudflare_api_error: None,
            classification: None,
        }
    }

    fn with_cloudflare_api_error(mut self, error: Option<CloudflareApiError>) -> Self {
        self.cloudflare_api_error = error;
        self
    }

    fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    fn with_classification(mut self, classification: ErrorClassificationPayload) -> Self {
        self.classification = Some(classification);
        self
    }

    pub fn payload(&self) -> AdapterErrorPayload {
        AdapterErrorPayload {
            code: self.code,
            message: self.message.clone(),
            hint: self.hint,
            retryable: self.retryable,
            status: self.status,
            classification: self.classification.clone(),
        }
    }

    pub(crate) fn cloudflare_api_error_code(&self) -> Option<i64> {
        self.cloudflare_api_error
            .as_ref()
            .and_then(|error| error.code)
    }

    pub(crate) fn cloudflare_api_error_message(&self) -> Option<&str> {
        self.cloudflare_api_error
            .as_ref()
            .and_then(|error| error.message.as_deref())
    }
}

#[derive(Debug, Clone)]
pub struct CloudflareClient {
    pub(crate) cfg: CloudflareApiConfig,
    pub(crate) http: reqwest::Client,
    reconciliation_http: reqwest::Client,
    migration_write_http: reqwest::Client,
}

#[derive(Debug, Clone, Serialize)]
pub struct R2Object {
    pub bucket_name: String,
    pub object_key: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub range: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct R2ObjectMetadata {
    pub bucket_name: String,
    pub object_key: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub range: Option<String>,
    pub custom_metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct R2ObjectDownload {
    pub bucket_name: String,
    pub object_key: String,
    pub status: u16,
    pub output_path: String,
    pub bytes_written: u64,
    pub sha256: String,
    pub truncated: bool,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub range: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct R2PutObjectResult {
    pub bucket_name: String,
    pub object_key: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

type HmacSha256 = Hmac<Sha256>;

const WORKER_VERSION_PAGE_SIZE: u32 = 100;
const WORKER_VERSION_MAX_PAGES: u32 = 32;
const WORKER_VERSION_MAX_ITEMS: usize = 1024;
const D1_MIGRATION_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct WorkerVersionInventory {
    items: Vec<Value>,
    total_count: u32,
    total_pages: u32,
}

struct R2RequestOptions<'a> {
    range: Option<&'a str>,
    content_type: Option<&'a str>,
    metadata: &'a [(String, String)],
    body: Vec<u8>,
}

struct R2Response {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct R2OpenResponse {
    status: u16,
    headers: HeaderMap,
    response: reqwest::Response,
}

tokio::task_local! {
    static REQUEST_API_TOKEN_OVERRIDE: Option<String>;
}

pub async fn with_request_api_token_override<F, T>(token: Option<String>, future: F) -> T
where
    F: Future<Output = T>,
{
    REQUEST_API_TOKEN_OVERRIDE.scope(token, future).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryPolicy {
    Idempotent,
    NonIdempotent,
}

impl RetryPolicy {
    pub(crate) fn allows_retry(self) -> bool {
        matches!(self, Self::Idempotent)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct D1MigrationReconciliationBatch {
    pub(crate) result: Value,
    pub(crate) response_body_sha256: String,
    pub(crate) response_body_size_bytes: usize,
    pub(crate) lifecycle: D1MigrationReconciliationReadLifecycle,
}

#[derive(Debug, Clone)]
pub(crate) struct D1MigrationReconciliationBatchError {
    pub(crate) error: AdapterErrorPayload,
    pub(crate) provider_error: Option<D1MigrationProviderError>,
    pub(crate) response_body_sha256: Option<String>,
    pub(crate) response_body_size_bytes: Option<usize>,
    pub(crate) lifecycle: D1MigrationReconciliationReadLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct D1MigrationProviderError {
    pub(crate) code: i64,
    pub(crate) category: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct D1MigrationManifestWrite {
    pub(crate) result: Value,
    pub(crate) response_body_sha256: String,
    pub(crate) response_body_size_bytes: usize,
    pub(crate) lifecycle: D1MigrationManifestWriteLifecycle,
}

#[derive(Debug, Clone)]
pub(crate) struct D1MigrationManifestWriteError {
    pub(crate) error: AdapterErrorPayload,
    pub(crate) response_body_sha256: Option<String>,
    pub(crate) response_body_size_bytes: Option<usize>,
    pub(crate) lifecycle: D1MigrationManifestWriteLifecycle,
}

pub(crate) fn d1_migration_reconciliation_only_cause(error: &AdapterErrorPayload) -> Value {
    json!({
        "code": error.code,
        "status": error.status,
        "retryable": false,
        "operator_guidance": "reconciliation_only",
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct D1MigrationReconciliationReadLifecycle {
    pub(crate) dispatch_stage: &'static str,
    pub(crate) response_stage: &'static str,
    pub(crate) body_stage: &'static str,
    pub(crate) http_status: Option<u16>,
}

impl D1MigrationReconciliationReadLifecycle {
    const fn pre_dispatch() -> Self {
        Self {
            dispatch_stage: "pre_dispatch",
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
        }
    }

    const fn attempted_without_response() -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
        }
    }

    const fn response_received(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "not_read",
            http_status: Some(http_status),
        }
    }

    const fn body_partially_read(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "partially_read",
            http_status: Some(http_status),
        }
    }

    fn body_read_failed(http_status: u16, bytes_read: usize) -> Self {
        if bytes_read == 0 {
            Self::response_received(http_status)
        } else {
            Self::body_partially_read(http_status)
        }
    }

    const fn body_completely_read(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "completely_read",
            http_status: Some(http_status),
        }
    }

    pub(crate) fn provider_calls(self) -> usize {
        if self.dispatch_stage == "attempted" {
            1
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct D1MigrationManifestWriteLifecycle {
    pub(crate) dispatch_stage: &'static str,
    pub(crate) response_stage: &'static str,
    pub(crate) body_stage: &'static str,
    pub(crate) http_status: Option<u16>,
}

impl D1MigrationManifestWriteLifecycle {
    const fn pre_dispatch() -> Self {
        Self {
            dispatch_stage: "pre_dispatch",
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
        }
    }

    const fn attempted_without_response() -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "not_received",
            body_stage: "not_read",
            http_status: None,
        }
    }

    const fn response_received(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "not_read",
            http_status: Some(http_status),
        }
    }

    const fn body_partially_read(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "partially_read",
            http_status: Some(http_status),
        }
    }

    fn body_read_failed(http_status: u16, bytes_read: usize) -> Self {
        if bytes_read == 0 {
            Self::response_received(http_status)
        } else {
            Self::body_partially_read(http_status)
        }
    }

    const fn body_completely_read(http_status: u16) -> Self {
        Self {
            dispatch_stage: "attempted",
            response_stage: "received",
            body_stage: "completely_read",
            http_status: Some(http_status),
        }
    }

    pub(crate) fn provider_calls(self) -> usize {
        usize::from(self.dispatch_stage == "attempted")
    }
}

pub(crate) fn d1_migration_manifest_write_reconciliation_cause(
    failure: &D1MigrationManifestWriteError,
) -> Value {
    let mut cause = d1_migration_reconciliation_only_cause(&failure.error);
    let cause_fields = cause
        .as_object_mut()
        .expect("reconciliation-only cause is always an object");
    cause_fields.insert(
        "provider_write_lifecycle".to_string(),
        json!(failure.lifecycle),
    );
    cause_fields.insert(
        "response_body_sha256".to_string(),
        json!(failure.response_body_sha256),
    );
    cause_fields.insert(
        "response_body_size_bytes".to_string(),
        json!(failure.response_body_size_bytes),
    );
    cause
}

pub(crate) fn d1_migration_manifest_write_provider_result_cause(
    write: &D1MigrationManifestWrite,
    detail: &Value,
) -> Value {
    json!({
        "kind": "provider_result",
        "detail": {
            "code": detail.get("code"),
            "classification": detail.get("classification"),
            "message": detail.get("message"),
            "retryable": false,
            "operator_guidance": "reconciliation_only",
            "provider_write_lifecycle": write.lifecycle,
            "response_body_sha256": write.response_body_sha256,
            "response_body_size_bytes": write.response_body_size_bytes,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum D1EnvelopePolicy {
    Generic,
    RequireEmptyErrors,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareEnvelope<T> {
    pub(crate) success: bool,
    pub(crate) result: Option<T>,
    #[serde(default, deserialize_with = "null_as_default_vec")]
    pub(crate) errors: Vec<CloudflareApiError>,
    #[allow(dead_code)]
    #[serde(default, deserialize_with = "null_as_default_vec")]
    pub(crate) messages: Vec<CloudflareApiMessage>,
    #[serde(default)]
    pub(crate) result_info: Option<PageInfo>,
}

/// The manifest migration boundary cannot use the compatibility envelope above:
/// `errors` is deliberately normalised there so ordinary Cloudflare endpoints
/// can omit it or return `null`. For a one-time migration write, either shape
/// is ambiguous evidence and must not be mistaken for an empty error list.
#[derive(Debug, Deserialize)]
struct StrictD1MigrationManifestEnvelope<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Option<Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct CloudflareApiError {
    code: Option<i64>,
    message: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct CloudflareApiMessage {
    code: Option<i64>,
    message: Option<String>,
}

impl CloudflareClient {
    pub fn new(cfg: CloudflareApiConfig) -> Result<Self, AdapterError> {
        let http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .map_err(|err| {
                AdapterError::new(
                    "cloudflare.client_init_failed",
                    format!("failed to create HTTP client: {err}"),
                    "Verify TLS/runtime dependencies and CLOUDFLARE_MCP_API_TIMEOUT_MS settings.",
                )
            })?;
        let reconciliation_http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                AdapterError::new(
                    "cloudflare.client_init_failed",
                    format!("failed to create reconciliation HTTP client: {err}"),
                    "Verify TLS/runtime dependencies and CLOUDFLARE_MCP_API_TIMEOUT_MS settings.",
                )
            })?;
        let migration_write_http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                AdapterError::new(
                    "cloudflare.client_init_failed",
                    format!("failed to create migration-write HTTP client: {err}"),
                    "Verify TLS/runtime dependencies and CLOUDFLARE_MCP_API_TIMEOUT_MS settings.",
                )
            })?;
        Ok(Self {
            cfg,
            http,
            reconciliation_http,
            migration_write_http,
        })
    }

    pub fn default_account_id(&self) -> Option<&str> {
        self.cfg.default_account_id.as_deref()
    }

    pub fn api_token_source(&self) -> ApiTokenSource {
        self.cfg.api_token_source
    }

    pub fn api_token_header_name(&self) -> &str {
        self.cfg.api_token_header.as_str()
    }

    pub fn default_zone_id(&self) -> Option<&str> {
        self.cfg.default_zone_id.as_deref()
    }

    pub async fn get_zone_identity(&self, zone_id: &str) -> Result<ZoneIdentity, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{}", path_segment(zone_id)));

        let envelope: CloudflareEnvelope<ZoneIdentity> = self
            .send_envelope("cloudflare.zones.get", RetryPolicy::Idempotent, || {
                self.http
                    .get(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            })
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a zone result payload",
                "Inspect Cloudflare API response schema and ensure expected fields are present.",
            )
        })
    }

    pub async fn list_d1_databases(
        &self,
        account_id: &str,
        page: u32,
        per_page: u32,
        name: Option<&str>,
    ) -> Result<Page<D1Database>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database",
            path_segment(account_id)
        ));
        let name = name.map(str::trim).filter(|value| !value.is_empty());

        let envelope: CloudflareEnvelope<Vec<D1Database>> = self
            .send_envelope(
                "cloudflare.d1.databases.list",
                RetryPolicy::Idempotent,
                || {
                    let mut builder = self
                        .http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .query(&[("page", page), ("per_page", per_page)]);
                    if let Some(name) = name {
                        builder = builder.query(&[("name", name)]);
                    }
                    builder
                },
            )
            .await?;

        Ok(Page {
            items: envelope.result.unwrap_or_default(),
            page_info: envelope.result_info,
        })
    }

    pub async fn get_d1_database(
        &self,
        account_id: &str,
        database_id: &str,
    ) -> Result<D1Database, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let database_id = require_non_empty("database_id", database_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}",
            path_segment(account_id),
            path_segment(database_id),
        ));

        let envelope: CloudflareEnvelope<D1Database> = self
            .send_envelope(
                "cloudflare.d1.databases.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a D1 database result",
                "Verify D1 database response schema.",
            )
        })
    }

    pub async fn rename_d1_database(
        &self,
        account_id: &str,
        database_id: &str,
        name: &str,
    ) -> Result<D1Database, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let database_id = require_non_empty("database_id", database_id)?;
        let name = require_non_empty("name", name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}",
            path_segment(account_id),
            path_segment(database_id),
        ));
        let body = json!({ "name": name });

        let envelope: CloudflareEnvelope<D1Database> = self
            .send_envelope(
                "cloudflare.d1.databases.rename",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .patch(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&body)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a renamed D1 database result",
                "Verify D1 database response schema.",
            )
        })
    }

    pub async fn delete_d1_database(
        &self,
        account_id: &str,
        database_id: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let database_id = require_non_empty("database_id", database_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}",
            path_segment(account_id),
            path_segment(database_id),
        ));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.d1.databases.delete",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .delete(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        Ok(envelope.result.unwrap_or_else(|| json!({})))
    }

    pub async fn query_d1_database(
        &self,
        account_id: &str,
        database_id: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<Value, AdapterError> {
        self.execute_d1_query(
            "cloudflare.d1.databases.query",
            RetryPolicy::Idempotent,
            D1EnvelopePolicy::Generic,
            account_id,
            database_id,
            sql,
            params,
        )
        .await
    }

    pub async fn query_d1_database_read_only(
        &self,
        account_id: &str,
        database_id: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<Value, AdapterError> {
        match self
            .query_d1_database(account_id, database_id, sql, params)
            .await
        {
            Ok(result) => Ok(result),
            Err(err)
                if params.is_empty()
                    && is_d1_sqlite_auth_error(&err)
                    && is_d1_catalog_discovery_query(sql) =>
            {
                let table_list = self
                    .query_d1_database(account_id, database_id, "PRAGMA table_list", &[])
                    .await?;
                let mut schema = Map::new();
                schema.insert(
                    "objects".to_string(),
                    json!(d1_table_list_rows_to_schema_objects(&table_list)),
                );
                schema.insert("columns".to_string(), Value::Null);
                schema.insert(
                    "discovery_strategy".to_string(),
                    Value::String("pragma_table_list".to_string()),
                );
                schema.insert("discovery_fidelity".to_string(), d1_table_list_fidelity());
                Ok(d1_schema_to_query_result(Value::Object(schema)))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn execute_d1_database_write(
        &self,
        account_id: &str,
        database_id: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<Value, AdapterError> {
        self.execute_d1_query(
            "cloudflare.d1.databases.write",
            RetryPolicy::NonIdempotent,
            D1EnvelopePolicy::Generic,
            account_id,
            database_id,
            sql,
            params,
        )
        .await
    }

    /// Query a D1 migration ledger without discarding contradictory outer
    /// Cloudflare-envelope error evidence. This is intentionally narrower than
    /// the general D1 query surface: manifest application treats every provider
    /// ambiguity as a reconciliation boundary.
    pub async fn query_d1_migration_manifest(
        &self,
        account_id: &str,
        database_id: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<Value, AdapterError> {
        self.execute_d1_query(
            "cloudflare.d1.migration_manifest.query",
            RetryPolicy::Idempotent,
            D1EnvelopePolicy::RequireEmptyErrors,
            account_id,
            database_id,
            sql,
            params,
        )
        .await
    }

    /// Execute one internally constructed read-only reconciliation batch.
    ///
    /// Unlike the general D1 read adapter, this boundary performs exactly one
    /// HTTP attempt and retains a digest of the exact response bytes. The
    /// reconciliation state machine owns any subsequent complete read and
    /// compares canonical evidence across the two calls itself.
    pub(crate) async fn query_d1_migration_reconciliation_batch(
        &self,
        account_id: &str,
        database_id: &str,
        sql: &str,
    ) -> Result<D1MigrationReconciliationBatch, D1MigrationReconciliationBatchError> {
        let account_id = require_non_empty("account_id", account_id).map_err(|error| {
            D1MigrationReconciliationBatchError {
                error: error.payload(),
                provider_error: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                lifecycle: D1MigrationReconciliationReadLifecycle::pre_dispatch(),
            }
        })?;
        let database_id = require_non_empty("database_id", database_id).map_err(|error| {
            D1MigrationReconciliationBatchError {
                error: error.payload(),
                provider_error: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                lifecycle: D1MigrationReconciliationReadLifecycle::pre_dispatch(),
            }
        })?;
        let sql =
            require_non_empty("sql", sql).map_err(|error| D1MigrationReconciliationBatchError {
                error: error.payload(),
                provider_error: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                lifecycle: D1MigrationReconciliationReadLifecycle::pre_dispatch(),
            })?;
        let token = self
            .bearer_token()
            .map_err(|error| D1MigrationReconciliationBatchError {
                error: error.payload(),
                provider_error: None,
                response_body_sha256: None,
                response_body_size_bytes: None,
                lifecycle: D1MigrationReconciliationReadLifecycle::pre_dispatch(),
            })?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}/query",
            path_segment(account_id),
            path_segment(database_id),
        ));
        let response = self
            .reconciliation_http
            .post(url)
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            .json(&json!({"sql": sql}))
            .send()
            .await
            .map_err(|error| {
                let pre_dispatch = error.is_builder();
                let retryable = !pre_dispatch
                    && (error.is_timeout() || error.is_connect() || error.is_request());
                let code = if pre_dispatch {
                    "cloudflare.request_build_failed"
                } else if error.is_timeout() {
                    "cloudflare.timeout"
                } else {
                    "cloudflare.transport_error"
                };
                D1MigrationReconciliationBatchError {
                    error: AdapterError::new(
                        code,
                        format!(
                            "cloudflare.d1.migration_reconciliation.query request failed: {error}"
                        ),
                        "Treat reconciliation evidence as unavailable; do not retry the retained migration attempt.",
                    )
                    .with_retryable(retryable)
                    .payload(),
                    provider_error: None,
                    response_body_sha256: None,
                    response_body_size_bytes: None,
                    lifecycle: if pre_dispatch {
                        D1MigrationReconciliationReadLifecycle::pre_dispatch()
                    } else {
                        D1MigrationReconciliationReadLifecycle::attempted_without_response()
                    },
                }
            })?;
        let status = response.status();
        let status_code = status.as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > D1_MIGRATION_RESPONSE_MAX_BYTES as u64)
        {
            return Err(D1MigrationReconciliationBatchError {
                error: AdapterError::new(
                    "cloudflare.d1.migration_reconciliation_response_too_large",
                    "Cloudflare reconciliation response exceeded the exact-evidence byte limit",
                    "Reduce the bounded expectation scope; retain the lease and do not retry the migration attempt.",
                )
                .with_status(Some(status.as_u16()))
                .payload(),
                provider_error: None,
                response_body_sha256: None,
                response_body_size_bytes: response
                    .content_length()
                    .map(|length| usize::try_from(length).unwrap_or(usize::MAX)),
                lifecycle: D1MigrationReconciliationReadLifecycle::response_received(status_code),
            });
        }
        let initial_capacity = response
            .content_length()
            .map(|length| cmp::min(length as usize, D1_MIGRATION_RESPONSE_MAX_BYTES))
            .unwrap_or(0);
        let mut bytes = Vec::with_capacity(initial_capacity);
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| D1MigrationReconciliationBatchError {
                error: AdapterError::new(
                    "cloudflare.response_read_failed",
                    format!("failed reading Cloudflare reconciliation response body: {error}"),
                    "Treat reconciliation evidence as unavailable; do not retry the retained migration attempt.",
                )
                .with_status(Some(status_code))
                .payload(),
                provider_error: None,
                response_body_sha256: None,
                response_body_size_bytes: Some(bytes.len()),
                lifecycle: D1MigrationReconciliationReadLifecycle::body_read_failed(
                    status_code,
                    bytes.len(),
                ),
            })?;
            let observed_size = bytes.len().saturating_add(chunk.len());
            if observed_size > D1_MIGRATION_RESPONSE_MAX_BYTES {
                return Err(D1MigrationReconciliationBatchError {
                    error: AdapterError::new(
                        "cloudflare.d1.migration_reconciliation_response_too_large",
                        "Cloudflare reconciliation response exceeded the exact-evidence byte limit",
                        "Reduce the bounded expectation scope; retain the lease and do not retry the migration attempt.",
                    )
                    .with_status(Some(status.as_u16()))
                    .payload(),
                    provider_error: None,
                    response_body_sha256: None,
                    response_body_size_bytes: Some(observed_size),
                    lifecycle:
                        D1MigrationReconciliationReadLifecycle::body_partially_read(status_code),
                });
            }
            hasher.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        let response_body_size_bytes = bytes.len();
        let response_body_sha256 = format!("{:x}", hasher.finalize());
        let evidence_error =
            |error: AdapterError, provider_error: Option<D1MigrationProviderError>| {
                D1MigrationReconciliationBatchError {
                    error: error.payload(),
                    provider_error,
                    response_body_sha256: Some(response_body_sha256.clone()),
                    response_body_size_bytes: Some(response_body_size_bytes),
                    lifecycle: D1MigrationReconciliationReadLifecycle::body_completely_read(
                        status_code,
                    ),
                }
            };
        let body = std::str::from_utf8(&bytes).map_err(|error| {
            evidence_error(
                AdapterError::new(
                    "cloudflare.d1.migration_reconciliation_malformed_utf8",
                    format!("Cloudflare reconciliation response was not valid UTF-8: {error}"),
                    "Treat the provider evidence as contradictory and retain the lease.",
                )
                .with_status(Some(status_code)),
                None,
            )
        })?;
        if !status.is_success() {
            return Err(evidence_error(
                d1_migration_reconciliation_http_status_error(status),
                classify_d1_migration_provider_error(body),
            ));
        }
        let envelope = decode_strict_d1_migration_reconciliation_envelope(body)
            .map_err(|error| evidence_error(error.with_status(Some(status_code)), None))?;
        Ok(D1MigrationReconciliationBatch {
            result: envelope.result.unwrap_or(Value::Null),
            response_body_sha256,
            response_body_size_bytes,
            lifecycle: D1MigrationReconciliationReadLifecycle::body_completely_read(status_code),
        })
    }

    /// Submit one manifest-owned migration statement. The non-idempotent
    /// transport policy and strict outer-envelope evidence are both required:
    /// callers must reconcile rather than retry an ambiguous result.
    pub(crate) async fn execute_d1_migration_manifest_write(
        &self,
        account_id: &str,
        database_id: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<D1MigrationManifestWrite, D1MigrationManifestWriteError> {
        let pre_dispatch = |error: AdapterError| D1MigrationManifestWriteError {
            error: error.payload(),
            response_body_sha256: None,
            response_body_size_bytes: None,
            lifecycle: D1MigrationManifestWriteLifecycle::pre_dispatch(),
        };
        let account_id = require_non_empty("account_id", account_id).map_err(pre_dispatch)?;
        let database_id = require_non_empty("database_id", database_id).map_err(pre_dispatch)?;
        let sql = require_non_empty("sql", sql).map_err(pre_dispatch)?;
        let token = self.bearer_token().map_err(pre_dispatch)?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}/query",
            path_segment(account_id),
            path_segment(database_id),
        ));
        let mut body = Map::new();
        body.insert("sql".to_string(), Value::String(sql.to_string()));
        if !params.is_empty() {
            body.insert("params".to_string(), Value::Array(params.to_vec()));
        }
        let request = self
            .migration_write_http
            .post(url)
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .json(&Value::Object(body))
            .build()
            .map_err(|error| {
                pre_dispatch(AdapterError::new(
                    "cloudflare.request_build_failed",
                    format!("cloudflare.d1.migration_manifest.write request build failed: {error}"),
                    "Correct the request configuration; no provider request was dispatched.",
                ))
            })?;
        let response = self
            .migration_write_http
            .execute(request)
            .await
            .map_err(|error| {
                let code = if error.is_timeout() {
                    "cloudflare.timeout"
                } else {
                    "cloudflare.transport_error"
                };
                D1MigrationManifestWriteError {
                    error: AdapterError::new(
                        code,
                        format!("cloudflare.d1.migration_manifest.write request failed: {error}"),
                        "Treat the provider outcome as ambiguous; retain custody and do not replay the migration write.",
                    )
                    .with_retryable(false)
                    .payload(),
                    response_body_sha256: None,
                    response_body_size_bytes: None,
                    lifecycle: D1MigrationManifestWriteLifecycle::attempted_without_response(),
                }
            })?;
        let status = response.status();
        let status_code = status.as_u16();
        let identity_encoded = response
            .headers()
            .get_all(reqwest::header::CONTENT_ENCODING)
            .iter()
            .all(|value| {
                value.to_str().ok().is_some_and(|value| {
                    value
                        .split(',')
                        .all(|encoding| encoding.trim().eq_ignore_ascii_case("identity"))
                })
            });
        if !identity_encoded {
            return Err(D1MigrationManifestWriteError {
                error: AdapterError::new(
                    "cloudflare.d1.migration_manifest_unsupported_content_encoding",
                    "Cloudflare migration-write response used a non-identity content encoding",
                    "Treat the provider outcome as ambiguous; retain custody and do not replay the migration write.",
                )
                .with_status(Some(status_code))
                .payload(),
                response_body_sha256: None,
                response_body_size_bytes: None,
                lifecycle: D1MigrationManifestWriteLifecycle::response_received(status_code),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > D1_MIGRATION_RESPONSE_MAX_BYTES as u64)
        {
            return Err(D1MigrationManifestWriteError {
                error: AdapterError::new(
                    "cloudflare.d1.migration_manifest_response_too_large",
                    "Cloudflare migration-write response exceeded the exact-evidence byte limit",
                    "Treat the provider outcome as ambiguous; retain custody and do not replay the migration write.",
                )
                .with_status(Some(status_code))
                .payload(),
                response_body_sha256: None,
                response_body_size_bytes: response.content_length().map(|length| length as usize),
                lifecycle: D1MigrationManifestWriteLifecycle::response_received(status_code),
            });
        }
        let initial_capacity = response
            .content_length()
            .map(|length| cmp::min(length as usize, D1_MIGRATION_RESPONSE_MAX_BYTES))
            .unwrap_or(0);
        let mut bytes = Vec::with_capacity(initial_capacity);
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| D1MigrationManifestWriteError {
                error: AdapterError::new(
                    "cloudflare.response_read_failed",
                    format!("failed reading Cloudflare migration-write response body: {error}"),
                    "Treat the provider outcome as ambiguous; retain custody and do not replay the migration write.",
                )
                .with_status(Some(status_code))
                .with_retryable(false)
                .payload(),
                response_body_sha256: None,
                response_body_size_bytes: Some(bytes.len()),
                lifecycle: D1MigrationManifestWriteLifecycle::body_read_failed(
                    status_code,
                    bytes.len(),
                ),
            })?;
            let observed_size = bytes.len().saturating_add(chunk.len());
            if observed_size > D1_MIGRATION_RESPONSE_MAX_BYTES {
                return Err(D1MigrationManifestWriteError {
                    error: AdapterError::new(
                        "cloudflare.d1.migration_manifest_response_too_large",
                        "Cloudflare migration-write response exceeded the exact-evidence byte limit",
                        "Treat the provider outcome as ambiguous; retain custody and do not replay the migration write.",
                    )
                    .with_status(Some(status_code))
                    .payload(),
                    response_body_sha256: None,
                    response_body_size_bytes: Some(observed_size),
                    lifecycle: D1MigrationManifestWriteLifecycle::body_partially_read(status_code),
                });
            }
            hasher.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        let response_body_size_bytes = bytes.len();
        let response_body_sha256 = format!("{:x}", hasher.finalize());
        let evidence_error = |error: AdapterError| D1MigrationManifestWriteError {
            error: error.with_retryable(false).payload(),
            response_body_sha256: Some(response_body_sha256.clone()),
            response_body_size_bytes: Some(response_body_size_bytes),
            lifecycle: D1MigrationManifestWriteLifecycle::body_completely_read(status_code),
        };
        let body = std::str::from_utf8(&bytes).map_err(|error| {
            evidence_error(
                AdapterError::new(
                    "cloudflare.d1.migration_manifest_malformed_utf8",
                    format!("Cloudflare migration-write response was not valid UTF-8: {error}"),
                    "Treat the provider outcome as ambiguous; retain custody and do not replay the migration write.",
                )
                .with_status(Some(status_code)),
            )
        })?;
        if !status.is_success() {
            return Err(evidence_error(http_status_error(status, body)));
        }
        let envelope = decode_strict_d1_migration_manifest_envelope(body)
            .map_err(|error| evidence_error(error.with_status(Some(status_code))))?;
        Ok(D1MigrationManifestWrite {
            result: envelope.result.unwrap_or(Value::Null),
            response_body_sha256,
            response_body_size_bytes,
            lifecycle: D1MigrationManifestWriteLifecycle::body_completely_read(status_code),
        })
    }

    async fn execute_d1_query(
        &self,
        operation: &'static str,
        retry_policy: RetryPolicy,
        envelope_policy: D1EnvelopePolicy,
        account_id: &str,
        database_id: &str,
        sql: &str,
        params: &[Value],
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let database_id = require_non_empty("database_id", database_id)?;
        let sql = require_non_empty("sql", sql)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{}/d1/database/{}/query",
            path_segment(account_id),
            path_segment(database_id),
        ));
        let mut body = Map::new();
        body.insert("sql".to_string(), Value::String(sql.to_string()));
        if !params.is_empty() {
            body.insert("params".to_string(), Value::Array(params.to_vec()));
        }

        let request = || {
            self.http
                .post(url.clone())
                .bearer_auth(&token)
                .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                .json(&Value::Object(body.clone()))
        };
        let envelope: CloudflareEnvelope<Value> = match envelope_policy {
            D1EnvelopePolicy::Generic => {
                self.send_envelope(operation, retry_policy, request).await?
            }
            D1EnvelopePolicy::RequireEmptyErrors => {
                self.send_d1_migration_manifest_envelope(operation, retry_policy, request)
                    .await?
            }
        };

        Ok(envelope.result.unwrap_or_else(|| json!(null)))
    }

    pub async fn inspect_d1_schema(
        &self,
        account_id: &str,
        database_id: &str,
        include_columns: bool,
        include_tables: &[String],
        include_table_pattern: Option<&str>,
    ) -> Result<Value, AdapterError> {
        let (raw_objects, discovery_strategy, discovery_fidelity) = match self
            .query_d1_database(
                account_id,
                database_id,
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
                &[],
            )
            .await
        {
            Ok(result) => (
                d1_result_rows(&result),
                "sqlite_master".to_string(),
                None,
            ),
            Err(err) if is_d1_sqlite_auth_error(&err) => {
                let table_list = self
                    .query_d1_database(account_id, database_id, "PRAGMA table_list", &[])
                    .await?;
                (
                    d1_table_list_rows_to_schema_objects(&table_list),
                    "pragma_table_list".to_string(),
                    Some(d1_table_list_fidelity()),
                )
            }
            Err(err) => return Err(err),
        };
        let include_tables = d1_include_table_names(include_tables);
        let include_table_pattern = include_table_pattern
            .map(str::trim)
            .filter(|pattern| !pattern.is_empty());
        let filter_applied = !include_tables.is_empty() || include_table_pattern.is_some();
        let object_selection = d1_select_application_schema_objects(
            raw_objects,
            &include_tables,
            include_table_pattern,
        );
        let objects = object_selection.objects;

        let (columns, column_errors) = if include_columns {
            let mut columns = Vec::new();
            let mut column_errors = Vec::new();
            for object in d1_schema_column_objects(&objects) {
                let table_name = object.name.as_str();
                let sql = format!("PRAGMA table_info({})", sqlite_quote_identifier(table_name));
                match self
                    .query_d1_database(account_id, database_id, &sql, &[])
                    .await
                {
                    Ok(table_columns) => {
                        columns.extend(d1_table_info_rows(&object, &table_columns));
                    }
                    Err(err) if is_d1_sqlite_auth_error(&err) => {
                        column_errors.push(d1_column_discovery_error(table_name, &err));
                    }
                    Err(err) => return Err(err),
                }
            }
            (Some(Value::Array(columns)), column_errors)
        } else {
            (None, Vec::new())
        };

        let mut schema = Map::new();
        schema.insert("objects".to_string(), json!(objects));
        schema.insert("columns".to_string(), json!(columns));
        schema.insert(
            "discovery_strategy".to_string(),
            Value::String(discovery_strategy),
        );
        if let Some(discovery_fidelity) = discovery_fidelity {
            schema.insert("discovery_fidelity".to_string(), discovery_fidelity);
        }
        schema.insert(
            "application_schema_available".to_string(),
            Value::Bool(!objects.is_empty()),
        );
        schema.insert(
            "partial_success".to_string(),
            Value::Bool(!column_errors.is_empty() || !object_selection.skipped_internal.is_empty()),
        );
        schema.insert(
            "summary".to_string(),
            d1_schema_inspection_summary(
                &objects,
                columns.as_ref(),
                &column_errors,
                &object_selection.skipped_internal,
                filter_applied,
            ),
        );
        if filter_applied {
            schema.insert(
                "filter".to_string(),
                json!({
                    "include_tables": include_tables.iter().cloned().collect::<Vec<_>>(),
                    "include_table_pattern": include_table_pattern,
                    "matched_application_objects": objects.len(),
                    "filtered_out_application_objects": object_selection.filtered_out.len(),
                }),
            );
            if !object_selection.filtered_out.is_empty() {
                schema.insert(
                    "filtered_out_tables".to_string(),
                    Value::Array(object_selection.filtered_out),
                );
            }
        }
        if !object_selection.skipped_internal.is_empty() {
            schema.insert(
                "skipped_internal_tables".to_string(),
                Value::Array(object_selection.skipped_internal),
            );
        }
        if !column_errors.is_empty() {
            schema.insert(
                "column_discovery_fidelity".to_string(),
                d1_column_discovery_fidelity(),
            );
            schema.insert("column_errors".to_string(), Value::Array(column_errors));
        }

        Ok(Value::Object(schema))
    }

    pub async fn get_r2_object(
        &self,
        account_id: &str,
        bucket_name: &str,
        object_key: &str,
        range: Option<&str>,
    ) -> Result<R2Object, AdapterError> {
        let response = self
            .r2_request(
                reqwest::Method::GET,
                account_id,
                bucket_name,
                object_key,
                R2RequestOptions {
                    range,
                    content_type: None,
                    metadata: &[],
                    body: Vec::new(),
                },
            )
            .await?;

        Ok(R2Object {
            bucket_name: bucket_name.to_string(),
            object_key: object_key.to_string(),
            status: response.status,
            content_type: header_string(&response.headers, reqwest::header::CONTENT_TYPE),
            content_length: header_string(&response.headers, reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.parse::<u64>().ok()),
            etag: header_string(&response.headers, reqwest::header::ETAG),
            last_modified: header_string(&response.headers, reqwest::header::LAST_MODIFIED),
            range: header_string(&response.headers, reqwest::header::CONTENT_RANGE),
            body: response.body,
        })
    }

    pub async fn inspect_r2_object(
        &self,
        account_id: &str,
        bucket_name: &str,
        object_key: &str,
    ) -> Result<R2ObjectMetadata, AdapterError> {
        let response = self
            .r2_request(
                reqwest::Method::HEAD,
                account_id,
                bucket_name,
                object_key,
                R2RequestOptions {
                    range: None,
                    content_type: None,
                    metadata: &[],
                    body: Vec::new(),
                },
            )
            .await?;

        Ok(R2ObjectMetadata {
            bucket_name: bucket_name.to_string(),
            object_key: object_key.to_string(),
            status: response.status,
            content_type: header_string(&response.headers, reqwest::header::CONTENT_TYPE),
            content_length: header_string(&response.headers, reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.parse::<u64>().ok()),
            etag: header_string(&response.headers, reqwest::header::ETAG),
            last_modified: header_string(&response.headers, reqwest::header::LAST_MODIFIED),
            range: header_string(&response.headers, reqwest::header::CONTENT_RANGE),
            custom_metadata: r2_custom_metadata(&response.headers),
        })
    }

    pub async fn download_r2_object_to_file(
        &self,
        account_id: &str,
        bucket_name: &str,
        object_key: &str,
        range: Option<&str>,
        output_path: &Path,
        max_bytes: Option<u64>,
    ) -> Result<R2ObjectDownload, AdapterError> {
        let open = self
            .r2_open_request(
                reqwest::Method::GET,
                account_id,
                bucket_name,
                object_key,
                R2RequestOptions {
                    range,
                    content_type: None,
                    metadata: &[],
                    body: Vec::new(),
                },
            )
            .await?;
        let mut file = std::fs::File::create(output_path).map_err(|err| {
            AdapterError::new(
                "cloudflare.r2_output_write_failed",
                format!("failed to create output file: {err}"),
                "Check output_path permissions and parent directory.",
            )
        })?;
        let mut stream = open.response.bytes_stream();
        let mut hasher = Sha256::new();
        let mut bytes_written = 0u64;
        let mut truncated = false;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                AdapterError::new(
                    "cloudflare.r2_body_read_failed",
                    format!("failed to read R2 object body: {err}"),
                    "Retry the request; if persistent, inspect network/runtime limits.",
                )
                .with_retryable(err.is_timeout() || err.is_connect())
            })?;
            let mut bytes = chunk.as_ref();
            if let Some(max_bytes) = max_bytes {
                let remaining = max_bytes.saturating_sub(bytes_written);
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                if bytes.len() as u64 > remaining {
                    bytes = &bytes[..remaining as usize];
                    truncated = true;
                }
            }
            file.write_all(bytes).map_err(|err| {
                AdapterError::new(
                    "cloudflare.r2_output_write_failed",
                    format!("failed writing output file: {err}"),
                    "Check output_path permissions and available disk space.",
                )
            })?;
            hasher.update(bytes);
            bytes_written += bytes.len() as u64;
            if truncated {
                break;
            }
        }
        file.flush().map_err(|err| {
            AdapterError::new(
                "cloudflare.r2_output_write_failed",
                format!("failed flushing output file: {err}"),
                "Check output_path permissions and available disk space.",
            )
        })?;

        Ok(R2ObjectDownload {
            bucket_name: bucket_name.to_string(),
            object_key: object_key.to_string(),
            status: open.status,
            output_path: output_path.display().to_string(),
            bytes_written,
            sha256: format!("{:x}", hasher.finalize()),
            truncated,
            content_type: header_string(&open.headers, reqwest::header::CONTENT_TYPE),
            content_length: header_string(&open.headers, reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.parse::<u64>().ok()),
            etag: header_string(&open.headers, reqwest::header::ETAG),
            last_modified: header_string(&open.headers, reqwest::header::LAST_MODIFIED),
            range: header_string(&open.headers, reqwest::header::CONTENT_RANGE),
        })
    }

    pub async fn put_r2_object(
        &self,
        account_id: &str,
        bucket_name: &str,
        object_key: &str,
        body: Vec<u8>,
        content_type: Option<&str>,
        metadata: &[(String, String)],
    ) -> Result<R2PutObjectResult, AdapterError> {
        let response = self
            .r2_request(
                reqwest::Method::PUT,
                account_id,
                bucket_name,
                object_key,
                R2RequestOptions {
                    range: None,
                    content_type,
                    metadata,
                    body,
                },
            )
            .await?;

        Ok(R2PutObjectResult {
            bucket_name: bucket_name.to_string(),
            object_key: object_key.to_string(),
            status: response.status,
            content_type: header_string(&response.headers, reqwest::header::CONTENT_TYPE),
            content_length: header_string(&response.headers, reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.parse::<u64>().ok()),
            etag: header_string(&response.headers, reqwest::header::ETAG),
            version_id: header_string(
                &response.headers,
                HeaderName::from_static("x-amz-version-id"),
            ),
        })
    }

    async fn r2_request(
        &self,
        method: reqwest::Method,
        account_id: &str,
        bucket_name: &str,
        object_key: &str,
        options: R2RequestOptions<'_>,
    ) -> Result<R2Response, AdapterError> {
        let open = self
            .r2_open_request(method.clone(), account_id, bucket_name, object_key, options)
            .await?;

        let body = open.response.bytes().await.map_err(|err| {
            AdapterError::new(
                "cloudflare.r2_body_read_failed",
                format!("failed to read R2 object body: {err}"),
                "Retry the request; if persistent, inspect network/runtime limits.",
            )
            .with_retryable(err.is_timeout() || err.is_connect())
        })?;

        Ok(R2Response {
            status: open.status,
            headers: open.headers,
            body: body.to_vec(),
        })
    }

    async fn r2_open_request(
        &self,
        method: reqwest::Method,
        account_id: &str,
        bucket_name: &str,
        object_key: &str,
        options: R2RequestOptions<'_>,
    ) -> Result<R2OpenResponse, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let bucket_name = require_non_empty("bucket_name", bucket_name)?;
        let object_key = require_non_empty("object_key", object_key)?;
        let access_key_id = self.cfg.r2_access_key_id.as_deref().ok_or_else(|| {
            AdapterError::new(
                "cloudflare.r2_credentials_missing",
                "R2 access key id is not configured",
                "Set CLOUDFLARE_MCP_R2_ACCESS_KEY_ID or CLOUDFLARE_MCP_R2_ACCESS_KEY_ID_FILE.",
            )
        })?;
        let secret_access_key = self.cfg.r2_secret_access_key.as_deref().ok_or_else(|| {
            AdapterError::new(
                "cloudflare.r2_credentials_missing",
                "R2 secret access key is not configured",
                "Set CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY or CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY_FILE.",
            )
        })?;
        let endpoint = self
            .cfg
            .r2_endpoint
            .clone()
            .unwrap_or_else(|| format!("https://{account_id}.r2.cloudflarestorage.com"));
        let endpoint = endpoint.trim_end_matches('/');
        let canonical_uri = format!(
            "/{}/{}",
            aws_uri_encode(bucket_name, false),
            aws_uri_encode(object_key, false)
        );
        let url = format!("{endpoint}{canonical_uri}");
        let now = OffsetDateTime::now_utc();
        let amz_date = aws_amz_date(now);
        let short_date = aws_short_date(now);
        let host = Url::parse(endpoint)
            .ok()
            .and_then(|url| url.host_str().map(str::to_string))
            .ok_or_else(|| {
                AdapterError::new(
                    "cloudflare.r2_endpoint_invalid",
                    "R2 endpoint must be an absolute URL with a host",
                    "Set CLOUDFLARE_MCP_R2_ENDPOINT to a valid https endpoint or unset it for the account default.",
                )
            })?;

        let payload_hash = sha256_hex(&options.body);
        let mut signed_headers = vec![
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if let Some(range) = options.range.filter(|value| !value.trim().is_empty()) {
            signed_headers.push(("range".to_string(), range.trim().to_string()));
        }
        if let Some(content_type) = options
            .content_type
            .filter(|value| !value.trim().is_empty())
        {
            signed_headers.push(("content-type".to_string(), content_type.trim().to_string()));
        }
        for (name, value) in options.metadata {
            let name = name.trim().to_ascii_lowercase();
            if !name.is_empty() && !value.trim().is_empty() {
                signed_headers.push((format!("x-amz-meta-{name}"), value.trim().to_string()));
            }
        }
        signed_headers.sort_by(|left, right| left.0.cmp(&right.0));
        let canonical_headers = signed_headers
            .iter()
            .map(|(name, value)| format!("{name}:{}\n", value.trim()))
            .collect::<String>();
        let signed_header_names = signed_headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "{}\n{canonical_uri}\n\n{canonical_headers}\n{signed_header_names}\n{payload_hash}",
            method.as_str()
        );
        let credential_scope = format!("{short_date}/auto/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = aws_signing_signature(secret_access_key, &short_date, &string_to_sign)?;
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_header_names}, Signature={signature}"
        );

        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::HOST, header_value("host", &host)?);
        headers.insert(
            HeaderName::from_static("x-amz-content-sha256"),
            header_value("x-amz-content-sha256", &payload_hash)?,
        );
        headers.insert(
            HeaderName::from_static("x-amz-date"),
            header_value("x-amz-date", &amz_date)?,
        );
        headers.insert(
            reqwest::header::AUTHORIZATION,
            header_value("authorization", &authorization)?,
        );
        if let Some(range) = options.range.filter(|value| !value.trim().is_empty()) {
            headers.insert(reqwest::header::RANGE, header_value("range", range.trim())?);
        }
        if let Some(content_type) = options
            .content_type
            .filter(|value| !value.trim().is_empty())
        {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                header_value("content-type", content_type.trim())?,
            );
        }
        for (name, value) in options.metadata {
            let name = name.trim().to_ascii_lowercase();
            if !name.is_empty() && !value.trim().is_empty() {
                headers.insert(
                    HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()).map_err(
                        |err| {
                            AdapterError::new(
                                "cloudflare.r2_metadata_invalid",
                                format!("invalid R2 metadata header name: {err}"),
                                "Use simple ASCII metadata keys.",
                            )
                        },
                    )?,
                    header_value("x-amz-meta", value.trim())?,
                );
            }
        }

        let response = self
            .http
            .request(method.clone(), url)
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            .headers(headers)
            .body(options.body)
            .send()
            .await
            .map_err(|err| {
                AdapterError::new(
                    "cloudflare.r2_request_failed",
                    format!("R2 object {} failed: {err}", method.as_str()),
                    "Check network connectivity, R2 endpoint, bucket name, object key, and credentials.",
                )
                .with_retryable(err.is_timeout() || err.is_connect())
            })?;

        let status = response.status();
        let headers = response.headers().clone();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AdapterError::new(
                "cloudflare.r2_request_rejected",
                format!("R2 object {} returned HTTP {status}: {body}", method.as_str()),
                "Check R2 credentials, bucket permissions, bucket name, object key, and optional byte range.",
            )
            .with_status(Some(status.as_u16()))
            .with_retryable(matches!(
                status,
                StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            )));
        }

        Ok(R2OpenResponse {
            status: status.as_u16(),
            headers,
            response,
        })
    }

    pub async fn list_tunnels(
        &self,
        account_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Page<Tunnel>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/cfd_tunnel"));

        let envelope: CloudflareEnvelope<Vec<Tunnel>> = self
            .send_envelope("cloudflare.tunnels.list", RetryPolicy::Idempotent, || {
                self.http
                    .get(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .query(&[("page", page), ("per_page", per_page)])
            })
            .await?;

        Ok(Page {
            items: envelope.result.unwrap_or_default(),
            page_info: envelope.result_info,
        })
    }

    pub async fn create_tunnel(
        &self,
        account_id: &str,
        name: &str,
    ) -> Result<Tunnel, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let name = require_non_empty("name", name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/cfd_tunnel"));

        let envelope: CloudflareEnvelope<Tunnel> = self
            .send_envelope(
                "cloudflare.tunnels.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&json!({ "name": name }))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a tunnel result payload",
                "Inspect Cloudflare API response schema and ensure expected fields are present.",
            )
        })
    }

    pub async fn list_dns_records(
        &self,
        zone_id: &str,
        hostname: Option<&str>,
    ) -> Result<Page<DnsRecord>, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/dns_records"));
        let hostname = hostname.map(str::trim).filter(|value| !value.is_empty());

        let envelope: CloudflareEnvelope<Vec<DnsRecord>> = self
            .send_envelope("cloudflare.dns.list", RetryPolicy::Idempotent, || {
                let builder = self
                    .http
                    .get(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .query(&[("type", "CNAME")]);
                if let Some(hostname) = hostname {
                    builder.query(&[("name", hostname)])
                } else {
                    builder
                }
            })
            .await?;

        Ok(Page {
            items: envelope.result.unwrap_or_default(),
            page_info: envelope.result_info,
        })
    }

    pub async fn upsert_dns_cname(
        &self,
        zone_id: &str,
        request: &DnsRecordUpsertRequest,
    ) -> Result<DnsRecord, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let hostname = require_non_empty("hostname", &request.hostname)?;
        let target = require_non_empty("target", &request.target)?;

        let existing = self.list_dns_records(zone_id, Some(hostname)).await?;
        let token = self.bearer_token()?;

        if let Some(record) = existing
            .items
            .iter()
            .find(|record| record.record_type.eq_ignore_ascii_case("CNAME"))
        {
            if record.content == target
                && record.proxied == request.proxied
                && normalize_ttl(record.ttl) == normalize_ttl(request.ttl)
            {
                return Ok(record.clone());
            }

            let url = self.endpoint(&format!("/zones/{zone_id}/dns_records/{}", record.id));
            let envelope: CloudflareEnvelope<DnsRecord> = self
                .send_envelope("cloudflare.dns.update", RetryPolicy::Idempotent, || {
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&json!({
                            "type": "CNAME",
                            "name": hostname,
                            "content": target,
                            "proxied": request.proxied,
                            "ttl": request.ttl,
                        }))
                })
                .await?;
            return envelope.result.ok_or_else(|| {
                AdapterError::new(
                    "cloudflare.empty_result",
                    "Cloudflare returned success without a DNS update result",
                    "Verify the DNS update endpoint and response schema for this account/zone.",
                )
            });
        }

        let url = self.endpoint(&format!("/zones/{zone_id}/dns_records"));
        let envelope: CloudflareEnvelope<DnsRecord> = self
            .send_envelope("cloudflare.dns.create", RetryPolicy::NonIdempotent, || {
                self.http
                    .post(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .json(&json!({
                        "type": "CNAME",
                        "name": hostname,
                        "content": target,
                        "proxied": request.proxied,
                        "ttl": request.ttl,
                    }))
            })
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a DNS create result",
                "Verify the DNS create endpoint and response schema for this account/zone.",
            )
        })
    }

    pub async fn disable_dns_cname(
        &self,
        zone_id: &str,
        hostname: &str,
    ) -> Result<DnsRouteDisableResult, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let hostname = require_non_empty("hostname", hostname)?;
        let existing = self.list_dns_records(zone_id, Some(hostname)).await?;
        let mut removed_record_ids = Vec::new();

        for record in existing.items.into_iter().filter(|record| {
            record.record_type.eq_ignore_ascii_case("CNAME")
                && record.name.eq_ignore_ascii_case(hostname)
        }) {
            self.delete_dns_record(zone_id, &record.id).await?;
            removed_record_ids.push(record.id);
        }

        Ok(DnsRouteDisableResult {
            hostname: hostname.to_string(),
            already_absent: removed_record_ids.is_empty(),
            removed_record_ids,
        })
    }

    pub async fn list_access_apps(
        &self,
        account_id: &str,
        hostname: Option<&str>,
    ) -> Result<Page<AccessApplication>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/access/apps"));
        let hostname = hostname.map(str::trim).filter(|value| !value.is_empty());

        let envelope: CloudflareEnvelope<Vec<AccessApplication>> = self
            .send_envelope(
                "cloudflare.access.apps.list",
                RetryPolicy::Idempotent,
                || {
                    let builder = self
                        .http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());
                    if let Some(hostname) = hostname {
                        builder.query(&[("domain", hostname)])
                    } else {
                        builder
                    }
                },
            )
            .await?;

        Ok(Page {
            items: envelope.result.unwrap_or_default(),
            page_info: envelope.result_info,
        })
    }

    pub async fn upsert_access_app(
        &self,
        account_id: &str,
        request: &AccessAppUpsertRequest,
    ) -> Result<AccessApplication, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let hostname = require_non_empty("hostname", &request.hostname)?;
        let app_name = require_non_empty("app_name", &request.app_name)?;
        let token = self.bearer_token()?;

        let existing = self.list_access_apps(account_id, Some(hostname)).await?;
        let maybe_existing = existing
            .items
            .into_iter()
            .find(|app| app.domain.as_deref() == Some(hostname));

        if let Some(existing) = maybe_existing {
            if existing.name == app_name {
                return Ok(existing);
            }
            let url = self.endpoint(&format!(
                "/accounts/{account_id}/access/apps/{}",
                existing.id
            ));
            let envelope: CloudflareEnvelope<AccessApplication> = self
                .send_envelope(
                    "cloudflare.access.apps.update",
                    RetryPolicy::Idempotent,
                    || {
                        self.http
                            .put(url.clone())
                            .bearer_auth(&token)
                            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                            .json(&json!({
                                "name": app_name,
                                "domain": hostname,
                                "type": "self_hosted",
                            }))
                    },
                )
                .await?;
            return envelope.result.ok_or_else(|| {
                AdapterError::new(
                    "cloudflare.empty_result",
                    "Cloudflare returned success without an Access app update result",
                    "Verify Access app update response schema.",
                )
            });
        }

        let url = self.endpoint(&format!("/accounts/{account_id}/access/apps"));
        let envelope: CloudflareEnvelope<AccessApplication> = self
            .send_envelope(
                "cloudflare.access.apps.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&json!({
                            "name": app_name,
                            "domain": hostname,
                            "type": "self_hosted",
                        }))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without an Access app create result",
                "Verify Access app create response schema.",
            )
        })
    }

    pub async fn list_access_policies(
        &self,
        account_id: &str,
        app_id: &str,
    ) -> Result<Vec<AccessPolicy>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let app_id = require_non_empty("app_id", app_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/access/apps/{app_id}/policies"
        ));

        let envelope: CloudflareEnvelope<Vec<AccessPolicy>> = self
            .send_envelope(
                "cloudflare.access.policies.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        Ok(envelope.result.unwrap_or_default())
    }

    pub async fn list_workers(
        &self,
        account_id: &str,
        tags: Option<&str>,
    ) -> Result<Page<WorkerScript>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/workers/scripts"));
        let tags = tags.map(str::trim).filter(|value| !value.is_empty());

        let envelope: CloudflareEnvelope<Vec<WorkerScript>> = self
            .send_envelope("cloudflare.workers.list", RetryPolicy::Idempotent, || {
                let builder = self
                    .http
                    .get(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());
                if let Some(tags) = tags {
                    builder.query(&[("tags", tags)])
                } else {
                    builder
                }
            })
            .await?;

        Ok(Page {
            items: envelope.result.unwrap_or_default(),
            page_info: envelope.result_info,
        })
    }

    pub async fn get_worker_settings(
        &self,
        account_id: &str,
        script_name: &str,
    ) -> Result<WorkerSettings, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{script_name}/settings"
        ));

        let envelope: CloudflareEnvelope<WorkerSettings> = self
            .send_envelope(
                "cloudflare.workers.settings.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without Worker settings",
                "Verify Worker script name and Cloudflare Workers API response schema.",
            )
        })
    }

    /// Read the complete initial Worker version evidence after a create-only
    /// upload.  Settings are not authoritative for module uploads (Cloudflare
    /// may legitimately return `main_module: null`), so bind the readback to
    /// the sole version returned for this newly-created script and fetch that
    /// version's detail separately.  Any ambiguous or malformed version
    /// inventory fails closed before the caller can continue.
    pub async fn get_worker_initial_version_evidence(
        &self,
        account_id: &str,
        script_name: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let listing_before_page = self.list_workers(account_id, None).await?;
        let listing_before =
            worker_listing_target(&listing_before_page.items, script_name)?.clone();
        let versions_before = self
            .list_worker_versions_exhaustive(account_id, script_name)
            .await?;
        if versions_before.items.len() != 1 {
            return Err(AdapterError::new(
                "workers.upload_version_readback_ambiguous",
                format!(
                    "Worker version readback returned {} versions; expected exactly one",
                    versions_before.items.len()
                ),
                "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
            ));
        }
        let version = versions_before.items[0].clone();
        let version_id = worker_version_id(
            &version,
            "Worker version readback omitted a canonical version id",
        )?;
        let detail_path = format!(
            "/accounts/{account_id}/workers/scripts/{}/versions/{}",
            path_segment(script_name),
            path_segment(version_id),
        );
        let detail = self
            .api_request(
                "cloudflare.workers.versions.detail",
                reqwest::Method::GET,
                &detail_path,
                &[],
                None,
            )
            .await?;
        let detail_id = worker_version_id(
            &detail,
            "Worker version detail omitted a canonical version id",
        )?;
        if detail_id != version_id {
            return Err(AdapterError::new(
                "workers.upload_version_readback_conflict",
                "Worker version detail id did not match the sole listed version",
                "Reconcile the provider response; conflicting version evidence is not authoritative.",
            ));
        }

        let listing_after_page = self.list_workers(account_id, None).await?;
        let listing_after_item =
            worker_listing_target(&listing_after_page.items, script_name)?.clone();
        let listing_etag_before = worker_script_etag(&listing_before)?;
        let listing_etag_after = worker_script_etag(&listing_after_item)?;
        if worker_listing_identity(&listing_before)?
            != worker_listing_identity(&listing_after_item)?
            || listing_etag_before != listing_etag_after
        {
            return Err(AdapterError::new(
                "workers.upload_listing_readback_drift",
                "Worker listing identity or etag changed during version readback",
                "Reconcile the Worker listing and version detail before retrying or continuing the create-only sequence.",
            ));
        }
        let versions_after = self
            .list_worker_versions_exhaustive(account_id, script_name)
            .await?;
        if versions_after.items.len() != 1 {
            return Err(AdapterError::new(
                "workers.upload_version_readback_ambiguous",
                format!(
                    "Worker stable version readback returned {} versions; expected exactly one",
                    versions_after.items.len()
                ),
                "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
            ));
        }
        let version_id_after = worker_version_id(
            &versions_after.items[0],
            "Stable Worker version readback omitted a canonical version id",
        )?;
        if version_id_after != version_id {
            return Err(AdapterError::new(
                "workers.upload_version_readback_drift",
                "Worker version id changed during version detail readback",
                "Reconcile the Worker version inventory before retrying or continuing the create-only sequence.",
            ));
        }
        Ok(json!({
            "listing": listing_before,
            "listing_after": listing_after_item,
            "versions": versions_before.items,
            "versions_after": versions_after.items,
            "version_pagination": {
                "total_count": versions_before.total_count,
                "total_pages": versions_before.total_pages,
                "stable_total_count": versions_after.total_count,
                "stable_total_pages": versions_after.total_pages,
            },
            "version": version,
            "detail": detail,
        }))
    }

    async fn list_worker_versions_exhaustive(
        &self,
        account_id: &str,
        script_name: &str,
    ) -> Result<WorkerVersionInventory, AdapterError> {
        let mut page = 1u32;
        let mut seen_pages = BTreeSet::new();
        let mut items = Vec::new();
        let mut seen_ids = BTreeSet::new();
        let mut expected_total_count = None;
        let mut expected_total_pages = None;

        loop {
            if page > WORKER_VERSION_MAX_PAGES || !seen_pages.insert(page) {
                return Err(AdapterError::new(
                    "workers.upload_version_readback_pagination_invalid",
                    "Worker version pagination exceeded the bounded page contract or repeated a page",
                    "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
                ));
            }
            let (result, result_info) = self
                .get_worker_versions_page(account_id, script_name, page, WORKER_VERSION_PAGE_SIZE)
                .await?;
            let page_items = result
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    AdapterError::new(
                        "workers.upload_version_readback_invalid",
                        "Worker version readback did not contain the expected items array",
                        "Reconcile the provider response; no create-only upload may continue from malformed version evidence.",
                    )
                })?;
            let metadata = worker_version_page_metadata(&result, result_info.as_ref(), page)?;
            if expected_total_count
                .replace(metadata.total_count)
                .is_some_and(|old| old != metadata.total_count)
                || expected_total_pages
                    .replace(metadata.total_pages)
                    .is_some_and(|old| old != metadata.total_pages)
            {
                return Err(AdapterError::new(
                    "workers.upload_version_readback_pagination_drift",
                    "Worker version pagination metadata changed between pages",
                    "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
                ));
            }
            if page_items.len() as u32 > metadata.per_page {
                return Err(AdapterError::new(
                    "workers.upload_version_readback_pagination_invalid",
                    "Worker version page contained more items than its authoritative page size",
                    "Reconcile the provider response before retrying or continuing the create-only sequence.",
                ));
            }
            if metadata
                .count
                .is_some_and(|count| count as usize != page_items.len())
            {
                return Err(AdapterError::new(
                    "workers.upload_version_readback_pagination_conflict",
                    "Worker version page count did not match its authoritative result_info count",
                    "Reconcile the provider response before retrying or continuing the create-only sequence.",
                ));
            }
            for item in page_items {
                let id = worker_version_id(
                    item,
                    "Worker version page contained an item without a canonical id",
                )?;
                if !seen_ids.insert(id.to_string()) {
                    return Err(AdapterError::new(
                        "workers.upload_version_readback_duplicate",
                        "Worker version pagination contained a duplicate version id",
                        "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
                    ));
                }
                items.push(item.clone());
                if items.len() > WORKER_VERSION_MAX_ITEMS {
                    return Err(AdapterError::new(
                        "workers.upload_version_readback_pagination_invalid",
                        "Worker version pagination exceeded the bounded item contract",
                        "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
                    ));
                }
            }
            if page == metadata.total_pages {
                if items.len() as u32 != metadata.total_count {
                    return Err(AdapterError::new(
                        "workers.upload_version_readback_truncated",
                        "Worker version pagination did not exhaust the authoritative total count",
                        "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
                    ));
                }
                return Ok(WorkerVersionInventory {
                    items,
                    total_count: metadata.total_count,
                    total_pages: metadata.total_pages,
                });
            }
            if page_items.is_empty() {
                return Err(AdapterError::new(
                    "workers.upload_version_readback_truncated",
                    "Worker version pagination returned an empty non-terminal page",
                    "Reconcile the provider version inventory before retrying or continuing the create-only sequence.",
                ));
            }
            page += 1;
        }
    }

    async fn get_worker_versions_page(
        &self,
        account_id: &str,
        script_name: &str,
        page: u32,
        per_page: u32,
    ) -> Result<(Value, Option<PageInfo>), AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{}/versions",
            path_segment(script_name),
        ));
        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.workers.versions.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .query(&[("page", page), ("per_page", per_page)])
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;
        let result = envelope.result.ok_or_else(|| {
            AdapterError::new(
                "workers.upload_version_readback_invalid",
                "Worker version readback omitted its result payload",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            )
        })?;
        Ok((result, envelope.result_info))
    }

    pub async fn patch_worker_settings(
        &self,
        account_id: &str,
        script_name: &str,
        settings_patch: &Value,
    ) -> Result<WorkerSettings, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{script_name}/settings"
        ));

        let envelope: CloudflareEnvelope<WorkerSettings> = self
            .send_envelope(
                "cloudflare.workers.settings.patch",
                RetryPolicy::NonIdempotent,
                || {
                    let settings_part = reqwest::multipart::Part::text(settings_patch.to_string())
                        .mime_str("application/json")
                        .expect("static settings mime type");
                    let form = reqwest::multipart::Form::new().part("settings", settings_part);
                    self.http
                        .patch(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .multipart(form)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without patched Worker settings",
                "Verify Worker settings patch endpoint and response schema.",
            )
        })
    }

    pub async fn upload_worker_module(
        &self,
        account_id: &str,
        script_name: &str,
        metadata: &Value,
        module_name: &str,
        file_name: &str,
        content_type: &str,
        bytes: Vec<u8>,
        create_only: bool,
    ) -> Result<WorkerScript, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let module_name = require_non_empty("module_name", module_name)?;
        let file_name = require_non_empty("file_name", file_name)?;
        let content_type = require_non_empty("content_type", content_type)?;
        reqwest::multipart::Part::bytes(Vec::new())
            .mime_str(content_type)
            .map_err(|err| {
                AdapterError::new(
                    "cloudflare.invalid_content_type",
                    format!("invalid Worker module content type: {err}"),
                    "Use a MIME type such as application/javascript+module.",
                )
            })?;

        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{script_name}"
        ));
        let metadata_text = metadata.to_string();
        let module_name = module_name.to_string();
        let file_name = file_name.to_string();
        let content_type = content_type.to_string();

        let envelope: CloudflareEnvelope<WorkerScript> = match self
            .send_envelope(
                "cloudflare.workers.script.upload_module",
                RetryPolicy::NonIdempotent,
                || {
                    let metadata_part = reqwest::multipart::Part::text(metadata_text.clone())
                        .mime_str("application/json")
                        .expect("static metadata MIME type");
                    let module_part = reqwest::multipart::Part::bytes(bytes.clone())
                        .file_name(file_name.clone())
                        .mime_str(&content_type)
                        .expect("Worker module content type was validated");
                    let form = reqwest::multipart::Form::new()
                        .part("metadata", metadata_part)
                        .part(module_name.clone(), module_part);
                    let mut request = self
                        .http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());
                    if create_only {
                        request = request.header(reqwest::header::IF_NONE_MATCH, "*");
                    }
                    request.multipart(form)
                },
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(err) => return Err(classify_worker_upload_error(err, create_only)),
        };

        envelope.result.ok_or_else(|| {
            classify_worker_upload_error(
                AdapterError::new(
                    "cloudflare.empty_result",
                    "Cloudflare returned success without uploaded Worker script details",
                    "Verify Worker script upload endpoint and response schema.",
                ),
                create_only,
            )
        })
    }

    pub async fn upload_worker_multipart(
        &self,
        account_id: &str,
        script_name: &str,
        content_type: &str,
        bytes: Vec<u8>,
        create_only: bool,
    ) -> Result<WorkerScript, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let content_type = require_non_empty("content_type", content_type)?;
        let content_type_header = header_value("content-type", content_type)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{script_name}"
        ));

        let envelope: CloudflareEnvelope<WorkerScript> = match self
            .send_envelope(
                "cloudflare.workers.script.upload_multipart",
                RetryPolicy::NonIdempotent,
                || {
                    let mut request = self
                        .http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .header(reqwest::header::CONTENT_TYPE, content_type_header.clone());
                    if create_only {
                        request = request.header(reqwest::header::IF_NONE_MATCH, "*");
                    }
                    request.body(bytes.clone())
                },
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(err) => return Err(classify_worker_upload_error(err, create_only)),
        };

        envelope.result.ok_or_else(|| {
            classify_worker_upload_error(
                AdapterError::new(
                    "cloudflare.empty_result",
                    "Cloudflare returned success without uploaded Worker script details",
                    "Verify Worker script upload endpoint and response schema.",
                ),
                create_only,
            )
        })
    }

    pub async fn replace_access_policies(
        &self,
        account_id: &str,
        app_id: &str,
        policies: &[AccessPolicyWrite],
    ) -> Result<Vec<AccessPolicy>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let app_id = require_non_empty("app_id", app_id)?;
        if policies.is_empty() {
            return Err(AdapterError::new(
                "cloudflare.invalid_argument",
                "policies must contain at least one policy",
                "Provide at least one allow policy when replacing Access policies.",
            ));
        }

        let current_policies = self.list_access_policies(account_id, app_id).await?;
        let desired_policy_ids: BTreeSet<String> = policies
            .iter()
            .filter_map(|policy| policy.id.as_deref().map(str::trim))
            .filter(|policy_id| !policy_id.is_empty())
            .map(ToOwned::to_owned)
            .collect();

        for policy in policies {
            if let Some(policy_id) = policy.id.as_deref().map(str::trim)
                && !policy_id.is_empty()
            {
                self.update_access_policy(account_id, app_id, policy_id, policy)
                    .await?;
            }
        }

        for policy in &current_policies {
            if !desired_policy_ids.contains(&policy.id) {
                self.delete_access_policy(account_id, app_id, &policy.id)
                    .await?;
            }
        }

        for policy in policies {
            let has_policy_id = policy
                .id
                .as_deref()
                .map(str::trim)
                .is_some_and(|policy_id| !policy_id.is_empty());
            if !has_policy_id {
                self.create_access_policy(account_id, app_id, policy)
                    .await?;
            }
        }

        self.list_access_policies(account_id, app_id).await
    }

    async fn create_access_policy(
        &self,
        account_id: &str,
        app_id: &str,
        policy: &AccessPolicyWrite,
    ) -> Result<AccessPolicy, AdapterError> {
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/access/apps/{app_id}/policies"
        ));

        let envelope: CloudflareEnvelope<AccessPolicy> = self
            .send_envelope(
                "cloudflare.access.policies.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(policy)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without an Access policy create result",
                "Verify Access policy create response schema.",
            )
        })
    }

    async fn update_access_policy(
        &self,
        account_id: &str,
        app_id: &str,
        policy_id: &str,
        policy: &AccessPolicyWrite,
    ) -> Result<AccessPolicy, AdapterError> {
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}"
        ));

        let envelope: CloudflareEnvelope<AccessPolicy> = self
            .send_envelope(
                "cloudflare.access.policies.update",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(policy)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without an Access policy update result",
                "Verify Access policy update response schema.",
            )
        })
    }

    async fn delete_access_policy(
        &self,
        account_id: &str,
        app_id: &str,
        policy_id: &str,
    ) -> Result<(), AdapterError> {
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}"
        ));

        let _envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.access.policies.delete",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .delete(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        Ok(())
    }

    pub async fn purge_cache(
        &self,
        zone_id: &str,
        environment_id: Option<&str>,
        payload: &Value,
    ) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = if let Some(environment_id) = environment_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.endpoint(&format!(
                "/zones/{zone_id}/environments/{environment_id}/purge_cache"
            ))
        } else {
            self.endpoint(&format!("/zones/{zone_id}/purge_cache"))
        };

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope("cloudflare.cache.purge", RetryPolicy::NonIdempotent, || {
                self.http
                    .post(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .json(payload)
            })
            .await?;
        Ok(envelope.result.unwrap_or_else(|| json!({})))
    }

    pub async fn get_zone_setting(
        &self,
        zone_id: &str,
        setting_id: &str,
    ) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let setting_id = require_non_empty("setting_id", setting_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/settings/{setting_id}"));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.zone.setting.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;
        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a zone setting result",
                "Verify zone_id, setting_id, and Cloudflare settings endpoint compatibility.",
            )
        })
    }

    pub async fn update_zone_setting(
        &self,
        zone_id: &str,
        setting_id: &str,
        value: Value,
    ) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let setting_id = require_non_empty("setting_id", setting_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/settings/{setting_id}"));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.zone.setting.update",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .patch(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&json!({ "value": value }))
                },
            )
            .await?;
        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without an updated zone setting result",
                "Verify zone setting update endpoint and response schema.",
            )
        })
    }

    pub async fn get_cache_ruleset(
        &self,
        zone_id: &str,
        phase: &str,
    ) -> Result<CacheRuleset, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let phase = require_non_empty("phase", phase)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/zones/{zone_id}/rulesets/phases/{phase}/entrypoint"
        ));

        let envelope: CloudflareEnvelope<CacheRuleset> = self
            .send_envelope(
                "cloudflare.cache.ruleset.get",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;
        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a cache ruleset result",
                "Verify ruleset phase and Cloudflare Rulesets response schema.",
            )
        })
    }

    pub async fn update_cache_ruleset(
        &self,
        zone_id: &str,
        phase: &str,
        ruleset: &CacheRuleset,
    ) -> Result<CacheRuleset, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let phase = require_non_empty("phase", phase)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/zones/{zone_id}/rulesets/phases/{phase}/entrypoint"
        ));

        let envelope: CloudflareEnvelope<CacheRuleset> = self
            .send_envelope(
                "cloudflare.cache.ruleset.update",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(ruleset)
                },
            )
            .await?;
        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without an updated cache ruleset result",
                "Verify Rulesets update endpoint and response schema.",
            )
        })
    }

    pub async fn cache_get(&self, zone_id: &str, path: &str) -> Result<Value, AdapterError> {
        self.cache_request(reqwest::Method::GET, zone_id, path, None)
            .await
    }

    pub async fn cache_update(
        &self,
        zone_id: &str,
        path: &str,
        payload: Value,
    ) -> Result<Value, AdapterError> {
        self.cache_request(reqwest::Method::PATCH, zone_id, path, Some(payload))
            .await
    }

    pub async fn cache_put(
        &self,
        zone_id: &str,
        path: &str,
        payload: Value,
    ) -> Result<Value, AdapterError> {
        self.cache_request(reqwest::Method::PUT, zone_id, path, Some(payload))
            .await
    }

    pub async fn cache_delete(&self, zone_id: &str, path: &str) -> Result<Value, AdapterError> {
        self.cache_request(reqwest::Method::DELETE, zone_id, path, None)
            .await
    }

    pub async fn api_request(
        &self,
        operation: &'static str,
        method: reqwest::Method,
        path: &str,
        query: &[(String, String)],
        payload: Option<Value>,
    ) -> Result<Value, AdapterError> {
        let path = require_non_empty("path", path)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(path);
        let retry_policy = if method == reqwest::Method::GET || method == reqwest::Method::DELETE {
            RetryPolicy::Idempotent
        } else {
            RetryPolicy::NonIdempotent
        };
        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(operation, retry_policy, || {
                let builder = self
                    .http
                    .request(method.clone(), url.clone())
                    .query(query)
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());
                if let Some(payload) = &payload {
                    builder.json(payload)
                } else {
                    builder
                }
            })
            .await?;
        Ok(envelope.result.unwrap_or_else(|| json!({})))
    }

    pub async fn graphql_analytics_query(&self, payload: &Value) -> Result<Value, AdapterError> {
        let token = self.bearer_token()?;
        let url = self.endpoint("/graphql");
        let mut attempt = 0u32;
        let max_attempts = self.cfg.max_retries;

        loop {
            let response = match self
                .http
                .post(url.clone())
                .bearer_auth(&token)
                .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                .json(payload)
                .send()
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    let retryable = err.is_timeout() || err.is_connect() || err.is_request();
                    if retryable && attempt < max_attempts {
                        tokio::time::sleep(backoff_delay(
                            attempt,
                            self.cfg.retry_base_delay,
                            self.cfg.retry_max_delay,
                        ))
                        .await;
                        attempt += 1;
                        continue;
                    }
                    let code = if err.is_timeout() {
                        "cloudflare.timeout"
                    } else {
                        "cloudflare.transport_error"
                    };
                    return Err(AdapterError::new(
                        code,
                        format!("cloudflare.graphql.analytics request failed: {err}"),
                        "Check Cloudflare API reachability, token validity, GraphQL permissions, and timeout settings.",
                    )
                    .with_retryable(retryable));
                }
            };

            let status = response.status();
            let retry_after = parse_retry_after(response.headers());
            let body = response.text().await.map_err(|err| {
                AdapterError::new(
                    "cloudflare.response_read_failed",
                    format!("failed reading Cloudflare GraphQL response body: {err}"),
                    "Retry request and inspect Cloudflare GraphQL API availability.",
                )
            })?;

            if is_retryable_status(status) && attempt < max_attempts {
                let delay = retry_after.unwrap_or_else(|| {
                    backoff_delay(attempt, self.cfg.retry_base_delay, self.cfg.retry_max_delay)
                });
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }

            if !status.is_success() {
                return Err(http_status_error(status, &body));
            }

            return serde_json::from_str(&body).map_err(|err| {
                AdapterError::new(
                    "cloudflare.decode_error",
                    format!("failed decoding Cloudflare GraphQL response: {err}"),
                    "Verify Cloudflare GraphQL endpoint compatibility with expected JSON response schema.",
                )
            });
        }
    }

    async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<(), AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let record_id = require_non_empty("record_id", record_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/dns_records/{record_id}"));

        let _envelope: CloudflareEnvelope<Value> = self
            .send_envelope("cloudflare.dns.delete", RetryPolicy::Idempotent, || {
                self.http
                    .delete(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            })
            .await?;
        Ok(())
    }

    async fn cache_request(
        &self,
        method: reqwest::Method,
        zone_id: &str,
        path: &str,
        payload: Option<Value>,
    ) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let path = require_non_empty("path", path)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/zones/{zone_id}/{}",
            path.trim().trim_start_matches('/')
        ));
        let retry_policy = if method == reqwest::Method::GET || method == reqwest::Method::DELETE {
            RetryPolicy::Idempotent
        } else {
            RetryPolicy::NonIdempotent
        };
        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope("cloudflare.cache.resource", retry_policy, || {
                let builder = self
                    .http
                    .request(method.clone(), url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());
                if let Some(payload) = &payload {
                    builder.json(payload)
                } else {
                    builder
                }
            })
            .await?;
        Ok(envelope.result.unwrap_or_else(|| json!({})))
    }

    pub(crate) async fn send_envelope<T, F>(
        &self,
        operation: &'static str,
        retry_policy: RetryPolicy,
        request_builder: F,
    ) -> Result<CloudflareEnvelope<T>, AdapterError>
    where
        T: DeserializeOwned,
        F: FnMut() -> reqwest::RequestBuilder,
    {
        self.send_envelope_with_decoder(operation, retry_policy, request_builder, |body| {
            decode_cloudflare_envelope(body)
        })
        .await
    }

    /// The manifest migration path has stricter outer-envelope semantics than
    /// generic D1 calls. It rejects omitted, null, non-array, and non-empty
    /// `errors` before returning a result to the migration state machine.
    async fn send_d1_migration_manifest_envelope<F>(
        &self,
        operation: &'static str,
        retry_policy: RetryPolicy,
        request_builder: F,
    ) -> Result<CloudflareEnvelope<Value>, AdapterError>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        self.send_envelope_with_decoder(operation, retry_policy, request_builder, |body| {
            decode_strict_d1_migration_manifest_envelope(body)
        })
        .await
    }

    async fn send_envelope_with_decoder<T, F, D>(
        &self,
        operation: &'static str,
        retry_policy: RetryPolicy,
        mut request_builder: F,
        decode: D,
    ) -> Result<T, AdapterError>
    where
        F: FnMut() -> reqwest::RequestBuilder,
        D: Fn(&str) -> Result<T, AdapterError>,
    {
        let mut attempt = 0u32;
        let max_attempts = self.cfg.max_retries;

        loop {
            let response = match request_builder().send().await {
                Ok(response) => response,
                Err(err) => {
                    let retryable = err.is_timeout() || err.is_connect() || err.is_request();
                    if retry_policy.allows_retry() && retryable && attempt < max_attempts {
                        tokio::time::sleep(backoff_delay(
                            attempt,
                            self.cfg.retry_base_delay,
                            self.cfg.retry_max_delay,
                        ))
                        .await;
                        attempt += 1;
                        continue;
                    }
                    let code = if err.is_timeout() {
                        "cloudflare.timeout"
                    } else {
                        "cloudflare.transport_error"
                    };
                    return Err(AdapterError::new(
                        code,
                        format!("{operation} request failed: {err}"),
                        "Check Cloudflare API reachability, token validity, and timeout settings.",
                    )
                    .with_retryable(retryable));
                }
            };

            let status = response.status();
            let retry_after = parse_retry_after(response.headers());
            let body = response.text().await.map_err(|err| {
                AdapterError::new(
                    "cloudflare.response_read_failed",
                    format!("failed reading Cloudflare response body: {err}"),
                    "Retry request and inspect Cloudflare API availability.",
                )
            })?;

            if retry_policy.allows_retry() && is_retryable_status(status) && attempt < max_attempts
            {
                let delay = retry_after.unwrap_or_else(|| {
                    backoff_delay(attempt, self.cfg.retry_base_delay, self.cfg.retry_max_delay)
                });
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }

            if !status.is_success() {
                return Err(http_status_error(status, &body));
            }

            return decode(&body);
        }
    }

    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.cfg.api_base_url.trim_end_matches('/'),
            path.trim_start_matches('/'),
        )
    }

    pub(crate) fn bearer_token(&self) -> Result<String, AdapterError> {
        let configured_token = self
            .cfg
            .api_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let request_header_token = REQUEST_API_TOKEN_OVERRIDE
            .try_with(Clone::clone)
            .ok()
            .flatten()
            .map(|token| token.trim().to_string())
            .filter(|value| !value.is_empty());

        let token = match self.cfg.api_token_source {
            ApiTokenSource::Config => configured_token.map(str::to_string),
            ApiTokenSource::Header => request_header_token,
            ApiTokenSource::HeaderOrConfig => {
                request_header_token.or_else(|| configured_token.map(str::to_string))
            }
        };

        token.ok_or_else(|| {
            let hint = if self.cfg.api_token_source.uses_request_header() {
                "Provide the request header token (default header: x-cloudflare-api-token) or configure CLOUDFLARE_MCP_API_TOKEN."
            } else {
                "Set CLOUDFLARE_MCP_API_TOKEN with a Cloudflare API token scoped for tunnels, DNS, and Access APIs."
            };
            AdapterError::new(
                "cloudflare.config_missing_token",
                "No Cloudflare API token is available for this request",
                hint,
            )
        })
    }
}

fn require_non_empty<'a>(name: &'static str, value: &'a str) -> Result<&'a str, AdapterError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::new(
            "cloudflare.invalid_argument",
            format!("{name} must not be empty"),
            "Provide a non-empty identifier.",
        ));
    }
    Ok(trimmed)
}

pub(crate) fn is_d1_sqlite_auth_error(err: &AdapterError) -> bool {
    let mut message = err.message.to_ascii_lowercase();
    if let Some(api_message) = err.cloudflare_api_error_message() {
        message.push(' ');
        message.push_str(&api_message.to_ascii_lowercase());
    }
    if message.contains("no such column") || message.contains("no such table") {
        return false;
    }
    message.contains("sqlite_auth")
        || message.contains("not authorized")
        || message.contains("authorization policy")
        || message.contains("access denied")
        || err.cloudflare_api_error_code() == Some(7500)
}

fn is_d1_catalog_discovery_query(sql: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    upper.contains("SQLITE_MASTER") || upper.contains("SQLITE_SCHEMA")
}

fn d1_schema_to_query_result(schema: Value) -> Value {
    let objects = schema
        .get("objects")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut meta = Map::new();
    meta.insert("d1_catalog_fallback".to_string(), Value::Bool(true));
    if let Some(strategy) = schema.get("discovery_strategy").cloned() {
        meta.insert("discovery_strategy".to_string(), strategy);
    }
    if let Some(fidelity) = schema.get("discovery_fidelity").cloned() {
        meta.insert("discovery_fidelity".to_string(), fidelity);
    }

    json!([{
        "success": true,
        "results": objects,
        "meta": Value::Object(meta),
    }])
}

fn d1_result_rows(result: &Value) -> Vec<Value> {
    match result {
        Value::Array(items) => items
            .iter()
            .flat_map(|item| d1_result_rows_from_item(item).into_iter())
            .collect(),
        other => d1_result_rows_from_item(other),
    }
}

fn d1_result_rows_from_item(item: &Value) -> Vec<Value> {
    item.get("results")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| item.as_array().cloned())
        .unwrap_or_default()
}

fn d1_table_list_rows_to_schema_objects(result: &Value) -> Vec<Value> {
    let mut objects: Vec<Value> = d1_result_rows(result)
        .into_iter()
        .filter(|row| {
            row.get("schema")
                .and_then(Value::as_str)
                .is_none_or(|schema| schema == "main")
        })
        .filter_map(|row| {
            let name = row.get("name").and_then(Value::as_str)?;
            if name.starts_with("sqlite_") {
                return None;
            }
            let object_type = match row.get("type").and_then(Value::as_str) {
                Some("table") => "table",
                Some("view") => "view",
                Some("shadow") => "shadow",
                Some("virtual") => "virtual",
                _ => return None,
            };
            Some(json!({
                "type": object_type,
                "name": name,
                "tbl_name": name,
                "sql": Value::Null,
            }))
        })
        .collect();
    objects.sort_by(|left, right| {
        let left_name = left.get("name").and_then(Value::as_str).unwrap_or("");
        let right_name = right.get("name").and_then(Value::as_str).unwrap_or("");
        left_name.cmp(right_name).then_with(|| {
            let left_type = left.get("type").and_then(Value::as_str).unwrap_or("");
            let right_type = right.get("type").and_then(Value::as_str).unwrap_or("");
            left_type.cmp(right_type)
        })
    });
    objects
}

struct D1SchemaObjectSelection {
    objects: Vec<Value>,
    skipped_internal: Vec<Value>,
    filtered_out: Vec<Value>,
}

fn d1_include_table_names(include_tables: &[String]) -> BTreeSet<String> {
    include_tables
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

fn d1_select_application_schema_objects(
    objects: Vec<Value>,
    include_tables: &BTreeSet<String>,
    include_table_pattern: Option<&str>,
) -> D1SchemaObjectSelection {
    let include_table_pattern = include_table_pattern.map(|pattern| pattern.to_ascii_lowercase());
    let filter_applied = !include_tables.is_empty() || include_table_pattern.is_some();
    let mut selected = Vec::new();
    let mut skipped_internal = Vec::new();
    let mut filtered_out = Vec::new();

    for object in objects {
        if d1_schema_object_is_cloudflare_internal(&object) {
            skipped_internal.push(d1_schema_object_skip(
                &object,
                "cloudflare_internal",
                "Cloudflare-owned D1 internal objects are skipped because column PRAGMA calls can return SQLITE_AUTH; application schema discovery is unaffected.",
            ));
            continue;
        }

        if filter_applied
            && !d1_schema_object_matches_filter(
                &object,
                include_tables,
                include_table_pattern.as_deref(),
            )
        {
            filtered_out.push(d1_schema_object_skip(
                &object,
                "include_filter_not_matched",
                "Object did not match include_tables or include_table_pattern.",
            ));
            continue;
        }

        selected.push(object);
    }

    D1SchemaObjectSelection {
        objects: selected,
        skipped_internal,
        filtered_out,
    }
}

fn d1_schema_object_matches_filter(
    object: &Value,
    include_tables: &BTreeSet<String>,
    include_table_pattern: Option<&str>,
) -> bool {
    let names = d1_schema_object_filter_names(object);
    if names.is_empty() {
        return false;
    }

    names.iter().any(|name| include_tables.contains(name))
        || include_table_pattern.is_some_and(|pattern| {
            names
                .iter()
                .any(|name| simple_glob_match(pattern.as_bytes(), name.as_bytes()))
        })
}

fn d1_schema_object_filter_names(object: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for key in ["name", "tbl_name"] {
        if let Some(name) = object.get(key).and_then(Value::as_str) {
            let name = name.trim();
            if !name.is_empty() {
                let name = name.to_ascii_lowercase();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

fn d1_schema_object_is_cloudflare_internal(object: &Value) -> bool {
    d1_schema_object_filter_names(object)
        .iter()
        .any(|name| name.starts_with("_cf_"))
}

fn d1_schema_object_skip(object: &Value, reason: &str, hint: &str) -> Value {
    json!({
        "name": object.get("name").cloned().unwrap_or(Value::Null),
        "tbl_name": object.get("tbl_name").cloned().unwrap_or(Value::Null),
        "object_type": object.get("type").cloned().unwrap_or(Value::Null),
        "reason": reason,
        "hint": hint,
    })
}

fn d1_schema_inspection_summary(
    objects: &[Value],
    columns: Option<&Value>,
    column_errors: &[Value],
    skipped_internal: &[Value],
    filter_applied: bool,
) -> Value {
    let column_rows = columns
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();
    let status = if objects.is_empty() && !skipped_internal.is_empty() {
        "internal_only"
    } else if objects.is_empty() && filter_applied {
        "no_matching_application_tables"
    } else if objects.is_empty() {
        "no_application_tables"
    } else if !column_errors.is_empty() {
        "partial_application_schema"
    } else {
        "application_schema"
    };
    let message = match status {
        "internal_only" => {
            "only internal Cloudflare D1 objects were discovered; no application schema was returned"
        }
        "no_matching_application_tables" => {
            "no application tables matched include_tables or include_table_pattern"
        }
        "no_application_tables" => "schema discovery succeeded but returned no application tables",
        "partial_application_schema" => {
            "schema returned for application tables; some application column metadata could not be read"
        }
        _ if !skipped_internal.is_empty() => {
            "schema returned for application tables; internal Cloudflare tables skipped"
        }
        _ => "schema returned for application tables",
    };

    json!({
        "status": status,
        "message": message,
        "application_objects": objects.len(),
        "application_column_rows": column_rows,
        "skipped_internal_tables": skipped_internal.len(),
        "column_errors": column_errors.len(),
    })
}

fn simple_glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut previous = vec![false; text.len() + 1];
    previous[0] = true;
    for &pattern_byte in pattern {
        let mut current = vec![false; text.len() + 1];
        if pattern_byte == b'*' {
            current[0] = previous[0];
            for index in 1..=text.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=text.len() {
                current[index] = previous[index - 1]
                    && (pattern_byte == b'?' || pattern_byte == text[index - 1]);
            }
        }
        previous = current;
    }
    previous[text.len()]
}

struct D1SchemaColumnObject {
    name: String,
    object_type: String,
}

fn d1_schema_column_objects(objects: &[Value]) -> Vec<D1SchemaColumnObject> {
    objects
        .iter()
        .filter(|row| {
            matches!(
                row.get("type").and_then(Value::as_str),
                Some("table") | Some("view") | Some("virtual")
            )
        })
        .filter_map(|row| {
            Some(D1SchemaColumnObject {
                name: row.get("name").and_then(Value::as_str)?.to_string(),
                object_type: row
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("table")
                    .to_string(),
            })
        })
        .filter(|object| !object.name.starts_with("sqlite_"))
        .collect()
}

fn d1_table_info_rows(object: &D1SchemaColumnObject, result: &Value) -> Vec<Value> {
    let table_name = object.name.as_str();
    let object_type = object.object_type.as_str();
    let derived = object_type == "view";

    d1_result_rows(result)
        .into_iter()
        .map(|row| {
            json!({
                "table_name": table_name,
                "object_type": object_type,
                "column_id": row.get("cid").cloned().unwrap_or(Value::Null),
                "column_name": row.get("name").cloned().unwrap_or(Value::Null),
                "column_type": row.get("type").cloned().unwrap_or(Value::Null),
                "not_null": row.get("notnull").cloned().unwrap_or(Value::Null),
                "default_value": row.get("dflt_value").cloned().unwrap_or(Value::Null),
                "primary_key": row.get("pk").cloned().unwrap_or(Value::Null),
                "derived": derived,
                "source": "pragma_table_info",
            })
        })
        .collect()
}

fn d1_column_discovery_error(table_name: &str, err: &AdapterError) -> Value {
    json!({
        "table_name": table_name,
        "code": err.code,
        "message": err.message,
        "hint": "D1 denied column discovery for this table at the SQLite authorization layer; schema objects and other readable columns are still returned.",
        "status": err.status,
    })
}

fn sqlite_quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn d1_table_list_fidelity() -> Value {
    json!({
        "mode": "lossy",
        "limitations": [
            "sql_ddl",
            "indexes",
            "triggers",
        ],
    })
}

fn d1_column_discovery_fidelity() -> Value {
    json!({
        "mode": "partial",
        "limitations": [
            "some_table_columns",
        ],
    })
}

fn path_segment(value: &str) -> String {
    aws_uri_encode(value, true)
}

fn null_as_default_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

fn decode_cloudflare_envelope<T>(body: &str) -> Result<CloudflareEnvelope<T>, AdapterError>
where
    T: DeserializeOwned,
{
    let envelope: CloudflareEnvelope<T> = serde_json::from_str(body).map_err(|err| {
        AdapterError::new(
            "cloudflare.decode_error",
            format!("failed decoding Cloudflare envelope: {err}"),
            "Verify Cloudflare endpoint compatibility with expected response schema.",
        )
    })?;
    if !envelope.success {
        return Err(api_error(&envelope.errors));
    }
    Ok(envelope)
}

fn decode_strict_d1_migration_manifest_envelope(
    body: &str,
) -> Result<CloudflareEnvelope<Value>, AdapterError> {
    let value = decode_json_rejecting_duplicate_object_keys(body).map_err(|error| match error {
        DuplicateSafeJsonError::DuplicateObjectKey => manifest_duplicate_object_key_error(),
        DuplicateSafeJsonError::Malformed(error) => AdapterError::new(
            "cloudflare.d1.migration_manifest_malformed_envelope",
            format!("failed decoding strict D1 migration-manifest envelope: {error}"),
            "Treat the manifest operation as ambiguous and reconcile the exact provider ledger before another apply.",
        ),
    })?;
    let envelope: StrictD1MigrationManifestEnvelope<Value> =
        serde_json::from_value(value).map_err(|err| {
            AdapterError::new(
                "cloudflare.d1.migration_manifest_malformed_envelope",
                format!("failed decoding strict D1 migration-manifest envelope: {err}"),
                "Treat the manifest operation as ambiguous and reconcile the exact provider ledger before another apply.",
            )
        })?;

    validate_strict_d1_migration_manifest_envelope(envelope)
}

fn validate_strict_d1_migration_manifest_envelope(
    envelope: StrictD1MigrationManifestEnvelope<Value>,
) -> Result<CloudflareEnvelope<Value>, AdapterError> {
    let errors = match envelope.errors {
        Some(Value::Array(errors)) if errors.is_empty() => Vec::new(),
        Some(Value::Array(_)) => {
            return Err(AdapterError::new(
                "cloudflare.d1.migration_manifest_contradictory_envelope",
                "Cloudflare D1 migration-manifest envelope reported a non-empty errors array",
                "Treat the manifest operation as ambiguous and reconcile the exact provider ledger before another apply.",
            ));
        }
        Some(Value::Null) | None => {
            return Err(AdapterError::new(
                "cloudflare.d1.migration_manifest_malformed_envelope",
                "Cloudflare D1 migration-manifest envelope omitted errors or supplied null",
                "Treat the manifest operation as ambiguous and reconcile the exact provider ledger before another apply.",
            ));
        }
        Some(_) => {
            return Err(AdapterError::new(
                "cloudflare.d1.migration_manifest_malformed_envelope",
                "Cloudflare D1 migration-manifest envelope errors field was not an array",
                "Treat the manifest operation as ambiguous and reconcile the exact provider ledger before another apply.",
            ));
        }
    };

    if !envelope.success {
        return Err(AdapterError::new(
            "cloudflare.d1.migration_manifest_unsuccessful_envelope",
            "Cloudflare D1 migration-manifest envelope did not report success",
            "Treat the manifest operation as ambiguous and reconcile the exact provider ledger before another apply.",
        ));
    }

    Ok(CloudflareEnvelope {
        success: true,
        result: envelope.result,
        errors,
        messages: Vec::new(),
        result_info: None,
    })
}

const DUPLICATE_JSON_OBJECT_KEY_MARKER: &str = "duplicate JSON object key";

struct DuplicateSafeJsonValue(Value);

enum DuplicateSafeJsonError {
    DuplicateObjectKey,
    Malformed(serde_json::Error),
}

impl<'de> Deserialize<'de> for DuplicateSafeJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateSafeJsonValueVisitor)
    }
}

struct DuplicateSafeJsonValueVisitor;

impl<'de> Visitor<'de> for DuplicateSafeJsonValueVisitor {
    type Value = DuplicateSafeJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateSafeJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateSafeJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateSafeJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(DuplicateSafeJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateSafeJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateSafeJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateSafeJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateSafeJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<DuplicateSafeJsonValue>()? {
            values.push(value.0);
        }
        Ok(DuplicateSafeJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(DUPLICATE_JSON_OBJECT_KEY_MARKER));
            }
            let value = object.next_value::<DuplicateSafeJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(DuplicateSafeJsonValue(Value::Object(values)))
    }
}

fn decode_strict_d1_migration_reconciliation_envelope(
    body: &str,
) -> Result<CloudflareEnvelope<Value>, AdapterError> {
    let value = decode_json_rejecting_duplicate_object_keys(body).map_err(|error| match error {
        DuplicateSafeJsonError::DuplicateObjectKey => reconciliation_duplicate_object_key_error(),
        DuplicateSafeJsonError::Malformed(error) => AdapterError::new(
            "cloudflare.d1.migration_manifest_malformed_envelope",
            format!("failed decoding strict D1 reconciliation envelope: {error}"),
            "Treat the provider evidence as contradictory and retain the lease.",
        ),
    })?;
    let envelope: StrictD1MigrationManifestEnvelope<Value> = serde_json::from_value(value)
        .map_err(|error| {
            AdapterError::new(
                "cloudflare.d1.migration_manifest_malformed_envelope",
                format!("failed decoding strict D1 reconciliation envelope: {error}"),
                "Treat the provider evidence as contradictory and retain the lease.",
            )
        })?;
    validate_strict_d1_migration_manifest_envelope(envelope)
}

fn classify_d1_migration_provider_error(body: &str) -> Option<D1MigrationProviderError> {
    let Value::Object(envelope) = decode_json_rejecting_duplicate_object_keys(body).ok()? else {
        return None;
    };
    if envelope.len() != 4
        || envelope.get("success") != Some(&Value::Bool(false))
        || envelope.get("result") != Some(&Value::Null)
        || !matches!(envelope.get("messages"), Some(Value::Array(messages)) if messages.is_empty())
    {
        return None;
    }
    let errors = envelope.get("errors")?.as_array()?;
    let [Value::Object(error)] = errors.as_slice() else {
        return None;
    };
    if error.len() != 2 || !error.get("message").is_some_and(Value::is_string) {
        return None;
    }
    let code = error.get("code")?.as_i64()?;
    let category = match code {
        7_500 => "d1_error",
        10_000 => "authentication_error",
        _ => return None,
    };
    Some(D1MigrationProviderError { code, category })
}

fn decode_json_rejecting_duplicate_object_keys(
    body: &str,
) -> Result<Value, DuplicateSafeJsonError> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let value = DuplicateSafeJsonValue::deserialize(&mut deserializer).map_err(|error| {
        if error.to_string().contains(DUPLICATE_JSON_OBJECT_KEY_MARKER) {
            DuplicateSafeJsonError::DuplicateObjectKey
        } else {
            DuplicateSafeJsonError::Malformed(error)
        }
    })?;
    deserializer
        .end()
        .map_err(DuplicateSafeJsonError::Malformed)?;
    Ok(value.0)
}

fn reconciliation_duplicate_object_key_error() -> AdapterError {
    AdapterError::new(
        "cloudflare.d1.migration_reconciliation_duplicate_object_key",
        "Cloudflare reconciliation response contained a duplicate JSON object key",
        "Treat the provider evidence as contradictory and retain the lease.",
    )
}

fn manifest_duplicate_object_key_error() -> AdapterError {
    AdapterError::new(
        "cloudflare.d1.migration_manifest_duplicate_object_key",
        "Cloudflare migration-manifest response contained a duplicate JSON object key",
        "Treat the manifest operation as ambiguous and do not create custody or submit migration SQL.",
    )
}

fn header_value(name: &'static str, value: &str) -> Result<HeaderValue, AdapterError> {
    HeaderValue::from_str(value).map_err(|err| {
        let mut message = String::from(name);
        message.push_str(" header value is invalid: ");
        message.push_str(&err.to_string());
        AdapterError::new(
            "cloudflare.invalid_header",
            message,
            "Check configured endpoint, credentials, and request arguments for invalid characters.",
        )
    })
}

fn header_string(headers: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn r2_custom_metadata(headers: &HeaderMap) -> std::collections::BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str();
            let key = name.strip_prefix("x-amz-meta-")?;
            value
                .to_str()
                .ok()
                .map(|value| (key.to_string(), value.to_string()))
        })
        .collect()
}

fn aws_uri_encode(value: &str, encode_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b'/' if !encode_slash => encoded.push('/'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn aws_short_date(now: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

fn aws_amz_date(now: OffsetDateTime) -> String {
    format!(
        "{}T{:02}{:02}{:02}Z",
        aws_short_date(now),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(Sha256::digest(bytes).as_slice())
}

fn aws_signing_signature(
    secret_access_key: &str,
    short_date: &str,
    string_to_sign: &str,
) -> Result<String, AdapterError> {
    let date_key = hmac_sha256(
        format!("AWS4{secret_access_key}").as_bytes(),
        short_date.as_bytes(),
    )?;
    let region_key = hmac_sha256(&date_key, b"auto")?;
    let service_key = hmac_sha256(&region_key, b"s3")?;
    let signing_key = hmac_sha256(&service_key, b"aws4_request")?;
    Ok(hex_lower(&hmac_sha256(
        &signing_key,
        string_to_sign.as_bytes(),
    )?))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AdapterError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|err| {
        AdapterError::new(
            "cloudflare.r2_signing_failed",
            format!("failed to initialize R2 request signer: {err}"),
            "Check R2 credential material.",
        )
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn normalize_ttl(value: Option<u32>) -> Option<u32> {
    value.filter(|ttl| *ttl > 0)
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

#[derive(Debug, Clone, Copy)]
struct WorkerVersionPageMetadata {
    page: u32,
    per_page: u32,
    count: Option<u32>,
    total_count: u32,
    total_pages: u32,
}

fn worker_version_page_metadata(
    value: &Value,
    result_info: Option<&PageInfo>,
    expected_page: u32,
) -> Result<WorkerVersionPageMetadata, AdapterError> {
    let pagination_value = value.get("pagination");
    let result_info = result_info.ok_or_else(|| {
        AdapterError::new(
            "workers.upload_version_readback_pagination_invalid",
            "Worker version readback omitted authoritative result_info pagination metadata",
            "Reconcile the provider response before retrying or continuing the create-only sequence.",
        )
    })?;
    let page = result_info.page.ok_or_else(|| {
        AdapterError::new(
            "workers.upload_version_readback_pagination_invalid",
            "Worker version result_info omitted page",
            "Reconcile the provider response before retrying or continuing the create-only sequence.",
        )
    })?;
    let per_page = result_info.per_page.ok_or_else(|| {
        AdapterError::new(
            "workers.upload_version_readback_pagination_invalid",
            "Worker version result_info omitted per_page",
            "Reconcile the provider response before retrying or continuing the create-only sequence.",
        )
    })?;
    let total_count = result_info.total_count.ok_or_else(|| {
        AdapterError::new(
            "workers.upload_version_readback_pagination_invalid",
            "Worker version result_info omitted total_count",
            "Reconcile the provider response before retrying or continuing the create-only sequence.",
        )
    })?;
    let derived_total_pages = if total_count == 0 {
        1
    } else if per_page == 0 {
        0
    } else {
        total_count / per_page + if total_count % per_page != 0 { 1 } else { 0 }
    };
    let outer = WorkerVersionPageMetadata {
        page,
        per_page,
        count: result_info.count,
        total_count,
        total_pages: result_info.total_pages.unwrap_or(derived_total_pages),
    };
    let page_item_count = value
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| {
            AdapterError::new(
                "workers.upload_version_readback_invalid",
                "Worker version readback did not contain an items array for pagination validation",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            )
        })?;
    if outer
        .count
        .is_some_and(|count| count as usize != page_item_count)
    {
        return Err(AdapterError::new(
            "workers.upload_version_readback_pagination_conflict",
            "Worker version page count did not match its authoritative result_info count",
            "Reconcile the provider response before retrying or continuing the create-only sequence.",
        ));
    }
    if let Some(pagination) = pagination_value {
        let pagination = pagination.as_object().ok_or_else(|| {
            AdapterError::new(
                "workers.upload_version_readback_pagination_invalid",
                "Worker version nested pagination metadata was not an object",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            )
        })?;
        let number = |name: &str| {
            pagination
                .get(name)
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| {
                    AdapterError::new(
                        "workers.upload_version_readback_pagination_invalid",
                        format!("Worker version nested pagination field {name} was missing or invalid"),
                        "Reconcile the provider response before retrying or continuing the create-only sequence.",
                    )
                })
        };
        let optional_number = |name: &str| {
            pagination
                .get(name)
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or_else(|| {
                            AdapterError::new(
                                "workers.upload_version_readback_pagination_invalid",
                                format!("Worker version nested pagination field {name} was invalid"),
                                "Reconcile the provider response before retrying or continuing the create-only sequence.",
                            )
                        })
                })
                .transpose()
        };
        let nested_page = number("page")?;
        let nested_per_page = number("per_page")?;
        let nested_total_count = number("total_count")?;
        if nested_page == 0 || nested_per_page == 0 {
            return Err(AdapterError::new(
                "workers.upload_version_readback_pagination_invalid",
                "Worker version nested pagination page or per_page was zero",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            ));
        }
        let nested_derived_total_pages = if nested_total_count == 0 {
            1
        } else {
            nested_total_count / nested_per_page
                + if nested_total_count % nested_per_page != 0 {
                    1
                } else {
                    0
                }
        };
        let nested = WorkerVersionPageMetadata {
            page: nested_page,
            per_page: nested_per_page,
            count: optional_number("count")?,
            total_count: nested_total_count,
            total_pages: pagination
                .get("total_pages")
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or_else(|| {
                            AdapterError::new(
                                "workers.upload_version_readback_pagination_invalid",
                                "Worker version nested pagination total_pages was invalid",
                                "Reconcile the provider response before retrying or continuing the create-only sequence.",
                            )
                        })
                })
                .transpose()?
                .unwrap_or(nested_derived_total_pages),
        };
        if nested
            .count
            .is_some_and(|count| count as usize != page_item_count)
        {
            return Err(AdapterError::new(
                "workers.upload_version_readback_pagination_conflict",
                "Worker version nested pagination count did not match its page items",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            ));
        }
        if outer.page != nested.page
            || outer.per_page != nested.per_page
            || outer.total_count != nested.total_count
            || outer.total_pages != nested.total_pages
            || matches!((outer.count, nested.count), (Some(a), Some(b)) if a != b)
        {
            return Err(AdapterError::new(
                "workers.upload_version_readback_pagination_conflict",
                "Worker version readback contained conflicting pagination metadata",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            ));
        }
    }
    if outer.page != expected_page
        || outer.page == 0
        || outer.per_page == 0
        || outer.total_pages == 0
        || outer.total_pages > WORKER_VERSION_MAX_PAGES
        || outer.total_count as usize > WORKER_VERSION_MAX_ITEMS
        || outer.page > outer.total_pages
        || outer.total_pages
            != if outer.total_count == 0 {
                1
            } else {
                outer.total_count / outer.per_page
                    + if outer.total_count % outer.per_page != 0 {
                        1
                    } else {
                        0
                    }
            }
    {
        return Err(AdapterError::new(
            "workers.upload_version_readback_pagination_invalid",
            "Worker version pagination metadata violated the bounded page contract",
            "Reconcile the provider response before retrying or continuing the create-only sequence.",
        ));
    }
    if let Some(count) = outer.count {
        if count as usize > WORKER_VERSION_MAX_ITEMS {
            return Err(AdapterError::new(
                "workers.upload_version_readback_pagination_invalid",
                "Worker version page count exceeded the bounded item contract",
                "Reconcile the provider response before retrying or continuing the create-only sequence.",
            ));
        }
    }
    Ok(outer)
}

fn worker_version_id<'a>(value: &'a Value, message: &'static str) -> Result<&'a str, AdapterError> {
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.trim() == *id)
        .ok_or_else(|| {
            AdapterError::new(
                "workers.upload_version_readback_invalid",
                message,
                "Reconcile the provider response; no create-only upload may continue from malformed version evidence.",
            )
        })
}

fn worker_listing_target<'a>(
    items: &'a [WorkerScript],
    script_name: &str,
) -> Result<&'a WorkerScript, AdapterError> {
    let mut matches = Vec::new();
    for item in items {
        if worker_listing_identity(item)? == script_name {
            matches.push(item);
        }
    }
    if matches.len() != 1 {
        return Err(AdapterError::new(
            "workers.upload_listing_readback_ambiguous",
            format!(
                "Worker listing readback returned {} canonical matches for the created script; expected exactly one",
                matches.len()
            ),
            "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
        ));
    }
    Ok(matches[0])
}

fn worker_listing_identity(script: &WorkerScript) -> Result<&str, AdapterError> {
    let mut identities = Vec::new();
    for identity in [script.script_name.as_deref(), script.id.as_deref()] {
        if let Some(identity) = identity {
            if identity.trim().is_empty() {
                return Err(AdapterError::new(
                    "workers.upload_listing_readback_invalid",
                    "Worker listing item contained a blank identity/name",
                    "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
                ));
            }
            identities.push(identity);
        }
    }
    if let Some(identity) = script.extra.get("name") {
        let identity = identity.as_str().ok_or_else(|| {
            AdapterError::new(
                "workers.upload_listing_readback_invalid",
                "Worker listing item contained a non-string identity/name",
                "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
            )
        })?;
        if identity.trim().is_empty() {
            return Err(AdapterError::new(
                "workers.upload_listing_readback_invalid",
                "Worker listing item contained a blank identity/name",
                "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
            ));
        }
        identities.push(identity);
    }
    let Some(first) = identities.first().copied() else {
        return Err(AdapterError::new(
            "workers.upload_listing_readback_invalid",
            "Worker listing item omitted a canonical identity/name",
            "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
        ));
    };
    if identities.iter().any(|identity| *identity != first) {
        return Err(AdapterError::new(
            "workers.upload_listing_readback_conflict",
            "Worker listing item contained conflicting identity/name fields",
            "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
        ));
    }
    Ok(first)
}

fn worker_script_etag(script: &WorkerScript) -> Result<&str, AdapterError> {
    let etag = script
        .extra
        .get("etag")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .ok_or_else(|| {
            AdapterError::new(
                "workers.upload_listing_readback_invalid",
                "Worker listing item omitted a canonical non-whitespace etag",
                "Reconcile the authenticated Worker listing before retrying or continuing the create-only sequence.",
            )
        })?;
    Ok(etag)
}

fn classify_worker_upload_error(err: AdapterError, create_only: bool) -> AdapterError {
    if create_only && err.status == Some(StatusCode::PRECONDITION_FAILED.as_u16()) {
        return AdapterError::new(
            "workers.upload_create_only_conflict",
            "Worker script already exists; create_only upload was not applied",
            "Use a new script name, or omit create_only when an update is intentional.",
        )
        .with_status(Some(StatusCode::PRECONDITION_FAILED.as_u16()));
    }

    if create_only
        && (matches!(
            err.code,
            "cloudflare.timeout"
                | "cloudflare.transport_error"
                | "cloudflare.response_read_failed"
                | "cloudflare.decode_error"
                | "cloudflare.empty_result"
        ) || err
            .status
            .is_some_and(|status| (500..=599).contains(&status)))
    {
        return AdapterError::new(
            "workers.upload_create_only_outcome_uncertain",
            format!(
                "Worker create-only upload outcome is uncertain after request dispatch: {}",
                err.message
            ),
            "Do not retry or claim creation; read back the Worker script and reconcile provider evidence before deciding whether to continue.",
        )
        .with_retryable(false)
        .with_status(err.status);
    }

    err
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let seconds = raw.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}

fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let multiplier = 2u32.saturating_pow(cmp::min(attempt, 10));
    let raw = base.saturating_mul(multiplier);
    cmp::min(raw, max)
}

fn api_error(errors: &[CloudflareApiError]) -> AdapterError {
    let cloudflare_api_error = errors.first().cloned();
    let detail = cloudflare_api_error
        .as_ref()
        .map(cloudflare_api_error_detail)
        .unwrap_or_else(|| {
            "Cloudflare API returned success=false without error details".to_string()
        });

    let mut error = AdapterError::new(
        "cloudflare.api_error",
        detail,
        "Inspect account/zone permissions and Cloudflare API request payload.",
    )
    .with_cloudflare_api_error(cloudflare_api_error)
    .with_status(Some(StatusCode::BAD_REQUEST.as_u16()));
    if error
        .cloudflare_api_error_code()
        .is_some_and(|code| code == 7003)
        || error
            .message
            .to_ascii_lowercase()
            .contains("resource not found")
    {
        error = error.with_classification(wrong_account_or_zone_context_classification());
    }
    error
}

fn http_status_error(status: StatusCode, body: &str) -> AdapterError {
    let envelope_error = serde_json::from_str::<CloudflareEnvelope<Value>>(body)
        .ok()
        .and_then(|envelope| envelope.errors.first().cloned());

    let detail = envelope_error
        .as_ref()
        .map(cloudflare_api_error_detail)
        .unwrap_or_else(|| {
            let fallback = sanitize_error_message(body, 256);
            if fallback.is_empty() {
                format!("HTTP status {}", status.as_u16())
            } else {
                format!("HTTP status {}: {fallback}", status.as_u16())
            }
        });

    let (code, hint) = match status {
        StatusCode::UNAUTHORIZED => (
            "cloudflare.http_unauthorized",
            "Verify CLOUDFLARE_MCP_API_TOKEN has not expired and is correctly configured.",
        ),
        StatusCode::FORBIDDEN => (
            "cloudflare.http_forbidden",
            "Token lacks required scopes for this Cloudflare endpoint.",
        ),
        StatusCode::NOT_FOUND => (
            "cloudflare.http_not_found",
            "Verify account_id/zone_id/app_id values and endpoint path.",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "cloudflare.http_rate_limited",
            "Request was rate-limited; retry with backoff and consider lower request concurrency.",
        ),
        _ if status.is_server_error() => (
            "cloudflare.http_server_error",
            "Cloudflare service error. Retry later or inspect Cloudflare status.",
        ),
        _ => (
            "cloudflare.http_error",
            "Inspect request payload and Cloudflare API response details.",
        ),
    };

    let error = AdapterError::new(code, detail, hint)
        .with_cloudflare_api_error(envelope_error)
        .with_retryable(is_retryable_status(status))
        .with_status(Some(status.as_u16()));
    match status {
        StatusCode::UNAUTHORIZED => {
            error.with_classification(invalid_or_expired_token_classification())
        }
        StatusCode::NOT_FOUND => {
            error.with_classification(wrong_account_or_zone_context_classification())
        }
        _ => error,
    }
}

fn d1_migration_reconciliation_http_status_error(status: StatusCode) -> AdapterError {
    let (code, hint) = match status {
        StatusCode::UNAUTHORIZED => (
            "cloudflare.http_unauthorized",
            "Verify the configured API token before another reconciliation read.",
        ),
        StatusCode::FORBIDDEN => (
            "cloudflare.http_forbidden",
            "Verify the token's D1 read scope before another reconciliation read.",
        ),
        StatusCode::NOT_FOUND => (
            "cloudflare.http_not_found",
            "Verify the retained target identity before another reconciliation read.",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "cloudflare.http_rate_limited",
            "Treat reconciliation evidence as unavailable and retain custody.",
        ),
        _ if status.is_server_error() => (
            "cloudflare.http_server_error",
            "Treat reconciliation evidence as unavailable and retain custody.",
        ),
        _ => (
            "cloudflare.http_error",
            "Treat reconciliation evidence as contradictory and retain custody.",
        ),
    };
    AdapterError::new(
        code,
        format!(
            "Cloudflare D1 reconciliation returned HTTP status {}",
            status.as_u16()
        ),
        hint,
    )
    .with_retryable(false)
    .with_status(Some(status.as_u16()))
}

fn invalid_or_expired_token_classification() -> ErrorClassificationPayload {
    ErrorClassificationPayload {
        code: "invalid_or_expired_token",
        next_step: "Refresh the configured API token or run account_api_tokens action=verify to confirm the token is still active.",
    }
}

fn wrong_account_or_zone_context_classification() -> ErrorClassificationPayload {
    ErrorClassificationPayload {
        code: "wrong_account_or_zone_context",
        next_step: "Verify the account_id, zone_id, token_id, or GraphQL filter variables before retrying the same request.",
    }
}

fn cloudflare_api_error_detail(error: &CloudflareApiError) -> String {
    match (error.code, error.message.as_deref()) {
        (Some(code), Some(message)) => format!("Cloudflare API error {code}: {message}"),
        (Some(code), None) => format!("Cloudflare API error {code}"),
        (None, Some(message)) => format!("Cloudflare API error: {message}"),
        (None, None) => "Cloudflare API returned an unknown error".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::{Body, Bytes};
    use axum::extract::{OriginalUri, Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::Response;
    use axum::routing::{get, post, put};
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        AdapterError, CloudflareApiError, CloudflareClient, D1_MIGRATION_RESPONSE_MAX_BYTES,
        D1MigrationManifestWriteLifecycle, D1MigrationProviderError,
        D1MigrationReconciliationReadLifecycle, classify_d1_migration_provider_error,
        decode_strict_d1_migration_manifest_envelope,
        decode_strict_d1_migration_reconciliation_envelope, is_d1_sqlite_auth_error, path_segment,
        with_request_api_token_override, worker_listing_identity, worker_version_id,
        worker_version_page_metadata,
    };
    use crate::cloudflare::model::{AccessPolicyWrite, PageInfo, WorkerScript};
    use crate::config::{ApiTokenSource, CloudflareApiConfig};

    fn fixture_material(label: &str) -> String {
        let mut value = String::from("fixture-");
        value.push_str(label);
        value.push_str("-value");
        value
    }

    fn test_config(base_url: String) -> CloudflareApiConfig {
        CloudflareApiConfig {
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
            max_retries: 2,
            retry_base_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(5),
            user_agent: "cloudflare-mcp-test".to_string(),
        }
    }

    fn test_config_with_r2_endpoint(base_url: String, r2_endpoint: String) -> CloudflareApiConfig {
        let mut cfg = test_config(base_url);
        cfg.r2_endpoint = Some(r2_endpoint);
        cfg
    }

    async fn spawn_router(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        format!("http://{}", addr)
    }

    fn refused_loopback_url(path: &str) -> String {
        format!("http://{}:9/{path}", std::net::Ipv4Addr::LOCALHOST) // DevSkim: ignore DS137138 -- loopback-only transport fixture
    }

    #[test]
    fn path_segment_encodes_separators() {
        assert_eq!(path_segment("zone/one two"), "zone%2Fone%20two");
    }

    #[tokio::test]
    async fn d1_account_and_database_path_segments_cannot_inject_path_query_or_fragment() {
        async fn query(OriginalUri(uri): OriginalUri) -> Json<Value> {
            assert_eq!(
                uri.to_string(),
                "/accounts/acct%2Fone%3Fnext%3D1%23fragment/d1/database/db%2Fone%3Fnext%3D1%23fragment/query"
            );
            Json(json!({"success": true, "errors": [], "messages": [], "result": []}))
        }

        let base = spawn_router(Router::new().route("/{*path}", post(query))).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        client
            .query_d1_database(
                "acct/one?next=1#fragment",
                "db/one?next=1#fragment",
                "SELECT 1",
                &[],
            )
            .await
            .expect("encoded D1 query");
    }

    #[tokio::test]
    async fn oversized_reconciliation_response_preserves_http_status() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let router = Router::new().route(
                "/accounts/acct-1/d1/database/db-1/query",
                post(move || async move {
                    let oversized_body = vec![b'x'; 16 * 1024 * 1024 + 1];
                    Response::builder()
                        .status(status)
                        .header("content-length", oversized_body.len().to_string())
                        .body(Body::from(oversized_body))
                        .expect("oversized response")
                }),
            );
            let base = spawn_router(router).await;
            let client = CloudflareClient::new(test_config(base)).expect("client");
            let error = client
                .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
                .await
                .expect_err("oversized reconciliation response must fail closed");
            assert_eq!(
                error.error.code,
                "cloudflare.d1.migration_reconciliation_response_too_large"
            );
            assert_eq!(error.error.status, Some(status.as_u16()));
            assert_eq!(error.response_body_sha256, None);
            assert_eq!(error.lifecycle.provider_calls(), 1);
            assert_eq!(
                error.lifecycle,
                D1MigrationReconciliationReadLifecycle::response_received(status.as_u16())
            );
        }
    }

    #[tokio::test]
    async fn reconciliation_http_error_surfaces_only_allowlisted_code_and_category() {
        let private_message = "SQL SELECT * FROM private_table at /private/path";
        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            post(move || async move {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "errors": [{"code": 7500, "message": private_message}],
                        "messages": [],
                        "result": null,
                    })),
                )
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
            .await
            .expect_err("HTTP error must fail closed");
        assert_eq!(
            error.provider_error,
            Some(D1MigrationProviderError {
                code: 7_500,
                category: "d1_error",
            })
        );
        assert_eq!(error.error.code, "cloudflare.http_error");
        assert!(!error.error.message.contains(private_message));
        assert!(!error.error.message.contains("private_table"));
        assert_eq!(error.error.status, Some(400));
        assert_eq!(error.lifecycle.body_stage, "completely_read");
        assert!(error.response_body_sha256.is_some());
    }

    #[tokio::test]
    async fn reconciliation_pre_dispatch_failure_has_zero_provider_calls() {
        let mut cfg = test_config(refused_loopback_url("pre-dispatch"));
        cfg.api_token = None;
        let client = CloudflareClient::new(cfg).expect("client");
        let error = client
            .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
            .await
            .expect_err("missing token must fail before dispatch");
        assert_eq!(error.error.code, "cloudflare.config_missing_token");
        assert_eq!(error.error.status, None);
        assert_eq!(error.lifecycle.provider_calls(), 0);
        assert_eq!(
            error.lifecycle,
            D1MigrationReconciliationReadLifecycle::pre_dispatch()
        );
    }

    #[tokio::test]
    async fn reconciliation_request_builder_failure_remains_pre_dispatch() {
        let mut cfg = test_config(refused_loopback_url("builder-must-not-dispatch"));
        cfg.api_token = Some("invalid\nheader".to_string());
        let client = CloudflareClient::new(cfg).expect("client");
        let error = client
            .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
            .await
            .expect_err("invalid authorization header must fail before dispatch");
        assert_eq!(error.error.code, "cloudflare.request_build_failed");
        assert!(!error.error.retryable);
        assert_eq!(error.lifecycle.provider_calls(), 0);
        assert_eq!(
            error.lifecycle,
            D1MigrationReconciliationReadLifecycle::pre_dispatch()
        );
        assert_eq!(error.response_body_sha256, None);
        assert_eq!(error.response_body_size_bytes, None);
    }

    #[tokio::test]
    async fn reconciliation_transport_failure_records_attempt_without_response() {
        let client =
            CloudflareClient::new(test_config(refused_loopback_url("attempted"))).expect("client");
        let error = client
            .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
            .await
            .expect_err("closed loopback port must fail after dispatch attempt");
        assert_eq!(error.error.status, None);
        assert_eq!(error.lifecycle.provider_calls(), 1);
        assert_eq!(
            error.lifecycle,
            D1MigrationReconciliationReadLifecycle::attempted_without_response()
        );
    }

    #[tokio::test]
    async fn reconciliation_stream_failures_distinguish_zero_and_partial_body_reads() {
        async fn spawn_truncated_response(
            prefix: Option<Bytes>,
            calls: Arc<AtomicUsize>,
        ) -> String {
            let listener = TcpListener::bind("127.0.0.1:0") // DevSkim: ignore DS162092 -- loopback-only reconciliation stream fixture
                .await
                .expect("bind truncated response fixture");
            let addr = listener.local_addr().expect("truncated fixture address");
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let count = stream.read(&mut chunk).await.expect("read request");
                    assert!(count > 0, "request closed before complete headers and body");
                    request.extend_from_slice(&chunk[..count]);
                    let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let headers = std::str::from_utf8(&request[..header_end])
                        .expect("request headers are UTF-8");
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("content length"))
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
                calls.fetch_add(1, Ordering::SeqCst);
                stream
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n")
                    .await
                    .expect("write truncated response headers");
                if let Some(prefix) = prefix {
                    stream
                        .write_all(&prefix)
                        .await
                        .expect("write partial response body");
                }
            });
            format!("http://{addr}") // DevSkim: ignore DS137138 -- loopback-only reconciliation stream fixture
        }

        for (prefix, expected_size, expected_lifecycle) in [
            (
                None,
                0,
                D1MigrationReconciliationReadLifecycle::response_received(503),
            ),
            (
                Some(Bytes::from_static(b"{")),
                1,
                D1MigrationReconciliationReadLifecycle::body_partially_read(503),
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let base = spawn_truncated_response(prefix, calls.clone()).await;
            let client = CloudflareClient::new(test_config(base)).expect("client");
            let error = client
                .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
                .await
                .expect_err("incomplete response stream must fail closed");

            assert_eq!(error.error.code, "cloudflare.response_read_failed");
            assert_eq!(error.error.status, Some(503));
            assert!(!error.error.retryable);
            assert_eq!(error.response_body_sha256, None);
            assert_eq!(error.response_body_size_bytes, Some(expected_size));
            assert_eq!(error.lifecycle, expected_lifecycle);
            assert_eq!(error.lifecycle.provider_calls(), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn reconciliation_redirect_is_not_followed() {
        let redirect_location = refused_loopback_url("must-not-be-followed");
        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            post(move || {
                let redirect_location = redirect_location.clone();
                async move {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", redirect_location)
                        .body(Body::empty())
                        .expect("redirect response")
                }
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
            .await
            .expect_err("redirect is contradictory evidence");
        assert_eq!(error.error.status, Some(302));
        assert_eq!(error.lifecycle.provider_calls(), 1);
        assert_eq!(
            error.lifecycle,
            D1MigrationReconciliationReadLifecycle::body_completely_read(302)
        );
    }

    #[tokio::test]
    async fn migration_manifest_write_does_not_follow_same_origin_307_or_308() {
        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let source_calls = Arc::new(AtomicUsize::new(0));
            let target_calls = Arc::new(AtomicUsize::new(0));
            let source_calls_for_route = source_calls.clone();
            let target_calls_for_route = target_calls.clone();
            let router = Router::new()
                .route(
                    "/accounts/acct-1/d1/database/db-1/query",
                    post(move |headers: HeaderMap| {
                        let source_calls = source_calls_for_route.clone();
                        async move {
                            source_calls.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(
                                headers
                                    .get(reqwest::header::ACCEPT_ENCODING)
                                    .and_then(|value| value.to_str().ok()),
                                Some("identity")
                            );
                            Response::builder()
                                .status(status)
                                .header("location", "/redirect-target")
                                .body(Body::empty())
                                .expect("migration-write redirect response")
                        }
                    }),
                )
                .route(
                    "/redirect-target",
                    post(move || {
                        let target_calls = target_calls_for_route.clone();
                        async move {
                            target_calls.fetch_add(1, Ordering::SeqCst);
                            Json(json!({
                                "success": true,
                                "errors": [],
                                "result": [],
                            }))
                        }
                    }),
                );
            let base = spawn_router(router).await;
            let client = CloudflareClient::new(test_config(base)).expect("client");
            let error = client
                .execute_d1_migration_manifest_write(
                    "acct-1",
                    "db-1",
                    "CREATE TABLE guarded(id INTEGER PRIMARY KEY)",
                    &[],
                )
                .await
                .expect_err("redirected migration write must remain ambiguous");

            assert_eq!(source_calls.load(Ordering::SeqCst), 1, "{status}");
            assert_eq!(target_calls.load(Ordering::SeqCst), 0, "{status}");
            assert_eq!(error.error.status, Some(status.as_u16()), "{status}");
            assert!(!error.error.retryable, "{status}");
            assert_eq!(error.response_body_size_bytes, Some(0), "{status}");
            assert_eq!(
                error.lifecycle,
                D1MigrationManifestWriteLifecycle::body_completely_read(status.as_u16()),
                "{status}"
            );
            assert_eq!(error.lifecycle.provider_calls(), 1, "{status}");
        }
    }

    #[tokio::test]
    async fn migration_manifest_write_stream_cap_stops_without_replay() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_route = calls.clone();
        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            post(move |headers: HeaderMap| {
                let calls = calls_for_route.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(
                        headers
                            .get(reqwest::header::ACCEPT_ENCODING)
                            .and_then(|value| value.to_str().ok()),
                        Some("identity")
                    );
                    let body = Body::from_stream(futures::stream::iter([
                        Ok::<Bytes, Infallible>(Bytes::from(vec![
                            b'x';
                            D1_MIGRATION_RESPONSE_MAX_BYTES
                        ])),
                        Ok::<Bytes, Infallible>(Bytes::from_static(b"x")),
                    ]));
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(body)
                        .expect("oversized streamed migration-write response")
                }
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .execute_d1_migration_manifest_write(
                "acct-1",
                "db-1",
                "CREATE TABLE guarded(id INTEGER PRIMARY KEY)",
                &[],
            )
            .await
            .expect_err("oversized streamed response must remain ambiguous");

        assert_eq!(
            error.error.code,
            "cloudflare.d1.migration_manifest_response_too_large"
        );
        assert_eq!(error.error.status, Some(200));
        assert!(!error.error.retryable);
        assert_eq!(error.response_body_sha256, None);
        assert!(
            error
                .response_body_size_bytes
                .is_some_and(|size| size > D1_MIGRATION_RESPONSE_MAX_BYTES)
        );
        assert_eq!(
            error.lifecycle,
            D1MigrationManifestWriteLifecycle::body_partially_read(200)
        );
        assert_eq!(error.lifecycle.provider_calls(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn migration_manifest_write_stream_failure_is_ambiguous_without_replay() {
        let listener = TcpListener::bind("127.0.0.1:0") // DevSkim: ignore DS162092 -- loopback-only migration-write fixture
            .await
            .expect("bind truncated migration-write fixture");
        let addr = listener
            .local_addr()
            .expect("truncated migration-write fixture address");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_server = calls.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept migration write");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let count = stream.read(&mut chunk).await.expect("read migration write");
                assert!(count > 0, "request closed before complete body");
                request.extend_from_slice(&chunk[..count]);
                let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let header_end = header_end + 4;
                let headers = std::str::from_utf8(&request[..header_end])
                    .expect("migration-write headers are UTF-8");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("content length"))
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + content_length {
                    break;
                }
            }
            calls_for_server.fetch_add(1, Ordering::SeqCst);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n{")
                .await
                .expect("write truncated migration response");
        });
        let client = CloudflareClient::new(test_config(format!("http://{addr}"))) // DevSkim: ignore DS137138 -- loopback-only migration-write fixture
            .expect("migration-write client");
        let error = client
            .execute_d1_migration_manifest_write(
                "acct-1",
                "db-1",
                "CREATE TABLE guarded(id INTEGER PRIMARY KEY)",
                &[],
            )
            .await
            .expect_err("truncated stream must remain ambiguous");

        assert_eq!(error.error.code, "cloudflare.response_read_failed");
        assert_eq!(error.error.status, Some(200));
        assert!(!error.error.retryable);
        assert_eq!(error.response_body_sha256, None);
        assert_eq!(error.response_body_size_bytes, Some(1));
        assert_eq!(
            error.lifecycle,
            D1MigrationManifestWriteLifecycle::body_partially_read(200)
        );
        assert_eq!(error.lifecycle.provider_calls(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn migration_manifest_write_rejects_encoded_and_malformed_bodies_without_replay() {
        enum FailureBody {
            Encoded,
            InvalidUtf8,
            DuplicateJsonKey,
        }

        for (case, expected_code) in [
            (
                FailureBody::Encoded,
                "cloudflare.d1.migration_manifest_unsupported_content_encoding",
            ),
            (
                FailureBody::InvalidUtf8,
                "cloudflare.d1.migration_manifest_malformed_utf8",
            ),
            (
                FailureBody::DuplicateJsonKey,
                "cloudflare.d1.migration_manifest_duplicate_object_key",
            ),
        ] {
            let (body, content_encoding) = match case {
                FailureBody::Encoded => (
                    br#"{"success":true,"errors":[],"result":[]}"#.to_vec(),
                    Some("gzip"),
                ),
                FailureBody::InvalidUtf8 => (vec![0xff, 0xfe], None),
                FailureBody::DuplicateJsonKey => (
                    br#"{"success":true,"success":true,"errors":[],"result":[]}"#.to_vec(),
                    None,
                ),
            };
            let expected_body_size = body.len();
            let expected_body_sha256 = format!("{:x}", Sha256::digest(&body));
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_for_route = calls.clone();
            let router = Router::new().route(
                "/accounts/acct-1/d1/database/db-1/query",
                post(move || {
                    let calls = calls_for_route.clone();
                    let body = body.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let mut response = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json");
                        if let Some(content_encoding) = content_encoding {
                            response = response.header("content-encoding", content_encoding);
                        }
                        response
                            .body(Body::from(body))
                            .expect("malformed migration-write response")
                    }
                }),
            );
            let base = spawn_router(router).await;
            let client = CloudflareClient::new(test_config(base)).expect("client");
            let error = client
                .execute_d1_migration_manifest_write(
                    "acct-1",
                    "db-1",
                    "CREATE TABLE guarded(id INTEGER PRIMARY KEY)",
                    &[],
                )
                .await
                .expect_err("post-dispatch response defect must remain ambiguous");

            assert_eq!(error.error.code, expected_code);
            assert_eq!(error.error.status, Some(200));
            assert!(!error.error.retryable);
            assert_eq!(error.lifecycle.provider_calls(), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if content_encoding.is_some() {
                assert_eq!(error.response_body_sha256, None);
                assert_eq!(error.response_body_size_bytes, None);
                assert_eq!(
                    error.lifecycle,
                    D1MigrationManifestWriteLifecycle::response_received(200)
                );
            } else {
                assert_eq!(error.response_body_sha256, Some(expected_body_sha256));
                assert_eq!(error.response_body_size_bytes, Some(expected_body_size));
                assert_eq!(
                    error.lifecycle,
                    D1MigrationManifestWriteLifecycle::body_completely_read(200)
                );
            }
        }
    }

    #[tokio::test]
    async fn migration_manifest_write_builder_failure_is_zero_call_predispatch() {
        let mut cfg = test_config(refused_loopback_url("write-builder-must-not-dispatch"));
        cfg.api_token = Some("invalid\nheader".to_string());
        let client = CloudflareClient::new(cfg).expect("client");
        let error = client
            .execute_d1_migration_manifest_write(
                "acct-1",
                "db-1",
                "CREATE TABLE guarded(id INTEGER PRIMARY KEY)",
                &[],
            )
            .await
            .expect_err("invalid authorization header must fail before dispatch");

        assert_eq!(error.error.code, "cloudflare.request_build_failed");
        assert_eq!(error.error.status, None);
        assert_eq!(error.response_body_sha256, None);
        assert_eq!(error.response_body_size_bytes, None);
        assert_eq!(
            error.lifecycle,
            D1MigrationManifestWriteLifecycle::pre_dispatch()
        );
        assert_eq!(error.lifecycle.provider_calls(), 0);
    }

    #[tokio::test]
    async fn malformed_reconciliation_bodies_preserve_http_status() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let router = Router::new().route(
                "/accounts/acct-1/d1/database/db-1/query",
                post(move || async move {
                    Response::builder()
                        .status(status)
                        .body(Body::from(vec![0xff, 0xfe]))
                        .expect("malformed UTF-8 response")
                }),
            );
            let base = spawn_router(router).await;
            let client = CloudflareClient::new(test_config(base)).expect("client");
            let error = client
                .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
                .await
                .expect_err("malformed UTF-8 must fail closed");
            assert_eq!(
                error.error.code,
                "cloudflare.d1.migration_reconciliation_malformed_utf8"
            );
            assert_eq!(error.error.status, Some(status.as_u16()));
            assert_eq!(
                error.lifecycle,
                D1MigrationReconciliationReadLifecycle::body_completely_read(status.as_u16())
            );
        }

        let router = Router::new().route(
            "/accounts/acct-1/d1/database/db-1/query",
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("{"))
                    .expect("malformed JSON response")
            }),
        );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let error = client
            .query_d1_migration_reconciliation_batch("acct-1", "db-1", "SELECT 1")
            .await
            .expect_err("malformed JSON must fail closed");
        assert_eq!(error.error.status, Some(200));
        assert_eq!(
            error.lifecycle,
            D1MigrationReconciliationReadLifecycle::body_completely_read(200)
        );
    }

    #[test]
    fn reconciliation_decoder_rejects_recursive_duplicate_object_keys_in_both_orders() {
        let duplicate_pairs = [("false", "true"), ("true", "false")];
        for (first, second) in duplicate_pairs {
            let (numeric_first, numeric_second) = if first == "false" { (1, 2) } else { (2, 1) };
            let cases = [
                format!(r#"{{"success":{first},"success":{second},"errors":[],"result":[]}}"#),
                format!(
                    r#"{{"success":true,"errors":[],"result":[{{"success":{first},"success":{second},"errors":[],"results":[],"meta":{{}}}}]}}"#
                ),
                format!(
                    r#"{{"success":true,"errors":[],"result":[{{"success":true,"errors":[],"results":[],"meta":{{"served_by_primary":{first},"served_by_primary":{second}}}}}]}}"#
                ),
                format!(
                    r#"{{"success":true,"errors":[],"result":[{{"success":true,"errors":[{{"code":{numeric_first},"code":{numeric_second}}}],"results":[],"meta":{{}}}}]}}"#
                ),
                format!(
                    r#"{{"success":true,"errors":[],"result":[{{"success":true,"errors":[],"results":[{{"id":{numeric_first},"id":{numeric_second}}}],"meta":{{}}}}]}}"#
                ),
            ];
            for body in cases {
                let error = decode_strict_d1_migration_reconciliation_envelope(&body)
                    .expect_err("every recursive duplicate object key must fail closed");
                assert_eq!(
                    error.code,
                    "cloudflare.d1.migration_reconciliation_duplicate_object_key"
                );
                assert_eq!(
                    error.message,
                    "Cloudflare reconciliation response contained a duplicate JSON object key"
                );
            }
        }

        let envelope = decode_strict_d1_migration_reconciliation_envelope(
            r#"{"success":true,"errors":[],"result":[{"success":true,"errors":[],"results":[{"id":1}],"meta":{"served_by_primary":true}}]}"#,
        )
        .expect("duplicate-free nested reconciliation envelope");
        assert!(envelope.success);
        assert!(envelope.result.is_some());
    }

    #[test]
    fn reconciliation_provider_error_classifier_is_allowlisted_complete_and_message_blind() {
        for (code, category) in [(7_500, "d1_error"), (10_000, "authentication_error")] {
            let body = json!({
                "success": false,
                "errors": [{
                    "code": code,
                    "message": "SQL SELECT * FROM private_table at /private/path"
                }],
                "messages": [],
                "result": null,
            })
            .to_string();
            assert_eq!(
                classify_d1_migration_provider_error(&body),
                Some(D1MigrationProviderError { code, category })
            );
        }

        for body in [
            r#"{"success":false,"errors":[{"code":9999,"message":"private"}],"messages":[],"result":null}"#,
            r#"{"success":false,"errors":[{"code":7500}],"messages":[],"result":null}"#,
            r#"{"success":false,"errors":[{"code":"7500","message":"private"}],"messages":[],"result":null}"#,
            r#"{"success":false,"errors":[{"code":7500,"message":"private"}],"result":null}"#,
            r#"{"success":false,"errors":[{"code":7500,"message":"private"}],"messages":[{}],"result":null}"#,
            r#"{"success":false,"errors":[{"code":7500,"message":"private"}],"messages":[],"result":null,"unexpected":true}"#,
            r#"{"success":false,"success":true,"errors":[{"code":7500,"message":"private"}],"messages":[],"result":null}"#,
            "{",
        ] {
            assert_eq!(classify_d1_migration_provider_error(body), None, "{body}");
        }
    }

    #[test]
    fn manifest_decoder_rejects_recursive_duplicate_authority_keys_in_both_orders() {
        for (first, second) in [("false", "true"), ("true", "false")] {
            for body in [
                format!(r#"{{"success":{first},"success":{second},"errors":[],"result":[]}}"#),
                r#"{"success":true,"errors":[],"result":[{"success":true,"errors":[],"results":[{"type":"table","name":"d1_migrations","tbl_name":"d1_migrations","sql":"CREATE TABLE x","sql":"CREATE TABLE y"}],"meta":{"served_by_primary":true}}]}"#.to_string(),
                [
                    r#"{"success":true,"errors":[],"result":[{"success":true,"errors":[],"results":[{"type":"table","name":"d1_migrations","name":"D1_MIGRATIONS","tbl_name":"d1_migrations","sql":"CREATE TABLE x"}],"meta":{"served_by_primary":"#,
                    first,
                    r#","served_by_primary":"#,
                    second,
                    r#"}}]}"#,
                ]
                .concat(),
            ] {
                let error = decode_strict_d1_migration_manifest_envelope(&body)
                    .expect_err("every recursive duplicate authority key must fail closed");
                assert_eq!(
                    error.code,
                    "cloudflare.d1.migration_manifest_duplicate_object_key"
                );
            }
        }
    }

    #[tokio::test]
    async fn get_r2_object_signs_and_reads_private_object() {
        async fn get_object(
            Path((bucket, key)): Path<(String, String)>,
            headers: HeaderMap,
        ) -> (StatusCode, HeaderMap, &'static str) {
            assert_eq!(bucket, "bucket-a");
            assert_eq!(key, "folder/file.txt");
            assert!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.starts_with(&format!(
                            "AWS4-HMAC-SHA256 Credential={}/",
                            fixture_material("r2-id")
                        )) && value.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
                    })
            );
            assert!(
                headers
                    .get("x-amz-content-sha256")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value
                        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            );
            let mut response_headers = HeaderMap::new();
            response_headers.insert("content-type", "text/plain".parse().expect("content-type"));
            response_headers.insert("etag", "\"etag-1\"".parse().expect("etag"));
            (StatusCode::OK, response_headers, "hello from r2")
        }

        let base = spawn_router(Router::new().route("/{bucket}/{*key}", get(get_object))).await;
        let client = CloudflareClient::new(test_config_with_r2_endpoint(
            "http://127.0.0.1:9".to_string(),
            base,
        ))
        .expect("client");

        let object = client
            .get_r2_object("acct-1", "bucket-a", "folder/file.txt", None)
            .await
            .expect("r2 object");

        assert_eq!(
            std::str::from_utf8(&object.body).expect("utf8"),
            "hello from r2"
        );
        assert_eq!(object.content_type.as_deref(), Some("text/plain"));
        assert_eq!(object.etag.as_deref(), Some("\"etag-1\""));
    }

    #[tokio::test]
    async fn download_r2_object_streams_to_file_with_hash_and_range() {
        async fn get_object(
            Path((bucket, key)): Path<(String, String)>,
            headers: HeaderMap,
        ) -> (StatusCode, HeaderMap, &'static str) {
            assert_eq!(bucket, "bucket-a");
            assert_eq!(key, "folder/file.csv");
            assert_eq!(
                headers.get("range").and_then(|value| value.to_str().ok()),
                Some("bytes=0-12")
            );
            assert!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value
                        .contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"))
            );
            let mut response_headers = HeaderMap::new();
            response_headers.insert("content-type", "text/csv".parse().expect("content-type"));
            response_headers.insert("content-length", "13".parse().expect("content-length"));
            response_headers.insert("content-range", "bytes 0-12/128".parse().expect("range"));
            response_headers.insert("etag", "\"etag-1\"".parse().expect("etag"));
            (
                StatusCode::PARTIAL_CONTENT,
                response_headers,
                "col1,col2\n1,2",
            )
        }

        let base = spawn_router(Router::new().route("/{bucket}/{*key}", get(get_object))).await;
        let client = CloudflareClient::new(test_config_with_r2_endpoint(
            "http://127.0.0.1:9".to_string(),
            base,
        ))
        .expect("client");
        let output_path = std::env::temp_dir().join(format!(
            "cloudflare-mcp-r2-download-test-{}-file.csv",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&output_path);

        let download = client
            .download_r2_object_to_file(
                "acct-1",
                "bucket-a",
                "folder/file.csv",
                Some("bytes=0-12"),
                &output_path,
                None,
            )
            .await
            .expect("r2 download");

        assert_eq!(
            std::fs::read_to_string(&output_path).expect("read downloaded file"),
            "col1,col2\n1,2"
        );
        assert_eq!(download.bytes_written, 13);
        assert_eq!(
            download.sha256,
            "3859dd5cfe2b51951a9fad553d665d1999016f2c2d03c97d5702ca70aee1fade"
        );
        assert_eq!(download.content_type.as_deref(), Some("text/csv"));
        assert_eq!(download.range.as_deref(), Some("bytes 0-12/128"));

        let _ = std::fs::remove_file(output_path);
    }

    #[tokio::test]
    async fn worker_create_only_upload_uses_atomic_precondition_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts/worker-a",
                put({
                    let calls = calls.clone();
                    move |headers: HeaderMap, _body: Bytes| {
                        let calls = calls.clone();
                        async move {
                            let attempt = calls.fetch_add(1, Ordering::SeqCst);
                            if attempt == 0 {
                                assert_eq!(
                                    headers
                                        .get(reqwest::header::IF_NONE_MATCH)
                                        .and_then(|value| value.to_str().ok()),
                                    Some("*")
                                );
                                return (
                                    StatusCode::PRECONDITION_FAILED,
                                    Json(json!({
                                        "success": false,
                                        "errors": [{"code": 1001, "message": "script already exists"}],
                                        "messages": [],
                                        "result": null,
                                    })),
                                );
                            }

                            assert!(headers.get(reqwest::header::IF_NONE_MATCH).is_none());
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "success": true,
                                    "errors": [],
                                    "messages": [],
                                    "result": {"id": "worker-a", "script_name": "worker-a"},
                                })),
                            )
                        }
                    }
                }),
            )
            .with_state(());

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_module(
                "acct-1",
                "worker-a",
                &json!({"main_module": "worker.js"}),
                "worker.js",
                "worker.js",
                "application/javascript+module",
                b"export default {}".to_vec(),
                true,
            )
            .await
            .expect_err("existing Worker must conflict");

        assert_eq!(err.code, "workers.upload_create_only_conflict");
        assert_eq!(err.status, Some(412));
        assert!(!err.retryable);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        client
            .upload_worker_module(
                "acct-1",
                "worker-a",
                &json!({"main_module": "worker.js"}),
                "worker.js",
                "worker.js",
                "application/javascript+module",
                b"export default {}".to_vec(),
                false,
            )
            .await
            .expect("legacy update upload");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn worker_initial_version_evidence_binds_sole_version_to_detail() {
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"id": "worker-a", "etag": "etag-1"}],
                        "result_info": {"page": 1, "per_page": 1000, "count": 1, "total_count": 1},
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "items": [{"id": "version-1", "number": 1}]
                        },
                        "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1},
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions/version-1",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "id": "version-1",
                            "resources": {
                                "script": {
                                    "etag": "etag-1",
                                    "handlers": ["fetch", "scheduled"],
                                    "named_handlers": [{"name": "handler", "handlers": ["class"]}],
                                }
                            }
                        },
                    }))
                }),
            );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let evidence = client
            .get_worker_initial_version_evidence("acct-1", "worker-a")
            .await
            .expect("version evidence");

        assert_eq!(evidence["versions"][0]["id"], json!("version-1"));
        assert_eq!(
            evidence["detail"]["resources"]["script"]["etag"],
            json!("etag-1")
        );
    }

    #[tokio::test]
    async fn worker_version_inventory_exhausts_outer_result_info_pages() {
        async fn list_versions(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
            let page = query
                .get("page")
                .and_then(|value| value.parse::<u32>().ok())
                .expect("page query");
            let (items, count) = match page {
                1 => (json!([{ "id": "version-1" }]), 1),
                2 => (json!([{ "id": "version-2" }]), 1),
                _ => panic!("unexpected page {page}"),
            };
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {"items": items},
                "result_info": {
                    "page": page,
                    "per_page": 1,
                    "count": count,
                    "total_count": 2
                }
            }))
        }

        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a/versions",
            get(list_versions),
        );
        let client =
            CloudflareClient::new(test_config(spawn_router(router).await)).expect("client");
        let inventory = client
            .list_worker_versions_exhaustive("acct-1", "worker-a")
            .await
            .expect("exhaustive inventory");

        assert_eq!(inventory.total_count, 2);
        assert_eq!(inventory.total_pages, 2);
        assert_eq!(
            inventory
                .items
                .iter()
                .map(|item| item["id"].as_str().expect("version id"))
                .collect::<Vec<_>>(),
            vec!["version-1", "version-2"]
        );
    }

    #[test]
    fn worker_version_page_metadata_rejects_missing_outer_result_info() {
        let err = worker_version_page_metadata(&json!({"items": []}), None, 1)
            .expect_err("missing result_info must fail closed");
        assert_eq!(
            err.code,
            "workers.upload_version_readback_pagination_invalid"
        );
    }

    #[test]
    fn worker_version_page_metadata_rejects_conflicting_nested_pagination() {
        let result_info = PageInfo {
            page: Some(1),
            per_page: Some(1),
            count: Some(1),
            total_count: Some(2),
            total_pages: Some(2),
        };
        let err = worker_version_page_metadata(
            &json!({
                "items": [{"id": "version-1"}],
                "pagination": {"page": 1, "per_page": 1, "count": 1, "total_count": 3, "total_pages": 3}
            }),
            Some(&result_info),
            1,
        )
        .expect_err("conflicting nested metadata must fail closed");
        assert_eq!(
            err.code,
            "workers.upload_version_readback_pagination_conflict"
        );
    }

    #[test]
    fn worker_version_page_metadata_rejects_nested_count_without_outer_count() {
        let result_info = PageInfo {
            page: Some(1),
            per_page: Some(100),
            count: None,
            total_count: Some(1),
            total_pages: Some(1),
        };
        let err = worker_version_page_metadata(
            &json!({
                "items": [{"id": "version-1"}],
                "pagination": {"page": 1, "per_page": 100, "count": 2, "total_count": 1, "total_pages": 1}
            }),
            Some(&result_info),
            1,
        )
        .expect_err("nested count must match page items even without outer count");
        assert_eq!(
            err.code,
            "workers.upload_version_readback_pagination_conflict"
        );
    }

    #[test]
    fn worker_version_page_metadata_allows_empty_inventory_total_count() {
        let result_info = PageInfo {
            page: Some(1),
            per_page: Some(100),
            count: Some(0),
            total_count: Some(0),
            total_pages: Some(1),
        };
        let metadata = worker_version_page_metadata(&json!({"items": []}), Some(&result_info), 1)
            .expect("zero total_count is a valid exhaustive page");
        assert_eq!(metadata.total_count, 0);
    }

    #[test]
    fn worker_version_id_rejects_whitespace_aliases() {
        let valid = json!({"id": "version-1"});
        assert_eq!(
            worker_version_id(&valid, "test version id").expect("canonical id"),
            "version-1"
        );

        for invalid in [json!({"id": " version-1"}), json!({"id": "version-1 "})] {
            let err = worker_version_id(&invalid, "test version id")
                .expect_err("whitespace aliases must fail closed");
            assert_eq!(err.code, "workers.upload_version_readback_invalid");
        }
    }

    #[tokio::test]
    async fn worker_version_inventory_rejects_truncated_outer_result_info_pages() {
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a/versions",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                let page = query
                    .get("page")
                    .and_then(|value| value.parse::<u32>().ok())
                    .expect("page query");
                Json(match page {
                    1 => json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {"items": [{"id": "version-1"}]},
                        "result_info": {
                            "page": 1,
                            "per_page": 1,
                            "count": 1,
                            "total_count": 2,
                            "total_pages": 2
                        }
                    }),
                    2 => json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {"items": []},
                        "result_info": {
                            "page": 2,
                            "per_page": 1,
                            "count": 0,
                            "total_count": 2,
                            "total_pages": 2
                        }
                    }),
                    _ => panic!("unexpected page {page}"),
                })
            }),
        );
        let client =
            CloudflareClient::new(test_config(spawn_router(router).await)).expect("client");
        let err = client
            .list_worker_versions_exhaustive("acct-1", "worker-a")
            .await
            .expect_err("truncated inventory must fail closed");
        assert_eq!(err.code, "workers.upload_version_readback_truncated");
    }

    #[tokio::test]
    async fn worker_initial_version_evidence_rejects_multiple_versions() {
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"id": "worker-a", "etag": "etag-1"}],
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "items": [{"id": "version-1"}, {"id": "version-2"}]
                        },
                        "result_info": {"page": 1, "per_page": 100, "count": 2, "total_count": 2},
                    }))
                }),
            );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .get_worker_initial_version_evidence("acct-1", "worker-a")
            .await
            .expect_err("ambiguous version inventory");

        assert_eq!(err.code, "workers.upload_version_readback_ambiguous");
    }

    #[tokio::test]
    async fn worker_initial_version_evidence_rejects_malformed_version_shape() {
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"id": "worker-a", "etag": "etag-1"}],
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{"id": "version-1"}],
                    }))
                }),
            );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .get_worker_initial_version_evidence("acct-1", "worker-a")
            .await
            .expect_err("bare version array must be rejected");

        assert_eq!(err.code, "workers.upload_version_readback_invalid");
    }

    #[tokio::test]
    async fn worker_initial_version_evidence_rejects_listing_etag_drift() {
        let listing_calls = Arc::new(AtomicUsize::new(0));
        let listing_calls_for_route = listing_calls.clone();
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts",
                get(move || {
                    let listing_calls = listing_calls_for_route.clone();
                    async move {
                        let etag = if listing_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            "etag-1"
                        } else {
                            "etag-2"
                        };
                        Json(json!({
                            "success": true,
                            "errors": [],
                            "messages": [],
                            "result": [{"id": "worker-a", "etag": etag}],
                        }))
                    }
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "items": [{"id": "version-1"}]
                        },
                        "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1},
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/versions/version-1",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {"id": "version-1"},
                    }))
                }),
            );
        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .get_worker_initial_version_evidence("acct-1", "worker-a")
            .await
            .expect_err("listing drift must stop readback");

        assert_eq!(err.code, "workers.upload_listing_readback_drift");
    }

    #[test]
    fn worker_listing_identity_rejects_blank_alias() {
        let script: WorkerScript = serde_json::from_value(json!({
            "id": "worker-a",
            "script_name": ""
        }))
        .expect("Worker listing fixture");
        let err = worker_listing_identity(&script).expect_err("blank alias must fail closed");
        assert_eq!(err.code, "workers.upload_listing_readback_invalid");
    }

    #[test]
    fn worker_listing_identity_rejects_non_string_name_alias() {
        let script: WorkerScript = serde_json::from_value(json!({
            "id": "worker-a",
            "name": 42
        }))
        .expect("Worker listing fixture");
        let err =
            worker_listing_identity(&script).expect_err("non-string name alias must fail closed");
        assert_eq!(err.code, "workers.upload_listing_readback_invalid");
    }

    #[test]
    fn worker_listing_identity_requires_byte_identical_aliases() {
        let script: WorkerScript = serde_json::from_value(json!({
            "id": "worker-a",
            "script_name": " worker-a "
        }))
        .expect("Worker listing fixture");
        let err =
            worker_listing_identity(&script).expect_err("non-identical aliases must fail closed");
        assert_eq!(err.code, "workers.upload_listing_readback_conflict");
    }

    #[test]
    fn worker_create_only_classifier_preserves_legacy_empty_result() {
        let err = AdapterError::new(
            "cloudflare.empty_result",
            "Cloudflare returned success without uploaded Worker script details",
            "Verify Worker script upload endpoint and response schema.",
        );
        let classified = super::classify_worker_upload_error(err, false);

        assert_eq!(classified.code, "cloudflare.empty_result");
        assert!(!classified.retryable);
        assert_eq!(classified.status, None);
    }

    #[tokio::test]
    async fn worker_create_only_module_response_loss_is_uncertain_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a",
            put({
                let calls = calls.clone();
                move |headers: HeaderMap, _body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(reqwest::header::IF_NONE_MATCH)
                                .and_then(|value| value.to_str().ok()),
                            Some("*")
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        let body = Body::from_stream(futures::stream::once(async {
                            Err::<Bytes, std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "response connection reset after upload acceptance",
                            ))
                        }));
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .expect("response")
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_module(
                "acct-1",
                "worker-a",
                &json!({"main_module": "worker.js"}),
                "worker.js",
                "worker.js",
                "application/javascript+module",
                b"export default {}".to_vec(),
                true,
            )
            .await
            .expect_err("response loss must be uncertain");

        assert_eq!(err.code, "workers.upload_create_only_outcome_uncertain");
        assert!(!err.retryable);
        assert!(err.hint.contains("read back"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_create_only_module_empty_result_is_uncertain_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a",
            put({
                let calls = calls.clone();
                move |headers: HeaderMap, _body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(reqwest::header::IF_NONE_MATCH)
                                .and_then(|value| value.to_str().ok()),
                            Some("*")
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::OK,
                            Json(json!({
                                "success": true,
                                "errors": [],
                                "messages": [],
                                "result": null,
                            })),
                        )
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_module(
                "acct-1",
                "worker-a",
                &json!({"main_module": "worker.js"}),
                "worker.js",
                "worker.js",
                "application/javascript+module",
                b"export default {}".to_vec(),
                true,
            )
            .await
            .expect_err("empty result must be uncertain");

        assert_eq!(err.code, "workers.upload_create_only_outcome_uncertain");
        assert!(!err.retryable);
        assert!(err.hint.contains("reconcile"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_create_only_multipart_response_loss_is_uncertain_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a",
            put({
                let calls = calls.clone();
                move |headers: HeaderMap, _body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(reqwest::header::IF_NONE_MATCH)
                                .and_then(|value| value.to_str().ok()),
                            Some("*")
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        let body = Body::from_stream(futures::stream::once(async {
                            Err::<Bytes, std::io::Error>(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "response connection reset after upload acceptance",
                            ))
                        }));
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .expect("response")
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_multipart(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"--fixture\r\n--fixture--\r\n".to_vec(),
                true,
            )
            .await
            .expect_err("response loss must be uncertain");

        assert_eq!(err.code, "workers.upload_create_only_outcome_uncertain");
        assert!(!err.retryable);
        assert!(err.hint.contains("reconcile"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_create_only_multipart_empty_result_is_uncertain_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a",
            put({
                let calls = calls.clone();
                move |headers: HeaderMap, _body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(reqwest::header::IF_NONE_MATCH)
                                .and_then(|value| value.to_str().ok()),
                            Some("*")
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::OK,
                            Json(json!({
                                "success": true,
                                "errors": [],
                                "messages": [],
                                "result": null,
                            })),
                        )
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_multipart(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"--fixture\r\n--fixture--\r\n".to_vec(),
                true,
            )
            .await
            .expect_err("empty result must be uncertain");

        assert_eq!(err.code, "workers.upload_create_only_outcome_uncertain");
        assert!(!err.retryable);
        assert!(err.hint.contains("read back"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_create_only_multipart_conflict_uses_atomic_precondition_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a",
            put({
                let calls = calls.clone();
                move |headers: HeaderMap, _body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(reqwest::header::IF_NONE_MATCH)
                                .and_then(|value| value.to_str().ok()),
                            Some("*")
                        );
                        calls.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::PRECONDITION_FAILED,
                            Json(json!({
                                "success": false,
                                "errors": [{"code": 1001, "message": "script already exists"}],
                                "messages": [],
                                "result": null,
                            })),
                        )
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_multipart(
                "acct-1",
                "worker-a",
                "multipart/form-data; boundary=fixture",
                b"--fixture\r\n--fixture--\r\n".to_vec(),
                true,
            )
            .await
            .expect_err("existing Worker must conflict");

        assert_eq!(err.code, "workers.upload_create_only_conflict");
        assert_eq!(err.status, Some(412));
        assert!(!err.retryable);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_create_only_server_error_is_uncertain_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/workers/scripts/worker-a",
            put({
                let calls = calls.clone();
                move |headers: HeaderMap, _body: Bytes| {
                    let calls = calls.clone();
                    async move {
                        let attempt = calls.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            assert_eq!(
                                headers
                                    .get(reqwest::header::IF_NONE_MATCH)
                                    .and_then(|value| value.to_str().ok()),
                                Some("*")
                            );
                        } else {
                            assert!(headers.get(reqwest::header::IF_NONE_MATCH).is_none());
                        }
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({
                                "success": false,
                                "errors": [{"code": 1000, "message": "temporary outage"}],
                                "messages": [],
                                "result": null,
                            })),
                        )
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .upload_worker_module(
                "acct-1",
                "worker-a",
                &json!({"main_module": "worker.js"}),
                "worker.js",
                "worker.js",
                "application/javascript+module",
                b"export default {}".to_vec(),
                true,
            )
            .await
            .expect_err("server error must be uncertain");

        assert_eq!(err.code, "workers.upload_create_only_outcome_uncertain");
        assert_eq!(err.status, Some(503));
        assert!(!err.retryable);

        let legacy_err = client
            .upload_worker_module(
                "acct-1",
                "worker-a",
                &json!({"main_module": "worker.js"}),
                "worker.js",
                "worker.js",
                "application/javascript+module",
                b"export default {}".to_vec(),
                false,
            )
            .await
            .expect_err("legacy update must retain generic server error");
        assert_eq!(legacy_err.code, "cloudflare.http_server_error");
        assert!(legacy_err.retryable);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn inspect_r2_object_uses_signed_head_and_returns_metadata() {
        async fn head_object(
            Path((bucket, key)): Path<(String, String)>,
            headers: HeaderMap,
        ) -> (StatusCode, HeaderMap) {
            assert_eq!(bucket, "bucket-a");
            assert_eq!(key, "folder/file.txt");
            assert!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.starts_with(&format!(
                            "AWS4-HMAC-SHA256 Credential={}/",
                            fixture_material("r2-id")
                        )) && value.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
                    })
            );
            let mut response_headers = HeaderMap::new();
            response_headers.insert("content-type", "text/plain".parse().expect("content-type"));
            response_headers.insert("content-length", "12".parse().expect("content-length"));
            response_headers.insert("etag", "\"etag-1\"".parse().expect("etag"));
            response_headers.insert("x-amz-meta-owner", "ops".parse().expect("metadata"));
            (StatusCode::OK, response_headers)
        }

        let base = spawn_router(
            Router::new().route("/{bucket}/{*key}", get(|| async { "" }).head(head_object)),
        )
        .await;
        let client = CloudflareClient::new(test_config_with_r2_endpoint(
            "http://127.0.0.1:9".to_string(),
            base,
        ))
        .expect("client");

        let metadata = client
            .inspect_r2_object("acct-1", "bucket-a", "folder/file.txt")
            .await
            .expect("r2 metadata");

        assert_eq!(metadata.content_type.as_deref(), Some("text/plain"));
        assert_eq!(metadata.content_length, Some(12));
        assert_eq!(
            metadata.custom_metadata.get("owner").map(String::as_str),
            Some("ops")
        );
    }

    #[tokio::test]
    async fn put_r2_object_signs_body_and_metadata() {
        async fn put_object(
            Path((bucket, key)): Path<(String, String)>,
            headers: HeaderMap,
            body: Bytes,
        ) -> (StatusCode, HeaderMap) {
            assert_eq!(bucket, "bucket-a");
            assert_eq!(key, "folder/file.txt");
            assert_eq!(&body[..], b"hello write");
            assert!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-owner")
                    })
            );
            assert_eq!(
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok()),
                Some("text/plain")
            );
            assert_eq!(
                headers
                    .get("x-amz-meta-owner")
                    .and_then(|value| value.to_str().ok()),
                Some("ops")
            );
            let mut response_headers = HeaderMap::new();
            response_headers.insert("etag", "\"etag-write\"".parse().expect("etag"));
            (StatusCode::OK, response_headers)
        }

        let base = spawn_router(
            Router::new().route("/{bucket}/{*key}", get(|| async { "" }).put(put_object)),
        )
        .await;
        let client = CloudflareClient::new(test_config_with_r2_endpoint(
            "http://127.0.0.1:9".to_string(),
            base,
        ))
        .expect("client");

        let result = client
            .put_r2_object(
                "acct-1",
                "bucket-a",
                "folder/file.txt",
                b"hello write".to_vec(),
                Some("text/plain"),
                &[("owner".to_string(), "ops".to_string())],
            )
            .await
            .expect("r2 put");

        assert_eq!(result.status, 200);
        assert_eq!(result.etag.as_deref(), Some("\"etag-write\""));
    }

    #[tokio::test]
    async fn parses_pagination_for_tunnels() {
        let router = Router::new().route(
            "/accounts/acct-1/cfd_tunnel",
            get(|| async {
                Json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": [{"id": "tun-1", "name": "preview", "status": "active"}],
                    "result_info": {"page": 2, "per_page": 1, "count": 1, "total_count": 3, "total_pages": 3}
                }))
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let page = client
            .list_tunnels("acct-1", 2, 1)
            .await
            .expect("list tunnels");

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, "tun-1");
        assert_eq!(page.page_info.and_then(|info| info.page), Some(2));
    }

    #[tokio::test]
    async fn cache_purge_and_zone_settings_use_zone_endpoints() {
        let purge_calls = Arc::new(AtomicUsize::new(0));
        let patch_calls = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/zones/zone-1/purge_cache",
                post({
                    let purge_calls = purge_calls.clone();
                    move |Json(body): Json<Value>| {
                        let purge_calls = purge_calls.clone();
                        async move {
                            purge_calls.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(body, json!({"tags": ["asset-v1"]}));
                            Json(json!({
                                "success": true,
                                "errors": [],
                                "messages": [],
                                "result": {"id": "purge-1"}
                            }))
                        }
                    }
                }),
            )
            .route(
                "/zones/zone-1/settings/browser_cache_ttl",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {"id": "browser_cache_ttl", "value": 14400}
                    }))
                })
                .patch({
                    let patch_calls = patch_calls.clone();
                    move |Json(body): Json<Value>| {
                        let patch_calls = patch_calls.clone();
                        async move {
                            patch_calls.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(body, json!({"value": 7200}));
                            Json(json!({
                                "success": true,
                                "errors": [],
                                "messages": [],
                                "result": {"id": "browser_cache_ttl", "value": 7200}
                            }))
                        }
                    }
                }),
            );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");

        let purge = client
            .purge_cache("zone-1", None, &json!({"tags": ["asset-v1"]}))
            .await
            .expect("purge");
        assert_eq!(purge["id"], json!("purge-1"));

        let setting = client
            .get_zone_setting("zone-1", "browser_cache_ttl")
            .await
            .expect("setting");
        assert_eq!(setting["value"], json!(14400));

        let updated = client
            .update_zone_setting("zone-1", "browser_cache_ttl", json!(7200))
            .await
            .expect("update setting");
        assert_eq!(updated["value"], json!(7200));
        assert_eq!(purge_calls.load(Ordering::SeqCst), 1);
        assert_eq!(patch_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_after_rate_limit() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/cfd_tunnel",
            get({
                let attempts = attempts.clone();
                move || {
                    let attempts = attempts.clone();
                    async move {
                        let current = attempts.fetch_add(1, Ordering::SeqCst);
                        if current == 0 {
                            let mut headers = HeaderMap::new();
                            headers.insert("Retry-After", "0".parse().expect("retry-after"));
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                headers,
                                Json(json!({
                                    "success": false,
                                    "errors": [{"code": 1015, "message": "rate limited"}],
                                    "messages": [],
                                    "result": null
                                })),
                            );
                        }

                        (
                            StatusCode::OK,
                            HeaderMap::new(),
                            Json(json!({
                                "success": true,
                                "errors": [],
                                "messages": [],
                                "result": [{"id": "tun-2", "name": "retry-success"}],
                                "result_info": {"page": 1, "per_page": 1, "count": 1, "total_count": 1, "total_pages": 1}
                            })),
                        )
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let page = client
            .list_tunnels("acct-1", 1, 1)
            .await
            .expect("list tunnels");

        assert_eq!(page.items[0].name, "retry-success");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn does_not_retry_non_idempotent_create_on_rate_limit() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let router = Router::new().route(
            "/accounts/acct-1/cfd_tunnel",
            axum::routing::post({
                let attempts = attempts.clone();
                move || {
                    let attempts = attempts.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        let mut headers = HeaderMap::new();
                        headers.insert("Retry-After", "0".parse().expect("retry-after"));
                        (
                            StatusCode::TOO_MANY_REQUESTS,
                            headers,
                            Json(json!({
                                "success": false,
                                "errors": [{"code": 1015, "message": "rate limited"}],
                                "messages": [],
                                "result": null
                            })),
                        )
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .create_tunnel("acct-1", "preview")
            .await
            .expect_err("expected non-idempotent rate-limit failure");

        assert_eq!(err.code, "cloudflare.http_rate_limited");
        assert!(err.retryable);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn returns_typed_api_error_on_success_false() {
        let router = Router::new().route(
            "/accounts/acct-1/access/apps/app-1/policies",
            get(|| async {
                Json(json!({
                    "success": false,
                    "errors": [{"code": 7003, "message": "resource not found"}],
                    "messages": [],
                    "result": null
                }))
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .list_access_policies("acct-1", "app-1")
            .await
            .expect_err("expected api error");

        assert_eq!(err.code, "cloudflare.api_error");
        assert!(err.message.contains("7003"));
        assert_eq!(
            err.payload()
                .classification
                .as_ref()
                .map(|classification| classification.code),
            Some("wrong_account_or_zone_context")
        );
        assert_eq!(
            err.payload().hint,
            "Inspect account/zone permissions and Cloudflare API request payload."
        );
    }

    #[tokio::test]
    async fn classifies_http_unauthorized_as_invalid_or_expired_token() {
        let router = Router::new().route(
            "/accounts/acct-1/access/apps/app-1/policies",
            get(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "success": false,
                        "errors": [{"code": 10000, "message": "authentication error"}],
                        "messages": [],
                        "result": null
                    })),
                )
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .list_access_policies("acct-1", "app-1")
            .await
            .expect_err("expected http unauthorized");

        assert_eq!(err.code, "cloudflare.http_unauthorized");
        assert_eq!(
            err.payload()
                .classification
                .as_ref()
                .map(|classification| classification.code),
            Some("invalid_or_expired_token")
        );
    }

    #[tokio::test]
    async fn preserves_cloudflare_api_error_metadata_on_http_status_errors() {
        let router = Router::new().route(
            "/accounts/acct-1/access/apps/app-1/policies",
            get(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "success": false,
                        "errors": [{"code": 7500, "message": "D1 query rejected by authorization policy"}],
                        "messages": [],
                        "result": null
                    })),
                )
            }),
        );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let err = client
            .list_access_policies("acct-1", "app-1")
            .await
            .expect_err("expected http error");

        assert_eq!(err.code, "cloudflare.http_error");
        assert_eq!(err.cloudflare_api_error_code(), Some(7500));
        assert_eq!(
            err.cloudflare_api_error_message(),
            Some("D1 query rejected by authorization policy")
        );
    }

    #[test]
    fn d1_sqlite_auth_detection_keeps_opaque_code_7500_as_fallback_signal() {
        let err = AdapterError::new(
            "cloudflare.api_error",
            "Cloudflare API error 7500",
            "Inspect D1 permissions.",
        )
        .with_cloudflare_api_error(Some(CloudflareApiError {
            code: Some(7500),
            message: None,
        }));

        assert!(is_d1_sqlite_auth_error(&err));
    }

    #[test]
    fn d1_sqlite_auth_detection_does_not_mask_missing_schema_errors() {
        let err = AdapterError::new(
            "cloudflare.api_error",
            "SQLITE_ERROR: no such table: missing_table",
            "Inspect D1 permissions.",
        )
        .with_cloudflare_api_error(Some(CloudflareApiError {
            code: Some(7500),
            message: Some("SQLITE_ERROR: no such table: missing_table".to_string()),
        }));

        assert!(!is_d1_sqlite_auth_error(&err));
    }

    #[tokio::test]
    async fn replace_access_policies_reconciles_with_policy_item_endpoints() {
        #[derive(Clone)]
        struct PolicyState {
            policies: Arc<Mutex<Vec<Value>>>,
            collection_put_calls: Arc<AtomicUsize>,
            policy_put_calls: Arc<AtomicUsize>,
            policy_post_calls: Arc<AtomicUsize>,
            policy_delete_calls: Arc<AtomicUsize>,
        }

        async fn list_policies(State(state): State<PolicyState>) -> Json<Value> {
            let policies = state.policies.lock().expect("policies lock").clone();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": policies,
            }))
        }

        async fn collection_put(State(state): State<PolicyState>) -> (StatusCode, Json<Value>) {
            state.collection_put_calls.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::METHOD_NOT_ALLOWED,
                Json(json!({
                    "success": false,
                    "errors": [{"code": 405, "message": "method not allowed"}],
                    "messages": [],
                    "result": null,
                })),
            )
        }

        async fn update_policy(
            Path(policy_id): Path<String>,
            State(state): State<PolicyState>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            state.policy_put_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(payload["id"], json!(policy_id));
            assert_eq!(payload["name"], json!("allow-updated"));

            let updated = json!({
                "id": policy_id,
                "name": payload["name"],
                "decision": payload["decision"],
                "include": payload["include"],
                "exclude": payload["exclude"],
                "require": payload["require"],
            });
            let mut policies = state.policies.lock().expect("policies lock");
            let slot = policies
                .iter_mut()
                .find(|policy| policy.get("id").and_then(Value::as_str) == Some("pol-1"))
                .expect("existing policy");
            *slot = updated.clone();
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": updated,
            }))
        }

        async fn create_policy(
            State(state): State<PolicyState>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            state.policy_post_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(payload.get("id"), None);
            let created = json!({
                "id": "pol-new",
                "name": payload["name"],
                "decision": payload["decision"],
                "include": payload["include"],
                "exclude": payload["exclude"],
                "require": payload["require"],
            });
            state
                .policies
                .lock()
                .expect("policies lock")
                .push(created.clone());
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": created,
            }))
        }

        async fn delete_policy(
            Path(policy_id): Path<String>,
            State(state): State<PolicyState>,
        ) -> Json<Value> {
            state.policy_delete_calls.fetch_add(1, Ordering::SeqCst);
            let mut policies = state.policies.lock().expect("policies lock");
            policies.retain(|policy| policy.get("id").and_then(Value::as_str) != Some(&policy_id));
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {"id": policy_id},
            }))
        }

        let state = PolicyState {
            policies: Arc::new(Mutex::new(vec![
                json!({
                    "id": "pol-1",
                    "name": "allow",
                    "decision": "allow",
                    "include": [{"email": {"email": "old@example.com"}}],
                    "exclude": [],
                    "require": [],
                }),
                json!({
                    "id": "pol-old",
                    "name": "stale",
                    "decision": "allow",
                    "include": [{"email": {"email": "stale@example.com"}}],
                    "exclude": [],
                    "require": [],
                }),
            ])),
            collection_put_calls: Arc::new(AtomicUsize::new(0)),
            policy_put_calls: Arc::new(AtomicUsize::new(0)),
            policy_post_calls: Arc::new(AtomicUsize::new(0)),
            policy_delete_calls: Arc::new(AtomicUsize::new(0)),
        };
        let router = Router::new()
            .route(
                "/accounts/acct-1/access/apps/app-1/policies",
                get(list_policies).put(collection_put).post(create_policy),
            )
            .route(
                "/accounts/acct-1/access/apps/app-1/policies/{policy_id}",
                axum::routing::put(update_policy).delete(delete_policy),
            )
            .with_state(state.clone());

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let policies = client
            .replace_access_policies(
                "acct-1",
                "app-1",
                &[
                    AccessPolicyWrite {
                        id: Some("pol-1".to_string()),
                        name: "allow-updated".to_string(),
                        decision: "allow".to_string(),
                        include: json!([{"email": {"email": "new@example.com"}}]),
                        exclude: Some(json!([])),
                        require: Some(json!([])),
                        precedence: Some(1),
                    },
                    AccessPolicyWrite {
                        id: None,
                        name: "created-service-auth".to_string(),
                        decision: "non_identity".to_string(),
                        include: json!([{"service_token": {"token_id": "tok-1"}}]),
                        exclude: Some(json!([])),
                        require: Some(json!([])),
                        precedence: Some(2),
                    },
                ],
            )
            .await
            .expect("replace policies");

        assert_eq!(state.collection_put_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.policy_put_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.policy_delete_calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.policy_post_calls.load(Ordering::SeqCst), 1);
        assert_eq!(policies.len(), 2);
        assert!(policies.iter().any(|policy| policy.id == "pol-1"));
        assert!(policies.iter().any(|policy| policy.id == "pol-new"));
        assert!(!policies.iter().any(|policy| policy.id == "pol-old"));
    }

    #[tokio::test]
    async fn validates_missing_token_before_request() {
        let base = "http://127.0.0.1:65530".to_string();
        let mut cfg = test_config(base);
        cfg.api_token = None;
        let client = CloudflareClient::new(cfg).expect("client");

        let err = client
            .replace_access_policies(
                "acct-1",
                "app-1",
                &[AccessPolicyWrite {
                    id: None,
                    name: "allow".to_string(),
                    decision: "allow".to_string(),
                    include: json!({"email": {"email": ["user@example.com"]}}),
                    exclude: None,
                    require: None,
                    precedence: Some(1),
                }],
            )
            .await
            .expect_err("expected config error");

        assert_eq!(err.code, "cloudflare.config_missing_token");
    }

    #[tokio::test]
    async fn uses_request_token_override_in_header_mode() {
        let header_material = fixture_material("header");
        let router = Router::new().route(
            "/accounts/acct-1/cfd_tunnel",
            get({
                let expected_authorization = format!("Bearer {header_material}");
                move |headers: HeaderMap| {
                    let expected_authorization = expected_authorization.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get("authorization")
                                .and_then(|value| value.to_str().ok()),
                            Some(expected_authorization.as_str())
                        );
                        Json(json!({
                            "success": true,
                            "errors": [],
                            "messages": [],
                            "result": [{"id": "tun-1", "name": "override"}],
                            "result_info": {"page": 1, "per_page": 1, "count": 1, "total_count": 1, "total_pages": 1}
                        }))
                    }
                }
            }),
        );

        let base = spawn_router(router).await;
        let mut cfg = test_config(base);
        cfg.api_token = None;
        cfg.api_token_source = ApiTokenSource::Header;
        let client = CloudflareClient::new(cfg).expect("client");

        let page = with_request_api_token_override(
            Some(header_material),
            client.list_tunnels("acct-1", 1, 1),
        )
        .await
        .expect("list tunnels");

        assert_eq!(page.items[0].name, "override");
    }

    #[tokio::test]
    async fn upsert_dns_updates_existing_record_when_target_changes() {
        #[derive(Clone)]
        struct DnsState {
            updates: Arc<AtomicUsize>,
        }

        async fn list_dns() -> Json<Value> {
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": [{
                    "id": "rec-1",
                    "name": "preview.example.com",
                    "type": "CNAME",
                    "content": "old.example.com",
                    "proxied": true,
                    "ttl": 1
                }],
                "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1}
            }))
        }

        async fn update_dns(State(state): State<DnsState>) -> Json<Value> {
            state.updates.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": {
                    "id": "rec-1",
                    "name": "preview.example.com",
                    "type": "CNAME",
                    "content": "new.example.com",
                    "proxied": true,
                    "ttl": 1
                }
            }))
        }

        let state = DnsState {
            updates: Arc::new(AtomicUsize::new(0)),
        };

        let router = Router::new()
            .route("/zones/zone-1/dns_records", get(list_dns))
            .route(
                "/zones/zone-1/dns_records/rec-1",
                axum::routing::put(update_dns),
            )
            .with_state(state.clone());

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let record = client
            .upsert_dns_cname(
                "zone-1",
                &crate::cloudflare::model::DnsRecordUpsertRequest {
                    hostname: "preview.example.com".to_string(),
                    target: "new.example.com".to_string(),
                    proxied: Some(true),
                    ttl: Some(1),
                },
            )
            .await
            .expect("upsert");

        assert_eq!(record.content, "new.example.com");
        assert_eq!(state.updates.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reads_and_patches_worker_settings() {
        let router = Router::new()
            .route(
                "/accounts/acct-1/workers/scripts",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": [{
                            "id": "worker-a",
                            "created_on": "2026-05-08T00:00:00Z",
                            "modified_on": "2026-05-08T00:00:00Z",
                            "compatibility_date": "2026-05-01",
                            "compatibility_flags": ["nodejs_compat"],
                            "usage_model": "standard"
                        }],
                        "result_info": {"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1}
                    }))
                }),
            )
            .route(
                "/accounts/acct-1/workers/scripts/worker-a/settings",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "old"}],
                            "compatibility_date": "2026-05-01"
                        }
                    }))
                })
                .patch(|headers: HeaderMap, body: String| async move {
                    assert!(
                        headers
                            .get("content-type")
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|value| value.starts_with("multipart/form-data;")),
                        "Worker settings patch must use multipart form data"
                    );
                    assert_eq!(
                        body.contains("name=\"settings\""),
                        true,
                        "multipart body should include settings part"
                    );
                    assert!(
                        body.contains(
                            r#""bindings":[{"name":"DESTINATION","text":"new","type":"plain_text"}]"#
                        ),
                        "multipart settings part should contain compact JSON patch"
                    );
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "messages": [],
                        "result": {
                            "bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "new"}],
                            "compatibility_date": "2026-05-01"
                        }
                    }))
                }),
            );

        let base = spawn_router(router).await;
        let client = CloudflareClient::new(test_config(base)).expect("client");
        let workers = client
            .list_workers("acct-1", None)
            .await
            .expect("list workers");
        assert_eq!(workers.items[0].id.as_deref(), Some("worker-a"));

        let before = client
            .get_worker_settings("acct-1", "worker-a")
            .await
            .expect("settings");
        assert_eq!(
            before
                .bindings
                .as_ref()
                .and_then(|bindings| bindings[0].get("text")),
            Some(&json!("old"))
        );

        let patched = client
            .patch_worker_settings(
                "acct-1",
                "worker-a",
                &json!({
                    "bindings": [{"type": "plain_text", "name": "DESTINATION", "text": "new"}]
                }),
            )
            .await
            .expect("patch settings");
        assert_eq!(
            patched
                .bindings
                .as_ref()
                .and_then(|bindings| bindings[0].get("text")),
            Some(&json!("new"))
        );
    }
}
