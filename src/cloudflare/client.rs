use std::cmp;
use std::collections::BTreeSet;
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::de::DeserializeOwned;
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

    pub fn payload(&self) -> AdapterErrorPayload {
        AdapterErrorPayload {
            code: self.code,
            message: self.message.clone(),
            hint: self.hint,
            retryable: self.retryable,
            status: self.status,
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
        Ok(Self { cfg, http })
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
        let url = self.endpoint(&format!("/accounts/{account_id}/d1/database"));
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
            "/accounts/{account_id}/d1/database/{}",
            path_segment(database_id)
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
            "/accounts/{account_id}/d1/database/{}",
            path_segment(database_id)
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
            "/accounts/{account_id}/d1/database/{}",
            path_segment(database_id)
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
            account_id,
            database_id,
            sql,
            params,
        )
        .await
    }

    async fn execute_d1_query(
        &self,
        operation: &'static str,
        retry_policy: RetryPolicy,
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
            "/accounts/{account_id}/d1/database/{}/query",
            path_segment(database_id)
        ));
        let mut body = Map::new();
        body.insert("sql".to_string(), Value::String(sql.to_string()));
        if !params.is_empty() {
            body.insert("params".to_string(), Value::Array(params.to_vec()));
        }

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(operation, retry_policy, || {
                self.http
                    .post(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .json(&Value::Object(body.clone()))
            })
            .await?;

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

        let envelope: CloudflareEnvelope<WorkerScript> = self
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
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .multipart(form)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without uploaded Worker script details",
                "Verify Worker script upload endpoint and response schema.",
            )
        })
    }

    pub async fn upload_worker_multipart(
        &self,
        account_id: &str,
        script_name: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<WorkerScript, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let content_type = require_non_empty("content_type", content_type)?;
        let content_type_header = header_value("content-type", content_type)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{script_name}"
        ));

        let envelope: CloudflareEnvelope<WorkerScript> = self
            .send_envelope(
                "cloudflare.workers.script.upload_multipart",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .header(reqwest::header::CONTENT_TYPE, content_type_header.clone())
                        .body(bytes.clone())
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without uploaded Worker script details",
                "Verify Worker script upload endpoint and response schema.",
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
        mut request_builder: F,
    ) -> Result<CloudflareEnvelope<T>, AdapterError>
    where
        T: DeserializeOwned,
        F: FnMut() -> reqwest::RequestBuilder,
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

            let envelope: CloudflareEnvelope<T> = serde_json::from_str(&body).map_err(|err| {
                AdapterError::new(
                    "cloudflare.decode_error",
                    format!("failed decoding Cloudflare envelope: {err}"),
                    "Verify Cloudflare endpoint compatibility with expected response schema.",
                )
            })?;

            if !envelope.success {
                return Err(api_error(&envelope.errors));
            }

            return Ok(envelope);
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

    AdapterError::new(
        "cloudflare.api_error",
        detail,
        "Inspect account/zone permissions and Cloudflare API request payload.",
    )
    .with_cloudflare_api_error(cloudflare_api_error)
    .with_status(Some(StatusCode::BAD_REQUEST.as_u16()))
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

    AdapterError::new(code, detail, hint)
        .with_cloudflare_api_error(envelope_error)
        .with_retryable(is_retryable_status(status))
        .with_status(Some(status.as_u16()))
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::{
        AdapterError, CloudflareApiError, CloudflareClient, is_d1_sqlite_auth_error, path_segment,
        with_request_api_token_override,
    };
    use crate::cloudflare::model::AccessPolicyWrite;
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

    #[test]
    fn path_segment_encodes_separators() {
        assert_eq!(path_segment("zone/one two"), "zone%2Fone%20two");
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
            err.payload().hint,
            "Inspect account/zone permissions and Cloudflare API request payload."
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
