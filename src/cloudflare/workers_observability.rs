use serde_json::Value;

use crate::cloudflare::client::{CloudflareClient, CloudflareEnvelope, RetryPolicy};
use crate::cloudflare::{AdapterError, Page, PageInfo};

impl CloudflareClient {
    pub async fn query_workers_observability(
        &self,
        account_id: &str,
        body: &Value,
    ) -> Result<Value, AdapterError> {
        self.post_workers_observability_value(
            "cloudflare.workers.observability.telemetry.query",
            account_id,
            "/workers/observability/telemetry/query",
            body,
        )
        .await
    }

    pub async fn list_workers_observability_keys(
        &self,
        account_id: &str,
        body: &Value,
    ) -> Result<Page<Value>, AdapterError> {
        self.post_workers_observability_page(
            "cloudflare.workers.observability.telemetry.keys",
            account_id,
            "/workers/observability/telemetry/keys",
            body,
        )
        .await
    }

    pub async fn list_workers_observability_values(
        &self,
        account_id: &str,
        body: &Value,
    ) -> Result<Page<Value>, AdapterError> {
        self.post_workers_observability_page(
            "cloudflare.workers.observability.telemetry.values",
            account_id,
            "/workers/observability/telemetry/values",
            body,
        )
        .await
    }

    pub async fn list_worker_tails(
        &self,
        account_id: &str,
        script_name: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let script_name = require_non_empty("script_name", script_name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/workers/scripts/{}/tails",
            path_segment(script_name)
        ));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.workers.scripts.tails.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        Ok(envelope.result.unwrap_or_else(|| Value::Null))
    }

    async fn post_workers_observability_value(
        &self,
        operation: &'static str,
        account_id: &str,
        path_suffix: &str,
        body: &Value,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}{path_suffix}"));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(operation, RetryPolicy::Idempotent, || {
                self.http
                    .post(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .json(body)
            })
            .await?;

        Ok(envelope.result.unwrap_or_else(|| Value::Null))
    }

    async fn post_workers_observability_page(
        &self,
        operation: &'static str,
        account_id: &str,
        path_suffix: &str,
        body: &Value,
    ) -> Result<Page<Value>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}{path_suffix}"));

        let envelope: CloudflareEnvelope<Vec<Value>> = self
            .send_envelope(operation, RetryPolicy::Idempotent, || {
                self.http
                    .post(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                    .json(body)
            })
            .await?;

        let items = envelope.result.unwrap_or_default();
        Ok(Page {
            page_info: envelope.result_info.or_else(|| {
                Some(PageInfo {
                    page: None,
                    per_page: None,
                    count: Some(items.len().min(u32::MAX as usize) as u32),
                    total_count: None,
                    total_pages: None,
                })
            }),
            items,
        })
    }
}

fn path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
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
