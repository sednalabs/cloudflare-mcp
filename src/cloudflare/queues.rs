use crate::cloudflare::client::{CloudflareClient, CloudflareEnvelope, RetryPolicy};
use serde_json::Value;

use crate::cloudflare::model::{Queue, QueueMetrics};
use crate::cloudflare::{AdapterError, Page, PageInfo};

impl CloudflareClient {
    pub async fn list_queues(&self, account_id: &str) -> Result<Page<Queue>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/queues"));

        let envelope: CloudflareEnvelope<Vec<Queue>> = self
            .send_envelope("cloudflare.queues.list", RetryPolicy::Idempotent, || {
                self.http
                    .get(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            })
            .await?;

        let items = envelope.result.unwrap_or_default();
        Ok(Page {
            page_info: envelope.result_info.or_else(|| {
                Some(PageInfo {
                    page: None,
                    per_page: None,
                    count: Some(items.len() as u32),
                    total_count: None,
                    total_pages: None,
                })
            }),
            items,
        })
    }

    pub async fn get_queue(&self, account_id: &str, queue_id: &str) -> Result<Queue, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let queue_id = require_non_empty("queue_id", queue_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/queues/{}",
            path_segment(queue_id)
        ));

        let envelope: CloudflareEnvelope<Queue> = self
            .send_envelope("cloudflare.queues.get", RetryPolicy::Idempotent, || {
                self.http
                    .get(url.clone())
                    .bearer_auth(&token)
                    .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            })
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a Queue result",
                "Verify Queues response schema.",
            )
        })
    }

    pub async fn get_queue_metrics(
        &self,
        account_id: &str,
        queue_id: &str,
    ) -> Result<QueueMetrics, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let queue_id = require_non_empty("queue_id", queue_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/queues/{}/metrics",
            path_segment(queue_id)
        ));

        let envelope: CloudflareEnvelope<QueueMetrics> = self
            .send_envelope(
                "cloudflare.queues.metrics.get",
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
                "Cloudflare returned success without Queue metrics",
                "Verify Queues metrics response schema.",
            )
        })
    }

    pub async fn list_queue_consumers(
        &self,
        account_id: &str,
        queue_id: &str,
    ) -> Result<Page<Value>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let queue_id = require_non_empty("queue_id", queue_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/queues/{}/consumers",
            path_segment(queue_id)
        ));

        let envelope: CloudflareEnvelope<Vec<Value>> = self
            .send_envelope(
                "cloudflare.queues.consumers.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                },
            )
            .await?;

        let items = envelope.result.unwrap_or_default();
        Ok(Page {
            page_info: envelope.result_info.or_else(|| {
                Some(PageInfo {
                    page: None,
                    per_page: None,
                    count: Some(items.len() as u32),
                    total_count: None,
                    total_pages: None,
                })
            }),
            items,
        })
    }

    pub async fn get_queue_purge_status(
        &self,
        account_id: &str,
        queue_id: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let queue_id = require_non_empty("queue_id", queue_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/queues/{}/purge",
            path_segment(queue_id)
        ));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.queues.purge.get",
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
