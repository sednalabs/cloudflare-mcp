use serde_json::Value;

use crate::cloudflare::client::{CloudflareClient, CloudflareEnvelope, RetryPolicy};
use crate::cloudflare::{AdapterError, Page, PageInfo};

impl CloudflareClient {
    pub async fn get_email_routing_settings(&self, zone_id: &str) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/email/routing"));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.email_routing.settings.get",
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
                "Cloudflare returned success without Email Routing settings",
                "Verify Email Routing settings response schema.",
            )
        })
    }

    pub async fn get_email_routing_dns(&self, zone_id: &str) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/email/routing/dns"));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.email_routing.dns.get",
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

    pub async fn list_email_routing_rules(
        &self,
        zone_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Page<Value>, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/email/routing/rules"));

        let envelope: CloudflareEnvelope<Vec<Value>> = self
            .send_envelope(
                "cloudflare.email_routing.rules.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .query(&[("page", page), ("per_page", per_page)])
                },
            )
            .await?;

        let items = envelope.result.unwrap_or_default();
        Ok(Page {
            page_info: envelope.result_info.or_else(|| {
                Some(PageInfo {
                    page: Some(page),
                    per_page: Some(per_page),
                    count: Some(items.len().min(u32::MAX as usize) as u32),
                    total_count: None,
                    total_pages: None,
                })
            }),
            items,
        })
    }

    pub async fn get_email_routing_rule(
        &self,
        zone_id: &str,
        rule_identifier: &str,
    ) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let rule_identifier = require_non_empty("rule_identifier", rule_identifier)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/zones/{zone_id}/email/routing/rules/{}",
            path_segment(rule_identifier)
        ));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.email_routing.rules.get",
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
                "Cloudflare returned success without an Email Routing rule",
                "Verify Email Routing rule response schema.",
            )
        })
    }

    pub async fn get_email_routing_catch_all(&self, zone_id: &str) -> Result<Value, AdapterError> {
        let zone_id = require_non_empty("zone_id", zone_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/zones/{zone_id}/email/routing/rules/catch_all"));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.email_routing.catch_all.get",
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
                "Cloudflare returned success without an Email Routing catch-all rule",
                "Verify Email Routing catch-all response schema.",
            )
        })
    }

    pub async fn list_email_routing_addresses(
        &self,
        account_id: &str,
        page: u32,
        per_page: u32,
    ) -> Result<Page<Value>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/email/routing/addresses"));

        let envelope: CloudflareEnvelope<Vec<Value>> = self
            .send_envelope(
                "cloudflare.email_routing.addresses.list",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .query(&[("page", page), ("per_page", per_page)])
                },
            )
            .await?;

        let items = envelope.result.unwrap_or_default();
        Ok(Page {
            page_info: envelope.result_info.or_else(|| {
                Some(PageInfo {
                    page: Some(page),
                    per_page: Some(per_page),
                    count: Some(items.len().min(u32::MAX as usize) as u32),
                    total_count: None,
                    total_pages: None,
                })
            }),
            items,
        })
    }

    pub async fn get_email_routing_address(
        &self,
        account_id: &str,
        destination_address_identifier: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let destination_address_identifier = require_non_empty(
            "destination_address_identifier",
            destination_address_identifier,
        )?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/email/routing/addresses/{}",
            path_segment(destination_address_identifier)
        ));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.email_routing.addresses.get",
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
                "Cloudflare returned success without an Email Routing destination address",
                "Verify Email Routing destination address response schema.",
            )
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
