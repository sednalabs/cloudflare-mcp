use serde_json::{Map, Value, json};

use crate::cloudflare::client::{CloudflareClient, CloudflareEnvelope, RetryPolicy};
use crate::cloudflare::model::{BulkRedirectItemWrite, RulesList, RulesListOperation, Ruleset};
use crate::cloudflare::{AdapterError, Page, PageInfo};

const REDIRECT_PHASE: &str = "http_request_redirect";

impl CloudflareClient {
    pub async fn list_rules_lists(
        &self,
        account_id: &str,
    ) -> Result<Page<RulesList>, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/rules/lists"));

        let envelope: CloudflareEnvelope<Vec<RulesList>> = self
            .send_envelope(
                "cloudflare.rules.lists.list",
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

    pub async fn get_rules_list(
        &self,
        account_id: &str,
        list_id: &str,
    ) -> Result<RulesList, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let list_id = require_non_empty("list_id", list_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rules/lists/{}",
            path_segment(list_id)
        ));

        let envelope: CloudflareEnvelope<RulesList> = self
            .send_envelope(
                "cloudflare.rules.lists.get",
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
                "Cloudflare returned success without a rules list result",
                "Verify Rules Lists response schema.",
            )
        })
    }

    pub async fn create_redirect_list(
        &self,
        account_id: &str,
        name: &str,
        description: Option<&str>,
    ) -> Result<RulesList, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let name = require_non_empty("name", name)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/rules/lists"));
        let mut body = Map::new();
        body.insert("name".to_string(), Value::String(name.to_string()));
        body.insert("kind".to_string(), Value::String("redirect".to_string()));
        if let Some(description) = description.map(str::trim).filter(|value| !value.is_empty()) {
            body.insert(
                "description".to_string(),
                Value::String(description.to_string()),
            );
        }

        let envelope: CloudflareEnvelope<RulesList> = self
            .send_envelope(
                "cloudflare.rules.lists.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&Value::Object(body.clone()))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a rules list create result",
                "Verify Rules Lists create response schema.",
            )
        })
    }

    pub async fn update_rules_list(
        &self,
        account_id: &str,
        list_id: &str,
        description: Option<&str>,
    ) -> Result<RulesList, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let list_id = require_non_empty("list_id", list_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rules/lists/{}",
            path_segment(list_id)
        ));
        let mut body = Map::new();
        if let Some(description) = description.map(str::trim) {
            body.insert(
                "description".to_string(),
                Value::String(description.to_string()),
            );
        }
        require_non_empty_object("rules list update", &body)?;

        let envelope: CloudflareEnvelope<RulesList> = self
            .send_envelope(
                "cloudflare.rules.lists.update",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&Value::Object(body.clone()))
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a rules list update result",
                "Verify Rules Lists update response schema.",
            )
        })
    }

    pub async fn list_rules_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        cursor: Option<&str>,
        per_page: Option<u32>,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let list_id = require_non_empty("list_id", list_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rules/lists/{}/items",
            path_segment(list_id)
        ));
        let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
        let per_page = per_page.map(|value| value.clamp(1, 500));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.rules.lists.items.list",
                RetryPolicy::Idempotent,
                || {
                    let mut builder = self
                        .http
                        .get(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());
                    if let Some(cursor) = cursor {
                        builder = builder.query(&[("cursor", cursor)]);
                    }
                    if let Some(per_page) = per_page {
                        builder = builder.query(&[("per_page", per_page)]);
                    }
                    builder
                },
            )
            .await?;

        Ok(json!({
            "result": envelope.result.unwrap_or_else(|| json!([])),
            "result_info": envelope.result_info,
        }))
    }

    pub async fn import_redirect_list_items(
        &self,
        account_id: &str,
        list_id: &str,
        items: &[BulkRedirectItemWrite],
        mode: BulkRedirectImportMode,
    ) -> Result<RulesListOperation, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let list_id = require_non_empty("list_id", list_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rules/lists/{}/items",
            path_segment(list_id)
        ));
        let body = redirect_items_body(items);

        let envelope: CloudflareEnvelope<RulesListOperation> = self
            .send_envelope(
                "cloudflare.rules.lists.items.import",
                RetryPolicy::NonIdempotent,
                || {
                    let builder = match mode {
                        BulkRedirectImportMode::Append => self.http.post(url.clone()),
                        BulkRedirectImportMode::Replace => self.http.put(url.clone()),
                    };
                    builder
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&body)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a rules list operation result",
                "Verify Rules Lists bulk operation response schema.",
            )
        })
    }

    pub async fn get_rules_list_operation(
        &self,
        account_id: &str,
        operation_id: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let operation_id = require_non_empty("operation_id", operation_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rules/lists/bulk_operations/{}",
            path_segment(operation_id)
        ));

        let envelope: CloudflareEnvelope<Value> = self
            .send_envelope(
                "cloudflare.rules.lists.operations.get",
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
                "Cloudflare returned success without a rules list operation status",
                "Verify Rules Lists bulk operation status response schema.",
            )
        })
    }

    pub async fn get_account_redirect_ruleset(
        &self,
        account_id: &str,
    ) -> Result<Ruleset, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rulesets/phases/{REDIRECT_PHASE}/entrypoint"
        ));

        let envelope: CloudflareEnvelope<Ruleset> = self
            .send_envelope(
                "cloudflare.rulesets.redirect.entrypoint.get",
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
                "Cloudflare returned success without a redirect ruleset result",
                "Verify Rulesets response schema.",
            )
        })
    }

    pub async fn create_account_redirect_ruleset(
        &self,
        account_id: &str,
        rules: Vec<Value>,
    ) -> Result<Ruleset, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/rulesets"));
        let body = json!({
            "name": "default",
            "kind": "root",
            "phase": REDIRECT_PHASE,
            "rules": rules,
        });

        let envelope: CloudflareEnvelope<Ruleset> = self
            .send_envelope(
                "cloudflare.rulesets.redirect.entrypoint.create",
                RetryPolicy::NonIdempotent,
                || {
                    self.http
                        .post(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&body)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a redirect ruleset create result",
                "Verify Rulesets create response schema.",
            )
        })
    }

    pub async fn update_account_redirect_ruleset(
        &self,
        account_id: &str,
        ruleset: &Ruleset,
        rules: Vec<Value>,
    ) -> Result<Ruleset, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!(
            "/accounts/{account_id}/rulesets/{}",
            path_segment(&ruleset.id)
        ));
        let body = json!({
            "name": ruleset.name,
            "kind": ruleset.kind,
            "phase": ruleset.phase,
            "description": ruleset.description,
            "rules": rules,
        });

        let envelope: CloudflareEnvelope<Ruleset> = self
            .send_envelope(
                "cloudflare.rulesets.redirect.entrypoint.update",
                RetryPolicy::Idempotent,
                || {
                    self.http
                        .put(url.clone())
                        .bearer_auth(&token)
                        .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
                        .json(&body)
                },
            )
            .await?;

        envelope.result.ok_or_else(|| {
            AdapterError::new(
                "cloudflare.empty_result",
                "Cloudflare returned success without a redirect ruleset update result",
                "Verify Rulesets update response schema.",
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkRedirectImportMode {
    Append,
    Replace,
}

impl BulkRedirectImportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Replace => "replace",
        }
    }
}

pub fn redirect_rule_for_list(list_name: &str, description: Option<&str>, enabled: bool) -> Value {
    let description = description
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Enable bulk redirect list {list_name}"));
    json!({
        "description": description,
        "expression": format!("http.request.full_uri in ${list_name}"),
        "action": "redirect",
        "action_parameters": {
            "from_list": {
                "name": list_name,
                "key": "http.request.full_uri",
            },
        },
        "enabled": enabled,
    })
}

fn redirect_items_body(items: &[BulkRedirectItemWrite]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| {
                let mut redirect = Map::new();
                redirect.insert(
                    "source_url".to_string(),
                    Value::String(item.source_url.trim().to_string()),
                );
                redirect.insert(
                    "target_url".to_string(),
                    Value::String(item.target_url.trim().to_string()),
                );
                if let Some(status_code) = item.status_code {
                    redirect.insert(
                        "status_code".to_string(),
                        Value::Number(serde_json::Number::from(status_code)),
                    );
                }
                if let Some(value) = item.preserve_query_string {
                    redirect.insert("preserve_query_string".to_string(), Value::Bool(value));
                }
                if let Some(value) = item.include_subdomains {
                    redirect.insert("include_subdomains".to_string(), Value::Bool(value));
                }
                if let Some(value) = item.subpath_matching {
                    redirect.insert("subpath_matching".to_string(), Value::Bool(value));
                }
                if let Some(value) = item.preserve_path_suffix {
                    redirect.insert("preserve_path_suffix".to_string(), Value::Bool(value));
                }
                json!({ "redirect": Value::Object(redirect) })
            })
            .collect(),
    )
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

fn require_non_empty_object(
    name: &'static str,
    value: &Map<String, Value>,
) -> Result<(), AdapterError> {
    if value.is_empty() {
        return Err(AdapterError::new(
            "cloudflare.invalid_argument",
            format!("{name} must include at least one field"),
            "Provide a non-empty update payload.",
        ));
    }
    Ok(())
}
