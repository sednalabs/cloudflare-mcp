use serde_json::Value;

use crate::cloudflare::AdapterError;
use crate::cloudflare::client::CloudflareClient;

impl CloudflareClient {
    pub async fn query_analytics_engine(
        &self,
        account_id: &str,
        sql: &str,
    ) -> Result<Value, AdapterError> {
        let account_id = require_non_empty("account_id", account_id)?;
        let sql = require_non_empty("sql", sql)?;
        let token = self.bearer_token()?;
        let url = self.endpoint(&format!("/accounts/{account_id}/analytics_engine/sql"));

        let response = self
            .http
            .post(url)
            .bearer_auth(&token)
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone())
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(sql.to_string())
            .send()
            .await
            .map_err(|err| analytics_engine_transport_error(err))?;

        let status = response.status();
        let body = response.text().await.map_err(|err| {
            AdapterError::new(
                "cloudflare.response_read_failed",
                format!("failed reading Cloudflare Analytics Engine response body: {err}"),
                "Retry request and inspect Cloudflare Analytics Engine availability.",
            )
        })?;

        if !status.is_success() {
            return Err(AdapterError::new(
                "cloudflare.http_error",
                format!("HTTP status {status}: {body}"),
                "Inspect request payload and Cloudflare Analytics Engine response details.",
            ));
        }

        analytics_engine_sql_result(&body)
    }
}

fn analytics_engine_transport_error(err: reqwest::Error) -> AdapterError {
    let code = if err.is_timeout() {
        "cloudflare.timeout"
    } else {
        "cloudflare.transport_error"
    };
    AdapterError::new(
        code,
        format!("cloudflare.analytics_engine.sql request failed: {err}"),
        "Check Cloudflare API reachability, token validity, and timeout settings.",
    )
}

fn analytics_engine_sql_result(body: &str) -> Result<Value, AdapterError> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(Value::Null);
    }

    let value: Value = serde_json::from_str(trimmed).map_err(|err| {
        AdapterError::new(
            "cloudflare.decode_error",
            format!("failed decoding Cloudflare Analytics Engine SQL response: {err}"),
            "Use the default Analytics Engine FORMAT JSON response, or inspect the endpoint response.",
        )
    })?;

    if let Some(result) = cloudflare_envelope_result(&value)? {
        return Ok(result);
    }

    Ok(value)
}

fn cloudflare_envelope_result(value: &Value) -> Result<Option<Value>, AdapterError> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(success) = object.get("success").and_then(Value::as_bool) else {
        return Ok(None);
    };
    if success {
        return Ok(Some(object.get("result").cloned().unwrap_or(Value::Null)));
    }

    let message = object
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("Cloudflare Analytics Engine API returned success=false");
    Err(AdapterError::new(
        "cloudflare.api_error",
        message,
        "Inspect Cloudflare Analytics Engine SQL and token permissions.",
    ))
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
