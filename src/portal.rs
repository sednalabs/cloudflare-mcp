use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use crate::config::PortalAgentConfig;

const HEADER_CF_ACCESS_CLIENT_ID: &str = "CF-Access-Client-Id";
const HEADER_CF_ACCESS_CLIENT_SECRET: &str = "CF-Access-Client-Secret";
const MAX_RESPONSE_TEXT_CHARS: usize = 4096;

#[derive(Clone, Debug)]
pub struct PortalAgentClient {
    cfg: PortalAgentConfig,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortalAgentErrorPayload {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Error)]
#[error("{code}: {message}")]
pub struct PortalAgentError {
    pub code: &'static str,
    pub message: String,
    pub hint: &'static str,
    pub status: Option<u16>,
}

impl PortalAgentError {
    fn new(code: &'static str, message: impl Into<String>, hint: &'static str) -> Self {
        Self {
            code,
            message: mcp_toolkit_observability::sanitize_error_message(&message.into(), 512),
            hint,
            status: None,
        }
    }

    fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    pub fn payload(&self) -> PortalAgentErrorPayload {
        PortalAgentErrorPayload {
            code: self.code,
            message: self.message.clone(),
            hint: self.hint,
            status: self.status,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortalAgentResponse {
    pub status: u16,
    pub success: bool,
    pub response: Value,
}

impl PortalAgentClient {
    pub fn new(cfg: PortalAgentConfig) -> Result<Self, PortalAgentError> {
        let http = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .map_err(|err| {
                PortalAgentError::new(
                    "portal.client_init_failed",
                    format!("failed to create portal HTTP client: {err}"),
                    "Verify TLS/runtime dependencies and CLOUDFLARE_MCP_PORTAL_TIMEOUT_MS.",
                )
            })?;
        Ok(Self { cfg, http })
    }

    pub fn has_agent_token(&self) -> bool {
        self.cfg.agent_token.is_some()
    }

    pub fn has_access_service_token(&self) -> bool {
        self.cfg.access_client_id.is_some() && self.cfg.access_client_secret.is_some()
    }

    pub fn allowed_url_prefixes(&self) -> &[String] {
        &self.cfg.allowed_url_prefixes
    }

    pub fn validate_request_url(&self, url: &str) -> Result<Url, PortalAgentError> {
        let parsed = Url::parse(url).map_err(|err| {
            PortalAgentError::new(
                "portal.invalid_url",
                format!("invalid portal URL: {err}"),
                "Provide an absolute HTTPS URL allowed by CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES.",
            )
        })?;
        if parsed.scheme() != "https" {
            return Err(PortalAgentError::new(
                "portal.invalid_scheme",
                "portal URL must use https",
                "Use an HTTPS endpoint; secrets are never attached to plaintext HTTP.",
            ));
        }
        if !self
            .cfg
            .allowed_url_prefixes
            .iter()
            .any(|prefix| parsed.as_str().starts_with(prefix))
        {
            return Err(PortalAgentError::new(
                "portal.url_not_allowed",
                "portal URL is outside the configured allowlist",
                "Set CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES to the approved endpoint prefix.",
            ));
        }
        Ok(parsed)
    }

    pub async fn send(
        &self,
        url: &Url,
        method: &str,
        body: Option<Value>,
        use_agent_token: bool,
        use_access_service_token: bool,
    ) -> Result<PortalAgentResponse, PortalAgentError> {
        let method = parse_method(method)?;
        let mut request = self
            .http
            .request(method, url.clone())
            .header(reqwest::header::USER_AGENT, self.cfg.user_agent.clone());

        if use_agent_token {
            let token = self.cfg.agent_token.as_deref().ok_or_else(|| {
                PortalAgentError::new(
                    "portal.agent_token_missing",
                    "portal agent token is not configured",
                    "Set CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN or AGENT_API_TOKEN in the server environment.",
                )
            })?;
            request = request.bearer_auth(token);
        }

        if use_access_service_token {
            let client_id = self.cfg.access_client_id.as_deref().ok_or_else(|| {
                PortalAgentError::new(
                    "portal.access_client_id_missing",
                    "Cloudflare Access client id is not configured",
                    "Set CLOUDFLARE_MCP_ACCESS_CLIENT_ID in the server environment.",
                )
            })?;
            let client_secret = self.cfg.access_client_secret.as_deref().ok_or_else(|| {
                PortalAgentError::new(
                    "portal.access_client_secret_missing",
                    "Cloudflare Access client secret is not configured",
                    "Set CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET in the server environment.",
                )
            })?;
            request = request
                .header(HEADER_CF_ACCESS_CLIENT_ID, client_id)
                .header(HEADER_CF_ACCESS_CLIENT_SECRET, client_secret);
        }

        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await.map_err(|err| {
            let code = if err.is_timeout() {
                "portal.request_timeout"
            } else {
                "portal.request_failed"
            };
            PortalAgentError::new(
                code,
                format!("portal request failed: {err}"),
                "Retry if transient; otherwise inspect portal endpoint availability and credentials.",
            )
        })?;
        let status = response.status();
        let body_text = response.text().await.map_err(|err| {
            PortalAgentError::new(
                "portal.response_read_failed",
                format!("failed to read portal response: {err}"),
                "Retry the request; inspect portal logs if the failure persists.",
            )
            .with_status(Some(status.as_u16()))
        })?;

        Ok(PortalAgentResponse {
            status: status.as_u16(),
            success: status.is_success(),
            response: parse_sanitized_response(&body_text),
        })
    }
}

pub fn parse_method(value: &str) -> Result<Method, PortalAgentError> {
    match value.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        _ => Err(PortalAgentError::new(
            "portal.invalid_method",
            "method must be GET, POST, PUT, PATCH, or DELETE",
            "Use a standard HTTP method supported by the portal endpoint.",
        )),
    }
}

fn parse_sanitized_response(body_text: &str) -> Value {
    match serde_json::from_str::<Value>(body_text) {
        Ok(value) => redact_sensitive_json(value),
        Err(_) => json!({
            "body_preview": truncate(body_text, MAX_RESPONSE_TEXT_CHARS),
            "json": false,
        }),
    }
}

pub fn redact_sensitive_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(&key) {
                        Value::String("<redacted>".to_string())
                    } else {
                        redact_sensitive_json(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_sensitive_json).collect())
        }
        Value::String(value) => Value::String(truncate(&value, MAX_RESPONSE_TEXT_CHARS)),
        other => other,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "authorization",
        "access_client_secret",
        "api_key",
        "api_token",
        "bearer",
        "client_secret",
        "credential",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{PortalAgentClient, redact_sensitive_json};
    use crate::config::PortalAgentConfig;

    fn fixture_material(label: &str) -> String {
        let mut value = String::from("fixture-");
        value.push_str(label);
        value.push_str("-value");
        value
    }

    fn test_client() -> PortalAgentClient {
        PortalAgentClient::new(PortalAgentConfig {
            allowed_url_prefixes: vec!["https://staff.example.com/api/agent/".to_string()],
            agent_token: Some(fixture_material("agent")),
            access_client_id: Some("access-id".to_string()),
            access_client_secret: Some(fixture_material("access-material")),
            request_timeout: Duration::from_secs(1),
            user_agent: "cloudflare-mcp-test".to_string(),
        })
        .expect("portal client")
    }

    #[test]
    fn validates_https_url_allowlist() {
        let client = test_client();
        assert!(
            client
                .validate_request_url("https://staff.example.com/api/agent/import")
                .is_ok()
        );
        assert!(
            client
                .validate_request_url("https://other.example.com/api/agent/import")
                .expect_err("outside allowlist")
                .code
                .contains("url_not_allowed")
        );
        assert!(
            client
                .validate_request_url("http://staff.example.com/api/agent/import")
                .expect_err("plaintext")
                .code
                .contains("invalid_scheme")
        );
    }

    #[test]
    fn redacts_sensitive_json_response_keys() {
        let sanitized = redact_sensitive_json(json!({
            "ok": true,
            "token": fixture_material("payload"),
            "nested": {
                "client_secret": fixture_material("nested-payload"),
                "value": "visible"
            }
        }));
        assert_eq!(sanitized["token"], json!("<redacted>"));
        assert_eq!(sanitized["nested"]["client_secret"], json!("<redacted>"));
        assert_eq!(sanitized["nested"]["value"], json!("visible"));
    }
}
