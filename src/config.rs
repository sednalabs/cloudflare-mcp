use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use mcp_toolkit_auth::{AuthConfig, AuthMode, AuthSecurityProfile, ClientAuthMethod};
use url::Url;

const DEFAULT_ELICITATION_REQUIRED_TOOLS: &str = "account_api_tokens,api_mutate,lock_first_publish,emergency_unpublish,replace_access_policies,apply_access_allowlist,portal_agent_request,cache_purge,cache_rules,r2_put_object,workers_upload_script";
const MANDATORY_ELICITATION_REQUIRED_TOOLS: &[&str] = &["account_api_tokens", "api_mutate"];
const DEFAULT_ELICITATION_TIMEOUT_MS: i64 = 30_000;
const INSECURE_DEV_DELEGATION_SECRET: &str = "cloudflare-mcp-loopback-fixture";
const AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET: &str =
    "CLOUDFLARE_MCP_AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeMode {
    Off,
    Historyless,
}

impl ResumeMode {
    pub fn resume_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifecycleMode {
    Legacy,
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiTokenSource {
    Config,
    Header,
    HeaderOrConfig,
}

impl ApiTokenSource {
    pub fn uses_request_header(self) -> bool {
        matches!(self, Self::Header | Self::HeaderOrConfig)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Header => "header",
            Self::HeaderOrConfig => "header_or_config",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamableHttpConfig {
    pub resume_mode: ResumeMode,
    pub max_streams: usize,
    pub max_events: usize,
    pub session_keep_alive: Option<Duration>,
    pub session_lifecycle_mode: SessionLifecycleMode,
    pub session_disconnected_idle_timeout: Option<Duration>,
    pub retry_interval: Option<Duration>,
    pub stateless_fallback: bool,
}

#[derive(Debug, Clone)]
pub struct CloudflareApiConfig {
    pub api_base_url: String,
    pub api_token: Option<String>,
    pub api_token_source: ApiTokenSource,
    pub api_token_header: String,
    pub r2_access_key_id: Option<String>,
    pub r2_secret_access_key: Option<String>,
    pub r2_endpoint: Option<String>,
    pub default_account_id: Option<String>,
    pub default_zone_id: Option<String>,
    pub request_timeout: Duration,
    pub max_retries: u32,
    pub retry_base_delay: Duration,
    pub retry_max_delay: Duration,
    pub user_agent: String,
}

#[derive(Clone)]
pub struct PortalAgentConfig {
    pub allowed_url_prefixes: Vec<String>,
    pub agent_token: Option<String>,
    pub access_client_id: Option<String>,
    pub access_client_secret: Option<String>,
    pub request_timeout: Duration,
    pub user_agent: String,
}

impl std::fmt::Debug for PortalAgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalAgentConfig")
            .field("allowed_url_prefixes", &self.allowed_url_prefixes)
            .field("has_agent_token", &self.agent_token.is_some())
            .field("has_access_client_id", &self.access_client_id.is_some())
            .field(
                "has_access_client_secret",
                &self.access_client_secret.is_some(),
            )
            .field("request_timeout", &self.request_timeout)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ElicitationConfig {
    pub enabled: bool,
    pub required_tools: Vec<String>,
    pub apply_only: bool,
    pub timeout: Option<Duration>,
    pub fail_open_unsupported_client: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub allow_non_loopback: bool,
    pub allowed_hosts: Vec<String>,
    pub read_only_mode: bool,
    pub api_parity_enabled: bool,
    pub elicitation: ElicitationConfig,
    pub streamable_http: StreamableHttpConfig,
    pub auth_mode: Option<AuthMode>,
    pub auth_resource_server_mode: bool,
    pub auth_optional_loopback: bool,
    pub auth_realm: String,
    pub auth_resource_url: Option<String>,
    pub auth_issuer: Option<String>,
    pub auth_scopes_supported: Vec<String>,
    pub auth_allowed_client_ids: Vec<String>,
    pub auth_config: AuthConfig,
    pub cloudflare: CloudflareApiConfig,
    pub portal_agent: PortalAgentConfig,
}

pub fn load_config() -> Result<Config, String> {
    load_config_with_auth_default("delegation")
}

pub fn load_config_with_auth_default(auth_mode_default: &str) -> Result<Config, String> {
    let bind_addr = env_setting("CLOUDFLARE_MCP_BIND_ADDR", "127.0.0.1:9501");
    let allow_non_loopback = env_flag("CLOUDFLARE_MCP_ALLOW_NON_LOOPBACK", false)?;
    let allowed_hosts = env_csv("CLOUDFLARE_MCP_ALLOWED_HOSTS", "localhost,127.0.0.1,::1");
    let read_only_mode = env_flag("CLOUDFLARE_MCP_READ_ONLY", false)?;
    let api_parity_enabled = env_flag("CLOUDFLARE_MCP_API_PARITY_ENABLED", true)?;
    let auth_optional_loopback = env_flag("CLOUDFLARE_MCP_AUTH_OPTIONAL_LOOPBACK", false)?;
    let auth_realm = env_setting("CLOUDFLARE_MCP_AUTH_REALM", "cloudflare-mcp");

    let auth_mode_raw = env_setting("CLOUDFLARE_MCP_AUTH_MODE", auth_mode_default);
    let auth_resource_server_mode = auth_mode_raw.trim().eq_ignore_ascii_case("resource_server");
    let auth_mode = parse_auth_mode(&auth_mode_raw)?;
    let auth_resource_url = env_optional_string("CLOUDFLARE_MCP_AUTH_RESOURCE_URL");
    let auth_issuer = env_optional_string("CLOUDFLARE_MCP_AUTH_ISSUER");

    let mut auth_config = AuthConfig::with_profile(AuthSecurityProfile::L2Strong);
    if let Some(mode) = auth_mode {
        auth_config.mode = mode;
    }
    auth_config.strict_oauth =
        env_flag("CLOUDFLARE_MCP_AUTH_STRICT_OAUTH", auth_config.strict_oauth)?;
    auth_config.jwks_url = env_optional_string("CLOUDFLARE_MCP_AUTH_JWKS_URL");
    auth_config.issuer = auth_issuer.clone();
    auth_config.audience = env_optional_string("CLOUDFLARE_MCP_AUTH_AUDIENCE");
    auth_config.required_scopes = env_csv(
        "CLOUDFLARE_MCP_AUTH_REQUIRED_SCOPES",
        "cloudflare:read,cloudflare:write",
    );
    auth_config.actor_claim = env_setting("CLOUDFLARE_MCP_AUTH_ACTOR_CLAIM", "sub");
    auth_config.introspection_url = env_optional_string("CLOUDFLARE_MCP_AUTH_INTROSPECTION_URL");
    auth_config.introspection_client_id =
        env_optional_string("CLOUDFLARE_MCP_AUTH_INTROSPECTION_CLIENT_ID");
    auth_config.introspection_client_secret =
        env_optional_string("CLOUDFLARE_MCP_AUTH_INTROSPECTION_CLIENT_SECRET");
    auth_config.introspection_auth_method = parse_auth_method(&env_setting(
        "CLOUDFLARE_MCP_AUTH_INTROSPECTION_AUTH_METHOD",
        "client_secret_basic",
    ))?;
    auth_config.introspection_cache_ttl_s = env_f64(
        "CLOUDFLARE_MCP_AUTH_INTROSPECTION_CACHE_TTL_S",
        auth_config.introspection_cache_ttl_s,
    )?;
    auth_config.introspection_force = env_flag(
        "CLOUDFLARE_MCP_AUTH_INTROSPECTION_FORCE",
        auth_config.introspection_force,
    )?;
    auth_config.delegation_secret = env_optional_string("CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET");
    auth_config.delegation_issuer =
        env_setting("CLOUDFLARE_MCP_AUTH_DELEGATION_ISSUER", "cloudflare-mcp");
    auth_config.delegation_audience =
        env_setting("CLOUDFLARE_MCP_AUTH_DELEGATION_AUDIENCE", "cloudflare-mcp");
    auth_config.jti_ttl_s = env_f64("CLOUDFLARE_MCP_AUTH_JTI_TTL_S", auth_config.jti_ttl_s)?;
    auth_config.jti_cache_size = env_i64(
        "CLOUDFLARE_MCP_AUTH_JTI_CACHE_SIZE",
        auth_config.jti_cache_size,
    )?;
    auth_config.jti_enforce_bearer = env_flag(
        "CLOUDFLARE_MCP_AUTH_JTI_ENFORCE_BEARER",
        auth_config.jti_enforce_bearer,
    )?;
    auth_config.clock_skew_s =
        env_f64("CLOUDFLARE_MCP_AUTH_CLOCK_SKEW_S", auth_config.clock_skew_s)?;

    let auth_scopes_supported = env_csv("CLOUDFLARE_MCP_AUTH_SCOPES_SUPPORTED", "");
    if auth_scopes_supported.is_empty() {
        auth_config.required_scopes = auth_config
            .required_scopes
            .iter()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect();
    }

    if auth_mode.is_some() {
        validate_url(
            "CLOUDFLARE_MCP_AUTH_RESOURCE_URL",
            auth_resource_url.as_deref(),
        )?;
        validate_url("CLOUDFLARE_MCP_AUTH_ISSUER", auth_issuer.as_deref())?;
    }
    if matches!(
        auth_mode,
        Some(AuthMode::Jwks) | Some(AuthMode::Introspection)
    ) && auth_issuer.is_none()
    {
        return Err(
            "CLOUDFLARE_MCP_AUTH_ISSUER is required when CLOUDFLARE_MCP_AUTH_MODE is resource_server, jwks, or introspection."
                .to_string(),
        );
    }

    if auth_mode.is_some() && auth_config.audience.is_none() {
        let derived_audience =
            canonical_auth_resource_url(&bind_addr, auth_resource_url.as_deref())?;
        auth_config.audience = Some(derived_audience);
    }
    apply_delegation_secret_policy(auth_mode, &bind_addr, &mut auth_config)?;

    let streamable_http = load_streamable_http_config()?;
    let elicitation = load_elicitation_config()?;
    let api_token_source =
        parse_api_token_source(&env_setting("CLOUDFLARE_MCP_API_TOKEN_SOURCE", "config"))?;
    let api_token_header = env_setting("CLOUDFLARE_MCP_API_TOKEN_HEADER", "x-cloudflare-api-token");
    if api_token_source.uses_request_header() && api_token_header.trim().is_empty() {
        return Err(
            "CLOUDFLARE_MCP_API_TOKEN_HEADER must be set when CLOUDFLARE_MCP_API_TOKEN_SOURCE uses request headers."
                .to_string(),
        );
    }

    let cloudflare = CloudflareApiConfig {
        api_base_url: env_setting(
            "CLOUDFLARE_MCP_API_BASE_URL",
            "https://api.cloudflare.com/client/v4",
        ),
        api_token: env_optional_string("CLOUDFLARE_MCP_API_TOKEN"),
        api_token_source,
        api_token_header: api_token_header.trim().to_string(),
        r2_access_key_id: env_secret_or_file(
            "CLOUDFLARE_MCP_R2_ACCESS_KEY_ID",
            "CLOUDFLARE_MCP_R2_ACCESS_KEY_ID_FILE",
        )?,
        r2_secret_access_key: env_secret_or_file(
            "CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY",
            "CLOUDFLARE_MCP_R2_SECRET_ACCESS_KEY_FILE",
        )?,
        r2_endpoint: env_optional_string("CLOUDFLARE_MCP_R2_ENDPOINT"),
        default_account_id: env_optional_string("CLOUDFLARE_MCP_DEFAULT_ACCOUNT_ID"),
        default_zone_id: env_optional_string("CLOUDFLARE_MCP_DEFAULT_ZONE_ID"),
        request_timeout: Duration::from_millis(env_u64("CLOUDFLARE_MCP_API_TIMEOUT_MS", 15_000)?),
        max_retries: env_u32("CLOUDFLARE_MCP_API_MAX_RETRIES", 2)?,
        retry_base_delay: Duration::from_millis(env_u64(
            "CLOUDFLARE_MCP_API_RETRY_BASE_DELAY_MS",
            150,
        )?),
        retry_max_delay: Duration::from_millis(env_u64(
            "CLOUDFLARE_MCP_API_RETRY_MAX_DELAY_MS",
            1_200,
        )?),
        user_agent: env_setting("CLOUDFLARE_MCP_API_USER_AGENT", "cloudflare-mcp/0.1.0"),
    };

    validate_url(
        "CLOUDFLARE_MCP_API_BASE_URL",
        Some(&cloudflare.api_base_url),
    )?;
    validate_url(
        "CLOUDFLARE_MCP_R2_ENDPOINT",
        cloudflare.r2_endpoint.as_deref(),
    )?;
    let portal_agent = load_portal_agent_config()?;

    Ok(Config {
        bind_addr,
        allow_non_loopback,
        allowed_hosts,
        read_only_mode,
        api_parity_enabled,
        elicitation,
        streamable_http,
        auth_mode,
        auth_resource_server_mode,
        auth_optional_loopback,
        auth_realm,
        auth_resource_url,
        auth_issuer,
        auth_scopes_supported: if auth_scopes_supported.is_empty() {
            auth_config.required_scopes.clone()
        } else {
            auth_scopes_supported
        },
        auth_allowed_client_ids: env_csv("CLOUDFLARE_MCP_AUTH_ALLOWED_CLIENT_IDS", ""),
        auth_config,
        cloudflare,
        portal_agent,
    })
}

fn load_portal_agent_config() -> Result<PortalAgentConfig, String> {
    let allowed_url_prefixes = env_csv(
        "CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES",
        "https://example.com/api/agent/",
    );
    if allowed_url_prefixes.is_empty() {
        return Err(
            "CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES must include at least one HTTPS URL prefix."
                .to_string(),
        );
    }
    for prefix in &allowed_url_prefixes {
        validate_url("CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES", Some(prefix))?;
        let parsed = Url::parse(prefix)
            .map_err(|err| format!("Invalid CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES: {err}"))?;
        if parsed.scheme() != "https" {
            return Err(
                "CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES entries must use https.".to_string(),
            );
        }
    }

    let agent_token = env_secret_or_file(
        "CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN",
        "CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN_FILE",
    )?
    .or(env_secret_or_file(
        "AGENT_API_TOKEN",
        "AGENT_API_TOKEN_FILE",
    )?);

    Ok(PortalAgentConfig {
        allowed_url_prefixes,
        agent_token,
        access_client_id: env_secret_or_file(
            "CLOUDFLARE_MCP_ACCESS_CLIENT_ID",
            "CLOUDFLARE_MCP_ACCESS_CLIENT_ID_FILE",
        )?,
        access_client_secret: env_secret_or_file(
            "CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET",
            "CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET_FILE",
        )?,
        request_timeout: Duration::from_millis(env_u64(
            "CLOUDFLARE_MCP_PORTAL_TIMEOUT_MS",
            15_000,
        )?),
        user_agent: env_setting("CLOUDFLARE_MCP_PORTAL_USER_AGENT", "cloudflare-mcp/0.1.0"),
    })
}

fn env_secret_or_file(value_key: &str, file_key: &str) -> Result<Option<String>, String> {
    if let Some(value) = env_optional_string(value_key) {
        return Ok(Some(value));
    }
    let Some(path) = env_optional_string(file_key) else {
        return Ok(None);
    };
    read_secret_file(file_key, Path::new(&path))
}

fn read_secret_file(file_key: &str, path: &Path) -> Result<Option<String>, String> {
    validate_secret_file_permissions(file_key, path)?;
    let value =
        fs::read_to_string(path).map_err(|err| format!("Failed to read {file_key}: {err}"))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(format!("{file_key} points to an empty secret file."));
    }
    Ok(Some(value))
}

fn validate_secret_file_permissions(file_key: &str, path: &Path) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|err| format!("Failed to inspect {file_key}: {err}"))?;
    if !metadata.is_file() {
        return Err(format!("{file_key} must point to a regular file."));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{file_key} must point to a file readable only by the owner (mode 0600 or stricter)."
            ));
        }
    }
    Ok(())
}

fn load_elicitation_config() -> Result<ElicitationConfig, String> {
    let enabled = env_flag("CLOUDFLARE_MCP_ELICITATION_ENABLED", false)?;
    let required_tools = env_csv(
        "CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS",
        DEFAULT_ELICITATION_REQUIRED_TOOLS,
    );
    let apply_only = env_flag("CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY", true)?;
    let timeout_ms = env_i64(
        "CLOUDFLARE_MCP_ELICITATION_TIMEOUT_MS",
        DEFAULT_ELICITATION_TIMEOUT_MS,
    )?;
    let timeout = if timeout_ms <= 0 {
        None
    } else {
        Some(Duration::from_millis(timeout_ms as u64))
    };
    let fail_open_unsupported_client = env_flag(
        "CLOUDFLARE_MCP_ELICITATION_FAIL_OPEN_UNSUPPORTED_CLIENT",
        false,
    )?;
    let mut required_tools = normalize_tool_names(required_tools);
    if enabled {
        add_mandatory_elicitation_tools(&mut required_tools);
    }
    if enabled && required_tools.is_empty() {
        return Err(
            "CLOUDFLARE_MCP_ELICITATION_ENABLED=1 requires at least one mutating tool in CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS."
                .to_string(),
        );
    }
    validate_elicitation_required_tools(&required_tools)?;

    Ok(ElicitationConfig {
        enabled,
        required_tools,
        apply_only,
        timeout,
        fail_open_unsupported_client,
    })
}

fn normalize_tool_names(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let canonical = trimmed.to_string();
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }
    normalized
}

fn add_mandatory_elicitation_tools(required_tools: &mut Vec<String>) {
    for tool in MANDATORY_ELICITATION_REQUIRED_TOOLS {
        if !required_tools.iter().any(|value| value == tool) {
            required_tools.push((*tool).to_string());
        }
    }
}

fn validate_elicitation_required_tools(required_tools: &[String]) -> Result<(), String> {
    if required_tools.is_empty() {
        return Ok(());
    }

    let validation =
        crate::tool_surface::validate_mutating_tool_subset(required_tools).map_err(|err| {
            format!("Failed to validate CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS: {err}")
        })?;
    if !validation.unknown.is_empty() {
        return Err(format!(
            "Unknown tools in CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS: {}",
            validation.unknown.join(", ")
        ));
    }
    if !validation.read_only.is_empty() {
        return Err(format!(
            "CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS must include only mutating tools; read-only entries found: {}",
            validation.read_only.join(", ")
        ));
    }

    Ok(())
}

fn apply_delegation_secret_policy(
    auth_mode: Option<AuthMode>,
    bind_addr: &str,
    auth_config: &mut AuthConfig,
) -> Result<(), String> {
    if !matches!(auth_mode, Some(AuthMode::Delegation)) {
        return Ok(());
    }
    if auth_config.delegation_secret.is_some() {
        return Ok(());
    }

    let allow_insecure_dev_secret = env_flag(AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET, false)?;
    if allow_insecure_dev_secret && bind_addr_is_loopback(bind_addr) {
        auth_config.delegation_secret = Some(INSECURE_DEV_DELEGATION_SECRET.to_string());
        return Ok(());
    }

    Err(format!(
        "CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET is required when CLOUDFLARE_MCP_AUTH_MODE=delegation. \
Set {AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET}=1 only for loopback-only local development."
    ))
}

fn bind_addr_is_loopback(bind_addr: &str) -> bool {
    if let Ok(addr) = bind_addr.parse::<SocketAddr>() {
        return addr.ip().is_loopback();
    }
    let Some((host, _)) = bind_addr.rsplit_once(':') else {
        return false;
    };
    matches!(
        host.trim().trim_matches(['[', ']']),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn load_streamable_http_config() -> Result<StreamableHttpConfig, String> {
    let resume_raw = env_setting("CLOUDFLARE_MCP_HTTP_RESUME_MODE", "historyless")
        .trim()
        .to_lowercase();
    let resume_mode = match resume_raw.as_str() {
        "" | "0" | "false" | "off" | "none" => ResumeMode::Off,
        "historyless" | "history-less" | "no-history" | "nohistory" => ResumeMode::Historyless,
        _ => {
            return Err(format!(
                "Unsupported CLOUDFLARE_MCP_HTTP_RESUME_MODE={resume_raw:?}; use 'historyless' or 'off'."
            ));
        }
    };

    let max_streams = env_usize("CLOUDFLARE_MCP_HTTP_MAX_STREAMS", 200)?;
    let max_events = env_usize("CLOUDFLARE_MCP_HTTP_MAX_EVENTS", 200)?;

    let session_keep_alive_s = env_i64("CLOUDFLARE_MCP_HTTP_SESSION_KEEP_ALIVE_S", 0)?;
    let session_keep_alive = if session_keep_alive_s <= 0 {
        None
    } else {
        Some(Duration::from_secs(session_keep_alive_s as u64))
    };
    let session_lifecycle_mode = parse_session_lifecycle_mode(&env_setting(
        "CLOUDFLARE_MCP_HTTP_SESSION_LIFECYCLE_MODE",
        "legacy",
    ))?;
    let disconnected_idle_timeout_s = env_i64(
        "CLOUDFLARE_MCP_HTTP_SESSION_DISCONNECTED_IDLE_TIMEOUT_S",
        7200,
    )?;
    let session_disconnected_idle_timeout = if disconnected_idle_timeout_s <= 0 {
        None
    } else {
        Some(Duration::from_secs(disconnected_idle_timeout_s as u64))
    };

    let retry_ms = env_i64("CLOUDFLARE_MCP_HTTP_RETRY_INTERVAL_MS", 0)?;
    let retry_interval = if resume_mode.resume_enabled() && retry_ms > 0 {
        Some(Duration::from_millis(retry_ms as u64))
    } else {
        None
    };

    let stateless_fallback = env_flag("CLOUDFLARE_MCP_HTTP_STATELESS_FALLBACK", true)?;

    Ok(StreamableHttpConfig {
        resume_mode,
        max_streams,
        max_events,
        session_keep_alive,
        session_lifecycle_mode,
        session_disconnected_idle_timeout,
        retry_interval,
        stateless_fallback,
    })
}

fn parse_auth_mode(value: &str) -> Result<Option<AuthMode>, String> {
    match value.trim().to_lowercase().as_str() {
        "" | "0" | "false" | "off" | "none" | "disabled" => Ok(None),
        "resource_server" | "resource-server" => Ok(Some(AuthMode::Jwks)),
        "jwks" => Ok(Some(AuthMode::Jwks)),
        "introspection" => Ok(Some(AuthMode::Introspection)),
        "delegation" => Ok(Some(AuthMode::Delegation)),
        _ => Err(format!(
            "Unsupported CLOUDFLARE_MCP_AUTH_MODE={value:?}; use resource_server, jwks, introspection, delegation, or off."
        )),
    }
}

fn parse_api_token_source(value: &str) -> Result<ApiTokenSource, String> {
    match value.trim().to_lowercase().as_str() {
        "" | "config" | "env" | "static" => Ok(ApiTokenSource::Config),
        "header" | "request_header" => Ok(ApiTokenSource::Header),
        "header_or_config" | "request_header_or_config" => Ok(ApiTokenSource::HeaderOrConfig),
        _ => Err(format!(
            "Unsupported CLOUDFLARE_MCP_API_TOKEN_SOURCE={value:?}; use config, header, or header_or_config."
        )),
    }
}

fn parse_auth_method(value: &str) -> Result<ClientAuthMethod, String> {
    match value.trim().to_lowercase().as_str() {
        "client_secret_basic" | "basic" => Ok(ClientAuthMethod::ClientSecretBasic),
        "client_secret_post" | "post" => Ok(ClientAuthMethod::ClientSecretPost),
        _ => Err(format!(
            "Unsupported CLOUDFLARE_MCP_AUTH_INTROSPECTION_AUTH_METHOD={value:?}."
        )),
    }
}

fn parse_session_lifecycle_mode(value: &str) -> Result<SessionLifecycleMode, String> {
    match value.trim().to_lowercase().as_str() {
        "legacy" => Ok(SessionLifecycleMode::Legacy),
        "connected" => Ok(SessionLifecycleMode::Connected),
        _ => Err(format!(
            "Unsupported CLOUDFLARE_MCP_HTTP_SESSION_LIFECYCLE_MODE={value:?}; use legacy or connected."
        )),
    }
}

fn validate_url(field: &str, value: Option<&str>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    Url::parse(value).map_err(|err| {
        let mut message = String::from("Invalid ");
        message.push_str(field);
        message.push_str(": ");
        message.push_str(&err.to_string());
        message
    })?;
    Ok(())
}

fn canonical_auth_resource_url(
    bind_addr: &str,
    auth_resource_url: Option<&str>,
) -> Result<String, String> {
    let value = auth_resource_url.map(str::to_string).unwrap_or_else(|| {
        let mut value = String::from("http://");
        value.push_str(bind_addr);
        value.push_str("/mcp");
        value
    });
    let mut parsed = Url::parse(&value).map_err(|err| {
        let mut message =
            String::from("Failed to derive canonical auth audience from resource URL ");
        message.push('"');
        message.push_str(&value);
        message.push('"');
        message.push_str(": ");
        message.push_str(&err.to_string());
        message
    })?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let mut canonical = parsed.to_string();
    while canonical.ends_with('/') {
        canonical.pop();
    }
    Ok(canonical)
}

fn env_setting(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_optional_string(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

fn env_csv(key: &str, default: &str) -> Vec<String> {
    let raw = env::var(key).unwrap_or_else(|_| default.to_string());
    raw.split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn env_flag(key: &str, default: bool) -> Result<bool, String> {
    match env::var(key) {
        Ok(raw) => match raw.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            "" => Ok(default),
            _ => Err(format!("Invalid boolean for {key}: {raw}")),
        },
        Err(_) => Ok(default),
    }
}

fn env_usize(key: &str, default: usize) -> Result<usize, String> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<usize>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

fn env_i64(key: &str, default: i64) -> Result<i64, String> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<i64>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

fn env_u32(key: &str, default: u32) -> Result<u32, String> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u32>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

fn env_u64(key: &str, default: u64) -> Result<u64, String> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u64>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

fn env_f64(key: &str, default: f64) -> Result<f64, String> {
    match env::var(key) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<f64>()
            .map_err(|err| format!("Invalid {key}: {err}")),
        _ => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::{load_config, load_config_with_auth_default};
    use mcp_toolkit_auth::AuthMode;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_env<R, F>(overrides: &[(&str, Option<&str>)], run: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = env_lock().lock().expect("env lock poisoned");
        let mut previous = BTreeMap::new();
        for (key, _) in overrides {
            previous.insert((*key).to_string(), std::env::var(key).ok());
        }

        for (key, value) in overrides {
            match value {
                Some(value) => {
                    // SAFETY: test-only helper serializes env mutation with a process-global mutex.
                    unsafe { std::env::set_var(key, value) };
                }
                None => {
                    // SAFETY: test-only helper serializes env mutation with a process-global mutex.
                    unsafe { std::env::remove_var(key) };
                }
            }
        }

        let result = run();

        for (key, value) in previous {
            match value {
                Some(value) => {
                    // SAFETY: test-only helper serializes env mutation with a process-global mutex.
                    unsafe { std::env::set_var(&key, value) };
                }
                None => {
                    // SAFETY: test-only helper serializes env mutation with a process-global mutex.
                    unsafe { std::env::remove_var(&key) };
                }
            }
        }

        result
    }

    fn temp_secret_file(name: &str, contents: &str, mode: u32) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cloudflare-mcp-{name}-{}-{stamp}.secret",
            std::process::id()
        ));
        fs::write(&path, contents).expect("write secret file");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set secret file permissions");
        path
    }

    fn fixture_material(label: &str) -> String {
        let mut value = String::from("fixture-");
        value.push_str(label);
        value.push_str("-value");
        value
    }

    #[test]
    fn defaults_to_delegation_auth_mode() {
        let material = fixture_material("delegation");
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", None),
                (
                    "CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET",
                    Some(material.as_str()),
                ),
            ],
            || load_config().expect("load config"),
        );
        assert!(cfg.auth_mode.is_some());
        assert!(!cfg.auth_resource_server_mode);
        assert_eq!(cfg.auth_realm, "cloudflare-mcp");
        assert_eq!(cfg.bind_addr, "127.0.0.1:9501");
    }

    #[test]
    fn supports_turning_auth_off() {
        let cfg = with_env(&[("CLOUDFLARE_MCP_AUTH_MODE", Some("off"))], || {
            load_config().expect("load config")
        });
        assert!(cfg.auth_mode.is_none());
        assert!(!cfg.auth_resource_server_mode);
    }

    #[test]
    fn supports_curated_only_api_parity_switch() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_API_PARITY_ENABLED", Some("0")),
            ],
            || load_config().expect("load config"),
        );
        assert!(!cfg.api_parity_enabled);
    }

    #[test]
    fn supports_auth_mode_default_override() {
        let cfg = with_env(&[("CLOUDFLARE_MCP_AUTH_MODE", None)], || {
            load_config_with_auth_default("off").expect("load config")
        });
        assert!(cfg.auth_mode.is_none());
        assert!(!cfg.auth_resource_server_mode);
    }

    #[test]
    fn resource_server_mode_maps_to_jwks_mode() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("resource_server")),
                (
                    "CLOUDFLARE_MCP_AUTH_ISSUER",
                    Some("https://issuer.example.com"),
                ),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(cfg.auth_mode, Some(AuthMode::Jwks));
        assert!(cfg.auth_resource_server_mode);
    }

    #[test]
    fn derives_auth_audience_from_resource_url_when_missing() {
        let material = fixture_material("delegation");
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("delegation")),
                (
                    "CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET",
                    Some(material.as_str()),
                ),
                ("CLOUDFLARE_MCP_AUTH_AUDIENCE", None),
                (
                    "CLOUDFLARE_MCP_AUTH_RESOURCE_URL",
                    Some("https://mcp.example.com/mcp"),
                ),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(
            cfg.auth_config.audience.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
    }

    #[test]
    fn jwks_mode_requires_issuer() {
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("jwks")),
                ("CLOUDFLARE_MCP_AUTH_ISSUER", None),
                (
                    "CLOUDFLARE_MCP_AUTH_JWKS_URL",
                    Some("https://issuer.example.com/jwks"),
                ),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("CLOUDFLARE_MCP_AUTH_ISSUER is required"));
    }

    #[test]
    fn parses_header_based_api_token_source() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_API_TOKEN_SOURCE", Some("header_or_config")),
                (
                    "CLOUDFLARE_MCP_API_TOKEN_HEADER",
                    Some("x-cloudflare-api-token"),
                ),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(
            cfg.cloudflare.api_token_source,
            super::ApiTokenSource::HeaderOrConfig
        );
        assert_eq!(cfg.cloudflare.api_token_header, "x-cloudflare-api-token");
    }

    #[test]
    fn parses_cloudflare_retry_configuration() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_API_MAX_RETRIES", Some("5")),
                ("CLOUDFLARE_MCP_API_RETRY_BASE_DELAY_MS", Some("50")),
                ("CLOUDFLARE_MCP_API_RETRY_MAX_DELAY_MS", Some("400")),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(cfg.cloudflare.max_retries, 5);
        assert_eq!(cfg.cloudflare.retry_base_delay.as_millis(), 50);
        assert_eq!(cfg.cloudflare.retry_max_delay.as_millis(), 400);
    }

    #[test]
    fn parses_portal_agent_configuration_without_exposing_secret_debug() {
        let agent_material = fixture_material("portal-agent");
        let access_material = fixture_material("access-material");
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                (
                    "CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES",
                    Some("https://staff.example.com/api/agent/"),
                ),
                (
                    "CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN",
                    Some(agent_material.as_str()),
                ),
                ("CLOUDFLARE_MCP_ACCESS_CLIENT_ID", Some("access-id")),
                (
                    "CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET",
                    Some(access_material.as_str()),
                ),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(
            cfg.portal_agent.allowed_url_prefixes,
            vec!["https://staff.example.com/api/agent/".to_string()]
        );
        assert_eq!(
            cfg.portal_agent.agent_token.as_deref(),
            Some(agent_material.as_str())
        );
        let debug = format!("{:?}", cfg.portal_agent);
        assert!(debug.contains("has_agent_token"));
        assert!(!debug.contains(agent_material.as_str()));
        assert!(!debug.contains(access_material.as_str()));
    }

    #[test]
    fn loads_portal_agent_credentials_from_protected_files() {
        let agent_material = fixture_material("file-agent");
        let access_id_material = fixture_material("file-access-id");
        let access_material = fixture_material("file-access-material");
        let agent_token = temp_secret_file("agent-token", &(agent_material.clone() + "\n"), 0o600);
        let access_id = temp_secret_file("access-id", &(access_id_material.clone() + "\n"), 0o600);
        let access_secret =
            temp_secret_file("access-material", &(access_material.clone() + "\n"), 0o600);

        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN", None),
                ("AGENT_API_TOKEN", None),
                (
                    "CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN_FILE",
                    Some(agent_token.to_str().expect("utf8 path")),
                ),
                ("CLOUDFLARE_MCP_ACCESS_CLIENT_ID", None),
                (
                    "CLOUDFLARE_MCP_ACCESS_CLIENT_ID_FILE",
                    Some(access_id.to_str().expect("utf8 path")),
                ),
                ("CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET", None),
                (
                    "CLOUDFLARE_MCP_ACCESS_CLIENT_SECRET_FILE",
                    Some(access_secret.to_str().expect("utf8 path")),
                ),
            ],
            || load_config().expect("load config"),
        );

        assert_eq!(
            cfg.portal_agent.agent_token.as_deref(),
            Some(agent_material.as_str())
        );
        assert_eq!(
            cfg.portal_agent.access_client_id.as_deref(),
            Some(access_id_material.as_str())
        );
        assert_eq!(
            cfg.portal_agent.access_client_secret.as_deref(),
            Some(access_material.as_str())
        );

        fs::remove_file(agent_token).ok();
        fs::remove_file(access_id).ok();
        fs::remove_file(access_secret).ok();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_portal_agent_secret_files_readable_by_group_or_world() {
        let agent_material = fixture_material("loose-agent");
        let agent_token = temp_secret_file("loose-agent-token", &(agent_material + "\n"), 0o644);
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN", None),
                ("AGENT_API_TOKEN", None),
                (
                    "CLOUDFLARE_MCP_PORTAL_AGENT_TOKEN_FILE",
                    Some(agent_token.to_str().expect("utf8 path")),
                ),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("0600 or stricter"));
        fs::remove_file(agent_token).ok();
    }

    #[test]
    fn rejects_plaintext_portal_agent_prefixes() {
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                (
                    "CLOUDFLARE_MCP_PORTAL_ALLOWED_URL_PREFIXES",
                    Some("http://staff.example.com/api/agent/"),
                ),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("must use https"));
    }

    #[test]
    fn supports_read_only_mode() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_READ_ONLY", Some("1")),
            ],
            || load_config().expect("load config"),
        );
        assert!(cfg.read_only_mode);
    }

    #[test]
    fn parses_elicitation_configuration() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_ELICITATION_ENABLED", Some("1")),
                (
                    "CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS",
                    Some("lock_first_publish,emergency_unpublish,lock_first_publish"),
                ),
                ("CLOUDFLARE_MCP_ELICITATION_APPLY_ONLY", Some("0")),
                ("CLOUDFLARE_MCP_ELICITATION_TIMEOUT_MS", Some("15000")),
                (
                    "CLOUDFLARE_MCP_ELICITATION_FAIL_OPEN_UNSUPPORTED_CLIENT",
                    Some("1"),
                ),
            ],
            || load_config().expect("load config"),
        );
        assert!(cfg.elicitation.enabled);
        assert_eq!(
            cfg.elicitation.required_tools,
            vec![
                "lock_first_publish".to_string(),
                "emergency_unpublish".to_string(),
                "account_api_tokens".to_string(),
                "api_mutate".to_string()
            ]
        );
        assert!(!cfg.elicitation.apply_only);
        assert_eq!(
            cfg.elicitation.timeout.map(|value| value.as_millis()),
            Some(15_000)
        );
        assert!(cfg.elicitation.fail_open_unsupported_client);
    }

    #[test]
    fn enabled_elicitation_with_empty_required_tools_adds_mandatory_tools() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_ELICITATION_ENABLED", Some("1")),
                ("CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS", Some("")),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(
            cfg.elicitation.required_tools,
            vec!["account_api_tokens".to_string(), "api_mutate".to_string()]
        );
    }

    #[test]
    fn enabled_elicitation_default_gates_dangerous_tools() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_ELICITATION_ENABLED", Some("1")),
                ("CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS", None),
            ],
            || load_config().expect("load config"),
        );
        for tool in [
            "account_api_tokens",
            "api_mutate",
            "lock_first_publish",
            "emergency_unpublish",
            "replace_access_policies",
            "apply_access_allowlist",
            "portal_agent_request",
            "cache_purge",
            "cache_rules",
            "r2_put_object",
            "workers_upload_script",
        ] {
            assert!(
                cfg.elicitation
                    .required_tools
                    .iter()
                    .any(|required| required == tool),
                "missing default elicitation gate for {tool}"
            );
        }
    }

    #[test]
    fn rejects_unknown_elicitation_required_tools() {
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                (
                    "CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS",
                    Some("unknown_tool"),
                ),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("Unknown tools"));
        assert!(err.contains("unknown_tool"));
    }

    #[test]
    fn rejects_read_only_elicitation_required_tools() {
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                (
                    "CLOUDFLARE_MCP_ELICITATION_REQUIRED_TOOLS",
                    Some("list_tunnels"),
                ),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("must include only mutating tools"));
        assert!(err.contains("list_tunnels"));
    }

    #[test]
    fn defaults_elicitation_timeout_to_finite_window() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("off")),
                ("CLOUDFLARE_MCP_ELICITATION_ENABLED", Some("1")),
                ("CLOUDFLARE_MCP_ELICITATION_TIMEOUT_MS", None),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(
            cfg.elicitation.timeout.map(|value| value.as_millis()),
            Some(30_000)
        );
    }

    #[test]
    fn delegation_auth_mode_requires_secret_by_default() {
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("delegation")),
                ("CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET", None),
                (
                    "CLOUDFLARE_MCP_AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET",
                    None,
                ),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET is required"));
    }

    #[test]
    fn loopback_can_opt_into_insecure_dev_delegation_secret() {
        let cfg = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("delegation")),
                ("CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET", None),
                (
                    "CLOUDFLARE_MCP_AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET",
                    Some("1"),
                ),
                ("CLOUDFLARE_MCP_BIND_ADDR", Some("127.0.0.1:9501")),
            ],
            || load_config().expect("load config"),
        );
        assert_eq!(
            cfg.auth_config.delegation_secret.as_deref(),
            Some(super::INSECURE_DEV_DELEGATION_SECRET)
        );
    }

    #[test]
    fn insecure_dev_delegation_secret_rejected_on_non_loopback_bind() {
        let err = with_env(
            &[
                ("CLOUDFLARE_MCP_AUTH_MODE", Some("delegation")),
                ("CLOUDFLARE_MCP_AUTH_DELEGATION_SECRET", None),
                (
                    "CLOUDFLARE_MCP_AUTH_ALLOW_INSECURE_DEV_DELEGATION_SECRET",
                    Some("1"),
                ),
                ("CLOUDFLARE_MCP_BIND_ADDR", Some("0.0.0.0:9501")),
            ],
            || load_config().expect_err("expected config failure"),
        );
        assert!(err.contains("loopback-only local development"));
    }
}
