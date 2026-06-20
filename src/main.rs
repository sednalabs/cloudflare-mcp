use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::State;
use axum::http::{
    HeaderMap, Method, Request, StatusCode,
    uri::{PathAndQuery, Uri},
};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use mcp_toolkit_auth::surface::{AuthSurfaceConfig, AuthSurfaceLayer, IssuerEntry};
use mcp_toolkit_auth::{AuthConfig, Authenticator, discover_oidc_metadata};
use mcp_toolkit_core::notifications::ToolListTracker;
use mcp_toolkit_http::host::validate_host_header;
use mcp_toolkit_http::session::{
    BoundedSessionManager, RecordingSessionManager, SessionLifecycleConfig,
    SessionLifecycleMode as ToolkitSessionLifecycleMode,
};
use mcp_toolkit_observability::sanitize_error_message;
use rmcp::serve_server;
use rmcp::transport::common::http_header::{HEADER_LAST_EVENT_ID, HEADER_SESSION_ID};
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
    session::SessionManager,
    session::local::{LocalSessionManager, SessionConfig},
};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use url::Url;

use cloudflare_mcp::cloudflare::CloudflareClient;
use cloudflare_mcp::config::{
    Config, SessionLifecycleMode, load_config, load_config_with_auth_default,
};
use cloudflare_mcp::portal::PortalAgentClient;
use cloudflare_mcp::server::CloudflareMcp;

#[derive(Clone)]
struct AppState {
    allowed_hosts: HashSet<String>,
    session_manager: Arc<BoundedSessionManager>,
    service: StreamableHttpService<CloudflareMcp, RecordingSessionManager>,
    stateless_service: Option<StreamableHttpService<CloudflareMcp, RecordingSessionManager>>,
    auth_enabled: bool,
    read_only_mode: bool,
    api_parity_enabled: bool,
    elicitation_enabled: bool,
    elicitation_apply_only: bool,
    elicitation_required_tools: Vec<String>,
    has_api_token: bool,
    api_token_source: String,
    api_token_header: String,
    default_account_id: Option<String>,
    default_zone_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeAttestation {
    component: &'static str,
    version: &'static str,
    parity_target: &'static str,
    non_goal: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeTransport {
    Http,
    Stdio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeOptions {
    transport: RuntimeTransport,
    print_tools: bool,
    help: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            transport: RuntimeTransport::Http,
            print_tools: false,
            help: false,
        }
    }
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.session_manager.stats().await;
    Json(json!({
        "status": "ok",
        "auth_enabled": state.auth_enabled,
        "read_only_mode": state.read_only_mode,
        "api_parity_enabled": state.api_parity_enabled,
        "elicitation": {
            "enabled": state.elicitation_enabled,
            "apply_only": state.elicitation_apply_only,
            "required_tools": state.elicitation_required_tools,
        },
        "cloudflare": {
            "has_api_token": state.has_api_token,
            "api_token_source": state.api_token_source,
            "api_token_header": state.api_token_header,
            "default_account_id": state.default_account_id,
            "default_zone_id": state.default_zone_id,
        },
        "session": {
            "active_sessions": stats.active_sessions,
            "max_sessions": stats.max_sessions,
            "resume_enabled": stats.resume_enabled,
            "lifecycle_mode": lifecycle_mode_label(stats.lifecycle_mode),
            "lifecycle_connected_streams": stats.lifecycle_connected_streams,
            "lifecycle_disconnected_sessions": stats.lifecycle_disconnected_sessions,
            "lifecycle_expired_sessions_total": stats.lifecycle_expired_sessions_total,
        }
    }))
}

async fn attest() -> impl IntoResponse {
    let attest = RuntimeAttestation {
        component: "cloudflare-mcp",
        version: env!("CARGO_PKG_VERSION"),
        parity_target: "cloudflared",
        non_goal: "third-party cloudflare mcp ecosystem parity",
    };
    Json(json!({
        "component": attest.component,
        "version": attest.version,
        "parity_target": attest.parity_target,
        "non_goal": attest.non_goal,
        "verification": {
            "provenance": "verify_http_gate",
            "status_resource": "cloudflare-mcp://adapter-status",
        }
    }))
}

fn lifecycle_mode_label(mode: ToolkitSessionLifecycleMode) -> &'static str {
    match mode {
        ToolkitSessionLifecycleMode::LegacyKeepAlive => "legacy_keep_alive",
        ToolkitSessionLifecycleMode::ConnectedUnboundedDisconnectedIdle => {
            "connected_unbounded_disconnected_idle"
        }
    }
}

async fn host_guard(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if let Err(err) = validate_host_header(req.headers(), &state.allowed_hosts) {
        let status = err.status_code();
        let message = err.message();
        return Response::builder()
            .status(status)
            .body(Body::from(message))
            .unwrap_or_else(|_| Response::new(Body::from(message)));
    }

    next.run(req).await
}

async fn trim_trailing_slash(req: axum::extract::Request, next: Next) -> Response {
    let mut req = req;
    let path = req.uri().path();
    if path.len() > 1 && path.ends_with('/') {
        let trimmed_path = path.trim_end_matches('/').to_string();
        let query = req.uri().query().map(|q| q.to_string());
        let normalized = match query {
            Some(query) if !query.is_empty() => format!("{trimmed_path}?{query}"),
            _ => trimmed_path,
        };
        if let Ok(path_and_query) = normalized.parse::<PathAndQuery>() {
            let mut parts = req.uri().clone().into_parts();
            parts.path_and_query = Some(path_and_query);
            if let Ok(uri) = Uri::from_parts(parts) {
                *req.uri_mut() = uri;
            }
        }
    }
    next.run(req).await
}

fn public_base_url_from_bind_addr(bind_addr: &SocketAddr) -> String {
    format!("http://{bind_addr}")
}

fn public_base_url_from_resource_url(resource_url: &str) -> Result<Option<String>, String> {
    let mut parsed =
        Url::parse(resource_url).map_err(|err| format!("invalid auth resource URL: {err}"))?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let path = parsed.path().trim_end_matches('/').to_string();
    let Some(prefix) = path.strip_suffix("/mcp") else {
        return Ok(None);
    };
    if prefix.is_empty() {
        parsed.set_path("/");
    } else {
        parsed.set_path(prefix);
    }
    let mut value = parsed.to_string();
    while value.ends_with('/') {
        value.pop();
    }
    Ok(Some(value))
}

fn fallback_oauth_endpoints(issuer: &str) -> (String, String) {
    let trimmed = issuer.trim_end_matches('/');
    if trimmed.contains("/realms/") {
        return (
            format!("{trimmed}/protocol/openid-connect/auth"),
            format!("{trimmed}/protocol/openid-connect/token"),
        );
    }
    (
        format!("{trimmed}/oauth/authorize"),
        format!("{trimmed}/oauth/token"),
    )
}

fn url_uses_insecure_http(value: &str) -> bool {
    Url::parse(value)
        .map(|url| url.scheme() == "http")
        .unwrap_or(false)
}

fn auth_surface_allow_insecure_http(config: &AuthSurfaceConfig) -> bool {
    if url_uses_insecure_http(&config.public_base_url) {
        return true;
    }
    config.entries.iter().any(|entry| {
        url_uses_insecure_http(&entry.issuer)
            || url_uses_insecure_http(&entry.authorization_endpoint)
            || url_uses_insecure_http(&entry.token_endpoint)
            || entry
                .jwks_uri
                .as_deref()
                .map(url_uses_insecure_http)
                .unwrap_or(false)
            || entry
                .introspection_endpoint
                .as_deref()
                .map(url_uses_insecure_http)
                .unwrap_or(false)
            || entry
                .resource_url_override
                .as_deref()
                .map(url_uses_insecure_http)
                .unwrap_or(false)
    })
}

async fn build_auth_surface_layer(
    config: &Config,
    bind_addr: &SocketAddr,
    auth: Arc<Authenticator>,
) -> Result<AuthSurfaceLayer, String> {
    let optional_loopback = config.auth_optional_loopback && bind_addr.ip().is_loopback();

    let mut public_base_url = public_base_url_from_bind_addr(bind_addr);
    if let Some(resource_url) = config.auth_resource_url.as_deref() {
        match public_base_url_from_resource_url(resource_url)? {
            Some(derived) => public_base_url = derived,
            None => {
                tracing::warn!(
                    resource_url,
                    "CLOUDFLARE_MCP_AUTH_RESOURCE_URL does not end with /mcp; using bind address for auth surface base URL"
                );
            }
        }
    }

    let issuer = config
        .auth_issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| public_base_url.clone());

    let (default_authz, default_token) = fallback_oauth_endpoints(&issuer);
    let (
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        discovered_jwks_uri,
        discovered_introspection,
    ) = if config.auth_issuer.is_some() {
        match discover_oidc_metadata(&issuer, None).await {
            Ok(metadata) => (
                metadata
                    .authorization_endpoint
                    .unwrap_or_else(|| default_authz.clone()),
                metadata
                    .token_endpoint
                    .unwrap_or_else(|| default_token.clone()),
                metadata.registration_endpoint,
                Some(metadata.jwks_uri),
                metadata.introspection_endpoint,
            ),
            Err(err) => {
                tracing::warn!(
                    issuer,
                    err = %err,
                    "Failed OIDC discovery for auth surface; using fallback OAuth endpoint URLs"
                );
                (default_authz, default_token, None, None, None)
            }
        }
    } else {
        (default_authz, default_token, None, None, None)
    };

    let mcp_entry = IssuerEntry {
        resource_path: "/mcp".to_string(),
        issuer,
        authorization_endpoint,
        token_endpoint,
        registration_endpoint,
        jwks_uri: config.auth_config.jwks_url.clone().or(discovered_jwks_uri),
        introspection_endpoint: config
            .auth_config
            .introspection_url
            .clone()
            .or(discovered_introspection),
        device_authorization_endpoint: None,
        grant_types_supported: None,
        client_id_metadata_document_supported: None,
        token_endpoint_auth_methods_supported: None,
        code_challenge_methods_supported: None,
        realm: config.auth_realm.clone(),
        scopes_supported: config.auth_scopes_supported.clone(),
        allowed_client_ids: config.auth_allowed_client_ids.iter().cloned().collect(),
        authenticator: auth,
        resource_url_override: config.auth_resource_url.clone(),
    };

    let mut mcp_surface = AuthSurfaceConfig::single_issuer(public_base_url, mcp_entry);
    // Public endpoints by policy: health + attest should be reachable without auth.
    mcp_surface.public_paths.insert("/health".to_string());
    mcp_surface.public_paths.insert("/attest".to_string());
    if optional_loopback {
        mcp_surface.public_prefixes.push("/mcp".to_string());
    }
    mcp_surface.allow_insecure_http = auth_surface_allow_insecure_http(&mcp_surface);

    AuthSurfaceLayer::from_config(mcp_surface)
        .map_err(|err| format!("invalid auth surface config: {err}"))
}

async fn runtime_auth_config(config: &Config) -> Result<AuthConfig, String> {
    let mut auth_config = config.auth_config.clone();
    if !config.auth_resource_server_mode {
        return Ok(auth_config);
    }

    let issuer = config
        .auth_issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "CLOUDFLARE_MCP_AUTH_ISSUER is required for CLOUDFLARE_MCP_AUTH_MODE=resource_server."
                .to_string()
        })?;

    let metadata = discover_oidc_metadata(issuer, None).await.map_err(|err| {
        format!("resource-server OIDC discovery failed for issuer {issuer}: {err}")
    })?;
    if auth_config.jwks_url.is_none() {
        auth_config.jwks_url = Some(metadata.jwks_uri.clone());
    }
    if auth_config.issuer.is_none() {
        auth_config.issuer = metadata.issuer.clone().or_else(|| Some(issuer.to_string()));
    }
    tracing::info!(
        issuer,
        jwks_url = ?auth_config.jwks_url,
        introspection_url = ?auth_config.introspection_url,
        "OAuth resource-server mode configured from OIDC issuer metadata"
    );
    Ok(auth_config)
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_SESSION_ID)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn last_event_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_LAST_EVENT_ID)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_initialize_payload(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    match payload {
        serde_json::Value::Object(map) => map
            .get("method")
            .and_then(|value| value.as_str())
            .map(|method| method == "initialize")
            .unwrap_or(false),
        _ => false,
    }
}

async fn forward_service<M>(
    service: StreamableHttpService<CloudflareMcp, M>,
    req: Request<Body>,
) -> Response<Body>
where
    M: SessionManager,
{
    let response = service.handle(req).await;
    response.map(Body::new)
}

async fn session_exists(state: &AppState, session_id: &str) -> bool {
    state
        .session_manager
        .has_session(&session_id.into())
        .await
        .unwrap_or(false)
}

async fn handle_mcp(State(state): State<AppState>, req: Request<Body>) -> Response<Body> {
    let method = req.method().clone();
    let session_id = session_id_from_headers(req.headers());

    match method {
        Method::POST => {
            if let Some(session_id) = session_id.clone() {
                if session_exists(&state, &session_id).await {
                    return forward_service(state.service.clone(), req).await;
                }
                if let Some(stateless) = state.stateless_service.clone() {
                    return forward_service(stateless, req).await;
                }
                return session_error(
                    StatusCode::NOT_FOUND,
                    "Invalid or expired session ID.",
                    "Re-initialize with POST /mcp to obtain a new session id.",
                );
            }

            let (parts, body) = req.into_parts();
            let bytes = match axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return session_error(
                        StatusCode::BAD_REQUEST,
                        "Failed to read request body.",
                        "Retry the request.",
                    );
                }
            };
            if is_initialize_payload(&bytes) {
                let req = Request::from_parts(parts, Body::from(bytes));
                return forward_service(state.service.clone(), req).await;
            }
            if let Some(stateless) = state.stateless_service.clone() {
                let req = Request::from_parts(parts, Body::from(bytes));
                return forward_service(stateless, req).await;
            }
            session_error(
                StatusCode::BAD_REQUEST,
                "Missing session ID.",
                "Initialize with POST /mcp to obtain a session id.",
            )
        }
        Method::GET | Method::DELETE => {
            let Some(session_id) = session_id else {
                if matches!(method, Method::GET) && !state.auth_enabled {
                    return endpoint_ready_hint();
                }
                return session_error(
                    StatusCode::BAD_REQUEST,
                    "Missing session ID.",
                    "Initialize with POST /mcp to obtain a session id.",
                );
            };
            if !session_exists(&state, &session_id).await {
                if matches!(method, Method::GET) {
                    if let Some(_last_event_id) = last_event_id_from_headers(req.headers()) {
                        // historyless mode expects clients to reinitialize if session expired.
                    }
                }
                return session_error(
                    StatusCode::NOT_FOUND,
                    "Invalid or expired session ID.",
                    "Re-initialize with POST /mcp to obtain a new session id.",
                );
            }
            forward_service(state.service.clone(), req).await
        }
        _ => session_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed.",
            "Use POST /mcp to initialize, then reuse the session id for later requests.",
        ),
    }
}

fn session_error(status: StatusCode, message: &str, hint: &str) -> Response<Body> {
    let body = json!({
        "status": "error",
        "error": message,
        "hint": hint,
    });
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("{\"status\":\"error\"}")))
}

fn endpoint_ready_hint() -> Response<Body> {
    let body = json!({
        "status": "ok",
        "message": "MCP endpoint reachable.",
        "hint": "Initialize with POST /mcp to obtain a session id.",
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("{\"status\":\"ok\"}")))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

fn parse_runtime_options() -> Result<RuntimeOptions> {
    parse_runtime_options_from(std::env::args().skip(1))
}

fn parse_runtime_options_from<I, S>(args: I) -> Result<RuntimeOptions>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut options = RuntimeOptions::default();
    let mut args = args.into_iter().map(Into::into).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => options.help = true,
            "--print-tools" => options.print_tools = true,
            "--stdio" | "stdio" => options.transport = RuntimeTransport::Stdio,
            "--http" | "http" => options.transport = RuntimeTransport::Http,
            "--transport" => {
                let Some(value) = args.next() else {
                    return Err(anyhow!("--transport requires 'http' or 'stdio'"));
                };
                options.transport = parse_transport_mode(&value)?;
            }
            value if value.starts_with("--transport=") => {
                let value = value.trim_start_matches("--transport=");
                options.transport = parse_transport_mode(value)?;
            }
            _ => {}
        }
    }
    Ok(options)
}

fn parse_transport_mode(value: &str) -> Result<RuntimeTransport> {
    match value.trim().to_lowercase().as_str() {
        "http" | "streamable-http" | "streamable_http" => Ok(RuntimeTransport::Http),
        "stdio" => Ok(RuntimeTransport::Stdio),
        _ => Err(anyhow!(
            "unsupported transport {value:?}; use 'http' or 'stdio'"
        )),
    }
}

fn print_help() {
    println!(
        "\
cloudflare-mcp

Usage:
  cloudflare-mcp [--transport http|stdio] [--print-tools]
  cloudflare-mcp --stdio

Options:
  --transport http|stdio  Runtime transport. Defaults to http.
  --stdio                 Run as a JSON-RPC MCP server over stdin/stdout.
  --http                  Run the Streamable HTTP server on CLOUDFLARE_MCP_BIND_ADDR.
  --print-tools           Print registered tool names as JSON and exit.
  --help                  Show this help.
"
    );
}

fn build_router(state: AppState, auth_layer: Option<AuthSurfaceLayer>) -> Router {
    let base = Router::new()
        .route("/health", get(health))
        .route("/attest", get(attest))
        .route("/mcp", any(handle_mcp))
        .route("/mcp/", any(handle_mcp))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        .layer(middleware::from_fn(trim_trailing_slash))
        .with_state(state);

    if let Some(layer) = auth_layer {
        base.layer(layer)
    } else {
        base
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("cloudflare-mcp failed to start: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    init_tracing();
    let options = parse_runtime_options()?;
    if options.help {
        print_help();
        return Ok(());
    }

    let config = match options.transport {
        RuntimeTransport::Http => load_config(),
        RuntimeTransport::Stdio => load_config_with_auth_default("off"),
    }
    .map_err(|err| anyhow!(err))?;

    if options.print_tools {
        let server = build_cloudflare_server(&config, minimal_session_manager())?;
        println!("{}", serde_json::to_string_pretty(&server.tool_names())?);
        return Ok(());
    }

    match options.transport {
        RuntimeTransport::Http => run_http(config).await,
        RuntimeTransport::Stdio => run_stdio(config).await,
    }
}

async fn run_http(config: Config) -> Result<()> {
    let addr: SocketAddr = config
        .bind_addr
        .parse()
        .with_context(|| format!("invalid CLOUDFLARE_MCP_BIND_ADDR {}", config.bind_addr))?;
    if !config.allow_non_loopback && !addr.ip().is_loopback() {
        return Err(anyhow!(
            "non-loopback bind denied; set CLOUDFLARE_MCP_ALLOW_NON_LOOPBACK=1 to override"
        ));
    }
    if !addr.ip().is_loopback() && config.auth_mode.is_none() {
        return Err(anyhow!(
            "auth is disabled but bind address is non-loopback; enable auth or bind to loopback"
        ));
    }

    let allowed_hosts: HashSet<String> = config
        .allowed_hosts
        .iter()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .collect();

    log_runtime_posture(&config, RuntimeTransport::Http, Some(addr));

    let lifecycle_config = match config.streamable_http.session_lifecycle_mode {
        SessionLifecycleMode::Legacy => SessionLifecycleConfig::default(),
        SessionLifecycleMode::Connected => SessionLifecycleConfig::connected(
            config.streamable_http.session_disconnected_idle_timeout,
        ),
    };
    let enable_background_session_sweeper = matches!(
        config.streamable_http.session_lifecycle_mode,
        SessionLifecycleMode::Connected
    ) && config
        .streamable_http
        .session_disconnected_idle_timeout
        .is_some();

    let token = CancellationToken::new();
    let mut session_config = SessionConfig::default();
    session_config.channel_capacity = config.streamable_http.max_events;
    session_config.keep_alive = match config.streamable_http.session_lifecycle_mode {
        SessionLifecycleMode::Legacy => config.streamable_http.session_keep_alive,
        SessionLifecycleMode::Connected => None,
    };
    let session_manager = Arc::new(BoundedSessionManager::new_with_lifecycle(
        LocalSessionManager::default(),
        config.streamable_http.max_streams,
        config.streamable_http.resume_mode.resume_enabled(),
        session_config,
        lifecycle_config,
    ));

    let server_template = build_cloudflare_server(&config, session_manager.clone())?;

    let recording_session_manager =
        Arc::new(RecordingSessionManager::new(session_manager.clone(), None));

    let service = {
        let server_template = server_template.clone();
        StreamableHttpService::new(
            move || Ok::<CloudflareMcp, std::io::Error>(server_template.clone()),
            recording_session_manager.clone(),
            {
                let mut server_config = StreamableHttpServerConfig::default();
                server_config.sse_retry = config.streamable_http.retry_interval;
                server_config.cancellation_token = token.child_token();
                server_config
            },
        )
    };

    let stateless_service = if config.streamable_http.stateless_fallback {
        let server_template = server_template.clone();
        Some(StreamableHttpService::new(
            move || Ok::<CloudflareMcp, std::io::Error>(server_template.clone()),
            recording_session_manager.clone(),
            {
                let mut server_config = StreamableHttpServerConfig::default();
                server_config.sse_retry = None;
                server_config.stateful_mode = false;
                server_config.cancellation_token = token.child_token();
                server_config
            },
        ))
    } else {
        None
    };

    let state = AppState {
        allowed_hosts,
        session_manager,
        service,
        stateless_service,
        auth_enabled: config.auth_mode.is_some(),
        read_only_mode: config.read_only_mode,
        api_parity_enabled: config.api_parity_enabled,
        elicitation_enabled: config.elicitation.enabled,
        elicitation_apply_only: config.elicitation.apply_only,
        elicitation_required_tools: config.elicitation.required_tools.clone(),
        has_api_token: config.cloudflare.api_token.is_some(),
        api_token_source: config.cloudflare.api_token_source.as_str().to_string(),
        api_token_header: config.cloudflare.api_token_header.clone(),
        default_account_id: config.cloudflare.default_account_id.clone(),
        default_zone_id: config.cloudflare.default_zone_id.clone(),
    };

    if enable_background_session_sweeper {
        let sweep_token = token.child_token();
        let sweep_sessions = state.session_manager.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = sweep_token.cancelled() => break,
                    _ = ticker.tick() => {
                        sweep_sessions.sweep_expired_sessions().await;
                    }
                }
            }
        });
    }

    let auth_layer = if config.auth_mode.is_some() {
        let auth_config = runtime_auth_config(&config)
            .await
            .map_err(|err| anyhow!(sanitize_error_message(&err, 512)))?;
        let auth = Authenticator::new(auth_config).map_err(|err| {
            let err = sanitize_error_message(&err.to_string(), 512);
            anyhow!("invalid auth config: {err}")
        })?;
        let auth = Arc::new(auth);
        Some(
            build_auth_surface_layer(&config, &addr, auth)
                .await
                .map_err(|err| anyhow!(sanitize_error_message(&err, 512)))?,
        )
    } else {
        None
    };

    let router = build_router(state, auth_layer);

    tracing::info!(bind_addr = %config.bind_addr, "cloudflare-mcp listening");

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let shutdown_token = token.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        shutdown_token.cancel();
        shutdown_handle.graceful_shutdown(None);
    });

    axum_server::bind(addr)
        .handle(handle)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}

async fn run_stdio(config: Config) -> Result<()> {
    if config.auth_mode.is_some() {
        return Err(anyhow!(
            "stdio transport requires CLOUDFLARE_MCP_AUTH_MODE=off; stdio is process-local and does not expose HTTP bearer-auth endpoints"
        ));
    }
    log_runtime_posture(&config, RuntimeTransport::Stdio, None);

    let server = build_cloudflare_server(&config, minimal_session_manager())?;
    tracing::info!("cloudflare-mcp stdio transport ready");
    let transport = stdio();
    let service = serve_server(server, transport).await?;
    service.waiting().await?;
    Ok(())
}

fn minimal_session_manager() -> Arc<BoundedSessionManager> {
    let mut session_config = SessionConfig::default();
    session_config.channel_capacity = 8;
    session_config.keep_alive = None;
    Arc::new(BoundedSessionManager::new_with_lifecycle(
        LocalSessionManager::default(),
        1,
        false,
        session_config,
        SessionLifecycleConfig::default(),
    ))
}

fn build_cloudflare_server(
    config: &Config,
    session_manager: Arc<BoundedSessionManager>,
) -> Result<CloudflareMcp> {
    let cloudflare = Arc::new(CloudflareClient::new(config.cloudflare.clone())?);
    let portal_agent = Arc::new(PortalAgentClient::new(config.portal_agent.clone())?);
    let tool_list_tracker = Arc::new(ToolListTracker::default());
    Ok(CloudflareMcp::new(
        cloudflare,
        config.cloudflare.default_account_id.clone(),
        config.cloudflare.default_zone_id.clone(),
        config.cloudflare.api_token.is_some(),
        config.cloudflare.api_token_source,
        config.cloudflare.api_token_header.clone(),
        config.auth_mode.is_some(),
        config.read_only_mode,
        config.api_parity_enabled,
        portal_agent,
        config.elicitation.clone(),
        tool_list_tracker,
        session_manager,
        config.streamable_http.resume_mode,
    ))
}

fn log_runtime_posture(
    config: &Config,
    transport: RuntimeTransport,
    bind_addr: Option<SocketAddr>,
) {
    match transport {
        RuntimeTransport::Http => {
            if config.auth_mode.is_some() {
                tracing::info!(auth_mode = ?config.auth_mode, "OAuth authentication enabled");
                if config.auth_optional_loopback
                    && bind_addr
                        .map(|addr| addr.ip().is_loopback())
                        .unwrap_or(false)
                {
                    tracing::warn!(
                        "OAuth enforcement is disabled on loopback (CLOUDFLARE_MCP_AUTH_OPTIONAL_LOOPBACK=1)"
                    );
                }
            } else {
                tracing::warn!("OAuth authentication disabled (CLOUDFLARE_MCP_AUTH_MODE=off)");
            }
        }
        RuntimeTransport::Stdio => {
            tracing::info!("stdio transport selected; HTTP auth surface disabled");
        }
    }
    if config.read_only_mode {
        tracing::warn!("Read-only mode enabled (CLOUDFLARE_MCP_READ_ONLY=1)");
    }
    if config.elicitation.enabled {
        tracing::warn!(
            required_tools = ?config.elicitation.required_tools,
            apply_only = config.elicitation.apply_only,
            fail_open_unsupported_client = config.elicitation.fail_open_unsupported_client,
            "Dangerous-tool elicitation enabled"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header::AUTHORIZATION};
    use axum::routing::get;
    use axum::{Json, Router};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use mcp_toolkit_auth::{AuthConfig, AuthMode, Authenticator};
    use mcp_toolkit_core::notifications::ToolListTracker;
    use mcp_toolkit_http::session::{
        BoundedSessionManager, RecordingSessionManager, SessionLifecycleConfig,
    };
    use rmcp::transport::streamable_http_server::session::local::{
        LocalSessionManager, SessionConfig,
    };
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use serde_json::json;
    use tower::ServiceExt;

    use super::{
        AppState, RuntimeTransport, build_auth_surface_layer, build_router,
        fallback_oauth_endpoints, parse_runtime_options_from, runtime_auth_config,
    };
    use cloudflare_mcp::cloudflare::CloudflareClient;
    use cloudflare_mcp::config::{
        ApiTokenSource, CloudflareApiConfig, Config, ElicitationConfig, PortalAgentConfig,
        ResumeMode, SessionLifecycleMode, StreamableHttpConfig,
    };
    use cloudflare_mcp::portal::PortalAgentClient;
    use cloudflare_mcp::server::CloudflareMcp;

    fn make_delegation_token(secret: &str, issuer: &str, audience: &str) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs()
            + 300;
        let claims = json!({
            "exp": exp,
            "sub": "agent-test",
            "aud": audience,
            "iss": issuer,
            "jti": "test-jti-1"
        });
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("token")
    }

    fn fixture_material(label: &str) -> String {
        let mut value = String::from("fixture-");
        value.push_str(label);
        value.push_str("-value");
        value
    }

    fn test_config() -> Config {
        let mut auth_config = AuthConfig::default();
        auth_config.mode = AuthMode::Delegation;
        auth_config.delegation_secret = Some(fixture_material("delegation"));
        auth_config.delegation_issuer = "issuer.test".to_string();
        auth_config.delegation_audience = "audience.test".to_string();

        Config {
            bind_addr: "127.0.0.1:9520".to_string(),
            allow_non_loopback: false,
            allowed_hosts: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            read_only_mode: false,
            api_parity_enabled: true,
            elicitation: ElicitationConfig {
                enabled: false,
                required_tools: Vec::new(),
                apply_only: true,
                timeout: None,
                fail_open_unsupported_client: false,
            },
            streamable_http: StreamableHttpConfig {
                resume_mode: ResumeMode::Historyless,
                max_streams: 20,
                max_events: 32,
                session_keep_alive: None,
                session_lifecycle_mode: SessionLifecycleMode::Legacy,
                session_disconnected_idle_timeout: None,
                retry_interval: None,
                stateless_fallback: true,
            },
            auth_mode: Some(AuthMode::Delegation),
            auth_resource_server_mode: false,
            auth_optional_loopback: false,
            auth_realm: "cloudflare-mcp-test".to_string(),
            auth_resource_url: Some("http://127.0.0.1:9520/mcp".to_string()),
            auth_issuer: Some("https://issuer.test".to_string()),
            auth_scopes_supported: vec!["cloudflare:read".to_string()],
            auth_allowed_client_ids: Vec::new(),
            auth_config,
            cloudflare: CloudflareApiConfig {
                api_base_url: "http://127.0.0.1:9520".to_string(),
                api_token: Some(fixture_material("api")),
                api_token_source: ApiTokenSource::Config,
                api_token_header: "x-cloudflare-api-token".to_string(),
                r2_access_key_id: Some(fixture_material("r2-id")),
                r2_secret_access_key: Some(fixture_material("r2-material")),
                r2_endpoint: None,
                default_account_id: Some("acct-1".to_string()),
                default_zone_id: Some("zone-1".to_string()),
                request_timeout: Duration::from_secs(1),
                max_retries: 1,
                retry_base_delay: Duration::from_millis(1),
                retry_max_delay: Duration::from_millis(5),
                user_agent: "cloudflare-mcp-test".to_string(),
            },
            portal_agent: PortalAgentConfig {
                allowed_url_prefixes: vec!["https://staff.example.com/api/agent/".to_string()],
                agent_token: Some(fixture_material("portal-agent")),
                access_client_id: Some("access-client-id".to_string()),
                access_client_secret: Some(fixture_material("access-material")),
                request_timeout: Duration::from_secs(1),
                user_agent: "cloudflare-mcp-test".to_string(),
            },
        }
    }

    #[test]
    fn runtime_options_default_to_http() {
        let options = parse_runtime_options_from(Vec::<String>::new()).expect("options");
        assert_eq!(options.transport, RuntimeTransport::Http);
        assert!(!options.print_tools);
    }

    #[test]
    fn runtime_options_accept_stdio_shortcut() {
        let options = parse_runtime_options_from(["--stdio"]).expect("options");
        assert_eq!(options.transport, RuntimeTransport::Stdio);
    }

    #[test]
    fn runtime_options_accept_transport_value() {
        let options =
            parse_runtime_options_from(["--transport", "streamable-http", "--print-tools"])
                .expect("options");
        assert_eq!(options.transport, RuntimeTransport::Http);
        assert!(options.print_tools);
    }

    async fn test_router_with_auth(auth_enabled: bool) -> Router {
        let mut cfg = test_config();
        if !auth_enabled {
            cfg.auth_mode = None;
            cfg.auth_resource_server_mode = false;
        }
        let cloudflare = Arc::new(CloudflareClient::new(cfg.cloudflare.clone()).expect("client"));
        let session_manager = Arc::new(BoundedSessionManager::new_with_lifecycle(
            LocalSessionManager::default(),
            cfg.streamable_http.max_streams,
            cfg.streamable_http.resume_mode.resume_enabled(),
            {
                let mut session_config = SessionConfig::default();
                session_config.channel_capacity = cfg.streamable_http.max_events;
                session_config.keep_alive = cfg.streamable_http.session_keep_alive;
                session_config
            },
            SessionLifecycleConfig::default(),
        ));

        let tool_list_tracker = Arc::new(ToolListTracker::default());
        let portal_agent =
            Arc::new(PortalAgentClient::new(cfg.portal_agent.clone()).expect("portal client"));
        let server_template = CloudflareMcp::new(
            cloudflare,
            cfg.cloudflare.default_account_id.clone(),
            cfg.cloudflare.default_zone_id.clone(),
            true,
            ApiTokenSource::Config,
            "x-cloudflare-api-token".to_string(),
            auth_enabled,
            cfg.read_only_mode,
            cfg.api_parity_enabled,
            portal_agent,
            cfg.elicitation.clone(),
            tool_list_tracker,
            session_manager.clone(),
            cfg.streamable_http.resume_mode,
        );

        let recording_session_manager =
            Arc::new(RecordingSessionManager::new(session_manager.clone(), None));
        let service = {
            let server_template = server_template.clone();
            StreamableHttpService::new(
                move || Ok::<CloudflareMcp, std::io::Error>(server_template.clone()),
                recording_session_manager.clone(),
                StreamableHttpServerConfig::default(),
            )
        };
        let stateless_service = {
            let server_template = server_template.clone();
            Some(StreamableHttpService::new(
                move || Ok::<CloudflareMcp, std::io::Error>(server_template.clone()),
                recording_session_manager,
                {
                    let mut server_config = StreamableHttpServerConfig::default();
                    server_config.stateful_mode = false;
                    server_config
                },
            ))
        };

        let state = AppState {
            allowed_hosts: cfg.allowed_hosts.iter().cloned().collect(),
            session_manager,
            service,
            stateless_service,
            auth_enabled,
            read_only_mode: cfg.read_only_mode,
            api_parity_enabled: cfg.api_parity_enabled,
            elicitation_enabled: cfg.elicitation.enabled,
            elicitation_apply_only: cfg.elicitation.apply_only,
            elicitation_required_tools: cfg.elicitation.required_tools.clone(),
            has_api_token: true,
            api_token_source: "config".to_string(),
            api_token_header: "x-cloudflare-api-token".to_string(),
            default_account_id: cfg.cloudflare.default_account_id.clone(),
            default_zone_id: cfg.cloudflare.default_zone_id.clone(),
        };

        if auth_enabled {
            let auth = Arc::new(Authenticator::new(cfg.auth_config.clone()).expect("auth"));
            let layer =
                build_auth_surface_layer(&cfg, &"127.0.0.1:9520".parse().expect("addr"), auth)
                    .await
                    .expect("layer");
            build_router(state, Some(layer))
        } else {
            build_router(state, None)
        }
    }

    async fn test_router() -> Router {
        test_router_with_auth(true).await
    }

    async fn test_router_auth_disabled() -> Router {
        test_router_with_auth(false).await
    }

    async fn spawn_oidc_discovery_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oidc discovery server");
        let addr = listener.local_addr().expect("oidc discovery addr");
        let issuer = format!("http://{addr}");
        let issuer_for_handler = issuer.clone();

        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let issuer = issuer_for_handler.clone();
                async move {
                    Json(json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
                        "token_endpoint": format!("{issuer}/oauth/token"),
                        "jwks_uri": format!("{issuer}/jwks"),
                        "introspection_endpoint": format!("{issuer}/oauth/introspect")
                    }))
                }
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("oidc discovery server");
        });

        issuer
    }

    #[test]
    fn fallback_uses_generic_oauth_paths_for_non_realm_issuers() {
        let issuer = "https://issuer.example.com";
        let (authz, token) = fallback_oauth_endpoints(issuer);
        assert_eq!(authz, "https://issuer.example.com/oauth/authorize");
        assert_eq!(token, "https://issuer.example.com/oauth/token");
    }

    #[tokio::test]
    async fn discovery_is_public_and_mcp_requires_auth() {
        let router = test_router().await;

        let discovery = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource/mcp")
                    .header("host", "127.0.0.1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(discovery.status(), StatusCode::OK);

        let unauthenticated = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let signing_material = fixture_material("delegation");
        let token = make_delegation_token(&signing_material, "issuer.test", "audience.test");
        let authenticated = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "127.0.0.1")
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.0.1"}}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_ne!(authenticated.status(), StatusCode::UNAUTHORIZED);
        assert_ne!(authenticated.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn host_guard_rejects_disallowed_host_header() {
        let router = test_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("host", "attacker.example")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), 1024).await.expect("body");
        assert_eq!(body.as_ref(), b"Host not allowed");
    }

    #[tokio::test]
    async fn auth_disabled_get_without_session_returns_readiness_hint() {
        let router = test_router_auth_disabled().await;
        let response = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("host", "127.0.0.1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("body bytes");
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(
            payload.pointer("/status").and_then(|v| v.as_str()),
            Some("ok")
        );
        assert!(
            payload
                .pointer("/hint")
                .and_then(|v| v.as_str())
                .expect("hint")
                .contains("Initialize with POST /mcp")
        );
    }

    #[tokio::test]
    async fn resource_server_mode_hydrates_runtime_auth_from_oidc_discovery() {
        let issuer = spawn_oidc_discovery_server().await;
        let mut cfg = test_config();
        cfg.auth_mode = Some(AuthMode::Jwks);
        cfg.auth_resource_server_mode = true;
        cfg.auth_issuer = Some(issuer.clone());
        cfg.auth_config.mode = AuthMode::Jwks;
        cfg.auth_config.issuer = None;
        cfg.auth_config.jwks_url = None;
        cfg.auth_config.introspection_url = None;
        cfg.auth_config.audience = Some("audience.test".to_string());

        let hydrated = runtime_auth_config(&cfg)
            .await
            .expect("runtime auth config");
        let expected_jwks = format!("{issuer}/jwks");
        assert_eq!(hydrated.jwks_url.as_deref(), Some(expected_jwks.as_str()));
        assert_eq!(hydrated.issuer.as_deref(), Some(issuer.as_str()));
        assert_eq!(hydrated.introspection_url, None);
    }
}
